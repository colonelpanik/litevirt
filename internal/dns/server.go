// Package dns implements the embedded DNS server for litevirt.
// It resolves names in the configured domain (default: litevirt.local) to VM IPs
// from the dns_records table, and forwards unknown queries upstream.
//
// Name format: <vm>.<stack>.<domain> or <vm>.<domain>
package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	defaultTTL     = 30 // seconds
	forwardTimeout = 3 * time.Second
	// upstream resolvers used when the query is outside our domain
	upstreamDNS = "8.8.8.8:53"
)

// Server is the embedded DNS resolver.
type Server struct {
	domain    string // e.g. "litevirt.local."  (always trailing dot)
	port      int
	db        *corrosion.Client
	srv       *dns.Server
	rrCounter atomic.Uint64 // service-endpoint round-robin pointer
}

// NewServer creates a DNS server for the given domain on the given UDP port.
func NewServer(domain string, port int, db *corrosion.Client) *Server {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return &Server{domain: domain, port: port, db: db}
}

// Start begins serving DNS. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	mux := dns.NewServeMux()
	mux.HandleFunc(s.domain, s.handleLocal)
	mux.HandleFunc(".", s.handleForward)

	s.srv = &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", s.port),
		Net:     "udp",
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.srv.ShutdownContext(shutCtx) //nolint:errcheck
	}()

	slog.Info("DNS server listening", "domain", s.domain, "port", s.port)
	if err := s.srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		slog.Error("DNS server error", "error", err)
	}
}

// handleLocal answers queries for names within our domain.
func (s *Server) handleLocal(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}

		name := strings.ToLower(q.Name)

		// anycast: service_endpoints rows return multiple
		// A records for one name, round-robin-rotated. Falls through
		// to the legacy single-value dns_records lookup if no
		// service is registered under this name.
		if ips := s.lookupService(name); len(ips) > 0 {
			for _, ip := range ips {
				parsed := net.ParseIP(ip).To4()
				if parsed == nil {
					continue
				}
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    defaultTTL,
					},
					A: parsed,
				})
			}
			continue
		}

		ip := s.lookup(name)
		if ip == "" {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m) //nolint:errcheck
			return
		}

		parsed := net.ParseIP(ip).To4()
		if parsed == nil {
			continue
		}
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			A: parsed,
		})
	}

	w.WriteMsg(m) //nolint:errcheck
}

// lookupService returns the IPs registered for a service name in
// service_endpoints, rotated by an atomic counter so successive
// queries see different orderings — DNS-level round-robin without
// requiring a real anycast routing layer.
func (s *Server) lookupService(name string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// A client queries the FQDN ("api.litevirt.local") but service_endpoints
	// stores the BARE service name ("api", as `lv region anycast add --name api`
	// writes it). Match either: strip our domain suffix to get the bare key, and
	// also keep the full name so legacy FQDN-stored rows still resolve.
	full := strings.TrimSuffix(strings.ToLower(name), ".")
	bare := full
	if dom := strings.TrimSuffix(strings.ToLower(s.domain), "."); dom != "" {
		bare = strings.TrimSuffix(full, "."+dom)
	}
	rows, err := s.db.Query(ctx,
		`SELECT ip, weight FROM service_endpoints
		 WHERE service_name IN (?, ?) AND deleted_at IS NULL
		 ORDER BY ip`, bare, full)
	if err != nil || len(rows) == 0 {
		return nil
	}
	// Expand by weight so the rotation respects per-endpoint weight.
	expanded := make([]string, 0, len(rows))
	for _, r := range rows {
		ip := r.String("ip")
		w := r.Int("weight")
		if w <= 0 {
			w = 1
		}
		for i := 0; i < w; i++ {
			expanded = append(expanded, ip)
		}
	}
	// Rotate by an atomic counter so each query sees a different head.
	off := int(s.rrCounter.Add(1)) % len(expanded)
	return append(expanded[off:], expanded[:off]...)
}

// lookup finds the IP for a DNS name by querying the dns_records table.
// It tries an exact match first, then strips one label at a time.
func (s *Server) lookup(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Strip trailing dot for DB lookup.
	key := strings.TrimSuffix(name, ".")

	rows, err := s.db.Query(ctx,
		`SELECT value FROM dns_records
		 WHERE name = ? AND deleted_at IS NULL
		 LIMIT 1`, key)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].String("value")
}

// handleForward proxies queries outside our domain to the upstream resolver.
func (s *Server) handleForward(w dns.ResponseWriter, r *dns.Msg) {
	c := &dns.Client{Timeout: forwardTimeout}
	resp, _, err := c.Exchange(r, upstreamDNS)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m) //nolint:errcheck
		return
	}
	w.WriteMsg(resp) //nolint:errcheck
}

// UpsertRecord writes a name→IP mapping into dns_records.
// Called by the VM lifecycle when an interface gets an IP assigned.
func UpsertRecord(ctx context.Context, db *corrosion.Client, name, ip string) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`INSERT INTO dns_records (name, type, value, source, updated_at)
		 VALUES (?, 'A', ?, 'auto', ?)
		 ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, deleted_at=NULL`,
		name, ip, now,
	)
}

// DeleteRecord tombstones a dns_record entry. dns_records is full-state
// anti-entropy with a deleted_at column, so the tombstone MUST bump updated_at
// (the LWW key) — otherwise a peer's stale live row out-times it and resurrects
// the record. deleted_at is the bare marker; updated_at is the monotonic key.
func DeleteRecord(ctx context.Context, db *corrosion.Client, name string) error {
	return db.Execute(ctx,
		`UPDATE dns_records SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		time.Now().UTC().Format(time.RFC3339), db.NowTS(), name,
	)
}

// VMRecordName returns the DNS name for a VM in a stack: vm.stack.domain
func VMRecordName(vmName, stackName, domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	if stackName != "" {
		return fmt.Sprintf("%s.%s.%s", vmName, stackName, domain)
	}
	return fmt.Sprintf("%s.%s", vmName, domain)
}
