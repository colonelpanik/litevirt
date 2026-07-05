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
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	defaultTTL       = 30 // seconds
	forwardTimeout   = 3 * time.Second
	fallbackUpstream = "8.8.8.8:53" // only if /etc/resolv.conf yields nothing usable
)

// Server is the embedded DNS resolver.
type Server struct {
	domain    string // e.g. "litevirt.local."  (always trailing dot)
	port      int
	db        *corrosion.Client
	srv       *dns.Server
	rrCounter atomic.Uint64 // service-endpoint round-robin pointer
	upstream  string        // resolver for out-of-domain forwards
}

// NewServer creates a DNS server for the given domain on the given UDP port.
func NewServer(domain string, port int, db *corrosion.Client) *Server {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return &Server{domain: domain, port: port, db: db, upstream: resolvConfUpstream()}
}

// resolvConfUpstream returns the first non-loopback nameserver from
// /etc/resolv.conf as "ip:53", falling back to a public resolver. Used only for
// out-of-domain forwards — which, once dnsmasq forwards ONLY the litevirt domain
// to this server, are rare (a direct query here for an external name). Replaces a
// hardcoded 8.8.8.8 so a host with a real upstream is honored.
func resolvConfUpstream() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fallbackUpstream
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && !ip.IsLoopback() {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return fallbackUpstream
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

	nameMissed := false
	for _, q := range r.Question {
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}

		name := strings.ToLower(q.Name)

		// anycast: service_endpoints rows return multiple records for one name,
		// round-robin-rotated. Falls through to the legacy single-value dns_records
		// lookup if no service is registered under this name.
		var ips []string
		if svc := s.lookupService(name); len(svc) > 0 {
			ips = svc
		} else if ip := s.lookup(name); ip != "" {
			ips = []string{ip}
		} else {
			// The name has no record at all. Don't NXDOMAIN mid-loop (that would
			// discard answers already gathered for earlier questions); decide after.
			nameMissed = true
			continue
		}
		for _, ip := range ips {
			if rr := recordFor(q, ip); rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	// NXDOMAIN only when a queried name genuinely does not exist AND we produced
	// no answers. A name that exists but has no record of the requested family
	// (e.g. an AAAA query for a v4-only name) is NODATA/NOERROR, not NXDOMAIN.
	if len(m.Answer) == 0 && nameMissed {
		m.SetRcode(r, dns.RcodeNameError)
	}

	w.WriteMsg(m) //nolint:errcheck
}

// recordFor builds the answer RR for a question given a stored IP: an A record
// for an A query with an IPv4 value, or an AAAA record for an AAAA query with an
// IPv6 value. Returns nil when the query type and the address family don't match
// — a v4-only name must yield NO answer to an AAAA query, never an A record in an
// AAAA response (the prior code emitted A records for AAAA queries).
func recordFor(q dns.Question, ip string) dns.RR {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: defaultTTL}
	}
	if q.Qtype == dns.TypeAAAA {
		if parsed.To4() == nil {
			return &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: parsed.To16()}
		}
		return nil
	}
	if v4 := parsed.To4(); v4 != nil {
		return &dns.A{Hdr: hdr(dns.TypeA), A: v4}
	}
	return nil
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

// lookup finds the IP for a DNS name by an EXACT match against dns_records
// (litevirt names are flat — <vm>.<domain> or <vm>.<stack>.<domain> — and are
// written whole, so no label-stripping is performed).
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
	resp, _, err := c.Exchange(r, s.upstream)
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

// ContainerRecordName returns the DNS name for a container in a stack:
// ct.stack.domain (a standalone container ⇒ ct.domain). Containers share the VM
// name→IP namespace, so this mirrors VMRecordName exactly.
func ContainerRecordName(ctName, stackName, domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	if stackName != "" {
		return fmt.Sprintf("%s.%s.%s", ctName, stackName, domain)
	}
	return fmt.Sprintf("%s.%s", ctName, domain)
}
