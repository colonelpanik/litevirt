// Package lb manages HAProxy + keepalived for VRRP-based load balancing.
package lb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
)

// deriveAuthPass returns a per-LB VRRP authentication password. keepalived
// truncates auth_pass to 8 characters, so we take the first 8 hex chars of a
// salted SHA-256 of the LB name. This is NOT cryptographically secret (VRRP
// PASS auth is plaintext on the wire and sniffable on the L2 segment); its
// purpose is to give each LB a distinct password so two unrelated VRRP
// instances on the same segment can't accidentally pair up. Rely on L2
// segmentation for actual security. (F6: was a single hardcoded "litevirt".)
func deriveAuthPass(name string) string {
	sum := sha256.Sum256([]byte("litevirt-vrrp:" + name))
	return hex.EncodeToString(sum[:])[:8]
}

// Config holds everything needed to render HAProxy + keepalived configs for one LB instance.
type Config struct {
	Name      string   // e.g. "app-server"
	VIP       string   // e.g. "10.0.100.100"
	VIPPrefix int      // CIDR prefix length
	Interface string   // network interface for VRRP (e.g. "eth0")
	VRID      int      // VRRP virtual router ID (1–255, unique per VIP)
	Priority  int      // 100 = master, 50 = backup
	Backends  []Backend
	Ports     []Port
	Algorithm string   // roundrobin | leastconn | source
	Health    *HealthConfig // backend health check (nil = default tcp-check)

	// SNAT fields — set when LB provides outbound NAT for host-isolated VMs.
	SNATEnabled bool   // enable SNAT + conntrackd
	LocalIP     string // this host's IP for conntrackd sync
	PeerIP      string // VRRP peer IP for conntrackd sync
	Subnet      string // VM subnet CIDR for SNAT rule (e.g. "10.100.0.0/24")
}

// HealthConfig configures HAProxy backend health checking.
type HealthConfig struct {
	Type       string // "tcp" | "http" (default: tcp)
	Path       string // HTTP health check path (only for type "http")
	IntervalMS int    // check interval in milliseconds (0 = default 2000)
}

// Backend is a single VM instance behind the LB.
type Backend struct {
	Name string
	IP   string
	Port int
}

// Port is a listener on the VIP.
type Port struct {
	Listen   int
	Target   int    // backend port
	Protocol string // tcp | http
	TLS      *TLSConfig
}

// TLSConfig holds cert/key paths for TLS termination.
type TLSConfig struct {
	Cert string
	Key  string
}

const haproxyTmplStr = `
global
    log /dev/log local0
    maxconn 4096
    user haproxy
    group haproxy
    daemon
    stats socket /run/litevirt/lb/{{.Name}}-haproxy.sock mode 660 level admin
    stats timeout 30s

defaults
    log     global
    mode    tcp
    option  tcplog
    retries 3
    timeout connect 5s
    timeout client  30s
    timeout server  30s

{{- range .Ports}}
frontend {{$.Name}}-{{.Listen}}
    {{- if .TLS}}
    bind {{$.VIP}}:{{.Listen}} ssl crt /etc/litevirt/lb/{{$.Name}}-{{.Listen}}.pem
    {{- else}}
    bind {{$.VIP}}:{{.Listen}}
    {{- end}}
    default_backend {{$.Name}}-{{.Listen}}-be

backend {{$.Name}}-{{.Listen}}-be
    balance {{$.Algorithm}}
    {{- if and $.Health (eq $.Health.Type "http")}}
    option httpchk GET {{or $.Health.Path "/"}}
    http-check expect status 200
    {{- else}}
    option tcp-check
    {{- end}}
    {{- range $.Backends}}
    server {{.Name}} {{.IP}}:{{.Port}} check inter {{checkInterval $}} rise 2 fall 3
    {{- end}}
{{- end}}
`

var keepalivedTmpl = template.Must(template.New("keepalived").Parse(`
global_defs {
    enable_script_security
    script_user root
}

vrrp_script chk_haproxy {
    script "/usr/bin/pgrep -f {{.Name}}-haproxy.cfg"
    interval 2
    weight 2
    rise 2
    fall 3
}

vrrp_instance {{.Name}} {
    state {{if eq .Priority 100}}MASTER{{else}}BACKUP{{end}}
    interface {{.Interface}}
    virtual_router_id {{.VRID}}
    priority {{.Priority}}
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass {{.AuthPass}}
    }

    virtual_ipaddress {
        {{.VIP}}/{{.VIPPrefix}}
    }

    track_script {
        chk_haproxy
    }
{{- if .SNATEnabled}}

    notify_master "/etc/litevirt/lb/{{.Name}}-notify.sh MASTER"
    notify_backup "/etc/litevirt/lb/{{.Name}}-notify.sh BACKUP"
    notify_fault  "/etc/litevirt/lb/{{.Name}}-notify.sh FAULT"
{{- end}}
}
`))

// RenderHAProxy produces an haproxy.cfg content string.
func RenderHAProxy(cfg Config) (string, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = "roundrobin"
	}

	funcs := template.FuncMap{
		"checkInterval": func(cfg Config) string {
			if cfg.Health != nil && cfg.Health.IntervalMS > 0 {
				return fmt.Sprintf("%dms", cfg.Health.IntervalMS)
			}
			return "2s"
		},
	}
	tmpl, err := template.New("haproxy").Funcs(funcs).Parse(haproxyTmplStr)
	if err != nil {
		return "", fmt.Errorf("parse haproxy template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render haproxy config: %w", err)
	}
	return buf.String(), nil
}

// RenderKeepalived produces a keepalived.conf content string.
//
// INVARIANT: the template emits EXACTLY ONE address in the virtual_ipaddress block
// (a single {{.VIP}}/{{.VIPPrefix}} per LB). parseKeepalivedVIP relies on this — it
// returns the sole address in that block — so if this template is ever changed to render
// multiple VIPs per instance, parseKeepalivedVIP + DemoteAll must be revisited to
// enumerate all of them (today "one LB ⇒ one VIP" makes single-address parsing exact).
func RenderKeepalived(cfg Config) (string, error) {
	var buf bytes.Buffer
	// Augment cfg with a derived, per-LB VRRP auth password (F6).
	data := struct {
		Config
		AuthPass string
	}{Config: cfg, AuthPass: deriveAuthPass(cfg.Name)}
	if err := keepalivedTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render keepalived config: %w", err)
	}
	return buf.String(), nil
}

// RenderConntrackd produces a conntrackd.conf for SNAT conntrack sync between VRRP peers.
func RenderConntrackd(cfg Config) (string, error) {
	if cfg.LocalIP == "" || cfg.PeerIP == "" {
		return "", fmt.Errorf("conntrackd requires LocalIP and PeerIP")
	}
	var buf bytes.Buffer
	if err := conntrackdTmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render conntrackd config: %w", err)
	}
	return buf.String(), nil
}

// RenderNotifyScript produces the keepalived notify script for conntrackd state transitions.
func RenderNotifyScript(cfg Config) (string, error) {
	var buf bytes.Buffer
	if err := notifyTmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render notify script: %w", err)
	}
	return buf.String(), nil
}

var conntrackdTmpl = template.Must(template.New("conntrackd").Parse(`Sync {
    Mode FTFW {}
    UDP {
        IPv4_address {{.LocalIP}}
        IPv4_Destination_Address {{.PeerIP}}
        Port 3780
        Interface {{.Interface}}
    }
}

General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    Syslog on
    LockFile /var/lock/conntrack-{{.Name}}.lock
    UNIX { Path /var/run/conntrackd-{{.Name}}.ctl }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept { TCP UDP }
        Address Accept { IPv4_address {{.Subnet}} }
    }
}
`))

var notifyTmpl = template.Must(template.New("notify").Parse(`#!/bin/bash
CTL="/var/run/conntrackd-{{.Name}}.ctl"
case "$1" in
    MASTER)
        conntrackd -C "$CTL" -c -C commit
        conntrackd -C "$CTL" -c -f internal
        ;;
    BACKUP|FAULT)
        conntrackd -C "$CTL" -c -f external
        ;;
esac
`))

// ParseVIP splits "10.0.100.100/24" into IP and prefix length.
func ParseVIP(vip string) (ip string, prefix int, err error) {
	parts := strings.SplitN(vip, "/", 2)
	if len(parts) != 2 {
		return vip, 32, nil
	}
	ip = parts[0]
	if _, err := fmt.Sscanf(parts[1], "%d", &prefix); err != nil {
		return "", 0, fmt.Errorf("invalid VIP CIDR %q", vip)
	}
	return ip, prefix, nil
}
