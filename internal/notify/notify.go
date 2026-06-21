// Package notify delivers operator notifications (backup failures, host
// fences, replication failures, quota breaches, …) to configurable targets.
// It mirrors internal/billing in spirit — fire-and-log delivery that never
// blocks the caller — but fans out to multiple typed targets selected by
// event-pattern + minimum-severity routes.
//
// Targets today: webhook (generic JSON POST) and slack (incoming-webhook
// payload). Both are thin HTTP POSTs; email/gotify are future Target impls on
// the same interface.
package notify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Severity orders notifications so a route can subscribe to "warn and above".
type Severity string

const (
	SevInfo  Severity = "info"
	SevWarn  Severity = "warn"
	SevError Severity = "error"
)

func severityRank(s Severity) int {
	switch s {
	case SevError:
		return 3
	case SevWarn:
		return 2
	default:
		return 1 // info / unknown
	}
}

// AtLeast reports whether s is at or above min severity.
func (s Severity) AtLeast(min Severity) bool { return severityRank(s) >= severityRank(min) }

// Notification is one event worth telling an operator about. Kind is the
// verb-period-noun event key (e.g. "backup.failed", "host.fenced",
// "replication.failed", "quota.exceeded").
type Notification struct {
	Kind      string    `json:"kind"`
	Severity  Severity  `json:"severity"`
	Subject   string    `json:"subject"` // the resource (VM/host/project)
	Detail    string    `json:"detail"`
	Cluster   string    `json:"cluster,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Target delivers a notification to one destination.
type Target interface {
	Name() string
	Send(ctx context.Context, n Notification) error
}

// NewTarget builds a Target from its stored type + JSON config. Supported
// types: "webhook", "slack". Returns an error for an unknown type so a typo in
// the stored config surfaces instead of silently dropping notifications.
func NewTarget(name, typ, configJSON string) (Target, error) {
	switch typ {
	case "webhook":
		return newWebhookTarget(name, configJSON)
	case "slack":
		return newSlackTarget(name, configJSON)
	default:
		return nil, fmt.Errorf("unknown notification target type %q", typ)
	}
}

// MatchPattern reports whether an event Kind matches a route pattern. A pattern
// is a dotted glob where "*" matches one segment and a trailing ".*" or bare
// "*" matches the rest: "backup.*" matches "backup.failed"; "*" matches all.
func MatchPattern(pattern, kind string) bool {
	pattern, kind = strings.TrimSpace(pattern), strings.TrimSpace(kind)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == kind {
		return true
	}
	ps, ks := strings.Split(pattern, "."), strings.Split(kind, ".")
	for i, p := range ps {
		if p == "*" {
			// A trailing "*" segment matches the remainder.
			if i == len(ps)-1 {
				return true
			}
			if i >= len(ks) {
				return false
			}
			continue
		}
		if i >= len(ks) || ks[i] != p {
			return false
		}
	}
	return len(ps) == len(ks)
}
