package ssh

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// TestHostKeyVerdict pins the one distinction the old callback collapsed.
//
// SSH here is not "just a transport for setup" — it is the channel that
// carries the cluster CA-signed HOST PRIVATE KEY to a machine that has no mTLS
// identity yet. There is no other trust anchor at that moment, so accepting a
// changed host key hands that key to whoever answered.
//
// An UNKNOWN host is unavoidable: provisioning a new machine means first
// contact. A CHANGED key is not: it means something that is not the host we
// talked to last time is answering for it.
func TestHostKeyVerdict(t *testing.T) {
	t.Run("known and matching is accepted", func(t *testing.T) {
		if err := hostKeyVerdict("node-1", nil); err != nil {
			t.Fatalf("hostKeyVerdict(_, nil) = %v, want nil", err)
		}
	})

	t.Run("unknown host is accepted on first contact", func(t *testing.T) {
		if err := hostKeyVerdict("node-1", &knownhosts.KeyError{}); err != nil {
			t.Fatalf("an unknown host must be accepted (provisioning is always first contact), got %v", err)
		}
	})

	t.Run("changed key is REFUSED", func(t *testing.T) {
		mismatch := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Filename: "known_hosts", Line: 1}}}
		if err := hostKeyVerdict("node-1", mismatch); err == nil {
			t.Fatal("a CHANGED host key was accepted; SSH carries the CA-signed host key " +
				"to a node with no mTLS identity, so this hands it to a man in the middle")
		}
	})

	t.Run("an unrelated error is not swallowed", func(t *testing.T) {
		sentinel := errors.New("dial broke")
		if err := hostKeyVerdict("node-1", sentinel); !errors.Is(err, sentinel) {
			t.Fatalf("hostKeyVerdict(_, %v) = %v, want it passed through", sentinel, err)
		}
	})
}
