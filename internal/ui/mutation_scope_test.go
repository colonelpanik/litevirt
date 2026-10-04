package ui

import "testing"

// TestSelfServiceMutation classifies the routes a user performs on THEMSELVES.
//
// The mutation gate asks the daemon for cluster-write authority, which is
// correct for the firewall/ipset/notification handlers that write cluster-wide
// state in-process. It is wrong for self-service: a Viewer must still be able
// to change their own password and enrol a security key, and those routes
// carry no authority beyond the session that already authenticated.
func TestSelfServiceMutation(t *testing.T) {
	selfService := []string{
		"/account/password",
		"/account/2fa/webauthn/begin",
		"/account/2fa/webauthn/finish",
	}
	for _, p := range selfService {
		if !selfServiceMutation(p) {
			t.Errorf("selfServiceMutation(%q) = false; a viewer must be able to manage their own credentials", p)
		}
	}

	cluster := []string{
		"/ui/firewall/default-deny",
		"/ui/firewall/cluster-rules",
		"/ui/firewall/ipsets",
		"/ui/notifications/routes",
		"/ui/resource-mappings",
		"/ui/security-groups/rules",
		"/account/../ui/firewall/cluster-rules", // must not be laundered by traversal
	}
	for _, p := range cluster {
		if selfServiceMutation(p) {
			t.Errorf("selfServiceMutation(%q) = true; this writes cluster-wide state", p)
		}
	}
}
