package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func formReq(form url.Values) *http.Request {
	r, _ := http.NewRequest("POST", "/ui/vms", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}

func TestBuildCloudInitUserdata(t *testing.T) {
	t.Run("empty when nothing supplied", func(t *testing.T) {
		if got := buildCloudInitUserdata(formReq(url.Values{"name": {"vm1"}})); got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})

	t.Run("raw override returned verbatim", func(t *testing.T) {
		raw := "#cloud-config\nruncmd:\n  - echo hi"
		got := buildCloudInitUserdata(formReq(url.Values{
			"ci_raw":  {raw + "\n"}, // trailing whitespace is trimmed
			"ci_user": {"ignored"},  // raw wins over friendly fields
		}))
		if got != raw {
			t.Fatalf("raw not returned verbatim:\n%q", got)
		}
	})

	t.Run("friendly fields produce valid cloud-config", func(t *testing.T) {
		got := buildCloudInitUserdata(formReq(url.Values{
			"ci_user":     {"ubuntu"},
			"ci_password": {"s3cr3t:with\"quote"},
			"ci_ssh_keys": {"ssh-ed25519 AAAAC3 a@b\nssh-rsa BBBB c@d\n"},
			"ci_packages": {"htop, curl ,qemu-guest-agent"},
			"ci_upgrade":  {"true"},
		}))
		if !strings.HasPrefix(got, "#cloud-config\n") {
			t.Fatalf("missing #cloud-config header:\n%s", got)
		}
		// Must be well-formed YAML (the comment line is ignored by the parser).
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
			t.Fatalf("generated cloud-config is not valid YAML: %v\n%s", err, got)
		}
		users, ok := doc["users"].([]any)
		if !ok || len(users) != 1 {
			t.Fatalf("expected one user entry, got %#v", doc["users"])
		}
		u := users[0].(map[string]any)
		if u["name"] != "ubuntu" {
			t.Errorf("user name = %v", u["name"])
		}
		sk, _ := u["ssh_authorized_keys"].([]any)
		if len(sk) != 2 {
			t.Errorf("expected 2 ssh keys, got %#v", u["ssh_authorized_keys"])
		}
		pkgs, _ := doc["packages"].([]any)
		if len(pkgs) != 3 {
			t.Errorf("expected 3 packages, got %#v", doc["packages"])
		}
		if doc["package_upgrade"] != true {
			t.Errorf("package_upgrade not set")
		}
		// The quote-bearing password survived as a quoted scalar.
		cp, _ := doc["chpasswd"].(map[string]any)
		cu, _ := cp["users"].([]any)
		if len(cu) != 1 || cu[0].(map[string]any)["password"] != "s3cr3t:with\"quote" {
			t.Errorf("password not preserved: %#v", cp)
		}
	})

	t.Run("ssh key without user applies to default user", func(t *testing.T) {
		got := buildCloudInitUserdata(formReq(url.Values{
			"ci_ssh_keys": {"ssh-ed25519 AAAAC3 a@b"},
		}))
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
			t.Fatalf("invalid YAML: %v\n%s", err, got)
		}
		if _, hasUsers := doc["users"]; hasUsers {
			t.Errorf("did not expect a users block: %s", got)
		}
		if sk, _ := doc["ssh_authorized_keys"].([]any); len(sk) != 1 {
			t.Errorf("expected top-level ssh_authorized_keys, got %s", got)
		}
	})
}

// TestNewVMModalHasCloudInit verifies the cloud-init panel renders in the
// create-VM modal fragment.
func TestNewVMModalHasCloudInit(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/new-modal")))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), "Cloud-init", `name="ci_user"`, `name="ci_ssh_keys"`, `name="ci_raw"`)
}
