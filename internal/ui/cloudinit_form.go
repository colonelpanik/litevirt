package ui

import (
	"net/http"
	"strings"
)

// buildCloudInitUserdata assembles a #cloud-config document from the friendly
// cloud-init fields in the VM-create form. If the advanced raw field is set it
// is returned verbatim (the user takes full control). Returns "" when nothing
// cloud-init-related was provided, so the caller leaves spec.CloudInit nil.
func buildCloudInitUserdata(r *http.Request) string {
	if raw := strings.TrimSpace(r.FormValue("ci_raw")); raw != "" {
		return raw
	}

	user := strings.TrimSpace(r.FormValue("ci_user"))
	password := strings.TrimSpace(r.FormValue("ci_password"))
	packages := splitCSV(r.FormValue("ci_packages"))
	upgrade := r.FormValue("ci_upgrade") == "true"

	var keys []string
	for _, k := range strings.Split(r.FormValue("ci_ssh_keys"), "\n") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}

	if user == "" && password == "" && len(keys) == 0 && len(packages) == 0 && !upgrade {
		return ""
	}

	var b strings.Builder
	b.WriteString("#cloud-config\n")

	switch {
	case user != "":
		b.WriteString("users:\n")
		b.WriteString("  - name: " + yamlScalar(user) + "\n")
		b.WriteString("    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n")
		b.WriteString("    shell: /bin/bash\n")
		if password != "" {
			b.WriteString("    lock_passwd: false\n")
		}
		if len(keys) > 0 {
			b.WriteString("    ssh_authorized_keys:\n")
			for _, k := range keys {
				b.WriteString("      - " + yamlScalar(k) + "\n")
			}
		}
	case len(keys) > 0:
		// No explicit user → apply keys to the image's default user.
		b.WriteString("ssh_authorized_keys:\n")
		for _, k := range keys {
			b.WriteString("  - " + yamlScalar(k) + "\n")
		}
	}

	if password != "" {
		target := user
		if target == "" {
			target = "root"
		}
		b.WriteString("ssh_pwauth: true\n")
		b.WriteString("chpasswd:\n")
		b.WriteString("  expire: false\n")
		b.WriteString("  users:\n")
		b.WriteString("    - name: " + yamlScalar(target) + "\n")
		b.WriteString("      password: " + yamlScalar(password) + "\n")
		b.WriteString("      type: text\n")
	}

	if len(packages) > 0 {
		b.WriteString("packages:\n")
		for _, p := range packages {
			b.WriteString("  - " + yamlScalar(p) + "\n")
		}
	}
	if upgrade {
		b.WriteString("package_upgrade: true\n")
	}
	return b.String()
}

// yamlScalar renders a YAML-safe double-quoted scalar so arbitrary user input
// (keys, passwords, package names) can't break the document structure.
func yamlScalar(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
