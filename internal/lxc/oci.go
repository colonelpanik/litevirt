package lxc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PullOCIOptions controls an OCI → LXC rootfs conversion.
type PullOCIOptions struct {
	// Image is the OCI reference, either a remote ("docker.io/library/alpine:3.19")
	// or a local OCI directory ("oci:/var/lib/litevirt/oci/alpine:3.19").
	Image string
	// Dest is the rootfs directory umoci will populate. Created if missing.
	Dest string
	// Tag overrides the default tag selection. Empty = use the image
	// reference's natural tag.
	Tag string
	// Username / Password authenticate the skopeo pull against a private
	// registry. Empty = anonymous. Passed to skopeo as --src-creds (an exec
	// arg, not a temp authfile, so there is nothing to leak on crash). Only
	// applied when the source is a remote (docker://) registry.
	Username string
	Password string
}

// PullOCI extracts an OCI image's flattened rootfs to disk via umoci.
// Two binaries are required: skopeo (to copy the image into a local
// OCI layout) and umoci (to unpack it). The hosts ship both in their
// container-runtime package set.
//
// Conversion runs in two stages so we can resume a failed unpack
// without re-downloading the layers:
//
//   1. skopeo copy &lt;image&gt; oci:&lt;tmp&gt;:&lt;tag&gt;
//   2. umoci unpack --image &lt;tmp&gt;:&lt;tag&gt; --rootless &lt;dest&gt;
//
// We choose --rootless so containers can run unprivileged when the
// host config supports user namespaces.
func PullOCI(ctx context.Context, opts PullOCIOptions) error {
	if opts.Image == "" {
		return errors.New("oci: image required")
	}
	if opts.Dest == "" {
		return errors.New("oci: dest required")
	}
	if err := requireBinary("skopeo"); err != nil {
		return err
	}
	if err := requireBinary("umoci"); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.Dest, 0750); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	tmpLayout := opts.Dest + ".oci"
	tag := opts.Tag
	if tag == "" {
		tag = parseOCITag(opts.Image)
	}

	// Stage 1: skopeo into a local OCI directory layout. The "docker://"
	// prefix tells skopeo to fetch from a registry; "oci:" works for
	// local OCI dirs.
	srcRef := opts.Image
	remote := !strings.Contains(srcRef, "://")
	if remote {
		srcRef = "docker://" + srcRef
	} else {
		remote = strings.HasPrefix(srcRef, "docker://")
	}
	dstRef := fmt.Sprintf("oci:%s:%s", tmpLayout, tag)
	args := []string{"copy"}
	// Credentials only make sense for a remote registry source; a local
	// "oci:" layout has nothing to authenticate to. Args go through the exec
	// slice (not a shell), so a password with shell metacharacters is safe.
	if opts.Username != "" && remote {
		args = append(args, "--src-creds", opts.Username+":"+opts.Password)
	}
	args = append(args, srcRef, dstRef)
	if out, err := exec.CommandContext(ctx, "skopeo", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("skopeo copy: %w: %s", err, out)
	}

	// Stage 2: umoci unpack flattens the layers into a usable rootfs.
	if out, err := exec.CommandContext(ctx,
		"umoci", "unpack", "--rootless", "--image", fmt.Sprintf("%s:%s", tmpLayout, tag),
		opts.Dest,
	).CombinedOutput(); err != nil {
		return fmt.Errorf("umoci unpack: %w: %s", err, out)
	}
	return nil
}

// parseOCITag extracts the ":<tag>" portion of an image reference, or
// returns "latest" if absent. Handles registry-with-port edge cases.
//
//	"alpine"                            → "latest"
//	"alpine:3.19"                       → "3.19"
//	"docker.io/library/alpine:3.19"     → "3.19"
//	"registry.local:5000/team/img:v1"   → "v1"
//	"registry.local:5000/team/img"      → "latest"
func parseOCITag(ref string) string {
	// Strip any scheme prefix.
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	// Path-aware split: only count the LAST ':' if the segment after
	// it contains no '/' (otherwise it's the registry port).
	last := strings.LastIndex(ref, ":")
	if last < 0 {
		return "latest"
	}
	if strings.ContainsAny(ref[last:], "/") {
		return "latest"
	}
	return ref[last+1:]
}

// RegistryHost extracts the registry hostname from an IMAGE REFERENCE (the pull
// path), using the same scheme-strip + path-aware handling as parseOCITag.
// Returns "" for a local "oci:" layout (which has no registry, so no credential
// applies). Follows Docker's canonical disambiguation: the first path component
// is the registry iff it contains '.' or ':' or is "localhost"; otherwise the
// reference is a Docker Hub short name and the registry defaults to docker.io.
//
//	"alpine"                          → "docker.io"
//	"alpine:3.19"                     → "docker.io"
//	"library/alpine"                  → "docker.io"
//	"docker.io/library/alpine:3.19"   → "docker.io"
//	"ghcr.io/org/x"                   → "ghcr.io"
//	"docker://ghcr.io/org/x"          → "ghcr.io"
//	"registry:5000/team/img:v1"       → "registry:5000"
//	"localhost:5000/x"                → "localhost:5000"
//	"oci:/var/lib/litevirt/oci/x:1"   → ""
func RegistryHost(ref string) string {
	// A local OCI layout reference ("oci:/path:tag") never authenticates.
	if strings.HasPrefix(ref, "oci:") {
		return ""
	}
	// Strip any scheme prefix (e.g. "docker://").
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	first := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		first = ref[:i]
	} else {
		// No '/': a bare "name" or "name:tag" — always Docker Hub.
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return canonicalRegistry(first)
	}
	return "docker.io"
}

// NormalizeRegistry canonicalizes a REGISTRY HOST argument — what a user passes
// to `lv registry add <registry>` or stores a credential against — as opposed
// to a full image reference (use RegistryHost for that). It strips any scheme
// and trailing path so a full reference's host can be recovered, and folds the
// Docker Hub aliases onto "docker.io" so a credential stored here matches what
// RegistryHost derives from a pulled image.
//
//	"ghcr.io"                         → "ghcr.io"
//	"docker.io"                       → "docker.io"
//	"index.docker.io"                 → "docker.io"
//	"registry:5000"                   → "registry:5000"
//	"https://ghcr.io"                 → "ghcr.io"
//	"docker.io/library/alpine"        → "docker.io"
//	"oci:/var/lib/.../x:1"            → ""
func NormalizeRegistry(reg string) string {
	if strings.HasPrefix(reg, "oci:") {
		return ""
	}
	if i := strings.Index(reg, "://"); i >= 0 {
		reg = reg[i+3:]
	}
	if i := strings.Index(reg, "/"); i >= 0 {
		reg = reg[:i]
	}
	return canonicalRegistry(strings.TrimSpace(reg))
}

// canonicalRegistry folds the several Docker Hub hostnames onto the single
// canonical "docker.io" so credentials and pulls agree on one key.
func canonicalRegistry(host string) string {
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return host
}

// requireBinary errors if the named binary is not on PATH. Useful so
// PullOCI fails fast instead of mid-download.
func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required binary %q not found in PATH", name)
	}
	return nil
}

// RootfsPath returns the canonical rootfs location for a container
// stored under <lxcpath>/<name>/rootfs. Used by callers that pull an
// OCI image first and then hand the path to Create() as a Template.
func RootfsPath(lxcpath, name string) string {
	if lxcpath == "" {
		lxcpath = "/var/lib/lxc"
	}
	return filepath.Join(lxcpath, name, "rootfs")
}
