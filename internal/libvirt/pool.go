package libvirt

import (
	"fmt"
	"log/slog"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// EnsureStoragePool creates a libvirt storage pool if it doesn't already exist,
// then ensures it's started and set to autostart. Idempotent — safe to call on
// every daemon startup.
//
// Driver mapping:
//
//	local → dir pool
//	nfs   → netfs pool
//	ceph  → rbd pool
//	iscsi → iscsi pool
func (c *Client) EnsureStoragePool(name, driver, source, target string, opts map[string]string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if pool already exists.
	pool, err := c.virt.StoragePoolLookupByName(name)
	if err == nil {
		// Pool exists — make sure it's active and autostarted.
		active, _ := c.virt.StoragePoolIsActive(pool)
		if active == 0 {
			c.virt.StoragePoolCreate(pool, golibvirt.StoragePoolCreateNormal) //nolint:errcheck
		}
		c.virt.StoragePoolSetAutostart(pool, 1) //nolint:errcheck
		slog.Debug("storage pool already exists", "pool", name)
		return nil
	}

	poolXML, err := generatePoolXML(name, driver, source, target, opts)
	if err != nil {
		return err
	}

	pool, err = c.virt.StoragePoolDefineXML(poolXML, 0)
	if err != nil {
		return fmt.Errorf("pool define %s: %w", name, err)
	}

	// Build the pool (creates target directory for dir/netfs pools).
	c.virt.StoragePoolBuild(pool, golibvirt.StoragePoolBuildNew) //nolint:errcheck

	if err := c.virt.StoragePoolCreate(pool, golibvirt.StoragePoolCreateNormal); err != nil {
		return fmt.Errorf("pool start %s: %w", name, err)
	}

	if err := c.virt.StoragePoolSetAutostart(pool, 1); err != nil {
		return fmt.Errorf("pool autostart %s: %w", name, err)
	}

	slog.Info("created libvirt storage pool", "pool", name, "driver", driver)
	return nil
}

// PoolDestroyIfDefined stops (if active) and undefines a libvirt storage pool.
// Tolerates the pool not being defined — returns nil (idempotent), since litevirt
// runtime pools usually have no libvirt object (CreateStoragePool doesn't
// EnsureStoragePool). Belt-and-suspenders cleanup on `lv pool delete`; it does NOT
// delete the underlying storage (no StoragePoolDelete), only the libvirt handle.
func (c *Client) PoolDestroyIfDefined(name string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pool, err := c.virt.StoragePoolLookupByName(name)
	if err != nil {
		return nil // not defined in libvirt — nothing to undefine
	}
	if active, _ := c.virt.StoragePoolIsActive(pool); active != 0 {
		c.virt.StoragePoolDestroy(pool) //nolint:errcheck // best-effort stop before undefine
	}
	if err := c.virt.StoragePoolUndefine(pool); err != nil {
		return fmt.Errorf("pool undefine %s: %w", name, err)
	}
	slog.Info("undefined libvirt storage pool", "pool", name)
	return nil
}

// generatePoolXML builds the libvirt storage pool XML for the given driver type.
func generatePoolXML(name, driver, source, target string, opts map[string]string) (string, error) {
	switch driver {
	case "local", "dir", "":
		if target == "" {
			return "", fmt.Errorf("local pool %q requires target path", name)
		}
		return fmt.Sprintf(`<pool type='dir'>
  <name>%s</name>
  <target><path>%s</path></target>
</pool>`, name, target), nil

	case "nfs", "netfs":
		host, path, ok := splitNFSSource(source)
		if !ok {
			return "", fmt.Errorf("nfs pool %q: source must be host:/path, got %q", name, source)
		}
		if target == "" {
			return "", fmt.Errorf("nfs pool %q requires target mount path", name)
		}
		return fmt.Sprintf(`<pool type='netfs'>
  <name>%s</name>
  <source>
    <host name='%s'/>
    <dir path='%s'/>
  </source>
  <target><path>%s</path></target>
</pool>`, name, host, path, target), nil

	case "ceph", "rbd":
		if source == "" {
			return "", fmt.Errorf("ceph pool %q requires source (Ceph pool name)", name)
		}
		authXML := ""
		if id := opts["id"]; id != "" {
			authXML = fmt.Sprintf("\n    <auth type='ceph' username='%s'/>", id)
		}
		return fmt.Sprintf(`<pool type='rbd'>
  <name>%s</name>
  <source>
    <name>%s</name>%s
  </source>
</pool>`, name, source, authXML), nil

	case "iscsi":
		host, iqn := source, opts["iqn"]
		if i := strings.Index(source, ":"); i > 0 && iqn == "" {
			host, iqn = source[:i], source[i+1:]
		}
		if host == "" || iqn == "" {
			return "", fmt.Errorf("iscsi pool %q requires source host and IQN", name)
		}
		return fmt.Sprintf(`<pool type='iscsi'>
  <name>%s</name>
  <source>
    <host name='%s'/>
    <device path='%s'/>
  </source>
</pool>`, name, host, iqn), nil

	default:
		return "", fmt.Errorf("unsupported storage pool driver %q for pool %q", driver, name)
	}
}

// splitNFSSource splits "host:/path" into host and path.
func splitNFSSource(source string) (host, path string, ok bool) {
	i := strings.Index(source, ":")
	if i <= 0 || i >= len(source)-1 {
		return "", "", false
	}
	return source[:i], source[i+1:], true
}
