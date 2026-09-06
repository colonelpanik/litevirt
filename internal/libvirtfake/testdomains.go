package libvirtfake

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DefineStoppedDomain seeds a PERSISTENT, shut-off domain whose XML carries a
// UUID and one NIC holding mac — the shape a crash (or a half-finished delete)
// leaves behind, and the one an orphan proof has to see.
//
// A stopped-but-defined domain is not a leftover: libvirt will happily start it
// again on the MAC (and therefore the address) written in its definition, so any
// scan that only looks at RUNNING domains reads it as an absence.
//
// Seeding is direct (like SetState), not a DefineDomain call, so it cannot fail
// and does not trip a scenario's FailDefineDomain injection.
func (f *Fake) DefineStoppedDomain(name, mac string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[name] = StateShutdown
	f.xml[name] = StoppedDomainXML(name, DomainUUIDFor(name), mac)
	f.record("define", name, "stopped")
}

// StoppedDomainXML renders the minimal persistent domain definition
// DefineStoppedDomain seeds: a name, a UUID, and one NIC's MAC. Exported so a
// scenario that needs a VARIANT (a live view that diverges from the persistent
// config, say) can build one from the same shape.
func StoppedDomainXML(name, uuid, mac string) string {
	return fmt.Sprintf(
		`<domain type='kvm'>`+
			`<name>%s</name>`+
			`<uuid>%s</uuid>`+
			`<memory unit='MiB'>1024</memory><vcpu>1</vcpu>`+
			`<devices><interface type='network'><mac address='%s'/></interface></devices>`+
			`</domain>`, name, uuid, mac)
}

// DomainUUIDFor is the deterministic UUID DefineStoppedDomain stamps into a
// domain's XML. Derived from the name so a test can predict it without the
// helper having to take one, and shaped like a real UUID so a substring scan
// behaves the way it would against libvirt.
func DomainUUIDFor(name string) string {
	sum := sha256.Sum256([]byte("libvirtfake:" + name))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
