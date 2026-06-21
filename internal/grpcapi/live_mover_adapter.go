package grpcapi

import (
	"github.com/litevirt/litevirt/internal/libvirt"
)

// LibvirtLiveMover bridges grpcapi.LiveMover to internal/libvirt.Client.
// Constructed by the daemon at startup.
type LibvirtLiveMover struct{ Client *libvirt.Client }

func NewLibvirtLiveMover(c *libvirt.Client) *LibvirtLiveMover { return &LibvirtLiveMover{Client: c} }

func (l *LibvirtLiveMover) StartBlockCopy(domain, disk, destXML string, flags uint32) error {
	return l.Client.StartBlockCopy(domain, disk, destXML, flags)
}

func (l *LibvirtLiveMover) BlockJobStatus(domain, disk string) (LiveMoverStatus, error) {
	st, err := l.Client.BlockJobStatus(domain, disk)
	if err != nil {
		return LiveMoverStatus{}, err
	}
	return LiveMoverStatus{Found: st.Found, Cur: st.Cur, End: st.End}, nil
}

func (l *LibvirtLiveMover) PivotBlockCopy(domain, disk string) error {
	return l.Client.PivotBlockCopy(domain, disk)
}

func (l *LibvirtLiveMover) CancelBlockCopy(domain, disk string) error {
	return l.Client.CancelBlockCopy(domain, disk)
}
