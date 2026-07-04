//go:build linux

package watchdog

import "testing"

// The WDIOC_* request numbers are hand-computed (unix doesn't export them), so verify them
// against the _IOC encoding — a hex typo would issue the WRONG ioctl to a real watchdog.
// _IOC(dir,type,nr,size) = (dir<<30)|(size<<16)|(type<<8)|nr; 'W'=0x57, int size=4;
// _IOR dir=2 (READ), _IOWR dir=3 (READ|WRITE).
func TestWatchdogIoctlConstants(t *testing.T) {
	ioc := func(dir, nr uint) uint { return (dir << 30) | (4 << 16) | (uint('W') << 8) | nr }
	const read, readWrite = 2, 3
	for _, c := range []struct {
		name string
		got  uint
		want uint
	}{
		{"WDIOC_SETOPTIONS", wdiocSetOptions, ioc(read, 4)},
		{"WDIOC_SETTIMEOUT", wdiocSetTimeout, ioc(readWrite, 6)},
		{"WDIOC_GETTIMELEFT", wdiocGetTimeLeft, ioc(read, 10)},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
	if wdiosEnableCard != 0x2 || wdiosDisableCard != 0x1 {
		t.Errorf("WDIOS enable/disable = %#x/%#x, want 0x2/0x1", wdiosEnableCard, wdiosDisableCard)
	}
}
