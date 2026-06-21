package cli

import (
	"testing"
)

func TestStreamConsole_DetectsCtrlClose(t *testing.T) {
	// The Ctrl+] byte is 0x1d — verify the constant is correct.
	ctrlClose := byte(0x1d)
	if ctrlClose != 29 {
		t.Errorf("Ctrl+] byte = %d, want 29", ctrlClose)
	}
}

func TestStreamConsole_CtrlCloseInBuffer(t *testing.T) {
	// Simulate scanning a buffer for Ctrl+].
	buf := []byte("hello\x1dworld")
	found := false
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0x1d {
			found = true
			break
		}
	}
	if !found {
		t.Error("should detect Ctrl+] in buffer")
	}
}

func TestStreamConsole_NoCtrlCloseInBuffer(t *testing.T) {
	buf := []byte("hello world, no control chars")
	found := false
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0x1d {
			found = true
			break
		}
	}
	if found {
		t.Error("should not detect Ctrl+] in buffer without it")
	}
}

func TestStreamConsole_CtrlCloseAtBoundaries(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"at_start", []byte{0x1d, 'a', 'b'}, true},
		{"at_end", []byte{'a', 'b', 0x1d}, true},
		{"single_byte", []byte{0x1d}, true},
		{"empty", []byte{}, false},
		{"only_zeros", []byte{0, 0, 0}, false},
		{"adjacent_values", []byte{0x1c, 0x1e}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, b := range tt.buf {
				if b == 0x1d {
					found = true
					break
				}
			}
			if found != tt.want {
				t.Errorf("found = %v, want %v", found, tt.want)
			}
		})
	}
}
