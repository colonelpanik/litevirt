package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type exitStatusError int

func (e exitStatusError) Error() string { return "exit status" }
func (e exitStatusError) ExitCode() int { return int(e) }

func TestNFSPrepareControlCommands(t *testing.T) {
	mountFailure := errors.New("mount failed")
	for _, tc := range []struct {
		name      string
		timeout   string
		cancel    bool
		mode      string
		wantErr   error
		wantCalls []string
		wantTrim  bool
	}{
		{
			name:      "already mounted skips mount",
			mode:      "mounted",
			wantCalls: []string{"mountpoint"},
		},
		{
			name:      "mount failure trims output",
			mode:      "mount failure",
			wantErr:   mountFailure,
			wantCalls: []string{"mountpoint", "mount"},
			wantTrim:  true,
		},
		{
			name:      "parent cancellation stops before mount",
			cancel:    true,
			mode:      "parent cancelled",
			wantErr:   context.Canceled,
			wantCalls: []string{"mountpoint"},
		},
		{
			name:      "blank timeout uses default",
			timeout:   "  \t",
			mode:      "mounted",
			wantCalls: []string{"mountpoint"},
		},
		{
			name:      "whitespace timeout parses",
			timeout:   " 20ms ",
			mode:      "mounted",
			wantCalls: []string{"mountpoint"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var calls []string
			d := &nfsDriver{
				source:         "server:/export",
				targetOverride: t.TempDir(),
				opts:           map[string]string{"command_timeout": tc.timeout},
				run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
					calls = append(calls, name)
					switch tc.mode {
					case "mounted":
						return nil, nil
					case "mount failure":
						if name == "mountpoint" {
							return nil, exitStatusError(32)
						}
						return []byte(" \n" + strings.Repeat("x", maxNFSCommandOutput+100) + "\n "), mountFailure
					case "parent cancelled":
						return nil, errors.New("runner observed cancellation")
					default:
						t.Fatalf("unknown mode %q", tc.mode)
						return nil, nil
					}
				},
			}

			err := d.Prepare(ctx)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Prepare error = %v, want %v", err, tc.wantErr)
			}
			if strings.Join(calls, ",") != strings.Join(tc.wantCalls, ",") {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
			if tc.wantTrim && (!strings.Contains(err.Error(), "…") || strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), strings.Repeat("x", maxNFSCommandOutput+1))) {
				t.Fatalf("mount error output was not trimmed and bounded: %q", err)
			}
		})
	}
}

func TestNFSTeardownControlCommands(t *testing.T) {
	probeFailure := errors.New("mountpoint probe failed")
	umountFailure := errors.New("umount failed")
	for _, tc := range []struct {
		name      string
		timeout   string
		cancel    bool
		mode      string
		wantErr   error
		wantCalls []string
		wantTrim  bool
	}{
		{
			name:      "not mounted skips umount",
			mode:      "not mounted",
			wantCalls: []string{"mountpoint"},
		},
		{
			name:      "probe failure is returned",
			mode:      "probe failure",
			wantErr:   probeFailure,
			wantCalls: []string{"mountpoint"},
		},
		{
			name:      "umount failure trims output",
			mode:      "umount failure",
			wantErr:   umountFailure,
			wantCalls: []string{"mountpoint", "umount"},
			wantTrim:  true,
		},
		{
			name:      "umount timeout preserves deadline",
			timeout:   "20ms",
			mode:      "umount timeout",
			wantErr:   context.DeadlineExceeded,
			wantCalls: []string{"mountpoint", "umount"},
		},
		{
			name:      "parent cancellation stops before umount",
			cancel:    true,
			mode:      "parent cancelled",
			wantErr:   context.Canceled,
			wantCalls: []string{"mountpoint"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var calls []string
			d := &nfsDriver{
				source:    "server:/export",
				mountBase: t.TempDir(),
				opts:      map[string]string{"command_timeout": tc.timeout},
				run: func(ctx context.Context, name string, _ ...string) ([]byte, error) {
					calls = append(calls, name)
					switch tc.mode {
					case "not mounted":
						return nil, exitStatusError(32)
					case "probe failure", "parent cancelled":
						return []byte(" probe output \n"), probeFailure
					case "umount failure":
						if name == "mountpoint" {
							return nil, nil
						}
						return []byte(" \n" + strings.Repeat("x", maxNFSCommandOutput+100) + "\n "), umountFailure
					case "umount timeout":
						if name == "mountpoint" {
							return nil, nil
						}
						<-ctx.Done()
						return nil, errors.New("umount process killed")
					default:
						t.Fatalf("unknown mode %q", tc.mode)
						return nil, nil
					}
				},
			}

			err := d.Teardown(ctx)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Teardown error = %v, want %v", err, tc.wantErr)
			}
			if strings.Join(calls, ",") != strings.Join(tc.wantCalls, ",") {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
			if tc.wantTrim && (!strings.Contains(err.Error(), "…") || strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), strings.Repeat("x", maxNFSCommandOutput+1))) {
				t.Fatalf("umount error output was not trimmed and bounded: %q", err)
			}
		})
	}
}
