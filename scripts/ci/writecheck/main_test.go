package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

const header = `package sample

import "github.com/litevirt/litevirt/internal/corrosion"

func f(ctx interface{}, db *corrosion.Client) {
`

func TestWritecheck_FlagsBareCall(t *testing.T) {
	p := writeTemp(t, header+
		"\tcorrosion.UpdateVMState(nil, db, \"vm\", \"running\", \"\")\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 1 || v[0].fn != "UpdateVMState" {
		t.Fatalf("want 1 UpdateVMState violation, got %+v", v)
	}
}

func TestWritecheck_FlagsBlankAssign(t *testing.T) {
	p := writeTemp(t, header+
		"\t_ = corrosion.SetContainerStateDetail(nil, db, \"h\", \"c\", \"stopped\", \"\")\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 1 || v[0].fn != "SetContainerStateDetail" {
		t.Fatalf("want 1 SetContainerStateDetail violation, got %+v", v)
	}
}

func TestWritecheck_AllowsCheckedCall(t *testing.T) {
	p := writeTemp(t, header+
		"\tif err := corrosion.UpdateVMHost(nil, db, \"vm\", \"h\", \"running\"); err != nil {\n\t\t_ = err\n\t}\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("checked call should not be flagged, got %+v", v)
	}
}

func TestWritecheck_HonorsAllowDirective(t *testing.T) {
	p := writeTemp(t, header+
		"\tcorrosion.UpdateImageHostStatus(nil, db, \"img\", \"h\", \"pulling\") //writecheck:allow best-effort progress\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("allow directive should suppress the violation, got %+v", v)
	}
}

func TestWritecheck_FlagsGoAndDefer(t *testing.T) {
	p := writeTemp(t, header+
		"\tgo corrosion.UpdateVMState(nil, db, \"vm\", \"running\", \"\")\n"+
		"\tdefer corrosion.SetContainerState(nil, db, \"h\", \"c\", \"stopped\")\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 2 {
		t.Fatalf("want 2 violations (go + defer), got %d: %+v", len(v), v)
	}
}

func TestWritecheck_AllowDirectiveOnMultilineClosingLine(t *testing.T) {
	// The directive on the trailing `})` line of a multi-line call must suppress.
	p := writeTemp(t, header+
		"\tcorrosion.InsertImage(nil, db, corrosion.ImageRecord{\n"+
		"\t\tName: \"img\",\n"+
		"\t}) //writecheck:allow best-effort placeholder\n}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("allow directive on the closing line should suppress, got %+v", v)
	}
}

func TestWritecheck_IgnoresNonCorrosionAndReturn(t *testing.T) {
	p := writeTemp(t, header+
		"\tsomethingElse()\n}\n\nfunc g(ctx interface{}, db *corrosion.Client) error {\n"+
		"\treturn corrosion.UpdateVMState(nil, db, \"vm\", \"running\", \"\")\n}\n\nfunc somethingElse() {}\n")
	v, err := scanFile(p)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("returned call should not be flagged, got %+v", v)
	}
}
