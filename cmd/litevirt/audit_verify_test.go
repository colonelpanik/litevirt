package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The exit code is the only part of `lv audit verify` a monitoring system
// reads, so it must track Tampered and nothing else. An unsigned row exiting
// non-zero would page someone on every cluster that has not finished rolling
// out signing; a bad signature exiting zero would page nobody at all.
func TestAuditVerifyExitCodeTracksTamperedOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resp    *pb.VerifyAuditChainResponse
		wantErr bool
	}{
		{"clean and signed", &pb.VerifyAuditChainResponse{RowsChecked: 12}, false},
		{"unsigned rows only", &pb.VerifyAuditChainResponse{RowsChecked: 12, UnsignedRows: 12}, false},
		{"no keyring to check with", &pb.VerifyAuditChainResponse{RowsChecked: 12, UnverifiableRows: 4}, false},
		{"rows with no host", &pb.VerifyAuditChainResponse{RowsChecked: 12, UnattributedRows: 2}, false},
		{"hash mismatch", &pb.VerifyAuditChainResponse{RowsChecked: 12, BrokenAtId: "r7", Tampered: true}, true},
		{"bad signature", &pb.VerifyAuditChainResponse{
			RowsChecked: 12, BadSignature: []string{"r7: bad"}, Tampered: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			err := reportAuditVerify(&out, tc.resp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error: %v (output: %s)", err, tc.wantErr, out.String())
			}
		})
	}
}

// A clean run must never use the word an operator scans for. If "tampered"
// appears on the unsigned path they learn to ignore it, and the one run that
// matters looks like all the others.
func TestAuditVerifyCleanOutputNeverSaysTampered(t *testing.T) {
	for _, resp := range []*pb.VerifyAuditChainResponse{
		{RowsChecked: 12},
		{RowsChecked: 12, UnsignedRows: 12},
		{RowsChecked: 12, UnsignedRows: 3, UnverifiableRows: 2, UnattributedRows: 1},
	} {
		var out strings.Builder
		if err := reportAuditVerify(&out, resp); err != nil {
			t.Fatalf("clean result returned error: %v", err)
		}
		got := out.String()
		if strings.Contains(strings.ToLower(got), "tamper") && !strings.Contains(got, "predate tamper-evidence") {
			t.Errorf("clean output mentions tampering: %q", got)
		}
		if !strings.Contains(got, "audit chain intact") {
			t.Errorf("clean output missing the intact line: %q", got)
		}
	}
	// The unsigned count has to be on screen, not implied by its absence —
	// "12 rows verified" alone reads as "12 rows are tamper-evident".
	var out strings.Builder
	_ = reportAuditVerify(&out, &pb.VerifyAuditChainResponse{RowsChecked: 12, UnsignedRows: 12})
	if !strings.Contains(out.String(), "12 predate tamper-evidence") {
		t.Errorf("unsigned count not reported: %q", out.String())
	}
}

// Every category that fired has to be printed with its rows. Reporting only the
// first one hides the shape of the attack: a hash break next to a sequence gap
// is a deleted run of rows, and an operator shown only the break will go
// looking for disk corruption.
func TestAuditVerifyPrintsEveryCategory(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked:    40,
		BrokenAtId:     "row-7",
		BadSignature:   []string{"row-8: signature does not verify"},
		UnknownKeyId:   []string{"row-9: no published certificate"},
		SeqGaps:        []string{"node-b: row row-10 has seq 14 after 11"},
		Laundered:      []string{"row-11"},
		TruncatedHosts: []string{"node-c: head attests 90 rows, 40 present"},
		UnsignedRows:   5,
		Tampered:       true,
	})
	if err == nil {
		t.Fatal("tampered result must return an error so main.go exits 1")
	}
	got := out.String()
	for _, want := range []string{
		"TAMPERED",
		"row-7",
		"row-8: signature does not verify",
		"row-9: no published certificate",
		"node-b: row row-10 has seq 14 after 11",
		"row-11",
		"node-c: head attests 90 rows, 40 present",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// The unsigned count is context here, not a finding — it must be labelled
	// as such so it is not counted among the evidence.
	if !strings.Contains(got, "not tampering, for context") {
		t.Errorf("unsigned rows not separated from the findings:\n%s", got)
	}
}
