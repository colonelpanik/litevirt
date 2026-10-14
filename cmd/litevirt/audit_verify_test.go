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

// The third outcome. `never adopted` is the one finding derived from a row any
// peer can write, so it must fail the command WITHOUT using the word an operator
// scans for — otherwise anyone who can reach the cluster can make `lv audit
// verify` cry tampering about a host that did nothing.
func TestAuditVerifyNeverAdoptedFailsWithoutClaimingTampering(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked:  12,
		UnsignedRows: 12,
		Unverified:   true,
		NeverAdopted: []string{"node-4: published signing certificate abc but never recorded an adoption"},
	})
	if err == nil {
		t.Fatal("a host declaring signed rows it cannot sign exited 0")
	}
	got := out.String()
	if strings.Contains(got, "TAMPERED") {
		t.Errorf("a forgeable finding is reported as tampering: %q", got)
	}
	if !strings.Contains(got, "COULD NOT BE VERIFIED") {
		t.Errorf("output does not name the outcome: %q", got)
	}
	if !strings.Contains(got, "node-4") {
		t.Errorf("the affected host is not named: %q", got)
	}
	// The operator has to be told the remedy is an authenticated one, or they will
	// go looking for a way to delete the row — which is deliberately not there.
	if !strings.Contains(got, "retire-audit-key") {
		t.Errorf("output does not say how to clear it: %q", got)
	}
}

// The headline must state the outcome. The unverified path used to print
// "audit chain intact ... all signed" first and contradict itself four lines
// later, so the first line of a run that exits 1 read as a pass — which is what
// an operator scanning output and a CI job grepping for "intact" both see.
func TestAuditVerifyUnverifiedHeadlineDoesNotSayIntact(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked:  12,
		UnsignedRows: 12,
		Unverified:   true,
		NeverAdopted: []string{"node-4: published a signing certificate but never adopted"},
	})
	if err == nil {
		t.Fatal("the unverified outcome exited 0")
	}
	first, _, _ := strings.Cut(out.String(), "\n")
	if strings.Contains(first, "intact") {
		t.Errorf("the first line of a failing run reads as a pass: %q", first)
	}
	if !strings.Contains(first, "NOT FULLY VERIFIED") {
		t.Errorf("the headline does not state the outcome: %q", first)
	}
	// The unsigned count still has to be visible — it is the context for the rest.
	if !strings.Contains(out.String(), "12 predate tamper-evidence") {
		t.Errorf("the unsigned count was dropped from the unverified path: %q", out.String())
	}
}

func TestAuditVerifyConsumesTheDaemonUnverifiedVerdict(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked: 77,
		Unverified:  true,
	})
	if err == nil {
		t.Fatal("daemon Unverified=true was re-derived as a clean CLI verdict")
	}
	if !strings.Contains(out.String(), "NOT FULLY VERIFIED") {
		t.Fatalf("CLI did not report the daemon's verdict: %q", out.String())
	}
}

// A row with a NUL in a hashed field has a hash that does not determine its
// content, so it must fail the run. It is not tampering — an older build wrote
// such rows verbatim — so it must not say TAMPERED, and the row has to be named.
func TestAuditVerifyAmbiguousRowsFailWithoutClaimingTampering(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked:   3,
		Unverified:    true,
		AmbiguousRows: []string{"row-7: node-1: field target contains a NUL byte"},
	})
	if err == nil {
		t.Fatal("an ambiguous row exited 0")
	}
	got := out.String()
	if strings.Contains(got, "TAMPERED") {
		t.Errorf("an ambiguous row is reported as tampering: %q", got)
	}
	if !strings.Contains(got, "row-7") {
		t.Errorf("the ambiguous row is not named: %q", got)
	}
	if strings.Contains(got, "inspect its logs") {
		t.Errorf("a named finding fell through to the unspecified message: %q", got)
	}
}

// The first broken link is named for what it is. A forked chain — a second
// chain opened at seq 1 with an empty prev_hash under a host name that already
// had one — hashes correctly and is not an edit; printing it under "row content
// does not match its recorded hash" sent the lab 1 investigation looking for
// tampering that had not happened. It still fails the command.
func TestAuditVerifyNamesTheKindOfBreak(t *testing.T) {
	const contentLabel = "row content does not match its recorded hash"
	for _, tc := range []struct {
		kind      string
		want      string
		notWanted string
	}{
		{"forked", "forked chain", contentLabel},
		{"unlinked", "does not link to the row before it", contentLabel},
		{"content", contentLabel, "forked chain"},
		// A daemon older than broken_at_kind sends none; its only label was the
		// content one, and that is what an empty kind still prints.
		{"", contentLabel, "forked chain"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var out strings.Builder
			err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
				RowsChecked: 12, BrokenAtId: "b9fbdd30", BrokenAtKind: tc.kind, Tampered: true,
			})
			if err == nil {
				t.Fatal("a broken link must still exit non-zero")
			}
			got := out.String()
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "b9fbdd30") {
				t.Errorf("kind %q: output lacks %q or the row id:\n%s", tc.kind, tc.want, got)
			}
			if strings.Contains(got, tc.notWanted) {
				t.Errorf("kind %q: output says %q:\n%s", tc.kind, tc.notWanted, got)
			}
		})
	}
}

// Re-review m-3: an orphaned row (a deletion a fork hides) is named, under
// its own heading, so the operator can act on the finding the hourly check
// reports.
//
// Mutation: the orphaned group not printed — red.
func TestAuditVerifyNamesOrphanedRows(t *testing.T) {
	var out strings.Builder
	err := reportAuditVerify(&out, &pb.VerifyAuditChainResponse{
		RowsChecked: 12, BrokenAtId: "fork-1", BrokenAtKind: "forked", Tampered: true,
		SeqGaps:      []string{"node-3: row fork-1 repeats seq 1 (duplicate: two rows claim the same position, a forked chain)"},
		OrphanedRows: []string{"node-3: row r3 (seq 3) follows prev_hash abc, which is the hash of no row of node-3 at seq 2 — the row before it was deleted"},
	})
	if err == nil {
		t.Fatal("an orphaned row must fail the command")
	}
	got := out.String()
	for _, want := range []string{"orphaned (on a forked host, the row before it was deleted or rewritten, or it was renumbered or relinked", "node-3: row r3 (seq 3)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// A chain whose only finding is a fork must not be headlined TAMPERED: nothing
// found says a row was edited, deleted or forged. It still fails the command,
// and the row is still named. Any other finding keeps the TAMPERED headline.
//
// Mutation: header ignores resp.Forked — red.
func TestAuditVerifyHeaderMatchesTheClassification(t *testing.T) {
	fork := &pb.VerifyAuditChainResponse{
		RowsChecked: 12, BrokenAtId: "fork-1", BrokenAtKind: "forked", Tampered: true, Forked: true,
		SeqGaps: []string{"node-3: row fork-1 repeats seq 1 (duplicate: two rows claim the same position, a forked chain)"},
	}
	var out strings.Builder
	if err := reportAuditVerify(&out, fork); err == nil {
		t.Fatal("a forked chain must still exit non-zero")
	}
	got := out.String()
	if strings.Contains(got, "TAMPERED") || !strings.Contains(got, "AUDIT CHAIN FORKED") || !strings.Contains(got, "fork-1") {
		t.Errorf("fork-only output is mislabelled:\n%s", got)
	}

	// A real tamper finding keeps its headline, including when the response
	// also claims Forked (the CLI does not trust that flag alone).
	for _, forked := range []bool{false, true} {
		real := &pb.VerifyAuditChainResponse{
			RowsChecked: 12, BrokenAtId: "fork-1", BrokenAtKind: "forked", Tampered: true, Forked: forked,
			BadSignature: []string{"row-8: signature does not verify"},
		}
		out.Reset()
		if err := reportAuditVerify(&out, real); err == nil {
			t.Fatal("tampering must exit non-zero")
		}
		if got := out.String(); !strings.Contains(got, "AUDIT CHAIN TAMPERED") || strings.Contains(got, "FORKED —") {
			t.Errorf("forked=%v: a real tamper finding lost its headline:\n%s", forked, got)
		}
	}
}
