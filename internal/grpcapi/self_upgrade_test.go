package grpcapi

import "testing"

// chooseSelfUpgradeTarget converges every node to the NEWEST build reachable
// (highest schema; among equal schema, the strictly-newer semver version) so a
// single seeded node flows to the whole fleet — the only model that scales to a
// large cluster. It never downgrades schema, and never chases an unparseable
// (dev / ephemeral) version.
func TestChooseSelfUpgradeTarget(t *testing.T) {
	p := func(host, ver string, schema int) peerVersionInfo {
		return peerVersionInfo{host: host, version: ver, schema: schema}
	}

	cases := []struct {
		name     string
		myVer    string
		mySchema int
		peers    []peerVersionInfo
		wantOK   bool
		wantVer  string // expected target version (host is non-deterministic for ties)
	}{
		{
			name:  "schema-behind: pull the higher-schema peer",
			myVer: "v1.0.45", mySchema: 17,
			peers:  []peerVersionInfo{p("a", "v1.0.46", 18), p("b", "v1.0.46", 18)},
			wantOK: true, wantVer: "v1.0.46",
		},
		{
			name:  "NEWEST-WINS: a single newer same-schema peer is pulled (no majority needed)",
			myVer: "v1.0.45", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.46", 18), p("b", "v1.0.45", 18)},
			wantOK: true, wantVer: "v1.0.46",
		},
		{
			name:  "NEWEST-WINS: lone newer node among a same-version crowd still wins",
			myVer: "v1.0.45", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.45", 18), p("b", "v1.0.45", 18), p("c", "v1.0.46", 18)},
			wantOK: true, wantVer: "v1.0.46",
		},
		{
			name:  "pick the newest among several",
			myVer: "v1.0.44", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.45", 18), p("b", "v1.0.46", 18), p("c", "v1.0.45", 18)},
			wantOK: true, wantVer: "v1.0.46",
		},
		{
			name:  "I am already newest: do nothing",
			myVer: "v1.0.46", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.46", 18), p("b", "v1.0.45", 18)},
			wantOK: false,
		},
		{
			name:  "never downgrade schema: peers behind on schema",
			myVer: "v1.0.46", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.45", 17), p("b", "v1.0.45", 17)},
			wantOK: false,
		},
		{
			name:  "no peers",
			myVer: "v1.0.45", mySchema: 18,
			peers:  nil,
			wantOK: false,
		},
		{
			name:  "schema-ahead beats a newer same-schema version",
			myVer: "v1.0.45", mySchema: 17,
			// a is a newer VERSION but same (old) schema; b is a higher SCHEMA — schema wins.
			peers:  []peerVersionInfo{p("a", "v1.0.99", 17), p("b", "v1.0.45", 18)},
			wantOK: true, wantVer: "v1.0.45",
		},
		{
			name:  "ignore an unparseable (dev) version",
			myVer: "v1.0.45", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "dev", 18)},
			wantOK: false,
		},
		{
			name:  "an ephemeral build sorts below its base release (not chased)",
			myVer: "v1.0.45", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "v1.0.45-1-gabc123-eph", 18)},
			wantOK: false,
		},
		{
			name:  "prefer a valid release over an unparseable peer at the same schema",
			myVer: "v1.0.45", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "dev", 18), p("b", "v1.0.46", 18)},
			wantOK: true, wantVer: "v1.0.46",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := chooseSelfUpgradeTarget(c.myVer, c.mySchema, c.peers)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (got %+v)", ok, c.wantOK, got)
			}
			if ok && got.version != c.wantVer {
				t.Errorf("version=%q want %q", got.version, c.wantVer)
			}
			if ok && got.schema < c.mySchema {
				t.Errorf("target schema %d < mine %d (downgrade!)", got.schema, c.mySchema)
			}
		})
	}
}
