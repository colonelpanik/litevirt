package grpcapi

import "testing"

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
			name: "schema-behind: pull the higher-schema peer",
			myVer: "old", mySchema: 17,
			peers:   []peerVersionInfo{p("a", "new", 18), p("b", "new", 18)},
			wantOK:  true, wantVer: "new",
		},
		{
			name: "same-schema majority drift: pull the majority version",
			myVer: "old", mySchema: 18,
			peers:   []peerVersionInfo{p("a", "new", 18), p("b", "new", 18), p("c", "new", 18)},
			wantOK:  true, wantVer: "new", // 3 peers + me = 4; majority 3; "new" has 3
		},
		{
			name: "no majority at same schema: do nothing",
			myVer: "old", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "new", 18), p("b", "other", 18)}, // me+2=3, majority 2; new=1, other=1
			wantOK: false,
		},
		{
			name: "everyone agrees with me: do nothing",
			myVer: "cur", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "cur", 18), p("b", "cur", 18)},
			wantOK: false,
		},
		{
			name: "never downgrade: peers behind on schema",
			myVer: "new", mySchema: 18,
			peers:  []peerVersionInfo{p("a", "old", 17), p("b", "old", 17)},
			wantOK: false,
		},
		{
			name: "no peers",
			myVer: "x", mySchema: 18,
			peers:  nil,
			wantOK: false,
		},
		{
			name: "schema-behind beats a same-schema majority",
			myVer: "old", mySchema: 17,
			peers:   []peerVersionInfo{p("a", "mid", 17), p("b", "mid", 17), p("c", "newest", 18)},
			wantOK:  true, wantVer: "newest",
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
