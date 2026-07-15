package corrosion

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

// TestEncodeRowCellsV2_GoldenVectors is BYTE-FROZEN: a change here re-fingerprints every
// row under digest_v2 and forces a resync across the version boundary — don't change these
// expected strings.
func TestEncodeRowCellsV2_GoldenVectors(t *testing.T) {
	cases := []struct {
		cols []string
		vals []interface{}
		want string
	}{
		{[]string{"a"}, []interface{}{nil}, "1:a=N;"},
		{[]string{"a"}, []interface{}{"hello"}, "1:a=V5:hello"},
		{[]string{"a"}, []interface{}{""}, "1:a=V0:"},
		{[]string{"a"}, []interface{}{int64(42)}, "1:a=V2:42"},
		{[]string{"a"}, []interface{}{float64(42)}, "1:a=V2:42"},
		{[]string{"a"}, []interface{}{int64(5000000000)}, "1:a=V10:5000000000"},
		{[]string{"a"}, []interface{}{true}, "1:a=V4:true"},
		{[]string{"a"}, []interface{}{false}, "1:a=V5:false"},
		{[]string{"a"}, []interface{}{[]byte("x")}, "1:a=V1:x"},
		{[]string{"a"}, []interface{}{float64(42.5)}, "1:a=V4:42.5"},
		{[]string{"a"}, []interface{}{"V1:x=N;"}, "1:a=V7:V1:x=N;"}, // delimiter-like data
		{[]string{"col", "b"}, []interface{}{"x", "y"}, "1:b=V1:y3:col=V1:x"},
		{[]string{"a", "bb"}, []interface{}{nil, "z"}, "1:a=N;2:bb=V1:z"},
	}
	for _, tc := range cases {
		got, err := encodeRowCellsV2(tc.cols, tc.vals)
		if err != nil {
			t.Errorf("encodeRowCellsV2(%v,%v) error: %v", tc.cols, tc.vals, err)
			continue
		}
		if got != tc.want {
			t.Errorf("encodeRowCellsV2(%v,%v) = %q, want %q", tc.cols, tc.vals, got, tc.want)
		}
	}
}

// TestEncodeRowCellsV2_OrderInvariant: the same name→value mapping in two different
// physical column orders must encode identically (the whole point of digest_v2).
func TestEncodeRowCellsV2_OrderInvariant(t *testing.T) {
	a, err1 := encodeRowCellsV2([]string{"name", "state", "cpu"}, []interface{}{"vm1", "running", int64(2)})
	b, err2 := encodeRowCellsV2([]string{"state", "cpu", "name"}, []interface{}{"running", int64(2), "vm1"})
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v %v", err1, err2)
	}
	if a != b {
		t.Errorf("column reorder changed the v2 encoding:\n a=%q\n b=%q", a, b)
	}
}

func TestEncodeRowCellsV2_RealDifferenceStillDiffers(t *testing.T) {
	a, _ := encodeRowCellsV2([]string{"name", "state"}, []interface{}{"vm1", "running"})
	b, _ := encodeRowCellsV2([]string{"name", "state"}, []interface{}{"vm1", "stopped"})
	if a == b {
		t.Error("a genuine value difference must still change the v2 encoding")
	}
}

func TestEncodeRowCellsV2_DupNameRejected(t *testing.T) {
	if _, err := encodeRowCellsV2([]string{"a", "a"}, []interface{}{"1", "2"}); !errors.Is(err, ErrDupColumn) {
		t.Errorf("duplicate column name must return ErrDupColumn, got %v", err)
	}
}

// TestCanonicalCellValue_CrossPath: logically equal values from the two read paths
// (direct-SQL int64/float64 vs JSON-dump json.Number) must canonicalize identically.
func TestCanonicalCellValue_CrossPath(t *testing.T) {
	eq := func(a, b interface{}) {
		t.Helper()
		ca, ea := canonicalCellValue(a)
		cb, eb := canonicalCellValue(b)
		if ea != nil || eb != nil {
			t.Fatalf("unexpected error: %v / %v", ea, eb)
		}
		if ca != cb {
			t.Errorf("canonicalCellValue(%v=%q) != canonicalCellValue(%v=%q)", a, ca, b, cb)
		}
	}
	eq(int64(42), float64(42))
	eq(int64(42), json.Number("42"))
	eq(int64(5000000000), float64(5000000000))
	eq(int64(5000000000), json.Number("5e9"))     // exponent form normalizes
	eq(int64(9007199254740993), json.Number("9007199254740993")) // 2^53+1 lossless via big.Int
	eq(float64(0), math.Copysign(0, -1))           // -0 == 0
	eq("x", []byte("x"))
	// non-finite is corruption
	if _, err := canonicalCellValue(math.Inf(1)); err == nil {
		t.Error("non-finite float must error")
	}
	if _, err := canonicalCellValue(math.NaN()); err == nil {
		t.Error("NaN must error")
	}
}
