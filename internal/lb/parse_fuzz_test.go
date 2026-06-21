package lb

import "testing"

// FuzzParseVIP drives the string parser the LB relies on for keepalived
// VIP config. Property: never panics. Errors are fine; runtime crashes
// in production from malformed user input are not.
func FuzzParseVIP(f *testing.F) {
	for _, s := range []string{
		"10.0.100.100/24",
		"::1/128",
		"",
		"abc",
		"1.2.3.4",
		"1.2.3.4/notanumber",
		"1.2.3.4/-1",
		"1.2.3.4/999",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = ParseVIP(s)
	})
}
