// Package netbox is a typed client for the NetBox REST API. It imports nothing
// from litevirt so it can be unit-tested in isolation against httptest.
package netbox

import (
	"errors"
	"fmt"
)

// ErrClass separates the three outcomes that mean different things to a caller.
// A 4xx is a real answer from NetBox (bad token, validation refusal); a 5xx or a
// transport failure is an AMBIGUOUS outcome, because the write may have
// committed before the response was lost.
type ErrClass int

const (
	ClassTransport ErrClass = iota // connection refused, timeout, DNS
	ClassClient                    // 4xx — NetBox answered, and said no
	ClassServer                    // 5xx — NetBox may or may not have committed
)

// APIError is a non-2xx response from NetBox.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("netbox: HTTP %d: %s", e.Status, e.Body)
}

// Classify maps an error to the class its caller must branch on. Anything that
// is not an APIError is a transport failure.
func Classify(err error) ErrClass {
	var ae *APIError
	if errors.As(err, &ae) {
		if ae.Status >= 500 {
			return ClassServer
		}
		return ClassClient
	}
	return ClassTransport
}
