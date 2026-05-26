package coverage

import "errors"

// ErrCSPUnavailable is returned when the CSP endpoint cannot be reached
// (connection refused, DNS failure, network error). Callers can distinguish
// "target is down" from "target returned an error status".
var ErrCSPUnavailable = errors.New("coverage: CSP endpoint unreachable")

// ErrCSPBadStatus is returned when the CSP endpoint responds with a
// non-2xx HTTP status. Wrapped with the actual status code:
//
//	fmt.Errorf("%w: status %d", ErrCSPBadStatus, code)
var ErrCSPBadStatus = errors.New("coverage: CSP returned non-2xx status")

// ErrCSPInvalidResponse is returned when /csp/dump responds with invalid
// JSON or a JSON body that does not match the expected schema.
var ErrCSPInvalidResponse = errors.New("coverage: invalid CSP response")
