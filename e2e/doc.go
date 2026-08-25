// Package e2e holds end-to-end tests that need dependencies the library itself
// does not: a real gRPC client and server, for one. It is a separate module so
// those dependencies stay out of github.com/vivid-money/vtunnel's go.mod and
// never reach anyone importing the library.
//
// It has no non-test code, and nothing imports it.
package e2e
