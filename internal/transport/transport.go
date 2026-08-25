// Package transport and its subpackages carry a tunnel's bytes.
//
// A transport is a pair, never half of one: something that dials, and
// something that accepts. Both ends deal in net.Conn and nothing else, so
// every transport looks the same from above:
//
//	dial   func(ctx context.Context) (net.Conn, error)
//	accept net.Listener
//
// net.Listener is the accepting half even for transports that are not
// listeners underneath — the WebSocket one runs an HTTP server inside and
// hands upgraded connections out of Accept, so that the tunnel above never
// learns the difference.
//
// A transport contributes nothing to security. It may be a WebSocket over TLS
// or plain TCP; the session layer authenticates and encrypts on top either
// way, and the tunnel is exactly as safe. That is the whole reason this is a
// separate layer: choosing how to reach the sandbox is a networking decision,
// not a security one.
package transport
