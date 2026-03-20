package vtunnel

import "io"

// ReadMsg exports readMsg for testing.
var ReadMsg = readMsg

// WriteMsg exports writeMsg for testing.
func WriteMsg(w io.Writer, v any) error { return writeMsg(w, v) }
