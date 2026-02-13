package vtunnel

import "encoding/json"

// Message types
const (
	MsgListen    = "listen"     // client -> server: start listening on port
	MsgListenOK  = "listen_ok"  // server -> client: listen established
	MsgListenErr = "listen_err" // server -> client: listen failed
	MsgConnect   = "connect"    // server -> client: new connection accepted
	MsgData      = "data"       // bidirectional: data for a stream
	MsgClose     = "close"      // bidirectional: close a stream
	MsgPing      = "ping"       // client -> server: keepalive ping
	MsgPong      = "pong"       // server -> client: keepalive pong
)

// Message is the wire format for vtunnel protocol
type Message struct {
	Type     string `json:"type"`
	Port     int    `json:"port,omitempty"`
	StreamID uint32 `json:"stream_id,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Error    string `json:"error,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for Message
func (m *Message) MarshalJSON() ([]byte, error) {
	type Alias Message
	return json.Marshal((*Alias)(m))
}

// UnmarshalJSON implements custom JSON unmarshaling for Message
func (m *Message) UnmarshalJSON(data []byte) error {
	type Alias Message
	return json.Unmarshal(data, (*Alias)(m))
}
