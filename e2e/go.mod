module github.com/vivid-money/vtunnel/e2e

go 1.26.0

require (
	github.com/gorilla/websocket v1.5.3
	github.com/vivid-money/vtunnel v0.0.0
	golang.org/x/net v0.53.0
	google.golang.org/grpc v1.82.1
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/vivid-money/vtunnel => ../
