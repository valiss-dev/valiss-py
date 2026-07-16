module github.com/valiss-dev/valiss-py/tests/interop

go 1.26.4

require (
	github.com/nats-io/nkeys v0.4.16
	valiss.dev/valiss v0.12.0
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace valiss.dev/valiss => ../../../valiss-go
