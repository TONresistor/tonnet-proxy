package client

import "context"

// ProxyClient defines the interface for proxy backends (circuit or direct)
type ProxyClient interface {
	// OpenStream opens a connection to the specified host:port
	OpenStream(ctx context.Context, host string, port int) (int, error)

	// SendData sends data on a stream
	SendData(ctx context.Context, streamID int, data []byte) error

	// RecvData receives data from a stream
	RecvData(ctx context.Context, streamID int) ([]byte, error)

	// CloseStream closes a specific stream
	CloseStream(streamID int)

	// Close closes the client
	Close() error
}
