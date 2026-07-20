package doctor

import (
	"context"
	"net"
	"os"
)

// ProbeResult contains only booleans and never credential contents.
type ProbeResult struct {
	TokenFileReadable bool `json:"token_file_readable"`
	TokenFileWritable bool `json:"token_file_writable"`
	BrokerEnvReadable bool `json:"broker_env_readable"`
	SocketConnectable bool `json:"socket_connectable"`
}

// CanOpen reports whether the current process can open path for reading.
func CanOpen(path string) bool {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied doctor probe path.
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// CanOpenForWrite reports whether the current process can open path for writing.
func CanOpenForWrite(path string) bool {
	file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- operator-supplied doctor probe path.
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// DialUnix reports whether the current process can connect to socket.
func DialUnix(ctx context.Context, socket string) bool {
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}
