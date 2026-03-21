// Package logger provides structured logging via log/slog for the proxy.
package logger

import (
	"log/slog"
	"os"
)

// Init configures the default slog logger. When debug is true the minimum
// level is set to Debug; otherwise Info is used. Output goes to stderr so
// that stdout remains available for machine-readable output.
func Init(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}
