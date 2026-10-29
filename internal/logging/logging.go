// Package logging builds a configurable slog logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/r2fn/go-ftproxy/internal/config"
)

// Setup returns a logger configured per cfg plus a closer for any opened file.
func Setup(cfg config.LogConfig) (*slog.Logger, func() error, error) {
	var lvl slog.Level
	switch strings.ToLower(cfg.Level) {
	case "", "info":
		lvl = slog.LevelInfo
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, nil, fmt.Errorf("log.level must be one of debug|info|warn|error, got %q", cfg.Level)
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var w io.Writer = os.Stdout
	closer := func() error { return nil }
	switch strings.ToLower(cfg.Output) {
	case "", "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("log.output: %w", err)
		}
		w = f
		closer = f.Close
	}

	var h slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("log.format must be text or json, got %q", cfg.Format)
	}
	return slog.New(h), closer, nil
}
