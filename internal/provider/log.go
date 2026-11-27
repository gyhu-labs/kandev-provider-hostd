package provider

import (
	"fmt"
	"io"

	"github.com/hashicorp/go-hclog"
)

// NewLogger returns the plugin logger: hclog JSON lines on w.
//
// Kandev reads a plugin's stderr through go-plugin, which forwards a JSON
// line at its own @level and any other line without a [INFO]/[WARN]/[ERROR]
// prefix at Debug (go-plugin v1.8.0 client.go:1227-1248). Kandev logs at
// info, so plain log.Printf lines never reached the pod log. Pass the
// process's original os.Stderr, captured before pluginsdk.Serve: go-plugin
// swaps os.Stderr for a pipe that Kandev does not read.
//
// Callers must never log secrets; the messages carry ids, phases, durations
// and error texts only.
func NewLogger(w io.Writer) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:       "hostd",
		Output:     w,
		JSONFormat: true,
		Level:      hclog.Info,
	})
}

// LevelLogf adapts l to a printf-style func at level.
func LevelLogf(l hclog.Logger, level hclog.Level) func(format string, args ...any) {
	return func(format string, args ...any) {
		l.Log(level, fmt.Sprintf(format, args...))
	}
}
