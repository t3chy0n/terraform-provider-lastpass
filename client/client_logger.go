package client

import "context"

type key int

const (
	loggerKey key = iota
)

// Logger is the interface which wraps the Printf method.
type Logger interface {
	Printf(format string, v ...interface{})
}

// NewContextWithLogger returns a new context with logging enabled.
func NewContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func (c *LastPassClient) log(format string, v ...interface{}) {

	if c.ctx != nil {

		if logger, ok := (*c.ctx).Value(loggerKey).(Logger); ok {
			logger.Printf(format, v...)
		}
	}

	if c.logger != nil {
		(*c.logger).Printf(format, v...)
	}
}
