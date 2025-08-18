package netunnel

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	SetLogLevel(LogLevelDebug)
}

func TestLogger(t *testing.T) {
	logCtx := NewLogID(context.TODO())
	logID := GetLogID(logCtx)
	assert.NotEmpty(t, logID)

	LogDebug(logCtx, "debug message test")

	LogInfo(logCtx, "info message test")

	LogError(logCtx, "error message test")

	LogFatal(logCtx, "fatal message test")
}

type customLogger struct {
	bytes.Buffer
}

func (c *customLogger) LogDebug(ctx context.Context, format string, v ...interface{}) {
	c.WriteString(fmt.Sprintf("[DEBUG] "+format+"\n", v...))
}

func (c *customLogger) LogInfo(ctx context.Context, format string, v ...interface{}) {
	c.WriteString(fmt.Sprintf("[INFO] "+format+"\n", v...))
}

func (c *customLogger) LogError(ctx context.Context, format string, v ...interface{}) {
	c.WriteString(fmt.Sprintf("[ERROR] "+format+"\n", v...))
}

func (c *customLogger) LogFatal(ctx context.Context, format string, v ...interface{}) {
	c.WriteString(fmt.Sprintf("[FATAL] "+format+"\n", v...))
}

func TestCustomLogger(t *testing.T) {
	old, newLogger := globalLogger, new(customLogger)
	SetLogger(newLogger)
	defer SetLogger(old)

	LogDebug(context.TODO(), "debug message test")
	LogInfo(context.TODO(), "info message test")
	LogError(context.TODO(), "error message test")
	LogFatal(context.TODO(), "fatal message test")
	assert.NotEmpty(t, newLogger.String())
	t.Log(newLogger.String())
}
