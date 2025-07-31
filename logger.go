package netunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	globalLogger   Logger
	globalLogLevel atomic.Uint32
	loggerOnce     sync.Once
	logIDCtxKey    struct{}
)

type LogLevelType = uint32

const (
	LogLevelDebug LogLevelType = 1 << iota
	LogLevelInfo
	LogLevelError
	LogLevelFatal
)

func init() {
	globalLogger = newStdLogger()
	globalLogLevel.Store(LogLevelInfo)
}

func SetLogger(l Logger) {
	loggerOnce.Do(func() {
		globalLogger = l
	})
}

func SetLogLevel(level LogLevelType) {
	globalLogLevel.Store(level)
}

type Logger interface {
	LogFatal(ctx context.Context, format string, v ...interface{})
	LogError(ctx context.Context, format string, v ...interface{})
	LogInfo(ctx context.Context, format string, v ...interface{})
	LogDebug(ctx context.Context, format string, v ...interface{})
}

func LogFatal(ctx context.Context, format string, v ...interface{}) {
	if level := globalLogLevel.Load(); level > LogLevelFatal {
		return
	}
	if logID := GetLogID(ctx); len(logID) > 0 {
		format = logID + " " + format
	}
	globalLogger.LogFatal(ctx, format, v...)
}

func LogError(ctx context.Context, format string, v ...interface{}) {
	if level := globalLogLevel.Load(); level > LogLevelError {
		return
	}
	if logID := GetLogID(ctx); len(logID) > 0 {
		format = logID + " " + format
	}
	globalLogger.LogError(ctx, format, v...)
}

func LogInfo(ctx context.Context, format string, v ...interface{}) {
	if level := globalLogLevel.Load(); level > LogLevelInfo {
		return
	}
	if logID := GetLogID(ctx); len(logID) > 0 {
		format = logID + " " + format
	}
	globalLogger.LogInfo(ctx, format, v...)
}

func LogDebug(ctx context.Context, format string, v ...interface{}) {
	if level := globalLogLevel.Load(); level > LogLevelDebug {
		return
	}
	if logID := GetLogID(ctx); len(logID) > 0 {
		format = logID + " " + format
	}
	globalLogger.LogDebug(ctx, format, v...)
}

func NewLogID(ctx context.Context) context.Context {
	t := time.Now()
	buf := make([]byte, 16)
	io.ReadFull(rand.Reader, buf)
	suffix := strings.ToUpper(hex.EncodeToString(buf))
	logID := t.Format("20060102150405") + suffix
	return context.WithValue(ctx, logIDCtxKey, logID)
}

func GetLogID(ctx context.Context) string {
	val := ctx.Value(logIDCtxKey)
	if v, ok := val.(string); ok {
		return v
	}
	return ""
}

type stdLogger struct {
	logger *log.Logger
}

func newStdLogger() *stdLogger {
	l := log.New(os.Stderr, "", log.Lmicroseconds|log.Lshortfile)
	return &stdLogger{logger: l}
}

func (s *stdLogger) LogFatal(ctx context.Context, format string, v ...interface{}) {
	s.logger.Output(3, fmt.Sprintf("[FATAL] "+format, v...))
}

func (s *stdLogger) LogError(ctx context.Context, format string, v ...interface{}) {
	s.logger.Output(3, fmt.Sprintf("[ERROR] "+format, v...))
}

func (s *stdLogger) LogInfo(ctx context.Context, format string, v ...interface{}) {
	s.logger.Output(3, fmt.Sprintf("[INFO] "+format, v...))
}

func (s *stdLogger) LogDebug(ctx context.Context, format string, v ...interface{}) {
	s.logger.Output(3, fmt.Sprintf("[DEBUG] "+format, v...))
}
