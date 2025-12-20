package otel

import (
	"context"
	"log/slog"
	"os"
	"strings"

	slogmulti "github.com/samber/slog-multi"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

func newLoggerProvider(ctx context.Context, res *resource.Resource) (*log.LoggerProvider, error) {
	// datadog has no direct logger provider, so just use otel
	return newOtelLoggerProvider(ctx, res)
}

func newOtelLoggerProvider(ctx context.Context, res *resource.Resource) (*log.LoggerProvider, error) {
	var (
		handlers       []slog.Handler
		loggerProvider *log.LoggerProvider
	)

	// Get log level from environment variable (same as CLI tool)
	level := strings.ToLower(os.Getenv("LOG_LEVEL"))
	var slogLevel slog.Level

	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	// currently getting `unknown service opentelemetry.proto.collector.logs.v1.LogsService` on the dd agent when trying to export logs
	// have this disabled unless explicitly enabled so we can test if needed
	if os.Getenv("OTEL_LOG_EXPORT") == "true" {
		logExporter, err := otlploggrpc.New(ctx)
		if err != nil {
			return nil, err
		}
		loggerProvider := log.NewLoggerProvider(
			log.WithProcessor(log.NewBatchProcessor(logExporter)),
			log.WithResource(res),
		)
		handlers = append(handlers, otelslog.NewHandler("micron_logger", otelslog.WithLoggerProvider(loggerProvider)))
	}

	handlers = append(handlers, slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	}))

	slogFan := slogmulti.Fanout(handlers...)

	slog.SetDefault(slog.New(slogFan))

	// Log the logger initialization (similar to CLI tool)
	slog.Info("Logger initialized", "level", slogLevel.String())

	return loggerProvider, nil
}
