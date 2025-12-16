package otel

import (
	"context"
	"errors"
	"log/slog"
	"os"

	ddotel "github.com/DataDog/dd-trace-go/v2/ddtrace/opentelemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	ddotelv1 "gopkg.in/DataDog/dd-trace-go.v1/ddtrace/opentelemetry"

	"github.com/adalundhe/micron/internal/config"
)

// copy from open telemtry home page
// setupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func SetupOTelSDK(ctx context.Context, buildInfo config.BuildInfo) error {
	var (
		shutdownFuncs []func(context.Context) error
		err           error
	)

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown := func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Setup resource.
	res, err := newResource(buildInfo.Name(), buildInfo.Version())
	if err != nil {
		handleErr(err)
		return err
	}

	// Setup trace provider.
	tracerProvider, err := newTraceProvider(ctx, res)
	if err != nil {
		handleErr(err)
		return err
	}
	if v, ok := tracerProvider.(*sdktrace.TracerProvider); ok {
		shutdownFuncs = append(shutdownFuncs, v.Shutdown)
	} else if v, ok := tracerProvider.(*ddotel.TracerProvider); ok {
		shutdownFuncs = append(shutdownFuncs, func(ctx context.Context) error {
			return v.Shutdown()
		})
	} else if v, ok := tracerProvider.(*ddotelv1.TracerProvider); ok {
		shutdownFuncs = append(shutdownFuncs, func(ctx context.Context) error {
			return v.Shutdown()
		})
	} else {
		return errors.New("unknown tracer provider")
	}
	otel.SetTracerProvider(tracerProvider)

	// Set up logger provider.
	loggerProvider, err := newLoggerProvider(ctx, res)
	if err != nil {
		handleErr(err)
		return err
	}
	if os.Getenv("OTEL_LOG_EXPORT") == "true" {
		global.SetLoggerProvider(loggerProvider)
	}

	metricsProvider, err := newMeterProvider(ctx, res)
	if err != nil {
		handleErr(err)
		return err
	}
	if v, ok := metricsProvider.(*sdkmetric.MeterProvider); ok {
		shutdownFuncs = append(shutdownFuncs, v.Shutdown)
	} else {
		return errors.New("unknown meter provider")
	}

	otel.SetMeterProvider(metricsProvider)

	go func() {
		<-ctx.Done()

		if err := shutdown(ctx); err != nil {
			slog.Error("failed to shutdown otel", slog.Any("error", err))
		}
	}()

	return err
}

func newResource(serviceName, serviceVersion string) (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		))
}
