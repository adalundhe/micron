package otel

import (
	"context"
	"os"
	"time"

	// orchestration appears to only be able to tie spans together with sdkv1. for now we will use sdkv1
	//ddotel "github.com/DataDog/dd-trace-go/v2/ddtrace/opentelemetry"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	ddotel "gopkg.in/DataDog/dd-trace-go.v1/ddtrace/opentelemetry"
)

func newTraceProvider(ctx context.Context, res *resource.Resource) (trace.TracerProvider, error) {
	if os.Getenv("TRACE_PROVIDER") == "otel" {
		return newOtelTraceProvider(ctx, res)
	} else {
		return newDDTraceProvider(ctx, res)
	}
}

func newOtelTraceProvider(ctx context.Context, res *resource.Resource) (trace.TracerProvider, error) {
	var (
		err           error
		traceExporter sdktrace.SpanExporter
	)
	if os.Getenv("ENVIRONMENT") == "local" {
		traceExporter, err = stdouttrace.New()
	} else {
		traceExporter, err = otlptracegrpc.New(ctx)
	}
	if err != nil {
		return nil, err
	}

	traceProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			sdktrace.WithBatchTimeout(time.Second)),
		sdktrace.WithResource(res),
	)

	return traceProvider, nil
}

func newDDTraceProvider(ctx context.Context, res *resource.Resource) (trace.TracerProvider, error) {
	return ddotel.NewTracerProvider(), nil
}
