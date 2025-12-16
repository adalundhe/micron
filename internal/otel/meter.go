package otel

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

func newMeterProvider(ctx context.Context, res *resource.Resource) (metric.MeterProvider, error) {
	// datadog has no direct meter provider, so just use otel
	return newOtelMeterProvider(ctx, res)
}

func newOtelMeterProvider(ctx context.Context, res *resource.Resource) (metric.MeterProvider, error) {
	var (
		err            error
		metricExporter sdkmetric.Exporter
	)
	if os.Getenv("ENVIRONMENT") == "local" {
		metricExporter, err = stdoutmetric.New()
	} else {
		metricExporter, err = otlpmetricgrpc.New(ctx)
	}
	if err != nil {
		return nil, err
	}

	var metricOptions []sdkmetric.PeriodicReaderOption

	if os.Getenv("OTEL_DISABLE_RUNTIME_METRICS") != "true" {
		metricOptions = append(metricOptions, sdkmetric.WithProducer(runtime.NewProducer()))
		metricOptions = append(metricOptions, sdkmetric.WithInterval(15*time.Second))
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter,
			metricOptions...,
		)),
		sdkmetric.WithResource(res),
	)

	if os.Getenv("OTEL_DISABLE_RUNTIME_METRICS") != "true" {
		runtime.Start(runtime.WithMeterProvider(meterProvider))
	}

	return meterProvider, nil
}
