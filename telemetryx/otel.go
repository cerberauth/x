package telemetryx

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

const (
	otelEndpoint = "https://telemetry.cerberauth.com"
	timeout      = 1 * time.Second
)

var (
	tracerProvider *trace.TracerProvider
	meterProvider  *metric.MeterProvider
)

func New(ctx context.Context, serviceName string, version string) (func(context.Context) error, error) {
	var shutdownFuncs []func(context.Context) error
	var err error

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

	res := newResource(serviceName, version)

	tracerProvider, err = newTracerProvider(ctx, res)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)

	meterProvider, err = newMeterProvider(ctx, res, serviceName)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)

	return shutdown, nil
}

func GetTracerProvider() *trace.TracerProvider {
	if tracerProvider == nil {
		noopTracerProvider := trace.NewTracerProvider()
		return noopTracerProvider
	}

	return tracerProvider
}

func GetMeterProvider() *metric.MeterProvider {
	if meterProvider == nil {
		noopMeterProvider := metric.NewMeterProvider()
		return noopMeterProvider
	}

	return meterProvider
}

func newResource(serviceName string, version string) *resource.Resource {
	res, _ := resource.New(
		context.Background(),
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithProcessRuntimeVersion(),
		resource.WithAttributes(semconv.ServiceNameKey.String(serviceName), semconv.ServiceVersionKey.String(version)),
	)

	return res
}

func newTracerProvider(ctx context.Context, res *resource.Resource, opts ...otlptracehttp.Option) (*trace.TracerProvider, error) {
	exporter, err := otlptracehttp.New(ctx, append(
		opts,
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		otlptracehttp.WithTimeout(timeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		otlptracehttp.WithEndpointURL(otelEndpoint),
	)...)
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter, trace.WithBatchTimeout(timeout)),
		trace.WithResource(res),
	)
	return tp, nil
}

func newMeterProvider(ctx context.Context, res *resource.Resource, serviceName string, opts ...otlpmetrichttp.Option) (*metric.MeterProvider, error) {
	metricExporter, err := otlpmetrichttp.New(ctx, append(
		opts,
		otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		otlpmetrichttp.WithTimeout(timeout),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
		otlpmetrichttp.WithEndpointURL(otelEndpoint),
	)...)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter)),
	)

	return meterProvider, nil
}
