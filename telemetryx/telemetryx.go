package telemetryx

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

const (
	otelEndpoint = "https://telemetry.cerberauth.com"
	timeout      = 1 * time.Second
)

var meterProvider *metric.MeterProvider

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
	meterProvider, err = newMeterProvider(ctx, res, serviceName)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)

	return shutdown, nil
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
