package telemetryx

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
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

var newReader = func(ctx context.Context, opts ...otlpmetrichttp.Option) (metric.Reader, error) {
	exp, err := newMetricExporter(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return metric.NewPeriodicReader(exp), nil
}

type options struct {
	commit string
	date   string
}

type Option func(*options)

func WithCommit(commit string) Option {
	return func(o *options) {
		o.commit = commit
	}
}

func WithBuildDate(date string) Option {
	return func(o *options) {
		o.date = date
	}
}

func New(ctx context.Context, serviceName string, version string, opts ...Option) (func(context.Context) error, error) {
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

	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	res, err := newResource(ctx, serviceName, version, opts...)
	if err != nil {
		handleErr(err)
		return nil, err
	}

	reader, err := newReader(ctx, otlpmetrichttp.WithEndpointURL(otelEndpoint))
	if err != nil {
		handleErr(err)
		return nil, err
	}

	meterProvider = newMeterProvider(res, reader)
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)

	return shutdown, nil
}

var noopProvider = metric.NewMeterProvider()

func GetMeterProvider() *metric.MeterProvider {
	if meterProvider == nil {
		return noopProvider
	}

	return meterProvider
}

func newResource(ctx context.Context, serviceName string, version string, opts ...Option) (*resource.Resource, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(version),
	}
	if o.commit != "" {
		attrs = append(attrs, attribute.String("vcs.repository.ref.revision", o.commit))
	}
	if o.date != "" {
		attrs = append(attrs, attribute.String("service.build.date", o.date))
	}

	return resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithProcessRuntimeVersion(),
		resource.WithAttributes(attrs...),
	)
}

func newMetricExporter(ctx context.Context, opts ...otlpmetrichttp.Option) (metric.Exporter, error) {
	return otlpmetrichttp.New(ctx, append(
		[]otlpmetrichttp.Option{
			otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
			otlpmetrichttp.WithTimeout(timeout),
			otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
		},
		opts...,
	)...)
}

func newMeterProvider(res *resource.Resource, reader metric.Reader) *metric.MeterProvider {
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(reader),
	)
}
