package otelx

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	globallog "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

type options struct {
	endpoint string
	timeout  time.Duration
	headers  map[string]string
	commit   string
	date     string
}

// Option configures otelx.New.
type Option func(*options)

func WithEndpoint(url string) Option {
	return func(o *options) { o.endpoint = url }
}

func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithHeaders sets exporter headers. Pass a non-nil map (even empty) to
// override OTEL_EXPORTER_OTLP_HEADERS; pass nil to let the env var apply.
func WithHeaders(h map[string]string) Option {
	return func(o *options) { o.headers = h }
}

func WithCommit(commit string) Option {
	return func(o *options) { o.commit = commit }
}

func WithBuildDate(date string) Option {
	return func(o *options) { o.date = date }
}

// Seams for test injection — override in _test.go files.
var (
	newMetricReader = func(ctx context.Context, opts ...otlpmetrichttp.Option) (sdkmetric.Reader, error) {
		exp, err := otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return nil, err
		}
		return sdkmetric.NewPeriodicReader(exp), nil
	}
	newTraceExporter = func(ctx context.Context, opts ...otlptracehttp.Option) (sdktrace.SpanExporter, error) {
		return otlptracehttp.New(ctx, opts...)
	}
	newLogExporter = func(ctx context.Context, opts ...otlploghttp.Option) (sdklog.Exporter, error) {
		return otlploghttp.New(ctx, opts...)
	}
)

// New initialises OTLP/HTTP exporters for metrics, traces, and logs, sets the
// three OTel global providers, and returns a single shutdown function that
// flushes and stops all providers in reverse order (log → trace → metric).
//
// When WithEndpoint is not supplied, OTEL_EXPORTER_OTLP_ENDPOINT (and its
// signal-specific variants) apply as per the standard SDK precedence rules.
func New(ctx context.Context, serviceName, version string, opts ...Option) (func(context.Context) error, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	var shutdownFuncs []func(context.Context) error
	var err error

	shutdown := func(ctx context.Context) error {
		var errs error
		for i := len(shutdownFuncs) - 1; i >= 0; i-- {
			errs = errors.Join(errs, shutdownFuncs[i](ctx))
		}
		shutdownFuncs = nil
		return errs
	}

	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	res, err := newResource(ctx, serviceName, version, o)
	if err != nil {
		handleErr(err)
		return nil, err
	}

	mp, err := newMeterProvider(ctx, res, o)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, mp.Shutdown)
	otel.SetMeterProvider(mp)

	tp, err := newTracerProvider(ctx, res, o)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, tp.Shutdown)
	otel.SetTracerProvider(tp)

	lp, err := newLoggerProvider(ctx, res, o)
	if err != nil {
		handleErr(err)
		return nil, err
	}
	shutdownFuncs = append(shutdownFuncs, lp.Shutdown)
	globallog.SetLoggerProvider(lp)

	return shutdown, nil
}

// newResource builds an OTel resource. resource.WithFromEnv is intentionally
// omitted so OTEL_RESOURCE_ATTRIBUTES / OTEL_SERVICE_NAME cannot override
// the programmatically supplied values.
func newResource(ctx context.Context, serviceName, version string, o *options) (*resource.Resource, error) {
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
	return resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithProcessRuntimeVersion(),
		resource.WithFromEnv(),
		resource.WithAttributes(attrs...),
	)
}

func newMeterProvider(ctx context.Context, res *resource.Resource, o *options) (*sdkmetric.MeterProvider, error) {
	exportOpts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
	}
	if o.timeout != 0 {
		exportOpts = append(exportOpts, otlpmetrichttp.WithTimeout(o.timeout))
	}
	if o.endpoint != "" {
		exportOpts = append(exportOpts, otlpmetrichttp.WithEndpointURL(o.endpoint))
	}
	if o.headers != nil {
		exportOpts = append(exportOpts, otlpmetrichttp.WithHeaders(o.headers))
	}
	reader, err := newMetricReader(ctx, exportOpts...)
	if err != nil {
		return nil, err
	}
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	), nil
}

func newTracerProvider(ctx context.Context, res *resource.Resource, o *options) (*sdktrace.TracerProvider, error) {
	exportOpts := []otlptracehttp.Option{
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
	}
	if o.timeout != 0 {
		exportOpts = append(exportOpts, otlptracehttp.WithTimeout(o.timeout))
	}
	if o.endpoint != "" {
		exportOpts = append(exportOpts, otlptracehttp.WithEndpointURL(o.endpoint))
	}
	if o.headers != nil {
		exportOpts = append(exportOpts, otlptracehttp.WithHeaders(o.headers))
	}
	exp, err := newTraceExporter(ctx, exportOpts...)
	if err != nil {
		return nil, err
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	), nil
}

func newLoggerProvider(ctx context.Context, res *resource.Resource, o *options) (*sdklog.LoggerProvider, error) {
	exportOpts := []otlploghttp.Option{
		otlploghttp.WithCompression(otlploghttp.GzipCompression),
		otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: false}),
	}
	if o.timeout != 0 {
		exportOpts = append(exportOpts, otlploghttp.WithTimeout(o.timeout))
	}
	if o.endpoint != "" {
		exportOpts = append(exportOpts, otlploghttp.WithEndpointURL(o.endpoint))
	}
	if o.headers != nil {
		exportOpts = append(exportOpts, otlploghttp.WithHeaders(o.headers))
	}
	exp, err := newLogExporter(ctx, exportOpts...)
	if err != nil {
		return nil, err
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	), nil
}
