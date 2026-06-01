package telemetryx

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	otellog "go.opentelemetry.io/otel/log"
	globallog "go.opentelemetry.io/otel/log/global"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/cerberauth/x/otelx"
)

const (
	otelEndpoint = "https://telemetry.cerberauth.com"
	timeout      = 1 * time.Second
)

var meterProvider *sdkmetric.MeterProvider

// otelxNew is a seam for test injection.
var otelxNew = otelx.New

type options struct {
	commit string
	date   string
}

// Option configures telemetryx.New.
type Option func(*options)

func WithCommit(commit string) Option {
	return func(o *options) { o.commit = commit }
}

func WithBuildDate(date string) Option {
	return func(o *options) { o.date = date }
}

// New initialises OpenTelemetry for metrics, traces, and logs, exporting to
// the cerberauth telemetry endpoint. All exporter options are hardcoded so
// OTEL_* environment variables cannot override the endpoint, timeout,
// compression, headers, or resource attributes.
//
// The returned shutdown function must be deferred at the program entry point.
// It automatically captures any unhandled panic, records it via OTEL, flushes
// all telemetry, and then re-panics so the runtime still sees the original
// crash.
func New(ctx context.Context, serviceName string, version string, opts ...Option) (func(context.Context) error, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	xOpts := []otelx.Option{
		otelx.WithEndpoint(otelEndpoint),
		otelx.WithTimeout(timeout),
		// Explicit empty headers block OTEL_EXPORTER_OTLP_HEADERS injection.
		otelx.WithHeaders(map[string]string{}),
	}
	if o.commit != "" {
		xOpts = append(xOpts, otelx.WithCommit(o.commit))
	}
	if o.date != "" {
		xOpts = append(xOpts, otelx.WithBuildDate(o.date))
	}

	internalShutdown, err := otelxNew(ctx, serviceName, version, xOpts...)
	if err != nil {
		return nil, err
	}

	if mp, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider); ok {
		meterProvider = mp
	}

	return func(ctx context.Context) error {
		if r := recover(); r != nil {
			otelx.ReportPanic(ctx, r)
			flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = internalShutdown(flushCtx)
			panic(r)
		}
		return internalShutdown(ctx)
	}, nil
}

var noopProvider = sdkmetric.NewMeterProvider()

// GetMeterProvider returns the SDK MeterProvider set by New, or a noop
// provider if New has not been called.
func GetMeterProvider() *sdkmetric.MeterProvider {
	if meterProvider == nil {
		return noopProvider
	}
	return meterProvider
}

// GetTracerProvider returns the global TracerProvider set by New.
func GetTracerProvider() trace.TracerProvider {
	return otel.GetTracerProvider()
}

// GetLoggerProvider returns the global LoggerProvider set by New.
func GetLoggerProvider() otellog.LoggerProvider {
	return globallog.GetLoggerProvider()
}
