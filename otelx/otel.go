package otelx

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

const (
	otelEndpoint = "https://telemetry.cerberauth.com"
	timeout      = 1 * time.Second
)

func InitResource(serviceName string, version string) *resource.Resource {
	res, _ := resource.New(
		context.Background(),
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithProcessRuntimeVersion(),
		resource.WithAttributes(semconv.ServiceNameKey.String(serviceName), semconv.ServiceVersionKey.String(version)),
	)

	return res
}

func New(ctx context.Context, serviceName string, version string) (*resource.Resource, *metric.Meter, *sdktrace.TracerProvider, error) {
	res := InitResource(serviceName, version)
	meter, _, err := InitMetric(ctx, res, serviceName)
	if err != nil {
		return nil, nil, nil, err
	}

	tp, err := InitTracerProvider(ctx, res)
	if err != nil {
		return nil, nil, nil, err
	}

	return res, meter, tp, nil
}

func InitMetric(ctx context.Context, res *resource.Resource, serviceName string, opts ...otlpmetrichttp.Option) (*metric.Meter, *otlpmetrichttp.Exporter, error) {
	exporter, err := otlpmetrichttp.New(ctx, append(
		opts,
		otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		otlpmetrichttp.WithTimeout(timeout),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
		otlpmetrichttp.WithEndpointURL(otelEndpoint),
	)...)
	if err != nil {
		return nil, nil, err
	}
	meter := otel.Meter(serviceName)
	return &meter, exporter, nil
}

func InitTracerProvider(ctx context.Context, res *resource.Resource, opts ...otlptracehttp.Option) (*sdktrace.TracerProvider, error) {
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
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}
