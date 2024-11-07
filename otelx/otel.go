package otelx

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

var (
	resource          *sdkresource.Resource
	initResourcesOnce sync.Once
)

const (
	otelEndpoint = "https://telemetry.cerberauth.com"
	timeout      = 2 * time.Second
)

func New(ctx context.Context, serviceName string, version string) (*sdkresource.Resource, *metric.Meter, *sdktrace.TracerProvider, error) {
	res := initResource(serviceName, version)
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

func initResource(serviceName string, version string) *sdkresource.Resource {
	initResourcesOnce.Do(func() {
		extraResources, _ := sdkresource.New(
			context.Background(),
			sdkresource.WithOS(),
			sdkresource.WithAttributes(
				semconv.ServiceName(serviceName),
				semconv.ServiceVersion(version),
			),
		)
		resource, _ = sdkresource.Merge(
			sdkresource.Default(),
			extraResources,
		)
	})

	return resource
}

func InitMetric(ctx context.Context, res *sdkresource.Resource, serviceName string, opts ...otlpmetrichttp.Option) (*metric.Meter, *otlpmetrichttp.Exporter, error) {
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

func InitTracerProvider(ctx context.Context, res *sdkresource.Resource, opts ...otlptracehttp.Option) (*sdktrace.TracerProvider, error) {
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
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}
