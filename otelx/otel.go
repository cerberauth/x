package otelx

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

var (
	resource          *sdkresource.Resource
	initResourcesOnce sync.Once
)

func InitResource(serviceName string, version string) *sdkresource.Resource {
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

func InitTracerProvider(ctx context.Context, serviceName string, version string, opts ...otlptracehttp.Option) (*sdktrace.TracerProvider, error) {
	opts = append(opts, otlptracehttp.WithEndpointURL("https://telemetry.cerberauth.com"))

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(InitResource(serviceName, version)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}
