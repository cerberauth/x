package analyticsx

import (
	"context"

	"github.com/cerberauth/x/otelx"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type AppInfo struct {
	Name    string
	Version string
}

func NewAnalytics(ctx context.Context, app AppInfo) (*sdktrace.TracerProvider, error) {
	return otelx.InitTracerProvider(ctx, app.Name, app.Version, otlptracehttp.WithEndpointURL("https://telemetry.cerberauth.com"))
}
