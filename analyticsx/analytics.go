package analyticsx

import (
	"context"

	"github.com/cerberauth/x/otelx"
	"go.opentelemetry.io/otel/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type AppInfo struct {
	Name    string
	Version string
}

func NewAnalytics(ctx context.Context, app AppInfo) (*metric.Meter, *sdktrace.TracerProvider, error) {
	_, met, tp, err := otelx.New(ctx, app.Name, app.Version)
	return met, tp, err
}
