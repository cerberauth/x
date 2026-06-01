package harnessxreporter

import (
	"context"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/cerberauth/harnessx/reporters"
)

type Option = reporters.OTelOption

func WithPrefix(prefix string) Option {
	return reporters.WithPrefix(prefix)
}

func New(ctx context.Context, meter metric.Meter, opts ...Option) (*reporters.OTelReporter, error) {
	tracer := noop.NewTracerProvider().Tracer("")
	return reporters.NewOTelReporter(ctx, tracer, meter, opts...)
}
