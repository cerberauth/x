package analyticsx

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TrackEvent(ctx context.Context, tracer trace.Tracer, eventName string, eventAttributes []attribute.KeyValue) {
	_, span := tracer.Start(
		ctx,
		eventName,
		trace.WithAttributes(eventAttributes...),
	)
	defer span.End()
}

func TrackError(ctx context.Context, tracer trace.Tracer, err error) {
	TrackEvent(ctx, tracer, "error", []attribute.KeyValue{
		attribute.String("error.message", err.Error()),
	})
}
