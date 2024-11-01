package analyticsx

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TrackEvent(ctx context.Context, tracer trace.Tracer, eventName string, eventAttributes ...attribute.KeyValue) {
	_, span := tracer.Start(
		ctx,
		eventName,
		trace.WithAttributes(eventAttributes...),
	)
	defer span.End()
}

func TrackError(ctx context.Context, tracer trace.Tracer, err error, eventAttributes ...attribute.KeyValue) {
	TrackEvent(ctx, tracer, "error", append(eventAttributes, attribute.String("error", err.Error()))...)
}
