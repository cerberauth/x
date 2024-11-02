package analyticsx

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func StartTrace(ctx context.Context, tracer trace.Tracer, spanName string, spanAttributes ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer.Start(ctx, spanName, trace.WithAttributes(spanAttributes...))
}

func TrackEvent(ctx context.Context, eventName string, eventAttributes ...attribute.KeyValue) (context.Context, trace.Span) {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ctx, nil
	}
	span.AddEvent(eventName, trace.WithAttributes(eventAttributes...))
	defer span.End()
	return ctx, span
}

func TrackError(ctx context.Context, err error, eventAttributes ...attribute.KeyValue) (context.Context, trace.Span) {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ctx, nil
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return ctx, span
}
