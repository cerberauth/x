package otelx

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	globallog "go.opentelemetry.io/otel/log/global"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

const recoverLoggerName = "otelx/recover"

// ReportPanic records a recovered panic value on the active span in ctx and
// emits a Fatal log record. It does not re-panic; the caller decides that.
// Use this when you already have the recovered value (e.g. inside a deferred
// combined shutdown+recover function).
func ReportPanic(ctx context.Context, r any) {
	stack := string(debug.Stack())
	msg := fmt.Sprintf("%v", r)
	typeName := fmt.Sprintf("%T", r)

	span := trace.SpanFromContext(ctx)
	span.RecordError(
		errors.New(msg),
		trace.WithAttributes(
			semconv.ExceptionTypeKey.String(typeName),
			semconv.ExceptionMessageKey.String(msg),
			semconv.ExceptionStacktraceKey.String(stack),
		),
	)
	span.SetStatus(codes.Error, msg)

	logger := globallog.GetLoggerProvider().Logger(recoverLoggerName)
	var rec otellog.Record
	rec.SetSeverity(otellog.SeverityFatal)
	rec.SetBody(otellog.StringValue(msg))
	rec.AddAttributes(
		otellog.String("exception.type", typeName),
		otellog.String("exception.message", msg),
		otellog.String("exception.stacktrace", stack),
	)
	logger.Emit(ctx, rec)
}

// RecoverAndReport is intended to be called with defer at the top of a
// goroutine. On panic it records exception attributes on the active span in
// ctx, emits a Fatal OTEL log record, then re-panics so the original panic
// propagates normally.
//
// Usage:
//
//	func serve(ctx context.Context) {
//	    defer otelx.RecoverAndReport(ctx)
//	    ...
//	}
func RecoverAndReport(ctx context.Context) {
	r := recover()
	if r == nil {
		return
	}
	ReportPanic(ctx, r)
	panic(r)
}
