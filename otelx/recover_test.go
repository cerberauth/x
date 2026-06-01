package otelx

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/codes"
	globallog "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// recordingLogExporter captures exported log records for assertions.
type recordingLogExporter struct {
	records []sdklog.Record
}

func (e *recordingLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.records = append(e.records, records...)
	return nil
}
func (e *recordingLogExporter) Shutdown(_ context.Context) error  { return nil }
func (e *recordingLogExporter) ForceFlush(_ context.Context) error { return nil }

// setupTraceAndLog returns ctx (with an active span), a span ender, the
// in-memory span exporter, and the log exporter. Call endSpan() before
// reading spanExp.GetSpans() — spans are only exported after End().
func setupTraceAndLog(t *testing.T) (ctx context.Context, endSpan func(), spanExp *tracetest.InMemoryExporter, logExp *recordingLogExporter) {
	t.Helper()

	spanExp = tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExp))

	logExp = &recordingLogExporter{}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(logExp)),
	)

	prevLP := globallog.GetLoggerProvider()
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = lp.Shutdown(context.Background())
		globallog.SetLoggerProvider(prevLP)
	})
	globallog.SetLoggerProvider(lp)

	var span trace.Span
	ctx, span = tp.Tracer("test").Start(context.Background(), "test-span")
	endSpan = func() { span.End() }
	t.Cleanup(endSpan)
	return
}

func TestRecoverAndReport_NoPanic_NoOp(t *testing.T) {
	ctx := context.Background()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	RecoverAndReport(ctx) // no panic in flight — must be a no-op
}

func TestRecoverAndReport_RepanicsSameValue(t *testing.T) {
	ctx, _, _, _ := setupTraceAndLog(t)
	const panicVal = "test panic value"

	var got any
	func() {
		defer func() { got = recover() }()
		func() {
			defer RecoverAndReport(ctx)
			panic(panicVal)
		}()
	}()

	if got != panicVal {
		t.Errorf("expected re-panic with %q, got %v", panicVal, got)
	}
}

func TestRecoverAndReport_RecordsExceptionOnSpan(t *testing.T) {
	ctx, endSpan, spanExp, _ := setupTraceAndLog(t)

	func() {
		defer func() { recover() }() //nolint:errcheck
		func() {
			defer RecoverAndReport(ctx)
			panic("boom")
		}()
	}()

	endSpan() // must end the span before it appears in GetSpans()

	spans := spanExp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one recorded span")
	}
	span := spans[0]

	var hasExceptionEvent bool
	for _, e := range span.Events {
		if e.Name == "exception" {
			hasExceptionEvent = true
			break
		}
	}
	if !hasExceptionEvent {
		t.Error("expected span to have an 'exception' event")
	}
}

func TestRecoverAndReport_SetsSpanStatusError(t *testing.T) {
	ctx, endSpan, spanExp, _ := setupTraceAndLog(t)

	func() {
		defer func() { recover() }() //nolint:errcheck
		func() {
			defer RecoverAndReport(ctx)
			panic("boom")
		}()
	}()

	endSpan() // must end the span before it appears in GetSpans()

	spans := spanExp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}
	if spans[0].Status.Code != codes.Error {
		t.Errorf("expected span status Error, got %v", spans[0].Status.Code)
	}
}

func TestRecoverAndReport_EmitsLogRecord(t *testing.T) {
	ctx, _, _, logExp := setupTraceAndLog(t)

	func() {
		defer func() { recover() }() //nolint:errcheck
		func() {
			defer RecoverAndReport(ctx)
			panic("crash!")
		}()
	}()

	if len(logExp.records) == 0 {
		t.Fatal("expected at least one log record")
	}
}
