package otelx

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	globallog "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// noopLogExporter satisfies sdklog.Exporter without network I/O.
type noopLogExporter struct{}

func (e *noopLogExporter) Export(_ context.Context, _ []sdklog.Record) error { return nil }
func (e *noopLogExporter) Shutdown(_ context.Context) error                  { return nil }
func (e *noopLogExporter) ForceFlush(_ context.Context) error                { return nil }

func useNoopExporters(t *testing.T) {
	t.Helper()

	origMetric := newMetricReader
	origTrace := newTraceExporter
	origLog := newLogExporter

	newMetricReader = func(_ context.Context, _ ...otlpmetrichttp.Option) (sdkmetric.Reader, error) {
		return sdkmetric.NewManualReader(), nil
	}
	newTraceExporter = func(_ context.Context, _ ...otlptracehttp.Option) (sdktrace.SpanExporter, error) {
		return tracetest.NewInMemoryExporter(), nil
	}
	newLogExporter = func(_ context.Context, _ ...otlploghttp.Option) (sdklog.Exporter, error) {
		return &noopLogExporter{}, nil
	}

	t.Cleanup(func() {
		newMetricReader = origMetric
		newTraceExporter = origTrace
		newLogExporter = origLog
	})
}

func resetGlobals(t *testing.T) {
	t.Helper()
	prevMP := otel.GetMeterProvider()
	prevTP := otel.GetTracerProvider()
	prevLP := globallog.GetLoggerProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevMP)
		otel.SetTracerProvider(prevTP)
		globallog.SetLoggerProvider(prevLP)
	})
}

func TestNew_ReturnsShutdownFunc(t *testing.T) {
	useNoopExporters(t)
	resetGlobals(t)

	ctx := context.Background()
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown func")
	}
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown error: %v", err)
	}
}

func TestNew_SetsAllThreeGlobalProviders(t *testing.T) {
	useNoopExporters(t)
	resetGlobals(t)

	ctx := context.Background()
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer shutdown(ctx) //nolint:errcheck

	if _, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider); !ok {
		t.Error("expected global MeterProvider to be *sdkmetric.MeterProvider")
	}
	if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); !ok {
		t.Error("expected global TracerProvider to be *sdktrace.TracerProvider")
	}
	if _, ok := globallog.GetLoggerProvider().(*sdklog.LoggerProvider); !ok {
		t.Error("expected global LoggerProvider to be *sdklog.LoggerProvider")
	}
}

func TestNew_ShutdownIdempotent(t *testing.T) {
	useNoopExporters(t)
	resetGlobals(t)

	ctx := context.Background()
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := shutdown(ctx); err != nil {
		t.Errorf("first shutdown error: %v", err)
	}
	// second call should not panic
	_ = shutdown(ctx)
}

func TestNewResource_ContainsServiceAttributes(t *testing.T) {
	const (
		svcName = "test-service"
		version = "1.2.3"
	)

	res, err := newResource(context.Background(), svcName, version, &options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil resource")
	}

	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range res.Attributes() {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[semconv.ServiceNameKey]; !ok || v.AsString() != svcName {
		t.Errorf("service.name: got %q, want %q", v.AsString(), svcName)
	}
	if v, ok := attrMap[semconv.ServiceVersionKey]; !ok || v.AsString() != version {
		t.Errorf("service.version: got %q, want %q", v.AsString(), version)
	}
}

func TestNewResource_SkipsFromEnv(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "injected.key=injected.value")

	res, err := newResource(context.Background(), "svc", "1.0", &options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, a := range res.Attributes() {
		if string(a.Key) == "injected.key" {
			t.Error("OTEL_RESOURCE_ATTRIBUTES must not inject attributes (WithFromEnv not called)")
		}
	}
}

func TestNewResource_WithCommitAndDate(t *testing.T) {
	o := &options{commit: "abc123", date: "2025-01-01"}
	res, err := newResource(context.Background(), "svc", "1.0", o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range res.Attributes() {
		attrMap[a.Key] = a.Value
	}

	if v := attrMap["vcs.repository.ref.revision"].AsString(); v != "abc123" {
		t.Errorf("commit attr: got %q, want %q", v, "abc123")
	}
	if v := attrMap["service.build.date"].AsString(); v != "2025-01-01" {
		t.Errorf("date attr: got %q, want %q", v, "2025-01-01")
	}
}
