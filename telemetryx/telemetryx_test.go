package telemetryx

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

func resetMeterProvider(t *testing.T) {
	t.Helper()
	original := meterProvider
	t.Cleanup(func() { meterProvider = original })
}

func useNoopReader(t *testing.T) {
	t.Helper()
	original := newReader
	newReader = func(_ context.Context, _ ...otlpmetrichttp.Option) (metric.Reader, error) {
		return metric.NewManualReader(), nil
	}
	t.Cleanup(func() { newReader = original })
}

func TestGetMeterProvider_ReturnsNoopWhenNil(t *testing.T) {
	resetMeterProvider(t)
	meterProvider = nil

	mp := GetMeterProvider()
	if mp == nil {
		t.Fatal("expected non-nil meter provider when global is nil")
	}
}

func TestGetMeterProvider_ReturnsInitializedProvider(t *testing.T) {
	resetMeterProvider(t)
	initialized := metric.NewMeterProvider()
	meterProvider = initialized

	mp := GetMeterProvider()
	if mp != initialized {
		t.Fatal("expected the initialized meter provider to be returned")
	}
}

func TestNewResource_ContainsServiceAttributes(t *testing.T) {
	const (
		serviceName = "test-service"
		version     = "1.2.3"
	)

	res, err := newResource(context.Background(), serviceName, version)
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

	if v, ok := attrMap[semconv.ServiceNameKey]; !ok || v.AsString() != serviceName {
		t.Errorf("service.name: got %q, want %q", v.AsString(), serviceName)
	}
	if v, ok := attrMap[semconv.ServiceVersionKey]; !ok || v.AsString() != version {
		t.Errorf("service.version: got %q, want %q", v.AsString(), version)
	}
}

func TestNewResource_EmptyValues(t *testing.T) {
	res, err := newResource(context.Background(), "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil resource even with empty strings")
	}
}

func TestNewMeterProvider_Success(t *testing.T) {
	ctx := context.Background()
	res, err := newResource(ctx, "test-service", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected resource error: %v", err)
	}

	mp := newMeterProvider(res, metric.NewManualReader())
	if mp == nil {
		t.Fatal("expected non-nil meter provider")
	}
	if err := mp.Shutdown(ctx); err != nil {
		t.Errorf("shutdown error: %v", err)
	}
}

func TestNewMeterProvider_ShutdownReleasesResources(t *testing.T) {
	ctx := context.Background()
	res, err := newResource(ctx, "test-service", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected resource error: %v", err)
	}

	mp := newMeterProvider(res, metric.NewManualReader())

	if err := mp.Shutdown(ctx); err != nil {
		t.Errorf("first shutdown error: %v", err)
	}
	if err := mp.Shutdown(ctx); err != nil {
		t.Logf("second shutdown returned error (acceptable): %v", err)
	}
}

func TestNew_ReturnsShutdownFunc(t *testing.T) {
	resetMeterProvider(t)
	useNoopReader(t)

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

func TestNew_SetsGlobalMeterProvider(t *testing.T) {
	resetMeterProvider(t)
	useNoopReader(t)

	ctx := context.Background()
	meterProvider = nil
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer shutdown(ctx) //nolint:errcheck

	if meterProvider == nil {
		t.Fatal("expected global meterProvider to be set after New()")
	}
}
