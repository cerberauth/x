package telemetryx

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	globallog "go.opentelemetry.io/otel/log/global"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/cerberauth/x/otelx"
)

func resetProviders(t *testing.T) {
	t.Helper()
	origMP := meterProvider
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()
	prevLP := globallog.GetLoggerProvider()
	t.Cleanup(func() {
		meterProvider = origMP
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		globallog.SetLoggerProvider(prevLP)
	})
}

func useNoopOtelx(t *testing.T) {
	t.Helper()
	orig := otelxNew
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	otelxNew = func(ctx context.Context, serviceName, version string, _ ...otelx.Option) (func(context.Context) error, error) {
		otel.SetMeterProvider(mp)
		return func(context.Context) error { return nil }, nil
	}
	t.Cleanup(func() {
		_ = mp.Shutdown(context.Background())
		otelxNew = orig
	})
}

func TestGetMeterProvider_ReturnsNoopWhenNil(t *testing.T) {
	resetProviders(t)
	meterProvider = nil

	mp := GetMeterProvider()
	if mp == nil {
		t.Fatal("expected non-nil meter provider when global is nil")
	}
}

func TestGetMeterProvider_ReturnsInitializedProvider(t *testing.T) {
	resetProviders(t)
	initialized := sdkmetric.NewMeterProvider()
	meterProvider = initialized

	mp := GetMeterProvider()
	if mp != initialized {
		t.Fatal("expected the initialized meter provider to be returned")
	}
}

func TestNew_ReturnsShutdownFunc(t *testing.T) {
	resetProviders(t)
	useNoopOtelx(t)

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
	resetProviders(t)
	useNoopOtelx(t)

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

func TestNew_ShutdownCapturesPanic(t *testing.T) {
	resetProviders(t)
	useNoopOtelx(t)

	ctx := context.Background()
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	const panicVal = "test crash"
	var repanicked bool

	func() {
		defer func() {
			if r := recover(); r == panicVal {
				repanicked = true
			}
		}()
		func() {
			defer shutdown(ctx) //nolint:errcheck
			panic(panicVal)
		}()
	}()

	if !repanicked {
		t.Error("expected panic to be re-panicked after crash capture")
	}
}

func TestNew_ShutdownNoPanicRunsNormally(t *testing.T) {
	resetProviders(t)
	useNoopOtelx(t)

	ctx := context.Background()
	shutdown, err := New(ctx, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Normal execution — no panic, shutdown should return nil error.
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown error on normal path: %v", err)
	}
}
