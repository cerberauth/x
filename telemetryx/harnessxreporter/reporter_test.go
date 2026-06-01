package harnessxreporter_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/x/telemetryx/harnessxreporter"
)

func newTestMeter(t *testing.T) *sdkmetric.MeterProvider {
	t.Helper()
	return sdkmetric.NewMeterProvider()
}

func TestNew_ReturnsReporter(t *testing.T) {
	mp := newTestMeter(t)
	r, err := harnessxreporter.New(context.Background(), mp.Meter("test"))
	require.NoError(t, err)
	assert.NotNil(t, r)
}

func TestNew_WithPrefix(t *testing.T) {
	mp := newTestMeter(t)
	r, err := harnessxreporter.New(context.Background(), mp.Meter("test"), harnessxreporter.WithPrefix("myapp"))
	require.NoError(t, err)
	assert.NotNil(t, r)
}

func TestNew_ImplementsReporterInterface(t *testing.T) {
	mp := newTestMeter(t)
	r, err := harnessxreporter.New(context.Background(), mp.Meter("test"))
	require.NoError(t, err)
	assert.Implements(t, (*harnessx.Reporter)(nil), r)
}
