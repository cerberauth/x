package reportx_test

import (
	"testing"

	"github.com/cerberauth/reportx/format"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
)

func newCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cobrareportx.RegisterFormatFlags(cmd)
	cobrareportx.RegisterTransportFlags(cmd)
	return cmd
}

func TestFormatterFromFlags_DefaultTerminal(t *testing.T) {
	cmd := newCmd()
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "text/plain", f.MediaType())
}

func TestFormatterFromFlags_JSON(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("format", "json"))
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "application/json", f.MediaType())
}

func TestFormatterFromFlags_SARIF(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("format", "sarif"))
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "application/sarif+json", f.MediaType())
}

func TestFormatterFromFlags_Markdown(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("format", "markdown"))
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "text/markdown", f.MediaType())
}

func TestFormatterFromFlags_HTML(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("format", "html"))
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "text/html", f.MediaType())
}

func TestFormatterFromFlags_NoColor(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("no-color", "true"))
	f, err := cobrareportx.FormatterFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, "text/plain", f.MediaType())
}

func TestFormatterFromFlags_Unknown(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("format", "bogus"))
	_, err := cobrareportx.FormatterFromFlags(cmd)
	assert.Error(t, err)
}

func TestWriterFromFlags_Stdout(t *testing.T) {
	cmd := newCmd()
	w, cleanup, err := cobrareportx.WriterFromFlags(cmd)
	require.NoError(t, err)
	defer cleanup()
	assert.NotNil(t, w)
}

func TestWriterFromFlags_File(t *testing.T) {
	cmd := newCmd()
	path := t.TempDir() + "/report.json"
	require.NoError(t, cmd.Flags().Set("output", path))
	w, cleanup, err := cobrareportx.WriterFromFlags(cmd)
	require.NoError(t, err)
	defer cleanup()
	assert.NotNil(t, w)
}

func TestHTTPTransportFromFlags_NoURL(t *testing.T) {
	cmd := newCmd()
	tr, err := cobrareportx.HTTPTransportFromFlags(cmd)
	require.NoError(t, err)
	assert.Nil(t, tr)
}

func TestHTTPTransportFromFlags_WithURL(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("report-url", "https://example.com/reports"))
	tr, err := cobrareportx.HTTPTransportFromFlags(cmd)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, "https://example.com/reports", tr.URL)
}

func TestHTTPTransportFromFlags_WithHeaders(t *testing.T) {
	cmd := newCmd()
	require.NoError(t, cmd.Flags().Set("report-url", "https://example.com/reports"))
	require.NoError(t, cmd.Flags().Set("report-header", "Authorization=Bearer tok"))
	tr, err := cobrareportx.HTTPTransportFromFlags(cmd)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, "Bearer tok", tr.Headers["Authorization"])
}

func TestRegisterFormatFlags_AllFormatsRegistered(t *testing.T) {
	cmd := newCmd()
	flag := cmd.Flags().Lookup("format")
	require.NotNil(t, flag)
	for _, name := range format.FormatNames {
		require.NoError(t, cmd.Flags().Set("format", string(name)))
		f, err := cobrareportx.FormatterFromFlags(cmd)
		require.NoError(t, err, "format %s should be valid", name)
		assert.NotNil(t, f)
	}
}
