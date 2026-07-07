package scanreporter_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/score"
	"github.com/cerberauth/reportx/transport"
	"github.com/cerberauth/x/reportx/scanreporter"
)

type mockFormatter struct {
	report *reportx.Report
	err    error
}

func (f *mockFormatter) Format(r *reportx.Report) ([]byte, error) {
	f.report = r
	if f.err != nil {
		return nil, f.err
	}
	return []byte("mocked formatted report"), nil
}

func (f *mockFormatter) MediaType() string {
	return "text/plain"
}

func (f *mockFormatter) FileExtension() string {
	return "txt"
}

type errWriter struct{}

func (errWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func TestReporter_Report_VulnerableOnly(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
	}

	results := []scanreporter.Result{
		{
			Name:        "CheckVulnerable",
			Payload:     "vulnerable-payload",
			Status:      200,
			Vulnerable:  true,
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CWEID:       "CWE-79",
			Extra:       "some extra detail",
			Description: "vulnerable desc",
			Link:        "https://example.com/cwe-79",
		},
		{
			Name:       "CheckNotVulnerable",
			Vulnerable: false,
		},
	}

	meta := scanreporter.ScanMeta{
		Target: "http://target-domain.com",
	}

	err := r.Report(context.Background(), results, meta)
	require.NoError(t, err)

	// Verify that the mocked formatted report was written
	assert.Equal(t, "mocked formatted report", buf.String())

	// Verify the constructed report
	require.NotNil(t, mFormatter.report)
	assert.Equal(t, "my-tool", mFormatter.report.ToolName)
	assert.Equal(t, "1.0.0", mFormatter.report.ToolVersion)
	assert.Equal(t, "my-report", mFormatter.report.Title)
	assert.Equal(t, "http://target-domain.com", mFormatter.report.Target)

	// Check findings
	require.Len(t, mFormatter.report.Findings, 1)
	f := mFormatter.report.Findings[0]
	assert.Equal(t, "CheckVulnerable", f.ID)
	assert.Equal(t, "CheckVulnerable", f.Title)
	assert.Equal(t, "vulnerable desc", f.Description)
	assert.Equal(t, "https://example.com/cwe-79", f.URL)
	assert.Equal(t, "CWE-79", f.CWEID)
	assert.Equal(t, 7.5, f.CVSS40Score)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", f.CVSS40Vector)
	assert.Equal(t, reportx.StatusActive, f.Status)
	assert.Equal(t, "vulnerable-payload", f.Parameter)
	assert.Equal(t, map[string]string{"detail": "some extra detail"}, f.Extra)

	// Severity should be mapped based on CVSSScore
	assert.Equal(t, score.Label(7.5), f.Severity)

	// Evidence
	require.NotNil(t, f.Evidence)
	ev, ok := f.Evidence.(*evidence.HTTPEvidence)
	require.True(t, ok)
	assert.Equal(t, "GET", ev.RequestMethod)
	assert.Equal(t, "http://target-domain.com", ev.RequestURL)
	assert.Equal(t, 200, ev.ResponseStatus)
}

func TestReporter_Report_OfflineTarget(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
	}

	results := []scanreporter.Result{
		{
			Name:       "CheckVulnerable",
			Vulnerable: true,
			CVSSScore:  0, // no severity or status mapped
		},
	}

	meta := scanreporter.ScanMeta{
		Target: "",
	}

	err := r.Report(context.Background(), results, meta)
	require.NoError(t, err)

	// target should fall back to "(offline)"
	require.NotNil(t, mFormatter.report)
	assert.Equal(t, "(offline)", mFormatter.report.Target)

	require.Len(t, mFormatter.report.Findings, 1)
	f := mFormatter.report.Findings[0]
	// Severity should not be set (is empty/default) since score is 0
	assert.Empty(t, f.Severity)
	// Evidence should not have status/URL/method since status is 0
	require.NotNil(t, f.Evidence)
	ev, ok := f.Evidence.(*evidence.HTTPEvidence)
	require.True(t, ok)
	assert.Empty(t, ev.RequestMethod)
	assert.Empty(t, ev.RequestURL)
	assert.Equal(t, 0, ev.ResponseStatus)
}

func TestReporter_Report_WriterError(t *testing.T) {
	mFormatter := &mockFormatter{}

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      errWriter{},
	}

	err := r.Report(context.Background(), []scanreporter.Result{}, scanreporter.ScanMeta{})
	assert.ErrorContains(t, err, "write error")
}

func TestReporter_Report_FormatterError(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{
		err: errors.New("formatter error"),
	}

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
	}

	err := r.Report(context.Background(), []scanreporter.Result{}, scanreporter.ScanMeta{})
	assert.ErrorContains(t, err, "formatter error")
}

func TestReporter_Report_WithTransportSuccess(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, "mocked formatted report", string(body))
		assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))
		assert.Equal(t, "custom-val", r.Header.Get("X-Custom"))
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tr := transport.NewHTTPTransport(ts.URL)
	tr.Headers = map[string]string{
		"X-Custom": "custom-val",
	}
	tr.Client = ts.Client()

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
		Transport:   tr,
	}

	err := r.Report(context.Background(), []scanreporter.Result{}, scanreporter.ScanMeta{})
	require.NoError(t, err)
}

func TestReporter_Report_WithTransportError(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	tr := transport.NewHTTPTransport(ts.URL)
	tr.Client = ts.Client()

	r := &scanreporter.Reporter{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
		Transport:   tr,
	}

	err := r.Report(context.Background(), []scanreporter.Result{}, scanreporter.ScanMeta{})
	assert.Error(t, err)
}
