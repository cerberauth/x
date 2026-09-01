package harnessreport

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/score"
	"github.com/cerberauth/reportx/transport"
)

func withStdout(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = f
	t.Cleanup(func() {
		os.Stdout = orig
		f.Close()
	})
}

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

func (f *mockFormatter) MediaType() string     { return "text/plain" }
func (f *mockFormatter) FileExtension() string { return "txt" }

type errWriter struct{}

func (errWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func TestBuild_EveryFindingOnNonStdoutSink(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks:       []Sink{{Formatter: mFormatter, Writer: &buf}},
	}}

	results := []Result{
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

	err := r.build(context.Background(), "http://target-domain.com", results, nil)
	require.NoError(t, err)

	assert.Equal(t, "mocked formatted report", buf.String())

	require.NotNil(t, mFormatter.report)
	assert.Equal(t, "my-tool", mFormatter.report.ToolName)
	assert.Equal(t, "1.0.0", mFormatter.report.ToolVersion)
	assert.Equal(t, "my-report", mFormatter.report.Title)
	assert.Equal(t, "http://target-domain.com", mFormatter.report.Target)

	// A non-stdout sink gets every finding, vulnerable or not.
	require.Len(t, mFormatter.report.Findings, 2)
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

	assert.Equal(t, score.Label(7.5), f.Severity)

	require.NotNil(t, f.Evidence)
	ev, ok := f.Evidence.(*evidence.HTTPEvidence)
	require.True(t, ok)
	assert.Equal(t, "GET", ev.RequestMethod)
	assert.Equal(t, "http://target-domain.com", ev.RequestURL)
	assert.Equal(t, 200, ev.ResponseStatus)
}

func TestBuild_OfflineTarget(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks:       []Sink{{Formatter: mFormatter, Writer: &buf}},
	}}

	results := []Result{
		{
			Name:       "CheckVulnerable",
			Vulnerable: true,
			CVSSScore:  0, // no severity or status mapped
		},
	}

	err := r.build(context.Background(), "", results, nil)
	require.NoError(t, err)

	require.NotNil(t, mFormatter.report)
	assert.Equal(t, "(offline)", mFormatter.report.Target)

	require.Len(t, mFormatter.report.Findings, 1)
	f := mFormatter.report.Findings[0]
	assert.Empty(t, f.Severity)
	require.NotNil(t, f.Evidence)
	ev, ok := f.Evidence.(*evidence.HTTPEvidence)
	require.True(t, ok)
	assert.Empty(t, ev.RequestMethod)
	assert.Empty(t, ev.RequestURL)
	assert.Equal(t, 0, ev.ResponseStatus)
}

func TestBuild_WriterError(t *testing.T) {
	mFormatter := &mockFormatter{}

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks:       []Sink{{Formatter: mFormatter, Writer: errWriter{}}},
	}}

	err := r.build(context.Background(), "", nil, nil)
	assert.ErrorContains(t, err, "write error")
}

func TestBuild_FormatterError(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{err: errors.New("formatter error")}

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks:       []Sink{{Formatter: mFormatter, Writer: &buf}},
	}}

	err := r.build(context.Background(), "", nil, nil)
	assert.ErrorContains(t, err, "formatter error")
}

func TestBuild_WithTransportSuccess(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tr := transport.NewHTTPTransport(ts.URL)
	tr.Client = ts.Client()

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks: []Sink{
			{Formatter: mFormatter, Writer: &buf},
			{Formatter: mFormatter, Transport: tr},
		},
	}}

	err := r.build(context.Background(), "", nil, nil)
	require.NoError(t, err)
}

func TestBuild_WithTransportError(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	tr := transport.NewHTTPTransport(ts.URL)
	tr.Client = ts.Client()

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks: []Sink{
			{Formatter: mFormatter, Writer: &buf},
			{Formatter: mFormatter, Transport: tr},
		},
	}}

	err := r.build(context.Background(), "", nil, nil)
	assert.Error(t, err)
}

func TestBuild_StdoutOnlyVulnerableByDefault(t *testing.T) {
	withStdout(t)

	stdoutFormatter := &mockFormatter{}
	var fileBuf bytes.Buffer
	fileFormatter := &mockFormatter{}

	r := &Reporter{cfg: Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Sinks: []Sink{
			{Formatter: stdoutFormatter, Writer: os.Stdout},
			{Formatter: fileFormatter, Writer: &fileBuf},
		},
	}}

	results := []Result{
		{Name: "CheckVulnerable", Vulnerable: true},
		{Name: "CheckNotVulnerable", Vulnerable: false},
	}

	err := r.build(context.Background(), "", results, nil)
	require.NoError(t, err)

	require.NotNil(t, stdoutFormatter.report)
	require.Len(t, stdoutFormatter.report.Findings, 1)
	assert.Equal(t, "CheckVulnerable", stdoutFormatter.report.Findings[0].ID)

	require.NotNil(t, fileFormatter.report)
	require.Len(t, fileFormatter.report.Findings, 2)
}

func TestBuild_ShowAllFindingsIncludesEverythingOnStdout(t *testing.T) {
	withStdout(t)

	stdoutFormatter := &mockFormatter{}

	r := &Reporter{cfg: Config{
		ToolName:        "my-tool",
		ToolVersion:     "1.0.0",
		Title:           "my-report",
		ShowAllFindings: true,
		Sinks:           []Sink{{Formatter: stdoutFormatter, Writer: os.Stdout}},
	}}

	results := []Result{
		{Name: "CheckVulnerable", Vulnerable: true},
		{Name: "CheckNotVulnerable", Vulnerable: false},
	}

	err := r.build(context.Background(), "", results, nil)
	require.NoError(t, err)

	require.NotNil(t, stdoutFormatter.report)
	require.Len(t, stdoutFormatter.report.Findings, 2)
}
