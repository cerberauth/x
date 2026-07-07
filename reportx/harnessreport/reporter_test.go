package harnessreport_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/reportx"
	xharnessx "github.com/cerberauth/x/harnessx"
	"github.com/cerberauth/x/reportx/harnessreport"
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

func (f *mockFormatter) MediaType() string     { return "text/plain" }
func (f *mockFormatter) FileExtension() string { return "txt" }

type errWriter struct{}

func (errWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func TestReporter_StampsCheckDefMetadata(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := harnessreport.New(context.Background(), harnessreport.Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
		CheckDefs: map[harnessx.CheckID]xharnessx.CheckDef{
			"alg_none": {
				Name:        "Algorithm None",
				Description: "alg=none accepted",
				Link:        "https://example.com/alg-none",
				CVSSVector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
				CVSSScore:   9.3,
				CWEID:       "CWE-345",
				OWASP:       "API2:2023",
			},
		},
	})

	r.OnScanStart(harnessx.Target{URL: "http://target.example"}, 1)
	r.OnCheckComplete(harnessx.Result{
		CheckID: "alg_none",
		Data: harnessreport.Result{
			Payload:    "eyJhbGciOiJub25lIn0...",
			Status:     200,
			Vulnerable: true,
		},
	})
	r.OnScanComplete(harnessx.ScanSummary{})

	require.NoError(t, r.Err())
	require.NotNil(t, mFormatter.report)
	require.Len(t, mFormatter.report.Findings, 1)

	f := mFormatter.report.Findings[0]
	assert.Equal(t, "Algorithm None", f.ID)
	assert.Equal(t, "alg=none accepted", f.Description)
	assert.Equal(t, "https://example.com/alg-none", f.URL)
	assert.Equal(t, "CWE-345", f.CWEID)
	assert.Equal(t, 9.3, f.CVSS40Score)
	assert.Equal(t, "http://target.example", mFormatter.report.Target)
}

func TestReporter_BaselineCheckExcludedFromFindings(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := harnessreport.New(context.Background(), harnessreport.Config{
		ToolName:        "my-tool",
		ToolVersion:     "1.0.0",
		Title:           "my-report",
		Formatter:       mFormatter,
		Writer:          &buf,
		BaselineCheckID: "baseline",
		CheckDefs: map[harnessx.CheckID]xharnessx.CheckDef{
			"no_verification": {Name: "no_verification"},
		},
	})

	r.OnScanStart(harnessx.Target{URL: "http://target.example"}, 2)
	r.OnCheckComplete(harnessx.Result{CheckID: "baseline", Data: 401})
	r.OnCheckComplete(harnessx.Result{
		CheckID: "no_verification",
		Data:    harnessreport.Result{Vulnerable: true},
	})
	r.OnScanComplete(harnessx.ScanSummary{})

	require.NoError(t, r.Err())
	require.Len(t, mFormatter.report.Findings, 1)
	assert.Equal(t, "no_verification", mFormatter.report.Findings[0].ID)
}

func TestReporter_SkippedCheckDoesNotNeedOnCheckStart(t *testing.T) {
	var buf bytes.Buffer
	mFormatter := &mockFormatter{}

	r := harnessreport.New(context.Background(), harnessreport.Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   mFormatter,
		Writer:      &buf,
		CheckDefs: map[harnessx.CheckID]xharnessx.CheckDef{
			"hmac_confusion": {Name: "HMAC Confusion"},
		},
	})

	// harnessx never calls OnCheckStart for skipped checks; the adapter
	// must recover the name/metadata from CheckDefs alone.
	r.OnCheckComplete(harnessx.Result{
		CheckID:    "hmac_confusion",
		Skipped:    true,
		SkipReason: "no public key provided",
	})
	r.OnScanComplete(harnessx.ScanSummary{})

	require.NoError(t, r.Err())
	// Skipped, non-vulnerable results aren't emitted as findings.
	assert.Empty(t, mFormatter.report.Findings)
}

func TestReporter_ErrSurfacesWriterFailure(t *testing.T) {
	r := harnessreport.New(context.Background(), harnessreport.Config{
		ToolName:    "my-tool",
		ToolVersion: "1.0.0",
		Title:       "my-report",
		Formatter:   &mockFormatter{},
		Writer:      errWriter{},
	})

	r.OnScanStart(harnessx.Target{}, 0)
	r.OnScanComplete(harnessx.ScanSummary{})

	assert.ErrorContains(t, r.Err(), "write error")
}
