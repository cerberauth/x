package scanmetrics

import (
	"context"
	"errors"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/x/reportx/harnessreport"
)

func TestIdentifier(t *testing.T) {
	tests := map[string]string{
		"kidinjection (path)":     "kidinjection-path",
		"no_verification":         "no_verification",
		"cache-deception":         "cache-deception",
		"  Weird  ID!! ":          "weird-id",
		"---":                     "other",
		"":                        "other",
		"a.b":                     "a.b",
		string(make([]byte, 100)): "other",
	}
	for in, want := range tests {
		if got := Identifier(in); got != want {
			t.Errorf("Identifier(%q) = %q, want %q", in, got, want)
		}
	}
	long := Identifier("x" + string(make([]rune, 0)) + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
	if len(long) > 64 {
		t.Errorf("expected at most 64 bytes, got %d", len(long))
	}
}

func TestOutcome(t *testing.T) {
	obs := []harnessx.Observation{{Title: "a"}, {Title: "b"}}
	tests := []struct {
		name     string
		result   harnessx.Result
		status   string
		findings int
	}{
		{"passed", harnessx.Result{}, StatusPassed, 0},
		{"observations", harnessx.Result{Observations: obs}, StatusVulnerable, 2},
		{"vulnerable result", harnessx.Result{Data: harnessreport.Result{Vulnerable: true}}, StatusVulnerable, 1},
		{"not vulnerable result", harnessx.Result{Data: harnessreport.Result{}}, StatusPassed, 0},
		{"error wins", harnessx.Result{Err: errors.New("x"), Observations: obs}, StatusError, 0},
		{"result error", harnessx.Result{Data: harnessreport.Result{Err: errors.New("x"), Vulnerable: true}}, StatusError, 0},
		{"skipped", harnessx.Result{Skipped: true}, StatusSkipped, 0},
		{"result skipped", harnessx.Result{Data: harnessreport.Result{Skipped: true}}, StatusSkipped, 0},
	}
	for _, tt := range tests {
		status, n := outcome(tt.result)
		if status != tt.status || n != tt.findings {
			t.Errorf("%s: got (%s, %d), want (%s, %d)", tt.name, status, n, tt.status, tt.findings)
		}
	}
}

func TestReporter_CountsFindingsBySeverityPerScan(t *testing.T) {
	r := New(context.Background(), Config{
		CheckDefs: map[harnessx.CheckID]checkdef.CheckDef{
			"algnone":  {CVSSScore: 9.1},
			"secret":   {CVSSScore: 7.5},
			"baseline": {CVSSScore: 9.9},
		},
		BaselineCheckID: "baseline",
	})
	r.OnScanStart(harnessx.Target{}, 3)
	r.OnCheckComplete(harnessx.Result{CheckID: "algnone", Observations: []harnessx.Observation{{}, {}}})
	r.OnCheckComplete(harnessx.Result{CheckID: "secret", Data: harnessreport.Result{Vulnerable: true}})
	r.OnCheckComplete(harnessx.Result{CheckID: "unknown", Observations: []harnessx.Observation{{}}}) // no def: helper, left out
	r.OnCheckComplete(harnessx.Result{CheckID: "baseline", Observations: []harnessx.Observation{{}}})
	r.OnCheckComplete(harnessx.Result{CheckID: "passing"})

	want := map[string]int{"critical": 2, "high": 1, "info": 0}
	for sev, n := range want {
		if r.bySeverity[sev] != n {
			t.Errorf("%s: got %d findings, want %d", sev, r.bySeverity[sev], n)
		}
	}
	// No client: recording must be a no-op, not a panic.
	r.OnScanComplete(harnessx.ScanSummary{})

	r.OnScanStart(harnessx.Target{}, 1)
	if len(r.bySeverity) != 0 {
		t.Error("expected each scan to start from zero")
	}
}

var _ harnessx.Reporter = (*Reporter)(nil)

type customFinding struct{}

func TestReporter_CustomFindings(t *testing.T) {
	r := New(context.Background(), Config{
		CheckDefs: map[harnessx.CheckID]checkdef.CheckDef{"cors": {CVSSScore: 5}},
		Findings: func(res harnessx.Result) (int, bool) {
			_, ok := res.Data.(*customFinding)
			return 1, ok
		},
	})
	r.OnScanStart(harnessx.Target{}, 1)
	r.OnCheckComplete(harnessx.Result{CheckID: "cors", Data: &customFinding{}})
	r.OnCheckComplete(harnessx.Result{CheckID: "cors"})
	r.OnCheckComplete(harnessx.Result{CheckID: "cors", Data: &customFinding{}, Err: errors.New("x")})
	if r.bySeverity["medium"] != 1 {
		t.Errorf("expected 1 medium finding, got %d", r.bySeverity["medium"])
	}
}
