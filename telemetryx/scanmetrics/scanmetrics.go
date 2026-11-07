// Package scanmetrics reports the outcome of a harnessx scan to Argvio as
// product metrics, so every CerberAuth scanner (jwtop, cache-detective,
// proxyaudit, ...) gets the same scan dashboards.
//
// Register a Reporter next to the report reporter:
//
//	harnessx.WithReporters(reportxReporter, scanmetrics.New(ctx, scanmetrics.Config{
//		CheckDefs:       defs,
//		BaselineCheckID: baselineID,
//	}))
//
// and declare the metrics in the CLI's argvio.metrics.yaml (see Metrics):
//
//   - scan.checks (counter, dims: status): one per check result, by status
//     passed, vulnerable, skipped or error.
//   - scan.vulnerable (counter, dims: check, severity): one per vulnerable
//     check result. check is the check ID normalized to an identifier.
//   - scan.findings (value, dims: severity): findings per scan, recorded once
//     per scan for every severity, zeros included.
//   - scan.check-duration (duration, dims: check): how long each check that
//     ran took, which shows the slow checks of a scanner.
//
// Only check IDs and severities chosen in code are sent: never a target, a
// resource, an observation's text or evidence.
package scanmetrics

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/reportx/score"
	"github.com/getargvio/argvio-go"

	"github.com/cerberauth/x/reportx/harnessreport"
)

// Metric names, for the CLI's argvio.metrics.yaml.
const (
	MetricChecks     = "scan.checks"
	MetricVulnerable = "scan.vulnerable"
	MetricFindings   = "scan.findings"

	MetricCheckDuration = "scan.check-duration"
)

// Check statuses, the values of scan.checks' status dimension.
const (
	StatusPassed     = "passed"
	StatusVulnerable = "vulnerable"
	StatusSkipped    = "skipped"
	StatusError      = "error"
)

// Severities, the values of the severity dimension, most severe first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

var (
	checks     = argvio.NewCounter(MetricChecks, argvio.Dims("status"))
	vulnerable = argvio.NewCounter(MetricVulnerable, argvio.Dims("check", "severity"))
	findings   = argvio.NewValue(MetricFindings, argvio.Dims("severity"), argvio.WithUnit(argvio.UnitCount))

	checkDuration = argvio.NewDuration(MetricCheckDuration, argvio.Dims("check"))
)

// Config configures a Reporter.
type Config struct {
	// CheckDefs gives each check's CVSS score, from which its severity is
	// derived like in the report. A check without one is "info".
	CheckDefs map[harnessx.CheckID]checkdef.CheckDef

	// BaselineCheckID, if set, is a check that only measures the target's
	// normal behaviour and is left out of the metrics. When CheckDefs is set,
	// checks it has no definition for (helpers that fetch or probe for other
	// checks) are left out too.
	BaselineCheckID harnessx.CheckID

	// Findings, if set, counts the findings of a result for CLIs whose checks
	// return their own finding type in Result.Data. ok false falls back to
	// the default: one per observation, plus one for a vulnerable
	// harnessreport.Result.
	Findings func(harnessx.Result) (n int, ok bool)
}

// Reporter implements harnessx.Reporter.
type Reporter struct {
	ctx context.Context
	cfg Config

	mu         sync.Mutex
	bySeverity map[string]int
}

// New returns a Reporter ready to be registered with harnessx.WithReporters.
func New(ctx context.Context, cfg Config) *Reporter {
	return &Reporter{ctx: ctx, cfg: cfg, bySeverity: map[string]int{}}
}

func (r *Reporter) OnScanStart(harnessx.Target, int) {
	r.mu.Lock()
	r.bySeverity = map[string]int{}
	r.mu.Unlock()
}

func (r *Reporter) OnCheckStart(harnessx.Check, harnessx.Target, *harnessx.Resource) {}

func (r *Reporter) OnCheckComplete(result harnessx.Result) {
	if !r.reported(result.CheckID) {
		return
	}
	if !result.Skipped {
		checkDuration.Record(r.ctx, result.Duration, Identifier(string(result.CheckID)))
	}
	status, n := outcome(result)
	if status == StatusPassed && r.cfg.Findings != nil {
		if custom, ok := r.cfg.Findings(result); ok && custom > 0 {
			status, n = StatusVulnerable, custom
		}
	}
	checks.Add(r.ctx, 1, status)
	if n == 0 {
		return
	}
	severity := r.severity(result)
	vulnerable.Add(r.ctx, 1, Identifier(string(result.CheckID)), severity)
	r.mu.Lock()
	r.bySeverity[severity] += n
	r.mu.Unlock()
}

func (r *Reporter) OnScanComplete(harnessx.ScanSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sev := range Severities {
		findings.Record(r.ctx, float64(r.bySeverity[sev]), sev)
	}
}

func (r *Reporter) reported(id harnessx.CheckID) bool {
	if r.cfg.BaselineCheckID != "" && id == r.cfg.BaselineCheckID {
		return false
	}
	if len(r.cfg.CheckDefs) > 0 {
		_, ok := r.cfg.CheckDefs[id]
		return ok
	}
	return true
}

// outcome classifies result and counts its findings: one per observation,
// plus one when the check reported a vulnerable harnessreport.Result.
func outcome(result harnessx.Result) (status string, findings int) {
	pr, hasPR := harnessx.DataAs[harnessreport.Result](result)
	switch {
	case result.Err != nil || (hasPR && pr.Err != nil):
		return StatusError, 0
	case result.Skipped || (hasPR && pr.Skipped):
		return StatusSkipped, 0
	}
	findings = len(result.Observations)
	if hasPR && pr.Vulnerable {
		findings++
	}
	if findings > 0 {
		return StatusVulnerable, findings
	}
	return StatusPassed, 0
}

func (r *Reporter) severity(result harnessx.Result) string {
	cvss := r.cfg.CheckDefs[result.CheckID].CVSSScore
	if pr, ok := harnessx.DataAs[harnessreport.Result](result); ok && pr.CVSSScore > 0 {
		cvss = pr.CVSSScore
	}
	return string(score.Label(cvss))
}

// Identifier turns a check ID chosen in code into an Argvio identifier
// (^[a-z0-9][a-z0-9._-]*$, at most 64 bytes): lower case, every run of other
// characters becomes one "-", leading and trailing ones are dropped.
// "kidinjection (path)" becomes "kidinjection-path".
func Identifier(id string) string {
	s := strings.Trim(nonIdentifier.ReplaceAllString(strings.ToLower(id), "-"), "._-")
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "._-")
	}
	if s == "" {
		return "other"
	}
	return s
}

var nonIdentifier = regexp.MustCompile(`[^a-z0-9._-]+`)
