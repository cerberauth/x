// Package harnessreport bridges harnessx's live Reporter hooks to reportx,
// so a reportx report is built and delivered with no post-scan glue code
// required in the caller.
package harnessreport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/score"
)

// Sink is an alias for reportx.Sink, kept so callers configuring a Reporter
// don't need to import reportx directly for it.
type Sink = reportx.Sink

// Config configures a Reporter.
type Config struct {
	ToolName    string
	ToolVersion string
	Title       string
	Sinks       []Sink

	// ShowAllFindings disables the default behavior of only writing
	// vulnerable findings to stdout - with it set, stdout gets every
	// finding, vulnerable or not, just like every other sink. Sinks other
	// than stdout (files, HTTP transports, ...) always receive every
	// finding regardless of this flag.
	ShowAllFindings bool

	// CheckDefs supplies per-check metadata (name, CVSS, CWE, OWASP, link,
	// description) that harnessx.Check itself doesn't carry.
	CheckDefs map[harnessx.CheckID]checkdef.CheckDef

	// BaselineCheckID, if set, marks a check whose Result carries an int
	// baseline status code rather than a finding; it's excluded from
	// findings.
	BaselineCheckID harnessx.CheckID
}

// Reporter implements harnessx.Reporter, accumulating results live during a
// scan and building/delivering a reportx report once the scan completes.
type Reporter struct {
	ctx context.Context
	cfg Config

	mu          sync.Mutex
	target      string
	results     []Result
	obsFindings []reportx.Finding
	err         error
}

// New returns a Reporter ready to be registered via harnessx.WithReporters.
func New(ctx context.Context, cfg Config) *Reporter {
	return &Reporter{ctx: ctx, cfg: cfg}
}

func (r *Reporter) OnScanStart(target harnessx.Target, _ int) {
	r.mu.Lock()
	r.target = target.URL
	r.mu.Unlock()
}

func (r *Reporter) OnCheckStart(harnessx.Check, harnessx.Target, *harnessx.Resource) {}

func (r *Reporter) OnCheckComplete(result harnessx.Result) {
	if r.cfg.BaselineCheckID != "" && result.CheckID == r.cfg.BaselineCheckID {
		return
	}

	def := r.cfg.CheckDefs[result.CheckID]

	var obsFindings []reportx.Finding
	for _, obs := range result.Observations {
		obsFindings = append(obsFindings, findingFromObservation(obs, def))
	}

	pr, ok := harnessx.DataAs[Result](result)
	if !ok {
		if !result.Skipped {
			if len(obsFindings) > 0 {
				r.mu.Lock()
				r.obsFindings = append(r.obsFindings, obsFindings...)
				r.mu.Unlock()
			}
			return
		}
		pr = Result{Skipped: true, SkipReason: result.SkipReason}
	}

	if pr.Name == "" {
		pr.Name = def.Name
	}
	pr.CVSSVector = def.CVSSVector
	pr.CVSSScore = def.CVSSScore
	pr.CWEID = def.CWEID
	pr.OWASP = def.OWASP
	pr.CAPECID = def.CAPECID
	pr.Tags = def.Tags
	pr.DefExtra = def.Extra
	pr.Link = def.Link
	pr.Description = def.Description

	r.mu.Lock()
	r.results = append(r.results, pr)
	r.obsFindings = append(r.obsFindings, obsFindings...)
	r.mu.Unlock()
}

// findingFromObservation converts a harnessx.Observation — a check-emitted,
// finding-worthy record independent of the Data/DataAs[Result] convention —
// into a reportx.Finding, falling back to the check's CheckDef for the
// scoring/classification metadata Observation doesn't carry itself.
func findingFromObservation(obs harnessx.Observation, def checkdef.CheckDef) reportx.Finding {
	f := reportx.Finding{
		ID:           obs.Title,
		Title:        obs.Title,
		Description:  obs.Description,
		URL:          def.Link,
		CWEID:        def.CWEID,
		OwaspTop10:   def.OWASP,
		CVSS40Score:  def.CVSSScore,
		CVSS40Vector: def.CVSSVector,
		Tags:         def.Tags,
		Status:       reportx.StatusActive,
	}
	if def.CVSSScore > 0 {
		f.Severity = score.Label(def.CVSSScore)
	}
	if obs.Evidence != "" {
		f.Evidence = &evidence.CustomEvidence{Data: map[string]any{"evidence": obs.Evidence}}
	}
	if def.CAPECID != "" || len(obs.Metadata) > 0 {
		f.Extra = map[string]string{}
		if def.CAPECID != "" {
			f.Extra["capec_id"] = def.CAPECID
		}
		for k, v := range obs.Metadata {
			f.Extra[k] = v
		}
	}
	return f
}

func (r *Reporter) OnScanComplete(_ harnessx.ScanSummary) {
	r.mu.Lock()
	target := r.target
	results := r.results
	obsFindings := r.obsFindings
	r.mu.Unlock()

	err := r.build(r.ctx, target, results, obsFindings)

	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

// Err returns any error from building, writing, or sending the reportx
// report. Safe to call once the harnessx engine.Run that registered this
// Reporter has returned, since OnScanComplete runs synchronously beforehand.
func (r *Reporter) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// findingFromResult converts a vulnerable Result into a reportx.Finding.
func findingFromResult(pr Result, target string) reportx.Finding {
	f := reportx.Finding{
		ID:           pr.Name,
		Title:        pr.Name,
		Description:  pr.Description,
		URL:          pr.Link,
		CWEID:        pr.CWEID,
		OwaspTop10:   pr.OWASP,
		CVSS40Score:  pr.CVSSScore,
		CVSS40Vector: pr.CVSSVector,
		Tags:         pr.Tags,
		Status:       reportx.StatusActive,
		Parameter:    pr.Payload,
	}
	if pr.CVSSScore > 0 {
		f.Severity = score.Label(pr.CVSSScore)
	}

	ev := &evidence.HTTPEvidence{}
	if pr.Status != 0 {
		ev.RequestMethod = "GET"
		ev.RequestURL = target
		ev.ResponseStatus = pr.Status
	}
	f.Evidence = ev

	if pr.Extra != "" || pr.CAPECID != "" || len(pr.DefExtra) > 0 {
		f.Extra = map[string]string{}
		if pr.Extra != "" {
			f.Extra["detail"] = pr.Extra
		}
		if pr.CAPECID != "" {
			f.Extra["capec_id"] = pr.CAPECID
		}
		for k, v := range pr.DefExtra {
			f.Extra[k] = fmt.Sprint(v)
		}
	}
	return f
}

// build constructs a reportx.Report from accumulated results and
// writes/sends it. Every finding, vulnerable or not, is part of the report;
// stdout is the one exception, where only vulnerable findings are shown
// unless Config.ShowAllFindings is set.
func (r *Reporter) build(ctx context.Context, target string, results []Result, obsFindings []reportx.Finding) error {
	findings, vulnerable := mergeFindings(obsFindings, results, target)

	reportTarget := target
	if reportTarget == "" {
		reportTarget = "(offline)"
	}

	report, err := reportx.NewBuilder().
		Tool(r.cfg.ToolName, r.cfg.ToolVersion).
		Target(reportTarget).
		Title(r.cfg.Title).
		Findings(findings).
		Enrich(enrich.EnrichAll).
		Build(ctx)
	if err != nil {
		return err
	}

	if r.cfg.ShowAllFindings {
		return report.DeliverAll(ctx, r.cfg.Sinks)
	}

	return r.deliverVulnerableOnly(ctx, report, vulnerable)
}

func mergeFindings(obsFindings []reportx.Finding, results []Result, target string) ([]reportx.Finding, []bool) {
	findings := append([]reportx.Finding{}, obsFindings...)
	vulnerable := make([]bool, len(obsFindings))
	for i := range vulnerable {
		vulnerable[i] = true
	}
	for _, pr := range results {
		findings = append(findings, findingFromResult(pr, target))
		vulnerable = append(vulnerable, pr.Vulnerable)
	}
	return findings, vulnerable
}

func (r *Reporter) deliverVulnerableOnly(ctx context.Context, report *reportx.Report, vulnerable []bool) error {
	vulnOnly := *report
	vulnOnly.Findings = nil
	for i, f := range report.Findings {
		if vulnerable[i] {
			vulnOnly.Findings = append(vulnOnly.Findings, f)
		}
	}

	var errs []error
	for _, s := range r.cfg.Sinks {
		rep := report
		if isStdout(s) {
			rep = &vulnOnly
		}
		if err := rep.DeliverAll(ctx, []Sink{s}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// isStdout reports whether s writes directly to stdout - the one sink whose
// display is limited to vulnerable findings by default.
func isStdout(s Sink) bool {
	return s.Writer == os.Stdout
}
