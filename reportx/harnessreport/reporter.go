// Package harnessreport bridges harnessx's live Reporter hooks to reportx,
// so a reportx report is built and delivered with no post-scan glue code
// required in the caller.
package harnessreport

import (
	"context"
	"io"
	"sync"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/score"
	"github.com/cerberauth/reportx/transport"
	xharnessx "github.com/cerberauth/x/harnessx"
)

// Config configures a Reporter.
type Config struct {
	ToolName    string
	ToolVersion string
	Title       string
	Formatter   format.Formatter
	Writer      io.Writer
	Transport   *transport.HTTPTransport // nil = no HTTP delivery

	// CheckDefs supplies per-check metadata (name, CVSS, CWE, OWASP, link,
	// description) that harnessx.Check itself doesn't carry.
	CheckDefs map[harnessx.CheckID]xharnessx.CheckDef

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

	mu      sync.Mutex
	target  string
	results []Result
	err     error
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

	pr, ok := harnessx.DataAs[Result](result)
	if !ok {
		if !result.Skipped {
			return
		}
		pr = Result{Skipped: true, SkipReason: result.SkipReason}
	}

	def := r.cfg.CheckDefs[result.CheckID]
	if pr.Name == "" {
		pr.Name = def.Name
	}
	pr.CVSSVector = def.CVSSVector
	pr.CVSSScore = def.CVSSScore
	pr.CWEID = def.CWEID
	pr.OWASP = def.OWASP
	pr.Link = def.Link
	pr.Description = def.Description

	r.mu.Lock()
	r.results = append(r.results, pr)
	r.mu.Unlock()
}

func (r *Reporter) OnScanComplete(_ harnessx.ScanSummary) {
	r.mu.Lock()
	target := r.target
	results := r.results
	r.mu.Unlock()

	err := r.build(r.ctx, target, results)

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

// build constructs a reportx.Report from accumulated results and
// writes/sends it.
func (r *Reporter) build(ctx context.Context, target string, results []Result) error {
	var findings []reportx.Finding
	for _, pr := range results {
		if !pr.Vulnerable {
			continue
		}
		f := reportx.Finding{
			ID:           pr.Name,
			Title:        pr.Name,
			Description:  pr.Description,
			URL:          pr.Link,
			CWEID:        pr.CWEID,
			CVSS40Score:  pr.CVSSScore,
			CVSS40Vector: pr.CVSSVector,
			Status:       reportx.StatusActive,
		}
		if pr.CVSSScore > 0 {
			f.Severity = score.Label(pr.CVSSScore)
		}

		f.Parameter = pr.Payload

		ev := &evidence.HTTPEvidence{}
		if pr.Status != 0 {
			ev.RequestMethod = "GET"
			ev.RequestURL = target
			ev.ResponseStatus = pr.Status
		}
		f.Evidence = ev

		if pr.Extra != "" {
			f.Extra = map[string]string{"detail": pr.Extra}
		}
		findings = append(findings, f)
	}

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

	if err := report.WriteTo(ctx, r.cfg.Writer, r.cfg.Formatter); err != nil {
		return err
	}
	if r.cfg.Transport != nil {
		return report.Send(ctx, r.cfg.Transport, r.cfg.Formatter)
	}
	return nil
}
