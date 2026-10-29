package telemetryx

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/getargvio/argvio-go"
	"github.com/getargvio/argvio-go/cobrasdk"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
)

const (
	// optOutFlag is the persistent flag every CerberAuth CLI exposes to opt
	// out of usage statistics.
	optOutFlag = "sqa-opt-out"
)

// argvioNew is a seam for test injection.
var argvioNew = argvio.New

// Instrument wires Argvio CLI usage analytics (command, flag names, exit
// code, latency, help usage, sessions) into root's entire command tree. It
// must be called once the tree is fully built and before root is executed,
// since it wraps each command's RunE at call time.
//
// apiKey is the CLI's own public_ingest-scoped Argvio API key, which selects
// the Argvio tenant its data lands in. It only allows sending usage data, so
// it is meant to be embedded in the CLI. The telemetry.cerberauth.com
// collector forwards it to Argvio as is.
//
// Telemetry is disabled when --sqa-opt-out is passed, as well as by
// DO_NOT_TRACK or ARGVIO_DISABLED (handled by argvio). Interactive runs
// report at argvio.TierBasic, CI runs at argvio.TierAnonymous.
//
// Failed commands are reported with an error category and, when the error
// carries one, a reason (see Classified and Reason). Errors returned from a
// command's RunE and errors passed to Fatal are classified the same way, by the
// default classifier unless WithClassifier gives another.
//
// The returned shutdown function must be called before the process exits,
// including before any os.Exit. It is always non-nil and safe to call more
// than once.
func Instrument(root *cobra.Command, version, apiKey string, opts ...InstrumentOption) func(context.Context) error {
	cfg := instrumentConfig{classifier: classify}
	for _, opt := range opts {
		opt(&cfg)
	}

	// See New: export failures must never be surfaced on stderr.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))

	argvioOpts := []argvio.Option{
		argvio.WithEndpoint(otelEndpoint),
		argvio.WithHTTPTransport(),
		argvio.WithDisableOTELEnvFallback(),
		argvio.WithExportTimeout(timeout),
		argvio.WithShutdownTimeout(timeout),
		argvio.WithConsentProvider(argvio.ChainProviders(
			argvio.EnvConsentProvider{},
			argvio.StaticProvider{Tier: argvio.TierBasic},
		)),
	}
	if optedOut(os.Args[1:]) {
		argvioOpts = append(argvioOpts, argvio.WithDisabled())
	}

	// New always returns a usable client, degraded to a no-op on error.
	client, _ := argvioNew(apiKey, root.Name(), version, argvioOpts...)
	argvioClient = client
	cobrasdk.InstrumentCobra(root, client, cobrasdk.WithErrorClassification(cfg.classifier))

	return func(ctx context.Context) error {
		return client.Shutdown(ctx)
	}
}

// InstrumentOption configures Instrument.
type InstrumentOption func(*instrumentConfig)

type instrumentConfig struct {
	classifier Classifier
}

// WithClassifier replaces the default error classifier, which maps deadlines,
// cancellations, network errors, missing files, Cobra usage errors and errors
// wrapped with Classified or Reason. A nil f keeps the default.
func WithClassifier(f Classifier) InstrumentOption {
	return func(c *instrumentConfig) {
		if f != nil {
			c.classifier = f
		}
	}
}

// argvioClient is the client Instrument set up, for Exit.
var argvioClient *argvio.Client

// osExit is a seam for test injection.
var osExit = os.Exit

// Exit records cmd as having finished with code, flushes all telemetry, then
// exits the process with code. Use it instead of os.Exit inside a command's
// Run/RunE: os.Exit skips the hooks that record a command's outcome and the
// deferred telemetry shutdowns. A non-zero code is recorded as an error of
// unknown category; use Fatal to report what went wrong.
func Exit(cmd *cobra.Command, code int) {
	exit(cmd, nil, code)
}

// Fatal is log.Fatal for use inside a command's Run/RunE: it logs v like
// log.Print, records the first error in v (or v's text) as the failure, then
// exits with code 1. The failure is reported with the category and reason the
// classifier gives it, so wrap err with Classified or Reason where the cause
// is known:
//
//	telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-url"))
func Fatal(cmd *cobra.Command, v ...any) {
	log.Print(v...)
	exit(cmd, errorFrom(v), 1)
}

func exit(cmd *cobra.Command, err error, code int) {
	if err != nil {
		cobrasdk.RecordExitError(cmd, argvioClient, err, code)
	} else {
		cobrasdk.RecordExit(cmd, argvioClient, code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*timeout)
	_ = argvioClient.Shutdown(ctx)
	if otelShutdown != nil {
		_ = otelShutdown(ctx)
	}
	cancel()
	osExit(code)
}

// Feature records that the user used one of the CLI's capabilities, so it
// shows up in Argvio's feature discovery. It is a no-op until Instrument has
// run, when telemetry is disabled, and at the anonymous tier (CI runs).
//
// name must be a fixed identifier chosen in code, such as "crack.john-detected",
// never user input: Argvio sends it as is, does not scrub it, and cuts it to 64
// bytes. Each name is reported at most once per process, and carries no count.
func Feature(ctx context.Context, name string) {
	argvioClient.RecordFeatureActivated(ctx, name)
}

// Counter adds n to a product counter in Argvio, for a number the CLI itself
// cares about, such as the OpenAPI operations in a scan. label is an optional
// second identifier ("" for none). It is a no-op until Instrument has run, when
// telemetry is disabled, and for n <= 0.
//
// WARNING: counters are accepted at the anonymous tier, so they are also sent
// from CI and when the user granted no consent. name and label must be fixed
// identifiers chosen in code ("openapi.scheme", "bearer"). Never pass user
// input, file paths, host names, URLs, tokens or anything derived from them.
// Argvio does not scrub them; it only drops a name or label that doesn't match
// ^[a-z0-9][a-z0-9._-]*$ or is longer than 64 bytes.
func Counter(ctx context.Context, name string, n int64, label string) {
	var opts []argvio.CounterOption
	if label != "" {
		opts = append(opts, argvio.WithLabel(label))
	}
	argvioClient.RecordCounter(ctx, name, n, opts...)
}

// optedOut reports whether args set --sqa-opt-out. The Argvio client has to
// be built before Cobra parses flags, so the flag is looked up on its own,
// ignoring every other flag.
func optedOut(args []string) bool {
	fs := pflag.NewFlagSet(optOutFlag, pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.SetOutput(io.Discard)
	optOut := fs.Bool(optOutFlag, false, "")
	// Declared so --help doesn't stop parsing with pflag.ErrHelp.
	fs.BoolP("help", "h", false, "")
	_ = fs.Parse(args)
	return *optOut
}
