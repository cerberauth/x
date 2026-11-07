package telemetryx

import (
	"context"
	"errors"
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
// collector forwards it to Argvio as is. CLIs should not commit it: inject it
// at release time (go build -ldflags "-X ...") from a CI secret. An empty key
// disables telemetry, as in local builds.
//
// Telemetry is disabled when --sqa-opt-out is passed, as well as by
// DO_NOT_TRACK or ARGVIO_DISABLED (handled by argvio). Interactive runs
// report at argvio.TierBasic, CI runs at argvio.TierAnonymous.
//
// Failed commands are reported with an error category and, when the error
// carries one, a reason (see Classified and Reason). Errors returned from a
// command's RunE and errors passed to Fatal are classified the same way, by the
// default classifier unless WithClassifier gives another. A command that
// panics is reported as failed with category internal, reason "panic" and exit
// code 2 (never the panic value), flushed, then the panic goes on.
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
	argvioOpts = append(argvioOpts, cfg.sessionOpt...)
	// An empty key means a build the release pipeline didn't inject one into
	// (a local build, go install): there is nothing to authenticate with, so
	// report nothing rather than send requests the collector would refuse.
	if apiKey == "" || optedOut(os.Args[1:]) {
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
	sessionOpt []argvio.Option
}

// errUnavailable is what a lazy session callback panics with to leave its
// attribute out. argvio recovers a panicking callback and sends nothing for
// it (see argvio.WithConfigCustomizedCountFunc), which is the only way a
// callback can say "not known for this run".
var errUnavailable = errors.New("telemetryx: session attribute not available")

// lazy adapts a callback that can say "not available" to the shape argvio
// takes.
func lazy[T any](fn func() (T, bool)) func() T {
	return func() T {
		v, ok := fn()
		if !ok {
			panic(errUnavailable)
		}
		return v
	}
}

// WithConfigCustomizedCount reports how many of the CLI's configuration keys
// the user has set to something other than the default, on the session start
// event. fn returns false when the count isn't known for this run (for example
// the command doesn't read a config file), and then nothing is sent.
//
// fn runs once, when the command starts and flags have been parsed, and only
// when the user's consent tier allows it, so it never runs for a user who has
// opted out or in CI. Keep it fast. Only the count is sent, never a key name or
// a value; argvio clamps it to [0, 1000].
func WithConfigCustomizedCount(fn func() (n int, ok bool)) InstrumentOption {
	return func(c *instrumentConfig) {
		if fn != nil {
			c.sessionOpt = append(c.sessionOpt, argvio.WithConfigCustomizedCountFunc(lazy(fn)))
		}
	}
}

// WithAuthState reports whether the user is signed in to the CLI vendor's own
// service, on the session start event. fn returns false when the state isn't
// known, and then nothing is sent. It is for CLIs that have an account of
// their own; do not use it for the credentials a CLI sends to a target it
// scans.
//
// fn runs once, under the same conditions as WithConfigCustomizedCount. Nothing
// about the account (name, ID, token) can be passed.
func WithAuthState(fn func() (state argvio.AuthState, ok bool)) InstrumentOption {
	return func(c *instrumentConfig) {
		if fn != nil {
			c.sessionOpt = append(c.sessionOpt, argvio.WithAuthStateFunc(lazy(fn)))
		}
	}
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

// Execute runs root like root.Execute and also records a mistyped command, as
// an unknown-command attempt with the nearest command as suggestion and without
// the text the user typed. Use it in main instead of root.Execute: cobra fails
// on an unknown root subcommand before any hook runs, so Instrument alone can't
// see it. (A mistyped subcommand of a parent that has none to run is recorded
// by Instrument.) It returns exactly the error root.Execute would, so the CLI's
// output and exit code don't change, and it is safe to call without Instrument.
func Execute(root *cobra.Command) error {
	return cobrasdk.Execute(root, argvioClient)
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
