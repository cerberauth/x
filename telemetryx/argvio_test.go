package telemetryx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
)

type argvioCall struct {
	apiKey, cliName, version string
	client                   *argvio.Client
}

// useLocalArgvio installs a test seam that builds a real argvio Client, but
// exporting to an unreachable local endpoint so tests never reach the
// network. It records what Instrument constructed the client with.
func useLocalArgvio(t *testing.T) *argvioCall {
	t.Helper()
	return useArgvioAt(t, "http://127.0.0.1:1")
}

// useArgvioAt is useLocalArgvio exporting to endpoint instead.
func useArgvioAt(t *testing.T, endpoint string) *argvioCall {
	t.Helper()
	// A developer's own opt-outs must not disable the client under test.
	t.Setenv("DO_NOT_TRACK", "")
	t.Setenv("ARGVIO_DISABLED", "")
	orig := argvioNew
	call := &argvioCall{}
	argvioNew = func(apiKey, cliName, version string, opts ...argvio.Option) (*argvio.Client, error) {
		opts = append(opts,
			argvio.WithEndpoint(endpoint),
			argvio.WithInstallIDPath(filepath.Join(t.TempDir(), "install-id")),
		)
		c, err := orig(apiKey, cliName, version, opts...)
		call.apiKey, call.cliName, call.version, call.client = apiKey, cliName, version, c
		return c, err
	}
	t.Cleanup(func() { argvioNew = orig })
	return call
}

// argvioEnvVars are the variables argvio reads, beyond those clearCIEnv clears:
// the remaining CI providers it treats as "running in CI", and the opt-outs.
var argvioEnvVars = []string{
	"TEAMCITY_VERSION", "APPVEYOR", "TF_BUILD", "DRONE", "CODEBUILD_BUILD_ID",
	"BITBUCKET_BUILD_NUMBER", "DO_NOT_TRACK", "ARGVIO_DISABLED",
}

// isolateArgvioEnv gives a test an interactive, opted-in client whether it runs
// on a laptop or in CI, so it passes the same in both.
func isolateArgvioEnv(t *testing.T) {
	t.Helper()
	clearCIEnv(t)
	for _, name := range argvioEnvVars {
		t.Setenv(name, "")
	}
}

func setArgs(t *testing.T, args ...string) {
	t.Helper()
	orig := os.Args
	os.Args = append([]string{"test-cli"}, args...)
	t.Cleanup(func() { os.Args = orig })
}

func newTestRoot(ran *bool) *cobra.Command {
	root := &cobra.Command{Use: "test-cli", Version: "1.0.0 (commit=abc)"}
	root.PersistentFlags().Bool(optOutFlag, false, "")
	root.AddCommand(&cobra.Command{
		Use: "sub",
		Run: func(*cobra.Command, []string) { *ran = true },
	})
	return root
}

func TestInstrument_BuildsClientFromKeyRootNameAndVersion(t *testing.T) {
	call := useLocalArgvio(t)
	setArgs(t, "sub")

	var ran bool
	shutdown := Instrument(newTestRoot(&ran), "1.0.0", "argv_live_pub_test")
	defer shutdown(context.Background()) //nolint:errcheck

	if call.apiKey != "argv_live_pub_test" {
		t.Errorf("expected the CLI's API key, got %q", call.apiKey)
	}
	if call.cliName != "test-cli" {
		t.Errorf("expected cli name %q, got %q", "test-cli", call.cliName)
	}
	if call.version != "1.0.0" {
		t.Errorf("expected version %q, got %q", "1.0.0", call.version)
	}
	if call.client.Disabled() {
		t.Error("expected client to be enabled without --sqa-opt-out")
	}
}

func TestInstrument_DisabledWithOptOutFlag(t *testing.T) {
	call := useLocalArgvio(t)
	setArgs(t, "sub", "--sqa-opt-out")

	var ran bool
	shutdown := Instrument(newTestRoot(&ran), "1.0.0", "argv_live_pub_test")
	defer shutdown(context.Background()) //nolint:errcheck

	if !call.client.Disabled() {
		t.Error("expected client to be disabled with --sqa-opt-out")
	}
}

func TestInstrument_DisabledWithoutAPIKey(t *testing.T) {
	call := useLocalArgvio(t)
	setArgs(t, "sub")

	var ran bool
	shutdown := Instrument(newTestRoot(&ran), "1.0.0", "")
	defer shutdown(context.Background()) //nolint:errcheck

	if !call.client.Disabled() {
		t.Error("expected client to be disabled when the build has no API key")
	}
}

func TestInstrument_CommandsStillRun(t *testing.T) {
	useLocalArgvio(t)
	setArgs(t, "sub")

	var ran bool
	root := newTestRoot(&ran)
	shutdown := Instrument(root, "1.0.0", "argv_live_pub_test")

	root.SetArgs([]string{"sub"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if !ran {
		t.Error("expected the instrumented subcommand to run")
	}
	// The local endpoint is unreachable, so the flush error is expected;
	// CLIs discard it. Shutdown must also be safe to call twice: CLIs call
	// it explicitly before os.Exit and again from a deferred call.
	_ = shutdown(context.Background())
	_ = shutdown(context.Background())
}

func TestExit_RecordsFlushesAndExits(t *testing.T) {
	useLocalArgvio(t)
	setArgs(t, "sub")
	origExit, origOtel := osExit, otelShutdown
	t.Cleanup(func() { osExit, otelShutdown = origExit, origOtel })
	var exitCode int
	osExit = func(code int) { exitCode = code }
	otelFlushed := false
	otelShutdown = func(context.Context) error { otelFlushed = true; return nil }

	var ran bool
	root := newTestRoot(&ran)
	root.Commands()[0].Run = func(cmd *cobra.Command, _ []string) { Exit(cmd, 2) }
	defer Instrument(root, "1.0.0", "argv_live_pub_test")(context.Background()) //nolint:errcheck

	root.SetArgs([]string{"sub"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2, got %d", exitCode)
	}
	if !otelFlushed {
		t.Error("expected Exit to flush the OTel pipeline")
	}
}

func TestFatal_ClassifiesTheErrorAndExits(t *testing.T) {
	useLocalArgvio(t)
	setArgs(t, "sub")
	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	var exitCode int
	osExit = func(code int) { exitCode = code }

	var gotErr error
	classifier := func(err error) (argvio.ErrorCategory, string) {
		gotErr = err
		return argvio.ErrorCategoryNetwork, "probe-failed"
	}

	var ran bool
	root := newTestRoot(&ran)
	failure := errors.New("connection refused")
	root.Commands()[0].Run = func(cmd *cobra.Command, _ []string) {
		Fatal(cmd, "scan failed:", failure)
	}
	defer Instrument(root, "1.0.0", "argv_live_pub_test", WithClassifier(classifier))(context.Background()) //nolint:errcheck

	root.SetArgs([]string{"sub"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if gotErr != failure {
		t.Errorf("expected the classifier to receive the error passed to Fatal, got %v", gotErr)
	}
}

func TestExit_NonZeroWithoutErrorIsStillRecorded(t *testing.T) {
	useLocalArgvio(t)
	setArgs(t, "sub")
	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	var exitCode int
	osExit = func(code int) { exitCode = code }

	var ran bool
	root := newTestRoot(&ran)
	root.Commands()[0].Run = func(cmd *cobra.Command, _ []string) { Exit(cmd, 3) }
	defer Instrument(root, "1.0.0", "argv_live_pub_test")(context.Background()) //nolint:errcheck

	root.SetArgs([]string{"sub"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if exitCode != 3 {
		t.Errorf("expected exit code 3, got %d", exitCode)
	}
}

func TestInstrument_ClassifiesErrorsReturnedFromRunE(t *testing.T) {
	useLocalArgvio(t)
	setArgs(t, "sub")

	var gotErr error
	classifier := func(err error) (argvio.ErrorCategory, string) {
		gotErr = err
		return argvio.ErrorCategoryUser, "bad-input"
	}

	var ran bool
	root := newTestRoot(&ran)
	root.SilenceErrors, root.SilenceUsage = true, true
	failure := errors.New("bad input")
	root.Commands()[0].Run = nil
	root.Commands()[0].RunE = func(*cobra.Command, []string) error { return failure }
	defer Instrument(root, "1.0.0", "argv_live_pub_test", WithClassifier(classifier))(context.Background()) //nolint:errcheck

	root.SetArgs([]string{"sub"})
	if err := root.Execute(); !errors.Is(err, failure) {
		t.Fatalf("expected the command's error back, got %v", err)
	}
	if gotErr != failure {
		t.Errorf("expected the classifier to receive the RunE error, got %v", gotErr)
	}
}

func TestWithClassifier_NilKeepsTheDefault(t *testing.T) {
	cfg := instrumentConfig{classifier: classify}
	WithClassifier(nil)(&cfg)
	category, _ := cfg.classifier(context.DeadlineExceeded)
	if category != argvio.ErrorCategoryTimeout {
		t.Errorf("expected the default classifier to remain, got category %q", category)
	}
}

func TestFeatureAndCounter_AreSafeBeforeInstrumentAndWhenDisabled(t *testing.T) {
	origClient, origDefault := argvioClient, argvio.Default()
	t.Cleanup(func() { argvioClient = origClient; argvio.SetDefault(origDefault) })
	ctx := context.Background()

	// Before Instrument has run there is no client.
	argvioClient = nil
	argvio.SetDefault(nil)
	ops := argvio.NewCounter("openapi.operations")
	scheme := argvio.NewCounter("openapi.scheme", argvio.Dims("scheme"))
	Feature(ctx, "crack.john-detected")
	ops.Add(ctx, 3)

	// With telemetry disabled by the opt-out flag.
	useLocalArgvio(t)
	setArgs(t, "sub", "--sqa-opt-out")
	var ran bool
	defer Instrument(newTestRoot(&ran), "1.0.0", "argv_live_pub_test")(ctx) //nolint:errcheck
	Feature(ctx, "crack.john-detected")
	ops.Add(ctx, 3)
	scheme.Add(ctx, 1, "bearer")
	argvio.NewCounter("not a valid name").Add(ctx, 1)
	ops.Add(ctx, 0)
}

// collect runs Instrument against a local collector, calls fn, flushes, and
// returns the metrics and logs payloads the collector received.
func collect(t *testing.T, fn func(ctx context.Context)) (metrics, logs string) {
	t.Helper()
	return collectWith(t, nil, func(_ *cobra.Command, ctx context.Context) { fn(ctx) })
}

// collectWith is collect with Instrument options, and fn also gets the root.
func collectWith(t *testing.T, opts []InstrumentOption, fn func(root *cobra.Command, ctx context.Context)) (metrics, logs string) {
	t.Helper()
	var mu sync.Mutex
	bodies := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies[r.URL.Path] = append(bodies[r.URL.Path], b...)
		mu.Unlock()
	}))
	defer srv.Close()

	useArgvioAt(t, srv.URL)
	setArgs(t, "sub")
	origClient, origDefault := argvioClient, argvio.Default()
	t.Cleanup(func() { argvioClient = origClient; argvio.SetDefault(origDefault) })

	var ran bool
	root := newTestRoot(&ran)
	shutdown := Instrument(root, "1.0.0", "argv_live_pub_test", opts...)
	ctx := context.Background()
	fn(root, ctx)
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	return string(bodies["/v1/metrics"]), string(bodies["/v1/logs"])
}

func TestFeatureAndCounter_AreSentToTheCollector(t *testing.T) {
	isolateArgvioEnv(t)
	metrics, logs := collect(t, func(ctx context.Context) {
		argvio.NewCounter("openapi.scheme", argvio.Dims("scheme")).Add(ctx, 2, "bearer")
		argvio.NewCounter("Not Valid").Add(ctx, 1)
		Feature(ctx, "crack.john-detected")
	})

	for _, want := range []string{"cli.counter", "openapi.scheme", "bearer"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("expected the metrics payload to contain %q", want)
		}
	}
	if strings.Contains(metrics, "Not Valid") {
		t.Error("expected a counter with an invalid name to be dropped")
	}
	if !strings.Contains(logs, "crack.john-detected") {
		t.Error("expected the logs payload to contain the activated feature")
	}
}

// In CI the client reports at the anonymous tier: counters are accepted
// there, features need the basic tier and are not sent.
func TestFeatureAndCounter_InCIOnlyCountersAreSent(t *testing.T) {
	isolateArgvioEnv(t)
	t.Setenv("CI", "true")
	metrics, logs := collect(t, func(ctx context.Context) {
		argvio.NewCounter("openapi.scheme", argvio.Dims("scheme")).Add(ctx, 1, "bearer")
		Feature(ctx, "crack.john-detected")
	})

	if !strings.Contains(metrics, "openapi.scheme") {
		t.Error("expected the counter to be sent from CI")
	}
	if strings.Contains(logs, "crack.john-detected") {
		t.Error("expected the feature not to be sent from CI")
	}
}

func TestDuration_IsSentToTheCollector(t *testing.T) {
	isolateArgvioEnv(t)
	metrics, _ := collect(t, func(ctx context.Context) {
		argvio.NewDuration("crack.external-tool", argvio.Dims("tool")).Record(ctx, 1500*time.Millisecond, "john")
		argvio.NewDuration("Not Valid").Record(ctx, time.Second)
		argvio.NewDuration("crack.zero").Record(ctx, 0)
		argvio.NewDuration("openapi.load").Start(ctx)()
		argvio.NewDuration("openapi.parse", argvio.Dims("format")).StartLate(ctx)("json")
	})

	for _, want := range []string{"cli.measure", "crack.external-tool", "cli.dim.tool", "john", "openapi.load", "openapi.parse", "cli.dim.format"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("expected the metrics payload to contain %q", want)
		}
	}
	for _, dropped := range []string{"Not Valid", "crack.zero"} {
		if strings.Contains(metrics, dropped) {
			t.Errorf("expected %q to be dropped", dropped)
		}
	}
}

// Durations, like counters, are accepted at the anonymous tier.
func TestDuration_InCIIsStillSent(t *testing.T) {
	isolateArgvioEnv(t)
	t.Setenv("CI", "true")
	metrics, _ := collect(t, func(ctx context.Context) {
		argvio.NewDuration("crack.external-tool").Record(ctx, time.Second)
	})
	if !strings.Contains(metrics, "crack.external-tool") {
		t.Error("expected the duration to be sent from CI")
	}
}

func TestSessionStart_ReportsEnvironmentConfigAndAuthState(t *testing.T) {
	isolateArgvioEnv(t)
	t.Setenv("SHELL", "/bin/zsh")
	var configRuns int
	_, logs := collectWith(t, []InstrumentOption{
		WithConfigCustomizedCount(func() (int, bool) { configRuns++; return 7, true }),
		WithAuthState(func() (argvio.AuthState, bool) { return argvio.AuthStateAuthenticated, true }),
	}, func(root *cobra.Command, ctx context.Context) {
		root.SetArgs([]string{"sub"})
		if err := root.Execute(); err != nil {
			t.Fatalf("Execute() error: %v", err)
		}
	})

	for _, want := range []string{"cli.session.started", "cli.shell", "zsh", "cli.stdout.is_tty", "cli.config.customized_count", "cli.auth.state", "authenticated"} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected the session start event to contain %q", want)
		}
	}
	if configRuns != 1 {
		t.Errorf("expected the config callback to run once, ran %d times", configRuns)
	}
}

func TestSessionStart_LeavesOutWhatIsNotAvailable(t *testing.T) {
	isolateArgvioEnv(t)
	_, logs := collectWith(t, []InstrumentOption{
		WithConfigCustomizedCount(func() (int, bool) { return 0, false }),
		WithAuthState(func() (argvio.AuthState, bool) { return argvio.AuthStateUnknown, false }),
	}, func(root *cobra.Command, ctx context.Context) {
		root.SetArgs([]string{"sub"})
		if err := root.Execute(); err != nil {
			t.Fatalf("Execute() error: %v", err)
		}
	})

	if !strings.Contains(logs, "cli.session.started") {
		t.Fatal("expected a session start event")
	}
	for _, absent := range []string{"cli.config.customized_count", "cli.auth.state"} {
		if strings.Contains(logs, absent) {
			t.Errorf("expected %q to be left out when not available", absent)
		}
	}
}

// The callbacks read the user's config and credentials, so they must not run
// when telemetry is off or the run is anonymous.
func TestSessionStart_CallbacksDoNotRunWithoutConsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"in CI", map[string]string{"CI": "true"}, []string{"sub"}},
		{"opted out by flag", nil, []string{"sub", "--sqa-opt-out"}},
		{"opted out by DO_NOT_TRACK", map[string]string{"DO_NOT_TRACK": "1"}, []string{"sub"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateArgvioEnv(t)
			useLocalArgvio(t) // clears the opt-outs, so set the case's env after it
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			setArgs(t, tc.args...)
			origClient := argvioClient
			t.Cleanup(func() { argvioClient = origClient })

			var ran, called bool
			root := newTestRoot(&ran)
			defer Instrument(root, "1.0.0", "argv_live_pub_test",
				WithConfigCustomizedCount(func() (int, bool) { called = true; return 1, true }),
				WithAuthState(func() (argvio.AuthState, bool) { called = true; return argvio.AuthStateAnonymous, true }),
			)(context.Background()) //nolint:errcheck

			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("Execute() error: %v", err)
			}
			if called {
				t.Error("expected the session callbacks not to run")
			}
		})
	}
}

func TestExecute_RecordsUnknownCommandAndKeepsTheError(t *testing.T) {
	isolateArgvioEnv(t)
	var gotErr error
	_, logs := collectWith(t, nil, func(root *cobra.Command, ctx context.Context) {
		root.SilenceErrors, root.SilenceUsage = true, true
		root.SetArgs([]string{"sbu"})
		gotErr = Execute(root)
	})

	if gotErr == nil || !strings.HasPrefix(gotErr.Error(), `unknown command "sbu"`) {
		t.Errorf("expected cobra's unknown command error back unchanged, got %v", gotErr)
	}
	if !strings.Contains(logs, "cli.command.unknown") {
		t.Error("expected an unknown command event")
	}
	if strings.Contains(logs, "sbu") {
		t.Error("expected the text the user typed not to be sent")
	}
}

func TestExecute_RunsKnownCommandsAndWorksWithoutInstrument(t *testing.T) {
	origClient, origDefault := argvioClient, argvio.Default()
	t.Cleanup(func() { argvioClient = origClient; argvio.SetDefault(origDefault) })
	argvioClient = nil
	argvio.SetDefault(nil)

	var ran bool
	root := newTestRoot(&ran)
	root.SetArgs([]string{"sub"})
	if err := Execute(root); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if !ran {
		t.Error("expected the subcommand to run")
	}
	argvio.NewDuration("crack.external-tool").Record(context.Background(), time.Second)
	argvio.NewDuration("openapi.load").Start(context.Background())()
	argvio.NewValue("openapi.operations", argvio.WithUnit(argvio.UnitCount)).Record(context.Background(), 3)
	argvio.NewCounter("openapi.operations").Add(context.Background(), 3)
	var nilCounter *argvio.Counter
	nilCounter.Add(context.Background(), 1)
}

func TestOptedOut(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"no args", nil, false},
		{"absent", []string{"scan", "--url", "https://example.com"}, false},
		{"flag", []string{"--sqa-opt-out"}, true},
		{"flag after subcommand", []string{"scan", "openapi", "--sqa-opt-out"}, true},
		{"flag among unknown flags", []string{"scan", "-v", "--url", "x", "--sqa-opt-out", "--other=1"}, true},
		{"explicit true", []string{"--sqa-opt-out=true"}, true},
		{"explicit false", []string{"--sqa-opt-out=false"}, false},
		{"after help", []string{"--help", "--sqa-opt-out"}, true},
		{"after short help", []string{"-h", "--sqa-opt-out"}, true},
		{"after terminator", []string{"--", "--sqa-opt-out"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := optedOut(tt.args); got != tt.want {
				t.Errorf("optedOut(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
