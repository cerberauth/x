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
	origClient := argvioClient
	t.Cleanup(func() { argvioClient = origClient })
	ctx := context.Background()

	// Before Instrument has run there is no client.
	argvioClient = nil
	Feature(ctx, "crack.john-detected")
	Counter(ctx, "openapi.operations", 3, "")

	// With telemetry disabled by the opt-out flag.
	useLocalArgvio(t)
	setArgs(t, "sub", "--sqa-opt-out")
	var ran bool
	defer Instrument(newTestRoot(&ran), "1.0.0", "argv_live_pub_test")(ctx) //nolint:errcheck
	Feature(ctx, "crack.john-detected")
	Counter(ctx, "openapi.operations", 3, "")
	Counter(ctx, "openapi.scheme", 1, "bearer")
	Counter(ctx, "not a valid name", 1, "")
	Counter(ctx, "openapi.operations", 0, "")
}

// collect runs Instrument against a local collector, calls fn, flushes, and
// returns the metrics and logs payloads the collector received.
func collect(t *testing.T, fn func(ctx context.Context)) (metrics, logs string) {
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
	origClient := argvioClient
	t.Cleanup(func() { argvioClient = origClient })

	var ran bool
	shutdown := Instrument(newTestRoot(&ran), "1.0.0", "argv_live_pub_test")
	ctx := context.Background()
	fn(ctx)
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
		Counter(ctx, "openapi.scheme", 2, "bearer")
		Counter(ctx, "Not Valid", 1, "")
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
		Counter(ctx, "openapi.scheme", 1, "bearer")
		Feature(ctx, "crack.john-detected")
	})

	if !strings.Contains(metrics, "openapi.scheme") {
		t.Error("expected the counter to be sent from CI")
	}
	if strings.Contains(logs, "crack.john-detected") {
		t.Error("expected the feature not to be sent from CI")
	}
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
