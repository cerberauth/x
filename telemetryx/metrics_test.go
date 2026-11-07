package telemetryx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
)

// A package-level handle made before Instrument records on the client
// Instrument creates, and follows the default when Instrument runs again.
func TestHandles_BindToTheCurrentClient(t *testing.T) {
	isolateArgvioEnv(t)
	k := argvio.NewCounter("early.counter")
	for _, name := range []string{"first", "second"} {
		t.Run(name, func(t *testing.T) {
			metrics, _ := collect(t, func(ctx context.Context) { k.Add(ctx, 1) })
			if !strings.Contains(metrics, "early.counter") {
				t.Error("expected the counter to be sent by this Instrument's client")
			}
		})
	}
}

// argvio's cobrasdk records a panicking command and flushes before the panic
// goes on; check it still does through Instrument.
func TestInstrument_RecordsPanicsWithoutTheValue(t *testing.T) {
	isolateArgvioEnv(t)
	var mu sync.Mutex
	var logs []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		if r.URL.Path == "/v1/logs" {
			logs = append(logs, b...)
		}
		mu.Unlock()
	}))
	defer srv.Close()
	useArgvioAt(t, srv.URL)
	setArgs(t, "sub")
	origClient := argvioClient
	t.Cleanup(func() { argvioClient = origClient })

	var ran bool
	root := newTestRoot(&ran)
	root.Commands()[0].Run = func(*cobra.Command, []string) { panic("secret-user-input") }
	shutdown := Instrument(root, "1.0.0", "argv_live_pub_test")
	defer shutdown(context.Background()) //nolint:errcheck

	root.SetArgs([]string{"sub"})
	func() {
		defer func() {
			if r := recover(); r != "secret-user-input" {
				t.Errorf("expected the original panic to go on, got %v", r)
			}
		}()
		_ = root.Execute()
	}()

	// No shutdown call before reading: the panic path must have flushed.
	mu.Lock()
	defer mu.Unlock()
	got := string(logs)
	for _, want := range []string{"cli.error.raised", "internal", "panic"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the flushed logs", want)
		}
	}
	if strings.Contains(got, "secret-user-input") {
		t.Error("expected the panic value not to be sent")
	}
}
