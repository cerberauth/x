package telemetryx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/getargvio/argvio-go"
)

func TestClassify(t *testing.T) {
	timeoutErr := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	tests := []struct {
		name         string
		err          error
		wantCategory argvio.ErrorCategory
		wantReason   string
	}{
		{"plain", errors.New("boom"), argvio.ErrorCategoryUnknown, ""},
		{"deadline", context.DeadlineExceeded, argvio.ErrorCategoryTimeout, ""},
		{"wrapped deadline", fmt.Errorf("scanning: %w", context.DeadlineExceeded), argvio.ErrorCategoryTimeout, ""},
		{"canceled", fmt.Errorf("scanning: %w", context.Canceled), argvio.ErrorCategoryCanceled, ""},
		{"network timeout", timeoutErr, argvio.ErrorCategoryTimeout, ""},
		{"network error", &net.DNSError{Err: "no such host"}, argvio.ErrorCategoryNetwork, ""},
		{"url error", &url.Error{Op: "Get", URL: "https://example.com", Err: &net.DNSError{Err: "no such host"}}, argvio.ErrorCategoryNetwork, ""},
		{"missing file", fmt.Errorf("reading spec: %w", os.ErrNotExist), argvio.ErrorCategoryUser, ""},
		{"unreadable file", fmt.Errorf("reading spec: %w", os.ErrPermission), argvio.ErrorCategoryUser, ""},
		{"unknown flag", errors.New("unknown flag: --nope"), argvio.ErrorCategoryUser, ""},
		{"unknown command", errors.New(`unknown command "x" for "cli"`), argvio.ErrorCategoryUser, ""},
		{"arg count", errors.New("accepts at most 1 arg(s), received 2"), argvio.ErrorCategoryUser, ""},
		{"required flag", errors.New(`required flag(s) "url" not set`), argvio.ErrorCategoryUser, ""},
		{"reason keeps inferred category", Reason(context.DeadlineExceeded, "probe-timeout"), argvio.ErrorCategoryTimeout, "probe-timeout"},
		{"reason on unknown", Reason(errors.New("boom"), "no-token"), argvio.ErrorCategoryUnknown, "no-token"},
		{"explicit category wins", Classified(context.DeadlineExceeded, argvio.ErrorCategoryAuth, "bad-key"), argvio.ErrorCategoryAuth, "bad-key"},
		{"wrapped after classified", fmt.Errorf("outer: %w", Classified(errors.New("x"), argvio.ErrorCategoryValidation, "bad-input")), argvio.ErrorCategoryValidation, "bad-input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category, reason := classify(tt.err)
			if category != tt.wantCategory || reason != tt.wantReason {
				t.Errorf("classify() = (%q, %q), want (%q, %q)", category, reason, tt.wantCategory, tt.wantReason)
			}
		})
	}
}

func TestClassified_NilStaysNil(t *testing.T) {
	if Classified(nil, argvio.ErrorCategoryUser, "x") != nil {
		t.Error("Classified(nil) should be nil")
	}
	if Reason(nil, "x") != nil {
		t.Error("Reason(nil) should be nil")
	}
}

func TestClassified_KeepsOriginalError(t *testing.T) {
	err := Reason(fmt.Errorf("reading: %w", os.ErrNotExist), "no-spec")
	if !errors.Is(err, os.ErrNotExist) {
		t.Error("expected errors.Is to see through Reason")
	}
	if err.Error() != "reading: file does not exist" {
		t.Errorf("message changed: %q", err.Error())
	}
}

func TestErrorFrom(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		v    []any
		want string
	}{
		{"empty", nil, ""},
		{"error", []any{boom}, "boom"},
		{"error after text", []any{"failed:", boom}, "boom"},
		{"text only", []any{"url is required"}, "url is required"},
		{"several values", []any{"a", 1, "b"}, "a1b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errorFrom(tt.v)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("errorFrom() = %v, want nil", err)
			case tt.want != "" && (err == nil || err.Error() != tt.want):
				t.Errorf("errorFrom() = %v, want %q", err, tt.want)
			}
		})
	}
	if got := errorFrom([]any{boom}); got != boom {
		t.Error("expected the original error back, not a copy")
	}
}
