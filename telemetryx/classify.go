package telemetryx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/getargvio/argvio-go"
)

// Classifier maps an error to the coarse category and the optional
// fixed-vocabulary reason Argvio records on a failed command.
type Classifier func(err error) (argvio.ErrorCategory, string)

// classifiedError carries a category and a reason alongside an error, so a
// CLI can say why a command failed at the place it knows.
type classifiedError struct {
	err      error
	category argvio.ErrorCategory
	reason   string
}

func (e *classifiedError) Error() string { return e.err.Error() }
func (e *classifiedError) Unwrap() error { return e.err }

// Classified wraps err with an explicit Argvio category and reason, for the
// default classifier (see WithClassifier) to report. It returns nil when err
// is nil, and err still matches errors.Is/As on the original.
//
// reason must be a fixed identifier chosen in code, such as "no-token" or
// "invalid-url", never the error's message or anything derived from user
// input: Argvio sends it as is, does not scrub it, and drops it unless it
// matches ^[a-z0-9][a-z0-9._-]*$ and is at most 64 bytes. An empty category
// keeps the one the default classifier infers from err.
func Classified(err error, category argvio.ErrorCategory, reason string) error {
	if err == nil {
		return nil
	}
	return &classifiedError{err: err, category: category, reason: reason}
}

// Reason is Classified without a category: the category is inferred from err,
// and reason says which of the CLI's own failure causes it was. See
// Classified for what reason may contain.
func Reason(err error, reason string) error {
	return Classified(err, "", reason)
}

// cobraUsagePrefixes are the beginnings of the messages Cobra and pflag use
// for bad flags, arguments and commands. They are the only way to recognise
// those errors, as Cobra doesn't export types for them.
var cobraUsagePrefixes = []string{
	"unknown command",
	"unknown flag",
	"unknown shorthand flag",
	"flag needs an argument",
	"bad flag syntax",
	"invalid argument",
	"required flag",
	"if any flags in the group",
	"accepts ",
	"requires at least",
	"requires at most",
}

// classify is the Classifier used unless Instrument is given another one. An
// error wrapped with Classified or Reason reports what it was wrapped with.
// Anything else is categorised from its cause: deadlines and cancellations,
// network errors, missing or unreadable files and Cobra usage errors. All
// other errors are unknown, with no reason.
func classify(err error) (argvio.ErrorCategory, string) {
	var category argvio.ErrorCategory
	var reason string
	var c *classifiedError
	if errors.As(err, &c) {
		category, reason = c.category, c.reason
	}
	if category == "" {
		category = categorize(err)
	}
	return category, reason
}

func categorize(err error) argvio.ErrorCategory {
	var netErr net.Error
	switch {
	case err == nil:
		return argvio.ErrorCategoryUnknown
	case errors.Is(err, context.DeadlineExceeded):
		return argvio.ErrorCategoryTimeout
	case errors.Is(err, context.Canceled):
		return argvio.ErrorCategoryCanceled
	case errors.As(err, &netErr):
		if netErr.Timeout() {
			return argvio.ErrorCategoryTimeout
		}
		return argvio.ErrorCategoryNetwork
	case errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrPermission):
		return argvio.ErrorCategoryUser
	}
	msg := err.Error()
	for _, p := range cobraUsagePrefixes {
		if strings.HasPrefix(msg, p) {
			return argvio.ErrorCategoryUser
		}
	}
	return argvio.ErrorCategoryUnknown
}

// errorFrom returns the error a Fatal call is reporting: the first error among
// v, else one made from v's text, else nil when v is empty.
func errorFrom(v []any) error {
	for _, x := range v {
		if err, ok := x.(error); ok {
			return err
		}
	}
	if len(v) == 0 {
		return nil
	}
	return errors.New(fmt.Sprint(v...))
}
