package telemetryx

import "strings"

// vocabOther is what Vocab returns for a value outside the allowed set.
const vocabOther = "other"

// Vocab returns value, lower-cased, when it is one of allowed, and "other"
// otherwise. Use it to build a counter label or a feature name from something
// the CLI read from its input (an HTTP method, a scheme name, a file format)
// without ever sending text a user or a scanned API chose: only the values you
// list in code can come out.
//
//	telemetryx.Counter(ctx, "openapi.scheme", 1, telemetryx.Vocab(s.Scheme, "bearer", "basic"))
//
// allowed must itself be valid Argvio identifiers (^[a-z0-9][a-z0-9._-]*$).
func Vocab(value string, allowed ...string) string {
	v := strings.ToLower(value)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return vocabOther
}
