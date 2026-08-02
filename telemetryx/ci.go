package telemetryx

import (
	"os"

	"go.opentelemetry.io/otel/attribute"
)

// CI provider names reported in the provider field / cicd.provider.name attribute.
const (
	ciProviderGitHubActions = "github_actions"
	ciProviderGitLabCI      = "gitlab_ci"
	ciProviderCircleCI      = "circleci"
	ciProviderBuildkite     = "buildkite"
	ciProviderJenkins       = "jenkins"
	ciProviderTravis        = "travis"
	ciProviderUnknown       = "unknown"
)

// ciInfo holds minimal information about the CI environment the process is
// running in: which provider it is, and whether the run is for a pull/merge
// request.
type ciInfo struct {
	provider string
	isPR     bool
}

// detectCI inspects well-known CI provider environment variables and
// reports the provider name and whether the run is for a pull/merge
// request. ok is false when no CI environment could be detected.
func detectCI() (info ciInfo, ok bool) {
	switch {
	case os.Getenv("GITHUB_ACTIONS") != "":
		return ciInfo{provider: ciProviderGitHubActions, isPR: os.Getenv("GITHUB_EVENT_NAME") == "pull_request"}, true
	case os.Getenv("GITLAB_CI") != "":
		return ciInfo{provider: ciProviderGitLabCI, isPR: os.Getenv("CI_MERGE_REQUEST_IID") != ""}, true
	case os.Getenv("CIRCLECI") != "":
		return ciInfo{provider: ciProviderCircleCI, isPR: os.Getenv("CIRCLE_PULL_REQUEST") != ""}, true
	case os.Getenv("BUILDKITE") != "":
		return ciInfo{provider: ciProviderBuildkite, isPR: isTruthyPR(os.Getenv("BUILDKITE_PULL_REQUEST"))}, true
	case os.Getenv("JENKINS_URL") != "":
		return ciInfo{provider: ciProviderJenkins, isPR: os.Getenv("CHANGE_ID") != ""}, true
	case os.Getenv("TRAVIS") != "":
		return ciInfo{provider: ciProviderTravis, isPR: isTruthyPR(os.Getenv("TRAVIS_PULL_REQUEST"))}, true
	case os.Getenv("CI") != "":
		return ciInfo{provider: ciProviderUnknown}, true
	default:
		return ciInfo{}, false
	}
}

// isTruthyPR reports whether a provider's pull-request env var denotes an
// actual PR. Buildkite and Travis use "false" (or unset) to mean "not a PR".
func isTruthyPR(v string) bool {
	return v != "" && v != "false"
}

// attributes maps the detected CI info to OTel resource attributes.
func (info ciInfo) attributes() []attribute.KeyValue {
	if info.provider == "" {
		return nil
	}
	return []attribute.KeyValue{
		attribute.String("cicd.provider.name", info.provider),
		attribute.Bool("cicd.pipeline.is_pull_request", info.isPR),
	}
}
