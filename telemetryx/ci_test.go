package telemetryx

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// clearCIEnv unsets every env var any detector checks, so tests start from
// a clean slate regardless of the environment they run in (e.g. real CI).
func clearCIEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"CI",
		"GITHUB_ACTIONS", "GITHUB_EVENT_NAME",
		"GITLAB_CI", "CI_MERGE_REQUEST_IID",
		"CIRCLECI", "CIRCLE_PULL_REQUEST",
		"BUILDKITE", "BUILDKITE_PULL_REQUEST",
		"JENKINS_URL", "CHANGE_ID",
		"TRAVIS", "TRAVIS_PULL_REQUEST",
	}
	for _, v := range vars {
		t.Setenv(v, "")
	}
}

func TestDetectCI_NoEnv_ReturnsNotOK(t *testing.T) {
	clearCIEnv(t)

	_, ok := detectCI()
	if ok {
		t.Fatal("expected ok=false when no CI env vars are set")
	}
}

func TestDetectCI_GenericFallback(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("CI", "true")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true when CI=true")
	}
	if info.provider != ciProviderUnknown {
		t.Errorf("provider: got %q, want %q", info.provider, ciProviderUnknown)
	}
}

func TestDetectCI_GitHubActions(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderGitHubActions {
		t.Errorf("provider: got %q", info.provider)
	}
	if !info.isPR {
		t.Error("expected isPR=true for pull_request event")
	}
}

func TestDetectCI_GitHubActions_NotPR(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "push")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.isPR {
		t.Error("expected isPR=false for push event")
	}
}

func TestDetectCI_GitLabCI(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "9")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderGitLabCI {
		t.Errorf("provider: got %q", info.provider)
	}
	if !info.isPR {
		t.Error("expected isPR=true when CI_MERGE_REQUEST_IID is set")
	}
}

func TestDetectCI_CircleCI(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("CIRCLECI", "true")
	t.Setenv("CIRCLE_PULL_REQUEST", "https://github.com/cerberauth/x/pull/3")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderCircleCI {
		t.Errorf("provider: got %q", info.provider)
	}
	if !info.isPR {
		t.Error("expected isPR=true when CIRCLE_PULL_REQUEST is set")
	}
}

func TestDetectCI_Buildkite(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("BUILDKITE", "true")
	t.Setenv("BUILDKITE_PULL_REQUEST", "false")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderBuildkite {
		t.Errorf("provider: got %q", info.provider)
	}
	if info.isPR {
		t.Error("expected isPR=false when BUILDKITE_PULL_REQUEST=false")
	}
}

func TestDetectCI_Jenkins(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("JENKINS_URL", "https://jenkins.example.com")
	t.Setenv("CHANGE_ID", "7")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderJenkins {
		t.Errorf("provider: got %q", info.provider)
	}
	if !info.isPR {
		t.Error("expected isPR=true when CHANGE_ID is set")
	}
}

func TestDetectCI_Travis(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("TRAVIS", "true")
	t.Setenv("TRAVIS_PULL_REQUEST", "false")

	info, ok := detectCI()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.provider != ciProviderTravis {
		t.Errorf("provider: got %q", info.provider)
	}
	if info.isPR {
		t.Error("expected isPR=false when TRAVIS_PULL_REQUEST=false")
	}
}

func TestCIInfo_Attributes(t *testing.T) {
	info := ciInfo{provider: ciProviderGitHubActions, isPR: true}
	attrs := info.attributes()

	if len(attrs) != 2 {
		t.Fatalf("expected 2 attributes, got %d: %v", len(attrs), attrs)
	}
	if attrs[0].Key != attribute.Key("cicd.provider.name") || attrs[0].Value.AsString() != ciProviderGitHubActions {
		t.Errorf("unexpected provider attribute: %v", attrs[0])
	}
	if attrs[1].Key != attribute.Key("cicd.pipeline.is_pull_request") || !attrs[1].Value.AsBool() {
		t.Errorf("unexpected isPR attribute: %v", attrs[1])
	}
}

func TestCIInfo_Attributes_EmptyProviderReturnsNil(t *testing.T) {
	info := ciInfo{}
	if attrs := info.attributes(); attrs != nil {
		t.Errorf("expected nil attributes for empty provider, got %v", attrs)
	}
}
