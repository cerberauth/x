package harnessx

import (
	harness "github.com/cerberauth/harnessx"
)

// CheckDef holds the descriptive/scoring metadata for a check, typically
// loaded from a YAML sidecar file next to the check implementation.
type CheckDef struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Link        string   `yaml:"link"`
	Tags        []string `yaml:"tags"`
	DependsOn   []string `yaml:"depends_on"`
	CVSSVector  string   `yaml:"cvss_vector"`
	CVSSScore   float64  `yaml:"cvss_score"`
	CWEID       string   `yaml:"cwe_id"`
	OWASP       string   `yaml:"owasp"`
}

func (d CheckDef) DependsOnIDs() []harness.CheckID {
	ids := make([]harness.CheckID, len(d.DependsOn))
	for i, s := range d.DependsOn {
		ids[i] = harness.CheckID(s)
	}
	return ids
}
