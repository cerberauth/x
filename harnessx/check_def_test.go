package harnessx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/harnessx"
	local "github.com/cerberauth/x/harnessx"
)

func TestCheckDef_DependsOnIDs(t *testing.T) {
	tests := []struct {
		name      string
		dependsOn []string
		expected  []harnessx.CheckID
	}{
		{
			name:      "empty depends on",
			dependsOn: []string{},
			expected:  []harnessx.CheckID{},
		},
		{
			name:      "nil depends on",
			dependsOn: nil,
			expected:  []harnessx.CheckID{},
		},
		{
			name:      "multiple items",
			dependsOn: []string{"check-1", "check-2"},
			expected:  []harnessx.CheckID{"check-1", "check-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := local.CheckDef{
				DependsOn: tt.dependsOn,
			}
			assert.Equal(t, tt.expected, d.DependsOnIDs())
		})
	}
}
