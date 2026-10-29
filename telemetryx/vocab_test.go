package telemetryx

import "testing"

func TestVocab(t *testing.T) {
	allowed := []string{"bearer", "basic"}
	tests := []struct {
		name, value, want string
	}{
		{"listed", "bearer", "bearer"},
		{"listed other", "basic", "basic"},
		{"case folded", "Bearer", "bearer"},
		{"unlisted", "negotiate", vocabOther},
		{"empty", "", vocabOther},
		{"user text never passes", "https://example.com/secret", vocabOther},
		{"near miss", "bearer ", vocabOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Vocab(tt.value, allowed...); got != tt.want {
				t.Errorf("Vocab(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
	if got := Vocab("anything"); got != vocabOther {
		t.Errorf("Vocab with no allowed values = %q, want %q", got, vocabOther)
	}
}
