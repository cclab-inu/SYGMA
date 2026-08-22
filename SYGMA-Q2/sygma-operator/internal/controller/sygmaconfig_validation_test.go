package controller

import (
	"strings"
	"testing"

	securityv1 "example.org/sygma/operator/api/v1"
)

func TestHasWildcardPolicyDoesNotTreatMissingThirdPartyAsWildcard(t *testing.T) {
	reconciler := &SYGMAConfigReconciler{}
	config := &securityv1.SYGMAConfig{}

	if reconciler.hasWildcardPolicy(config) {
		t.Fatal("hasWildcardPolicy() returned true with no third-party policy")
	}
}

func TestValidateInitPhasePolicy(t *testing.T) {
	tests := []struct {
		name      string
		policy    map[string][]int
		wantError string
	}{
		{
			name:      "nil policy",
			policy:    nil,
			wantError: "no syscall transitions",
		},
		{
			name:      "empty policy",
			policy:    map[string][]int{},
			wantError: "no syscall transitions",
		},
		{
			name:      "missing start transition",
			policy:    map[string][]int{"0": {1}},
			wantError: "missing the START",
		},
		{
			name:      "empty start transition",
			policy:    map[string][]int{"500": {}},
			wantError: "has no destination syscalls",
		},
		{
			name:   "valid start transition",
			policy: map[string][]int{"500": {158}, "158": {0}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInitPhasePolicy(tt.policy)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateInitPhasePolicy() returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("validateInitPhasePolicy() returned nil, want error containing %q", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateInitPhasePolicy() error = %q, want substring %q", err, tt.wantError)
			}
		})
	}
}
