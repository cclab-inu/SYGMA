package controller

import (
	"encoding/json"
	"strings"
	"testing"

	securityv1 "example.org/sygma/operator/api/v1"
	"example.org/sygma/operator/pkg/storage"
)

func boolPointer(value bool) *bool {
	return &value
}

func validStateMachine() *securityv1.StateMachinePolicySpec {
	return &securityv1.StateMachinePolicySpec{
		InitialState: 0,
		States: map[string]securityv1.StateMachineStateSpec{
			"0": {AllowedSyscalls: []int{0, 334, 424, 448}},
			"1": {AllowedSyscalls: []int{1}},
		},
		Transitions: map[string]map[string]uint32{
			"0": {"424": 1},
		},
	}
}

func TestResolveStateMachinePolicy(t *testing.T) {
	configured := validStateMachine()
	config := &securityv1.SYGMAConfig{
		Spec: securityv1.SYGMAConfigSpec{
			Policy: securityv1.ConfigPolicySpec{StateMachine: configured},
		},
	}

	policy, allowAll, err := resolveConfigPolicy(config)
	if err != nil {
		t.Fatalf("resolveConfigPolicy() error = %v", err)
	}
	if allowAll {
		t.Fatal("resolveConfigPolicy() marked a configured state machine as allowAll")
	}
	if policy.Type != storage.PolicyTypeStateMachine || policy.StateMachine == nil {
		t.Fatalf("unexpected main policy: %#v", policy)
	}

	configured.States["0"] = securityv1.StateMachineStateSpec{AllowedSyscalls: []int{9}}
	configured.Transitions["0"]["424"] = 0
	if got := policy.StateMachine.States["0"].AllowedSyscalls[2]; got != 424 {
		t.Fatalf("stored policy changed with input object: got syscall %d", got)
	}
	if got := policy.StateMachine.Transitions["0"]["424"]; got != 1 {
		t.Fatalf("stored transition changed with input object: got state %d", got)
	}
}

func TestResolvePolicyRequiresExactlyOneMode(t *testing.T) {
	tests := []struct {
		name   string
		policy securityv1.ConfigPolicySpec
	}{
		{name: "empty"},
		{name: "allowAll false", policy: securityv1.ConfigPolicySpec{AllowAll: boolPointer(false)}},
		{
			name: "both modes",
			policy: securityv1.ConfigPolicySpec{
				StateMachine: validStateMachine(),
				AllowAll:     boolPointer(true),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &securityv1.SYGMAConfig{
				Spec: securityv1.SYGMAConfigSpec{Policy: test.policy},
			}
			_, _, err := resolveConfigPolicy(config)
			if err == nil || !strings.Contains(err.Error(), "exactly one") {
				t.Fatalf("resolveConfigPolicy() error = %v, want exactly-one error", err)
			}
		})
	}
}

func TestValidateStateMachinePolicyRejectsInvalidModels(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*securityv1.StateMachinePolicySpec)
		wantError string
	}{
		{
			name: "missing initial state",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.InitialState = 9
			},
			wantError: "initial state 9 does not exist",
		},
		{
			name: "unsupported syscall gap",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.States["0"] = securityv1.StateMachineStateSpec{AllowedSyscalls: []int{335}}
			},
			wantError: "unsupported syscall 335",
		},
		{
			name: "duplicate syscall",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.States["0"] = securityv1.StateMachineStateSpec{AllowedSyscalls: []int{1, 1}}
			},
			wantError: "duplicate syscall 1",
		},
		{
			name: "transition outside allow list",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.Transitions["0"] = map[string]uint32{"1": 1}
			},
			wantError: "not allowed in state 0",
		},
		{
			name: "missing transition source",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.Transitions["9"] = map[string]uint32{"1": 1}
			},
			wantError: "source state 9 does not exist",
		},
		{
			name: "missing transition destination",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.Transitions["0"] = map[string]uint32{"424": 9}
			},
			wantError: "targets missing state 9",
		},
		{
			name: "non-canonical state ID",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.States["01"] = policy.States["1"]
				delete(policy.States, "1")
			},
			wantError: "not a canonical uint32",
		},
		{
			name: "non-canonical transition syscall",
			mutate: func(policy *securityv1.StateMachinePolicySpec) {
				policy.Transitions["0"] = map[string]uint32{"0424": 1}
			},
			wantError: "not a supported syscall",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validStateMachine()
			test.mutate(policy)
			err := validateStateMachinePolicy(policy)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateStateMachinePolicy() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestAllowAllPolicySynthesis(t *testing.T) {
	config := &securityv1.SYGMAConfig{
		Spec: securityv1.SYGMAConfigSpec{
			Policy: securityv1.ConfigPolicySpec{AllowAll: boolPointer(true)},
		},
	}
	mainPolicy, allowAll, err := resolveConfigPolicy(config)
	if err != nil {
		t.Fatalf("resolveConfigPolicy() error = %v", err)
	}
	if !allowAll || mainPolicy.Type != storage.PolicyTypeStateMachine {
		t.Fatalf("unexpected resolved allowAll policy: allowAll=%v policy=%#v", allowAll, mainPolicy)
	}
	if got := len(mainPolicy.StateMachine.States); got != 1 {
		t.Fatalf("state count = %d, want 1", got)
	}
	state := mainPolicy.StateMachine.States[evaluationAllowAllStateID]
	if got := len(state.AllowedSyscalls); got != 360 {
		t.Fatalf("main allow-list length = %d, want 360", got)
	}
	if len(mainPolicy.StateMachine.Transitions) != 0 {
		t.Fatalf("allowAll transitions = %#v, want none", mainPolicy.StateMachine.Transitions)
	}

	initPolicy := newAllowAllInitTransitions()
	if got := len(initPolicy); got != 361 {
		t.Fatalf("init source count = %d, want 361", got)
	}
	for _, source := range []string{"500", "0", "334", "424", "448"} {
		if got := len(initPolicy[source]); got != 360 {
			t.Fatalf("source %s destination count = %d, want 360", source, got)
		}
	}
	for _, syscall := range []int{0, 334, 424, 448} {
		if !containsSyscall(initPolicy["500"], syscall) {
			t.Fatalf("START row is missing supported syscall %d", syscall)
		}
	}
	for _, syscall := range []int{335, 500} {
		if containsSyscall(initPolicy["500"], syscall) {
			t.Fatalf("START row contains unsupported destination %d", syscall)
		}
	}
	initPolicy["500"][0] = -123
	if initPolicy["0"][0] != 0 {
		t.Fatal("allowAll init rows unexpectedly share their destination slices")
	}
}

func TestMainPolicyWireShape(t *testing.T) {
	policy := newMainPolicy(validStateMachine())
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(document) != 2 || document["type"] == nil || document["stateMachine"] == nil {
		t.Fatalf("wire document = %s, want only type and stateMachine", data)
	}
	if !strings.Contains(string(document["type"]), storage.PolicyTypeStateMachine) {
		t.Fatalf("wire type = %s", document["type"])
	}
}

func containsSyscall(syscalls []int, want int) bool {
	for _, syscall := range syscalls {
		if syscall == want {
			return true
		}
	}
	return false
}
