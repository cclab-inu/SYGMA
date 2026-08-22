package controller

import (
	"fmt"
	"strconv"

	securityv1 "example.org/sygma/operator/api/v1"
	"example.org/sygma/operator/pkg/storage"
)

const evaluationAllowAllStateID = "0"

func resolveConfigPolicy(config *securityv1.SYGMAConfig) (*storage.MainPolicySpec, bool, error) {
	if config == nil {
		return nil, false, fmt.Errorf("SYGMAConfig is nil")
	}

	policy := &config.Spec.Policy
	if policy.StateMachine != nil {
		if policy.AllowAll != nil {
			return nil, false, fmt.Errorf(
				"spec.policy must specify exactly one of stateMachine or allowAll=true",
			)
		}
		if err := validateStateMachinePolicy(policy.StateMachine); err != nil {
			return nil, false, fmt.Errorf("invalid state-machine policy: %w", err)
		}
		return newMainPolicy(copyStateMachinePolicy(policy.StateMachine)), false, nil
	}

	if policy.AllowAll == nil || !*policy.AllowAll {
		return nil, false, fmt.Errorf(
			"spec.policy must specify exactly one of stateMachine or allowAll=true",
		)
	}

	stateMachine := newAllowAllStateMachinePolicy()
	return newMainPolicy(stateMachine), true, nil
}

func newMainPolicy(stateMachine *securityv1.StateMachinePolicySpec) *storage.MainPolicySpec {
	return &storage.MainPolicySpec{
		Type:         storage.PolicyTypeStateMachine,
		StateMachine: stateMachine,
	}
}

func copyStateMachinePolicy(policy *securityv1.StateMachinePolicySpec) *securityv1.StateMachinePolicySpec {
	if policy == nil {
		return nil
	}

	result := &securityv1.StateMachinePolicySpec{
		InitialState: policy.InitialState,
		States:       make(map[string]securityv1.StateMachineStateSpec, len(policy.States)),
	}
	for stateID, state := range policy.States {
		result.States[stateID] = securityv1.StateMachineStateSpec{
			AllowedSyscalls: append([]int(nil), state.AllowedSyscalls...),
		}
	}
	if policy.Transitions != nil {
		result.Transitions = make(map[string]map[string]uint32, len(policy.Transitions))
		for stateID, transitions := range policy.Transitions {
			copied := make(map[string]uint32, len(transitions))
			for syscall, nextState := range transitions {
				copied[syscall] = nextState
			}
			result.Transitions[stateID] = copied
		}
	}
	return result
}

func validPolicySyscall(syscall int) bool {
	return (syscall >= 0 && syscall <= 334) || (syscall >= 424 && syscall <= 448)
}

func parseCanonicalUint32(owner, raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("%s %q is not a canonical uint32", owner, raw)
	}
	return uint32(value), nil
}

func parseCanonicalSyscall(owner, raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(value) != raw || !validPolicySyscall(value) {
		return 0, fmt.Errorf("%s %q is not a supported syscall", owner, raw)
	}
	return value, nil
}

func validateAllowedSyscalls(owner string, syscalls []int) error {
	if len(syscalls) == 0 {
		return fmt.Errorf("%s has no allowed syscalls", owner)
	}
	seen := make(map[int]struct{}, len(syscalls))
	for _, syscall := range syscalls {
		if !validPolicySyscall(syscall) {
			return fmt.Errorf("%s contains unsupported syscall %d", owner, syscall)
		}
		if _, exists := seen[syscall]; exists {
			return fmt.Errorf("%s contains duplicate syscall %d", owner, syscall)
		}
		seen[syscall] = struct{}{}
	}
	return nil
}

func validateStateMachinePolicy(policy *securityv1.StateMachinePolicySpec) error {
	if policy == nil {
		return fmt.Errorf("state-machine policy is nil")
	}
	if len(policy.States) == 0 {
		return fmt.Errorf("state-machine policy has no states")
	}

	stateIDs := make(map[uint32]securityv1.StateMachineStateSpec, len(policy.States))
	for raw, state := range policy.States {
		stateID, err := parseCanonicalUint32("state ID", raw)
		if err != nil {
			return err
		}
		if _, duplicate := stateIDs[stateID]; duplicate {
			return fmt.Errorf("state-machine policy contains duplicate state ID %d", stateID)
		}
		if err := validateAllowedSyscalls(
			fmt.Sprintf("state-machine state %d", stateID), state.AllowedSyscalls,
		); err != nil {
			return err
		}
		stateIDs[stateID] = state
	}
	if _, exists := stateIDs[policy.InitialState]; !exists {
		return fmt.Errorf("initial state %d does not exist", policy.InitialState)
	}

	for fromRaw, transitions := range policy.Transitions {
		from, err := parseCanonicalUint32("transition source state", fromRaw)
		if err != nil {
			return err
		}
		state, exists := stateIDs[from]
		if !exists {
			return fmt.Errorf("transition source state %d does not exist", from)
		}

		allowed := make(map[int]struct{}, len(state.AllowedSyscalls))
		for _, syscall := range state.AllowedSyscalls {
			allowed[syscall] = struct{}{}
		}
		for syscallRaw, nextState := range transitions {
			syscall, err := parseCanonicalSyscall(
				fmt.Sprintf("transition syscall in state %d", from), syscallRaw,
			)
			if err != nil {
				return err
			}
			if _, exists := allowed[syscall]; !exists {
				return fmt.Errorf("transition syscall %d is not allowed in state %d", syscall, from)
			}
			if _, exists := stateIDs[nextState]; !exists {
				return fmt.Errorf(
					"transition %d/%d targets missing state %d", from, syscall, nextState,
				)
			}
		}
	}
	return nil
}

func supportedSyscalls() []int {
	result := make([]int, 0, 360)
	for syscall := 0; syscall <= 334; syscall++ {
		result = append(result, syscall)
	}
	for syscall := 424; syscall <= 448; syscall++ {
		result = append(result, syscall)
	}
	return result
}

func newAllowAllStateMachinePolicy() *securityv1.StateMachinePolicySpec {
	return &securityv1.StateMachinePolicySpec{
		InitialState: 0,
		States: map[string]securityv1.StateMachineStateSpec{
			evaluationAllowAllStateID: {
				AllowedSyscalls: supportedSyscalls(),
			},
		},
		Transitions: map[string]map[string]uint32{},
	}
}

func newAllowAllInitTransitions() map[string][]int {
	allowed := supportedSyscalls()
	result := make(map[string][]int, len(allowed)+1)
	result["500"] = append([]int(nil), allowed...)
	for _, from := range allowed {
		result[strconv.Itoa(from)] = append([]int(nil), allowed...)
	}
	return result
}
