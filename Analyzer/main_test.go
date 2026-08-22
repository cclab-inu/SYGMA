package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompleteIndirectInvocationsAddsBareCallback(t *testing.T) {
	body := `{ return cmp(left, right); }`
	invocations := completeIndirectInvocations(body, nil, []string{"cmp"})
	if len(invocations) != 1 {
		t.Fatalf("got %d invocations, want 1", len(invocations))
	}
	if invocations[0].expression != "cmp" {
		t.Fatalf("expression = %q, want cmp", invocations[0].expression)
	}
	if len(invocations[0].arguments) != 2 ||
		invocations[0].arguments[0] != "left" ||
		invocations[0].arguments[1] != "right" {
		t.Fatalf("arguments = %#v, want [left right]", invocations[0].arguments)
	}
}

func TestCallbackBindingUsesTypedFunctionReference(t *testing.T) {
	target := &FunctionInfo{
		ID:          "target-id",
		Name:        "compare_items",
		DisplayName: "compare_items",
	}
	caller := &FunctionInfo{
		ID:         "caller-id",
		Name:       "caller",
		Parameters: []string{"items"},
		TypedCallees: map[string][]string{
			"compare_items": {target.ID},
		},
	}
	wrapper := &FunctionInfo{
		ID:          "wrapper-id",
		Name:        "wrapper",
		DisplayName: "wrapper",
		Parameters:  []string{"items", "cmp"},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID:  target,
			caller.ID:  caller,
			wrapper.ID: wrapper,
		},
	}

	constants := analyzer.bindCallAnalysisContext(
		caller,
		nil,
		wrapper,
		[]string{"items", "compare_items"},
	)
	if got := constants[contextCallbackPrefix+"cmp"]; got != target.ID {
		t.Fatalf("callback binding = %q, want %q", got, target.ID)
	}

	resolved := analyzer.resolveIndirectInvocationWithContext(
		wrapper,
		indirectCallInvocation{
			expression: "cmp",
			arguments:  []string{"left", "right"},
		},
		nil,
		constants,
	)
	if len(resolved) != 1 || resolved[0].functionID != target.ID {
		t.Fatalf("resolved targets = %#v, want only %q", resolved, target.ID)
	}
	if resolved[0].evidence.Kind != "callback-argument" ||
		!resolved[0].evidence.TargetSetClosed {
		t.Fatalf("evidence = %#v, want closed callback-argument", resolved[0].evidence)
	}
}

func TestFortifyRenamedCalleeUsesUniqueGlobalDefinition(t *testing.T) {
	target := &FunctionInfo{
		ID:          "global-kmemdup",
		Name:        "kmemdup",
		DisplayName: "kmemdup",
	}
	caller := &FunctionInfo{
		ID:   "fortify-kmemdup",
		Name: "kmemdup",
		File: "/kernel/include/linux/fortify-string.h",
		TypedCallees: map[string][]string{
			"__real_kmemdup": {"declaration-without-body"},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID: target,
			caller.ID: caller,
		},
		globalIndex: map[string][]string{
			"kmemdup": {target.ID},
		},
	}
	ids, status := analyzer.resolveCallee(caller, "__real_kmemdup")
	if status != "resolved" || len(ids) != 1 || ids[0] != target.ID {
		t.Fatalf("fortify alias resolution = %#v, %q", ids, status)
	}
}

func TestFortifyRenamedCalleeExcludesWrapperDefinition(t *testing.T) {
	target := &FunctionInfo{
		ID:          "global-kmemdup",
		Name:        "kmemdup",
		DisplayName: "kmemdup",
		File:        "/kernel/mm/util.c",
	}
	wrapper := &FunctionInfo{
		ID:          "fortify-kmemdup",
		Name:        "kmemdup",
		DisplayName: "kmemdup@fortify",
		File:        "/kernel/include/linux/fortify-string.h",
		TypedCallees: map[string][]string{
			"__real_kmemdup": {"declaration-without-body"},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID:  target,
			wrapper.ID: wrapper,
		},
		globalIndex: map[string][]string{
			"kmemdup": {wrapper.ID, target.ID},
		},
	}
	ids, status := analyzer.resolveCallee(
		wrapper,
		"__real_kmemdup",
	)
	if status != "resolved" || len(ids) != 1 ||
		ids[0] != target.ID {
		t.Fatalf(
			"fortify implementation resolution = %#v, %q",
			ids,
			status,
		)
	}
}

func TestFortifyRenamedCalleeRejectsMultipleImplementations(t *testing.T) {
	wrapper := &FunctionInfo{
		ID:   "fortify-strnlen",
		Name: "strnlen",
		File: "/kernel/include/linux/fortify-string.h",
		TypedCallees: map[string][]string{
			"__real_strnlen": {"declaration-without-body"},
		},
	}
	first := &FunctionInfo{
		ID:   "strnlen-one",
		Name: "strnlen",
		File: "/kernel/lib/string.c",
	}
	second := &FunctionInfo{
		ID:   "strnlen-two",
		Name: "strnlen",
		File: "/kernel/arch/example/string.c",
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			wrapper.ID: wrapper,
			first.ID:   first,
			second.ID:  second,
		},
		globalIndex: map[string][]string{
			"strnlen": {wrapper.ID, first.ID, second.ID},
		},
	}
	if ids, status := analyzer.resolveCallee(
		wrapper,
		"__real_strnlen",
	); status == "resolved" || len(ids) != 0 {
		t.Fatalf(
			"ambiguous fortify implementations were guessed: %#v, %q",
			ids,
			status,
		)
	}
}

func TestFortifyRenamedCalleeDoesNotGuessOutsideHeader(t *testing.T) {
	target := &FunctionInfo{
		ID:          "global-strnlen",
		Name:        "strnlen",
		DisplayName: "strnlen",
	}
	caller := &FunctionInfo{
		ID:   "ordinary-caller",
		Name: "ordinary_caller",
		File: "/kernel/fs/example.c",
		TypedCallees: map[string][]string{
			"__real_strnlen": {"declaration-without-body"},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID: target,
			caller.ID: caller,
		},
		globalIndex: map[string][]string{
			"strnlen": {target.ID},
		},
	}
	if ids, status := analyzer.resolveCallee(
		caller,
		"__real_strnlen",
	); status == "resolved" || len(ids) != 0 {
		t.Fatalf("out-of-context alias was guessed: %#v, %q", ids, status)
	}
}

func TestCallbackBindingPrefersExactClangArgumentTarget(t *testing.T) {
	target := &FunctionInfo{
		ID:          "selected-target",
		Name:        "selected_target",
		DisplayName: "selected_target",
	}
	caller := &FunctionInfo{
		ID:          "caller-id",
		Name:        "caller",
		DisplayName: "caller",
	}
	wrapper := &FunctionInfo{
		ID:          "wrapper-id",
		Name:        "wrapper",
		DisplayName: "wrapper",
		Parameters:  []string{"value", "callback"},
	}
	site := &ClangCallSite{
		Direct:    true,
		Name:      "wrapper",
		Arguments: []string{"value", "(callback_type)SELECT_CALLBACK()"},
		CallbackArguments: []ClangCallbackArgument{{
			Index:    1,
			Complete: true,
			Targets: []ClangCallTarget{{
				Name:       "selected_target",
				FunctionID: target.ID,
			}},
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID:  target,
			caller.ID:  caller,
			wrapper.ID: wrapper,
		},
	}

	constants := analyzer.bindCallAnalysisContext(
		caller,
		nil,
		wrapper,
		site.Arguments,
		site,
	)
	if got := constants[contextCallbackPrefix+"callback"]; got != target.ID {
		t.Fatalf("callback binding = %q, want exact AST target %q", got, target.ID)
	}
}

func TestResolveCalleeDoesNotReplaceMissingTypedTargetByName(t *testing.T) {
	wrong := &FunctionInfo{
		ID:          "same_name",
		Name:        "same_name",
		DisplayName: "same_name",
	}
	caller := &FunctionInfo{
		ID:   "caller",
		Name: "caller",
		TypedCallees: map[string][]string{
			"same_name": {"missing-static-definition"},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			wrong.ID:  wrong,
			caller.ID: caller,
		},
		globalIndex: map[string][]string{
			"same_name": {wrong.ID},
		},
	}
	ids, status := analyzer.resolveCallee(caller, "same_name")
	if status != "typed_target_incomplete" || len(ids) != 0 {
		t.Fatalf("resolved = %#v status=%q, want unresolved typed target", ids, status)
	}
}

func TestClangInlineIdentitySharesIdenticalSemanticVariantAcrossTUs(
	t *testing.T,
) {
	const (
		header = "/kernel/include/linux/example.h"
		name   = "inline_helper"
		hash   = "semantic-hash"
	)
	definitionID := makeClangFunctionID(
		header,
		name,
		true,
		true,
		hash,
		"/kernel/fs/first.c",
	)
	targetID := makeClangFunctionID(
		header,
		name,
		true,
		true,
		hash,
		"/kernel/fs/second.c",
	)
	if definitionID != targetID {
		t.Fatalf(
			"identical inline variant IDs differ: %q != %q",
			definitionID,
			targetID,
		)
	}
	target := &FunctionInfo{
		ID:          definitionID,
		Name:        name,
		DisplayName: name,
	}
	caller := &FunctionInfo{
		ID:   "caller",
		Name: "caller",
		TypedCallees: map[string][]string{
			name: {targetID},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			target.ID: target,
			caller.ID: caller,
		},
	}
	ids, status := analyzer.resolveCallee(caller, name)
	if status != "resolved" || len(ids) != 1 || ids[0] != definitionID {
		t.Fatalf(
			"resolved=%v status=%q, want shared inline definition",
			ids,
			status,
		)
	}
}

func TestCachedClangInlineIdentityMigrationRepairsTypedTargets(
	t *testing.T,
) {
	baseID := makeClangFunctionID(
		"/kernel/include/linux/example.h",
		"inline_helper",
		true,
		true,
		"semantic-hash",
		"",
	)
	firstID := baseID + "@@tu=/kernel/fs/first.c"
	secondID := baseID + "@@tu=/kernel/fs/second.c"
	target := func(id, translationUnit, displaySuffix string) *FunctionInfo {
		return &FunctionInfo{
			ID:                   id,
			Name:                 "inline_helper",
			DisplayName:          "inline_helper@header#semantic-hash@tu-" + displaySuffix,
			Body:                 "return 0;",
			File:                 "/kernel/include/linux/example.h",
			TranslationUnits:     []string{translationUnit},
			Static:               true,
			Inline:               true,
			SemanticHash:         "semantic-hash",
			Frontend:             "clang-ast-cfg",
			CFGComplete:          true,
			CFGHasSuccessExit:    true,
			TypedCallees:         map[string][]string{},
			TypedIndirectCalls:   map[string]ClangIndirectTarget{},
			FrontendVariantCount: 1,
		}
	}
	caller := &FunctionInfo{
		ID:          "caller",
		Name:        "caller",
		DisplayName: "caller",
		RawCallees:  []string{"inline_helper"},
		TypedCallees: map[string][]string{
			"inline_helper": {secondID},
		},
		CallSites: []ClangCallSite{{
			ID:   "site",
			Name: "wrapper",
			CallbackArguments: []ClangCallbackArgument{{
				Index:    0,
				Complete: true,
				Targets: []ClangCallTarget{{
					Name:       "inline_helper",
					FunctionID: secondID,
				}},
			}},
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			firstID:   target(firstID, "/kernel/fs/first.c", "111111111111"),
			secondID:  target(secondID, "/kernel/fs/second.c", "222222222222"),
			caller.ID: caller,
		},
	}
	if !analyzer.normalizeCachedClangFunctionIdentities() {
		t.Fatal("expected stale TU identities to be migrated")
	}
	if len(analyzer.functions) != 2 {
		t.Fatalf("function count = %d, want merged target plus caller", len(analyzer.functions))
	}
	merged := analyzer.functions[baseID]
	if merged == nil || len(merged.TranslationUnits) != 2 {
		t.Fatalf("merged target = %#v", merged)
	}
	if got := caller.TypedCallees["inline_helper"]; len(got) != 1 ||
		got[0] != baseID {
		t.Fatalf("typed targets = %#v, want %q", got, baseID)
	}
	callbackID := caller.CallSites[0].
		CallbackArguments[0].
		Targets[0].
		FunctionID
	if callbackID != baseID {
		t.Fatalf("callback target = %q, want %q", callbackID, baseID)
	}
	analyzer.rebuildFunctionIndexes()
	analyzer.resolveCalls()
	if len(caller.UnresolvedCalls) != 0 ||
		!containsString(caller.DirectCallees, baseID) {
		t.Fatalf(
			"resolved=%#v unresolved=%#v",
			caller.DirectCallees,
			caller.UnresolvedCalls,
		)
	}
}

func TestSignalPendingStateSIGKILLRelevance(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "uninterruptible",
			body: `if (signal_pending_state(0x0002, current)) return -EINTR;`,
			want: signalSIGKILLIrrelevant,
		},
		{
			name: "interruptible",
			body: `if (signal_pending_state(0x0001, current)) return -EINTR;`,
			want: signalSIGKILLRelevant,
		},
		{
			name: "killable bitwise state",
			body: `if (signal_pending_state((0x0100 | 0x0002), current)) return -EINTR;`,
			want: signalSIGKILLRelevant,
		},
		{
			name: "unknown state remains unresolved",
			body: `if (signal_pending_state(state, current)) return -EINTR;`,
			want: signalSIGKILLUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := signalCheckSIGKILLRelevance(test.body, "signal_pending_state"); got != test.want {
				t.Fatalf("signal relevance = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClangSignalPendingStateConstantRelevance(t *testing.T) {
	analyzer := &Analyzer{}
	function := &FunctionInfo{
		Frontend:                "clang-ast-cfg",
		CFGReachableCallSites:   []string{"relevant", "irrelevant"},
		CFGMustSuccessCallSites: []string{"irrelevant"},
		CallSites: []ClangCallSite{
			{
				ID:                "relevant",
				Direct:            true,
				Reachable:         true,
				Name:              "signal_pending_state",
				ArgumentConstants: []string{"257"},
			},
			{
				ID:                "irrelevant",
				Direct:            true,
				Reachable:         true,
				Name:              "signal_pending_state",
				ArgumentConstants: []string{"2"},
			},
		},
	}
	if got := analyzer.signalCheckSIGKILLRelevance(
		function,
		"",
		"signal_pending_state",
		false,
	); got != signalSIGKILLRelevant {
		t.Fatalf("reachable relevance = %q, want %q", got, signalSIGKILLRelevant)
	}
	if got := analyzer.signalCheckSIGKILLRelevance(
		function,
		"",
		"signal_pending_state",
		true,
	); got != signalSIGKILLIrrelevant {
		t.Fatalf("mandatory relevance = %q, want %q", got, signalSIGKILLIrrelevant)
	}
}

func TestSignalCallsitesDoNotShareAbortEvidence(t *testing.T) {
	function := &FunctionInfo{
		ID:                      "worker",
		Name:                    "worker",
		DisplayName:             "worker",
		Frontend:                "clang-ast-cfg",
		Body:                    "if (signal_pending_state(0x101, current)) return -ERESTARTSYS; signal_pending_state(0x2, current); return 0;",
		CFGReachableCallSites:   []string{"relevant", "irrelevant"},
		CFGMustSuccessCallSites: []string{"relevant", "irrelevant"},
		CallSites: []ClangCallSite{
			{
				ID:                "relevant",
				Direct:            true,
				Reachable:         true,
				Name:              "signal_pending_state",
				Arguments:         []string{"0x101", "current"},
				ArgumentConstants: []string{"257", ""},
				Line:              1,
				Column:            5,
			},
			{
				ID:                "irrelevant",
				Direct:            true,
				Reachable:         true,
				Name:              "signal_pending_state",
				Arguments:         []string{"0x2", "current"},
				ArgumentConstants: []string{"2", ""},
				Line:              1,
				Column:            80,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{function.ID: function},
	}
	evidences := analyzer.signalCheckEvidences(
		function,
		function.Body,
		"signal_pending_state",
		false,
		nil,
	)
	if len(evidences) != 2 {
		t.Fatalf("evidences = %#v, want two callsites", evidences)
	}
	if evidences[0].relevance != signalSIGKILLRelevant ||
		evidences[1].relevance != signalSIGKILLIrrelevant {
		t.Fatalf("callsite relevance = %#v", evidences)
	}
	effect := analyzer.analyzeSignalAbortEffect(
		[]signalEffectPathNode{{functionID: function.ID}},
		"signal_pending_state",
		evidences[0].localSite,
		evidences[0].requireSpecificSite,
	)
	if classifyFinalSignalAbortEffect(effect) != "guaranteed" {
		t.Fatalf("relevant callsite effect = %#v, want guaranteed", effect)
	}
	effect = analyzer.analyzeSignalAbortEffect(
		[]signalEffectPathNode{{functionID: function.ID}},
		"signal_pending_state",
		evidences[1].localSite,
		evidences[1].requireSpecificSite,
	)
	if classifyFinalSignalAbortEffect(effect) != "not_effective" {
		t.Fatalf("irrelevant callsite effect = %#v, want not_effective", effect)
	}
}

func TestMandatoryDirectCallUsesExactCallsiteArguments(t *testing.T) {
	child := &FunctionInfo{
		ID:         "child",
		Name:       "child",
		Parameters: []string{"state"},
	}
	caller := &FunctionInfo{
		ID:                      "caller",
		Name:                    "caller",
		Frontend:                "clang-ast-cfg",
		CFGMustSuccessCallSites: []string{"mandatory"},
		CFGMustSuccessCalls:     []string{"child"},
		TypedCallees: map[string][]string{
			"child": {child.ID},
		},
		CallSites: []ClangCallSite{
			{
				ID:        "mandatory",
				Direct:    true,
				Name:      "child",
				Arguments: []string{"2"},
			},
			{
				ID:        "conditional",
				Direct:    true,
				Name:      "child",
				Arguments: []string{"257"},
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			caller.ID: caller,
			child.ID:  child,
		},
	}
	scan := clangMustSuccessScan(caller)
	calls := analyzer.resolveContextCallsInContext(caller, nil, scan)
	if len(calls) != 1 {
		t.Fatalf("resolved calls = %#v, want one mandatory callsite", calls)
	}
	if got := calls[0].constants["state"]; got != "2" {
		t.Fatalf("mandatory state = %q, want 2", got)
	}
}

func TestContextFeasibleScanDoesNotRestoreSameNameBranch(t *testing.T) {
	function := &FunctionInfo{
		Frontend:              "clang-ast-cfg",
		CFGReachableCallSites: []string{"selected", "eliminated"},
		CFGReachableCalls:     []string{"child"},
		CallSites: []ClangCallSite{
			{
				ID:        "selected",
				Direct:    true,
				Name:      "child",
				Arguments: []string{"2"},
			},
			{
				ID:        "eliminated",
				Direct:    true,
				Name:      "child",
				Arguments: []string{"257"},
			},
		},
	}
	scan := constrainScanToClang(
		function,
		prefixScanResult{
			callees: []string{"child"},
			calls: []callInvocation{{
				name:      "child",
				arguments: []string{"2"},
			}},
		},
		false,
		nil,
	)
	if len(scan.calls) != 1 ||
		scan.calls[0].callSiteID != "selected" ||
		scan.calls[0].arguments[0] != "2" {
		t.Fatalf("constrained calls = %#v, want selected callsite only", scan.calls)
	}
}

func TestLSMAlternativeBranchClassification(t *testing.T) {
	alternatives := mergeLSMAlternatives(
		nonEnforcingLSMAlternatives(),
		enforcingLSMAlternatives("security_example"),
	)
	if got := classifyLSMAlternatives(alternatives); got != "non_enforcing" {
		t.Fatalf("N + E classification = %q, want non_enforcing", got)
	}
	afterCommonHook := sequenceLSMAlternatives(
		alternatives,
		enforcingLSMAlternatives("security_common"),
	)
	if got := classifyLSMAlternatives(afterCommonHook); got != "enforcing" {
		t.Fatalf("(N + E) then E classification = %q, want enforcing", got)
	}
}

func TestCertifiedSuccessBypassWinsAfterEnforcingPath(t *testing.T) {
	bypass := provenNonEnforcingLSMAlternatives(
		functionSuccessWitness{
			proven: true,
			method: "explicit_success_return",
		},
		"bypass",
	)
	alternatives := mergeLSMAlternatives(
		enforcingLSMAlternatives("security_example"),
		bypass,
	)
	if got := classifySuccessExitLSMAlternatives(alternatives); got !=
		"non_enforcing" {
		t.Fatalf("E + certified N classification = %q, want non_enforcing", got)
	}
}

func TestEnforcementAlternativeLattice(t *testing.T) {
	tests := []struct {
		name         string
		alternatives []lsmPathAlternative
		want         string
	}{
		{
			name: "N plus U is N",
			alternatives: mergeLSMAlternatives(
				nonEnforcingLSMAlternatives(),
				unresolvedLSMAlternatives(),
			),
			want: "non_enforcing",
		},
		{
			name: "E plus U is U",
			alternatives: mergeLSMAlternatives(
				enforcingLSMAlternatives("checkpoint"),
				unresolvedLSMAlternatives(),
			),
			want: "uncertain",
		},
		{
			name: "E plus E is E",
			alternatives: mergeLSMAlternatives(
				enforcingLSMAlternatives("checkpoint_a"),
				enforcingLSMAlternatives("checkpoint_b"),
			),
			want: "enforcing",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyLSMAlternatives(test.alternatives); got != test.want {
				t.Fatalf("classification = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSuccessExitRequiresProofOnlyForBypass(t *testing.T) {
	analyzer := &Analyzer{
		functions:           make(map[string]*FunctionInfo),
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	function := &FunctionInfo{
		ID:          "merged-return",
		Name:        "merged_return",
		DisplayName: "merged_return",
		ReturnType:  "int",
	}
	mergedReturn := ClangCFGBlock{
		ID:                   4,
		ReturnExpression:     "err",
		PotentialSuccessExit: true,
	}
	mixed := mergeLSMAlternatives(
		nonEnforcingLSMAlternatives(function.DisplayName),
		enforcingLSMAlternatives("security_example"),
	)
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		mergedReturn,
		nil,
		mixed,
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got != "uncertain" {
		t.Fatalf("merged error/success return classification = %q, want uncertain", got)
	}

	enforcementOnly := analyzer.finalizeSuccessExitAlternatives(
		function,
		mergedReturn,
		nil,
		enforcingLSMAlternatives("security_example"),
	)
	if got := classifySuccessExitLSMAlternatives(enforcementOnly); got != "enforcing" {
		t.Fatalf("enforcement-induced error classification = %q, want enforcing", got)
	}

	explicitSuccess := mergedReturn
	explicitSuccess.ReturnExpression = "0"
	bypass := analyzer.finalizeSuccessExitAlternatives(
		function,
		explicitSuccess,
		nil,
		nonEnforcingLSMAlternatives(function.DisplayName),
	)
	if got := classifySuccessExitLSMAlternatives(bypass); got != "non_enforcing" {
		t.Fatalf("explicit success bypass classification = %q, want non_enforcing", got)
	}
}

func TestSuccessfulReturnWitnessFollowsDirectReturnWrapper(t *testing.T) {
	child := &FunctionInfo{
		ID:                "child",
		Name:              "child",
		DisplayName:       "child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "parent",
		Name:              "parent",
		DisplayName:       "parent",
		ReturnType:        "long",
		Body:              "{ return child(); }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		TypedCallees: map[string][]string{
			"child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:        "returned-child",
			Direct:    true,
			Reachable: true,
			HasBlock:  true,
			BlockID:   0,
			Name:      "child",
		}},
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "child()",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		make(map[string]bool),
	)
	if !witness.proven ||
		witness.method != "forwarded_proven_success_return" {
		t.Fatalf("witness = %#v, want forwarded proven success", witness)
	}
}

func TestSuccessExitRequiresCorrelatedForwardedCallWitness(t *testing.T) {
	child := &FunctionInfo{
		ID:                "child",
		Name:              "child",
		DisplayName:       "child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body:        "{ return child(); }",
		TypedCallees: map[string][]string{
			"child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:        "returned-child",
			Direct:    true,
			Reachable: true,
			HasBlock:  true,
			BlockID:   0,
			Name:      "child",
		}},
	}
	block := ClangCFGBlock{
		ID:                   0,
		ReturnExpression:     "child()",
		PotentialSuccessExit: true,
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	unrelated := analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		nil,
		nonEnforcingLSMAlternatives(parent.DisplayName),
	)
	if got := classifySuccessExitLSMAlternatives(unrelated); got !=
		"uncertain" {
		t.Fatalf("uncorrelated forwarded success = %q, want uncertain", got)
	}

	correlated := analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassPath: []string{parent.DisplayName},
			bypassSuccessfulCalls: []successfulCallConstraint{{
				functionID:             parent.ID,
				callSiteID:             "returned-child",
				callee:                 "child",
				returnType:             "int",
				requirement:            "nonnegative",
				callerRequirement:      "nonnegative",
				provenCalleeSuccess:    true,
				certifiesCallerSuccess: true,
				method:                 "direct_forwarded_success_return",
			}},
		}},
	)
	if got := classifySuccessExitLSMAlternatives(correlated); got !=
		"non_enforcing" {
		t.Fatalf("correlated forwarded success = %q, want non_enforcing", got)
	}
}

func TestSuccessfulCallConstraintRejectsContradictoryBranch(t *testing.T) {
	function := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        0,
			Name:           "child",
			ResultVariable: "error",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "error",
			PotentialSuccessExit: true,
		}},
	}
	alternatives := []lsmPathAlternative{{
		bypassSuccessfulCalls: []successfulCallConstraint{{
			functionID:          function.ID,
			callSiteID:          "child-site",
			callee:              "child",
			resultVariable:      "error",
			returnType:          "int",
			requirement:         "zero",
			provenCalleeSuccess: true,
		}},
	}}
	analyzer := &Analyzer{}
	block := ClangCFGBlock{
		ID:                  0,
		TerminatorCondition: "error",
	}
	contradictory := analyzer.constrainAlternativesForCFGEdge(
		alternatives,
		function,
		block,
		cfgSuccessEdge{blockID: 1, branch: "true"},
	)
	if len(contradictory) != 0 {
		t.Fatalf(
			"zero-return call survived nonzero branch: %#v",
			contradictory,
		)
	}
	compatible := analyzer.constrainAlternativesForCFGEdge(
		alternatives,
		function,
		block,
		cfgSuccessEdge{blockID: 1, branch: "false"},
	)
	if len(compatible) != 1 {
		t.Fatalf("zero-return call lost zero branch: %#v", compatible)
	}
}

func TestUnrelatedSuccessfulCallCannotProveReturnedVariable(t *testing.T) {
	function := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        0,
			Name:           "child",
			ResultVariable: "child_result",
			ReturnType:     "int",
		}},
	}
	block := ClangCFGBlock{
		ID:                   1,
		ReturnExpression:     "error",
		PotentialSuccessExit: true,
	}
	analyzer := &Analyzer{}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassSuccessfulCalls: []successfulCallConstraint{{
				functionID:          function.ID,
				callSiteID:          "child-site",
				callee:              "child",
				resultVariable:      "child_result",
				returnType:          "int",
				requirement:         "zero",
				provenCalleeSuccess: true,
			}},
		}},
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"uncertain" {
		t.Fatalf("unrelated call certified return error: %q", got)
	}
}

func TestChildReturnOutcomeBecomesCallerValueConstraint(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	site := ClangCallSite{
		ID:             "child-site",
		Direct:         true,
		Reachable:      true,
		HasBlock:       true,
		Name:           "child",
		ResultVariable: "error",
		ReturnType:     "int",
	}
	analyzer := &Analyzer{}
	alternatives := analyzer.annotateSuccessfulCallAlternatives(
		[]lsmPathAlternative{{
			returnOutcome: returnOutcome{
				domain: returnDomainSigned,
				mask:   outcomeZero,
			},
			bypassSuccessProven: true,
		}},
		parent,
		child,
		"child",
		&site,
		"",
	)
	if len(alternatives) != 1 ||
		len(alternatives[0].bypassSuccessfulCalls) != 1 {
		t.Fatalf("child outcome was not projected: %#v", alternatives)
	}
	constraint := alternatives[0].bypassSuccessfulCalls[0]
	if constraint.resultVariable != "error" ||
		constraint.requirement != "zero" ||
		!constraint.provenCalleeSuccess {
		t.Fatalf("projected child outcome = %#v", constraint)
	}
}

func TestBroadChildSuccessRequirementCannotInventNarrowOutcome(
	t *testing.T,
) {
	parent := &FunctionInfo{
		ID:         "parent",
		Name:       "parent",
		ReturnType: "int",
	}
	child := &FunctionInfo{
		ID:         "child",
		Name:       "child",
		ReturnType: "int",
	}
	site := &ClangCallSite{
		ID:             "child-site",
		Direct:         true,
		Name:           "child",
		ResultVariable: "error",
		ReturnType:     "int",
	}
	if constraint, constrained, feasible :=
		successfulCallConstraintForAlternative(
			parent,
			child,
			child.Name,
			site,
			returnOutcome{},
			successfulCallConstraint{},
			false,
			true,
			"nonnegative",
		); !feasible || constrained {
		t.Fatalf(
			"broad success requirement invented constraint %#v",
			constraint,
		)
	}
	constraint, constrained, feasible :=
		successfulCallConstraintForAlternative(
			parent,
			child,
			child.Name,
			site,
			returnOutcome{},
			successfulCallConstraint{},
			false,
			true,
			"zero",
		)
	if !feasible || !constrained ||
		constraint.requirement != "zero" {
		t.Fatalf(
			"atomic success requirement was not retained: %#v",
			constraint,
		)
	}
}

func TestSourceFreeChildProjectsOnlyWitnessedAtomicOutcome(
	t *testing.T,
) {
	child := &FunctionInfo{
		ID:                "source-free-child",
		Name:              "source_free_child",
		DisplayName:       "source_free_child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          2,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                   2,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
			{
				ID:                   1,
				ReturnExpression:     "-EFAULT",
				PotentialSuccessExit: true,
			},
		},
	}
	parent := &FunctionInfo{
		ID:                "parent",
		Name:              "parent",
		DisplayName:       "parent",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		TypedCallees: map[string][]string{
			child.Name: {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        4,
			Name:           child.Name,
			ResultUse:      "assigned",
			ResultVariable: "error",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       4,
				SuccessSuccessors:        []int{3, 1},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "!error",
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "error",
					Expression: "source_free_child()",
					Kind:       "assign",
					CallSiteID: "child-site",
				}},
			},
			{
				ID:                   3,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
			{
				ID:                   1,
				ReturnExpression:     "error",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	analyzer.rebuildFunctionIndexes()
	alternatives := analyzer.sourceFreeCallAlternatives(
		parent,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		nil,
		[]string{child.ID},
	)
	if len(alternatives) != 1 ||
		len(alternatives[0].bypassSuccessfulCalls) != 1 ||
		alternatives[0].bypassSuccessfulCalls[0].requirement !=
			"zero" {
		t.Fatalf(
			"witnessed child outcome was not projected exactly: %#v",
			alternatives,
		)
	}
	falseBranch := analyzer.constrainAlternativesForCFGEdge(
		alternatives,
		parent,
		parent.CFGBlocks[0],
		cfgSuccessEdge{blockID: 1, branch: "false"},
	)
	if len(falseBranch) != 0 {
		t.Fatalf(
			"zero-only child survived nonzero branch: %#v",
			falseBranch,
		)
	}
}

func TestLLVMSufficientSuccessFactDoesNotDiscardOtherChildOutcome(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		File:        "/kernel/fs/parent.c",
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        0,
			Name:           "child",
			ResultVariable: "error",
			ReturnType:     "int",
			Line:           10,
			Column:         8,
		}},
		LLVMCallFacts: []LLVMCallFact{{
			Kind:                            "call",
			Callee:                          "child",
			Function:                        "parent",
			SourceFunction:                  "parent",
			SourceFile:                      "/kernel/fs/parent.c",
			SourceLine:                      10,
			SourceColumn:                    8,
			MustReturnNonnegativeOnPositive: true,
		}},
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	analyzer := &Analyzer{}
	alternatives := analyzer.annotateSuccessfulCallAlternatives(
		[]lsmPathAlternative{{
			returnOutcome: returnOutcome{
				domain: returnDomainSigned,
				mask:   outcomeZero,
			},
			bypassSuccessProven: true,
		}},
		parent,
		child,
		"child",
		&parent.CallSites[0],
		"",
	)
	if len(alternatives) != 1 {
		t.Fatalf("zero child outcome was discarded: %#v", alternatives)
	}
	if len(alternatives[0].bypassSuccessfulCalls) != 1 {
		t.Fatalf("zero child outcome was not retained: %#v", alternatives)
	}
	constraint := alternatives[0].bypassSuccessfulCalls[0]
	if constraint.requirement != "zero" ||
		constraint.certifiesCallerSuccess ||
		!constraint.provenCalleeSuccess {
		t.Fatalf("fallback child constraint = %#v", constraint)
	}
}

func TestSourceFreeCallPreservesProvenReturnConstraint(t *testing.T) {
	child := &FunctionInfo{
		ID:                "source-free-child",
		Name:              "source_free_child",
		DisplayName:       "source_free_child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:          "source-free-parent",
		Name:        "source_free_parent",
		DisplayName: "source_free_parent",
		ReturnType:  "int",
		Body: `
			int result = source_free_child();
			return result;
		`,
		TypedCallees: map[string][]string{
			child.Name: {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        0,
			Name:           child.Name,
			ResultUse:      "assigned",
			ResultVariable: "result",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "result",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			parent.ID: parent,
			child.ID:  child,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	alternatives := analyzer.sourceFreeCallAlternatives(
		parent,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		nil,
		[]string{child.ID},
	)
	if len(alternatives) != 1 ||
		len(alternatives[0].bypassSuccessfulCalls) != 1 {
		t.Fatalf(
			"source-free return constraint was lost: %#v",
			alternatives,
		)
	}
	constraint := alternatives[0].bypassSuccessfulCalls[0]
	if !constraint.provenCalleeSuccess ||
		constraint.resultVariable != "result" {
		t.Fatalf("source-free constraint = %#v", constraint)
	}
}

func TestUnprovenChildOutcomeCannotCertifyCallerSuccess(t *testing.T) {
	function := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{{
			ID:             "child-site",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			Name:           "child",
			ResultVariable: "result",
			ReturnType:     "int",
		}},
	}
	block := ClangCFGBlock{
		ID:                   1,
		ReturnExpression:     "result",
		PotentialSuccessExit: true,
	}
	analyzer := &Analyzer{}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassSuccessfulCalls: []successfulCallConstraint{{
				functionID:     function.ID,
				callSiteID:     "child-site",
				callee:         "child",
				resultVariable: "result",
				returnType:     "int",
				requirement:    "zero",
			}},
		}},
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"uncertain" {
		t.Fatalf("unproven child outcome certified caller: %q", got)
	}
}

func TestSuccessfulCallConstraintOnlySurvivesDirectReturnCallSite(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{
			{
				ID:        "ordinary-child",
				Direct:    true,
				Reachable: true,
				HasBlock:  true,
				BlockID:   0,
				Name:      "child",
			},
			{
				ID:        "returned-child",
				Direct:    true,
				Reachable: true,
				HasBlock:  true,
				BlockID:   1,
				Name:      "child",
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                0,
				SuccessSuccessors: []int{1},
			},
			{
				ID:                   1,
				ReturnExpression:     "child()",
				PotentialSuccessExit: true,
			},
		},
	}
	alternatives := []lsmPathAlternative{{
		bypassSuccessProven: true,
		bypassSuccessMethod: "explicit_success_return",
	}}

	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	analyzer := &Analyzer{}
	ordinary := analyzer.annotateSuccessfulCallAlternatives(
		alternatives,
		parent,
		child,
		"child",
		&parent.CallSites[0],
		"",
	)
	if len(ordinary[0].bypassSuccessfulCalls) != 0 {
		t.Fatalf(
			"ordinary call retained success constraints: %#v",
			ordinary[0].bypassSuccessfulCalls,
		)
	}

	returned := analyzer.annotateSuccessfulCallAlternatives(
		alternatives,
		parent,
		child,
		"child",
		&parent.CallSites[1],
		"",
	)
	if got := successfulCallConstraintKey(
		returned[0].bypassSuccessfulCalls,
	); got == "" {
		t.Fatal("direct returned call did not retain its success constraint")
	}
}

func TestLLVMSuccessPreservationCorrelatesAssignedCallReturn(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		File:        "/kernel/fs/parent.c",
		CallSites: []ClangCallSite{{
			ID:        "assigned-child",
			Direct:    true,
			Reachable: true,
			HasBlock:  true,
			BlockID:   0,
			Name:      "child",
			Line:      10,
			Column:    8,
		}},
		LLVMCallFacts: []LLVMCallFact{{
			Kind:                            "call",
			Callee:                          "child",
			Function:                        "parent",
			SourceFunction:                  "parent",
			SourceFile:                      "/kernel/fs/parent.c",
			SourceLine:                      10,
			SourceColumn:                    8,
			MustReturnNonnegativeOnZero:     true,
			MustReturnNonnegativeOnPositive: true,
			MustPreserveNonnegativeSuccess:  true,
			Verification:                    "must_preserve_nonnegative_success",
		}},
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	analyzer := &Analyzer{}
	alternatives := analyzer.annotateSuccessfulCallAlternatives(
		[]lsmPathAlternative{{
			bypassPath:          []string{"child"},
			bypassSuccessProven: true,
			bypassSuccessMethod: "explicit_success_return",
		}},
		parent,
		child,
		"child",
		&parent.CallSites[0],
		"",
	)
	if len(alternatives[0].bypassSuccessfulCalls) != 1 {
		t.Fatalf("LLVM success constraint missing: %#v", alternatives)
	}
	block := ClangCFGBlock{
		ID:                   2,
		ReturnExpression:     "retval",
		PotentialSuccessExit: true,
	}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		nil,
		alternatives,
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"non_enforcing" {
		t.Fatalf("LLVM-correlated success = %q, want non_enforcing", got)
	}
	if finalized[0].bypassSuccessMethod !=
		"llvm_ssa_nonnegative_success_preservation" {
		t.Fatalf("proof method = %q", finalized[0].bypassSuccessMethod)
	}
}

func TestLLVMSuccessPreservationDoesNotCertifyCyclicAlternative(t *testing.T) {
	function := &FunctionInfo{
		ID:          "cyclic-parent",
		Name:        "cyclic_parent",
		DisplayName: "cyclic_parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{{
			ID:        "assigned-child",
			Direct:    true,
			Reachable: true,
			Name:      "child",
		}},
	}
	block := ClangCFGBlock{
		ID:                   3,
		ReturnExpression:     "retval",
		PotentialSuccessExit: true,
	}
	analyzer := &Analyzer{}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassPath:   []string{"cyclic_parent"},
			bypassCyclic: true,
			bypassSuccessfulCalls: []successfulCallConstraint{{
				functionID:  function.ID,
				callSiteID:  "assigned-child",
				callee:      "child",
				requirement: "nonnegative",
				method:      "llvm_ssa_nonnegative_success_preservation",
			}},
		}},
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"uncertain" {
		t.Fatalf("cyclic LLVM success = %q, want uncertain", got)
	}
}

func TestProjectedChildCycleDoesNotPoisonCallerSuccessGuard(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body: `{
			int ret = child();
			if (ret >= 0)
				do_success();
			return ret;
		}`,
	}
	block := ClangCFGBlock{
		ID:                   3,
		ReturnExpression:     "ret",
		PotentialSuccessExit: true,
	}
	projected := projectChildAlternativesForCaller(
		[]lsmPathAlternative{{
			bypassPath:   []string{"child"},
			bypassCyclic: true,
		}},
	)
	if projected[0].bypassCyclic {
		t.Fatal("child-local cycle leaked into caller alternative")
	}
	projected[0].bypassConstraints = []successPathConstraint{{
		functionID: parent.ID,
		blockID:    2,
		expression: "ret >= 0",
		required:   true,
	}}
	analyzer := &Analyzer{}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		nil,
		projected,
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"non_enforcing" {
		t.Fatalf("caller guard after child cycle = %q, want non_enforcing", got)
	}
}

func TestChildFailureOutcomeCannotBecomeCallerSuccess(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		CallSites: []ClangCallSite{{
			ID:             "assigned-child",
			Direct:         true,
			Reachable:      true,
			Name:           "child",
			ResultUse:      "assigned",
			ResultVariable: "ret",
			ReturnType:     "int",
		}},
	}
	block := ClangCFGBlock{
		ID:                   3,
		ReturnExpression:     "ret",
		PotentialSuccessExit: true,
	}
	negativeChildReturn := []lsmPathAlternative{{
		bypassPath: []string{"child", "parent"},
		bypassSuccessfulCalls: []successfulCallConstraint{{
			functionID:     parent.ID,
			callSiteID:     "assigned-child",
			callee:         "child",
			resultVariable: "ret",
			returnType:     "int",
			requirement:    "negative",
			method:         "child_return_outcome",
		}},
	}}
	analyzer := &Analyzer{}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		map[string]string{
			contextReturnRequirementKey: "nonnegative",
		},
		negativeChildReturn,
	)
	if len(finalized) != 0 {
		t.Fatalf(
			"negative child return survived nonnegative caller exit: %#v",
			finalized,
		)
	}

	unknownChildReturn := cloneLSMAlternatives(negativeChildReturn)
	unknownChildReturn[0].bypassSuccessfulCalls = nil
	finalized = analyzer.finalizeSuccessExitAlternatives(
		parent,
		block,
		map[string]string{
			contextReturnRequirementKey: "nonnegative",
		},
		unknownChildReturn,
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"uncertain" {
		t.Fatalf("unknown child return = %q, want uncertain", got)
	}
}

func TestTrackedErrorValueConstrainsCompoundReturnExpression(t *testing.T) {
	function := &FunctionInfo{
		ID:          "kernel-read",
		Name:        "kernel_read",
		DisplayName: "kernel_read",
		ReturnType:  "int",
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                   1,
				ReturnExpression:     "ret == 0 ? copied : ret",
				PotentialSuccessExit: true,
			},
			{
				ID: 2,
				ValueWrites: []ClangCFGValueWrite{{
					Target:             "ret",
					Expression:         "-EFBIG",
					ExpressionExpanded: "-27",
					Kind:               "assign",
				}},
			},
		},
	}
	alternatives := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:             "ret",
			Expression:         "-EFBIG",
			ExpressionExpanded: "-27",
			Kind:               "assign",
			TargetTypeClass:    "signed_integer",
			TargetTypeSigned:   true,
			TargetTypeBits:     32,
			SourceTypeClass:    "signed_integer",
			SourceTypeSigned:   true,
			SourceTypeBits:     32,
		}}},
		nonEnforcingLSMAlternatives("kernel_read"),
	)
	if got := alternatives[0].bypassValues["ret"].expression; got != "-27" {
		t.Fatalf("tracked expanded errno = %q, want -27", got)
	}
	resolved := resolvedCFGConstantReturnExpression(
		"ret == 0 ? copied : ret",
		alternatives[0].bypassValues,
	)
	if compactExpression(resolved) != "-27==0?copied:-27" {
		t.Fatalf("resolved compound return = %q", resolved)
	}
	outcome := returnOutcomeFromExpression(
		function,
		resolved,
		nil,
		false,
		nil,
		"nonnegative",
	)
	if compatibility := returnOutcomeCompatibility(
		outcome,
		"nonnegative",
	); compatibility != "impossible" {
		t.Fatalf(
			"tracked errno compatibility = %q for %#v, want impossible",
			compatibility,
			outcome,
		)
	}
}

func TestWideningUnsignedReturnCanProveSignedSyscallSuccess(t *testing.T) {
	child := &FunctionInfo{
		ID:                "child",
		Name:              "child",
		DisplayName:       "child",
		ReturnType:        "unsigned_integer",
		ReturnTypeBits:    32,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "uid",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "parent",
		Name:              "parent",
		DisplayName:       "parent",
		ReturnType:        "long",
		ReturnTypeBits:    64,
		Body:              "{ return child(); }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		TypedCallees: map[string][]string{
			"child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:        "returned-child",
			Direct:    true,
			Reachable: true,
			HasBlock:  true,
			BlockID:   0,
			Name:      "child",
		}},
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "child()",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		make(map[string]bool),
	)
	if !witness.proven {
		t.Fatalf("widening unsigned success was not proven: %#v", witness)
	}

	parent.ReturnTypeBits = 32
	analyzer.successWitnessCache = make(map[string]functionSuccessWitness)
	if witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		make(map[string]bool),
	); witness.proven {
		t.Fatalf("same-width unsigned-to-signed conversion was certified: %#v", witness)
	}
}

func TestNarrowingSignedReturnDoesNotPreserveSuccess(t *testing.T) {
	parent := &FunctionInfo{
		ReturnType:     "int",
		ReturnTypeBits: 32,
	}
	child := &FunctionInfo{
		ReturnType:     "long",
		ReturnTypeBits: 64,
	}
	if requirementsCompatibleAcrossFunctions(
		parent,
		child,
		"nonnegative",
	) {
		t.Fatal("narrowing signed conversion was over-certified")
	}
	if !requirementsCompatibleAcrossFunctions(
		parent,
		child,
		"zero",
	) {
		t.Fatal("zero should survive a narrowing signed conversion")
	}
}

func TestAddressArithmeticIsNotCertifiedAsValidPointer(t *testing.T) {
	if !isDefinitelyValidAddressExpression("&object") {
		t.Fatal("simple object address was not recognized")
	}
	if isDefinitelyValidAddressExpression("&object + offset") {
		t.Fatal("address arithmetic was over-certified as a valid pointer")
	}
}

func TestFunctionSuccessUsesLLVMPreservedChildWitness(t *testing.T) {
	child := &FunctionInfo{
		ID:                "child",
		Name:              "child",
		DisplayName:       "child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "parent",
		Name:              "parent",
		DisplayName:       "parent",
		ReturnType:        "int",
		File:              "/kernel/fs/parent.c",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           2,
		Body:              "{ int ret = child(); return ret; }",
		TypedCallees: map[string][]string{
			"child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:        "assigned-child",
			Direct:    true,
			Reachable: true,
			HasBlock:  true,
			BlockID:   0,
			Name:      "child",
			Line:      10,
			Column:    8,
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                0,
				SuccessSuccessors: []int{1},
			},
			{
				ID:                   1,
				ReturnExpression:     "ret",
				PotentialSuccessExit: true,
			},
		},
		LLVMCallFacts: []LLVMCallFact{{
			Kind:                            "call",
			Callee:                          "child",
			Function:                        "parent",
			SourceFunction:                  "parent",
			SourceFile:                      "/kernel/fs/parent.c",
			SourceLine:                      10,
			SourceColumn:                    8,
			MustReturnNonnegativeOnZero:     true,
			MustReturnNonnegativeOnPositive: true,
			MustPreserveNonnegativeSuccess:  true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			parent.ID: parent,
			child.ID:  child,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		make(map[string]bool),
	)
	if !witness.proven ||
		witness.method !=
			"llvm_ssa_nonnegative_success_preservation" {
		t.Fatalf("witness = %#v, want LLVM-preserved child success", witness)
	}

	parent.LLVMCallFacts[0].MustReturnNonnegativeOnPositive = false
	parent.LLVMCallFacts[0].MustPreserveNonnegativeSuccess = false
	analyzer.successWitnessCache = make(map[string]functionSuccessWitness)
	witness = analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		make(map[string]bool),
	)
	if !witness.proven ||
		witness.method != "llvm_ssa_zero_success_preservation" {
		t.Fatalf(
			"witness = %#v, want zero-only LLVM success preservation",
			witness,
		)
	}
}

func TestCFGBackedgeMarksAlternativeCyclic(t *testing.T) {
	function := &FunctionInfo{
		ID:      "loop",
		CFGExit: 3,
		CFGBlocks: []ClangCFGBlock{
			{ID: 0, SuccessSuccessors: []int{1}},
			{ID: 1, SuccessSuccessors: []int{0, 2}},
			{ID: 2},
		},
	}
	analyzer := &Analyzer{cfgCycleEdgeCache: make(map[string]bool)}
	alternatives := analyzer.constrainAlternativesForCFGEdge(
		nonEnforcingLSMAlternatives(),
		function,
		function.CFGBlocks[1],
		cfgSuccessEdge{blockID: 0, branch: "unconditional"},
	)
	if len(alternatives) != 1 || !alternatives[0].bypassCyclic {
		t.Fatalf("backedge alternatives = %#v, want cyclic", alternatives)
	}
}

func TestClangOperationTableOverridesRegexApproximation(t *testing.T) {
	analyzer := &Analyzer{
		operationTargets:      make(map[string][]OperationTarget),
		operationTables:       make(map[string]*OperationTableInfo),
		operationTablesByName: make(map[string][]string),
	}
	regexApproximation := &OperationTableInfo{
		StructType:       "proto_ops",
		Table:            "inet_stream_ops",
		File:             "/kernel/net/ipv4/af_inet.c",
		Const:            true,
		Complete:         false,
		FieldTargets:     map[string]string{},
		FieldTargetFiles: map[string]string{},
		NullFields:       map[string]bool{},
		UnknownFields:    map[string]bool{"bind": true},
	}
	analyzer.mergeOperationTableInfo(regexApproximation)
	analyzer.applyClangOperationTable(ClangOperationTableRecord{
		Kind:       "operation_table",
		StructType: "proto_ops",
		Table:      "inet_stream_ops",
		File:       "/kernel/net/ipv4/af_inet.c",
		Const:      true,
		Complete:   true,
		FieldTargets: []ClangOperationFieldTarget{{
			Field:    "bind",
			Function: "inet_bind",
			File:     "/kernel/net/ipv4/af_inet.c",
		}},
	})
	info := analyzer.operationTables["/kernel/net/ipv4/af_inet.c\x00inet_stream_ops"]
	if info == nil || !info.VerifiedByClang || !info.Complete ||
		info.FieldTargets["bind"] != "inet_bind" {
		t.Fatalf("operation table = %#v", info)
	}
}

func TestClangOperationTableClosesVerifiedFieldDespiteUnrelatedUnknownField(
	t *testing.T,
) {
	info := &OperationTableInfo{
		StructType:      "proto_ops",
		Table:           "inet_stream_ops",
		File:            "/kernel/net/ipv4/af_inet.c",
		Const:           true,
		Complete:        false,
		VerifiedByClang: true,
		FieldTargets: map[string]string{
			"bind": "inet_bind",
		},
		FieldTargetFiles: map[string]string{
			"bind": "/kernel/net/ipv4/af_inet.c",
		},
		NullFields: map[string]bool{},
		UnknownFields: map[string]bool{
			"sendpage": true,
		},
	}
	if !operationTableFieldTargetSetClosed(info, "proto_ops", "bind") {
		t.Fatal("Clang-verified bind field should be closed independently")
	}
	if operationTableFieldTargetSetClosed(info, "proto_ops", "sendpage") {
		t.Fatal("unknown sendpage field must remain open")
	}
}

func TestConflictingClangOperationTableFieldRemainsOpen(t *testing.T) {
	analyzer := &Analyzer{
		operationTargets:      make(map[string][]OperationTarget),
		operationTables:       make(map[string]*OperationTableInfo),
		operationTablesByName: make(map[string][]string),
	}
	for _, function := range []string{"inet_bind", "inet6_bind"} {
		analyzer.applyClangOperationTable(ClangOperationTableRecord{
			Kind:       "operation_table",
			StructType: "proto_ops",
			Table:      "inet_stream_ops",
			File:       "/kernel/net/ipv4/af_inet.c",
			Const:      true,
			Complete:   true,
			FieldTargets: []ClangOperationFieldTarget{{
				Field:    "bind",
				Function: function,
				File:     "/kernel/net/ipv4/af_inet.c",
			}},
		})
	}
	info := analyzer.operationTables["/kernel/net/ipv4/af_inet.c\x00inet_stream_ops"]
	if info == nil || !info.UnknownFields["bind"] {
		t.Fatalf("conflicting field was not marked unknown: %#v", info)
	}
	if operationTableFieldTargetSetClosed(info, "proto_ops", "bind") {
		t.Fatal("conflicting Clang field must not close the target set")
	}
}

func TestProofGapCategoriesSeparateOpenWorldFromImplementation(t *testing.T) {
	openWorld := classifyUnresolvedProofEdge(UnresolvedProofEdge{
		Kind: "indirect_signal_target_set_unproven",
	})
	if openWorld.ResolutionScope != "static_analysis_limit" {
		t.Fatalf("open-world scope = %q", openWorld.ResolutionScope)
	}
	success := classifyUnresolvedProofEdge(UnresolvedProofEdge{
		Kind: "successful_execution_unproven",
	})
	if success.ResolutionScope != "implementation_improvable" {
		t.Fatalf("success scope = %q", success.ResolutionScope)
	}
}

func TestCanonicalAlternativesKeepOneEnforcementWitnessPerPath(t *testing.T) {
	alternatives := canonicalLSMAlternatives([]lsmPathAlternative{
		{hooks: []string{"security_b", "security_a"}},
		{hooks: []string{"security_c", "security_b"}},
	})
	if got := classifyLSMAlternatives(alternatives); got != "enforcing" {
		t.Fatalf("classification = %q, want enforcing", got)
	}
	if len(alternatives) != 2 {
		t.Fatalf("alternatives = %#v, want two witness classes", alternatives)
	}
	for _, alternative := range alternatives {
		if len(alternative.hooks) != 1 {
			t.Fatalf(
				"enforcing alternative retained redundant hooks: %#v",
				alternative.hooks,
			)
		}
	}
}

func TestCanonicalAlternativesPreferProvenBypassForSamePathState(
	t *testing.T,
) {
	alternatives := canonicalLSMAlternatives([]lsmPathAlternative{
		{
			hooks: []string{"security_example"},
		},
		{
			bypassPath:          []string{"entry", "return"},
			bypassSuccessProven: true,
			bypassSuccessMethod: "clang_cfg_success_return",
		},
	})
	if len(alternatives) != 1 {
		t.Fatalf("alternatives = %#v, want one proven bypass", alternatives)
	}
	if len(alternatives[0].hooks) != 0 ||
		!alternatives[0].bypassSuccessProven {
		t.Fatalf("dominant alternative = %#v, want proven bypass", alternatives[0])
	}
}

func TestCanonicalAlternativesKeepDistinctPathStates(t *testing.T) {
	alternatives := canonicalLSMAlternatives([]lsmPathAlternative{
		{
			hooks: []string{"security_example"},
			bypassConstraints: []successPathConstraint{{
				functionID: "caller",
				blockID:    1,
				expression: "condition",
				required:   true,
				pathStable: true,
			}},
		},
		{
			bypassPath:          []string{"entry", "return"},
			bypassSuccessProven: true,
			bypassSuccessMethod: "clang_cfg_success_return",
			bypassConstraints: []successPathConstraint{{
				functionID: "caller",
				blockID:    1,
				expression: "condition",
				required:   false,
				pathStable: true,
			}},
		},
	})
	if len(alternatives) != 2 {
		t.Fatalf("alternatives = %#v, want distinct branch states", alternatives)
	}
}

func TestSIGKILLAlternativeProductLimit(t *testing.T) {
	tests := []struct {
		name       string
		left       int
		right      int
		limit      int
		wantExceed bool
	}{
		{name: "at limit", left: 256, right: 256, limit: 65536},
		{
			name:       "over limit",
			left:       257,
			right:      256,
			limit:      65536,
			wantExceed: true,
		},
		{name: "empty input", left: 0, right: 100, limit: 10},
		{name: "disabled limit", left: 100, right: 100, limit: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := alternativeProductExceedsLimit(
				test.left,
				test.right,
				test.limit,
			); got != test.wantExceed {
				t.Fatalf("exceeds = %t, want %t", got, test.wantExceed)
			}
		})
	}
}

func TestChildAlternativeProjectionDropsFunctionLocalConstraints(t *testing.T) {
	projected := projectChildAlternativesForCaller([]lsmPathAlternative{{
		bypassPath:          []string{"child"},
		bypassSuccessProven: true,
		bypassSuccessMethod: "cfg_branch_constrained_success_return",
		bypassConstraints: []successPathConstraint{{
			functionID: "child",
			blockID:    3,
			expression: "ret >= 0",
			required:   true,
		}},
		bypassCyclic:        true,
		bypassDerivedEffect: true,
		bypassSuccessfulCalls: []successfulCallConstraint{{
			functionID: "child",
			callSiteID: "child-return",
			callee:     "grandchild",
		}},
	}})
	if len(projected) != 1 {
		t.Fatalf("projected alternatives = %#v", projected)
	}
	if len(projected[0].bypassConstraints) != 0 ||
		len(projected[0].bypassSuccessfulCalls) != 0 {
		t.Fatalf("child-local constraints survived projection: %#v", projected[0])
	}
	if !projected[0].bypassSuccessProven ||
		projected[0].bypassCyclic ||
		!projected[0].bypassDerivedEffect {
		t.Fatalf("caller-relevant proof state was lost: %#v", projected[0])
	}
}

func TestCanonicalTypedefReturnTypePreservesSignedDomain(t *testing.T) {
	if got := normalizeClangSemanticReturnType(
		"pid_t",
		"int",
		"signed_integer",
		true,
	); got != "int" {
		t.Fatalf("pid_t normalized to %q, want int", got)
	}
	if got := normalizeClangSemanticReturnType(
		"u32",
		"unsigned int",
		"unsigned_integer",
		false,
	); got != "unsigned_integer" {
		t.Fatalf("u32 normalized to %q, want unsigned_integer", got)
	}
}

func TestCFGInitializerProvesSuccessfulReturn(t *testing.T) {
	function := &FunctionInfo{
		ID:                "initialized-return",
		Name:              "initialized_return",
		DisplayName:       "initialized_return",
		ReturnType:        "int",
		Body:              "{ int expanded = 0; return expanded; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          2,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                2,
				SuccessSuccessors: []int{1},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "expanded",
					Expression: "0",
					Kind:       "initialize",
				}},
			},
			{
				ID:                   1,
				ReturnExpression:     "expanded",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		nil,
		nil,
	)
	if !witness.proven {
		t.Fatal("CFG initializer did not prove the successful return")
	}
}

func TestForcedSyscallSuccessCertifiesVariableReturn(t *testing.T) {
	function := &FunctionInfo{
		ID:                "forced-syscall-return",
		Name:              "__do_sys_forced_return",
		DisplayName:       "__do_sys_forced_return",
		ReturnType:        "long",
		Body:              "{ force_successful_syscall_return(); return value; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "value",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		nil,
		nil,
	)
	if !witness.proven ||
		witness.method != "force_successful_syscall_return" {
		t.Fatalf("forced syscall success witness = %#v", witness)
	}
}

func TestForcedSuccessMarkerDoesNotCertifyOrdinaryHelper(t *testing.T) {
	function := &FunctionInfo{
		ID:                "forced-helper-return",
		Name:              "forced_helper_return",
		DisplayName:       "forced_helper_return",
		ReturnType:        "long",
		Body:              "{ force_successful_syscall_return(); return value; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "value",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
	}
	if witness := analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		nil,
		nil,
	); witness.proven {
		t.Fatalf("ordinary helper was force-certified: %#v", witness)
	}
}

func TestCFGReassignmentInvalidatesBranchConstraint(t *testing.T) {
	function := &FunctionInfo{
		ID:          "reassigned-return",
		Name:        "reassigned_return",
		DisplayName: "reassigned_return",
		ReturnType:  "int",
		Body: `{
			int result = input;
			if (result >= 0)
				result = unknown_value;
			return result;
		}`,
	}
	alternatives := []lsmPathAlternative{{
		bypassConstraints: []successPathConstraint{{
			functionID: function.ID,
			blockID:    3,
			expression: "result >= 0",
			required:   true,
			pathStable: true,
		}},
	}}
	updated := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{
			ID: 2,
			ValueWrites: []ClangCFGValueWrite{{
				Target:     "result",
				Expression: "unknown_value",
				Kind:       "assign",
			}},
		},
		alternatives,
	)
	if len(updated) != 1 ||
		len(updated[0].bypassConstraints) != 0 {
		t.Fatalf("stale branch constraint survived reassignment: %#v", updated)
	}
}

func TestLLVMPointeeSummaryPreservesEscapedReturnConstraint(t *testing.T) {
	callee := &FunctionInfo{
		ID:          "preserve_slot",
		Name:        "preserve_slot",
		DisplayName: "preserve_slot",
		Frontend:    "clang-ast-cfg",
		LLVMFunctionFacts: []LLVMCallFact{{
			Kind:                              "function_summary",
			Function:                          "preserve_slot",
			SourceFunction:                    "preserve_slot",
			FunctionPreservedPointeeArguments: []int{0},
		}},
	}
	parent := &FunctionInfo{
		ID:                  "escaped_parent",
		Name:                "escaped_parent",
		DisplayName:         "escaped_parent",
		ReturnType:          "pointer",
		Frontend:            "clang-ast-cfg",
		Body:                `{ void *object; preserve_slot(&object); return object; }`,
		CFGEscapedVariables: []string{"object"},
		CallSites: []ClangCallSite{{
			ID:        "preserve-call",
			Direct:    true,
			Reachable: true,
			Name:      "preserve_slot",
			Arguments: []string{"&object"},
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			callee.ID: callee,
			parent.ID: parent,
		},
	}
	analyzer.rebuildFunctionIndexes()
	analyzer.refreshLLVMPreservedEscapes()
	if !containsString(parent.CFGPreservedEscapes, "object") {
		t.Fatalf(
			"preserved escapes = %#v, want object",
			parent.CFGPreservedEscapes,
		)
	}
	if !cfgConstraintStableUntilReturn(
		parent,
		"object",
		successPathConstraint{
			functionID: parent.ID,
			expression: "object",
			required:   true,
			pathStable: true,
		},
	) {
		t.Fatal("LLVM-preserved pointee invalidated a stable return constraint")
	}
}

func TestFalseCompoundOrConstrainsReturnedPointer(t *testing.T) {
	requirement := outcomeRequirementFromCondition(
		"pointer",
		"IS_ENABLED(CONFIG_PREEMPT_RT) || unlikely(!object || !page)",
		"object",
		false,
	)
	if requirement != "nonnull" {
		t.Fatalf("requirement = %q, want nonnull", requirement)
	}
}

func TestTrueCompoundOrDoesNotSelectReturnedPointerTerm(t *testing.T) {
	requirement := outcomeRequirementFromCondition(
		"pointer",
		"runtime_flag || !object",
		"object",
		true,
	)
	if requirement != "" {
		t.Fatalf("requirement = %q, want unknown", requirement)
	}
}

func TestMissingLLVMPointeeSummaryKeepsEscapeUnstable(t *testing.T) {
	callee := &FunctionInfo{
		ID:          "unknown_slot_writer",
		Name:        "unknown_slot_writer",
		DisplayName: "unknown_slot_writer",
		Frontend:    "clang-ast-cfg",
	}
	parent := &FunctionInfo{
		ID:                  "escaped_parent",
		Name:                "escaped_parent",
		DisplayName:         "escaped_parent",
		ReturnType:          "pointer",
		Frontend:            "clang-ast-cfg",
		Body:                `{ void *object; unknown_slot_writer(&object); return object; }`,
		CFGEscapedVariables: []string{"object"},
		CallSites: []ClangCallSite{{
			ID:        "unknown-call",
			Direct:    true,
			Reachable: true,
			Name:      "unknown_slot_writer",
			Arguments: []string{"&object"},
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			callee.ID: callee,
			parent.ID: parent,
		},
	}
	analyzer.rebuildFunctionIndexes()
	analyzer.refreshLLVMPreservedEscapes()
	if containsString(parent.CFGPreservedEscapes, "object") {
		t.Fatal("unproven pointee preservation was trusted")
	}
}

func TestSymbolicCallerParameterCanDischargeReturnedParameterSuccess(
	t *testing.T,
) {
	child := &FunctionInfo{
		ID:                "identity_pointer",
		Name:              "identity_pointer",
		DisplayName:       "identity_pointer",
		ReturnType:        "pointer",
		Parameters:        []string{"value"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "value",
			PotentialSuccessExit: true,
		}},
	}
	caller := &FunctionInfo{
		ID:          "caller",
		Name:        "caller",
		DisplayName: "caller",
		Parameters:  []string{"input"},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			caller.ID: caller,
		},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	constants := analyzer.bindSymbolicSuccessParameterAssumptions(
		caller,
		child,
		[]string{"input"},
		nil,
		nil,
		nil,
		"nonnull",
		nil,
	)
	constants = bindCallReturnRequirement(
		constants,
		child,
		"nonnull",
	)
	witness := analyzer.proveFunctionSuccessfulExecution(
		child.ID,
		constants,
		nil,
	)
	if !witness.proven {
		t.Fatal("symbolic caller parameter did not establish a success witness")
	}
}

func TestSymbolicSuccessAssumptionRejectsNullAndContradictoryPath(
	t *testing.T,
) {
	child := &FunctionInfo{
		ID:                "identity_pointer",
		Name:              "identity_pointer",
		DisplayName:       "identity_pointer",
		ReturnType:        "pointer",
		Parameters:        []string{"value"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "value",
			PotentialSuccessExit: true,
		}},
	}
	caller := &FunctionInfo{
		ID:          "caller",
		Name:        "caller",
		DisplayName: "caller",
		Parameters:  []string{"input"},
	}
	analyzer := &Analyzer{}
	nullConstants := analyzer.bindSymbolicSuccessParameterAssumptions(
		caller,
		child,
		[]string{"NULL"},
		nil,
		nil,
		nil,
		"nonnull",
		nil,
	)
	if nullConstants[successAssumptionKey("value")] != "" {
		t.Fatalf("NULL argument received a nonnull assumption: %#v", nullConstants)
	}

	contradictory := analyzer.bindSymbolicSuccessParameterAssumptions(
		caller,
		child,
		[]string{"input"},
		nil,
		[]successPathConstraint{{
			functionID: caller.ID,
			expression: "input == NULL",
			required:   true,
			pathStable: true,
		}},
		nil,
		"nonnull",
		nil,
	)
	if contradictory[successAssumptionKey("value")] != "" {
		t.Fatalf(
			"contradictory NULL path received a nonnull assumption: %#v",
			contradictory,
		)
	}
}

func TestCFGValueWriteRecoversMissingCallsiteResultVariable(t *testing.T) {
	function := &FunctionInfo{
		CallSites: []ClangCallSite{{
			ID:     "callsite:1",
			Direct: true,
			Name:   "child",
		}},
	}
	expression, site := forwardedCFGCallExpression(
		function,
		"ret",
		map[string]cfgPathValue{
			"ret": {
				expression: "child()",
				callSiteID: "callsite:1",
			},
		},
	)
	if expression != "child()" || site == nil ||
		site.ID != "callsite:1" {
		t.Fatalf(
			"forwarded expression = %q, site = %#v",
			expression,
			site,
		)
	}

	function.CallSites[0].ResultVariable = "other"
	if _, site := forwardedCFGCallExpression(
		function,
		"ret",
		map[string]cfgPathValue{
			"ret": {
				expression: "child()",
				callSiteID: "callsite:1",
			},
		},
	); site != nil {
		t.Fatal("an explicit conflicting result variable was accepted")
	}
}

func TestLLVMFunctionFactFallsBackToUniqueDefinitionLine(t *testing.T) {
	function := &FunctionInfo{
		ID:               "header_inline",
		Name:             "header_inline",
		DisplayName:      "header_inline",
		File:             "/kernel/include/header.h",
		SourceLine:       42,
		TranslationUnits: []string{"/kernel/other.c"},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
	}
	analyzer.rebuildFunctionIndexes()
	matched := analyzer.findLLVMFunctionForFact(
		"/kernel/caller.c",
		LLVMCallFact{
			Kind:           "function_summary",
			Function:       "header_inline",
			SourceFunction: "header_inline",
			SourceFile:     "/kernel/include/header.h",
			SourceLine:     42,
		},
	)
	if matched != function {
		t.Fatalf("matched = %#v, want unique exact definition", matched)
	}
}

func TestLLVMFunctionFactRejectsAmbiguousDefinitionFallback(t *testing.T) {
	left := &FunctionInfo{
		ID:          "header_inline_left",
		Name:        "header_inline",
		DisplayName: "header_inline_left",
		File:        "/kernel/include/header.h",
		SourceLine:  42,
	}
	right := &FunctionInfo{
		ID:          "header_inline_right",
		Name:        "header_inline",
		DisplayName: "header_inline_right",
		File:        "/kernel/include/header.h",
		SourceLine:  42,
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			left.ID:  left,
			right.ID: right,
		},
	}
	analyzer.rebuildFunctionIndexes()
	matched := analyzer.findLLVMFunctionForFact(
		"/kernel/caller.c",
		LLVMCallFact{
			Kind:           "function_summary",
			Function:       "header_inline",
			SourceFunction: "header_inline",
			SourceFile:     "/kernel/include/header.h",
			SourceLine:     42,
		},
	)
	if matched != nil {
		t.Fatalf("ambiguous fallback matched %#v", matched)
	}
}

func TestCFGAssignedCallCanForwardProvenSuccess(t *testing.T) {
	child := &FunctionInfo{
		ID:                "assigned-child",
		Name:              "assigned_child",
		DisplayName:       "assigned_child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "1",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "assigned-parent",
		Name:              "assigned_parent",
		DisplayName:       "assigned_parent",
		ReturnType:        "int",
		Body:              "{ int result = assigned_child(); return result; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          2,
		CFGExit:           0,
		TypedCallees: map[string][]string{
			"assigned_child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "assigned-call",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        2,
			Name:           "assigned_child",
			ResultUse:      "assigned",
			ResultVariable: "result",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                2,
				SuccessSuccessors: []int{1},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "result",
					Expression: "assigned_child()",
					Kind:       "initialize",
					CallSiteID: "assigned-call",
				}},
			},
			{
				ID:                   1,
				ReturnExpression:     "result",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		nil,
	)
	if !witness.proven {
		t.Fatal("assigned direct call did not forward proven child success")
	}
}

func TestCFGPointerReturnForwardsAcrossDiscardedObserver(t *testing.T) {
	child := &FunctionInfo{
		ID:                "pointer-child",
		Name:              "pointer_child",
		DisplayName:       "pointer_child",
		ReturnType:        "pointer",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "&object",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "pointer-parent",
		Name:              "pointer_parent",
		DisplayName:       "pointer_parent",
		ReturnType:        "pointer",
		Body:              "{ void *ret = pointer_child(); trace(ret); return ret; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		TypedCallees: map[string][]string{
			"pointer_child": {child.ID},
		},
		CallSites: []ClangCallSite{
			{
				ID:             "pointer-call",
				Direct:         true,
				Reachable:      true,
				HasBlock:       true,
				BlockID:        3,
				Name:           "pointer_child",
				ResultUse:      "assigned",
				ResultVariable: "ret",
				ReturnType:     "pointer",
			},
			{
				ID:         "trace-call",
				Direct:     true,
				Reachable:  true,
				HasBlock:   true,
				BlockID:    2,
				Name:       "trace",
				ResultUse:  "discarded",
				ReturnType: "void",
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                3,
				SuccessSuccessors: []int{2},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "ret",
					Expression: "pointer_child()",
					Kind:       "initialize",
					CallSiteID: "pointer-call",
				}},
			},
			{
				ID:                2,
				SuccessSuccessors: []int{1},
				Calls:             []string{"trace"},
				CallSiteIDs:       []string{"trace-call"},
			},
			{
				ID:                   1,
				ReturnExpression:     "ret",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnull",
		},
		nil,
	)
	if !witness.proven {
		t.Fatal("discarded observer prevented exact pointer success forwarding")
	}
}

func TestCFGExactArgumentTransformerPreservesCallSuccess(t *testing.T) {
	source := &FunctionInfo{
		ID:                "pointer-source",
		Name:              "pointer_source",
		DisplayName:       "pointer_source",
		ReturnType:        "pointer",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "&object",
			PotentialSuccessExit: true,
		}},
	}
	transform := &FunctionInfo{
		ID:                "pointer-transform",
		Name:              "pointer_transform",
		DisplayName:       "pointer_transform",
		ReturnType:        "pointer",
		Parameters:        []string{"context", "value"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "(void *)value",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "lineage-parent",
		Name:              "lineage_parent",
		DisplayName:       "lineage_parent",
		ReturnType:        "pointer",
		Body:              "{ void *ret = pointer_source(); ret = pointer_transform(ctx, ret); return ret; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          2,
		CFGExit:           0,
		TypedCallees: map[string][]string{
			"pointer_source":    {source.ID},
			"pointer_transform": {transform.ID},
		},
		CallSites: []ClangCallSite{
			{
				ID:             "source-call",
				Direct:         true,
				Reachable:      true,
				HasBlock:       true,
				BlockID:        2,
				Name:           "pointer_source",
				ResultUse:      "assigned",
				ResultVariable: "ret",
				ReturnType:     "pointer",
			},
			{
				ID:             "transform-call",
				Direct:         true,
				Reachable:      true,
				HasBlock:       true,
				BlockID:        2,
				Name:           "pointer_transform",
				ResultUse:      "assigned",
				ResultVariable: "ret",
				ReturnType:     "pointer",
				Arguments:      []string{"ctx", "ret"},
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                2,
				SuccessSuccessors: []int{1},
				ValueWrites: []ClangCFGValueWrite{
					{
						Target:     "ret",
						Expression: "pointer_source()",
						Kind:       "initialize",
						CallSiteID: "source-call",
					},
					{
						Target:     "ret",
						Expression: "pointer_transform(ctx, ret)",
						Kind:       "assign",
						CallSiteID: "transform-call",
					},
				},
			},
			{
				ID:                   1,
				ReturnExpression:     "ret",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			source.ID:    source,
			transform.ID: transform,
			parent.ID:    parent,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnull",
		},
		nil,
	)
	if !witness.proven ||
		witness.method != "cfg_exact_argument_call_lineage" {
		t.Fatalf("lineage witness = %#v", witness)
	}

	transform.CFGBlocks[0].ReturnExpression = "NULL"
	analyzer.successWitnessCache = nil
	witness = analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnull",
		},
		nil,
	)
	if witness.proven {
		t.Fatalf("non-preserving transformer produced witness %#v", witness)
	}
}

func TestClangExpandedReturnExpressionRecoversMacroConstant(t *testing.T) {
	block := ClangCFGBlock{
		ReturnExpression:         "ZERO_SIZE_PTR",
		ReturnExpressionExpanded: "(void *)16",
	}
	expression := clangCFGReturnExpression(block)
	if expression != "(void *)16" {
		t.Fatalf("expanded return expression = %q", expression)
	}
	if !returnExpressionProvesSuccess(
		"pointer",
		expression,
		"nonnull_valid_pointer",
	) {
		t.Fatal("expanded non-null pointer constant was not recognized")
	}
}

func TestCFGImpossibleCallGuardDoesNotProveSuccess(t *testing.T) {
	child := &FunctionInfo{
		ID:                "always-negative",
		Name:              "always_negative",
		DisplayName:       "always_negative",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "-EINVAL",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "guarded-parent",
		Name:              "guarded_parent",
		DisplayName:       "guarded_parent",
		ReturnType:        "int",
		Body:              "{ int result = always_negative(); if (result < 0) return result; return 0; }",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		TypedCallees: map[string][]string{
			"always_negative": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "negative-call",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        3,
			Name:           "always_negative",
			ResultUse:      "assigned",
			ResultVariable: "result",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       3,
				TerminatorCondition:      "result < 0",
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"false"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "result",
					Expression: "always_negative()",
					Kind:       "initialize",
					CallSiteID: "negative-call",
				}},
			},
			{
				ID:                   1,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	if witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		nil,
		nil,
	); witness.proven {
		t.Fatalf("impossible guarded success was certified: %#v", witness)
	}
}

func TestCFGVisitedStateKeepsLessRestrictedPath(t *testing.T) {
	seen := make(map[string][]map[int]bool)
	if !admitCFGVisitedState(
		seen,
		"state",
		map[int]bool{1: true, 2: true, 3: true},
	) {
		t.Fatal("first CFG state was rejected")
	}
	if !admitCFGVisitedState(
		seen,
		"state",
		map[int]bool{1: true, 2: true},
	) {
		t.Fatal("less restricted CFG path was incorrectly dominated")
	}
	if admitCFGVisitedState(
		seen,
		"state",
		map[int]bool{1: true, 2: true, 4: true},
	) {
		t.Fatal("state dominated by the less restricted path was admitted")
	}
	if len(seen["state"]) != 1 {
		t.Fatalf("dominated CFG histories remain: %#v", seen["state"])
	}
}

func TestCallReturnRequirementUsesSuccessfulIntegerGuard(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body: `
			int ret;
			ret = child();
			if (ret)
				return -EIO;
			return 0;
		`,
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	site := ClangCallSite{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		Name:       "child",
		ResultUse:  "assigned",
		ReturnType: "int",
	}
	parent.CallSites = []ClangCallSite{site}
	requirement := requiredCallReturnForSite(
		parent,
		child,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		"",
	)
	if requirement != "zero" {
		t.Fatalf("call requirement = %q, want zero", requirement)
	}
}

func TestChildFailureOutcomeCannotSatisfyCallerSuccessGuard(t *testing.T) {
	function := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	analyzer := &Analyzer{}
	negative := analyzer.finalizeSuccessExitAlternatives(
		function,
		ClangCFGBlock{
			ID:                   1,
			ReturnExpression:     "-EIO",
			PotentialSuccessExit: true,
		},
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		nonEnforcingLSMAlternatives(function.DisplayName),
	)
	if len(negative) != 0 {
		t.Fatalf("negative child outcome survived zero guard: %#v", negative)
	}

	zero := analyzer.finalizeSuccessExitAlternatives(
		function,
		ClangCFGBlock{
			ID:                   2,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		},
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		nonEnforcingLSMAlternatives(function.DisplayName),
	)
	if got := classifySuccessExitLSMAlternatives(zero); got !=
		"non_enforcing" {
		t.Fatalf("zero child outcome classified %q, want non_enforcing", got)
	}
}

func TestBranchConstrainedFailureDoesNotCompeteWithEnforcingExit(t *testing.T) {
	function := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
		Body: `
			int ret;
			if (ret < 0)
				return ret;
			return 0;
		`,
	}
	analyzer := &Analyzer{}
	failure := analyzer.finalizeSuccessExitAlternatives(
		function,
		ClangCFGBlock{
			ID:                   1,
			ReturnExpression:     "ret",
			PotentialSuccessExit: true,
		},
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		[]lsmPathAlternative{{
			bypassPath: []string{function.DisplayName},
			bypassConstraints: []successPathConstraint{{
				functionID: function.ID,
				blockID:    0,
				expression: "ret < 0",
				required:   true,
			}},
		}},
	)
	if len(failure) != 0 {
		t.Fatalf(
			"branch-constrained failure survived zero requirement: %#v",
			failure,
		)
	}
	enforcing := analyzer.finalizeSuccessExitAlternatives(
		function,
		ClangCFGBlock{
			ID:                   2,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		},
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		enforcingLSMAlternatives("security_example"),
	)
	if got := classifySuccessExitLSMAlternatives(
		mergeLSMAlternatives(failure, enforcing),
	); got != "enforcing" {
		t.Fatalf("merged child classification = %q, want enforcing", got)
	}
}

func TestErrOrNullGuardDoesNotAssumePTRERRIsAlwaysNegative(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body: `
			void *pointer;
			pointer = child();
			if (IS_ERR_OR_NULL(pointer))
				return PTR_ERR(pointer);
			return 0;
		`,
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "pointer",
	}
	parent.CallSites = []ClangCallSite{{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		Name:       "child",
		ResultUse:  "assigned",
		ReturnType: "pointer",
	}}
	if requirement := requiredCallReturnForSite(
		parent,
		child,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		"",
	); requirement != "" {
		t.Fatalf(
			"IS_ERR_OR_NULL/PTR_ERR inferred unsafe requirement %q",
			requirement,
		)
	}
}

func TestPTRERROutcomeFollowsISERRPathConstraint(t *testing.T) {
	function := &FunctionInfo{
		ID:         "pointer-error",
		Name:       "pointer_error",
		ReturnType: "int",
	}
	outcome := returnOutcomeFromExpression(
		function,
		"PTR_ERR(pointer)",
		[]successPathConstraint{{
			functionID: function.ID,
			blockID:    1,
			expression: "IS_ERR(pointer)",
			required:   true,
			pathStable: true,
		}},
		false,
		nil,
		"nonnegative",
	)
	if outcome.domain != returnDomainSigned ||
		outcome.mask != outcomeNegative {
		t.Fatalf("PTR_ERR outcome = %#v, want negative", outcome)
	}
}

func TestPTRERROutcomePreservesErrOrNullDistinction(t *testing.T) {
	function := &FunctionInfo{
		ID:         "pointer-error-or-null",
		Name:       "pointer_error_or_null",
		ReturnType: "int",
	}
	outcome := returnOutcomeFromExpression(
		function,
		"PTR_ERR(pointer)",
		[]successPathConstraint{{
			functionID: function.ID,
			blockID:    1,
			expression: "IS_ERR_OR_NULL(pointer)",
			required:   true,
			pathStable: true,
		}},
		false,
		nil,
		"nonnegative",
	)
	if outcome.domain != returnDomainSigned ||
		outcome.mask != outcomeNegative|outcomeZero {
		t.Fatalf(
			"PTR_ERR error-or-null outcome = %#v, want negative-or-zero",
			outcome,
		)
	}
	if returnOutcomeCompatibility(outcome, "nonnegative") !=
		"conditional" {
		t.Fatal("error-or-null PTR_ERR was over-certified as success")
	}
}

func TestERRPTROutcomeFollowsNegativeErrnoConstraint(t *testing.T) {
	function := &FunctionInfo{
		ID:         "errno-pointer",
		Name:       "errno_pointer",
		ReturnType: "pointer",
	}
	outcome := returnOutcomeFromExpression(
		function,
		"ERR_PTR(error)",
		[]successPathConstraint{{
			functionID: function.ID,
			blockID:    1,
			expression: "error < 0",
			required:   true,
			pathStable: true,
		}},
		false,
		nil,
		"nonnull_valid_pointer",
	)
	if outcome.domain != returnDomainPointer ||
		outcome.mask != outcomePointerError {
		t.Fatalf("ERR_PTR outcome = %#v, want error pointer", outcome)
	}

	outcome = returnOutcomeFromExpression(
		function,
		"ERR_PTR(unknown_error)",
		nil,
		false,
		nil,
		"nonnull_valid_pointer",
	)
	if outcome.domain != returnDomainPointer ||
		outcome.mask != outcomePointerError {
		t.Fatalf(
			"unknown ERR_PTR outcome = %#v, want error pointer",
			outcome,
		)
	}
	if returnOutcomeCompatibility(
		outcome,
		"nonnull_valid_pointer",
	) != "impossible" {
		t.Fatal("unknown ERR_PTR was allowed to become a valid pointer")
	}
}

func TestCFGTracksPTRERRConversionUntilPointerRewrite(t *testing.T) {
	function := &FunctionInfo{
		ID:         "pointer-conversion",
		Name:       "pointer_conversion",
		ReturnType: "int",
		CallSites: []ClangCallSite{{
			ID:             "pointer-site",
			Direct:         true,
			Name:           "child",
			ResultVariable: "pointer",
			ReturnType:     "pointer",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  1,
				TerminatorCondition: "IS_ERR(pointer)",
			},
			{
				ID:                   2,
				ReturnExpression:     "error",
				PotentialSuccessExit: true,
			},
		},
	}
	initial := []lsmPathAlternative{{
		bypassValues: map[string]cfgPathValue{
			"pointer": {
				expression: "child()",
				callSiteID: "pointer-site",
			},
		},
	}}
	converted := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "error",
			Expression: "PTR_ERR(pointer)",
			Kind:       "assign",
			CallSiteID: "ptr-err-site",
		}}},
		initial,
	)
	if len(converted) != 1 ||
		converted[0].bypassValues["error"].expression !=
			"PTR_ERR(pointer)" {
		t.Fatalf("PTR_ERR conversion was not tracked: %#v", converted)
	}
	if got := resolvedCFGConstantReturnExpression(
		"error",
		converted[0].bypassValues,
	); got != "PTR_ERR(pointer)" {
		t.Fatalf("resolved conversion = %q", got)
	}
	outcome := returnOutcomeFromExpression(
		function,
		resolvedCFGConstantReturnExpression(
			"error",
			converted[0].bypassValues,
		),
		[]successPathConstraint{{
			functionID: function.ID,
			blockID:    1,
			expression: "IS_ERR(pointer)",
			required:   true,
			pathStable: true,
		}},
		false,
		nil,
		"nonnegative",
	)
	if returnOutcomeCompatibility(outcome, "nonnegative") !=
		"impossible" {
		t.Fatalf(
			"IS_ERR/PTR_ERR failure path survived as success: %#v",
			outcome,
		)
	}
	if got := resolvedCFGConstantReturnExpression(
		"error",
		map[string]cfgPathValue{
			"error": {
				expression: "PTR_ERR(pointer)",
				callSiteID: "ptr-err-site",
			},
		},
	); got != "error" {
		t.Fatalf("ungrounded PTR_ERR conversion resolved to %q", got)
	}

	rewritten := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "pointer",
			Expression: "NULL",
			Kind:       "assign",
		}}},
		converted,
	)
	if _, ok := rewritten[0].bypassValues["error"]; ok {
		t.Fatalf(
			"stale PTR_ERR relation survived pointer rewrite: %#v",
			rewritten,
		)
	}
}

func TestCFGTracksSimpleCallResultAliasUntilSourceRewrite(t *testing.T) {
	function := &FunctionInfo{
		ID:         "result-alias",
		Name:       "result_alias",
		ReturnType: "int",
		CallSites: []ClangCallSite{{
			ID:             "value-site",
			Direct:         true,
			Name:           "child",
			ResultVariable: "value",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  1,
				TerminatorCondition: "value < 0",
			},
			{
				ID:                   2,
				ReturnExpression:     "result",
				PotentialSuccessExit: true,
			},
		},
	}
	initial := []lsmPathAlternative{{
		bypassValues: map[string]cfgPathValue{
			"value": {
				expression: "child()",
				callSiteID: "value-site",
			},
		},
	}}
	aliased := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "result",
			Expression: "value",
			Kind:       "assign",
		}}},
		initial,
	)
	if got := resolvedCFGConstantReturnExpression(
		"result",
		aliased[0].bypassValues,
	); got != "value" {
		t.Fatalf("resolved alias = %q, want value", got)
	}
	if lineage := aliased[0].bypassValues["result"].lineage; len(lineage) != 1 ||
		lineage[0].callSiteID != "value-site" {
		t.Fatalf("exact call-result lineage was lost: %#v", lineage)
	}

	rewritten := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "value",
			Expression: "0",
			Kind:       "assign",
		}}},
		aliased,
	)
	if _, ok := rewritten[0].bypassValues["result"]; ok {
		t.Fatalf("stale scalar alias survived source rewrite: %#v", rewritten)
	}
}

func TestCFGCallResultAliasProvesForwardedSuccess(t *testing.T) {
	child := &FunctionInfo{
		ID:                "alias-child",
		Name:              "alias_child",
		DisplayName:       "alias_child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          1,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "1",
			PotentialSuccessExit: true,
		}},
	}
	parent := &FunctionInfo{
		ID:                "alias-parent",
		Name:              "alias_parent",
		DisplayName:       "alias_parent",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		TypedCallees: map[string][]string{
			"alias_child": {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "alias-call",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        3,
			Name:           "alias_child",
			ResultUse:      "assigned",
			ResultVariable: "source",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                3,
				SuccessSuccessors: []int{2},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "source",
					Expression: "alias_child()",
					Kind:       "assign",
					CallSiteID: "alias-call",
				}},
			},
			{
				ID:                2,
				SuccessSuccessors: []int{1},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "result",
					Expression: "source",
					Kind:       "assign",
				}},
			},
			{
				ID:                   1,
				ReturnExpression:     "result",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		parent.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnegative",
		},
		nil,
	)
	if !witness.proven ||
		witness.method != "cfg_exact_call_result_alias" {
		t.Fatalf("call-result alias witness = %#v", witness)
	}
}

func TestCFGCallResultAliasRejectsCrossPathOutcomeMixing(t *testing.T) {
	child := &FunctionInfo{
		ID:                "mixed-outcome-child",
		Name:              "mixed_outcome_child",
		DisplayName:       "mixed_outcome_child",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       3,
				SuccessSuccessors:        []int{2, 1},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "condition",
			},
			{
				ID:                   2,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
			{
				ID:                   1,
				ReturnExpression:     "-EIO",
				PotentialSuccessExit: true,
			},
		},
	}
	parent := &FunctionInfo{
		ID:                "mixed-outcome-parent",
		Name:              "mixed_outcome_parent",
		DisplayName:       "mixed_outcome_parent",
		ReturnType:        "int",
		Body:              "int error; return error;",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		TypedCallees: map[string][]string{
			child.Name: {child.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "mixed-outcome-call",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        2,
			Name:           child.Name,
			ResultUse:      "assigned",
			ResultVariable: "error",
			ReturnType:     "int",
		}},
	}
	returnBlock := ClangCFGBlock{
		ID:                   1,
		ReturnExpression:     "error",
		PotentialSuccessExit: true,
	}
	values := map[string]cfgPathValue{
		"error": {
			expression: "mixed_outcome_child()",
			callSiteID: "mixed-outcome-call",
			lineage: []cfgPathCallStep{{
				expression:     "mixed_outcome_child()",
				callSiteID:     "mixed-outcome-call",
				sourceArgument: -1,
			}},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			child.ID:  child,
			parent.ID: parent,
		},
	}
	analyzer.rebuildFunctionIndexes()
	witness := analyzer.proveSuccessfulReturnBlockAlongPathWithValues(
		parent,
		returnBlock,
		map[string]string{
			contextReturnRequirementKey: "nonnegative",
		},
		nil,
		[]successPathConstraint{{
			functionID: parent.ID,
			blockID:    2,
			expression: "error",
			required:   true,
			pathStable: true,
		}},
		false,
		true,
		nil,
		values,
	)
	if witness.proven {
		t.Fatalf(
			"negative nonzero path mixed with zero success path: %#v",
			witness,
		)
	}
	witness = analyzer.proveSuccessfulReturnBlockAlongPathWithValues(
		parent,
		returnBlock,
		map[string]string{
			contextReturnRequirementKey: "nonnegative",
		},
		nil,
		[]successPathConstraint{{
			functionID: parent.ID,
			blockID:    2,
			expression: "error",
			required:   false,
			pathStable: true,
		}},
		false,
		true,
		nil,
		values,
	)
	if !witness.proven {
		t.Fatal("matching zero branch was not proven successful")
	}
}

func TestCFGTracksUnseededLocalAliasUntilSourceRewrite(t *testing.T) {
	function := &FunctionInfo{
		ID:         "local-alias",
		Name:       "local_alias",
		ReturnType: "long",
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "error",
			PotentialSuccessExit: true,
		}},
	}
	aliased := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "error",
			Expression: "len",
			Kind:       "assign",
		}}},
		nonEnforcingLSMAlternatives(),
	)
	if got := resolvedCFGConstantReturnExpression(
		"error",
		aliased[0].bypassValues,
	); got != "len" {
		t.Fatalf("resolved unseeded alias = %q, want len", got)
	}

	rewritten := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:     "len",
			Expression: "1",
			Kind:       "assign",
		}}},
		aliased,
	)
	if _, ok := rewritten[0].bypassValues["error"]; ok {
		t.Fatalf("stale unseeded alias survived rewrite: %#v", rewritten)
	}
}

func TestFunctionSuccessUsesConstrainedCurrentTernaryBranch(t *testing.T) {
	function := &FunctionInfo{
		ID:                "find-process",
		Name:              "find_process",
		DisplayName:       "find_process",
		ReturnType:        "pointer",
		Parameters:        []string{"pid"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          4,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{
			{ID: 0},
			{
				ID:                       1,
				ReturnExpressionExpanded: "pid ? lookup(pid) : get_current()",
				PotentialSuccessExit:     true,
				SuccessSuccessors:        []int{0},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                       2,
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                       3,
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                       4,
				TerminatorCondition:      "pid",
				SuccessSuccessors:        []int{2, 3},
				SuccessSuccessorBranches: []string{"true", "false"},
			},
		},
	}
	analyzer := &Analyzer{
		functions:           map[string]*FunctionInfo{function.ID: function},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnull",
		},
		make(map[string]bool),
	)
	if !witness.proven {
		t.Fatal("current ternary branch did not prove nonnull success")
	}
}

func TestFunctionSuccessUsesCallIntHookDefaultAllow(t *testing.T) {
	function := &FunctionInfo{
		ID:                "security-check",
		Name:              "security_check",
		DisplayName:       "security_check",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		Body: `
			return call_int_hook(example, 0, object);
		`,
	}
	analyzer := &Analyzer{
		functions:           map[string]*FunctionInfo{function.ID: function},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		make(map[string]bool),
	)
	if !witness.proven ||
		witness.method != "source_dispatch_default_success" {
		t.Fatalf("default-allow witness = %#v", witness)
	}

	function.Body = `return call_int_hook(example, -EACCES, object);`
	analyzer.successWitnessCache = make(map[string]functionSuccessWitness)
	witness = analyzer.proveFunctionSuccessfulExecution(
		function.ID,
		map[string]string{
			contextReturnRequirementKey: "zero",
		},
		make(map[string]bool),
	)
	if witness.proven {
		t.Fatalf("denying default was certified: %#v", witness)
	}
}

func TestKernelAllocatorRuntimeSuccessContractIsNarrow(t *testing.T) {
	allocator := &FunctionInfo{
		Name:        "kmem_cache_alloc",
		DisplayName: "kmem_cache_alloc",
		File:        "/kernel/include/linux/slab.h",
		ReturnType:  "pointer",
	}
	witness := kernelRuntimeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
	)
	if !witness.proven ||
		witness.method !=
			"kernel_fallible_allocator_success_contract" {
		t.Fatalf("allocator witness = %#v", witness)
	}
	if witness := kernelRuntimeSuccessContractWitness(
		allocator,
		"",
	); !witness.proven {
		t.Fatalf(
			"allocator default successful return was not certified: %#v",
			witness,
		)
	}
	if kernelRuntimeSuccessContractWitness(
		allocator,
		"error_pointer",
	).proven {
		t.Fatal("allocator contract certified an error pointer")
	}
	for _, name := range []string{
		"kmalloc_node",
		"alloc_pages",
		"__alloc_pages",
		"__alloc_pages_node",
	} {
		allocator.Name = name
		allocator.File = "/kernel/mm/page_alloc.c"
		if name == "kmalloc_node" {
			allocator.File = "/kernel/include/linux/slab.h"
		}
		if witness := kernelRuntimeSuccessContractWitness(
			allocator,
			"",
		); !witness.proven {
			t.Fatalf(
				"core allocator %s was not certified: %#v",
				name,
				witness,
			)
		}
	}

	allocator.Name = "custom_kmem_cache_alloc"
	if kernelRuntimeSuccessContractWitness(
		allocator,
		"nonnull",
	).proven {
		t.Fatal("lookalike allocator name was accepted")
	}
	allocator.Name = "kmem_cache_alloc"
	allocator.File = "/drivers/example.c"
	if kernelRuntimeSuccessContractWitness(
		allocator,
		"nonnull",
	).proven {
		t.Fatal("allocator contract escaped the kernel allocator files")
	}
}

func TestX86PKeyMinusOneSentinelSuccessContractIsNarrow(t *testing.T) {
	allocator := &FunctionInfo{
		Name:        "mm_pkey_alloc",
		DisplayName: "mm_pkey_alloc",
		File:        "/kernel/arch/x86/include/asm/pkeys.h",
		ReturnType:  "int",
	}
	witness := kernelRuntimeSuccessContractWitness(
		allocator,
		"nonnegative",
	)
	if !witness.proven ||
		witness.method !=
			"kernel_minus_one_sentinel_success_contract" {
		t.Fatalf("pkey sentinel witness = %#v", witness)
	}
	if kernelRuntimeSuccessContractWitness(
		allocator,
		"negative",
	).proven {
		t.Fatal("pkey sentinel contract certified a failure outcome")
	}
	allocator.File = "/drivers/example.c"
	if kernelRuntimeSuccessContractWitness(
		allocator,
		"nonnegative",
	).proven {
		t.Fatal("pkey sentinel contract escaped the x86 pkey implementation")
	}
}

func TestKernelAllocatorEffectFreeFastPathContractIsNarrow(
	t *testing.T,
) {
	allocator := &FunctionInfo{
		Name:        "kmem_cache_zalloc",
		DisplayName: "kmem_cache_zalloc",
		File:        "/kernel/include/linux/slab.h",
		ReturnType:  "pointer",
	}
	for _, domain := range []string{"lsm", "sigkill"} {
		witness := kernelRuntimeEffectFreeSuccessContractWitness(
			allocator,
			"nonnull_valid_pointer",
			domain,
		)
		if !witness.proven ||
			witness.method !=
				"kernel_fallible_allocator_effect_free_fast_path_contract" {
			t.Fatalf("%s allocator fast-path witness = %#v", domain, witness)
		}
	}
	if kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"error_pointer",
		"lsm",
	).proven {
		t.Fatal("allocator fast-path contract certified an error pointer")
	}
	if kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
		"other",
	).proven {
		t.Fatal("allocator fast-path contract accepted an unknown domain")
	}

	allocator.Name = "custom_kmem_cache_zalloc"
	if kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
		"sigkill",
	).proven {
		t.Fatal("lookalike allocator fast-path name was accepted")
	}
	allocator.Name = "kmem_cache_zalloc"
	allocator.File = "/drivers/example.c"
	if kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
		"sigkill",
	).proven {
		t.Fatal("allocator fast-path contract escaped allocator files")
	}
}

func TestKernelAllocatorContractCoversExactKvmallocHeader(t *testing.T) {
	allocator := &FunctionInfo{
		Name:        "kvmalloc",
		DisplayName: "kvmalloc",
		File:        "/kernel/include/linux/mm.h",
		ReturnType:  "pointer",
	}
	if witness := kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
		"sigkill",
	); !witness.proven {
		t.Fatalf("kvmalloc fast-path contract = %#v", witness)
	}
	allocator.Name = "custom_kvmalloc"
	if witness := kernelRuntimeEffectFreeSuccessContractWitness(
		allocator,
		"nonnull_valid_pointer",
		"sigkill",
	); witness.proven {
		t.Fatalf("lookalike kvmalloc was certified: %#v", witness)
	}
}

func TestReviewedKernelFailureContractsAreSourceScoped(t *testing.T) {
	tests := []struct {
		name      string
		function  string
		file      string
		callee    string
		childKind string
		body      string
		wantKind  string
		wantErrno string
	}{
		{
			name:      "capability errno to false",
			function:  "ns_capable_common",
			file:      "/kernel/kernel/capability.c",
			callee:    "security_capable",
			childKind: failureReturnErrno,
			body: `
				capable = security_capable(current_cred(), ns, cap, opts);
				if (capable == 0) {
					return true;
				}
				return false;
			`,
			wantKind:  failureReturnFalse,
			wantErrno: "normalized",
		},
		{
			name:      "file allocation errno to error pointer",
			function:  "__alloc_file",
			file:      "/kernel/fs/file_table.c",
			callee:    "security_file_alloc",
			childKind: failureReturnErrno,
			body: `
				error = security_file_alloc(f);
				if (error)
					return ERR_PTR(error);
				return f;
			`,
			wantKind:  failureReturnErrPtr,
			wantErrno: "exact",
		},
		{
			name:      "file wrapper preserves error pointer",
			function:  "alloc_empty_file",
			file:      "/kernel/fs/file_table.c",
			callee:    "__alloc_file",
			childKind: failureReturnErrPtr,
			body: `
				f = __alloc_file(flags, cred);
				if (!IS_ERR(f))
					percpu_counter_inc(&nr_files);
				return f;
			`,
			wantKind:  failureReturnErrPtr,
			wantErrno: "exact",
		},
		{
			name:      "anonymous fd converts error pointer",
			function:  "__anon_inode_getfd",
			file:      "/kernel/fs/anon_inodes.c",
			callee:    "__anon_inode_getfile",
			childKind: failureReturnErrPtr,
			body: `
				file = __anon_inode_getfile(name, fops, priv, flags, context_inode, secure);
				if (IS_ERR(file)) {
					error = PTR_ERR(file);
					goto err_put_unused_fd;
				}
				return fd;
			err_put_unused_fd:
				return error;
			`,
			wantKind:  failureReturnErrno,
			wantErrno: "exact",
		},
		{
			name:      "epoll converts file allocation denial",
			function:  "do_epoll_create",
			file:      "/kernel/fs/eventpoll.c",
			callee:    "anon_inode_getfile",
			childKind: failureReturnErrPtr,
			body: `
				file = anon_inode_getfile("[eventpoll]", fops, ep, flags);
				if (IS_ERR(file)) {
					error = PTR_ERR(file);
					goto out_free_fd;
				}
				return fd;
			out_free_fd:
				return error;
			`,
			wantKind:  failureReturnErrno,
			wantErrno: "exact",
		},
		{
			name:      "mqueue converts dentry allocation denial",
			function:  "do_mq_open",
			file:      "/kernel/ipc/mqueue.c",
			callee:    "dentry_open",
			childKind: failureReturnErrPtr,
			body: `
				file = dentry_open(&path, oflag, current_cred());
				if (IS_ERR(file))
					error = PTR_ERR(file);
				if (error)
					fd = error;
				return fd;
			`,
			wantKind:  failureReturnErrno,
			wantErrno: "exact",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			function := &FunctionInfo{
				Name:        test.function,
				DisplayName: test.function,
				File:        test.file,
				Body:        test.body,
				Frontend:    "clang-ast-cfg",
				CFGComplete: true,
			}
			effect, ok := reviewedKernelCallFailureEffect(
				function,
				test.callee,
				test.childKind,
			)
			if !ok {
				t.Fatal("reviewed contract was not recognized")
			}
			if effect.failureEncoding != test.wantKind ||
				effect.errnoPropagation != test.wantErrno ||
				classifySignalAbortEffect(effect) != "guaranteed" {
				t.Fatalf("contract effect = %#v", effect)
			}
		})
	}

	lookalike := &FunctionInfo{
		Name:        "__alloc_file",
		DisplayName: "__alloc_file",
		File:        "/kernel/drivers/example.c",
		Body: `
			error = security_file_alloc(f);
			if (error)
				return ERR_PTR(error);
			return f;
		`,
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	if effect, ok := reviewedKernelCallFailureEffect(
		lookalike,
		"security_file_alloc",
		failureReturnErrno,
	); ok {
		t.Fatalf("contract escaped its reviewed source file: %#v", effect)
	}

	lookalike.File = "/kernel/fs/file_table.c"
	lookalike.Body = `
		error = security_file_alloc(f);
		return f;
	`
	if effect, ok := reviewedKernelCallFailureEffect(
		lookalike,
		"security_file_alloc",
		failureReturnErrno,
	); ok {
		t.Fatalf("contract accepted a changed denial path: %#v", effect)
	}

	allocator := &FunctionInfo{
		Name:        "__alloc_file",
		DisplayName: "__alloc_file",
		File:        "/kernel/fs/file_table.c",
		Body: `
			error = security_file_alloc(f);
			if (error)
				return ERR_PTR(error);
			return f;
		`,
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	effect := (&Analyzer{}).localLSMErrorEffectForBody(
		allocator,
		allocator.Body,
		"security_file_alloc",
	)
	if effect.failureEncoding != failureReturnErrPtr ||
		classifySignalAbortEffect(effect) != "guaranteed" {
		t.Fatalf("local LSM contract was bypassed: %#v", effect)
	}
}

func TestPropagationUsesFailureEncodingInsteadOfSuccessRequirement(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		fallback string
		want     string
	}{
		{
			name:     "error pointer overrides valid pointer success",
			encoding: failureReturnErrPtr,
			fallback: "valid_pointer",
			want:     "failure_err_ptr",
		},
		{
			name:     "false overrides true success",
			encoding: failureReturnFalse,
			fallback: "true",
			want:     "failure_false",
		},
		{
			name:     "errno overrides nonnegative success",
			encoding: failureReturnErrno,
			fallback: "nonnegative",
			want:     "",
		},
		{
			name:     "unknown retains conservative fallback",
			encoding: failureReturnUnknown,
			fallback: "nonnegative",
			want:     "nonnegative",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			effect := localErrorEffect{
				failureEncoding: test.encoding,
			}
			if got := propagatedFailureRequirement(
				effect,
				test.fallback,
			); got != test.want {
				t.Fatalf("requirement = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReviewedKernelSuccessGateContractsAreSourceScoped(t *testing.T) {
	tests := []struct {
		name     string
		function string
		file     string
		body     string
		wantHook string
	}{
		{
			name:     "epoll file allocation",
			function: "do_epoll_create",
			file:     "/kernel/fs/eventpoll.c",
			body: `
				file = anon_inode_getfile(name, fops, ep, flags);
				if (IS_ERR(file)) {
					error = PTR_ERR(file);
				}
				fd_install(fd, file);
				return fd;
				return error;
			`,
			wantHook: "security_file_alloc",
		},
		{
			name:     "mqueue file allocation",
			function: "do_mq_open",
			file:     "/kernel/ipc/mqueue.c",
			body: `
				file = dentry_open(&path, oflag, current_cred());
				if (!IS_ERR(file))
					fd_install(fd, file);
				else
					error = PTR_ERR(file);
				fd = error;
				return fd;
			`,
			wantHook: "security_file_alloc",
		},
		{
			name:     "file handle open allocation",
			function: "do_handle_open",
			file:     "/kernel/fs/fhandle.c",
			body: `
				file = file_open_root(&path, "", open_flag, 0);
				if (IS_ERR(file)) {
					retval = PTR_ERR(file);
				}
				fd_install(fd, file);
				return retval;
			`,
			wantHook: "security_file_alloc",
		},
		{
			name:     "memfd branch intersection",
			function: "__do_sys_memfd_create",
			file:     "/kernel/mm/memfd.c",
			body: `
				file = hugetlb_file_setup(name, size, flags, ucounts, type, shift);
				file = shmem_file_setup(name, size, flags);
				if (IS_ERR(file)) {
					error = PTR_ERR(file);
				}
				fd_install(fd, file);
				return fd;
				return error;
			`,
			wantHook: "security_file_alloc",
		},
		{
			name:     "open tree branch intersection",
			function: "__do_sys_open_tree",
			file:     "/kernel/fs/namespace.c",
			body: `
				file = open_detached_copy(&path, flags & AT_RECURSIVE);
				file = dentry_open(&path, O_PATH, current_cred());
				if (IS_ERR(file)) {
					return PTR_ERR(file);
				}
				fd_install(fd, file);
				return fd;
			`,
			wantHook: "security_file_alloc",
		},
		{
			name:     "process madvise capability",
			function: "__do_sys_process_madvise",
			file:     "/kernel/mm/madvise.c",
			body: `
				if (!capable(CAP_SYS_NICE)) {
					ret = -EPERM;
					goto release_mm;
				}
			release_mm:
				mmput(mm);
				return ret;
			`,
			wantHook: "security_capable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			function := &FunctionInfo{
				Name:        test.function,
				DisplayName: test.function,
				File:        test.file,
				Body:        test.body,
				Frontend:    "clang-ast-cfg",
				CFGComplete: true,
			}
			gates := reviewedKernelFunctionLSMGates(function)
			if len(gates) != 1 || gates[0].hook != test.wantHook ||
				classifySignalAbortEffect(gates[0].effect) != "guaranteed" {
				t.Fatalf("reviewed gates = %#v", gates)
			}
		})
	}

	changed := &FunctionInfo{
		Name:        "__do_sys_process_madvise",
		DisplayName: "__do_sys_process_madvise",
		File:        "/kernel/mm/madvise.c",
		Body: `
			if (!capable(CAP_SYS_NICE))
				ret = -EPERM;
			return 0;
		`,
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	if gates := reviewedKernelFunctionLSMGates(changed); len(gates) != 0 {
		t.Fatalf("changed success semantics retained a contract: %#v", gates)
	}
	changed.File = "/kernel/drivers/example.c"
	changed.Body = `
		if (!capable(CAP_SYS_NICE)) {
			ret = -EPERM;
			goto release_mm;
		}
	release_mm:
		return ret;
	`
	if gates := reviewedKernelFunctionLSMGates(changed); len(gates) != 0 {
		t.Fatalf("contract escaped its reviewed source file: %#v", gates)
	}
}

func TestReviewedKernelSuccessGateDominatesUnknownDuplicateEffect(t *testing.T) {
	reviewed := LSMErrorEffect{
		Hook:              "security_file_alloc",
		BPFHook:           "file_alloc_security",
		HookKind:          "error-return",
		BlocksOperation:   "guaranteed",
		TerminatesSyscall: "guaranteed",
		ErrnoPropagation:  "normalized",
		FailureEncoding:   failureReturnErrno,
		ProofMethod:       reviewedKernelLSMGateProofMethod,
		LLVMVerification:  "not_available",
	}
	unknown := LSMErrorEffect{
		Hook:              reviewed.Hook,
		BPFHook:           reviewed.BPFHook,
		HookKind:          "error-return",
		BlocksOperation:   "unknown",
		TerminatesSyscall: "unknown",
		ErrnoPropagation:  "unknown",
		FailureEncoding:   failureReturnUnknown,
	}
	for _, merged := range []LSMErrorEffect{
		mergeLSMErrorEffects(reviewed, unknown),
		mergeLSMErrorEffects(unknown, reviewed),
	} {
		if !isCertifiedReviewedKernelLSMEffect(merged) {
			t.Fatalf("reviewed proof was degraded: %#v", merged)
		}
	}
}

func TestRecordReturnIsCompletedFunctionExecution(t *testing.T) {
	if !returnExpressionProvesSuccess(
		"record",
		"(kuid_t){ value }",
		"",
	) {
		t.Fatal("record-valued return was not treated as a completed call")
	}
	if returnExpressionProvesSuccess("record", "", "") {
		t.Fatal("missing record return expression was certified")
	}
}

func TestTypedUnsignedWideningProvesNonnegativeReturn(t *testing.T) {
	function := &FunctionInfo{
		ID:             "typed-widening",
		Name:           "typed_widening",
		DisplayName:    "typed_widening",
		ReturnType:     "long",
		ReturnTypeBits: 64,
		Body:           `int mask; return mask;`,
		CFGBlocks: []ClangCFGBlock{{
			ID:               1,
			ReturnExpression: "mask",
		}},
	}
	alternatives := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{
			ID: 2,
			ValueWrites: []ClangCFGValueWrite{{
				Target:           "mask",
				Expression:       "xchg(pointer, value)",
				Kind:             "assign",
				SourceTypeClass:  "unsigned_integer",
				SourceTypeBits:   16,
				TargetTypeClass:  "signed_integer",
				TargetTypeSigned: true,
				TargetTypeBits:   32,
			}},
		},
		nonEnforcingLSMAlternatives(),
	)
	if len(alternatives) != 1 {
		t.Fatalf("typed alternatives = %#v", alternatives)
	}
	outcome, ok := trackedCFGTypedReturnOutcome(
		function,
		"mask",
		alternatives[0].bypassValues,
	)
	if !ok ||
		returnOutcomeCompatibility(outcome, "nonnegative") !=
			"guaranteed" {
		t.Fatalf("typed return outcome = %#v, %v", outcome, ok)
	}
}

func TestClangNonnegativeExpressionFactProvesSignedReturn(t *testing.T) {
	function := &FunctionInfo{
		ID:             "typed-expression-range",
		ReturnType:     "long",
		ReturnTypeBits: 64,
		Body:           `int mask; return mask;`,
		CFGBlocks: []ClangCFGBlock{{
			ID:               1,
			ReturnExpression: "mask",
		}},
	}
	alternatives := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:                      "mask",
			Expression:                  "xchg(pointer, value)",
			Kind:                        "assign",
			SourceDefinitelyNonnegative: true,
			SourceTypeClass:             "signed_integer",
			SourceTypeBits:              32,
			TargetTypeClass:             "signed_integer",
			TargetTypeSigned:            true,
			TargetTypeBits:              32,
		}}},
		nonEnforcingLSMAlternatives(),
	)
	outcome, ok := trackedCFGTypedReturnOutcome(
		function,
		"mask",
		alternatives[0].bypassValues,
	)
	if !ok ||
		returnOutcomeCompatibility(outcome, "nonnegative") !=
			"guaranteed" {
		t.Fatalf("Clang nonnegative fact outcome = %#v, %v", outcome, ok)
	}
}

func TestKernelUserAccessReturnSuccessRequiresExpandedMacro(t *testing.T) {
	function := &FunctionInfo{
		ID:          "user-access",
		DisplayName: "user_access",
		ReturnType:  "int",
	}
	block := ClangCFGBlock{
		ID:                       1,
		ReturnExpression:         "__put_user(value, pointer)",
		ReturnExpressionExpanded: `({ int __ret_pu; asm("call __put_user_nocheck_4"); __ret_pu; })`,
	}
	witness := kernelUserAccessReturnSuccessWitness(
		function,
		block,
		"nonnegative",
	)
	if !witness.proven {
		t.Fatalf("user-access success witness = %#v", witness)
	}
	block.ReturnExpressionExpanded = "__put_user(value, pointer)"
	if witness := kernelUserAccessReturnSuccessWitness(
		function,
		block,
		"nonnegative",
	); witness.proven {
		t.Fatalf("unexpanded lookalike was certified: %#v", witness)
	}
	block.ReturnExpression = "custom_put_user(value, pointer)"
	block.ReturnExpressionExpanded = `({ int __ret_pu; asm("call __put_user_4"); __ret_pu; })`
	if witness := kernelUserAccessReturnSuccessWitness(
		function,
		block,
		"nonnegative",
	); witness.proven {
		t.Fatalf("lookalike macro was certified: %#v", witness)
	}
}

func TestTrackedKernelUserAccessWriteCanSucceedWithZero(t *testing.T) {
	function := &FunctionInfo{
		ID:          "tracked-user-access",
		DisplayName: "tracked_user_access",
		ReturnType:  "int",
		Body:        `int error; return error;`,
		CFGBlocks: []ClangCFGBlock{{
			ID:               1,
			ReturnExpression: "error",
		}},
	}
	alternatives := applyCFGValueWritesToAlternatives(
		function,
		ClangCFGBlock{ValueWrites: []ClangCFGValueWrite{{
			Target:             "error",
			Expression:         "put_user(value, pointer)",
			ExpressionExpanded: `({ int __ret_pu; asm("call __put_user_4"); __ret_pu; })`,
			Kind:               "assign",
			TargetTypeClass:    "signed_integer",
			TargetTypeSigned:   true,
			TargetTypeBits:     32,
		}}},
		nonEnforcingLSMAlternatives(),
	)
	witness := trackedKernelRuntimeSuccessWitness(
		function,
		function.CFGBlocks[0],
		"error",
		alternatives[0].bypassValues,
		nil,
		"nonnegative",
	)
	if !witness.proven {
		t.Fatalf("tracked user-access witness = %#v", witness)
	}
	if witness := trackedKernelRuntimeSuccessWitness(
		function,
		function.CFGBlocks[0],
		"error",
		alternatives[0].bypassValues,
		[]successPathConstraint{{
			functionID: function.ID,
			expression: "error < 0",
			required:   true,
			pathStable: true,
		}},
		"nonnegative",
	); witness.proven {
		t.Fatalf("zero-infeasible branch was certified: %#v", witness)
	}
}

func TestCFGBlockClonePreservesProofMetadata(t *testing.T) {
	original := []ClangCFGBlock{{
		ID:                           3,
		ReturnDefinitelyNonnegative:  true,
		ReturnDefinitelyValidPointer: true,
		Successors:                   []int{2, 1},
		SuccessorBranches:            []string{"true", "false"},
		SuccessSuccessors:            []int{2},
		SuccessSuccessorBranches:     []string{"true"},
		ValueWrites: []ClangCFGValueWrite{{
			Target:                       "result",
			Expression:                   "&object",
			SourceDefinitelyValidPointer: true,
		}},
		PointeeWrites: []ClangCFGPointeeWrite{{
			Parameter:                   "error",
			Expression:                  "0",
			Kind:                        "assign",
			SourceDefinitelyNonnegative: true,
		}},
	}}
	cloned := cloneCFGBlocks(original)
	if !cfgBlocksEqual(original, cloned) {
		t.Fatalf("cloned CFG blocks differ: %#v", cloned)
	}
	cloned[0].SuccessorBranches[0] = "false"
	cloned[0].PointeeWrites[0].Expression = "-EINVAL"
	if original[0].SuccessorBranches[0] != "true" ||
		original[0].PointeeWrites[0].Expression != "0" {
		t.Fatal("cloned CFG proof metadata aliases the source")
	}
	if cfgBlocksEqual(original, cloned) {
		t.Fatal("CFG equality ignored branch or pointee-write metadata")
	}
}

func TestClangNonnegativeReturnRequiresASTFact(t *testing.T) {
	function := &FunctionInfo{
		DisplayName: "count",
		ReturnType:  "int",
	}
	block := ClangCFGBlock{
		ID:                          7,
		ReturnExpression:            "count",
		ReturnDefinitelyNonnegative: true,
	}
	witness := clangNonnegativeReturnWitness(
		function,
		block,
		"nonnegative",
	)
	if !witness.proven ||
		witness.method != "clang_ast_nonnegative_return" {
		t.Fatalf("nonnegative return witness = %#v", witness)
	}
	if witness := clangNonnegativeReturnWitness(
		function,
		block,
		"positive",
	); witness.proven {
		t.Fatalf("nonnegative fact proved positivity: %#v", witness)
	}
	block.ReturnDefinitelyNonnegative = false
	if witness := clangNonnegativeReturnWitness(
		function,
		block,
		"nonnegative",
	); witness.proven {
		t.Fatalf("unverified range was certified: %#v", witness)
	}
}

func TestClangValidPointerReturnRequiresASTFact(t *testing.T) {
	function := &FunctionInfo{
		DisplayName: "container",
		ReturnType:  "pointer",
	}
	block := ClangCFGBlock{
		ID:                           4,
		ReturnExpression:             "&container->object",
		ReturnDefinitelyValidPointer: true,
	}
	witness := clangValidPointerReturnWitness(
		function,
		block,
		"nonnull_valid_pointer",
	)
	if !witness.proven ||
		witness.method != "clang_ast_valid_pointer_return" {
		t.Fatalf("valid address witness = %#v", witness)
	}
	block.ReturnDefinitelyValidPointer = false
	if witness := clangValidPointerReturnWitness(
		function,
		block,
		"nonnull_valid_pointer",
	); witness.proven {
		t.Fatalf("unverified pointer was certified: %#v", witness)
	}
}

func TestTrackedCFGValidPointerOutcome(t *testing.T) {
	function := &FunctionInfo{
		ReturnType: "pointer",
	}
	outcome, ok := trackedCFGTypedReturnOutcome(
		function,
		"result",
		map[string]cfgPathValue{
			"result": {
				typeClass:          "pointer",
				provenValidPointer: true,
			},
		},
	)
	if !ok || outcome.domain != returnDomainPointer ||
		outcome.mask != outcomePointerValue {
		t.Fatalf("valid pointer outcome = %#v, %v", outcome, ok)
	}
	if _, ok := trackedCFGTypedReturnOutcome(
		function,
		"result",
		map[string]cfgPathValue{
			"result": {typeClass: "pointer"},
		},
	); ok {
		t.Fatal("unverified tracked pointer was certified")
	}
}

func TestOutParameterFailureEliminatesFalseSuccessBypass(t *testing.T) {
	child := &FunctionInfo{
		ID:                "lookup",
		Name:              "lookup",
		DisplayName:       "lookup",
		ReturnType:        "pointer",
		ReturnTypeBits:    64,
		Parameters:        []string{"fd", "err"},
		Body:              `*err = -EBADF; if (valid) return &object; return NULL;`,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  3,
				Successors:          []int{2, 1},
				SuccessorBranches:   []string{"true", "false"},
				TerminatorCondition: "valid",
				PointeeWrites: []ClangCFGPointeeWrite{{
					Parameter:        "err",
					Expression:       "-EBADF",
					Kind:             "assign",
					SourceTypeClass:  "signed_integer",
					SourceTypeSigned: true,
					SourceTypeBits:   32,
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
			{
				ID:                       2,
				ReturnExpression:         "&object",
				ReturnExpressionExpanded: "&object",
			},
			{
				ID:                       1,
				ReturnExpression:         "NULL",
				ReturnExpressionExpanded: "NULL",
			},
		},
	}
	parent := &FunctionInfo{
		ID:             "caller",
		Name:           "caller",
		DisplayName:    "caller",
		ReturnType:     "long",
		ReturnTypeBits: 64,
		Body: `
			int err;
			void *result;
			result = lookup(fd, &err);
			if (!result)
				return err;
			return 0;
		`,
		CallSites: []ClangCallSite{{
			ID:             "callsite:1",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			BlockID:        3,
			Name:           "lookup",
			ResultVariable: "result",
			ReturnType:     "pointer",
			ReturnTypeBits: 64,
			Arguments:      []string{"fd", "&err"},
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       3,
				Successors:               []int{1, 2},
				SuccessorBranches:        []string{"true", "false"},
				SuccessSuccessors:        []int{1, 2},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "!result",
				CallSiteIDs:              []string{"callsite:1"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:          "result",
					Expression:      "lookup(fd, &err)",
					Kind:            "assign",
					CallSiteID:      "callsite:1",
					TargetTypeClass: "pointer",
					TargetTypeBits:  64,
				}},
			},
			{
				ID:                       1,
				ReturnExpression:         "err",
				ReturnExpressionExpanded: "err",
				PotentialSuccessExit:     true,
			},
			{
				ID:                       2,
				ReturnExpression:         "0",
				ReturnExpressionExpanded: "0",
				PotentialSuccessExit:     true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			parent.ID: parent,
			child.ID:  child,
		},
		globalIndex: map[string][]string{
			"lookup": {child.ID},
		},
	}
	alternatives := applyCFGValueWritesToAlternatives(
		parent,
		parent.CFGBlocks[0],
		nonEnforcingLSMAlternatives(),
	)
	if len(alternatives) != 1 {
		t.Fatalf("caller alternatives = %#v", alternatives)
	}
	alternatives[0].bypassConstraints = []successPathConstraint{{
		functionID: parent.ID,
		blockID:    3,
		expression: "!result",
		required:   true,
		pathStable: true,
	}}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		parent,
		parent.CFGBlocks[1],
		nil,
		alternatives,
	)
	if len(finalized) != 0 {
		t.Fatalf(
			"negative out-parameter path remained a success bypass: %#v",
			finalized,
		)
	}
}

func TestOutParameterProofRejectsPointerEscape(t *testing.T) {
	function := &FunctionInfo{
		Parameters: []string{"err"},
		Body:       `*err = -EINVAL; helper(err); return NULL;`,
		CFGBlocks: []ClangCFGBlock{{
			PointeeWrites: []ClangCFGPointeeWrite{{
				Parameter:  "err",
				Expression: "-EINVAL",
				Kind:       "assign",
			}},
		}},
	}
	if pointeeParameterWritesAreClosed(function, "err") {
		t.Fatal("escaped pointee parameter was treated as closed")
	}
}

func TestCFGSignalFailureFollowsAssignedGotoPath(t *testing.T) {
	function := &FunctionInfo{
		ID:                "prepare-wait",
		Name:              "prepare_wait",
		DisplayName:       "prepare_wait",
		ReturnType:        "long",
		ReturnTypeBits:    64,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          4,
		CFGExit:           0,
		CallSites: []ClangCallSite{{
			ID:         "callsite:1",
			Direct:     true,
			Reachable:  true,
			HasBlock:   true,
			BlockID:    4,
			Name:       "signal_pending_state",
			ReturnType: "int",
			Arguments:  []string{"state", "current"},
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  4,
				Successors:          []int{3, 2},
				SuccessorBranches:   []string{"true", "false"},
				TerminatorCondition: "signal_pending_state(state, current)",
			},
			{
				ID:                3,
				Successors:        []int{1},
				SuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "ret",
					Expression:       "-ERESTARTSYS",
					Kind:             "assign",
					SourceTypeClass:  "signed_integer",
					SourceTypeSigned: true,
					SourceTypeBits:   64,
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   64,
				}},
			},
			{
				ID:                2,
				Successors:        []int{1},
				SuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "ret",
					Expression:       "0",
					Kind:             "assign",
					SourceTypeClass:  "signed_integer",
					SourceTypeSigned: true,
					SourceTypeBits:   64,
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   64,
				}},
			},
			{
				ID:                       1,
				ReturnExpression:         "ret",
				ReturnExpressionExpanded: "ret",
			},
		},
	}
	effect := analyzeCFGSignalCheckFailureEffect(
		function,
		"signal_pending_state",
	)
	if classifySignalAbortEffect(effect) != "guaranteed" ||
		effect.failureEncoding != failureReturnErrno {
		t.Fatalf("CFG signal failure effect = %#v", effect)
	}
}

func TestCFGSignalFailureRejectsConditionalCheckpoint(t *testing.T) {
	function := &FunctionInfo{
		ID:          "conditional-wait",
		ReturnType:  "long",
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
		CFGEntry:    2,
		CFGExit:     0,
		CallSites: []ClangCallSite{{
			ID:         "callsite:1",
			Direct:     true,
			Reachable:  true,
			HasBlock:   true,
			BlockID:    2,
			Name:       "signal_pending",
			ReturnType: "int",
			Arguments:  []string{"current"},
		}},
		CFGBlocks: []ClangCFGBlock{{
			ID:                  2,
			Successors:          []int{1, 0},
			SuccessorBranches:   []string{"true", "false"},
			TerminatorCondition: "signal_pending(current) && retry",
		}, {
			ID:                       1,
			ReturnExpression:         "-EINTR",
			ReturnExpressionExpanded: "-EINTR",
		}},
	}
	if effect := analyzeCFGSignalCheckFailureEffect(
		function,
		"signal_pending",
	); classifySignalAbortEffect(effect) != "unknown" {
		t.Fatalf(
			"conditional signal checkpoint was certified: %#v",
			effect,
		)
	}
}

func TestCFGCallFailurePropagationPrunesSuccessBranch(t *testing.T) {
	function := &FunctionInfo{
		ID:             "cfg-call-failure",
		Name:           "cfg_call_failure",
		DisplayName:    "cfg_call_failure",
		ReturnType:     "int",
		ReturnTypeBits: 32,
		Frontend:       "clang-ast-cfg",
		CFGComplete:    true,
		CFGEntry:       3,
		CFGExit:        0,
		CallSites: []ClangCallSite{{
			ID:               "callsite:child",
			Direct:           true,
			Reachable:        true,
			HasBlock:         true,
			BlockID:          3,
			Name:             "child",
			ResultVariable:   "error",
			ReturnType:       "int",
			ReturnTypeClass:  "signed_integer",
			ReturnTypeSigned: true,
			ReturnTypeBits:   32,
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  3,
				Successors:          []int{2, 1},
				SuccessorBranches:   []string{"true", "false"},
				TerminatorCondition: "error < 0",
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:child",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
			{
				ID:                       2,
				ReturnExpression:         "error",
				ReturnExpressionExpanded: "error",
			},
			{
				ID:                       1,
				ReturnExpression:         "0",
				ReturnExpressionExpanded: "0",
			},
		},
	}
	effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	)
	if classifySignalAbortEffect(effect) != "guaranteed" ||
		effect.failureEncoding != failureReturnErrno {
		t.Fatalf("CFG call failure effect = %#v", effect)
	}
}

func TestOutcomeRequirementUnwrapsLikelyCondition(t *testing.T) {
	if got := outcomeRequirementFromCondition(
		"pointer",
		"likely(pointer)",
		"pointer",
		true,
	); got != "nonnull" {
		t.Fatalf("likely pointer requirement = %q, want nonnull", got)
	}
	if got := outcomeRequirementFromCondition(
		"int",
		"unlikely(error < 0)",
		"error",
		false,
	); got != "nonnegative" {
		t.Fatalf(
			"unlikely integer requirement = %q, want nonnegative",
			got,
		)
	}
}

func TestCFGCallFailureAllowsClosedPriorOutParameterEscape(t *testing.T) {
	outParameterChild := &FunctionInfo{
		ID:         "lookup",
		Name:       "lookup",
		Parameters: []string{"error"},
		Body:       `*error = -EBADF; return NULL;`,
		CFGBlocks: []ClangCFGBlock{{
			PointeeWrites: []ClangCFGPointeeWrite{{
				Parameter:  "error",
				Expression: "-EBADF",
				Kind:       "assign",
			}},
		}},
	}
	function := &FunctionInfo{
		ID:                  "cfg-closed-escape",
		Name:                "cfg_closed_escape",
		ReturnType:          "int",
		ReturnTypeBits:      32,
		Frontend:            "clang-ast-cfg",
		CFGComplete:         true,
		CFGEntry:            2,
		CFGExit:             0,
		CFGEscapedVariables: []string{"error"},
		Body: `
			lookup(&error);
			error = child();
			return error;
		`,
		CallSites: []ClangCallSite{
			{
				ID:        "callsite:lookup",
				Direct:    true,
				Reachable: true,
				HasBlock:  true,
				BlockID:   3,
				Name:      "lookup",
				Arguments: []string{"&error"},
			},
			{
				ID:               "callsite:child",
				Direct:           true,
				Reachable:        true,
				HasBlock:         true,
				BlockID:          2,
				Name:             "child",
				ResultVariable:   "error",
				ReturnType:       "int",
				ReturnTypeClass:  "signed_integer",
				ReturnTypeSigned: true,
				ReturnTypeBits:   32,
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       2,
				ReturnExpression:         "error",
				ReturnExpressionExpanded: "error",
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:child",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID:          function,
			outParameterChild.ID: outParameterChild,
		},
	}
	analyzer.rebuildFunctionIndexes()
	effect := analyzer.analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	)
	if classifySignalAbortEffect(effect) != "guaranteed" {
		t.Fatalf("closed prior out-parameter escape = %#v", effect)
	}
	outParameterChild.Body = `sink(error); *error = -EBADF; return NULL;`
	if effect := analyzer.analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	); classifySignalAbortEffect(effect) != "unknown" {
		t.Fatalf("open pointer escape was certified: %#v", effect)
	}
}

func TestCFGCallFailurePropagationClassifiesSuccessOverwrite(t *testing.T) {
	function := &FunctionInfo{
		ID:             "cfg-call-overwrite",
		Name:           "cfg_call_overwrite",
		ReturnType:     "int",
		ReturnTypeBits: 32,
		Frontend:       "clang-ast-cfg",
		CFGComplete:    true,
		CFGEntry:       2,
		CFGExit:        0,
		CallSites: []ClangCallSite{{
			ID:               "callsite:child",
			Direct:           true,
			Reachable:        true,
			HasBlock:         true,
			BlockID:          2,
			Name:             "child",
			ResultVariable:   "error",
			ReturnType:       "int",
			ReturnTypeClass:  "signed_integer",
			ReturnTypeSigned: true,
			ReturnTypeBits:   32,
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                2,
				Successors:        []int{1},
				SuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:child",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
			{
				ID:                       1,
				ReturnExpression:         "error",
				ReturnExpressionExpanded: "error",
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "0",
					Kind:             "assign",
					SourceTypeClass:  "signed_integer",
					SourceTypeSigned: true,
					SourceTypeBits:   32,
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
		},
	}
	if effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	); classifySignalAbortEffect(effect) != "not_effective" {
		t.Fatalf("success-overwritten failure effect = %#v", effect)
	}
}

func TestCFGCallFailurePropagationRecognizesAbsorbedFailure(t *testing.T) {
	function := &FunctionInfo{
		ID:                "wrapper",
		Name:              "wrapper",
		DisplayName:       "wrapper",
		ReturnType:        "signed_integer",
		ReturnTypeBits:    32,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          3,
		CFGExit:           0,
		CallSites: []ClangCallSite{{
			ID:               "callsite:1",
			Name:             "child",
			Direct:           true,
			Reachable:        true,
			HasBlock:         true,
			BlockID:          3,
			ResultVariable:   "error",
			ReturnType:       "signed_integer",
			ReturnTypeClass:  "signed_integer",
			ReturnTypeSigned: true,
			ReturnTypeBits:   32,
		}},
		CFGBlocks: []ClangCFGBlock{
			{ID: 0},
			{
				ID:                   1,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
				Successors:           []int{0},
			},
			{
				ID:                   2,
				ReturnExpression:     "1",
				PotentialSuccessExit: true,
				Successors:           []int{0},
			},
			{
				ID:                  3,
				TerminatorCondition: "error < 0",
				Successors:          []int{1, 2},
				SuccessorBranches:   []string{"true", "false"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:1",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
		},
	}
	effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	)
	if classifySignalAbortEffect(effect) != "not_effective" {
		t.Fatalf("absorbed failure effect = %#v", effect)
	}
}

func TestCFGCallFailurePropagationRejectsMixedAbsorption(t *testing.T) {
	function := &FunctionInfo{
		ID:                "wrapper",
		Name:              "wrapper",
		DisplayName:       "wrapper",
		ReturnType:        "signed_integer",
		ReturnTypeBits:    32,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          4,
		CFGExit:           0,
		CallSites: []ClangCallSite{{
			ID:               "callsite:1",
			Name:             "child",
			Direct:           true,
			Reachable:        true,
			HasBlock:         true,
			BlockID:          4,
			ResultVariable:   "error",
			ReturnType:       "signed_integer",
			ReturnTypeClass:  "signed_integer",
			ReturnTypeSigned: true,
			ReturnTypeBits:   32,
		}},
		CFGBlocks: []ClangCFGBlock{
			{ID: 0},
			{
				ID:                   1,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
				Successors:           []int{0},
			},
			{
				ID:               2,
				ReturnExpression: "error",
				FailureOnlyExit:  true,
				Successors:       []int{0},
			},
			{
				ID:                  3,
				TerminatorCondition: "condition",
				Successors:          []int{1, 2},
				SuccessorBranches:   []string{"true", "false"},
			},
			{
				ID:         4,
				Successors: []int{3},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:1",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
					TargetTypeBits:   32,
				}},
			},
		},
	}
	effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	)
	if classifySignalAbortEffect(effect) != "unknown" {
		t.Fatalf("mixed failure absorption was certified: %#v", effect)
	}
}

func TestCFGCallFailurePropagationHandlesErrorPointer(t *testing.T) {
	function := &FunctionInfo{
		ID:             "cfg-pointer-failure",
		Name:           "cfg_pointer_failure",
		ReturnType:     "int",
		ReturnTypeBits: 32,
		Frontend:       "clang-ast-cfg",
		CFGComplete:    true,
		CFGEntry:       3,
		CFGExit:        0,
		CallSites: []ClangCallSite{{
			ID:              "callsite:child",
			Direct:          true,
			Reachable:       true,
			HasBlock:        true,
			BlockID:         3,
			Name:            "child",
			ResultVariable:  "pointer",
			ReturnType:      "pointer",
			ReturnTypeClass: "pointer",
			ReturnTypeBits:  64,
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                  3,
				Successors:          []int{2, 1},
				SuccessorBranches:   []string{"true", "false"},
				TerminatorCondition: "IS_ERR(pointer)",
				ValueWrites: []ClangCFGValueWrite{{
					Target:          "pointer",
					Expression:      "child()",
					Kind:            "assign",
					CallSiteID:      "callsite:child",
					TargetTypeClass: "pointer",
					TargetTypeBits:  64,
				}},
			},
			{
				ID:                       2,
				ReturnExpression:         "PTR_ERR(pointer)",
				ReturnExpressionExpanded: "PTR_ERR(pointer)",
			},
			{
				ID:                       1,
				ReturnExpression:         "0",
				ReturnExpressionExpanded: "0",
			},
		},
	}
	effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"failure_err_ptr",
	)
	if classifySignalAbortEffect(effect) != "guaranteed" ||
		effect.failureEncoding != failureReturnErrno {
		t.Fatalf("error-pointer propagation = %#v", effect)
	}
}

func TestCFGCallFailurePropagationRejectsCycle(t *testing.T) {
	function := &FunctionInfo{
		ID:          "cfg-call-cycle",
		ReturnType:  "int",
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
		CFGEntry:    2,
		CFGExit:     0,
		CallSites: []ClangCallSite{{
			ID:               "callsite:child",
			Direct:           true,
			Reachable:        true,
			HasBlock:         true,
			BlockID:          2,
			Name:             "child",
			ResultVariable:   "error",
			ReturnType:       "int",
			ReturnTypeClass:  "signed_integer",
			ReturnTypeSigned: true,
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                2,
				Successors:        []int{1},
				SuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:           "error",
					Expression:       "child()",
					Kind:             "assign",
					CallSiteID:       "callsite:child",
					TargetTypeClass:  "signed_integer",
					TargetTypeSigned: true,
				}},
			},
			{
				ID:                1,
				Successors:        []int{1},
				SuccessorBranches: []string{"unconditional"},
			},
		},
	}
	if effect := (&Analyzer{}).analyzeCFGNamedCallFailureEffect(
		function,
		"child",
		"",
	); classifySignalAbortEffect(effect) != "unknown" {
		t.Fatalf("cyclic failure path was certified: %#v", effect)
	}
}

func TestMacroExpandedCallUsesCFGSuccessfulEdgeRequirement(t *testing.T) {
	caller := &FunctionInfo{
		ID:         "caller",
		Name:       "caller",
		ReturnType: "long",
		Body: `
			char *page = __getname();
			if (!page)
				return -ENOMEM;
			return 1;
		`,
		CFGBlocks: []ClangCFGBlock{{
			ID:                       4,
			Successors:               []int{3, 2},
			SuccessSuccessors:        []int{2},
			SuccessSuccessorBranches: []string{"false"},
			TerminatorCondition:      "!page",
			ValueWrites: []ClangCFGValueWrite{{
				Target:     "page",
				Expression: "__getname()",
				Kind:       "initialize",
				CallSiteID: "callsite:1",
			}},
		}},
	}
	callee := &FunctionInfo{
		Name:       "kmem_cache_alloc",
		ReturnType: "pointer",
	}
	site := &ClangCallSite{
		ID:             "callsite:1",
		Direct:         true,
		HasBlock:       true,
		BlockID:        4,
		Name:           "kmem_cache_alloc",
		ResultUse:      "assigned",
		ResultVariable: "page",
		MacroExpansion: true,
	}
	requirement := requiredCallReturnForSite(
		caller,
		callee,
		caller.Body,
		site.Name,
		site,
		"nonnegative",
	)
	if requirement != "nonnull" {
		t.Fatalf("macro-expanded call requirement = %q", requirement)
	}

	caller.CFGBlocks[0].SuccessSuccessors = []int{3, 2}
	caller.CFGBlocks[0].SuccessSuccessorBranches =
		[]string{"true", "false"}
	if requirement := cfgCallReturnRequirementOnSuccessfulEdge(
		caller,
		callee,
		site,
		"nonnegative",
	); requirement != "" {
		t.Fatalf("mixed successful branches yielded %q", requirement)
	}
}

func TestCFGSuccessfulEdgeRecoversNestedPointerAssignment(t *testing.T) {
	caller := &FunctionInfo{
		ID:         "caller",
		Name:       "caller",
		ReturnType: "long",
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       30,
				SuccessSuccessors:        []int{29, 28},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "!walk",
				CallSiteIDs:              []string{"callsite:1"},
				ValueWrites: []ClangCFGValueWrite{{
					Target: "walk",
					Expression: "walk->next = kmalloc(" +
						"size, GFP_KERNEL)",
					Kind: "assign",
				}},
			},
			{
				ID:                       29,
				SuccessSuccessors:        []int{27},
				SuccessSuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "error",
					Expression: "-ENOMEM",
					Kind:       "assign",
				}},
			},
			{
				ID:                   28,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
			{
				ID:                   27,
				ReturnExpression:     "error",
				PotentialSuccessExit: true,
			},
		},
	}
	callee := &FunctionInfo{
		Name:       "kmalloc",
		ReturnType: "pointer",
	}
	site := &ClangCallSite{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		HasBlock:   true,
		BlockID:    30,
		Name:       "kmalloc",
		ResultUse:  "assigned",
		ReturnType: "pointer",
		Arguments:  []string{"size", "GFP_KERNEL"},
	}
	caller.CallSites = []ClangCallSite{*site}

	if requirement := cfgCallReturnRequirementOnSuccessfulEdge(
		caller,
		callee,
		&caller.CallSites[0],
		"nonnegative",
	); requirement != "nonnull" {
		t.Fatalf(
			"nested pointer assignment requirement = %q, want nonnull",
			requirement,
		)
	}
}

func TestCFGSuccessfulEdgeRejectsUnsafeNestedAssignmentInference(
	t *testing.T,
) {
	baseCaller := FunctionInfo{
		ID:         "caller",
		Name:       "caller",
		ReturnType: "long",
		CFGBlocks: []ClangCFGBlock{{
			ID:                       30,
			SuccessSuccessors:        []int{28},
			SuccessSuccessorBranches: []string{"false"},
			TerminatorCondition:      "!walk",
			CallSiteIDs:              []string{"callsite:1"},
			ValueWrites: []ClangCFGValueWrite{{
				Target: "walk",
				Expression: "walk->next = kmalloc(" +
					"size, GFP_KERNEL)",
				Kind: "assign",
			}},
		}},
	}
	baseSite := ClangCallSite{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		HasBlock:   true,
		BlockID:    30,
		Name:       "kmalloc",
		ResultUse:  "assigned",
		ReturnType: "pointer",
		Arguments:  []string{"size", "GFP_KERNEL"},
	}
	tests := []struct {
		name   string
		mutate func(*FunctionInfo, *ClangCallSite, *FunctionInfo)
	}{
		{
			name: "transformed call",
			mutate: func(
				caller *FunctionInfo,
				_ *ClangCallSite,
				_ *FunctionInfo,
			) {
				caller.CFGBlocks[0].ValueWrites[0].Expression =
					"walk->next = transform(kmalloc(size, GFP_KERNEL))"
			},
		},
		{
			name: "ambiguous duplicate write",
			mutate: func(
				caller *FunctionInfo,
				_ *ClangCallSite,
				_ *FunctionInfo,
			) {
				caller.CFGBlocks[0].ValueWrites = append(
					caller.CFGBlocks[0].ValueWrites,
					caller.CFGBlocks[0].ValueWrites[0],
				)
			},
		},
		{
			name: "mixed successful branches",
			mutate: func(
				caller *FunctionInfo,
				_ *ClangCallSite,
				_ *FunctionInfo,
			) {
				caller.CFGBlocks[0].SuccessSuccessors =
					[]int{29, 28}
				caller.CFGBlocks[0].SuccessSuccessorBranches =
					[]string{"true", "false"}
			},
		},
		{
			name: "non pointer result",
			mutate: func(
				_ *FunctionInfo,
				site *ClangCallSite,
				callee *FunctionInfo,
			) {
				site.ReturnType = "int"
				callee.ReturnType = "int"
			},
		},
		{
			name: "mismatched arguments",
			mutate: func(
				_ *FunctionInfo,
				site *ClangCallSite,
				_ *FunctionInfo,
			) {
				site.Arguments = []string{"other", "GFP_KERNEL"}
			},
		},
		{
			name: "different member base",
			mutate: func(
				caller *FunctionInfo,
				_ *ClangCallSite,
				_ *FunctionInfo,
			) {
				caller.CFGBlocks[0].ValueWrites[0].Expression =
					"other->next = kmalloc(size, GFP_KERNEL)"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caller := baseCaller
			caller.CFGBlocks = append(
				[]ClangCFGBlock(nil),
				baseCaller.CFGBlocks...,
			)
			caller.CFGBlocks[0].ValueWrites = append(
				[]ClangCFGValueWrite(nil),
				baseCaller.CFGBlocks[0].ValueWrites...,
			)
			caller.CFGBlocks[0].SuccessSuccessors = append(
				[]int(nil),
				baseCaller.CFGBlocks[0].SuccessSuccessors...,
			)
			caller.CFGBlocks[0].SuccessSuccessorBranches = append(
				[]string(nil),
				baseCaller.CFGBlocks[0].SuccessSuccessorBranches...,
			)
			site := baseSite
			callee := FunctionInfo{
				Name:       "kmalloc",
				ReturnType: "pointer",
			}
			test.mutate(&caller, &site, &callee)
			caller.CallSites = []ClangCallSite{site}
			if requirement :=
				cfgCallReturnRequirementOnSuccessfulEdge(
					&caller,
					&callee,
					&caller.CallSites[0],
					"nonnegative",
				); requirement != "" {
				t.Fatalf(
					"unsafe nested assignment inferred %q",
					requirement,
				)
			}
		})
	}
}

func TestPKeySentinelFailureEdgeYieldsNonnegativeSuccess(
	t *testing.T,
) {
	caller := &FunctionInfo{
		ReturnType: "long",
		CFGBlocks: []ClangCFGBlock{{
			ID:                       4,
			SuccessSuccessors:        []int{2},
			SuccessSuccessorBranches: []string{"false"},
			TerminatorCondition:      "pkey == -1",
			ValueWrites: []ClangCFGValueWrite{{
				Target:     "pkey",
				Expression: "mm_pkey_alloc(mm)",
				CallSiteID: "callsite:1",
			}},
		}},
	}
	callee := &FunctionInfo{
		Name:       "mm_pkey_alloc",
		File:       "/kernel/arch/x86/include/asm/pkeys.h",
		ReturnType: "int",
	}
	site := &ClangCallSite{
		ID:             "callsite:1",
		Direct:         true,
		HasBlock:       true,
		BlockID:        4,
		ResultVariable: "pkey",
	}
	requirement := cfgCallReturnRequirementOnSuccessfulEdge(
		caller,
		callee,
		site,
		"nonnegative",
	)
	if requirement != "nonnegative" {
		t.Fatalf("pkey success requirement = %q", requirement)
	}

	callee.File = "/drivers/example.c"
	if requirement := cfgCallReturnRequirementOnSuccessfulEdge(
		caller,
		callee,
		site,
		"nonnegative",
	); requirement != "" {
		t.Fatalf("non-pkey sentinel yielded requirement %q", requirement)
	}
}

func TestTrackedSignedConstantComparisonIsPreserved(t *testing.T) {
	function := &FunctionInfo{
		CallSites: []ClangCallSite{{
			ID:             "callsite:1",
			Direct:         true,
			Name:           "child",
			ResultVariable: "result",
			ReturnType:     "int",
		}},
	}
	values := map[string]cfgPathValue{
		"result": {
			expression: "child()",
			callSiteID: "callsite:1",
		},
	}
	if !cfgBranchConstrainsTrackedCallValue(
		function,
		"result == -1",
		false,
		values,
	) {
		t.Fatal("signed sentinel comparison was not retained")
	}
	if cfgBranchConstrainsTrackedCallValue(
		function,
		"other == -1",
		false,
		values,
	) {
		t.Fatal("unrelated signed comparison was retained")
	}
}

func TestTrackedPKeySentinelSuccessSurvivesReturnAlias(t *testing.T) {
	caller := &FunctionInfo{
		ID:             "pkey-caller",
		Name:           "__do_sys_pkey_alloc",
		DisplayName:    "__do_sys_pkey_alloc",
		ReturnType:     "long",
		ReturnTypeBits: 64,
		CallSites: []ClangCallSite{{
			ID:             "callsite:1",
			Direct:         true,
			Reachable:      true,
			Name:           "mm_pkey_alloc",
			ResultVariable: "pkey",
			ReturnType:     "int",
		}},
	}
	child := &FunctionInfo{
		ID:          "pkey-child",
		Name:        "mm_pkey_alloc",
		DisplayName: "mm_pkey_alloc",
		File:        "/kernel/arch/x86/include/asm/pkeys.h",
		ReturnType:  "int",
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			caller.ID: caller,
			child.ID:  child,
		},
		nameIndex: map[string][]string{
			"mm_pkey_alloc": {child.ID},
		},
	}
	witness := analyzer.proveTrackedSentinelCallSuccess(
		caller,
		"ret",
		nil,
		[]successPathConstraint{{
			functionID: caller.ID,
			blockID:    3,
			expression: "pkey == -1",
			required:   false,
			pathStable: true,
		}},
		map[string]cfgPathValue{
			"ret": {
				expression: "pkey",
			},
			"pkey": {
				expression: "mm_pkey_alloc(mm)",
				callSiteID: "callsite:1",
			},
		},
		ClangCFGBlock{ID: 1},
	)
	if !witness.proven ||
		witness.method !=
			"kernel_minus_one_sentinel_success_contract" {
		t.Fatalf("tracked pkey sentinel witness = %#v", witness)
	}
}

func TestWiderSignedReturnPreservesUnsignedLocalNonnegative(t *testing.T) {
	function := &FunctionInfo{
		ReturnType:     "long",
		ReturnTypeBits: 64,
		Body: `
			unsigned len;
			return len;
		`,
	}
	outcome := returnOutcomeFromExpression(
		function,
		"len",
		nil,
		false,
		nil,
		"nonnegative",
	)
	if outcome.domain != returnDomainSigned ||
		outcome.mask != outcomeZero|outcomePositive {
		t.Fatalf("widened unsigned outcome = %#v", outcome)
	}

	function.ReturnType = "int"
	function.ReturnTypeBits = 32
	outcome = returnOutcomeFromExpression(
		function,
		"len",
		nil,
		false,
		nil,
		"nonnegative",
	)
	if outcome.mask != outcomeNegative|outcomeZero|outcomePositive {
		t.Fatalf("equal-width conversion was over-certified: %#v", outcome)
	}

	function.ReturnType = "long"
	function.ReturnTypeBits = 64
	function.Body = `
		unsigned len;
		{
			unsigned len;
			return len;
		}
	`
	outcome = returnOutcomeFromExpression(
		function,
		"len",
		nil,
		false,
		nil,
		"nonnegative",
	)
	if outcome.mask != outcomeNegative|outcomeZero|outcomePositive {
		t.Fatalf("shadowed unsigned local was certified: %#v", outcome)
	}
}

func TestDirectReturnedCallInheritsCallerRequirement(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "long",
		Body:        `return child();`,
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	parent.CallSites = []ClangCallSite{{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		Name:       "child",
		ResultUse:  "returned",
		ReturnType: "int",
	}}
	requirement := requiredCallReturnForSite(
		parent,
		child,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		"nonnegative",
	)
	if requirement != "nonnegative" {
		t.Fatalf(
			"direct-return requirement = %q, want nonnegative",
			requirement,
		)
	}
}

func TestDiscardedCallAcceptsAnyReturnedOutcome(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body:        `child(); return 0;`,
	}
	child := &FunctionInfo{
		ID:          "child",
		Name:        "child",
		DisplayName: "child",
		ReturnType:  "int",
	}
	parent.CallSites = []ClangCallSite{{
		ID:         "callsite:1",
		Direct:     true,
		Reachable:  true,
		Name:       "child",
		ResultUse:  "discarded",
		ReturnType: "int",
	}}
	requirement := requiredCallReturnForSite(
		parent,
		child,
		parent.Body,
		child.Name,
		&parent.CallSites[0],
		"",
	)
	if requirement != "any" {
		t.Fatalf("discarded-call requirement = %q, want any", requirement)
	}
}

func TestClosedIndirectCallUsesIntegerSuccessGuard(t *testing.T) {
	parent := &FunctionInfo{
		ID:          "parent",
		Name:        "parent",
		DisplayName: "parent",
		ReturnType:  "int",
		Body: `
			int ret;
			ret = ops->run();
			if (ret < 0)
				return ret;
			return 0;
		`,
	}
	child := &FunctionInfo{
		ID:          "target",
		Name:        "target",
		DisplayName: "target",
		ReturnType:  "int",
	}
	site := ClangCallSite{
		ID:         "callsite:1",
		Direct:     false,
		Reachable:  true,
		Expression: "ops->run",
		ResultUse:  "assigned",
		ReturnType: "int",
	}
	requirement := requiredIndirectCallReturnForSite(
		parent,
		child,
		parent.Body,
		&site,
		"",
	)
	if requirement != "nonnegative" {
		t.Fatalf(
			"indirect call requirement = %q, want nonnegative",
			requirement,
		)
	}
}

func TestEffectFreeFastPathProvesAllocatorLikeNonNullReturn(t *testing.T) {
	function := &FunctionInfo{
		ID:          "alloc_fixture",
		Name:        "alloc_fixture",
		DisplayName: "alloc_fixture",
		ReturnType:  "pointer",
		Body: `
			void *object;
			if (object != NULL)
				return object;
			if (fatal_signal_pending(current))
				return NULL;
			return NULL;
		`,
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           3,
		CallSites: []ClangCallSite{{
			ID:         "callsite:1",
			Direct:     true,
			Reachable:  true,
			HasBlock:   true,
			BlockID:    2,
			Name:       "fatal_signal_pending",
			ResultUse:  "condition",
			ReturnType: "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				SuccessSuccessors:        []int{1, 2},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "object != NULL",
			},
			{
				ID:                   1,
				ReturnExpression:     "object",
				PotentialSuccessExit: true,
			},
			{
				ID:                   2,
				CallSiteIDs:          []string{"callsite:1"},
				SignalChecks:         []string{"fatal_signal_pending"},
				ReturnExpression:     "NULL",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		nameIndex:              make(map[string][]string),
		globalIndex:            make(map[string][]string),
		successWitnessCache:    make(map[string]functionSuccessWitness),
		effectFreeSuccessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveEffectFreeSuccessfulExecution(
		function.ID,
		map[string]string{
			contextReturnRequirementKey: "nonnull",
		},
		nil,
		"sigkill",
		make(map[string]bool),
	)
	if !witness.proven ||
		witness.method !=
			"cfg_effect_free_fast_success_path+"+
				"cfg_branch_constrained_success_return" {
		t.Fatalf("effect-free fast-path witness = %#v", witness)
	}
}

func TestSignalCheckpointRecognizesNullFailureEncoding(t *testing.T) {
	function := &FunctionInfo{
		Name:       "allocator",
		ReturnType: "pointer",
	}
	body := `{
		if (fatal_signal_pending(current))
			return NULL;
		return object;
	}`
	sites := findNamedCallSites(body, "fatal_signal_pending")
	if len(sites) != 1 {
		t.Fatalf("signal sites = %#v", sites)
	}
	effect := analyzeSignalCheckLocalEffectForFunction(
		function,
		body,
		"fatal_signal_pending",
		&sites[0],
	)
	if classifySignalAbortEffect(effect) != "guaranteed" ||
		effect.failureEncoding != failureReturnNull {
		t.Fatalf("null signal failure effect = %#v", effect)
	}
}

func TestSignalCheckpointRecognizesConditionalNullFailure(t *testing.T) {
	function := &FunctionInfo{
		Name:       "allocator",
		ReturnType: "pointer",
	}
	body := `{
		if (fatal_signal_pending(current) && reclaiming)
			return NULL;
		return object;
	}`
	sites := findNamedCallSites(body, "fatal_signal_pending")
	effect := analyzeSignalCheckLocalEffectForFunction(
		function,
		body,
		"fatal_signal_pending",
		&sites[0],
	)
	if classifySignalAbortEffect(effect) != "conditional" ||
		effect.failureEncoding != failureReturnNull {
		t.Fatalf("conditional null signal effect = %#v", effect)
	}
}

func TestSignalCheckpointRejectsNestedControlFlowBeforeNullFailure(t *testing.T) {
	function := &FunctionInfo{
		Name:       "allocator",
		ReturnType: "pointer",
	}
	body := `{
		if (fatal_signal_pending(current)) {
			if (retry)
				goto out;
			return NULL;
		}
		return object;
	out:
		return object;
	}`
	sites := findNamedCallSites(body, "fatal_signal_pending")
	if len(sites) != 1 {
		t.Fatalf("signal sites = %#v", sites)
	}
	effect := analyzeSignalCheckLocalEffectForFunction(
		function,
		body,
		"fatal_signal_pending",
		&sites[0],
	)
	if classifySignalAbortEffect(effect) != "unknown" {
		t.Fatalf("nested signal failure effect = %#v, want unknown", effect)
	}
}

func TestClosedSourceAbsenceNeedsSuccessfulReturnWitness(t *testing.T) {
	function := &FunctionInfo{
		ID:                "source-free",
		Name:              "source_free",
		DisplayName:       "source_free",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "err",
			PotentialSuccessExit: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		lsmCoverageCache:      make(map[string]lsmCoverageResult),
		successWitnessCache:   make(map[string]functionSuccessWitness),
		lsmEffectSourceCache:  map[string]effectSourceState{function.ID: effectSourceNone},
		lsmEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionLSMCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "uncertain" {
		t.Fatalf("variable-return source-free coverage = %q, want uncertain", coverage.state)
	}

	function.CFGBlocks[0].ReturnExpression = "0"
	analyzer.lsmCoverageCache = make(map[string]lsmCoverageResult)
	analyzer.successWitnessCache = make(map[string]functionSuccessWitness)
	coverage = analyzer.analyzeFunctionLSMCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("explicit-success source-free coverage = %q, want non_enforcing", coverage.state)
	}
}

func TestSIGKILLCoverageFindsSuccessPathBypass(t *testing.T) {
	function := signalCoverageBranchFixture()
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:   make(map[string]signalCoverageResult),
		sigEffectSourceCache:  map[string]effectSourceState{function.ID: effectSourcePossible},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want non_enforcing", coverage.state)
	}
	if len(coverage.bypassProofPath) == 0 {
		t.Fatal("expected a certified bypass proof path")
	}
	if got := coverage.bypassProofPath[len(coverage.bypassProofPath)-1]; got !=
		"signal_branch#cfg-block-2" {
		t.Fatalf("bypass terminus = %q, want CFG success-exit witness", got)
	}
}

func TestSIGKILLNFirstSkipsExpensiveSwitchSibling(t *testing.T) {
	expensive := &FunctionInfo{
		ID:          "expensive",
		Name:        "expensive",
		DisplayName: "expensive",
		ReturnType:  "int",
	}
	function := &FunctionInfo{
		ID:                "switch-root",
		Name:              "switch_root",
		DisplayName:       "switch_root",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           4,
		Body: `{
			int ret;
			switch (cmd) {
			case 1:
				ret = expensive();
				break;
			case 2:
				ret = 0;
				break;
			}
			return ret;
		}`,
		TypedCallees: map[string][]string{
			"expensive": {expensive.ID},
		},
		CallSites: []ClangCallSite{{
			ID:             "callsite:expensive",
			Direct:         true,
			Reachable:      true,
			BlockID:        1,
			HasBlock:       true,
			Name:           "expensive",
			ResultUse:      "assigned",
			ResultVariable: "ret",
			ReturnType:     "int",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				SuccessSuccessors:        []int{1, 2},
				SuccessSuccessorBranches: []string{"unconditional", "unconditional"},
			},
			{
				ID:                       1,
				Calls:                    []string{"expensive"},
				CallSiteIDs:              []string{"callsite:expensive"},
				SuccessSuccessors:        []int{3},
				SuccessSuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "ret",
					Kind:       "assign",
					Expression: "expensive()",
					CallSiteID: "callsite:expensive",
				}},
			},
			{
				ID:                       2,
				SuccessSuccessors:        []int{3},
				SuccessSuccessorBranches: []string{"unconditional"},
				ValueWrites: []ClangCFGValueWrite{{
					Target:     "ret",
					Kind:       "assign",
					Expression: "0",
				}},
			},
			{
				ID:                   3,
				ReturnExpression:     "ret",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID:  function,
			expensive.ID: expensive,
		},
		signalCoverageCache: make(map[string]signalCoverageResult),
		successWitnessCache: make(map[string]functionSuccessWitness),
		effectFreeSuccessCache: make(
			map[string]functionSuccessWitness,
		),
		sigEffectSourceCache: map[string]effectSourceState{
			function.ID:  effectSourcePossible,
			expensive.ID: effectSourcePossible,
		},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want non_enforcing", coverage.state)
	}
	if _, analyzed := analyzer.signalCoverageCache[expensive.ID]; analyzed {
		t.Fatal("expensive switch sibling was analyzed before the certified N exit")
	}
}

func TestLSMEFirstSkipsExpensiveBPFDescendant(t *testing.T) {
	expensive := &FunctionInfo{
		ID:          "bpf-check",
		Name:        "bpf_check",
		DisplayName: "bpf_check",
		ReturnType:  "int",
	}
	function := &FunctionInfo{
		ID:                "sys-bpf",
		Name:              "__sys_bpf",
		DisplayName:       "__sys_bpf",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           3,
		Body: `{
			int err;
			err = security_bpf(cmd, &attr, size);
			if (err < 0)
				return err;
			err = bpf_check();
			return err;
		}`,
		TypedCallees: map[string][]string{
			"bpf_check": {expensive.ID},
		},
		CallSites: []ClangCallSite{
			{
				ID:             "callsite:security-bpf",
				Direct:         true,
				Reachable:      true,
				BlockID:        0,
				HasBlock:       true,
				Name:           "security_bpf",
				ResultUse:      "assigned",
				ResultVariable: "err",
				ReturnType:     "int",
			},
			{
				ID:             "callsite:bpf-check",
				Direct:         true,
				Reachable:      true,
				BlockID:        1,
				HasBlock:       true,
				Name:           "bpf_check",
				ResultUse:      "assigned",
				ResultVariable: "err",
				ReturnType:     "int",
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				CallSiteIDs:              []string{"callsite:security-bpf"},
				LSMHooks:                 []string{"security_bpf"},
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                       1,
				Calls:                    []string{"bpf_check"},
				CallSiteIDs:              []string{"callsite:bpf-check"},
				SuccessSuccessors:        []int{2},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                   2,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID:  function,
			expensive.ID: expensive,
		},
		lsmCoverageCache: make(map[string]lsmCoverageResult),
		successWitnessCache: make(
			map[string]functionSuccessWitness,
		),
		effectFreeSuccessCache: make(
			map[string]functionSuccessWitness,
		),
		lsmEffectSourceCache: map[string]effectSourceState{
			function.ID:  effectSourcePossible,
			expensive.ID: effectSourcePossible,
		},
		lsmEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionLSMCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "enforcing" {
		t.Fatalf("coverage = %q, want enforcing", coverage.state)
	}
	for key := range analyzer.lsmCoverageCache {
		if strings.HasPrefix(key, expensive.ID) {
			t.Fatal("bpf_check was analyzed after security_bpf certified E")
		}
	}
}

func TestSIGKILLEFirstSkipsExpensiveDescendant(t *testing.T) {
	expensive := &FunctionInfo{
		ID:          "signal-expensive",
		Name:        "signal_expensive",
		DisplayName: "signal_expensive",
		ReturnType:  "int",
	}
	function := &FunctionInfo{
		ID:                "signal-common-check",
		Name:              "signal_common_check",
		DisplayName:       "signal_common_check",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           3,
		Body: `{
			if (fatal_signal_pending(current))
				return -ERESTARTSYS;
			return signal_expensive();
		}`,
		DirectSigChecks: []string{"fatal_signal_pending"},
		TypedCallees: map[string][]string{
			"signal_expensive": {expensive.ID},
		},
		CallSites: []ClangCallSite{
			{
				ID:        "callsite:fatal-signal",
				Direct:    true,
				Reachable: true,
				BlockID:   0,
				HasBlock:  true,
				Name:      "fatal_signal_pending",
				Arguments: []string{"current"},
			},
			{
				ID:         "callsite:signal-expensive",
				Direct:     true,
				Reachable:  true,
				BlockID:    1,
				HasBlock:   true,
				Name:       "signal_expensive",
				ResultUse:  "returned",
				ReturnType: "int",
			},
		},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				CallSiteIDs:              []string{"callsite:fatal-signal"},
				SignalChecks:             []string{"fatal_signal_pending"},
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                       1,
				Calls:                    []string{"signal_expensive"},
				CallSiteIDs:              []string{"callsite:signal-expensive"},
				SuccessSuccessors:        []int{2},
				SuccessSuccessorBranches: []string{"unconditional"},
			},
			{
				ID:                   2,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID:  function,
			expensive.ID: expensive,
		},
		signalCoverageCache: make(map[string]signalCoverageResult),
		successWitnessCache: make(
			map[string]functionSuccessWitness,
		),
		effectFreeSuccessCache: make(
			map[string]functionSuccessWitness,
		),
		sigEffectSourceCache: map[string]effectSourceState{
			function.ID:  effectSourcePossible,
			expensive.ID: effectSourcePossible,
		},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "enforcing" {
		t.Fatalf("coverage = %q, want enforcing", coverage.state)
	}
	for key := range analyzer.signalCoverageCache {
		if strings.HasPrefix(key, expensive.ID) {
			t.Fatal("signal descendant was analyzed after checkpoint certified E")
		}
	}
}

func TestSIGKILLCoveragePrunesConstantFalseBranch(t *testing.T) {
	function := signalCoverageBranchFixture()
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:   make(map[string]signalCoverageResult),
		sigEffectSourceCache:  map[string]effectSourceState{function.ID: effectSourcePossible},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		map[string]string{"take_check": "1"},
		nil,
		make(map[string]bool),
	)
	if coverage.state != "enforcing" {
		t.Fatalf("constant-pruned coverage = %q, want enforcing", coverage.state)
	}
}

func TestSIGKILLUnprovenMergedReturnIsNotCertifiedBypass(t *testing.T) {
	function := signalCoverageBranchFixture()
	function.Body = `{
		int err = -EBADF;
		if (take_check) {
			if (fatal_signal_pending(current))
				return -ERESTARTSYS;
			err = 0;
		}
		return err;
	}`
	function.CFGBlocks[2].ReturnExpression = "err"
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:   make(map[string]signalCoverageResult),
		successWitnessCache:   make(map[string]functionSuccessWitness),
		sigEffectSourceCache:  map[string]effectSourceState{function.ID: effectSourcePossible},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "uncertain" {
		t.Fatalf("coverage = %q, want uncertain", coverage.state)
	}
	if len(coverage.bypassProofPath) != 0 {
		t.Fatalf("unexpected certified bypass = %#v", coverage.bypassProofPath)
	}
	if len(coverage.unprovenBypassPath) == 0 {
		t.Fatal("expected an unproven bypass diagnostic")
	}
	if !proofEdgesContainKind(
		coverage.unresolved,
		"successful_execution_unproven",
	) {
		t.Fatalf("unresolved edges = %#v, want successful_execution_unproven", coverage.unresolved)
	}
}

func TestSIGKILLCoverageCertifiesBranchConstrainedSuccessBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:                "branch-constrained-success",
		Name:              "branch_constrained_success",
		DisplayName:       "branch_constrained_success",
		ReturnType:        "int",
		Parameters:        []string{"take_check"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           4,
		Body: `{
			int ret = do_work();
			if (ret < 0)
				goto out;
			if (take_check) {
				if (fatal_signal_pending(current))
					return -ERESTARTSYS;
			}
		out:
			return ret;
		}`,
		DirectSigChecks: []string{"fatal_signal_pending"},
		CallSites: []ClangCallSite{{
			ID:        "signal-site",
			Direct:    true,
			Reachable: true,
			BlockID:   2,
			HasBlock:  true,
			Name:      "fatal_signal_pending",
			Arguments: []string{"current"},
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				SuccessSuccessors:        []int{1},
				SuccessSuccessorBranches: []string{"false"},
				TerminatorCondition:      "ret < 0",
			},
			{
				ID:                       1,
				SuccessSuccessors:        []int{2, 3},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "take_check",
			},
			{
				ID:                       2,
				SuccessSuccessors:        []int{3},
				SuccessSuccessorBranches: []string{"unconditional"},
				CallSiteIDs:              []string{"signal-site"},
				SignalChecks:             []string{"fatal_signal_pending"},
			},
			{
				ID:                   3,
				ReturnExpression:     "ret",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:   make(map[string]signalCoverageResult),
		successWitnessCache:   make(map[string]functionSuccessWitness),
		sigEffectSourceCache:  map[string]effectSourceState{function.ID: effectSourcePossible},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want non_enforcing: %#v", coverage.state, coverage)
	}
	if coverage.bypassProofMethod !=
		"cfg_effect_free_fast_success_path+"+
			"cfg_branch_constrained_success_return" {
		t.Fatalf(
			"bypass method = %q, want effect-free CFG branch proof",
			coverage.bypassProofMethod,
		)
	}
}

func TestCFGSuccessConstraintRejectsReturnVariableOverwrite(t *testing.T) {
	function := &FunctionInfo{
		ID:          "overwritten-return",
		Name:        "overwritten_return",
		DisplayName: "overwritten_return",
		ReturnType:  "int",
		Body: `{
			int ret = do_work();
			if (ret >= 0)
				ret = -EIO;
			return ret;
		}`,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "ret",
			PotentialSuccessExit: true,
		}},
	}
	constraint := successPathConstraint{
		functionID: function.ID,
		blockID:    0,
		expression: "ret >= 0",
		required:   true,
	}
	if returnExpressionProvesSuccessOnCFGPath(
		function,
		"ret",
		"",
		[]successPathConstraint{constraint},
	) {
		t.Fatal("overwritten return variable must not be certified successful")
	}
}

func TestSuccessConstraintDoesNotCertifyEffectDerivedBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:          "effect-derived",
		Name:        "effect_derived",
		DisplayName: "effect_derived",
		ReturnType:  "int",
		Body: `{
			int ret = do_work();
			if (ret >= 0)
				record_success();
			return ret;
		}`,
	}
	block := ClangCFGBlock{
		ID:                   2,
		ReturnExpression:     "ret",
		PotentialSuccessExit: true,
	}
	constraint := successPathConstraint{
		functionID: function.ID,
		blockID:    1,
		expression: "ret >= 0",
		required:   true,
	}
	analyzer := &Analyzer{
		functions:           map[string]*FunctionInfo{function.ID: function},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassPath:          []string{function.DisplayName},
			bypassConstraints:   []successPathConstraint{constraint},
			bypassDerivedEffect: true,
		}},
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"uncertain" {
		t.Fatalf("effect-derived bypass = %q, want uncertain", got)
	}
}

func TestProvenCallOutcomeCertifiesEffectDerivedBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:          "effect-derived-proven-call",
		Name:        "effect_derived_proven_call",
		DisplayName: "effect_derived_proven_call",
		ReturnType:  "int",
		Body: `{
			int ret = do_work();
			return ret;
		}`,
		CallSites: []ClangCallSite{{
			ID:             "work-call",
			Direct:         true,
			Reachable:      true,
			HasBlock:       true,
			Name:           "do_work",
			ResultVariable: "ret",
			ReturnType:     "int",
		}},
	}
	block := ClangCFGBlock{
		ID:                   2,
		ReturnExpression:     "ret",
		PotentialSuccessExit: true,
	}
	analyzer := &Analyzer{
		functions:           map[string]*FunctionInfo{function.ID: function},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	finalized := analyzer.finalizeSuccessExitAlternatives(
		function,
		block,
		nil,
		[]lsmPathAlternative{{
			bypassPath:          []string{function.DisplayName},
			bypassDerivedEffect: true,
			bypassSuccessfulCalls: []successfulCallConstraint{{
				functionID:          function.ID,
				callSiteID:          "work-call",
				callee:              "do_work",
				resultVariable:      "ret",
				returnType:          "int",
				requirement:         "zero",
				provenCalleeSuccess: true,
				method:              "child_return_outcome",
			}},
		}},
	)
	if got := classifySuccessExitLSMAlternatives(finalized); got !=
		"non_enforcing" {
		t.Fatalf("proven child outcome bypass = %q, want non_enforcing", got)
	}
}

func proofEdgesContainKind(edges []UnresolvedProofEdge, kind string) bool {
	for _, edge := range edges {
		if edge.Kind == kind {
			return true
		}
	}
	return false
}

func TestFrontendCacheRoundTripPreservesConfiguredGraph(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "frontend.gob.gz")
	function := &FunctionInfo{
		ID:                      "fixture",
		Name:                    "fixture",
		DisplayName:             "fixture",
		ReturnType:              "int",
		File:                    "/kernel/fs/fixture.c",
		TranslationUnits:        []string{"/kernel/fs/fixture.c"},
		Frontend:                "clang-ast-cfg",
		CFGComplete:             true,
		CFGHasSuccessExit:       true,
		CFGEntry:                0,
		CFGExit:                 2,
		Body:                    "{ return 0; }",
		DirectCallees:           []string{"child"},
		LSMEffectSourceState:    "possible",
		SIGEffectSourceState:    "unknown",
		LSMEffectUnknownWitness: "stale",
		CFGBlocks: []ClangCFGBlock{{
			ID:                   1,
			ReturnExpression:     "0",
			PotentialSuccessExit: true,
		}},
		LLVMCallFacts: []LLVMCallFact{{
			Kind:         "call",
			Callee:       "child",
			Function:     "fixture",
			Verification: "verified",
		}},
	}
	source := &Analyzer{
		cfg: Config{FrontendCache: cachePath},
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		structMembers: map[string][]string{
			"socket.ops": {"proto_ops"},
		},
		memberAliases: map[string][][]string{
			"alias": {{"socket", "ops"}},
		},
		operationTargets: map[string][]OperationTarget{
			"proto_ops.bind": {{
				StructType: "proto_ops",
				Field:      "bind",
				Function:   "inet_bind",
			}},
		},
		operationLinks: map[string][]string{
			"socket.ops": {"proto_ops"},
		},
		operationTables: map[string]*OperationTableInfo{
			"inet_ops": {
				StructType:   "proto_ops",
				Table:        "inet_ops",
				Const:        true,
				Complete:     true,
				FieldTargets: map[string]string{"bind": "inet_bind"},
			},
		},
		operationTablesByName: map[string][]string{
			"inet_ops": {"inet_ops"},
		},
		llvmFailures:     []string{"fixture warning"},
		lsmWrapperHooks:  map[string]string{"security_socket_bind": "socket_bind"},
		lsmHookNames:     map[string]bool{"socket_bind": true},
		lsmMetadataBuilt: true,
	}
	if err := source.saveFrontendCache("fixture-fingerprint"); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	target := &Analyzer{
		cfg: Config{FrontendCache: cachePath},
	}
	hit, err := target.loadFrontendCache("fixture-fingerprint")
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if !hit {
		t.Fatal("expected frontend cache hit")
	}
	loaded := target.functions["fixture"]
	if loaded == nil {
		t.Fatal("cached function is missing")
	}
	if loaded.Body != function.Body ||
		loaded.CFGBlocks[0].ReturnExpression != "0" ||
		len(loaded.LLVMCallFacts) != 1 {
		t.Fatalf("cached function lost analysis state: %#v", loaded)
	}
	if loaded.LSMEffectSourceState != "" ||
		loaded.SIGEffectSourceState != "" ||
		loaded.LSMEffectUnknownWitness != "" {
		t.Fatalf("stale report state survived cache load: %#v", loaded)
	}
	if target.lsmWrapperHooks["security_socket_bind"] != "socket_bind" {
		t.Fatalf("LSM metadata was not restored: %#v", target.lsmWrapperHooks)
	}
	if len(target.operationTargets["proto_ops.bind"]) != 1 {
		t.Fatalf("operation targets were not restored: %#v", target.operationTargets)
	}
	if target.frontendCacheStatus != "hit" {
		t.Fatalf("cache status = %q, want hit", target.frontendCacheStatus)
	}
}

func TestFrontendCacheAcceptsValidatedLegacyFingerprint(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "frontend.gob.gz")
	function := &FunctionInfo{
		ID:          "fixture",
		Name:        "fixture",
		DisplayName: "fixture",
	}
	source := &Analyzer{
		cfg:              Config{FrontendCache: cachePath},
		functions:        map[string]*FunctionInfo{function.ID: function},
		lsmMetadataBuilt: true,
	}
	if err := source.saveFrontendCache("legacy-fingerprint"); err != nil {
		t.Fatalf("save legacy cache: %v", err)
	}

	loaded := &Analyzer{
		cfg:                     Config{FrontendCache: cachePath},
		frontendCacheLegacyHash: "legacy-fingerprint",
	}
	hit, err := loaded.loadFrontendCache("current-fingerprint")
	if err != nil {
		t.Fatalf("load legacy cache: %v", err)
	}
	if !hit || loaded.frontendCacheStatus != "hit_legacy" {
		t.Fatalf(
			"legacy cache hit=%t status=%q, want hit_legacy",
			hit,
			loaded.frontendCacheStatus,
		)
	}
}

func TestFrontendCacheFingerprintTracksKernelHeaders(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "fs", "fixture.c")
	headerPath := filepath.Join(root, "include", "fixture.h")
	compileDB := filepath.Join(root, "compile_commands.json")
	for _, path := range []string{sourcePath, headerPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(sourcePath, []byte("int fixture(void) { return VALUE; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headerPath, []byte("#define VALUE 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compileDB, []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	analyzer := &Analyzer{
		cfg: Config{
			KernelRoot: root,
			CompileDB:  compileDB,
			Frontend:   "legacy",
			ScanAll:    true,
		},
		compileUnits: map[string]CompileCommand{
			sourcePath: {
				Directory: root,
				File:      sourcePath,
				Arguments: []string{"/bin/true", "-c", sourcePath},
			},
		},
	}
	before, err := analyzer.frontendCacheFingerprint()
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	if err := os.WriteFile(headerPath, []byte("#define VALUE 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := analyzer.frontendCacheFingerprint()
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if before == after {
		t.Fatal("header content change did not invalidate frontend cache")
	}
}

func signalCoverageBranchFixture() *FunctionInfo {
	return &FunctionInfo{
		ID:                "signal-branch",
		Name:              "signal_branch",
		DisplayName:       "signal_branch",
		ReturnType:        "int",
		Parameters:        []string{"take_check"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           3,
		Body: `{
			if (take_check) {
				if (fatal_signal_pending(current))
					return -ERESTARTSYS;
			}
			return 0;
		}`,
		DirectSigChecks: []string{"fatal_signal_pending"},
		CallSites: []ClangCallSite{{
			ID:        "signal-site",
			Direct:    true,
			Reachable: true,
			BlockID:   1,
			HasBlock:  true,
			Name:      "fatal_signal_pending",
			Arguments: []string{"current"},
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				SuccessSuccessors:        []int{1, 2},
				SuccessSuccessorBranches: []string{"true", "false"},
				TerminatorCondition:      "take_check",
			},
			{
				ID:                       1,
				SuccessSuccessors:        []int{2},
				SuccessSuccessorBranches: []string{"unconditional"},
				CallSiteIDs:              []string{"signal-site"},
				SignalChecks:             []string{"fatal_signal_pending"},
			},
			{
				ID:                   2,
				ReturnExpression:     "0",
				PotentialSuccessExit: true,
			},
		},
	}
}

func TestSIGKILLRootCoverageUsesEffectFreeSuccessWitness(t *testing.T) {
	function := signalCoverageBranchFixture()
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:    make(map[string]signalCoverageResult),
		successWitnessCache:    make(map[string]functionSuccessWitness),
		effectFreeSuccessCache: make(map[string]functionSuccessWitness),
		sigEffectSourceCache: map[string]effectSourceState{
			function.ID: effectSourcePossible,
		},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want certified bypass", coverage.state)
	}
	if !containsString(
		coverage.proofMethods,
		"cfg_effect_free_success_witness",
	) {
		t.Fatalf("proof methods = %#v, want effect-free witness", coverage.proofMethods)
	}
	if len(coverage.bypassProofPath) == 0 {
		t.Fatal("effect-free bypass proof path is missing")
	}
}

func TestSIGKILLRootCoverageUsesLLVMAllReturnSummary(t *testing.T) {
	function := &FunctionInfo{
		ID:                "llvm-return-summary",
		Name:              "llvm_return_summary",
		DisplayName:       "llvm_return_summary",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           1,
		CFGBlocks: []ClangCFGBlock{{
			ID:                   0,
			ReturnExpression:     "runtime_value",
			PotentialSuccessExit: true,
		}},
		LLVMFunctionFacts: []LLVMCallFact{{
			Kind:                          "function_summary",
			Function:                      "llvm_return_summary",
			SourceFunction:                "llvm_return_summary",
			FunctionHasReturn:             true,
			FunctionMustReturnNonnegative: true,
		}},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		signalCoverageCache:    make(map[string]signalCoverageResult),
		successWitnessCache:    make(map[string]functionSuccessWitness),
		effectFreeSuccessCache: make(map[string]functionSuccessWitness),
		sigEffectSourceCache: map[string]effectSourceState{
			function.ID: effectSourcePossible,
		},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want certified bypass", coverage.state)
	}
	if coverage.bypassProofMethod !=
		"cfg_effect_free_fast_success_path+llvm_all_returns_nonnegative" {
		t.Fatalf(
			"bypass method = %q, want LLVM all-return proof",
			coverage.bypassProofMethod,
		)
	}
}

func TestLLVMAllReturnSummaryRequiresEveryVariant(t *testing.T) {
	function := &FunctionInfo{
		Name:       "variant",
		ReturnType: "int",
		LLVMFunctionFacts: []LLVMCallFact{
			{
				Kind:                          "function_summary",
				Function:                      "variant",
				SourceFunction:                "variant",
				FunctionHasReturn:             true,
				FunctionMustReturnNonnegative: true,
			},
			{
				Kind:                          "function_summary",
				Function:                      "variant",
				SourceFunction:                "variant",
				FunctionHasReturn:             true,
				FunctionMustReturnNonnegative: false,
			},
		},
	}
	if _, proven := llvmFunctionSuccessProof(
		function,
		"nonnegative",
	); proven {
		t.Fatal("conflicting LLVM variants must not certify success")
	}
}

func TestLLVMNonpositiveSummaryRejectsPositiveSuccessArm(t *testing.T) {
	function := &FunctionInfo{
		ID:          "errno-helper",
		Name:        "errno_helper",
		DisplayName: "errno_helper",
		ReturnType:  "int",
		LLVMFunctionFacts: []LLVMCallFact{{
			Kind:                          "function_summary",
			Function:                      "errno_helper",
			SourceFunction:                "errno_helper",
			FunctionHasReturn:             true,
			FunctionMustReturnNonpositive: true,
		}},
	}
	outcome := constrainReturnOutcomeByLLVMFunctionFacts(
		function,
		returnOutcome{
			domain: returnDomainSigned,
			mask:   outcomePositive,
		},
	)
	if outcome.mask != 0 {
		t.Fatalf("positive outcome survived nonpositive summary: %#v", outcome)
	}

	outcome = constrainReturnOutcomeByLLVMFunctionFacts(
		function,
		returnOutcome{
			domain: returnDomainSigned,
			mask:   outcomeNegative | outcomeZero | outcomePositive,
		},
	)
	if outcome.mask != outcomeNegative|outcomeZero {
		t.Fatalf("nonpositive summary produced %#v", outcome)
	}
}

func TestNonpositiveCalleeMakesErrnoGuardRequireZero(t *testing.T) {
	parent := &FunctionInfo{
		Name:       "parent",
		ReturnType: "int",
	}
	child := &FunctionInfo{
		Name:       "child",
		ReturnType: "int",
		LLVMFunctionFacts: []LLVMCallFact{{
			Kind:                          "function_summary",
			SourceFunction:                "child",
			FunctionHasReturn:             true,
			FunctionMustReturnNonpositive: true,
		}},
	}
	requirement := survivingConditionRequirement(
		parent,
		child,
		"if (error) return error;",
		ifDetail{
			condText: "error",
			bodyText: "return error;",
		},
		"error",
		"nonnegative",
	)
	if requirement != "zero" {
		t.Fatalf("errno guard requirement = %q, want zero", requirement)
	}
}

func TestSIGKILLRootCoverageCorrelatesTernarySuccessArm(t *testing.T) {
	copyHelper := &FunctionInfo{
		ID:          "copy-helper",
		Name:        "copy_to_user",
		DisplayName: "copy_to_user",
		ReturnType:  "unsigned_integer",
	}
	function := &FunctionInfo{
		ID:                "ternary-success",
		Name:              "ternary_success",
		DisplayName:       "ternary_success",
		ReturnType:        "int",
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		CFGHasSuccessExit: true,
		CFGEntry:          0,
		CFGExit:           2,
		Body: `{
			return copy_to_user(dst, src, size) ? -EFAULT : 0;
		}`,
		TypedCallees: map[string][]string{
			"copy_to_user": {copyHelper.ID},
		},
		CallSites: []ClangCallSite{{
			ID:         "copy-site",
			Direct:     true,
			Reachable:  true,
			HasBlock:   true,
			BlockID:    0,
			Name:       "copy_to_user",
			ResultUse:  "condition",
			ReturnType: "unsigned_integer",
		}},
		CFGBlocks: []ClangCFGBlock{
			{
				ID:                       0,
				Calls:                    []string{"copy_to_user"},
				CallSiteIDs:              []string{"copy-site"},
				TerminatorCondition:      "copy_to_user(dst, src, size)",
				SuccessSuccessors:        []int{1, 1},
				SuccessSuccessorBranches: []string{"true", "false"},
			},
			{
				ID:                   1,
				ReturnExpression:     "copy_to_user(dst, src, size) ? -EFAULT : 0",
				PotentialSuccessExit: true,
			},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID:   function,
			copyHelper.ID: copyHelper,
		},
		nameIndex: map[string][]string{
			"copy_to_user": {copyHelper.ID},
		},
		signalCoverageCache:    make(map[string]signalCoverageResult),
		successWitnessCache:    make(map[string]functionSuccessWitness),
		effectFreeSuccessCache: make(map[string]functionSuccessWitness),
		sigEffectSourceCache: map[string]effectSourceState{
			function.ID:   effectSourcePossible,
			copyHelper.ID: effectSourceNone,
		},
		sigEffectSourcesBuilt: true,
	}
	coverage := analyzer.analyzeFunctionSIGKILLCoverage(
		function.ID,
		nil,
		nil,
		make(map[string]bool),
	)
	if coverage.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want ternary success bypass", coverage.state)
	}
	if len(coverage.bypassProofPath) == 0 {
		t.Fatal("ternary success-arm proof path is missing")
	}
}

func TestConstantConditionValueUsesBooleanShortCircuitFacts(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		value     bool
		known     bool
	}{
		{
			name:      "false and unknown",
			condition: "NULL && runtime_condition()",
			value:     false,
			known:     true,
		},
		{
			name:      "true or unknown",
			condition: "1 || runtime_condition()",
			value:     true,
			known:     true,
		},
		{
			name:      "unknown and true",
			condition: "runtime_condition() && 1",
			known:     false,
		},
		{
			name:      "unknown or false",
			condition: "runtime_condition() || 0",
			known:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, known := constantConditionValue(test.condition)
			if known != test.known || known && value != test.value {
				t.Fatalf(
					"constantConditionValue(%q) = (%t, %t), want (%t, %t)",
					test.condition,
					value,
					known,
					test.value,
					test.known,
				)
			}
		})
	}
}

func TestCFGSourceTernaryConstraintSurvivesExpandedSpelling(t *testing.T) {
	function := &FunctionInfo{
		ID:          "source-ternary",
		Name:        "source_ternary",
		DisplayName: "source_ternary",
		ReturnType:  "signed_integer",
		Parameters:  []string{"dataptr", "ret"},
		Body: `{
			if ((dataptr == NULL) && (ret == -EINVAL))
				return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;
			return ret;
		}`,
	}
	block := ClangCFGBlock{
		ID: 1,
		ReturnExpression: "((dataptr == NULL) && (ret == -EINVAL))" +
			" ? 0 : ret",
		ReturnExpressionExpanded: "((dataptr == ((void *)0)) && " +
			"(ret == -22)) ? 0 : ret",
		PotentialSuccessExit: true,
	}
	function.CFGBlocks = []ClangCFGBlock{block}
	constraint := successPathConstraint{
		functionID: function.ID,
		blockID:    0,
		expression: "((dataptr == NULL) && (ret == -EINVAL))",
		required:   true,
		pathStable: true,
	}
	if !cfgBranchMayConstrainFunctionReturn(
		function,
		constraint.expression,
		true,
	) {
		t.Fatal("source ternary condition was not correlated with CFG branch")
	}
	analyzer := &Analyzer{
		functions:           map[string]*FunctionInfo{function.ID: function},
		successWitnessCache: make(map[string]functionSuccessWitness),
	}
	witness := analyzer.proveSuccessfulReturnBlockAlongPathWithValues(
		function,
		block,
		nil,
		make(map[string]bool),
		[]successPathConstraint{constraint},
		false,
		false,
		nil,
		nil,
	)
	if !witness.proven {
		t.Fatal("source ternary success arm was not proven")
	}

	constraint.required = false
	witness = analyzer.proveSuccessfulReturnBlockAlongPathWithValues(
		function,
		block,
		nil,
		make(map[string]bool),
		[]successPathConstraint{constraint},
		false,
		false,
		nil,
		nil,
	)
	if witness.proven {
		t.Fatal("unconstrained false ternary arm must not be certified")
	}
}

func TestSignalSubjectRecognizesImmutableCurrentAlias(t *testing.T) {
	body := `
		struct task_struct *task = current;
		if (fatal_signal_pending(task))
			return -ERESTARTSYS;
	`
	if !signalArgumentIsCurrentInBody(body, "task") {
		t.Fatal("immutable local alias of current was not recognized")
	}
	body += "\ntask = other;\n"
	if signalArgumentIsCurrentInBody(body, "task") {
		t.Fatal("reassigned local alias must not be certified as current")
	}
}

func TestReportWorkersShareSerializedSIGKILLCacheOnly(t *testing.T) {
	sigkillMutex := &sync.Mutex{}
	analyzer := &Analyzer{
		summaryCache:          make(map[string]FunctionSummary),
		signalCoverageCache:   make(map[string]signalCoverageResult),
		lsmCoverageCache:      make(map[string]lsmCoverageResult),
		signalTransitionCache: make(map[string][]resolvedContextCall),
		sigkillCoverageMu:     sigkillMutex,
	}
	first := analyzer.newReportWorker()
	second := analyzer.newReportWorker()

	first.signalCoverageCache["function"] = signalCoverageResult{
		state: "non_enforcing",
	}
	if _, ok := second.signalCoverageCache["function"]; !ok {
		t.Fatal("report workers do not share the serialized SIGKILL DP cache")
	}
	if _, ok := analyzer.signalCoverageCache["function"]; !ok {
		t.Fatal("parent does not share the serialized SIGKILL DP cache")
	}
	if first.sigkillCoverageMu != sigkillMutex ||
		second.sigkillCoverageMu != sigkillMutex {
		t.Fatal("report workers do not share the SIGKILL serialization mutex")
	}

	first.lsmCoverageCache["function"] = lsmCoverageResult{
		state: "non_enforcing",
	}
	if _, ok := second.lsmCoverageCache["function"]; ok {
		t.Fatal("report workers unexpectedly share the LSM DP cache")
	}
	if _, ok := analyzer.lsmCoverageCache["function"]; ok {
		t.Fatal("report worker unexpectedly mutated the parent LSM DP cache")
	}
}

func TestLSMFinalClassificationUsesPerPathHookSets(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
		configSymbols: map[string]bool{
			"CONFIG_SECURITY":    true,
			"CONFIG_BPF_SYSCALL": true,
			"CONFIG_BPF_LSM":     true,
		},
		configValues: map[string]string{
			"CONFIG_LSM": "bpf",
		},
		lsmWrapperHooks: map[string]string{
			"security_a": "a",
			"security_b": "b",
			"security_c": "c",
		},
	}
	report := SyscallReport{
		LSMPathCoverage: LSMPathCoverageProof{
			Status: "enforcing",
			Hooks:  []string{"security_a", "security_b", "security_c"},
			SuccessPathHookSets: [][]string{
				{"security_a", "security_b"},
				{"security_c"},
			},
		},
		EffectiveLSMHooks: []string{"security_a", "security_c"},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.LSMClassification != "certified_bpf_lsm_enforceable" {
		t.Fatalf("classification = %q, want certified enforceable", report.LSMClassification)
	}
	if len(report.CertifiedBPFLSMHooks) != 2 {
		t.Fatalf("certified BPF hooks = %#v, want two path-covering hooks", report.CertifiedBPFLSMHooks)
	}

	report.EffectiveLSMHooks = []string{"security_a"}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.LSMClassification != "uncertain" {
		t.Fatalf("classification without second path hook = %q, want uncertain", report.LSMClassification)
	}
}

func TestUnprovenKernelGateCannotOverrideCertifiedLSMBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:          "root",
		Name:        "root",
		DisplayName: "root",
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		displayIndex: map[string]string{
			function.DisplayName: function.ID,
		},
	}
	coverage := lsmCoverageResult{
		state: "non_enforcing",
		alternatives: provenNonEnforcingLSMAlternatives(
			functionSuccessWitness{
				proven: true,
				method: "explicit_zero_return",
			},
			function.DisplayName,
		),
		reasons: []string{"certified normal-success bypass"},
	}
	promoted := analyzer.promoteKernelGateLSMCoverage(
		coverage,
		[]LSMErrorEffect{{
			Hook:      "security_example",
			ProofPath: []string{"security_example", function.DisplayName},
		}},
		[]string{"security_example"},
	)
	if promoted.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want N to take priority", promoted.state)
	}
	if !stringSlicesEqual(promoted.reasons, coverage.reasons) {
		t.Fatalf("N proof reasons changed: %#v", promoted.reasons)
	}
}

func TestCertifiedKernelGateOverridesInfeasibleLSMBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:          "root",
		Name:        "root",
		DisplayName: "root",
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		displayIndex: map[string]string{
			function.DisplayName: function.ID,
		},
	}
	coverage := lsmCoverageResult{
		state: "non_enforcing",
		alternatives: provenNonEnforcingLSMAlternatives(
			functionSuccessWitness{
				proven: true,
				method: "explicit_zero_return",
			},
			function.DisplayName,
		),
		reasons:           []string{"certified normal-success bypass"},
		bypassProofPath:   []string{function.DisplayName},
		bypassProofMethod: "explicit_zero_return",
	}
	promoted := analyzer.promoteKernelGateLSMCoverage(
		coverage,
		[]LSMErrorEffect{{
			Hook:              "security_example",
			BPFHook:           "example",
			HookKind:          "error-return",
			BlocksOperation:   "guaranteed",
			TerminatesSyscall: "guaranteed",
			ErrnoPropagation:  "exact",
			FailureEncoding:   failureReturnErrno,
			ProofPath:         []string{"security_example", function.DisplayName},
			LLVMVerification:  "not_available",
		}},
		[]string{"security_example"},
	)
	if promoted.state != "enforcing" {
		t.Fatalf("coverage = %q, want independently certified E", promoted.state)
	}
	if !containsString(promoted.proofMethods, "kernel_gate_invalidates_cfg_bypass") {
		t.Fatalf("proof methods = %#v, want bypass invalidation evidence", promoted.proofMethods)
	}
	if len(promoted.bypassProofPath) != 0 || promoted.bypassProofMethod != "" {
		t.Fatalf(
			"stale bypass proof remains: path=%#v method=%q",
			promoted.bypassProofPath,
			promoted.bypassProofMethod,
		)
	}
}

func TestKernelGateWithUnmappedBPFHookCannotOverrideLSMBypass(t *testing.T) {
	function := &FunctionInfo{
		ID:          "root",
		Name:        "root",
		DisplayName: "root",
		Frontend:    "clang-ast-cfg",
		CFGComplete: true,
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			function.ID: function,
		},
		displayIndex: map[string]string{
			function.DisplayName: function.ID,
		},
	}
	coverage := lsmCoverageResult{
		state:        "non_enforcing",
		alternatives: provenNonEnforcingLSMAlternatives(functionSuccessWitness{proven: true}),
	}
	promoted := analyzer.promoteKernelGateLSMCoverage(
		coverage,
		[]LSMErrorEffect{{
			Hook:              "security_unmapped",
			HookKind:          "error-return",
			BlocksOperation:   "guaranteed",
			TerminatesSyscall: "guaranteed",
			ErrnoPropagation:  "exact",
			FailureEncoding:   failureReturnErrno,
			ProofPath:         []string{"security_unmapped", function.DisplayName},
		}},
		[]string{"security_unmapped"},
	)
	if promoted.state != "non_enforcing" {
		t.Fatalf("coverage = %q, want N without a BPF hook mapping", promoted.state)
	}
}

func TestIncompleteInputCannotCertifyDisabledBPFLSM(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
		configSymbols: map[string]bool{
			"CONFIG_SECURITY":    true,
			"CONFIG_BPF_SYSCALL": true,
			"CONFIG_BPF_LSM":     false,
		},
		inputValidation: InputValidation{
			Performed: true,
			Status:    "development_incomplete",
			Reasons:   []string{"vmlinux is missing"},
		},
	}
	report := SyscallReport{
		LSMPathCoverage: LSMPathCoverageProof{
			Status: "non_enforcing",
		},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.LSMClassification != "uncertain" {
		t.Fatalf(
			"classification = %q, want uncertain for incomplete input",
			report.LSMClassification,
		)
	}
}

func TestSIGKILLEnforcingCoverageCanBeCertified(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
	}
	report := SyscallReport{
		SIGKILLPathCoverage: SIGKILLPathCoverageProof{
			Status: "enforcing",
			Checks: []string{"fatal_signal_pending"},
		},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.SIGKILLClassification != "certified_sigkill_enforceable" ||
		report.SIGKILLEnforcementState != "E" {
		t.Fatalf("classification = %q/%q, want certified E", report.SIGKILLClassification, report.SIGKILLEnforcementState)
	}
}

func TestSIGKILLEnforcingProofSurvivesCoveredGap(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
	}
	report := SyscallReport{
		SIGKILLPathCoverage: SIGKILLPathCoverageProof{
			Status: "enforcing",
			CoveredUnresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Kind:   "unrelated_open_edge",
			}},
		},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.SIGKILLClassification != "certified_sigkill_enforceable" {
		t.Fatalf("classification = %q, want certified SIGKILL enforceable", report.SIGKILLClassification)
	}
}

func TestUnavailableSyscallIsNotApplicable(t *testing.T) {
	output := t.TempDir()
	analyzer := &Analyzer{
		cfg: Config{OutDir: output},
	}
	report := analyzer.buildSyscallReport(SyscallEntry{
		Number:             134,
		ABI:                "64",
		Name:               "uselib",
		Availability:       syscallAvailabilityUnavailableSlot,
		AvailabilityReason: "no table implementation",
	})
	if report.LSMClassification != "not_applicable_unavailable" ||
		report.SIGKILLClassification != "not_applicable_unavailable" {
		t.Fatalf("unavailable classifications = %q / %q", report.LSMClassification, report.SIGKILLClassification)
	}
}

func TestLoadSyscallsPreservesUnavailableTableRows(t *testing.T) {
	root := t.TempDir()
	tableDirectory := filepath.Join(root, "arch", "x86", "entry", "syscalls")
	if err := os.MkdirAll(tableDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	table := "0 common read sys_read\n1 common obsolete\n2 x32 ignored sys_ignored\n"
	if err := os.WriteFile(
		filepath.Join(tableDirectory, "syscall_64.tbl"),
		[]byte(table),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	analyzer := &Analyzer{cfg: Config{KernelRoot: root}}
	if err := analyzer.loadSyscalls(); err != nil {
		t.Fatal(err)
	}
	if len(analyzer.syscalls) != 2 {
		t.Fatalf("syscalls = %#v, want two common/64 rows", analyzer.syscalls)
	}
	if analyzer.syscalls[1].Availability != syscallAvailabilityUnavailableSlot {
		t.Fatalf(
			"availability = %q, want %q",
			analyzer.syscalls[1].Availability,
			syscallAvailabilityUnavailableSlot,
		)
	}
}

func TestClassifySyscallAvailabilityFromSystemMap(t *testing.T) {
	analyzer := &Analyzer{
		syscalls: []SyscallEntry{
			{Name: "read", Entry: "sys_read"},
			{Name: "weak", Entry: "sys_weak"},
			{Name: "blank"},
			{Name: "missing", Entry: "sys_missing"},
		},
	}
	analyzer.classifySyscallAvailability(map[string]byte{
		"__x64_sys_read": 'T',
		"__x64_sys_weak": 'W',
	})
	want := []string{
		syscallAvailabilityImplemented,
		syscallAvailabilityUnavailableConfig,
		syscallAvailabilityUnavailableSlot,
		syscallAvailabilityUnresolvedLink,
	}
	for index, expected := range want {
		if analyzer.syscalls[index].Availability != expected {
			t.Fatalf(
				"syscall %d availability = %q, want %q",
				index,
				analyzer.syscalls[index].Availability,
				expected,
			)
		}
	}
}

func TestInputValidationRejectsMissingCompileObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	build := filepath.Join(t.TempDir(), "build")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(build, "include", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "sample.c")
	config := filepath.Join(build, ".config")
	for path, content := range map[string]string{
		source: "int sample(void) { return 0; }\n",
		config: "CONFIG_MODULES=n\n",
		filepath.Join(build, "include/config/auto.conf"): "CONFIG_MODULES=n\n",
		filepath.Join(build, "vmlinux"):                  "linked\n",
		filepath.Join(build, "System.map"):               "00000000 T __x64_sys_read\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	compileDatabase := filepath.Join(build, "compile_commands.json")
	if err := os.WriteFile(compileDatabase, []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	analyzer := &Analyzer{
		cfg: Config{
			KernelRoot:           root,
			CompileDB:            compileDatabase,
			Frontend:             "hybrid",
			ScanAll:              true,
			AllowIncompleteInput: true,
		},
		compileUnits: map[string]CompileCommand{
			source: {
				Directory: build,
				File:      source,
				Arguments: []string{
					"clang",
					"-c",
					source,
					"-o",
					filepath.Join(build, "sample.o"),
				},
			},
		},
		configPath:      config,
		hasKernelConfig: true,
		configSymbols:   map[string]bool{"CONFIG_MODULES": false},
		configValues:    map[string]string{},
		syscalls:        []SyscallEntry{{Name: "read", Entry: "sys_read"}},
		inputValidation: InputValidation{CompileCommandCount: 1, UniqueCompileSources: 1},
	}
	if err := analyzer.validateAnalysisInput(); err != nil {
		t.Fatal(err)
	}
	if analyzer.inputValidation.Status != "development_incomplete" {
		t.Fatalf("validation status = %q", analyzer.inputValidation.Status)
	}
	if len(analyzer.inputValidation.MissingCompileOutputs) != 1 {
		t.Fatalf("missing outputs = %#v", analyzer.inputValidation.MissingCompileOutputs)
	}
	if !strings.Contains(
		strings.Join(analyzer.inputValidation.Reasons, "\n"),
		"object output(s) are missing",
	) {
		t.Fatalf("validation reasons = %#v", analyzer.inputValidation.Reasons)
	}
}

func TestCountKernelConfigStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config")
	content := strings.Join([]string{
		"CONFIG_SECURITY=y",
		"CONFIG_EXAMPLE=m",
		"# CONFIG_UNUSED is not set",
		`CONFIG_LSM="landlock,bpf"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	states, err := countKernelConfigStates(path)
	if err != nil {
		t.Fatal(err)
	}
	if states.builtin != 1 || states.modules != 1 ||
		states.disabled != 1 {
		t.Fatalf("config states = %#v", states)
	}
}

func TestInputValidationAcceptsConfigOldObjectWithFreshKbuildDependencies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	build := filepath.Join(t.TempDir(), "build")
	configDir := filepath.Join(build, "include", "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	source := filepath.Join(root, "sample.c")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(build, "sample.o")
	config := filepath.Join(build, ".config")
	compileDatabase := filepath.Join(build, "compile_commands.json")
	configDependency := filepath.Join(configDir, "SAMPLE")
	for path, content := range map[string]string{
		source:                                "int sample(void) { return 0; }\n",
		object:                                "object\n",
		config:                                "CONFIG_MODULES=n\nCONFIG_SAMPLE=y\n",
		configDependency:                      "y\n",
		filepath.Join(configDir, "auto.conf"): "CONFIG_MODULES=n\nCONFIG_SAMPLE=y\n",
		filepath.Join(build, "vmlinux"):       "linked\n",
		filepath.Join(build, "System.map"):    "00000000 T __x64_sys_read\n",
		compileDatabase:                       "[]\n",
		kbuildCommandFile(object):             "deps_sample.o := \\\n  $(wildcard include/config/SAMPLE) \\\n\nsample.o: $(deps_sample.o)\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	base := time.Now().Add(-time.Hour)
	setModTime := func(path string, offset time.Duration) {
		t.Helper()
		stamp := base.Add(offset)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	setModTime(source, time.Second)
	setModTime(configDependency, 2*time.Second)
	setModTime(object, 3*time.Second)
	setModTime(config, 4*time.Second)
	setModTime(filepath.Join(build, "vmlinux"), 5*time.Second)
	setModTime(filepath.Join(build, "System.map"), 5*time.Second)
	setModTime(compileDatabase, 6*time.Second)

	analyzer := &Analyzer{
		cfg: Config{
			KernelRoot: root,
			CompileDB:  compileDatabase,
			Frontend:   "hybrid",
			ScanAll:    true,
		},
		compileUnits: map[string]CompileCommand{
			source: {
				Directory: build,
				File:      source,
				Arguments: []string{"clang", "-c", source, "-o", object},
			},
		},
		configPath:      config,
		hasKernelConfig: true,
		configSymbols:   map[string]bool{"CONFIG_MODULES": false},
		configValues:    map[string]string{},
		syscalls:        []SyscallEntry{{Name: "read", Entry: "sys_read"}},
		inputValidation: InputValidation{CompileCommandCount: 1, UniqueCompileSources: 1},
	}
	if err := analyzer.validateAnalysisInput(); err != nil {
		t.Fatal(err)
	}
	if analyzer.inputValidation.Status != "complete" {
		t.Fatalf(
			"validation status = %q, reasons = %#v",
			analyzer.inputValidation.Status,
			analyzer.inputValidation.Reasons,
		)
	}
	if analyzer.inputValidation.ConfigOldOutputsVerified != 1 {
		t.Fatalf(
			"verified config-old outputs = %d, want 1",
			analyzer.inputValidation.ConfigOldOutputsVerified,
		)
	}
	if analyzer.inputValidation.KbuildConfigDepsChecked != 1 {
		t.Fatalf(
			"checked Kbuild config dependencies = %d, want 1",
			analyzer.inputValidation.KbuildConfigDepsChecked,
		)
	}
}

func TestInputValidationRejectsObjectOlderThanRelevantKbuildConfigDependency(t *testing.T) {
	build := t.TempDir()
	object := filepath.Join(build, "sample.o")
	configDependency := filepath.Join(build, "include", "config", "SAMPLE")
	if err := os.MkdirAll(filepath.Dir(configDependency), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("object\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configDependency, []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		kbuildCommandFile(object),
		[]byte("deps_sample.o := \\\n  $(wildcard include/config/SAMPLE) \\\n\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	base := time.Now().Add(-time.Hour)
	if err := os.Chtimes(object, base, base); err != nil {
		t.Fatal(err)
	}
	newer := base.Add(time.Second)
	if err := os.Chtimes(configDependency, newer, newer); err != nil {
		t.Fatal(err)
	}

	check, err := checkKbuildConfigFreshness(build, object, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.NewerDependencies) != 1 ||
		check.NewerDependencies[0] != configDependency {
		t.Fatalf("newer dependencies = %#v, want %q", check.NewerDependencies, configDependency)
	}
}

func TestEffectFailureReturnKindCachesConservativeCycle(t *testing.T) {
	first := &FunctionInfo{
		ID:                "first",
		Name:              "first",
		Body:              "return second();",
		RawCallees:        []string{"second"},
		CFGReachableCalls: []string{"second"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		TypedCallees: map[string][]string{
			"second": {"second"},
		},
	}
	second := &FunctionInfo{
		ID:                "second",
		Name:              "second",
		Body:              "return first();",
		RawCallees:        []string{"first"},
		CFGReachableCalls: []string{"first"},
		Frontend:          "clang-ast-cfg",
		CFGComplete:       true,
		TypedCallees: map[string][]string{
			"first": {"first"},
		},
	}
	analyzer := &Analyzer{
		functions: map[string]*FunctionInfo{
			first.ID:  first,
			second.ID: second,
		},
		sigEffectSourceCache: map[string]effectSourceState{
			first.ID:  effectSourcePossible,
			second.ID: effectSourcePossible,
		},
		sigFailureKindCache: make(map[string]string),
	}

	if got := analyzer.effectFailureReturnKind(
		first.ID,
		"sigkill",
		make(map[string]bool),
	); got != failureReturnUnknown {
		t.Fatalf("failure kind = %q, want %q", got, failureReturnUnknown)
	}
	for _, functionID := range []string{first.ID, second.ID} {
		if got, ok := analyzer.sigFailureKindCache[functionID]; !ok ||
			got != failureReturnUnknown {
			t.Fatalf(
				"cached failure kind for %s = %q, %v; want %q, true",
				functionID,
				got,
				ok,
				failureReturnUnknown,
			)
		}
	}
}

func TestAssignedSignalErrorEffect(t *testing.T) {
	body := `
		long ret = 0;
		lock();
		if (signal_pending_state(0x0101, current)) {
			cleanup();
			ret = -ERESTARTSYS;
		}
		unlock();
		return ret;
	`
	effect := analyzeSignalCheckLocalEffect(body, "signal_pending_state")
	if got := classifyFinalSignalAbortEffect(effect); got != "guaranteed" {
		t.Fatalf("abort effect = %q (%#v), want guaranteed", got, effect)
	}
}

func TestSignalBypassProofCertifiesNotEnforceable(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
		configSymbols:   map[string]bool{},
		configValues:    map[string]string{},
	}
	report := SyscallReport{
		SIGKILLPathCoverage: SIGKILLPathCoverageProof{
			Status:  "non_enforcing",
			Reasons: []string{"success-path bypass witness"},
			CoveredUnresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Kind:   "unrelated_open_edge",
			}},
		},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.SIGKILLClassification != "certified_sigkill_not_enforceable" ||
		report.SIGKILLEnforcementState != "N" {
		t.Fatalf(
			"classification = %q, want certified SIGKILL not enforceable",
			report.SIGKILLClassification,
		)
	}
}

func TestSignalNoCheckpointRequiresClosedReachability(t *testing.T) {
	analyzer := &Analyzer{
		cfg: Config{
			Frontend:  "hybrid",
			CompileDB: "/tmp/compile_commands.json",
		},
		hasKernelConfig: true,
		configSymbols:   map[string]bool{},
		configValues:    map[string]string{},
	}
	report := SyscallReport{
		SIGKILLPathCoverage: SIGKILLPathCoverageProof{
			Status: "uncertain",
			Unresolved: []UnresolvedProofEdge{{
				Domain:     "sigkill",
				Caller:     "callback_wrapper",
				Kind:       "indirect_signal_target_set_unproven",
				Expression: "callback",
				Detail:     "target set is open",
			}},
		},
	}
	analyzer.applyFinalClassifications(&report, FunctionSummary{})
	if report.SIGKILLClassification != "uncertain" {
		t.Fatalf("classification = %q, want uncertain", report.SIGKILLClassification)
	}
}

func TestIncrementalReportProgressTracksUnresolvedRatios(t *testing.T) {
	started := time.Unix(100, 0)
	progress := newIncrementalReportProgress(2, started)
	updateIncrementalReportProgress(
		&progress,
		SyscallReport{
			Number:                2,
			ABI:                   "common",
			Name:                  "open",
			LSMClassification:     "uncertain",
			SIGKILLClassification: "certified_sigkill_not_enforceable",
			UnresolvedProofEdges: []UnresolvedProofEdge{
				{Domain: "lsm", Kind: "direct_call_unresolved"},
				{Domain: "sigkill", Kind: "cfg_incomplete"},
			},
		},
		1500*time.Millisecond,
		2*time.Second,
		"checkpoints/syscalls/002-open.json",
	)
	updateIncrementalReportProgress(
		&progress,
		SyscallReport{
			Number:                3,
			ABI:                   "common",
			Name:                  "close",
			LSMClassification:     "certified_bpf_lsm_not_enforceable",
			SIGKILLClassification: "uncertain",
		},
		250*time.Millisecond,
		3*time.Second,
		"checkpoints/syscalls/003-close.json",
	)

	if progress.CompletedSyscalls != 2 || progress.CompletedRatio != 1 {
		t.Fatalf("completion = %d/%d (%f)", progress.CompletedSyscalls, progress.TotalSyscalls, progress.CompletedRatio)
	}
	if progress.LSMUncertainRatio != 0.5 ||
		progress.SIGKILLUncertainRatio != 0.5 ||
		progress.EitherDomainUncertainRatio != 1 {
		t.Fatalf(
			"uncertain ratios = lsm:%f sigkill:%f either:%f",
			progress.LSMUncertainRatio,
			progress.SIGKILLUncertainRatio,
			progress.EitherDomainUncertainRatio,
		)
	}
	if progress.UnresolvedProofSyscallRatio != 0.5 ||
		progress.UnresolvedProofEdges != 2 ||
		progress.UnresolvedLSMProofEdges != 1 ||
		progress.UnresolvedSIGKILLProofEdges != 1 {
		t.Fatalf("unresolved progress = %#v", progress)
	}
	if progress.LastCompleted == nil ||
		progress.LastCompleted.Checkpoint != "checkpoints/syscalls/003-close.json" {
		t.Fatalf("last completed = %#v", progress.LastCompleted)
	}
}

func TestClassificationCountsSeparateUnavailableSyscalls(t *testing.T) {
	counts := buildClassificationCounts([]SyscallReport{
		{
			LSMClassification:     "certified_bpf_lsm_enforceable",
			SIGKILLClassification: "certified_sigkill_not_enforceable",
		},
		{
			LSMClassification:     "not_applicable_unavailable",
			SIGKILLClassification: "not_applicable_unavailable",
		},
	})
	if counts["total_syscall_table_entries"] != 2 ||
		counts["applicable_syscalls"] != 1 ||
		counts["unavailable_syscalls"] != 1 {
		t.Fatalf("classification counts = %#v", counts)
	}
}

func TestWriteJSONAtomicReplacesCompleteDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoints", "progress.json")
	if err := writeJSONAtomic(path, map[string]int{"completed": 1}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(path, map[string]int{"completed": 2}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]int
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("checkpoint is not valid JSON: %v", err)
	}
	if document["completed"] != 2 {
		t.Fatalf("completed = %d, want 2", document["completed"])
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".progress.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary checkpoint files remain: %#v", matches)
	}
}

func TestSyscallCheckpointFilename(t *testing.T) {
	report := SyscallReport{Number: 16, Name: "ioctl/test"}
	if got := syscallCheckpointFilename(report); got != "016-ioctl_test.json" {
		t.Fatalf("filename = %q, want 016-ioctl_test.json", got)
	}
}

func TestWriteReportsPersistsPerSyscallCheckpoint(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	analyzer := &Analyzer{
		cfg:       Config{OutDir: output, Frontend: "hybrid"},
		functions: map[string]*FunctionInfo{},
		syscalls: []SyscallEntry{{
			Number: 16,
			ABI:    "common",
			Name:   "ioctl",
			Start:  "__do_sys_ioctl",
		}},
	}
	if err := analyzer.writeReports(); err != nil {
		t.Fatal(err)
	}

	checkpointPath := filepath.Join(output, "checkpoints", "syscalls", "016-ioctl.json")
	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	var report SyscallReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Name != "ioctl" || report.LSMClassification != "uncertain" {
		t.Fatalf("checkpoint report = %#v", report)
	}

	progressData, err := os.ReadFile(filepath.Join(output, "checkpoints", "progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	var progress IncrementalReportProgress
	if err := json.Unmarshal(progressData, &progress); err != nil {
		t.Fatal(err)
	}
	if progress.Status != "complete" ||
		progress.CompletedSyscalls != 1 ||
		progress.UnresolvedProofSyscallRatio != 1 {
		t.Fatalf("progress = %#v", progress)
	}
	if _, err := os.Stat(filepath.Join(output, "function_index.json")); !os.IsNotExist(err) {
		t.Fatalf("function_index.json should be disabled by default, stat error = %v", err)
	}
}

func TestWriteReportsEmitsFunctionIndexOnRequest(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	analyzer := &Analyzer{
		cfg: Config{
			OutDir:            output,
			Frontend:          "hybrid",
			EmitFunctionIndex: true,
		},
		functions: map[string]*FunctionInfo{},
	}
	if err := analyzer.writeReports(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(output, "function_index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var functions map[string]*FunctionInfo
	if err := json.Unmarshal(data, &functions); err != nil {
		t.Fatal(err)
	}
	if len(functions) != 0 {
		t.Fatalf("function index = %#v, want empty index", functions)
	}
}
