package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type Config struct {
	KernelRoot           string
	CompileDB            string
	FrontendCache        string
	RebuildFrontendCache bool
	PrepareFrontendOnly  bool
	RequireFrontendCache bool
	OutDir               string
	Syscalls             map[string]struct{}
	MaxDepth             int
	ScanAll              bool
	AllowIncompleteInput bool
	EmitRaw              bool
	EmitFunctionIndex    bool
	PreprocessJobs       int
	Frontend             string
	ClangExtractor       string
	ClangJobs            int
	LLVMVerify           bool
	LLVMVerifier         string
	LLVMJobs             int
	ReportJobs           int
}

type CompileCommand struct {
	Directory string   `json:"directory"`
	File      string   `json:"file"`
	Command   string   `json:"command,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
}

type ConfiguredSource struct {
	Code           string
	ActiveOriginal string
}

type configuredSourceResult struct {
	index  int
	path   string
	source ConfiguredSource
	err    error
}

type preprocessorBranch struct {
	start int
	end   int
}

type preprocessorGroup struct {
	branches    []preprocessorBranch
	branchStart int
}

type SyscallEntry struct {
	Number             int    `json:"number"`
	ABI                string `json:"abi"`
	Name               string `json:"name"`
	Entry              string `json:"entry,omitempty"`
	Start              string `json:"start,omitempty"`
	LinkedSymbol       string `json:"linked_symbol,omitempty"`
	LinkedSymbolType   string `json:"linked_symbol_type,omitempty"`
	Availability       string `json:"availability"`
	AvailabilityReason string `json:"availability_reason,omitempty"`
}

type FunctionInfo struct {
	ID                      string                         `json:"id"`
	Name                    string                         `json:"name"`
	DisplayName             string                         `json:"display_name"`
	ReturnType              string                         `json:"return_type"`
	ReturnTypeSpelling      string                         `json:"return_type_spelling,omitempty"`
	ReturnTypeCanonical     string                         `json:"return_type_canonical,omitempty"`
	ReturnTypeClass         string                         `json:"return_type_class,omitempty"`
	ReturnTypeSigned        bool                           `json:"return_type_signed,omitempty"`
	ReturnTypeBits          int                            `json:"return_type_bits,omitempty"`
	Parameters              []string                       `json:"-"`
	StructVariables         map[string]string              `json:"-"`
	File                    string                         `json:"file"`
	TranslationUnits        []string                       `json:"translation_units,omitempty"`
	Static                  bool                           `json:"static"`
	Inline                  bool                           `json:"inline,omitempty"`
	SemanticHash            string                         `json:"semantic_hash,omitempty"`
	RawCallees              []string                       `json:"raw_callees"`
	DirectCallees           []string                       `json:"direct_callees"`
	DirectLSMHooks          []string                       `json:"direct_lsm_hooks"`
	InactiveLSMHooks        []string                       `json:"inactive_config_lsm_hooks,omitempty"`
	DirectSigChecks         []string                       `json:"direct_signal_checks"`
	AmbiguousCalls          []string                       `json:"ambiguous_calls"`
	UnresolvedCalls         []string                       `json:"unresolved_calls"`
	IndirectCalls           []string                       `json:"indirect_calls"`
	ResolvedIndirectCalls   []IndirectCallResolution       `json:"resolved_indirect_calls,omitempty"`
	Body                    string                         `json:"-"`
	RelFile                 string                         `json:"-"`
	Frontend                string                         `json:"frontend"`
	SourceLine              int                            `json:"source_line,omitempty"`
	CFGComplete             bool                           `json:"cfg_complete"`
	CFGBlockCount           int                            `json:"cfg_block_count,omitempty"`
	CFGHasSuccessExit       bool                           `json:"cfg_has_potential_success_exit"`
	CFGUsedErrnoGuards      bool                           `json:"cfg_used_kernel_errno_guards,omitempty"`
	CFGFailure              string                         `json:"cfg_failure,omitempty"`
	CFGEntry                int                            `json:"cfg_entry,omitempty"`
	CFGExit                 int                            `json:"cfg_exit,omitempty"`
	CFGBlocks               []ClangCFGBlock                `json:"-"`
	CFGUnplacedEvents       []string                       `json:"cfg_unplaced_events,omitempty"`
	CFGUnplacedCallSites    []string                       `json:"cfg_unplaced_callsite_ids,omitempty"`
	CFGEscapedVariables     []string                       `json:"cfg_escaped_variables,omitempty"`
	CFGPreservedEscapes     []string                       `json:"cfg_llvm_preserved_escaped_variables,omitempty"`
	CFGReachableCalls       []string                       `json:"cfg_reachable_calls,omitempty"`
	CFGReachableIndirect    []string                       `json:"cfg_reachable_indirect_calls,omitempty"`
	CFGReachableCallSites   []string                       `json:"cfg_reachable_callsite_ids,omitempty"`
	CFGMustSuccessCalls     []string                       `json:"cfg_must_success_calls,omitempty"`
	CFGMustSuccessIndirect  []string                       `json:"cfg_must_success_indirect_calls,omitempty"`
	CFGMustSuccessCallSites []string                       `json:"cfg_must_success_callsite_ids,omitempty"`
	CFGMustSuccessLSM       []string                       `json:"cfg_must_success_lsm_hooks,omitempty"`
	CFGMustSuccessSignals   []string                       `json:"cfg_must_success_signal_checks,omitempty"`
	LLVMHookFacts           []LLVMHookFact                 `json:"llvm_hook_facts,omitempty"`
	LLVMCallFacts           []LLVMCallFact                 `json:"llvm_call_facts,omitempty"`
	LLVMFunctionFacts       []LLVMCallFact                 `json:"llvm_function_facts,omitempty"`
	CallSites               []ClangCallSite                `json:"call_sites,omitempty"`
	TypedCallees            map[string][]string            `json:"typed_callees,omitempty"`
	TypedIndirectCalls      map[string]ClangIndirectTarget `json:"typed_indirect_calls,omitempty"`
	LSMEffectSourceState    string                         `json:"lsm_effect_source_state,omitempty"`
	SIGEffectSourceState    string                         `json:"sigkill_effect_source_state,omitempty"`
	LSMEffectUnknownWitness string                         `json:"lsm_effect_unknown_witness,omitempty"`
	SIGEffectUnknownWitness string                         `json:"sigkill_effect_unknown_witness,omitempty"`
	FrontendVariantCount    int                            `json:"frontend_variant_count,omitempty"`
	FrontendVariantConflict bool                           `json:"frontend_variant_conflict,omitempty"`
}

type ClangCFGBlock struct {
	ID                           int                    `json:"id"`
	Successors                   []int                  `json:"successors"`
	SuccessorBranches            []string               `json:"successor_branches,omitempty"`
	SuccessSuccessors            []int                  `json:"success_successors"`
	SuccessSuccessorBranches     []string               `json:"success_successor_branches,omitempty"`
	TerminatorCondition          string                 `json:"terminator_condition,omitempty"`
	ReturnExpression             string                 `json:"return_expression,omitempty"`
	ReturnExpressionExpanded     string                 `json:"return_expression_expanded,omitempty"`
	ReturnDefinitelyNonnegative  bool                   `json:"return_definitely_nonnegative,omitempty"`
	ReturnDefinitelyValidPointer bool                   `json:"return_definitely_valid_pointer,omitempty"`
	Calls                        []string               `json:"calls"`
	IndirectCalls                []string               `json:"indirect_calls"`
	LSMHooks                     []string               `json:"lsm_hooks"`
	SignalChecks                 []string               `json:"signal_checks"`
	CallSiteIDs                  []string               `json:"callsite_ids"`
	ValueWrites                  []ClangCFGValueWrite   `json:"value_writes,omitempty"`
	PointeeWrites                []ClangCFGPointeeWrite `json:"pointee_writes,omitempty"`
	PotentialSuccessExit         bool                   `json:"potential_success_exit"`
	FailureOnlyExit              bool                   `json:"failure_only_exit"`
}

type ClangCFGValueWrite struct {
	Target                       string `json:"target"`
	Expression                   string `json:"expression,omitempty"`
	ExpressionExpanded           string `json:"expression_expanded,omitempty"`
	Kind                         string `json:"kind"`
	CallSiteID                   string `json:"callsite_id,omitempty"`
	SourceDefinitelyNonnegative  bool   `json:"source_definitely_nonnegative,omitempty"`
	SourceDefinitelyValidPointer bool   `json:"source_definitely_valid_pointer,omitempty"`
	SourceTypeClass              string `json:"source_type_class,omitempty"`
	SourceTypeSigned             bool   `json:"source_type_signed,omitempty"`
	SourceTypeBits               int    `json:"source_type_bits,omitempty"`
	TargetTypeClass              string `json:"target_type_class,omitempty"`
	TargetTypeSigned             bool   `json:"target_type_signed,omitempty"`
	TargetTypeBits               int    `json:"target_type_bits,omitempty"`
}

type ClangCFGPointeeWrite struct {
	Parameter                    string `json:"parameter"`
	Expression                   string `json:"expression,omitempty"`
	Kind                         string `json:"kind"`
	SourceDefinitelyNonnegative  bool   `json:"source_definitely_nonnegative,omitempty"`
	SourceDefinitelyValidPointer bool   `json:"source_definitely_valid_pointer,omitempty"`
	SourceTypeClass              string `json:"source_type_class,omitempty"`
	SourceTypeSigned             bool   `json:"source_type_signed,omitempty"`
	SourceTypeBits               int    `json:"source_type_bits,omitempty"`
	TargetTypeClass              string `json:"target_type_class,omitempty"`
	TargetTypeSigned             bool   `json:"target_type_signed,omitempty"`
	TargetTypeBits               int    `json:"target_type_bits,omitempty"`
}

type ClangFunctionRecord struct {
	Kind                       string                `json:"kind"`
	Name                       string                `json:"name"`
	File                       string                `json:"file"`
	TranslationUnit            string                `json:"translation_unit"`
	Line                       int                   `json:"line"`
	Column                     int                   `json:"column"`
	ReturnType                 string                `json:"return_type"`
	ReturnTypeCanonical        string                `json:"return_type_canonical"`
	ReturnTypeClass            string                `json:"return_type_class"`
	ReturnTypeSigned           bool                  `json:"return_type_signed"`
	ReturnTypeBits             int                   `json:"return_type_bits"`
	Static                     bool                  `json:"static"`
	Inline                     bool                  `json:"inline"`
	SemanticHash               string                `json:"semantic_hash"`
	Parameters                 []string              `json:"parameters"`
	StructVariables            map[string]string     `json:"struct_variables"`
	Body                       string                `json:"body"`
	DirectCalls                []string              `json:"direct_calls"`
	IndirectCalls              []string              `json:"indirect_calls"`
	LSMHooks                   []string              `json:"lsm_hooks"`
	SignalChecks               []string              `json:"signal_checks"`
	DirectCallTargets          []ClangCallTarget     `json:"direct_call_targets"`
	IndirectCallTargets        []ClangIndirectTarget `json:"indirect_call_targets"`
	CallSites                  []ClangCallSite       `json:"call_sites"`
	ReachableCalls             []string              `json:"reachable_calls"`
	ReachableIndirectCalls     []string              `json:"reachable_indirect_calls"`
	ReachableLSMHooks          []string              `json:"reachable_lsm_hooks"`
	ReachableSignalChecks      []string              `json:"reachable_signal_checks"`
	MustSuccessCalls           []string              `json:"must_success_calls"`
	MustSuccessIndirectCalls   []string              `json:"must_success_indirect_calls"`
	MustSuccessLSMHooks        []string              `json:"must_success_lsm_hooks"`
	MustSuccessSignalChecks    []string              `json:"must_success_signal_checks"`
	ReachableCallSiteIDs       []string              `json:"reachable_callsite_ids"`
	MustSuccessCallSiteIDs     []string              `json:"must_success_callsite_ids"`
	UnplacedCallSiteIDs        []string              `json:"unplaced_callsite_ids"`
	UnplacedEvents             []string              `json:"unplaced_events"`
	EscapedVariables           []string              `json:"escaped_variables"`
	CFGComplete                bool                  `json:"cfg_complete"`
	CFGEntry                   int                   `json:"cfg_entry"`
	CFGExit                    int                   `json:"cfg_exit"`
	CFGHasPotentialSuccessExit bool                  `json:"cfg_has_potential_success_exit"`
	CFGUsedKernelErrnoGuards   bool                  `json:"cfg_used_kernel_errno_guards"`
	CFGFailure                 string                `json:"cfg_failure"`
	CFGBlocks                  []ClangCFGBlock       `json:"cfg_blocks"`
}

type ClangCallTarget struct {
	Name                string `json:"name"`
	File                string `json:"file"`
	ReturnType          string `json:"return_type,omitempty"`
	ReturnTypeCanonical string `json:"return_type_canonical,omitempty"`
	ReturnTypeClass     string `json:"return_type_class,omitempty"`
	ReturnTypeSigned    bool   `json:"return_type_signed,omitempty"`
	ReturnTypeBits      int    `json:"return_type_bits,omitempty"`
	Static              bool   `json:"static"`
	Inline              bool   `json:"inline"`
	SemanticHash        string `json:"semantic_hash"`
	Line                int    `json:"line"`
	FunctionID          string `json:"-"`
}

type ClangIndirectTarget struct {
	Expression          string `json:"expression"`
	StructType          string `json:"struct_type"`
	Field               string `json:"field"`
	ReturnType          string `json:"return_type,omitempty"`
	ReturnTypeSpelling  string `json:"return_type_spelling,omitempty"`
	ReturnTypeCanonical string `json:"return_type_canonical,omitempty"`
	ReturnTypeClass     string `json:"return_type_class,omitempty"`
	ReturnTypeSigned    bool   `json:"return_type_signed,omitempty"`
	ReturnTypeBits      int    `json:"return_type_bits,omitempty"`
}

type ClangCallSite struct {
	ID                  string                  `json:"id"`
	Direct              bool                    `json:"direct"`
	Reachable           bool                    `json:"reachable"`
	BlockID             int                     `json:"block_id,omitempty"`
	HasBlock            bool                    `json:"has_block"`
	Name                string                  `json:"name,omitempty"`
	Expression          string                  `json:"expression,omitempty"`
	ResultUse           string                  `json:"result_use"`
	ResultVariable      string                  `json:"result_variable,omitempty"`
	ReturnType          string                  `json:"return_type"`
	ReturnTypeSpelling  string                  `json:"return_type_spelling,omitempty"`
	ReturnTypeCanonical string                  `json:"return_type_canonical,omitempty"`
	ReturnTypeClass     string                  `json:"return_type_class,omitempty"`
	ReturnTypeSigned    bool                    `json:"return_type_signed,omitempty"`
	ReturnTypeBits      int                     `json:"return_type_bits,omitempty"`
	Arguments           []string                `json:"arguments,omitempty"`
	ArgumentConstants   []string                `json:"argument_constants,omitempty"`
	CallbackArguments   []ClangCallbackArgument `json:"callback_arguments,omitempty"`
	Line                int                     `json:"line,omitempty"`
	Column              int                     `json:"column,omitempty"`
	SpellingLine        int                     `json:"spelling_line,omitempty"`
	SpellingColumn      int                     `json:"spelling_column,omitempty"`
	MacroExpansion      bool                    `json:"macro_expansion,omitempty"`
}

type ClangCallbackArgument struct {
	Index     int               `json:"index"`
	Complete  bool              `json:"complete"`
	MayBeNull bool              `json:"may_be_null,omitempty"`
	Targets   []ClangCallTarget `json:"targets,omitempty"`
}

type LLVMHookFact struct {
	Hook                      string   `json:"hook"`
	Function                  string   `json:"function"`
	SourceFunction            string   `json:"source_function,omitempty"`
	SourceFile                string   `json:"source_file,omitempty"`
	SourceLine                int      `json:"source_line,omitempty"`
	SourceColumn              int      `json:"source_column,omitempty"`
	InlinedAtFunctions        []string `json:"inlined_at_functions,omitempty"`
	ResultUsed                bool     `json:"result_used"`
	ControlsBranch            bool     `json:"controls_branch"`
	ReachesReturn             bool     `json:"reaches_return"`
	MustReturnExact           bool     `json:"must_return_exact"`
	MustReturnNegativeOnError bool     `json:"must_return_negative_on_error"`
	MustReturnNegativeOnFalse bool     `json:"must_return_negative_on_false"`
	MustReturnNegativeOnTrue  bool     `json:"must_return_negative_on_true"`
	UseKinds                  []string `json:"use_kinds,omitempty"`
	Verification              string   `json:"verification"`
	Module                    string   `json:"module,omitempty"`
}

type LLVMCallFact struct {
	Kind                                 string   `json:"kind"`
	Hook                                 string   `json:"hook,omitempty"`
	Callee                               string   `json:"callee"`
	Function                             string   `json:"function"`
	SourceFunction                       string   `json:"source_function,omitempty"`
	SourceFile                           string   `json:"source_file,omitempty"`
	SourceLine                           int      `json:"source_line,omitempty"`
	SourceColumn                         int      `json:"source_column,omitempty"`
	InlinedAtFunctions                   []string `json:"inlined_at_functions,omitempty"`
	ResultUsed                           bool     `json:"result_used"`
	ControlsBranch                       bool     `json:"controls_branch"`
	ReachesReturn                        bool     `json:"reaches_return"`
	MustReturnExact                      bool     `json:"must_return_exact"`
	MustReturnNegativeOnError            bool     `json:"must_return_negative_on_error"`
	MustReturnNegativeOnFalse            bool     `json:"must_return_negative_on_false"`
	MustReturnNegativeOnTrue             bool     `json:"must_return_negative_on_true"`
	MustReturnNonnegativeOnZero          bool     `json:"must_return_nonnegative_on_zero"`
	MustReturnNonnegativeOnPositive      bool     `json:"must_return_nonnegative_on_positive"`
	MustPreserveNonnegativeSuccess       bool     `json:"must_preserve_nonnegative_success"`
	MustReturnValidPointerOnValidPointer bool     `json:"must_return_valid_pointer_on_valid_pointer"`
	MustPreserveValidPointerSuccess      bool     `json:"must_preserve_valid_pointer_success"`
	FunctionHasReturn                    bool     `json:"function_has_return"`
	FunctionMustReturnNonnegative        bool     `json:"function_must_return_nonnegative"`
	FunctionMustReturnNonpositive        bool     `json:"function_must_return_nonpositive"`
	FunctionMustReturnNonNull            bool     `json:"function_must_return_nonnull"`
	FunctionMustReturnValidPointer       bool     `json:"function_must_return_valid_pointer"`
	FunctionMustReturnTrue               bool     `json:"function_must_return_true"`
	FunctionPreservedPointeeArguments    []int    `json:"function_preserved_pointee_arguments,omitempty"`
	DoesNotAccessMemory                  bool     `json:"does_not_access_memory"`
	OnlyReadsMemory                      bool     `json:"only_reads_memory"`
	UseKinds                             []string `json:"use_kinds,omitempty"`
	Verification                         string   `json:"verification"`
	Module                               string   `json:"module,omitempty"`
}

type OperationTarget struct {
	StructType string
	Table      string
	Field      string
	Function   string
	File       string
}

type OperationTableInfo struct {
	StructType       string
	Table            string
	File             string
	Const            bool
	Complete         bool
	VerifiedByClang  bool
	FieldTargets     map[string]string
	FieldTargetFiles map[string]string
	NullFields       map[string]bool
	UnknownFields    map[string]bool
}

type ClangOperationFieldTarget struct {
	Field    string `json:"field"`
	Function string `json:"function"`
	File     string `json:"file"`
}

type ClangOperationTableRecord struct {
	Kind          string                      `json:"kind"`
	StructType    string                      `json:"struct_type"`
	Table         string                      `json:"table"`
	File          string                      `json:"file"`
	Const         bool                        `json:"const"`
	Complete      bool                        `json:"complete"`
	FieldTargets  []ClangOperationFieldTarget `json:"field_targets"`
	NullFields    []string                    `json:"null_fields"`
	UnknownFields []string                    `json:"unknown_fields"`
}

type IndirectCallResolution struct {
	Expression      string   `json:"expression"`
	Kind            string   `json:"kind"`
	TableType       string   `json:"table_type,omitempty"`
	Field           string   `json:"field,omitempty"`
	Targets         []string `json:"targets"`
	Tables          []string `json:"tables,omitempty"`
	TargetSetClosed bool     `json:"target_set_closed,omitempty"`
}

type IndirectCallEvidence struct {
	Caller          string   `json:"caller"`
	Expression      string   `json:"expression"`
	Kind            string   `json:"kind"`
	TableType       string   `json:"table_type,omitempty"`
	Field           string   `json:"field,omitempty"`
	Target          string   `json:"target"`
	Tables          []string `json:"tables,omitempty"`
	TargetSetClosed bool     `json:"target_set_closed,omitempty"`
}

type UnresolvedProofEdge struct {
	Domain          string `json:"domain"`
	Caller          string `json:"caller"`
	Kind            string `json:"kind"`
	Category        string `json:"category"`
	ResolutionScope string `json:"resolution_scope"`
	Symbol          string `json:"symbol,omitempty"`
	Expression      string `json:"expression,omitempty"`
	Detail          string `json:"detail"`
}

type DomainProofEligibility struct {
	Status        string   `json:"status"`
	PositiveProof bool     `json:"positive_proof"`
	NegativeProof bool     `json:"negative_proof"`
	Reasons       []string `json:"reasons"`
}

type SyscallProofEligibility struct {
	LSM     DomainProofEligibility `json:"lsm"`
	SIGKILL DomainProofEligibility `json:"sigkill"`
}

type ClassificationNegativeReasons struct {
	LSM     []string `json:"lsm"`
	SIGKILL []string `json:"sigkill"`
}

type FunctionSummary struct {
	ReachableLSMHooks       []string              `json:"reachable_lsm_hooks"`
	ReachableSigChecks      []string              `json:"reachable_signal_checks"`
	ReachableFuncs          []string              `json:"reachable_functions"`
	AlwaysLSMHooks          []string              `json:"always_lsm_hooks"`
	AlwaysSigChecks         []string              `json:"always_signal_checks"`
	ValidatedLSMHooks       []string              `json:"validated_lsm_hooks"`
	ValidatedSigChecks      []string              `json:"validated_signal_checks"`
	MustPassLSMHooks        []string              `json:"must_pass_lsm_hooks"`
	InactiveLSMHooks        []string              `json:"inactive_config_lsm_hooks"`
	NormalPathFuncs         []string              `json:"normal_path_functions"`
	StrongSigChecks         []string              `json:"strong_sig_checks"`
	CurrentReachableSignals []string              `json:"-"`
	CurrentAlwaysSignals    []string              `json:"-"`
	UnknownSubjectSignals   []string              `json:"-"`
	SignalPathFuncs         []string              `json:"-"`
	SignalCheckPaths        []SignalCheckPath     `json:"-"`
	AlwaysSignalCheckPaths  []SignalCheckPath     `json:"-"`
	LSMProofGaps            []UnresolvedProofEdge `json:"-"`
	SignalReachabilityGaps  []UnresolvedProofEdge `json:"-"`
	SignalAbortGaps         []UnresolvedProofEdge `json:"-"`
	SignalProofGaps         []UnresolvedProofEdge `json:"-"`
	SignalStats             SignalTraversalStats  `json:"-"`
}

type SignalTraversalStats struct {
	VisitedStates       int
	DominanceSkips      int
	DominatedStates     int
	TransitionCacheHits int
	TransitionBuilds    int
}

type IncrementalReportProgress struct {
	SchemaVersion                 int                       `json:"schema_version"`
	Status                        string                    `json:"status"`
	TotalSyscalls                 int                       `json:"total_syscalls"`
	CompletedSyscalls             int                       `json:"completed_syscalls"`
	CompletedApplicableSyscalls   int                       `json:"completed_applicable_syscalls"`
	UnavailableSyscalls           int                       `json:"unavailable_syscalls"`
	CompletedRatio                float64                   `json:"completed_ratio"`
	StartedAt                     string                    `json:"started_at"`
	UpdatedAt                     string                    `json:"updated_at"`
	ElapsedMilliseconds           int64                     `json:"elapsed_milliseconds"`
	LastCompleted                 *IncrementalSyscallResult `json:"last_completed,omitempty"`
	LSMClassifications            map[string]int            `json:"lsm_classifications"`
	SIGKILLClassifications        map[string]int            `json:"sigkill_classifications"`
	LSMUncertainSyscalls          int                       `json:"lsm_uncertain_syscalls"`
	LSMUncertainRatio             float64                   `json:"lsm_uncertain_ratio"`
	SIGKILLUncertainSyscalls      int                       `json:"sigkill_uncertain_syscalls"`
	SIGKILLUncertainRatio         float64                   `json:"sigkill_uncertain_ratio"`
	EitherDomainUncertainSyscalls int                       `json:"either_domain_uncertain_syscalls"`
	EitherDomainUncertainRatio    float64                   `json:"either_domain_uncertain_ratio"`
	UnresolvedProofSyscalls       int                       `json:"unresolved_proof_syscalls"`
	UnresolvedProofSyscallRatio   float64                   `json:"unresolved_proof_syscall_ratio"`
	UnresolvedProofEdges          int                       `json:"unresolved_proof_edges"`
	UnresolvedLSMProofEdges       int                       `json:"unresolved_lsm_proof_edges"`
	UnresolvedSIGKILLProofEdges   int                       `json:"unresolved_sigkill_proof_edges"`
	UnresolvedUnknownDomainEdges  int                       `json:"unresolved_unknown_domain_edges"`
}

type IncrementalSyscallResult struct {
	Number                int    `json:"number"`
	ABI                   string `json:"abi"`
	Name                  string `json:"name"`
	LSMClassification     string `json:"lsm_classification"`
	SIGKILLClassification string `json:"sigkill_classification"`
	UnresolvedProofEdges  int    `json:"unresolved_proof_edges"`
	ElapsedMilliseconds   int64  `json:"elapsed_milliseconds"`
	Checkpoint            string `json:"checkpoint"`
}

type signalDominanceState struct {
	constants            map[string]string
	operationConstraints map[string][]string
}

type SignalCheckCategories struct {
	GroupExit      []string `json:"group_exit"`
	FatalPending   []string `json:"fatal_pending"`
	GenericPending []string `json:"generic_pending"`
}

type SignalCheckPath struct {
	Check             string                 `json:"check"`
	CallSiteID        string                 `json:"callsite_id,omitempty"`
	Category          string                 `json:"category"`
	SIGKILLRelevance  string                 `json:"sigkill_relevance"`
	Subject           string                 `json:"subject"`
	Traversal         string                 `json:"traversal"`
	Function          string                 `json:"function"`
	BlocksOperation   string                 `json:"blocks_operation"`
	TerminatesSyscall string                 `json:"terminates_syscall"`
	ErrnoPropagation  string                 `json:"errno_propagation"`
	FailureEncoding   string                 `json:"failure_encoding"`
	AbortEffect       string                 `json:"abort_effect"`
	ProofPath         []string               `json:"proof_path"`
	IndirectEdges     []IndirectCallEvidence `json:"indirect_edges,omitempty"`
}

type LSMPathCoverageProof struct {
	Status              string                `json:"status"`
	Hooks               []string              `json:"hooks"`
	SuccessPathHookSets [][]string            `json:"success_path_hook_sets"`
	ProofMethods        []string              `json:"proof_methods"`
	ProofFunctions      []string              `json:"proof_functions"`
	HookProofPaths      map[string][]string   `json:"hook_proof_paths"`
	BypassProofPath     []string              `json:"bypass_proof_path,omitempty"`
	BypassProofMethod   string                `json:"bypass_proof_method,omitempty"`
	UnprovenBypassPath  []string              `json:"unproven_bypass_path,omitempty"`
	Reasons             []string              `json:"reasons"`
	Unresolved          []UnresolvedProofEdge `json:"unresolved_edges,omitempty"`
	CoveredUnresolved   []UnresolvedProofEdge `json:"covered_unresolved_edges,omitempty"`
}

type SIGKILLPathCoverageProof struct {
	Status               string                `json:"status"`
	Checks               []string              `json:"checks"`
	SuccessPathCheckSets [][]string            `json:"success_path_check_sets"`
	ProofMethods         []string              `json:"proof_methods"`
	ProofFunctions       []string              `json:"proof_functions"`
	CheckProofPaths      map[string][]string   `json:"check_proof_paths"`
	BypassProofPath      []string              `json:"bypass_proof_path,omitempty"`
	BypassProofMethod    string                `json:"bypass_proof_method,omitempty"`
	UnprovenBypassPath   []string              `json:"unproven_bypass_path,omitempty"`
	Reasons              []string              `json:"reasons"`
	Unresolved           []UnresolvedProofEdge `json:"unresolved_edges,omitempty"`
	CoveredUnresolved    []UnresolvedProofEdge `json:"covered_unresolved_edges,omitempty"`
}

type LSMErrorEffect struct {
	Hook              string         `json:"hook"`
	BPFHook           string         `json:"bpf_hook,omitempty"`
	HookKind          string         `json:"hook_kind"`
	CallsiteFunctions []string       `json:"callsite_functions"`
	BlocksOperation   string         `json:"blocks_operation"`
	TerminatesSyscall string         `json:"terminates_syscall"`
	ErrnoPropagation  string         `json:"errno_propagation"`
	FailureEncoding   string         `json:"failure_encoding"`
	OverwriteSites    []string       `json:"overwrite_sites"`
	ProofPath         []string       `json:"proof_path"`
	ProofMethod       string         `json:"proof_method,omitempty"`
	LLVMVerification  string         `json:"llvm_verification"`
	LLVMEvidence      []LLVMHookFact `json:"llvm_evidence,omitempty"`
}

type UnprovenLSMCandidate struct {
	Hook     string `json:"hook"`
	Function string `json:"function"`
	HookKind string `json:"hook_kind"`
	Reason   string `json:"reason"`
}

type SyscallReport struct {
	Number                  int                           `json:"number"`
	ABI                     string                        `json:"abi"`
	Name                    string                        `json:"name"`
	Entry                   string                        `json:"entry"`
	Start                   string                        `json:"start"`
	LinkedSymbol            string                        `json:"linked_symbol,omitempty"`
	LinkedSymbolType        string                        `json:"linked_symbol_type,omitempty"`
	Availability            string                        `json:"availability"`
	AvailabilityReason      string                        `json:"availability_reason,omitempty"`
	StartFound              bool                          `json:"start_found"`
	DirectLSMFunctions      []string                      `json:"direct_lsm_functions"`
	DirectSignalFuncs       []string                      `json:"direct_signal_functions"`
	ReachableLSMHooks       []string                      `json:"reachable_lsm_hooks"`
	ReachableSigChecks      []string                      `json:"reachable_signal_checks"`
	ReachableSigCategories  SignalCheckCategories         `json:"reachable_signal_check_categories"`
	SignalCheckPaths        []SignalCheckPath             `json:"signal_check_paths"`
	AlwaysLSMHooks          []string                      `json:"always_lsm_hooks"`
	AlwaysSigChecks         []string                      `json:"always_signal_checks"`
	AlwaysSigCategories     SignalCheckCategories         `json:"always_signal_check_categories"`
	ValidatedLSMHooks       []string                      `json:"validated_lsm_hooks"`
	ValidatedSigChecks      []string                      `json:"validated_signal_checks"`
	MustPassLSMHooks        []string                      `json:"must_pass_lsm_hooks"`
	InactiveLSMHooks        []string                      `json:"inactive_config_lsm_hooks"`
	OptionalLSMHooks        []string                      `json:"optional_lsm_hooks"`
	NormalPathFunctions     []string                      `json:"normal_path_functions"`
	StrongSigChecks         []string                      `json:"strong_sig_checks"`
	ConditionalLSMHooks     []string                      `json:"conditional_lsm_hooks"`
	ConditionalSigChecks    []string                      `json:"conditional_signal_checks"`
	ReachableFunctions      []string                      `json:"reachable_functions"`
	SuccessPathFunctions    []string                      `json:"success_path_functions"`
	RawReachableFunctions   []string                      `json:"raw_reachable_functions,omitempty"`
	CallTreeFile            string                        `json:"call_tree_file"`
	RawCallTreeFile         string                        `json:"raw_call_tree_file,omitempty"`
	ContainsLSMHook         bool                          `json:"contains_lsm_hook"`
	ContainsSignalChecks    bool                          `json:"contains_signal_checks"`
	LSMReachability         string                        `json:"lsm_reachability"`
	SignalReachability      string                        `json:"signal_reachability"`
	ValidatedLSMReach       string                        `json:"validated_lsm_reachability"`
	ValidatedSignalReach    string                        `json:"validated_signal_reachability"`
	HasSigkillChecks        bool                          `json:"has_sigkill_related_checks"`
	EffectiveLSMHooks       []string                      `json:"effective_enforcing_lsm_hooks"`
	CertifiedLSMHooks       []string                      `json:"certified_enforcing_lsm_hooks"`
	CertifiedBPFLSMHooks    []string                      `json:"certified_bpf_lsm_hooks"`
	LSMErrorEffects         []LSMErrorEffect              `json:"lsm_error_effects"`
	LSMPathCoverage         LSMPathCoverageProof          `json:"lsm_path_coverage"`
	SIGKILLPathCoverage     SIGKILLPathCoverageProof      `json:"sigkill_path_coverage"`
	UnprovenLSMCandidates   []UnprovenLSMCandidate        `json:"unproven_lsm_candidates"`
	CurrentReachableSig     []string                      `json:"current_task_reachable_signal_checks"`
	CurrentAlwaysSig        []string                      `json:"current_task_always_signal_checks"`
	UnknownSubjectSig       []string                      `json:"unknown_subject_signal_checks"`
	AlwaysSignalCheckPaths  []SignalCheckPath             `json:"always_signal_check_paths"`
	ProofEligibility        SyscallProofEligibility       `json:"proof_eligibility"`
	LSMClassification       string                        `json:"lsm_classification"`
	SIGKILLClassification   string                        `json:"sigkill_classification"`
	LSMEnforcementState     string                        `json:"lsm_enforcement_state"`
	SIGKILLEnforcementState string                        `json:"sigkill_enforcement_state"`
	NegativeReasons         ClassificationNegativeReasons `json:"negative_reasons"`
	UnresolvedProofEdges    []UnresolvedProofEdge         `json:"unresolved_edges_in_proof_cone"`
	AnalysisStats           SignalTraversalStats          `json:"-"`
}

type Analyzer struct {
	cfg                     Config
	functions               map[string]*FunctionInfo
	nameIndex               map[string][]string
	globalIndex             map[string][]string
	staticIndex             map[string]map[string][]string
	syscalls                []SyscallEntry
	allSyscalls             []SyscallEntry
	summaryCache            map[string]FunctionSummary
	allScanCache            map[string]prefixScanResult
	validScanCache          map[string]prefixScanResult
	successCache            map[string]prefixScanResult
	contextScanCache        map[string]prefixScanResult
	kernelSuccessCache      map[string]prefixScanResult
	kernelContextCache      map[string]prefixScanResult
	signalScanCache         map[string]prefixScanResult
	callRegex               *regexp.Regexp
	lsmRegex                *regexp.Regexp
	sigRegexes              map[string]*regexp.Regexp
	syscallMacroRE          *regexp.Regexp
	compileUnits            map[string]CompileCommand
	compileVariants         map[string][]CompileCommand
	inputValidation         InputValidation
	configPath              string
	configSymbols           map[string]bool
	configValues            map[string]string
	hasKernelConfig         bool
	structMembers           map[string][]string
	memberAliases           map[string][][]string
	operationTargets        map[string][]OperationTarget
	operationLinks          map[string][]string
	operationTables         map[string]*OperationTableInfo
	operationTablesByName   map[string][]string
	llvmFailures            []string
	signalTransitionCache   map[string][]resolvedContextCall
	lsmCoverageCache        map[string]lsmCoverageResult
	signalCoverageCache     map[string]signalCoverageResult
	sigkillCoverageMu       *sync.Mutex
	successWitnessCache     map[string]functionSuccessWitness
	effectFreeSuccessCache  map[string]functionSuccessWitness
	cfgCycleEdgeCache       map[string]bool
	lsmEffectSourceCache    map[string]effectSourceState
	sigEffectSourceCache    map[string]effectSourceState
	lsmEffectWitnessCache   map[string]string
	sigEffectWitnessCache   map[string]string
	lsmFailureKindCache     map[string]string
	sigFailureKindCache     map[string]string
	lsmEffectSourcesBuilt   bool
	sigEffectSourcesBuilt   bool
	buildingEffectSources   bool
	displayIndex            map[string]string
	lsmWrapperHooks         map[string]string
	lsmHookNames            map[string]bool
	lsmMetadataBuilt        bool
	frontendCacheStatus     string
	frontendCacheHash       string
	frontendCacheLegacyHash string
	frontendCacheBuiltAt    string
}

const (
	contextReturnRequirementKey = "@return"
	contextCallbackPrefix       = "@callback:"
	contextCallbackSeparator    = "\x1d"
	contextSuccessAssumePrefix  = "@success-assume:"
)

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() Config {
	kernelRoot := flag.String("kernel-root", "/workspace/git/linux-v5.15", "Linux kernel source root")
	kernelAlias := flag.String("kernel", "", "alias for -kernel-root")
	compileDB := flag.String("compile-db", "", "configured compile_commands.json used for preprocessing and Clang AST/CFG extraction")
	frontendCache := flag.String("frontend-cache", "auto", "persistent configured frontend cache path; auto stores it beside compile_commands.json, off disables it")
	rebuildFrontendCache := flag.Bool("rebuild-frontend-cache", false, "ignore and replace any existing configured frontend cache")
	prepareFrontendOnly := flag.Bool("prepare-frontend-only", false, "prepare or validate the persistent frontend cache, then exit before syscall reports")
	requireFrontendCache := flag.Bool("require-frontend-cache", false, "fail instead of rebuilding when the persistent frontend cache is absent or stale")
	outDir := flag.String("out-dir", "/workspace/test/systematic_analysis/output", "analysis output directory")
	syscallList := flag.String("syscalls", "", "comma-separated syscall filter; empty analyzes all x86-64 common/64 syscalls")
	maxDepth := flag.Int("max-depth", 0, "max traversal depth for call tree files; 0 means unlimited")
	scanAll := flag.Bool("scan-all", true, "scan the full configured kernel tree (required for final certification)")
	allowIncompleteInput := flag.Bool("allow-incomplete-input", false, "allow development runs with incomplete build artifacts; final classifications remain uncertified")
	emitRaw := flag.Bool("emit-raw", false, "emit branch-insensitive diagnostic graphs, including debug and failure-only paths")
	emitFunctionIndex := flag.Bool("emit-function-index", false, "emit the complete diagnostic function index (can require several gigabytes)")
	preprocessJobs := flag.Int("preprocess-jobs", min(4, runtime.NumCPU()), "parallel compiler preprocessors used with -compile-db")
	frontend := flag.String("frontend", "hybrid", "analysis frontend: hybrid (Clang AST/CFG plus selective LLVM) or legacy")
	clangExtractor := flag.String("clang-extractor", defaultHelperPath("clang_kernel_extractor"), "Clang AST/CFG extractor executable")
	clangJobs := flag.Int("clang-jobs", min(4, runtime.NumCPU()), "parallel Clang extraction processes used by the hybrid frontend")
	llvmVerify := flag.Bool("llvm-verify", true, "run selective LLVM IR hook-result verification in hybrid mode")
	llvmVerifier := flag.String("llvm-verifier", defaultHelperPath("llvm_hook_verifier"), "LLVM hook verifier executable")
	llvmJobs := flag.Int("llvm-jobs", min(2, runtime.NumCPU()), "parallel LLVM IR verification jobs")
	reportJobs := flag.Int("report-jobs", min(2, runtime.NumCPU()), "parallel syscall report workers")
	flag.Parse()

	filter := make(map[string]struct{})
	if trimmed := strings.TrimSpace(*syscallList); trimmed != "" {
		for _, item := range strings.Split(trimmed, ",") {
			name := strings.TrimSpace(item)
			if name == "" {
				continue
			}
			filter[name] = struct{}{}
		}
	}
	root := *kernelRoot
	if strings.TrimSpace(*kernelAlias) != "" {
		root = *kernelAlias
	}

	return Config{
		KernelRoot:           root,
		CompileDB:            *compileDB,
		FrontendCache:        strings.TrimSpace(*frontendCache),
		RebuildFrontendCache: *rebuildFrontendCache,
		PrepareFrontendOnly:  *prepareFrontendOnly,
		RequireFrontendCache: *requireFrontendCache,
		OutDir:               *outDir,
		Syscalls:             filter,
		MaxDepth:             *maxDepth,
		ScanAll:              *scanAll,
		AllowIncompleteInput: *allowIncompleteInput,
		EmitRaw:              *emitRaw,
		EmitFunctionIndex:    *emitFunctionIndex,
		PreprocessJobs:       max(1, *preprocessJobs),
		Frontend:             strings.ToLower(strings.TrimSpace(*frontend)),
		ClangExtractor:       *clangExtractor,
		ClangJobs:            max(1, *clangJobs),
		LLVMVerify:           *llvmVerify,
		LLVMVerifier:         *llvmVerifier,
		LLVMJobs:             max(1, *llvmJobs),
		ReportJobs:           max(1, *reportJobs),
	}
}

func defaultHelperPath(name string) string {
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), name)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
	}
	return filepath.Join(".", name)
}

func run(cfg Config) error {
	var err error
	cfg.KernelRoot, err = filepath.Abs(cfg.KernelRoot)
	if err != nil {
		return fmt.Errorf("resolve kernel root: %w", err)
	}
	if cfg.CompileDB != "" {
		cfg.CompileDB, err = filepath.Abs(cfg.CompileDB)
		if err != nil {
			return fmt.Errorf("resolve compile database: %w", err)
		}
	}
	cfg.FrontendCache, err = resolveFrontendCachePath(cfg)
	if err != nil {
		return err
	}
	if cfg.PrepareFrontendOnly && cfg.FrontendCache == "" {
		return errors.New("-prepare-frontend-only requires an enabled -frontend-cache")
	}
	if cfg.RequireFrontendCache && cfg.FrontendCache == "" {
		return errors.New("-require-frontend-cache requires an enabled -frontend-cache")
	}
	if cfg.RequireFrontendCache && cfg.RebuildFrontendCache {
		return errors.New("-require-frontend-cache and -rebuild-frontend-cache cannot be used together")
	}
	switch cfg.Frontend {
	case "hybrid", "legacy":
	default:
		return fmt.Errorf("unsupported -frontend %q: expected hybrid or legacy", cfg.Frontend)
	}
	if cfg.Frontend == "hybrid" && cfg.CompileDB == "" {
		return errors.New("-frontend hybrid requires -compile-db")
	}
	if cfg.ClangExtractor != "" {
		cfg.ClangExtractor, err = filepath.Abs(cfg.ClangExtractor)
		if err != nil {
			return fmt.Errorf("resolve clang extractor: %w", err)
		}
	}
	if cfg.LLVMVerifier != "" {
		cfg.LLVMVerifier, err = filepath.Abs(cfg.LLVMVerifier)
		if err != nil {
			return fmt.Errorf("resolve LLVM verifier: %w", err)
		}
	}

	analyzer := &Analyzer{
		cfg:                   cfg,
		functions:             make(map[string]*FunctionInfo),
		nameIndex:             make(map[string][]string),
		globalIndex:           make(map[string][]string),
		staticIndex:           make(map[string]map[string][]string),
		summaryCache:          make(map[string]FunctionSummary),
		allScanCache:          make(map[string]prefixScanResult),
		validScanCache:        make(map[string]prefixScanResult),
		successCache:          make(map[string]prefixScanResult),
		contextScanCache:      make(map[string]prefixScanResult),
		kernelSuccessCache:    make(map[string]prefixScanResult),
		kernelContextCache:    make(map[string]prefixScanResult),
		signalScanCache:       make(map[string]prefixScanResult),
		structMembers:         make(map[string][]string),
		memberAliases:         make(map[string][][]string),
		operationTargets:      make(map[string][]OperationTarget),
		operationLinks:        make(map[string][]string),
		operationTables:       make(map[string]*OperationTableInfo),
		operationTablesByName: make(map[string][]string),
		signalTransitionCache: make(map[string][]resolvedContextCall),
		lsmCoverageCache:      make(map[string]lsmCoverageResult),
		signalCoverageCache:   make(map[string]signalCoverageResult),
		sigkillCoverageMu:     &sync.Mutex{},
		successWitnessCache:   make(map[string]functionSuccessWitness),
		cfgCycleEdgeCache:     make(map[string]bool),
		lsmEffectSourceCache:  make(map[string]effectSourceState),
		sigEffectSourceCache:  make(map[string]effectSourceState),
		lsmEffectWitnessCache: make(map[string]string),
		sigEffectWitnessCache: make(map[string]string),
		lsmFailureKindCache:   make(map[string]string),
		sigFailureKindCache:   make(map[string]string),
		displayIndex:          make(map[string]string),
		lsmWrapperHooks:       make(map[string]string),
		lsmHookNames:          make(map[string]bool),
		configValues:          make(map[string]string),
		callRegex:             regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`),
		lsmRegex:              regexp.MustCompile(`\bsecurity_[A-Za-z0-9_]+\s*\(`),
		sigRegexes: map[string]*regexp.Regexp{
			"fatal_signal_pending":   regexp.MustCompile(`\bfatal_signal_pending\s*\(`),
			"signal_pending":         regexp.MustCompile(`\bsignal_pending\s*\(`),
			"__fatal_signal_pending": regexp.MustCompile(`\b__fatal_signal_pending\s*\(`),
			"task_sigpending":        regexp.MustCompile(`\btask_sigpending\s*\(`),
			"signal_group_exit":      regexp.MustCompile(`\bsignal_group_exit\s*\(`),
			"signal_pending_state":   regexp.MustCompile(`\bsignal_pending_state\s*\(`),
			"SIGNAL_GROUP_EXIT":      regexp.MustCompile(`\bSIGNAL_GROUP_EXIT\b`),
		},
		syscallMacroRE: regexp.MustCompile(`(?:^|\n)\s*((?:COMPAT_)?SYSCALL_DEFINE[0-6])\s*\(\s*([A-Za-z0-9_]+)`),
	}

	if err := analyzer.loadKernelConfig(); err != nil {
		return err
	}
	if cfg.CompileDB != "" {
		if err := analyzer.loadCompileDatabase(); err != nil {
			return err
		}
	}
	if err := analyzer.loadSyscalls(); err != nil {
		return err
	}
	if err := analyzer.validateAnalysisInput(); err != nil {
		return err
	}
	cacheLoaded := false
	if cfg.FrontendCache != "" {
		fingerprint, fingerprintErr := analyzer.frontendCacheFingerprint()
		if fingerprintErr != nil {
			return fingerprintErr
		}
		analyzer.frontendCacheHash = fingerprint
		if !cfg.RebuildFrontendCache {
			cacheLoaded, err = analyzer.loadFrontendCache(fingerprint)
			if err != nil {
				return err
			}
		} else {
			analyzer.frontendCacheStatus = "rebuild_requested"
		}
	}
	if !cacheLoaded && cfg.RequireFrontendCache {
		return fmt.Errorf(
			"configured frontend cache is not reusable (status=%s): rerun once with -prepare-frontend-only",
			analyzer.frontendCacheStatus,
		)
	}
	if cacheLoaded &&
		(analyzer.frontendCacheStatus == "hit_legacy" ||
			analyzer.frontendCacheStatus ==
				"hit_identity_migrated") {
		if err := analyzer.saveFrontendCache(
			analyzer.frontendCacheHash,
		); err != nil {
			return err
		}
	}
	if !cacheLoaded {
		if err := analyzer.indexStructMemberTypes(); err != nil {
			return err
		}
		if err := analyzer.indexFunctions(); err != nil {
			return err
		}
		if err := analyzer.buildLSMHookMetadata(); err != nil {
			return err
		}
		analyzer.reconfigureAllLSMHooks()
		analyzer.resolveCalls()
		if cfg.Frontend == "hybrid" && cfg.LLVMVerify {
			if err := analyzer.verifyLLVMHooks(); err != nil {
				return err
			}
		}
		if cfg.FrontendCache != "" {
			if err := analyzer.saveFrontendCache(analyzer.frontendCacheHash); err != nil {
				return err
			}
		} else {
			analyzer.frontendCacheStatus = "disabled"
		}
	} else {
		fmt.Fprintf(
			os.Stderr,
			"configured frontend cache: hit path=%s\n",
			cfg.FrontendCache,
		)
	}
	if cfg.PrepareFrontendOnly {
		fmt.Fprintf(
			os.Stderr,
			"configured frontend cache: ready status=%s path=%s\n",
			analyzer.frontendCacheStatus,
			cfg.FrontendCache,
		)
		return nil
	}
	return analyzer.writeReports()
}

func resolveFrontendCachePath(cfg Config) (string, error) {
	value := strings.TrimSpace(cfg.FrontendCache)
	switch strings.ToLower(value) {
	case "", "off", "none", "disabled":
		return "", nil
	case "auto":
		base := cfg.KernelRoot
		if cfg.CompileDB != "" {
			base = filepath.Dir(cfg.CompileDB)
		}
		return filepath.Join(
			base,
			".systematic-analysis",
			"configured-frontend-v2.gob.gz",
		), nil
	default:
		path, err := filepath.Abs(value)
		if err != nil {
			return "", fmt.Errorf("resolve frontend cache: %w", err)
		}
		return path, nil
	}
}

func (a *Analyzer) configuredTranslationUnitPaths() []string {
	paths := make([]string, 0, len(a.compileUnits))
	for path := range a.compileUnits {
		if filepath.Ext(path) != ".c" ||
			!shouldIndexFile(a.cfg.KernelRoot, path, a.cfg.ScanAll) {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (a *Analyzer) effectAnalysisSyscalls() []SyscallEntry {
	if len(a.allSyscalls) > 0 {
		return a.allSyscalls
	}
	return a.syscalls
}

func (a *Analyzer) resetAnalysisCachesAfterFrontendLoad() {
	a.summaryCache = make(map[string]FunctionSummary)
	a.allScanCache = make(map[string]prefixScanResult)
	a.validScanCache = make(map[string]prefixScanResult)
	a.successCache = make(map[string]prefixScanResult)
	a.contextScanCache = make(map[string]prefixScanResult)
	a.kernelSuccessCache = make(map[string]prefixScanResult)
	a.kernelContextCache = make(map[string]prefixScanResult)
	a.signalScanCache = make(map[string]prefixScanResult)
	a.signalTransitionCache = make(map[string][]resolvedContextCall)
	a.lsmCoverageCache = make(map[string]lsmCoverageResult)
	a.signalCoverageCache = make(map[string]signalCoverageResult)
	if a.sigkillCoverageMu == nil {
		a.sigkillCoverageMu = &sync.Mutex{}
	}
	a.successWitnessCache = make(map[string]functionSuccessWitness)
	a.effectFreeSuccessCache = make(map[string]functionSuccessWitness)
	a.lsmEffectSourceCache = make(map[string]effectSourceState)
	a.sigEffectSourceCache = make(map[string]effectSourceState)
	a.lsmEffectWitnessCache = make(map[string]string)
	a.sigEffectWitnessCache = make(map[string]string)
	a.lsmFailureKindCache = make(map[string]string)
	a.sigFailureKindCache = make(map[string]string)
	a.lsmEffectSourcesBuilt = false
	a.sigEffectSourcesBuilt = false
	a.buildingEffectSources = false
	for _, fn := range a.functions {
		fn.LSMEffectSourceState = ""
		fn.SIGEffectSourceState = ""
		fn.LSMEffectUnknownWitness = ""
		fn.SIGEffectUnknownWitness = ""
	}
	a.refreshLLVMPreservedEscapes()
}

func (a *Analyzer) refreshLLVMPreservedEscapes() {
	for _, fn := range a.functions {
		fn.CFGPreservedEscapes = nil
		if fn.Frontend != "clang-ast-cfg" ||
			fn.FrontendVariantConflict {
			continue
		}
		for _, identifier := range fn.CFGEscapedVariables {
			if a.addressEscapesOnlyThroughPreservingCalls(
				fn,
				identifier,
			) {
				fn.CFGPreservedEscapes = appendUnique(
					fn.CFGPreservedEscapes,
					identifier,
				)
			}
		}
	}
}

func (a *Analyzer) addressEscapesOnlyThroughPreservingCalls(
	fn *FunctionInfo,
	identifier string,
) bool {
	if fn == nil || identifier == "" {
		return false
	}
	addressPattern := regexp.MustCompile(
		`&\s*\(?\s*` + regexp.QuoteMeta(identifier) + `\b`,
	)
	addressUses := len(addressPattern.FindAllStringIndex(fn.Body, -1))
	if addressUses == 0 {
		return false
	}
	preservedUses := 0
	for _, site := range fn.CallSites {
		if !site.Direct {
			continue
		}
		ids, status := a.resolveCallee(fn, site.Name)
		if status != "resolved" || len(ids) != 1 {
			continue
		}
		callee := a.functions[ids[0]]
		if callee == nil {
			continue
		}
		for argumentIndex, argument := range site.Arguments {
			if !isDirectAddressOfIdentifier(
				argument,
				identifier,
			) {
				continue
			}
			if !llvmFunctionPreservesPointeeArgument(
				callee,
				argumentIndex,
			) {
				return false
			}
			preservedUses++
		}
	}
	return preservedUses > 0 && preservedUses == addressUses
}

func isDirectAddressOfIdentifier(
	expression, identifier string,
) bool {
	expression = compactExpression(stripSimpleCasts(
		strings.TrimSpace(expression),
	))
	if strings.HasPrefix(expression, "&(") &&
		strings.HasSuffix(expression, ")") {
		expression = "&" + expression[2:len(expression)-1]
	}
	return expression == "&"+identifier
}

func (a *Analyzer) loadKernelConfig() error {
	path := filepath.Join(a.cfg.KernelRoot, ".config")
	if a.cfg.CompileDB != "" {
		buildConfig := filepath.Join(filepath.Dir(a.cfg.CompileDB), ".config")
		if _, err := os.Stat(buildConfig); err == nil {
			path = buildConfig
		}
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read kernel config: %w", err)
	}
	a.configPath = path
	a.hasKernelConfig = true
	a.configSymbols = make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "CONFIG_"):
			name, value, ok := strings.Cut(line, "=")
			if ok {
				a.configSymbols[name] = value == "y" || value == "m"
				a.configValues[name] = strings.Trim(value, `"`)
			}
		case strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set"):
			name := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			a.configSymbols[name] = false
			a.configValues[name] = "n"
		}
	}
	return nil
}

func (a *Analyzer) loadSyscalls() error {
	tablePath := filepath.Join(a.cfg.KernelRoot, "arch/x86/entry/syscalls/syscall_64.tbl")
	file, err := os.Open(tablePath)
	if err != nil {
		return fmt.Errorf("open syscall table: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		abi := fields[1]
		if abi != "common" && abi != "64" {
			continue
		}

		name := fields[2]
		entry := ""
		if len(fields) >= 4 {
			entry = fields[3]
		}
		start := syscallStartCandidate(entry)
		availability := "unverified"
		availabilityReason := ""
		if entry == "" || entry == "sys_ni_syscall" {
			availability = "unavailable_table_slot"
			availabilityReason = "the x86-64 syscall table has no implementation entry for this ABI slot"
		}
		syscall := SyscallEntry{
			Number:             atoiSafe(fields[0]),
			ABI:                abi,
			Name:               name,
			Entry:              entry,
			Start:              start,
			Availability:       availability,
			AvailabilityReason: availabilityReason,
		}
		a.allSyscalls = append(a.allSyscalls, syscall)
		if len(a.cfg.Syscalls) > 0 {
			if _, ok := a.cfg.Syscalls[name]; !ok {
				continue
			}
		}
		a.syscalls = append(a.syscalls, syscall)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan syscall table: %w", err)
	}
	return nil
}

func (a *Analyzer) indexStructMemberTypes() error {
	return filepath.WalkDir(a.cfg.KernelRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == a.cfg.KernelRoot {
				return nil
			}
			if shouldSkipDir(a.cfg.KernelRoot, path, a.cfg.ScanAll) || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".h" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read struct declarations from %s: %w", path, err)
		}
		stripped := stripComments(string(raw))
		for key, targets := range extractStructMemberTypes(stripped) {
			for _, target := range targets {
				a.structMembers[key] = appendUnique(a.structMembers[key], target)
			}
		}
		for alias, chains := range extractStructMemberAliases(stripped) {
			for _, chain := range chains {
				a.memberAliases[alias] = appendUniqueStringSlice(a.memberAliases[alias], chain)
			}
		}
		return nil
	})
}

func extractStructMemberTypes(source string) map[string][]string {
	result := make(map[string][]string)
	structPattern := regexp.MustCompile(`\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+__[A-Za-z_][A-Za-z0-9_]*)*\s*\{`)
	pointerMemberPattern := regexp.MustCompile(`\b(?:const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+__[A-Za-z_][A-Za-z0-9_]*)*\s*\*+\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\b`)
	embeddedMemberPattern := regexp.MustCompile(`\b(?:const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|\[)`)
	for offset := 0; offset < len(source); {
		match := structPattern.FindStringSubmatchIndex(source[offset:])
		if match == nil {
			break
		}
		start := offset + match[0]
		openBrace := offset + match[1] - 1
		closeBrace, ok := findMatchingBrace(source, openBrace)
		if !ok {
			offset = start + 1
			continue
		}
		owner := source[offset+match[2] : offset+match[3]]
		body := source[openBrace+1 : closeBrace]
		for _, member := range pointerMemberPattern.FindAllStringSubmatch(body, -1) {
			key := structMemberKey(owner, member[2])
			result[key] = appendUnique(result[key], member[1])
		}
		for _, member := range embeddedMemberPattern.FindAllStringSubmatch(body, -1) {
			key := structMemberKey(owner, member[2])
			result[key] = appendUnique(result[key], member[1])
		}
		offset = closeBrace + 1
	}
	return result
}

func extractStructMemberAliases(source string) map[string][][]string {
	result := make(map[string][][]string)
	pattern := regexp.MustCompile(`(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*$`)
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		result[match[1]] = appendUniqueStringSlice(result[match[1]], strings.Split(match[2], "."))
	}
	return result
}

func appendUniqueStringSlice(values [][]string, value []string) [][]string {
	key := strings.Join(value, "\x00")
	for _, existing := range values {
		if strings.Join(existing, "\x00") == key {
			return values
		}
	}
	return append(values, append([]string(nil), value...))
}

func structMemberKey(owner, member string) string {
	return owner + "\x00" + member
}

func syscallStartCandidate(entry string) string {
	switch {
	case strings.HasPrefix(entry, "sys_"):
		return "__do_" + entry
	case strings.HasPrefix(entry, "compat_sys_"):
		return "__do_" + entry
	case strings.HasPrefix(entry, "__x64_sys_"), strings.HasPrefix(entry, "__ia32_sys_"), strings.HasPrefix(entry, "__x64_compat_sys_"), strings.HasPrefix(entry, "__ia32_compat_sys_"):
		idx := strings.Index(entry, "_sys_")
		if idx >= 0 {
			return "__do" + entry[idx:]
		}
	}
	return entry
}

func (a *Analyzer) indexFunctions() error {
	if a.cfg.CompileDB != "" {
		return a.indexConfiguredFunctions()
	}
	return filepath.WalkDir(a.cfg.KernelRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == a.cfg.KernelRoot {
				return nil
			}
			if shouldSkipDir(a.cfg.KernelRoot, path, a.cfg.ScanAll) {
				return filepath.SkipDir
			}
			switch d.Name() {
			case ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".c" {
			return nil
		}
		return a.parseFile(path)
	})
}

func (a *Analyzer) loadCompileDatabase() error {
	raw, err := os.ReadFile(a.cfg.CompileDB)
	if err != nil {
		return fmt.Errorf("read compile database: %w", err)
	}
	var commands []CompileCommand
	if err := json.Unmarshal(raw, &commands); err != nil {
		return fmt.Errorf("parse compile database: %w", err)
	}
	if len(commands) == 0 {
		return errors.New("compile database contains no commands")
	}

	a.compileUnits = make(map[string]CompileCommand, len(commands))
	a.compileVariants = make(map[string][]CompileCommand, len(commands))
	a.inputValidation.CompileCommandCount = len(commands)
	for _, command := range commands {
		if command.Directory == "" || command.File == "" {
			a.inputValidation.InvalidCompileCommands++
			continue
		}
		directory := command.Directory
		if !filepath.IsAbs(directory) {
			directory = filepath.Join(filepath.Dir(a.cfg.CompileDB), directory)
		}
		directory, err := filepath.Abs(directory)
		if err != nil {
			return fmt.Errorf("resolve compile command directory %q: %w", command.Directory, err)
		}
		file := command.File
		if !filepath.IsAbs(file) {
			file = filepath.Join(directory, file)
		}
		file = filepath.Clean(file)
		command.Directory = directory
		command.File = file
		a.compileVariants[file] = append(a.compileVariants[file], command)
	}
	for file, variants := range a.compileVariants {
		selected, ambiguous, auxiliaryCount := selectPrimaryCompileCommand(variants)
		a.compileUnits[file] = selected
		if len(variants) > 1 {
			a.inputValidation.DuplicateCompileSources++
		}
		a.inputValidation.AuxiliaryCompileVariants += auxiliaryCount
		if ambiguous {
			a.inputValidation.AmbiguousCompileVariants++
		}
	}
	a.inputValidation.UniqueCompileSources = len(a.compileUnits)
	if len(a.compileUnits) == 0 {
		return errors.New("compile database contains no usable commands")
	}
	return nil
}

func (a *Analyzer) indexConfiguredFunctions() error {
	paths := a.configuredTranslationUnitPaths()
	if len(paths) == 0 {
		return errors.New("compile database has no C files in the configured scan scope")
	}

	workerCount := min(a.cfg.PreprocessJobs, len(paths))
	fmt.Fprintf(os.Stderr, "configured preprocessing: %d translation units, %d workers\n", len(paths), workerCount)
	jobs := make(chan int)
	results := make(chan configuredSourceResult, workerCount)
	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				path := paths[index]
				source, err := configuredSource(a.compileUnits[path])
				results <- configuredSourceResult{index: index, path: path, source: source, err: err}
			}
		}()
	}
	go func() {
		for index := range paths {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	pending := make(map[int]configuredSourceResult, workerCount)
	next := 0
	completed := 0
	var firstErr error
	for result := range results {
		completed++
		if completed == 1 || completed%100 == 0 || completed == len(paths) {
			fmt.Fprintf(os.Stderr, "configured preprocessing: %d/%d\n", completed, len(paths))
		}
		pending[result.index] = result
		for {
			ordered, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			if ordered.err != nil && firstErr == nil {
				firstErr = fmt.Errorf("preprocess %s: %w", ordered.path, ordered.err)
			}
			if firstErr == nil {
				a.parseSource(ordered.path, ordered.source.Code, ordered.source.ActiveOriginal)
			}
			next++
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if a.cfg.Frontend == "hybrid" {
		return a.indexClangFunctions(paths)
	}
	return nil
}

type clangExtractionResult struct {
	index  int
	output string
	err    error
}

func (a *Analyzer) indexClangFunctions(paths []string) error {
	info, err := os.Stat(a.cfg.ClangExtractor)
	if err != nil {
		return fmt.Errorf("stat clang extractor %s: %w (build it with `make clang_kernel_extractor`)", a.cfg.ClangExtractor, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("clang extractor is not executable: %s", a.cfg.ClangExtractor)
	}

	tempDir, err := os.MkdirTemp("", "systematic-analysis-clang-")
	if err != nil {
		return fmt.Errorf("create Clang extraction temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	filteredCompileDB := filepath.Join(tempDir, "compile_commands.json")
	selectedCommands := make([]CompileCommand, 0, len(paths))
	for _, path := range paths {
		selectedCommands = append(selectedCommands, a.compileUnits[path])
	}
	if err := writeJSON(filteredCompileDB, selectedCommands); err != nil {
		return fmt.Errorf("write selected Clang compile database: %w", err)
	}

	workerCount := min(a.cfg.ClangJobs, len(paths))
	groups := make([][]string, workerCount)
	for index, path := range paths {
		groups[index%workerCount] = append(groups[index%workerCount], path)
	}
	fmt.Fprintf(os.Stderr, "Clang AST/CFG extraction: %d translation units, %d workers\n", len(paths), workerCount)

	results := make(chan clangExtractionResult, workerCount)
	var workers sync.WaitGroup
	for index, group := range groups {
		index, group := index, append([]string(nil), group...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			listPath := filepath.Join(tempDir, fmt.Sprintf("files-%d.txt", index))
			outputPath := filepath.Join(tempDir, fmt.Sprintf("index-%d.ndjson", index))
			content := strings.Join(group, "\n") + "\n"
			if writeErr := os.WriteFile(listPath, []byte(content), 0o600); writeErr != nil {
				results <- clangExtractionResult{index: index, err: fmt.Errorf("write Clang file list: %w", writeErr)}
				return
			}
			command := exec.Command(
				a.cfg.ClangExtractor,
				"--compile-db", filteredCompileDB,
				"--files-from", listPath,
				"--kernel-root", a.cfg.KernelRoot,
				"--output", outputPath,
			)
			command.Stderr = os.Stderr
			if runErr := command.Run(); runErr != nil {
				results <- clangExtractionResult{index: index, output: outputPath, err: fmt.Errorf("clang extractor worker %d: %w", index, runErr)}
				return
			}
			results <- clangExtractionResult{index: index, output: outputPath}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	ordered := make([]clangExtractionResult, workerCount)
	for result := range results {
		ordered[result.index] = result
	}
	for _, result := range ordered {
		if result.err != nil {
			return result.err
		}
	}
	for _, result := range ordered {
		if err := a.loadClangFunctionIndex(result.output); err != nil {
			return err
		}
	}
	a.pruneSupersededLegacyFunctions()
	a.rebuildFunctionIndexes()
	return nil
}

func (a *Analyzer) pruneSupersededLegacyFunctions() {
	clangDefinitions := make(map[string]struct{})
	for _, fn := range a.functions {
		if fn.Frontend != "clang-ast-cfg" {
			continue
		}
		clangDefinitions[fn.File+"\x00"+fn.Name] = struct{}{}
	}
	for id, fn := range a.functions {
		if fn.Frontend == "clang-ast-cfg" {
			continue
		}
		if _, ok := clangDefinitions[fn.File+"\x00"+fn.Name]; ok {
			delete(a.functions, id)
		}
	}
}

func (a *Analyzer) rebuildFunctionIndexes() {
	a.nameIndex = make(map[string][]string)
	a.globalIndex = make(map[string][]string)
	a.staticIndex = make(map[string]map[string][]string)
	a.displayIndex = make(map[string]string)
	ids := make([]string, 0, len(a.functions))
	for id := range a.functions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fn := a.functions[id]
		a.nameIndex[fn.Name] = appendUnique(a.nameIndex[fn.Name], id)
		a.displayIndex[fn.DisplayName] = id
		if fn.Inline {
			continue
		}
		if fn.Static {
			if a.staticIndex[fn.File] == nil {
				a.staticIndex[fn.File] = make(map[string][]string)
			}
			a.staticIndex[fn.File][fn.Name] = appendUnique(a.staticIndex[fn.File][fn.Name], id)
			continue
		}
		a.globalIndex[fn.Name] = appendUnique(a.globalIndex[fn.Name], id)
	}
}

func (a *Analyzer) loadClangFunctionIndex(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Clang function index: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var envelope struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			return fmt.Errorf("parse Clang index envelope %s:%d: %w", path, line, err)
		}
		if envelope.Kind == "operation_table" {
			var record ClangOperationTableRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				return fmt.Errorf("parse Clang operation table %s:%d: %w", path, line, err)
			}
			a.applyClangOperationTable(record)
			continue
		}
		var record ClangFunctionRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("parse Clang function index %s:%d: %w", path, line, err)
		}
		if record.Kind != "function" || record.Name == "" || record.File == "" {
			continue
		}
		a.applyClangFunction(record)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan Clang function index %s: %w", path, err)
	}
	return nil
}

func (a *Analyzer) applyClangOperationTable(
	record ClangOperationTableRecord,
) {
	if record.Table == "" || record.StructType == "" || record.File == "" {
		return
	}
	info := &OperationTableInfo{
		StructType:       record.StructType,
		Table:            record.Table,
		File:             record.File,
		Const:            record.Const,
		Complete:         record.Complete,
		VerifiedByClang:  true,
		FieldTargets:     make(map[string]string),
		FieldTargetFiles: make(map[string]string),
		NullFields:       make(map[string]bool),
		UnknownFields:    make(map[string]bool),
	}
	for _, target := range record.FieldTargets {
		if target.Field == "" || target.Function == "" {
			info.Complete = false
			continue
		}
		if existing := info.FieldTargets[target.Field]; existing != "" &&
			existing != target.Function {
			info.UnknownFields[target.Field] = true
			info.Complete = false
			delete(info.FieldTargets, target.Field)
			delete(info.FieldTargetFiles, target.Field)
			continue
		}
		targetFile := target.File
		if targetFile == "" {
			targetFile = record.File
		}
		info.FieldTargets[target.Field] = target.Function
		info.FieldTargetFiles[target.Field] = targetFile
		a.addOperationTarget(OperationTarget{
			StructType: record.StructType,
			Table:      record.Table,
			Field:      target.Field,
			Function:   target.Function,
			File:       targetFile,
		})
	}
	for _, field := range record.NullFields {
		if field != "" {
			info.NullFields[field] = true
		}
	}
	for _, field := range record.UnknownFields {
		if field != "" {
			info.UnknownFields[field] = true
			info.Complete = false
		}
	}
	a.mergeOperationTableInfo(info)
}

func (a *Analyzer) applyClangFunction(record ClangFunctionRecord) {
	static := record.Static
	id := makeClangFunctionID(
		record.File,
		record.Name,
		static,
		record.Inline,
		record.SemanticHash,
		record.TranslationUnit,
	)
	display := record.Name
	if isSyscallBodyName(record.Name) {
		id = record.Name
		static = false
	} else if (record.Static || record.Inline) && record.SemanticHash != "" {
		display = fmt.Sprintf("%s@%s#%s", record.Name, record.File, record.SemanticHash)
	} else if static {
		display = fmt.Sprintf("%s@%s", record.Name, record.File)
	}

	typedCallees := make(map[string][]string)
	for _, target := range record.DirectCallTargets {
		if target.Name == "" {
			continue
		}
		targetID := clangCallTargetFunctionID(target, record.TranslationUnit)
		typedCallees[target.Name] = appendUnique(typedCallees[target.Name], targetID)
	}
	typedIndirectCalls := make(map[string]ClangIndirectTarget)
	for _, target := range record.IndirectCallTargets {
		if target.Expression == "" || target.StructType == "" || target.Field == "" {
			continue
		}
		target.ReturnTypeSpelling = target.ReturnType
		target.ReturnType = normalizeClangSemanticReturnType(
			target.ReturnType,
			target.ReturnTypeCanonical,
			target.ReturnTypeClass,
			target.ReturnTypeSigned,
		)
		typedIndirectCalls[normalizeIndirectExpression(target.Expression)] = target
	}
	callSites := cloneClangCallSites(record.CallSites)
	for index := range callSites {
		callSites[index].ReturnTypeSpelling = callSites[index].ReturnType
		callSites[index].ReturnType = normalizeClangSemanticReturnType(
			callSites[index].ReturnType,
			callSites[index].ReturnTypeCanonical,
			callSites[index].ReturnTypeClass,
			callSites[index].ReturnTypeSigned,
		)
		for argumentIndex := range callSites[index].CallbackArguments {
			callback := &callSites[index].CallbackArguments[argumentIndex]
			for targetIndex := range callback.Targets {
				target := &callback.Targets[targetIndex]
				target.FunctionID = clangCallTargetFunctionID(
					*target,
					record.TranslationUnit,
				)
			}
		}
	}
	translationUnits := []string{}
	if record.TranslationUnit != "" {
		translationUnits = append(translationUnits, record.TranslationUnit)
	}

	body := normalizeClangBody(record.Body)
	info := &FunctionInfo{
		ID:          id,
		Name:        record.Name,
		DisplayName: display,
		ReturnType: normalizeClangSemanticReturnType(
			record.ReturnType,
			record.ReturnTypeCanonical,
			record.ReturnTypeClass,
			record.ReturnTypeSigned,
		),
		ReturnTypeSpelling:      record.ReturnType,
		ReturnTypeCanonical:     record.ReturnTypeCanonical,
		ReturnTypeClass:         record.ReturnTypeClass,
		ReturnTypeSigned:        record.ReturnTypeSigned,
		ReturnTypeBits:          record.ReturnTypeBits,
		Parameters:              append([]string(nil), record.Parameters...),
		StructVariables:         cloneStringMap(record.StructVariables),
		File:                    record.File,
		TranslationUnits:        translationUnits,
		RelFile:                 record.File,
		Static:                  static,
		Inline:                  record.Inline,
		SemanticHash:            record.SemanticHash,
		RawCallees:              filterInternalCallees(record.ReachableCalls),
		DirectLSMHooks:          uniqueStrings(record.ReachableLSMHooks),
		DirectSigChecks:         uniqueStrings(record.ReachableSignalChecks),
		IndirectCalls:           uniqueStrings(record.ReachableIndirectCalls),
		Body:                    body,
		Frontend:                "clang-ast-cfg",
		SourceLine:              record.Line,
		CFGComplete:             record.CFGComplete,
		CFGBlockCount:           len(record.CFGBlocks),
		CFGHasSuccessExit:       record.CFGHasPotentialSuccessExit,
		CFGUsedErrnoGuards:      record.CFGUsedKernelErrnoGuards,
		CFGFailure:              record.CFGFailure,
		CFGEntry:                record.CFGEntry,
		CFGExit:                 record.CFGExit,
		CFGBlocks:               cloneCFGBlocks(record.CFGBlocks),
		CFGUnplacedEvents:       uniqueStrings(record.UnplacedEvents),
		CFGUnplacedCallSites:    uniqueStrings(record.UnplacedCallSiteIDs),
		CFGEscapedVariables:     uniqueStrings(record.EscapedVariables),
		CFGReachableCalls:       filterInternalCallees(record.ReachableCalls),
		CFGReachableIndirect:    uniqueStrings(record.ReachableIndirectCalls),
		CFGReachableCallSites:   uniqueStrings(record.ReachableCallSiteIDs),
		CFGMustSuccessCalls:     filterInternalCallees(record.MustSuccessCalls),
		CFGMustSuccessIndirect:  uniqueStrings(record.MustSuccessIndirectCalls),
		CFGMustSuccessCallSites: uniqueStrings(record.MustSuccessCallSiteIDs),
		CFGMustSuccessLSM:       uniqueStrings(record.MustSuccessLSMHooks),
		CFGMustSuccessSignals:   uniqueStrings(record.MustSuccessSignalChecks),
		CallSites:               callSites,
		TypedCallees:            typedCallees,
		TypedIndirectCalls:      typedIndirectCalls,
		FrontendVariantCount:    1,
	}
	a.configureFunctionLSMHooks(info)
	a.configureCFGBlocks(info)
	activeMust, inactiveMust := a.partitionConfiguredLSMHooks(info.CFGMustSuccessLSM)
	info.CFGMustSuccessLSM = activeMust
	info.InactiveLSMHooks = uniqueStrings(append(info.InactiveLSMHooks, inactiveMust...))
	info.CFGMustSuccessCalls = subtractPreserve(info.CFGMustSuccessCalls, inactiveMust)

	if existing, ok := a.functions[id]; ok {
		if existing.Frontend == "clang-ast-cfg" {
			existing.FrontendVariantCount++
			existing.TranslationUnits = uniqueStrings(append(existing.TranslationUnits, info.TranslationUnits...))
			if !sameClangFunctionVariant(existing, info) {
				mergeClangFunctionVariant(existing, info)
			} else {
				mergeClangTypedTargets(existing, info)
			}
			return
		}
		if info.Body == "" {
			info.Body = existing.Body
		}
		for name, structType := range existing.StructVariables {
			if _, found := info.StructVariables[name]; !found {
				info.StructVariables[name] = structType
			}
		}
		a.functions[id] = info
		a.displayIndex[info.DisplayName] = id
		return
	}
	a.addFunction(info)
}

func sameClangFunctionVariant(left, right *FunctionInfo) bool {
	return left.Body == right.Body &&
		left.ReturnType == right.ReturnType &&
		left.ReturnTypeCanonical == right.ReturnTypeCanonical &&
		left.ReturnTypeClass == right.ReturnTypeClass &&
		left.ReturnTypeSigned == right.ReturnTypeSigned &&
		left.ReturnTypeBits == right.ReturnTypeBits &&
		left.CFGComplete == right.CFGComplete &&
		left.CFGHasSuccessExit == right.CFGHasSuccessExit &&
		left.CFGEntry == right.CFGEntry &&
		left.CFGExit == right.CFGExit &&
		stringSlicesEqual(left.CFGReachableCalls, right.CFGReachableCalls) &&
		stringSlicesEqual(left.CFGReachableIndirect, right.CFGReachableIndirect) &&
		stringSlicesEqual(left.CFGMustSuccessCalls, right.CFGMustSuccessCalls) &&
		stringSlicesEqual(left.CFGMustSuccessIndirect, right.CFGMustSuccessIndirect) &&
		stringSlicesEqual(left.CFGMustSuccessLSM, right.CFGMustSuccessLSM) &&
		stringSlicesEqual(left.CFGMustSuccessSignals, right.CFGMustSuccessSignals) &&
		stringSlicesEqual(left.CFGUnplacedEvents, right.CFGUnplacedEvents) &&
		stringSlicesEqual(left.CFGUnplacedCallSites, right.CFGUnplacedCallSites) &&
		stringSlicesEqual(left.CFGEscapedVariables, right.CFGEscapedVariables) &&
		stringSlicesEqual(left.CFGReachableCallSites, right.CFGReachableCallSites) &&
		stringSlicesEqual(left.CFGMustSuccessCallSites, right.CFGMustSuccessCallSites) &&
		cfgBlocksEqual(left.CFGBlocks, right.CFGBlocks) &&
		clangCallSitesEqual(left.CallSites, right.CallSites) &&
		stringMapsEqual(left.StructVariables, right.StructVariables) &&
		typedIndirectTargetsEqual(left.TypedIndirectCalls, right.TypedIndirectCalls)
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		other, ok := right[key]
		if !ok || other != value {
			return false
		}
	}
	return true
}

func cloneCFGBlocks(blocks []ClangCFGBlock) []ClangCFGBlock {
	result := make([]ClangCFGBlock, 0, len(blocks))
	for _, block := range blocks {
		block.Successors = append([]int(nil), block.Successors...)
		block.SuccessorBranches = append(
			[]string(nil),
			block.SuccessorBranches...,
		)
		block.SuccessSuccessors = append([]int(nil), block.SuccessSuccessors...)
		block.SuccessSuccessorBranches = append(
			[]string(nil),
			block.SuccessSuccessorBranches...,
		)
		block.Calls = append([]string(nil), block.Calls...)
		block.IndirectCalls = append([]string(nil), block.IndirectCalls...)
		block.LSMHooks = append([]string(nil), block.LSMHooks...)
		block.SignalChecks = append([]string(nil), block.SignalChecks...)
		block.CallSiteIDs = append([]string(nil), block.CallSiteIDs...)
		block.ValueWrites = append(
			[]ClangCFGValueWrite(nil),
			block.ValueWrites...,
		)
		block.PointeeWrites = append(
			[]ClangCFGPointeeWrite(nil),
			block.PointeeWrites...,
		)
		result = append(result, block)
	}
	return result
}

func cloneClangCallSites(sites []ClangCallSite) []ClangCallSite {
	result := make([]ClangCallSite, 0, len(sites))
	for _, site := range sites {
		site.Arguments = append([]string(nil), site.Arguments...)
		site.ArgumentConstants = append([]string(nil), site.ArgumentConstants...)
		site.CallbackArguments = cloneClangCallbackArguments(
			site.CallbackArguments,
		)
		result = append(result, site)
	}
	return result
}

func cloneClangCallbackArguments(
	arguments []ClangCallbackArgument,
) []ClangCallbackArgument {
	result := make([]ClangCallbackArgument, 0, len(arguments))
	for _, argument := range arguments {
		argument.Targets = append(
			[]ClangCallTarget(nil),
			argument.Targets...,
		)
		result = append(result, argument)
	}
	return result
}

func uniqueClangCallSites(sites []ClangCallSite) []ClangCallSite {
	seen := make(map[string]struct{}, len(sites))
	result := make([]ClangCallSite, 0, len(sites))
	for _, site := range sites {
		key := clangCallSiteKey(site)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, site)
	}
	return result
}

func clangCallSitesEqual(left, right []ClangCallSite) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, site := range left {
		counts[clangCallSiteKey(site)]++
	}
	for _, site := range right {
		key := clangCallSiteKey(site)
		if counts[key] == 0 {
			return false
		}
		counts[key]--
	}
	return true
}

func clangCallSiteKey(site ClangCallSite) string {
	return fmt.Sprintf(
		"%s\x00%t\x00%t\x00%d\x00%t\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%t\x00%d\x00%s\x00%s\x00%s\x00%d\x00%d",
		site.ID,
		site.Direct,
		site.Reachable,
		site.BlockID,
		site.HasBlock,
		site.Name,
		normalizeIndirectExpression(site.Expression),
		site.ResultUse,
		site.ResultVariable,
		site.ReturnType,
		site.ReturnTypeCanonical,
		site.ReturnTypeClass,
		site.ReturnTypeSigned,
		site.ReturnTypeBits,
		strings.Join(site.Arguments, "\x1f"),
		strings.Join(site.ArgumentConstants, "\x1f"),
		clangCallbackArgumentsKey(site.CallbackArguments),
		site.Line,
		site.Column,
	)
}

func clangCallbackArgumentsKey(arguments []ClangCallbackArgument) string {
	parts := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		targets := make([]string, 0, len(argument.Targets))
		for _, target := range argument.Targets {
			targets = append(targets, fmt.Sprintf(
				"%s\x1c%s\x1c%t\x1c%t\x1c%s\x1c%d\x1c%s",
				target.Name,
				target.File,
				target.Static,
				target.Inline,
				target.SemanticHash,
				target.Line,
				target.FunctionID,
			))
		}
		sort.Strings(targets)
		parts = append(parts, fmt.Sprintf(
			"%d\x1d%t\x1d%t\x1d%s",
			argument.Index,
			argument.Complete,
			argument.MayBeNull,
			strings.Join(targets, "\x1e"),
		))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x1f")
}

func clangCallTargetFunctionID(
	target ClangCallTarget,
	translationUnit string,
) string {
	targetID := target.Name
	if target.File != "" && !isSyscallBodyName(target.Name) &&
		(target.Static || target.Inline) {
		targetID = makeClangFunctionID(
			target.File,
			target.Name,
			target.Static,
			target.Inline,
			target.SemanticHash,
			translationUnit,
		)
	}
	return targetID
}

func cfgBlocksEqual(left, right []ClangCFGBlock) bool {
	if len(left) != len(right) {
		return false
	}
	leftByID := make(map[int]ClangCFGBlock, len(left))
	for _, block := range left {
		leftByID[block.ID] = block
	}
	for _, block := range right {
		other, ok := leftByID[block.ID]
		if !ok ||
			block.PotentialSuccessExit != other.PotentialSuccessExit ||
			block.FailureOnlyExit != other.FailureOnlyExit ||
			block.TerminatorCondition != other.TerminatorCondition ||
			block.ReturnExpression != other.ReturnExpression ||
			block.ReturnExpressionExpanded !=
				other.ReturnExpressionExpanded ||
			block.ReturnDefinitelyNonnegative !=
				other.ReturnDefinitelyNonnegative ||
			block.ReturnDefinitelyValidPointer !=
				other.ReturnDefinitelyValidPointer ||
			!intSlicesEqual(block.Successors, other.Successors) ||
			!stringSlicesEqual(
				block.SuccessorBranches,
				other.SuccessorBranches,
			) ||
			!intSlicesEqual(block.SuccessSuccessors, other.SuccessSuccessors) ||
			!stringSlicesEqual(
				block.SuccessSuccessorBranches,
				other.SuccessSuccessorBranches,
			) ||
			!stringSlicesEqual(block.Calls, other.Calls) ||
			!stringSlicesEqual(block.IndirectCalls, other.IndirectCalls) ||
			!stringSlicesEqual(block.LSMHooks, other.LSMHooks) ||
			!stringSlicesEqual(block.SignalChecks, other.SignalChecks) ||
			!stringSlicesEqual(block.CallSiteIDs, other.CallSiteIDs) ||
			!cfgValueWritesEqual(block.ValueWrites, other.ValueWrites) ||
			!cfgPointeeWritesEqual(
				block.PointeeWrites,
				other.PointeeWrites,
			) {
			return false
		}
	}
	return true
}

func cfgValueWritesEqual(
	left, right []ClangCFGValueWrite,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cfgPointeeWritesEqual(
	left, right []ClangCFGPointeeWrite,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func intSlicesEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	leftValues := append([]int(nil), left...)
	rightValues := append([]int(nil), right...)
	sort.Ints(leftValues)
	sort.Ints(rightValues)
	for index := range leftValues {
		if leftValues[index] != rightValues[index] {
			return false
		}
	}
	return true
}

func typedIndirectTargetsEqual(left, right map[string]ClangIndirectTarget) bool {
	if len(left) != len(right) {
		return false
	}
	for expression, target := range left {
		other, ok := right[expression]
		if !ok || target.StructType != other.StructType || target.Field != other.Field ||
			target.ReturnType != other.ReturnType ||
			target.ReturnTypeCanonical != other.ReturnTypeCanonical ||
			target.ReturnTypeClass != other.ReturnTypeClass ||
			target.ReturnTypeSigned != other.ReturnTypeSigned ||
			target.ReturnTypeBits != other.ReturnTypeBits {
			return false
		}
	}
	return true
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := make(map[string]int, len(left))
	for _, value := range left {
		leftSet[value]++
	}
	for _, value := range right {
		if leftSet[value] == 0 {
			return false
		}
		leftSet[value]--
	}
	return true
}

func mergeClangFunctionVariant(target, variant *FunctionInfo) {
	target.FrontendVariantConflict = true
	target.CFGComplete = target.CFGComplete && variant.CFGComplete
	target.CFGHasSuccessExit = target.CFGHasSuccessExit && variant.CFGHasSuccessExit
	target.CFGUsedErrnoGuards = target.CFGUsedErrnoGuards || variant.CFGUsedErrnoGuards
	target.CFGReachableCalls = uniqueStrings(append(target.CFGReachableCalls, variant.CFGReachableCalls...))
	target.CFGReachableIndirect = uniqueStrings(append(target.CFGReachableIndirect, variant.CFGReachableIndirect...))
	target.CFGUnplacedEvents = uniqueStrings(append(target.CFGUnplacedEvents, variant.CFGUnplacedEvents...))
	target.CFGUnplacedCallSites = uniqueStrings(append(target.CFGUnplacedCallSites, variant.CFGUnplacedCallSites...))
	target.CFGEscapedVariables = uniqueStrings(append(target.CFGEscapedVariables, variant.CFGEscapedVariables...))
	target.CFGReachableCallSites = uniqueStrings(append(target.CFGReachableCallSites, variant.CFGReachableCallSites...))
	target.TranslationUnits = uniqueStrings(append(target.TranslationUnits, variant.TranslationUnits...))
	target.RawCallees = uniqueStrings(append(target.RawCallees, variant.RawCallees...))
	target.DirectLSMHooks = uniqueStrings(append(target.DirectLSMHooks, variant.DirectLSMHooks...))
	target.DirectSigChecks = uniqueStrings(append(target.DirectSigChecks, variant.DirectSigChecks...))
	target.IndirectCalls = uniqueStrings(append(target.IndirectCalls, variant.IndirectCalls...))
	target.CallSites = uniqueClangCallSites(append(target.CallSites, variant.CallSites...))
	target.CFGMustSuccessCalls = intersectStrings(target.CFGMustSuccessCalls, variant.CFGMustSuccessCalls)
	target.CFGMustSuccessIndirect = intersectStrings(target.CFGMustSuccessIndirect, variant.CFGMustSuccessIndirect)
	target.CFGMustSuccessLSM = intersectStrings(target.CFGMustSuccessLSM, variant.CFGMustSuccessLSM)
	target.CFGMustSuccessSignals = intersectStrings(target.CFGMustSuccessSignals, variant.CFGMustSuccessSignals)
	target.CFGMustSuccessCallSites = intersectStrings(target.CFGMustSuccessCallSites, variant.CFGMustSuccessCallSites)
	target.InactiveLSMHooks = uniqueStrings(append(target.InactiveLSMHooks, variant.InactiveLSMHooks...))
	for callee, ids := range variant.TypedCallees {
		target.TypedCallees[callee] = uniqueStrings(append(target.TypedCallees[callee], ids...))
	}
	for expression, typedTarget := range variant.TypedIndirectCalls {
		if existing, ok := target.TypedIndirectCalls[expression]; ok &&
			(existing.StructType != typedTarget.StructType ||
				existing.Field != typedTarget.Field ||
				!sameClangTypeMetadata(
					existing.ReturnType,
					existing.ReturnTypeCanonical,
					existing.ReturnTypeClass,
					existing.ReturnTypeSigned,
					existing.ReturnTypeBits,
					typedTarget.ReturnType,
					typedTarget.ReturnTypeCanonical,
					typedTarget.ReturnTypeClass,
					typedTarget.ReturnTypeSigned,
					typedTarget.ReturnTypeBits,
				)) {
			delete(target.TypedIndirectCalls, expression)
			continue
		}
		target.TypedIndirectCalls[expression] = typedTarget
	}
	if target.CFGFailure == "" {
		target.CFGFailure = "translation_unit_variant_conflict"
	} else if !strings.Contains(target.CFGFailure, "translation_unit_variant_conflict") {
		target.CFGFailure += "; translation_unit_variant_conflict"
	}
}

func mergeClangTypedTargets(target, variant *FunctionInfo) {
	for callee, ids := range variant.TypedCallees {
		target.TypedCallees[callee] = uniqueStrings(append(target.TypedCallees[callee], ids...))
	}
	for expression, typedTarget := range variant.TypedIndirectCalls {
		if existing, ok := target.TypedIndirectCalls[expression]; ok &&
			(existing.StructType != typedTarget.StructType ||
				existing.Field != typedTarget.Field ||
				!sameClangTypeMetadata(
					existing.ReturnType,
					existing.ReturnTypeCanonical,
					existing.ReturnTypeClass,
					existing.ReturnTypeSigned,
					existing.ReturnTypeBits,
					typedTarget.ReturnType,
					typedTarget.ReturnTypeCanonical,
					typedTarget.ReturnTypeClass,
					typedTarget.ReturnTypeSigned,
					typedTarget.ReturnTypeBits,
				)) {
			delete(target.TypedIndirectCalls, expression)
			continue
		}
		target.TypedIndirectCalls[expression] = typedTarget
	}
}

func sameClangTypeMetadata(
	leftType, leftCanonical, leftClass string,
	leftSigned bool,
	leftBits int,
	rightType, rightCanonical, rightClass string,
	rightSigned bool,
	rightBits int,
) bool {
	return leftType == rightType &&
		leftCanonical == rightCanonical &&
		leftClass == rightClass &&
		leftSigned == rightSigned &&
		leftBits == rightBits
}

func normalizeClangBody(body string) string {
	body = strings.TrimSpace(stripComments(body))
	if len(body) >= 2 && body[0] == '{' {
		if closeBrace, ok := findMatchingBrace(body, 0); ok && closeBrace == len(body)-1 {
			return body[1:closeBrace]
		}
	}
	return body
}

func normalizeClangReturnType(returnType string) string {
	returnType = strings.TrimSpace(returnType)
	if strings.Contains(returnType, "*") {
		return "pointer"
	}
	switch {
	case returnType == "void":
		return "void"
	case strings.Contains(returnType, "bool"):
		return "bool"
	case strings.Contains(returnType, "ssize_t"):
		return "ssize_t"
	case strings.Contains(returnType, "size_t"):
		return "size_t"
	case strings.Contains(returnType, "unsigned"):
		return "unsigned_integer"
	case strings.Contains(returnType, "long"):
		return "long"
	case strings.Contains(returnType, "int"):
		return "int"
	default:
		return "unknown"
	}
}

func normalizeClangSemanticReturnType(
	spelling, canonical, class string,
	signed bool,
) string {
	switch strings.TrimSpace(class) {
	case "void", "bool", "pointer":
		return strings.TrimSpace(class)
	case "signed_integer":
		if !signed {
			return "unknown"
		}
		if strings.Contains(spelling, "ssize_t") {
			return "ssize_t"
		}
		if strings.Contains(canonical, "long") {
			return "long"
		}
		return "int"
	case "unsigned_integer":
		if strings.Contains(spelling, "size_t") &&
			!strings.Contains(spelling, "ssize_t") {
			return "size_t"
		}
		return "unsigned_integer"
	case "record":
		return "record"
	case "other":
		return "unknown"
	}
	if normalized := normalizeClangReturnType(canonical); normalized != "unknown" {
		return normalized
	}
	return normalizeClangReturnType(spelling)
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStringSliceMap(source map[string][]string) map[string][]string {
	result := make(map[string][]string, len(source))
	for key, values := range source {
		result[key] = append([]string(nil), values...)
	}
	return result
}

type llvmVerificationResult struct {
	index  int
	source string
	output string
	err    error
}

func (a *Analyzer) verifyLLVMHooks() error {
	info, err := os.Stat(a.cfg.LLVMVerifier)
	if err != nil {
		return fmt.Errorf("stat LLVM verifier %s: %w (build it with `make llvm_hook_verifier`)", a.cfg.LLVMVerifier, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("LLVM verifier is not executable: %s", a.cfg.LLVMVerifier)
	}

	if !a.lsmEffectSourcesBuilt {
		a.buildEffectSourceStates("lsm")
	}
	if !a.sigEffectSourcesBuilt {
		a.buildEffectSourceStates("sigkill")
	}
	fileSet := orderedSet(nil)
	for _, fn := range a.functions {
		if !a.functionNeedsLLVMVerification(fn) {
			continue
		}
		candidates := append(append([]string(nil), fn.TranslationUnits...), fn.File)
		for _, source := range uniqueStrings(candidates) {
			if _, ok := a.compileUnits[source]; ok {
				fileSet.add(source)
			}
		}
	}
	files := fileSet.slice()
	sort.Strings(files)
	if len(files) == 0 {
		return nil
	}

	tempDir, err := os.MkdirTemp("", "systematic-analysis-llvm-")
	if err != nil {
		return fmt.Errorf("create LLVM verification temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	workerCount := min(a.cfg.LLVMJobs, len(files))
	fmt.Fprintf(os.Stderr, "selective LLVM verification: %d translation units, %d workers\n", len(files), workerCount)
	jobs := make(chan int)
	results := make(chan llvmVerificationResult, workerCount)
	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				source := files[index]
				bitcodePath := filepath.Join(tempDir, fmt.Sprintf("module-%d.bc", index))
				factsPath := filepath.Join(tempDir, fmt.Sprintf("facts-%d.ndjson", index))
				command := a.compileUnits[source]
				arguments, argumentErr := compileCommandArguments(command)
				if argumentErr != nil {
					results <- llvmVerificationResult{index: index, source: source, err: argumentErr}
					continue
				}
				compiler := arguments[0]
				irCommand := exec.Command(compiler, emitLLVMArguments(arguments[1:], bitcodePath)...)
				irCommand.Dir = command.Directory
				var diagnostics strings.Builder
				irCommand.Stderr = &diagnostics
				if runErr := irCommand.Run(); runErr != nil {
					message := strings.TrimSpace(diagnostics.String())
					if message != "" {
						runErr = fmt.Errorf("%w: %s", runErr, message)
					}
					results <- llvmVerificationResult{index: index, source: source, err: fmt.Errorf("emit LLVM IR: %w", runErr)}
					continue
				}
				verifyCommand := exec.Command(a.cfg.LLVMVerifier, "--input", bitcodePath, "--output", factsPath)
				diagnostics.Reset()
				verifyCommand.Stderr = &diagnostics
				if runErr := verifyCommand.Run(); runErr != nil {
					message := strings.TrimSpace(diagnostics.String())
					if message != "" {
						runErr = fmt.Errorf("%w: %s", runErr, message)
					}
					results <- llvmVerificationResult{index: index, source: source, err: fmt.Errorf("verify LLVM IR: %w", runErr)}
					continue
				}
				results <- llvmVerificationResult{index: index, source: source, output: factsPath}
			}
		}()
	}
	go func() {
		for index := range files {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	ordered := make([]llvmVerificationResult, len(files))
	completed := 0
	for result := range results {
		ordered[result.index] = result
		completed++
		if completed == 1 || completed%25 == 0 || completed == len(files) {
			fmt.Fprintf(os.Stderr, "selective LLVM verification: %d/%d\n", completed, len(files))
		}
	}
	for _, result := range ordered {
		if result.err != nil {
			message := fmt.Sprintf("%s: %v", result.source, result.err)
			a.llvmFailures = append(a.llvmFailures, message)
			a.markLLVMVerificationUnknown(result.source, "ir_generation_or_verification_failed")
			fmt.Fprintf(os.Stderr, "warning: LLVM verification skipped: %s\n", message)
			continue
		}
		if err := a.loadLLVMHookFacts(result.source, result.output); err != nil {
			message := fmt.Sprintf("%s: %v", result.source, err)
			a.llvmFailures = append(a.llvmFailures, message)
			a.markLLVMVerificationUnknown(result.source, "llvm_fact_parse_failed")
			fmt.Fprintf(os.Stderr, "warning: LLVM verification facts skipped: %s\n", message)
		}
	}
	clear(a.lsmEffectSourceCache)
	clear(a.sigEffectSourceCache)
	clear(a.lsmEffectWitnessCache)
	clear(a.sigEffectWitnessCache)
	clear(a.lsmFailureKindCache)
	clear(a.sigFailureKindCache)
	a.lsmEffectSourcesBuilt = false
	a.sigEffectSourcesBuilt = false
	a.refreshLLVMPreservedEscapes()
	return nil
}

func (a *Analyzer) functionNeedsLLVMVerification(fn *FunctionInfo) bool {
	if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete {
		return false
	}
	if !a.effectSourceCacheNeedsVerification(fn.ID) {
		return false
	}
	if len(fn.DirectLSMHooks) > 0 || len(fn.DirectSigChecks) > 0 {
		return true
	}
	for _, callee := range effectRelevantDirectCalls(fn) {
		if strings.HasPrefix(callee, "security_") || isSignalCheckName(callee) {
			continue
		}
		if classifySignalAbortEffect(a.analyzeNamedCallErrorEffect(fn, fn.Body, callee)) != "unknown" {
			continue
		}
		ids, status := a.resolveCallee(fn, callee)
		if status != "resolved" && status != "ambiguous" {
			return true
		}
		for _, id := range ids {
			if a.effectSourceCacheNeedsVerification(id) {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) effectSourceCacheNeedsVerification(functionID string) bool {
	lsmState, lsmKnown := a.lsmEffectSourceCache[functionID]
	signalState, signalKnown := a.sigEffectSourceCache[functionID]
	return lsmKnown && lsmState != effectSourceNone ||
		signalKnown && signalState != effectSourceNone
}

func compileCommandArguments(command CompileCommand) ([]string, error) {
	arguments := append([]string(nil), command.Arguments...)
	if len(arguments) == 0 {
		var err error
		arguments, err = splitShellCommand(command.Command)
		if err != nil {
			return nil, err
		}
	}
	if len(arguments) == 0 {
		return nil, errors.New("empty compile command")
	}
	return arguments, nil
}

func emitLLVMArguments(arguments []string, output string) []string {
	result := make([]string, 0, len(arguments)+5)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "-c", "-S", "-MD", "-MMD", "-MP", "-MG", "-g":
			continue
		case "-o", "-MF", "-MT", "-MQ", "-MJ":
			index++
			continue
		}
		if strings.HasPrefix(argument, "-Wp,-MD") || strings.HasPrefix(argument, "-Wp,-MMD") ||
			strings.HasPrefix(argument, "-MF") || strings.HasPrefix(argument, "-MT") ||
			strings.HasPrefix(argument, "-MQ") || strings.HasPrefix(argument, "-MJ") ||
			(strings.HasPrefix(argument, "-o") && len(argument) > 2) ||
			strings.HasPrefix(argument, "-g") {
			continue
		}
		result = append(result, argument)
	}
	return append(result, "-gline-tables-only", "-emit-llvm", "-c", "-o", output)
}

func (a *Analyzer) loadLLVMHookFacts(source, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	seen := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var fact LLVMCallFact
		if err := json.Unmarshal(scanner.Bytes(), &fact); err != nil {
			return err
		}
		if fact.Kind == "function_summary" {
			fn := a.findLLVMFunctionForFact(source, fact)
			if fn != nil {
				fn.LLVMFunctionFacts = append(
					fn.LLVMFunctionFacts,
					fact,
				)
			}
			continue
		}
		if fact.Callee == "" {
			fact.Callee = fact.Hook
		}
		if fact.Kind == "" {
			if strings.HasPrefix(fact.Callee, "security_") {
				fact.Kind = "hook"
			} else {
				fact.Kind = "call"
			}
		}
		fn := a.findLLVMFunctionForFact(source, fact)
		if fn == nil {
			continue
		}
		fn.LLVMCallFacts = append(fn.LLVMCallFacts, fact)
		if fact.Kind != "hook" && !strings.HasPrefix(fact.Callee, "security_") {
			continue
		}
		hook := fact.Hook
		if hook == "" {
			hook = fact.Callee
		}
		fn.LLVMHookFacts = append(fn.LLVMHookFacts, LLVMHookFact{
			Hook:                      hook,
			Function:                  fact.Function,
			SourceFunction:            fact.SourceFunction,
			SourceFile:                fact.SourceFile,
			SourceLine:                fact.SourceLine,
			SourceColumn:              fact.SourceColumn,
			InlinedAtFunctions:        append([]string(nil), fact.InlinedAtFunctions...),
			ResultUsed:                fact.ResultUsed,
			ControlsBranch:            fact.ControlsBranch,
			ReachesReturn:             fact.ReachesReturn,
			MustReturnExact:           fact.MustReturnExact,
			MustReturnNegativeOnError: fact.MustReturnNegativeOnError,
			MustReturnNegativeOnFalse: fact.MustReturnNegativeOnFalse,
			MustReturnNegativeOnTrue:  fact.MustReturnNegativeOnTrue,
			UseKinds:                  append([]string(nil), fact.UseKinds...),
			Verification:              fact.Verification,
			Module:                    fact.Module,
		})
		if seen[fn.ID] == nil {
			seen[fn.ID] = make(map[string]bool)
		}
		seen[fn.ID][hook] = true
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for _, fn := range a.functions {
		if !functionBelongsToTranslationUnit(fn, source) || len(fn.DirectLSMHooks) == 0 {
			continue
		}
		for _, hook := range fn.DirectLSMHooks {
			if seen[fn.ID][hook] {
				continue
			}
			fn.LLVMHookFacts = append(fn.LLVMHookFacts, LLVMHookFact{
				Hook:         hook,
				Function:     fn.Name,
				Verification: "not_present_after_codegen",
				Module:       source,
			})
		}
	}
	return nil
}

func (a *Analyzer) findLLVMFunctionForFact(source string, fact LLVMCallFact) *FunctionInfo {
	name := fact.SourceFunction
	if name == "" {
		name = fact.Function
	}
	sourceFile := filepath.Clean(fact.SourceFile)
	candidates := make([]*FunctionInfo, 0)
	for _, id := range a.nameIndex[name] {
		fn := a.functions[id]
		if !functionBelongsToTranslationUnit(fn, source) {
			continue
		}
		if fact.SourceFile != "" && filepath.Clean(fn.File) != sourceFile {
			continue
		}
		candidates = append(candidates, fn)
	}
	if len(candidates) == 0 && fact.SourceFile != "" {
		for _, id := range a.nameIndex[name] {
			fn := a.functions[id]
			if fn == nil || filepath.Clean(fn.File) != sourceFile {
				continue
			}
			if fact.Kind == "function_summary" &&
				fact.SourceLine > 0 &&
				fn.SourceLine != fact.SourceLine {
				continue
			}
			candidates = append(candidates, fn)
		}
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	if len(candidates) > 1 && fact.SourceLine > 0 {
		best := make([]*FunctionInfo, 0)
		bestLine := -1
		for _, fn := range candidates {
			if fn.SourceLine <= 0 || fn.SourceLine > fact.SourceLine {
				continue
			}
			if fn.SourceLine > bestLine {
				best = []*FunctionInfo{fn}
				bestLine = fn.SourceLine
			} else if fn.SourceLine == bestLine {
				best = append(best, fn)
			}
		}
		if len(best) == 1 {
			return best[0]
		}
	}
	if name != fact.Function {
		return a.findLLVMFunction(source, fact.Function)
	}
	return nil
}

func (a *Analyzer) findLLVMFunction(source, name string) *FunctionInfo {
	var matched *FunctionInfo
	for _, id := range a.nameIndex[name] {
		fn := a.functions[id]
		if !functionBelongsToTranslationUnit(fn, source) {
			continue
		}
		if fn.File == source && !fn.Inline {
			return fn
		}
		if matched != nil {
			return nil
		}
		matched = fn
	}
	if matched != nil {
		return matched
	}
	if ids := a.globalIndex[name]; len(ids) == 1 {
		return a.functions[ids[0]]
	}
	return nil
}

func (a *Analyzer) markLLVMVerificationUnknown(source, reason string) {
	for _, fn := range a.functions {
		if !functionBelongsToTranslationUnit(fn, source) {
			continue
		}
		for _, hook := range fn.DirectLSMHooks {
			fn.LLVMHookFacts = append(fn.LLVMHookFacts, LLVMHookFact{
				Hook:         hook,
				Function:     fn.Name,
				Verification: reason,
				Module:       source,
			})
		}
	}
}

func functionBelongsToTranslationUnit(fn *FunctionInfo, source string) bool {
	if fn == nil {
		return false
	}
	return fn.File == source || containsString(fn.TranslationUnits, source)
}

func shouldIndexFile(root, path string, scanAll bool) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if scanAll {
		switch parts[0] {
		case "Documentation", "LICENSES", "samples", "tools", ".git":
			return false
		default:
			return true
		}
	}
	allowedTop := map[string]struct{}{
		"arch": {}, "block": {}, "fs": {}, "include": {}, "init": {}, "ipc": {},
		"kernel": {}, "lib": {}, "mm": {}, "net": {}, "security": {},
	}
	if _, ok := allowedTop[parts[0]]; !ok {
		return false
	}
	return len(parts) < 2 || parts[0] != "arch" || parts[1] == "x86"
}

func configuredSource(command CompileCommand) (ConfiguredSource, error) {
	raw, err := os.ReadFile(command.File)
	if err != nil {
		return ConfiguredSource{}, fmt.Errorf("read source: %w", err)
	}
	arguments := append([]string(nil), command.Arguments...)
	if len(arguments) == 0 {
		arguments, err = splitShellCommand(command.Command)
		if err != nil {
			return ConfiguredSource{}, err
		}
	}
	if len(arguments) == 0 {
		return ConfiguredSource{}, errors.New("empty compile command")
	}

	compiler := arguments[0]
	compilerArgs := preprocessArguments(arguments[1:])
	cmd := exec.Command(compiler, compilerArgs...)
	cmd.Dir = command.Directory
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ConfiguredSource{}, fmt.Errorf("open preprocessor output: %w", err)
	}
	var diagnostics strings.Builder
	cmd.Stderr = &diagnostics
	if err := cmd.Start(); err != nil {
		return ConfiguredSource{}, fmt.Errorf("start %s: %w", compiler, err)
	}

	originalLines := strings.SplitAfter(string(raw), "\n")
	activeLines := make(map[int]struct{})
	currentLine := 0
	currentSource := false
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if sourceLine, sourcePath, ok := preprocessorLineMarker(line); ok {
			currentLine = sourceLine
			currentSource = sameSourceFile(command.Directory, command.File, sourcePath)
			continue
		}
		if currentSource && currentLine > 0 && currentLine <= len(originalLines) && strings.TrimSpace(line) != "" {
			activeLines[currentLine] = struct{}{}
		}
		currentLine++
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return ConfiguredSource{}, fmt.Errorf("read preprocessor output: %w", scanErr)
	}
	if waitErr != nil {
		message := strings.TrimSpace(diagnostics.String())
		if message == "" {
			return ConfiguredSource{}, fmt.Errorf("preprocessor failed: %w", waitErr)
		}
		return ConfiguredSource{}, fmt.Errorf("preprocessor failed: %w: %s", waitErr, message)
	}

	configured := retainConfiguredBranches(string(raw), activeLines)
	return ConfiguredSource{
		Code:           configured,
		ActiveOriginal: configured,
	}, nil
}

func preprocessArguments(arguments []string) []string {
	result := make([]string, 0, len(arguments)+1)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "-c", "-MD", "-MMD", "-MP", "-MG":
			continue
		case "-o", "-MF", "-MT", "-MQ", "-MJ":
			index++
			continue
		}
		if strings.HasPrefix(argument, "-Wp,-MD") || strings.HasPrefix(argument, "-Wp,-MMD") ||
			strings.HasPrefix(argument, "-MF") || strings.HasPrefix(argument, "-MT") ||
			strings.HasPrefix(argument, "-MQ") || strings.HasPrefix(argument, "-MJ") ||
			(strings.HasPrefix(argument, "-o") && len(argument) > 2) {
			continue
		}
		result = append(result, argument)
	}
	return append(result, "-E")
}

func preprocessorLineMarker(line string) (int, string, bool) {
	if !strings.HasPrefix(line, "#") {
		return 0, "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	space := strings.IndexFunc(rest, unicode.IsSpace)
	if space < 0 {
		return 0, "", false
	}
	sourceLine, err := strconv.Atoi(rest[:space])
	if err != nil || sourceLine <= 0 {
		return 0, "", false
	}
	rest = strings.TrimSpace(rest[space:])
	if len(rest) < 2 || rest[0] != '"' {
		return 0, "", false
	}
	endQuote := strings.IndexByte(rest[1:], '"')
	if endQuote < 0 {
		return 0, "", false
	}
	return sourceLine, rest[1 : endQuote+1], true
}

func sameSourceFile(directory, sourceFile, locationPath string) bool {
	if locationPath == "" || strings.HasPrefix(locationPath, "<") {
		return false
	}
	candidate := locationPath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(directory, candidate)
	}
	return filepath.Clean(candidate) == sourceFile
}

func retainConfiguredBranches(source string, activeLines map[int]struct{}) string {
	lines := strings.SplitAfter(source, "\n")
	keep := make([]bool, len(lines))
	for index := range keep {
		keep[index] = true
	}

	activePrefix := make([]int, len(lines)+1)
	for index := range lines {
		activePrefix[index+1] = activePrefix[index]
		if _, active := activeLines[index+1]; active {
			activePrefix[index+1]++
		}
	}

	var groups []*preprocessorGroup
	var stack []*preprocessorGroup
	directiveContinuation := false
	for index, line := range lines {
		lineNumber := index + 1
		trimmed := strings.TrimSpace(line)
		if directiveContinuation {
			keep[index] = false
			directiveContinuation = strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(line, "\n")), "\\")
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		keep[index] = false
		directiveContinuation = strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(line, "\n")), "\\")
		directive := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "if", "ifdef", "ifndef":
			group := &preprocessorGroup{branchStart: lineNumber + 1}
			groups = append(groups, group)
			stack = append(stack, group)
		case "elif", "else":
			if len(stack) == 0 {
				continue
			}
			group := stack[len(stack)-1]
			group.branches = append(group.branches, preprocessorBranch{start: group.branchStart, end: lineNumber - 1})
			group.branchStart = lineNumber + 1
		case "endif":
			if len(stack) == 0 {
				continue
			}
			group := stack[len(stack)-1]
			group.branches = append(group.branches, preprocessorBranch{start: group.branchStart, end: lineNumber - 1})
			stack = stack[:len(stack)-1]
		}
	}
	for _, group := range stack {
		group.branches = append(group.branches, preprocessorBranch{start: group.branchStart, end: len(lines)})
	}

	for _, group := range groups {
		selected := -1
		for index, branch := range group.branches {
			start := max(1, branch.start)
			end := min(len(lines), branch.end)
			if start <= end && activePrefix[end]-activePrefix[start-1] > 0 {
				selected = index
				break
			}
		}
		for index, branch := range group.branches {
			if index == selected {
				continue
			}
			start := max(1, branch.start)
			end := min(len(lines), branch.end)
			for lineNumber := start; lineNumber <= end; lineNumber++ {
				keep[lineNumber-1] = false
			}
		}
	}

	var result strings.Builder
	result.Grow(len(source))
	for index, line := range lines {
		if keep[index] {
			result.WriteString(line)
			continue
		}
		if strings.HasSuffix(line, "\n") {
			result.WriteByte('\n')
		}
	}
	return result.String()
}

func splitShellCommand(command string) ([]string, error) {
	var result []string
	var current strings.Builder
	quote := rune(0)
	escaped := false
	hasToken := false
	flush := func() {
		if !hasToken {
			return
		}
		result = append(result, current.String())
		current.Reset()
		hasToken = false
	}

	for _, char := range command {
		if escaped {
			current.WriteRune(char)
			hasToken = true
			escaped = false
			continue
		}
		if quote == '\'' {
			if char == '\'' {
				quote = 0
			} else {
				current.WriteRune(char)
				hasToken = true
			}
			continue
		}
		if quote == '"' {
			switch char {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				current.WriteRune(char)
				hasToken = true
			}
			continue
		}
		switch {
		case char == '\\':
			escaped = true
			hasToken = true
		case char == '\'' || char == '"':
			quote = char
			hasToken = true
		case unicode.IsSpace(char):
			flush()
		default:
			current.WriteRune(char)
			hasToken = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated quoting in compile command")
	}
	flush()
	return result, nil
}

func shouldSkipDir(root, path string, scanAll bool) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 {
		return false
	}
	if scanAll {
		switch parts[0] {
		case "Documentation", "LICENSES", "samples", "tools", ".git":
			return true
		default:
			return false
		}
	}

	allowedTop := map[string]struct{}{
		"arch":     {},
		"block":    {},
		"fs":       {},
		"include":  {},
		"init":     {},
		"ipc":      {},
		"kernel":   {},
		"lib":      {},
		"mm":       {},
		"net":      {},
		"security": {},
	}
	if len(parts) == 1 {
		_, ok := allowedTop[parts[0]]
		return !ok
	}
	if parts[0] == "arch" && parts[1] != "x86" {
		return true
	}
	return false
}

func (a *Analyzer) parseFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	a.parseSource(path, string(raw), string(raw))
	return nil
}

func (a *Analyzer) parseSource(path, source, activeOriginal string) {
	src := stripComments(source)
	tagSource := stripComments(activeOriginal)
	a.indexOperationTables(path, src)
	syscallRanges := a.extractSyscallFunctions(path, src)
	occupied := make([]span, 0, len(syscallRanges))
	for _, fn := range syscallRanges {
		enrichSignalChecks(fn.info, fn.bodySpan, src, tagSource)
		a.configureFunctionLSMHooks(fn.info)
		occupied = append(occupied, fn.bodySpan)
		a.addFunction(fn.info)
	}

	for _, fn := range extractOrdinaryFunctions(path, src) {
		if overlapsAny(fn.bodySpan, occupied) {
			continue
		}
		enrichSignalChecks(fn.info, fn.bodySpan, src, tagSource)
		a.configureFunctionLSMHooks(fn.info)
		a.addFunction(fn.info)
	}
}

func (a *Analyzer) configureFunctionLSMHooks(info *FunctionInfo) {
	active, inactive := a.partitionConfiguredLSMHooks(info.DirectLSMHooks)
	info.DirectLSMHooks = active
	info.InactiveLSMHooks = inactive
	if len(inactive) > 0 {
		info.RawCallees = subtractPreserve(info.RawCallees, inactive)
	}
}

func (a *Analyzer) configureCFGBlocks(info *FunctionInfo) {
	for index := range info.CFGBlocks {
		active, _ := a.partitionConfiguredLSMHooks(info.CFGBlocks[index].LSMHooks)
		info.CFGBlocks[index].LSMHooks = active
		for _, hook := range subtractPreserve(info.CFGBlocks[index].Calls, active) {
			if strings.HasPrefix(hook, "security_") && !a.isConfiguredLSMHookActive(hook) {
				info.CFGBlocks[index].Calls = subtractPreserve(info.CFGBlocks[index].Calls, []string{hook})
			}
		}
	}
	filtered := make([]string, 0, len(info.CFGUnplacedEvents))
	for _, event := range info.CFGUnplacedEvents {
		hook := strings.TrimPrefix(event, "call:")
		if strings.HasPrefix(event, "call:security_") && !a.isConfiguredLSMHookActive(hook) {
			continue
		}
		filtered = append(filtered, event)
	}
	info.CFGUnplacedEvents = uniqueStrings(filtered)
}

func (a *Analyzer) partitionConfiguredLSMHooks(hooks []string) ([]string, []string) {
	active := orderedSet(nil)
	inactive := orderedSet(nil)
	for _, hook := range hooks {
		if a.isConfiguredLSMHookActive(hook) {
			active.add(hook)
		} else {
			inactive.add(hook)
		}
	}
	return active.slice(), inactive.slice()
}

func (a *Analyzer) isConfiguredLSMHookActive(hook string) bool {
	if a.cfg.CompileDB == "" || !a.hasKernelConfig {
		return true
	}
	if a.lsmMetadataBuilt {
		_, ok := a.lsmWrapperHooks[hook]
		return ok
	}
	if strings.HasPrefix(hook, "security_path_") {
		return a.configSymbols["CONFIG_SECURITY_PATH"]
	}
	return true
}

func (a *Analyzer) buildLSMHookMetadata() error {
	definitionsPath := filepath.Join(a.cfg.KernelRoot, "include", "linux", "lsm_hook_defs.h")
	raw, err := os.ReadFile(definitionsPath)
	if err != nil {
		return fmt.Errorf("read LSM hook definitions: %w", err)
	}
	definitionPattern := regexp.MustCompile(
		`(?m)^\s*LSM_HOOK\s*\(\s*[^,\n]+\s*,\s*[^,\n]+\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`,
	)
	a.lsmHookNames = make(map[string]bool)
	for _, match := range definitionPattern.FindAllStringSubmatch(string(raw), -1) {
		a.lsmHookNames[match[1]] = true
	}
	if len(a.lsmHookNames) == 0 {
		return errors.New("no LSM_HOOK definitions were parsed from include/linux/lsm_hook_defs.h")
	}

	wrapperCandidates := make(map[string]map[string]struct{})
	callHookPattern := regexp.MustCompile(
		`\bcall_(?:int|void)_hook\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\b`,
	)
	for _, fn := range a.functions {
		if !strings.HasPrefix(fn.Name, "security_") {
			continue
		}
		for _, match := range callHookPattern.FindAllStringSubmatch(fn.Body, -1) {
			canonical := match[1]
			if !a.lsmHookNames[canonical] {
				continue
			}
			if wrapperCandidates[fn.Name] == nil {
				wrapperCandidates[fn.Name] = make(map[string]struct{})
			}
			wrapperCandidates[fn.Name][canonical] = struct{}{}
		}
	}
	a.lsmWrapperHooks = make(map[string]string)
	for wrapper, candidates := range wrapperCandidates {
		if len(candidates) != 1 {
			continue
		}
		for canonical := range candidates {
			a.lsmWrapperHooks[wrapper] = canonical
		}
	}
	a.lsmMetadataBuilt = true
	return nil
}

func (a *Analyzer) reconfigureAllLSMHooks() {
	for _, fn := range a.functions {
		active, inactive := a.partitionConfiguredLSMHooks(fn.DirectLSMHooks)
		fn.DirectLSMHooks = active
		fn.InactiveLSMHooks = uniqueStrings(append(fn.InactiveLSMHooks, inactive...))
		fn.RawCallees = subtractPreserve(fn.RawCallees, inactive)
		activeMust, inactiveMust := a.partitionConfiguredLSMHooks(fn.CFGMustSuccessLSM)
		fn.CFGMustSuccessLSM = activeMust
		fn.InactiveLSMHooks = uniqueStrings(append(fn.InactiveLSMHooks, inactiveMust...))
		fn.CFGMustSuccessCalls = subtractPreserve(fn.CFGMustSuccessCalls, inactiveMust)
		a.configureCFGBlocks(fn)
	}
}

func (a *Analyzer) canonicalBPFLSMHook(wrapper string) string {
	return a.lsmWrapperHooks[wrapper]
}

func enrichSignalChecks(info *FunctionInfo, bodySpan span, source, tagSource string) {
	startLine := strings.Count(source[:bodySpan.start], "\n") + 1
	endLine := strings.Count(source[:bodySpan.end], "\n") + 1
	tagLines := strings.Split(tagSource, "\n")
	if startLine > len(tagLines) {
		return
	}
	if endLine > len(tagLines) {
		endLine = len(tagLines)
	}
	tags := extractSignalChecks(strings.Join(tagLines[startLine-1:endLine], "\n"))
	set := orderedSet(info.DirectSigChecks)
	set.addAll(tags)
	info.DirectSigChecks = set.slice()
}

func (a *Analyzer) addFunction(fn *FunctionInfo) {
	if _, exists := a.functions[fn.ID]; exists {
		return
	}
	if fn.Frontend == "" {
		fn.Frontend = "legacy-text"
	}
	a.functions[fn.ID] = fn
	a.displayIndex[fn.DisplayName] = fn.ID
	a.nameIndex[fn.Name] = appendUnique(a.nameIndex[fn.Name], fn.ID)
	if fn.Inline {
		return
	}
	if fn.Static {
		if _, ok := a.staticIndex[fn.File]; !ok {
			a.staticIndex[fn.File] = make(map[string][]string)
		}
		a.staticIndex[fn.File][fn.Name] = appendUnique(a.staticIndex[fn.File][fn.Name], fn.ID)
		return
	}
	a.globalIndex[fn.Name] = appendUnique(a.globalIndex[fn.Name], fn.ID)
}

type span struct {
	start int
	end   int
}

type parsedFunction struct {
	info     *FunctionInfo
	bodySpan span
}

func (a *Analyzer) extractSyscallFunctions(path, src string) []parsedFunction {
	matches := a.syscallMacroRE.FindAllStringSubmatchIndex(src, -1)
	result := make([]parsedFunction, 0, len(matches))
	for _, match := range matches {
		macroName := src[match[2]:match[3]]
		syscallName := src[match[4]:match[5]]
		macroOpen := strings.LastIndex(src[match[0]:match[4]], "(")
		if macroOpen < 0 {
			continue
		}
		macroOpen += match[0]
		openBrace := strings.Index(src[match[1]:], "{")
		if openBrace < 0 {
			continue
		}
		openBrace += match[1]
		closeBrace, ok := findMatchingBrace(src, openBrace)
		if !ok {
			continue
		}

		fnName := "__do_sys_" + syscallName
		if strings.HasPrefix(macroName, "COMPAT_") {
			fnName = "__do_compat_sys_" + syscallName
		}
		body := src[openBrace+1 : closeBrace]
		relPath := path
		parameters := extractSyscallMacroParameterNames(src, macroOpen)
		result = append(result, parsedFunction{
			info: &FunctionInfo{
				ID:              fnName,
				Name:            fnName,
				DisplayName:     fnName,
				ReturnType:      "long",
				Parameters:      parameters,
				StructVariables: extractSyscallMacroStructVariables(src, macroOpen, body),
				File:            path,
				RelFile:         relPath,
				RawCallees:      extractDirectCallees(body),
				DirectLSMHooks:  extractLSMHooks(body),
				DirectSigChecks: extractSignalChecks(body),
				IndirectCalls:   extractIndirectCalls(body),
				Body:            body,
			},
			bodySpan: span{start: openBrace, end: closeBrace},
		})
	}
	return result
}

func extractOrdinaryFunctions(path, src string) []parsedFunction {
	result := []parsedFunction{}
	structuralSource := maskStringAndCharLiterals(src)
	depth := 0
	for i := 0; i < len(structuralSource); i++ {
		switch structuralSource[i] {
		case '{':
			if depth == 0 {
				if fn, ok := parseFunctionAtBrace(path, src, i); ok {
					result = append(result, fn)
				}
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return result
}

func parseFunctionAtBrace(path, src string, openBrace int) (parsedFunction, bool) {
	j := openBrace - 1
	for j >= 0 && unicode.IsSpace(rune(src[j])) {
		j--
	}
	if j < 0 || src[j] != ')' {
		return parsedFunction{}, false
	}

	openParen, ok := findMatchingParenBackward(src, j)
	if !ok {
		return parsedFunction{}, false
	}

	nameEnd := openParen - 1
	for nameEnd >= 0 && unicode.IsSpace(rune(src[nameEnd])) {
		nameEnd--
	}
	if nameEnd < 0 {
		return parsedFunction{}, false
	}

	nameStart := nameEnd
	for nameStart >= 0 && isIdentChar(src[nameStart]) {
		nameStart--
	}
	nameStart++
	if nameStart > nameEnd {
		return parsedFunction{}, false
	}
	name := src[nameStart : nameEnd+1]
	if shouldSkipFunctionName(name) {
		return parsedFunction{}, false
	}

	prefix := strings.TrimSpace(src[max(0, nameStart-32):nameStart])
	if strings.HasSuffix(prefix, "=") || strings.HasSuffix(prefix, ",") {
		return parsedFunction{}, false
	}

	closeBrace, ok := findMatchingBrace(src, openBrace)
	if !ok {
		return parsedFunction{}, false
	}
	body := src[openBrace+1 : closeBrace]
	signature := src[openParen+1 : j]
	static := looksStaticDeclaration(src, nameStart)
	id := makeFunctionID(path, name, static)
	display := name
	if isSyscallBodyName(name) {
		id = name
		static = false
	} else if static {
		display = fmt.Sprintf("%s@%s", name, path)
	}

	return parsedFunction{
		info: &FunctionInfo{
			ID:              id,
			Name:            name,
			DisplayName:     display,
			ReturnType:      extractFunctionReturnType(src, nameStart),
			Parameters:      extractParameterNames(signature),
			StructVariables: extractFunctionStructVariables(signature, body),
			File:            path,
			RelFile:         path,
			Static:          static,
			RawCallees:      extractDirectCallees(body),
			DirectLSMHooks:  extractLSMHooks(body),
			DirectSigChecks: extractSignalChecks(body),
			IndirectCalls:   extractIndirectCalls(body),
			Body:            body,
		},
		bodySpan: span{start: openBrace, end: closeBrace},
	}, true
}

func extractSyscallMacroParameterNames(source string, openParen int) []string {
	closeParen, ok := findMatchingParenForward(source, openParen)
	if !ok {
		return nil
	}
	arguments := splitTopLevelCommaList(source[openParen+1 : closeParen])
	parameters := make([]string, 0, len(arguments)/2)
	for index := 2; index < len(arguments); index += 2 {
		name := strings.TrimSpace(arguments[index])
		if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) {
			parameters = append(parameters, name)
		}
	}
	return parameters
}

func extractParameterNames(signature string) []string {
	parts := splitTopLevelCommaList(signature)
	parameters := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "void" || part == "..." {
			continue
		}
		match := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)*$`).FindStringSubmatch(part)
		if len(match) == 2 {
			parameters = append(parameters, match[1])
		}
	}
	return parameters
}

func extractSyscallMacroStructVariables(source string, openParen int, body string) map[string]string {
	variables := extractFunctionStructVariables("", body)
	closeParen, ok := findMatchingParenForward(source, openParen)
	if !ok {
		return variables
	}
	arguments := splitTopLevelCommaList(source[openParen+1 : closeParen])
	for index := 1; index+1 < len(arguments); index += 2 {
		structType, ok := expressionStructType(arguments[index])
		if !ok {
			continue
		}
		name := strings.TrimSpace(arguments[index+1])
		if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) {
			variables[name] = structType
		}
	}
	return variables
}

func extractFunctionStructVariables(signature, body string) map[string]string {
	variables := make(map[string]string)
	pattern := regexp.MustCompile(`\b(?:const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+__[A-Za-z_][A-Za-z0-9_]*)*\s*\*+\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\b`)
	for _, match := range pattern.FindAllStringSubmatch(signature+";"+body, -1) {
		variables[match[2]] = match[1]
	}
	return variables
}

func expressionStructType(expression string) (string, bool) {
	match := regexp.MustCompile(`\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\b`).FindStringSubmatch(expression)
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}

func (a *Analyzer) indexOperationTables(path, source string) {
	a.indexOperationLinks(source)
	a.indexClosedOperationTables(path, source)
	tableTypes := make(map[string]string)
	declarationPattern := regexp.MustCompile(`\b(?:static\s+)?(?:const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^;=]*\]\s*)?(?:=|;)`)
	for _, declaration := range declarationPattern.FindAllStringSubmatch(source, -1) {
		tableTypes[declaration[2]] = declaration[1]
	}

	initializerPattern := regexp.MustCompile(`\b(?:static\s+)?(?:const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^;=]*\]\s*)?(?:__[A-Za-z_][A-Za-z0-9_]*\s*)*=\s*\{`)
	fieldPattern := regexp.MustCompile(`^\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$`)
	for offset := 0; offset < len(source); {
		match := initializerPattern.FindStringSubmatchIndex(source[offset:])
		if match == nil {
			break
		}
		openBrace := offset + match[1] - 1
		closeBrace, ok := findMatchingBrace(source, openBrace)
		if !ok {
			offset += match[1]
			continue
		}
		structType := source[offset+match[2] : offset+match[3]]
		table := source[offset+match[4] : offset+match[5]]
		tableTypes[table] = structType
		for _, item := range splitTopLevelCommaList(source[openBrace+1 : closeBrace]) {
			field := fieldPattern.FindStringSubmatch(strings.TrimSpace(item))
			if len(field) != 3 {
				continue
			}
			a.addOperationTarget(OperationTarget{
				StructType: structType,
				Table:      table,
				Field:      field[1],
				Function:   field[2],
				File:       path,
			})
		}
		offset = closeBrace + 1
	}

	assignmentPattern := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])*\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;`)
	for _, assignment := range assignmentPattern.FindAllStringSubmatch(source, -1) {
		structType, ok := tableTypes[assignment[1]]
		if !ok {
			continue
		}
		a.addOperationTarget(OperationTarget{
			StructType: structType,
			Table:      assignment[1],
			Field:      assignment[2],
			Function:   assignment[3],
			File:       path,
		})
	}
}

func (a *Analyzer) indexClosedOperationTables(path, source string) {
	pattern := regexp.MustCompile(`\b(?:static\s+)?(const\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^;=]*\]\s*)?(?:__[A-Za-z_][A-Za-z0-9_]*\s*)*=\s*\{`)
	designator := regexp.MustCompile(`^\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)
	target := regexp.MustCompile(`^&?\s*([A-Za-z_][A-Za-z0-9_]*)$`)
	for offset := 0; offset < len(source); {
		match := pattern.FindStringSubmatchIndex(source[offset:])
		if match == nil {
			break
		}
		openBrace := offset + match[1] - 1
		closeBrace, ok := findMatchingBrace(source, openBrace)
		if !ok {
			offset += match[1]
			continue
		}
		info := &OperationTableInfo{
			StructType:       source[offset+match[4] : offset+match[5]],
			Table:            source[offset+match[6] : offset+match[7]],
			File:             path,
			Const:            match[2] >= 0,
			Complete:         true,
			FieldTargets:     make(map[string]string),
			FieldTargetFiles: make(map[string]string),
			NullFields:       make(map[string]bool),
			UnknownFields:    make(map[string]bool),
		}
		for _, item := range splitTopLevelCommaList(source[openBrace+1 : closeBrace]) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			field := designator.FindStringSubmatch(item)
			if len(field) != 3 {
				info.Complete = false
				continue
			}
			fieldName := field[1]
			value := strings.TrimSpace(field[2])
			switch normalizeCondition(value) {
			case "0", "NULL":
				info.NullFields[fieldName] = true
			default:
				function := target.FindStringSubmatch(value)
				if len(function) != 2 {
					info.UnknownFields[fieldName] = true
					continue
				}
				info.FieldTargets[fieldName] = function[1]
				info.FieldTargetFiles[fieldName] = path
			}
		}
		a.mergeOperationTableInfo(info)
		offset = closeBrace + 1
	}
}

func (a *Analyzer) mergeOperationTableInfo(info *OperationTableInfo) {
	if info == nil || info.Table == "" || info.StructType == "" || info.File == "" {
		return
	}
	key := info.File + "\x00" + info.Table
	existing, ok := a.operationTables[key]
	if !ok {
		a.operationTables[key] = info
		a.operationTablesByName[info.Table] = appendUnique(a.operationTablesByName[info.Table], key)
		return
	}
	if info.VerifiedByClang && !existing.VerifiedByClang {
		a.operationTables[key] = info
		return
	}
	if existing.VerifiedByClang && !info.VerifiedByClang {
		return
	}
	if existing.StructType != info.StructType ||
		existing.Const != info.Const {
		existing.Complete = false
		existing.VerifiedByClang = false
		for field := range existing.FieldTargets {
			existing.UnknownFields[field] = true
		}
		for field := range info.FieldTargets {
			existing.UnknownFields[field] = true
		}
		clear(existing.FieldTargets)
		clear(existing.FieldTargetFiles)
		clear(existing.NullFields)
		return
	}
	fields := orderedSet(nil)
	for field := range existing.FieldTargets {
		fields.add(field)
	}
	for field := range existing.NullFields {
		fields.add(field)
	}
	for field := range existing.UnknownFields {
		fields.add(field)
	}
	for field := range info.FieldTargets {
		fields.add(field)
	}
	for field := range info.NullFields {
		fields.add(field)
	}
	for field := range info.UnknownFields {
		fields.add(field)
	}
	for _, field := range fields.slice() {
		if operationTableFieldState(existing, field) ==
			operationTableFieldState(info, field) {
			continue
		}
		existing.UnknownFields[field] = true
		delete(existing.FieldTargets, field)
		delete(existing.FieldTargetFiles, field)
		delete(existing.NullFields, field)
	}
	existing.Complete = existing.Complete && info.Complete
}

func operationTableFieldState(
	info *OperationTableInfo,
	field string,
) string {
	if info == nil || info.UnknownFields[field] {
		return "unknown"
	}
	if target := info.FieldTargets[field]; target != "" {
		return "target:" + target + "@" +
			info.FieldTargetFiles[field]
	}
	if info.NullFields[field] {
		return "null"
	}
	return "absent"
}

func (a *Analyzer) indexOperationLinks(source string) {
	blockPattern := regexp.MustCompile(`\{([^{}]*)\}`)
	fieldPattern := regexp.MustCompile(`\.\s*(ops|prot)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)`)
	for _, block := range blockPattern.FindAllStringSubmatch(source, -1) {
		var opsTable string
		var protoTable string
		for _, field := range fieldPattern.FindAllStringSubmatch(block[1], -1) {
			switch field[1] {
			case "ops":
				opsTable = field[2]
			case "prot":
				protoTable = field[2]
			}
		}
		if opsTable == "" || protoTable == "" {
			continue
		}
		a.operationLinks[opsTable] = appendUnique(a.operationLinks[opsTable], protoTable)
		a.operationLinks[protoTable] = appendUnique(a.operationLinks[protoTable], opsTable)
	}
}

func (a *Analyzer) addOperationTarget(target OperationTarget) {
	if target.StructType == "" || target.Table == "" || target.Field == "" || target.Function == "" {
		return
	}
	key := structMemberKey(target.StructType, target.Field)
	for _, existing := range a.operationTargets[key] {
		if existing.Table == target.Table && existing.Function == target.Function && existing.File == target.File {
			return
		}
	}
	a.operationTargets[key] = append(a.operationTargets[key], target)
}

func splitTopLevelCommaList(value string) []string {
	masked := maskStringAndCharLiterals(value)
	parts := make([]string, 0, 8)
	start := 0
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				parts = append(parts, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	return parts
}

func isSyscallBodyName(name string) bool {
	return strings.HasPrefix(name, "__do_sys_") || strings.HasPrefix(name, "__do_compat_sys_")
}

func (a *Analyzer) resolveCalls() {
	for _, fn := range a.functions {
		resolved := orderedSet(nil)
		ambiguous := orderedSet(nil)
		unresolved := orderedSet(nil)
		for _, callee := range fn.RawCallees {
			ids, status := a.resolveCallee(fn, callee)
			switch status {
			case "resolved":
				resolved.addAll(ids)
			case "ambiguous":
				for _, id := range ids {
					ambiguous.add(a.functions[id].DisplayName)
				}
			default:
				unresolved.add(callee)
			}
		}
		fn.DirectCallees = resolved.slice()
		fn.AmbiguousCalls = ambiguous.slice()
		fn.UnresolvedCalls = unresolved.slice()
		fn.ResolvedIndirectCalls = a.buildIndirectCallResolutions(fn)
	}
}

func (a *Analyzer) resolveCallee(fn *FunctionInfo, callee string) ([]string, string) {
	if typed, typedKnown := fn.TypedCallees[callee]; typedKnown {
		typed = uniqueStrings(typed)
		resolved := make([]string, 0, len(typed))
		for _, id := range typed {
			if _, ok := a.functions[id]; ok {
				resolved = appendUnique(resolved, id)
			}
		}
		if len(resolved) != len(typed) {
			if renamed, ok := a.resolveFortifyRenamedCallee(
				fn,
				callee,
			); ok {
				return renamed, "resolved"
			}
			return resolved, "typed_target_incomplete"
		}
		if len(resolved) == 1 {
			return resolved, "resolved"
		}
		if len(resolved) > 1 {
			return resolved, "ambiguous"
		}
		return nil, "typed_target_unresolved"
	}
	if byFile, ok := a.staticIndex[fn.File]; ok {
		if ids := byFile[callee]; len(ids) == 1 {
			return []string{ids[0]}, "resolved"
		} else if len(ids) > 1 {
			return append([]string(nil), ids...), "ambiguous"
		}
	}
	if ids := a.globalIndex[callee]; len(ids) == 1 {
		return []string{ids[0]}, "resolved"
	} else if len(ids) > 1 {
		return append([]string(nil), ids...), "ambiguous"
	}
	candidates := a.nameIndex[callee]
	if len(candidates) == 1 {
		return []string{candidates[0]}, "resolved"
	}
	if len(candidates) > 1 {
		return append([]string(nil), candidates...), "ambiguous"
	}
	return nil, "unresolved"
}

func (a *Analyzer) resolveFortifyRenamedCallee(
	fn *FunctionInfo,
	callee string,
) ([]string, bool) {
	if fn == nil ||
		!strings.HasSuffix(
			filepath.ToSlash(fn.File),
			"/include/linux/fortify-string.h",
		) ||
		!strings.HasPrefix(callee, "__real_") {
		return nil, false
	}
	linkName := strings.TrimPrefix(callee, "__real_")
	if linkName == "" {
		return nil, false
	}
	ids := uniqueStrings(a.globalIndex[linkName])
	implementations := make([]string, 0, len(ids))
	for _, id := range ids {
		candidate := a.functions[id]
		if candidate == nil ||
			strings.HasSuffix(
				filepath.ToSlash(candidate.File),
				"/include/linux/fortify-string.h",
			) {
			continue
		}
		implementations = append(implementations, id)
	}
	implementations = uniqueStrings(implementations)
	if len(implementations) != 1 {
		return nil, false
	}
	return implementations, true
}

func (a *Analyzer) summarizeFunction(id string, _ map[string]bool) FunctionSummary {
	if cached, ok := a.summaryCache[id]; ok {
		return cached
	}
	if _, ok := a.functions[id]; !ok {
		return FunctionSummary{}
	}
	signalCoverage := a.analyzeSIGKILLPathCoverage(id)

	reachableFuncs := orderedSet(nil)
	lsmHooks := orderedSet(nil)
	sigChecks := orderedSet(nil)
	alwaysLSM := orderedSet(nil)
	alwaysSig := orderedSet(nil)
	validatedLSM := orderedSet(nil)
	validatedSig := orderedSet(nil)
	mustPassLSM := orderedSet(nil)
	inactiveLSM := orderedSet(nil)
	normalPathFuncs := orderedSet(nil)
	signalPathFuncs := orderedSet(nil)
	strongSigChecks := orderedSet(nil)
	currentReachableSignals := orderedSet(nil)
	currentAlwaysSignals := orderedSet(nil)
	unknownSubjectSignals := orderedSet(nil)
	lsmProofGaps := make([]UnresolvedProofEdge, 0)
	signalReachabilityGaps := make([]UnresolvedProofEdge, 0)
	signalAbortGaps := make([]UnresolvedProofEdge, 0)
	lsmProofGapSeen := make(map[string]struct{})
	signalReachabilityGapSeen := make(map[string]struct{})
	signalAbortGapSeen := make(map[string]struct{})
	addSignalReachabilityGap := func(gap UnresolvedProofEdge) {
		addProofGap(&signalReachabilityGaps, signalReachabilityGapSeen, gap)
	}
	addSignalAbortGap := func(gap UnresolvedProofEdge) {
		addProofGap(&signalAbortGaps, signalAbortGapSeen, gap)
	}
	alwaysSignalPathIndex := make(map[string]int)
	alwaysSignalCheckPaths := make([]SignalCheckPath, 0)

	rawVisited := make(map[string]bool)
	var walkRaw func(string)
	walkRaw = func(functionID string) {
		if rawVisited[functionID] {
			return
		}
		fn, ok := a.functions[functionID]
		if !ok {
			return
		}
		rawVisited[functionID] = true
		reachableFuncs.add(fn.DisplayName)
		lsmHooks.addAll(fn.DirectLSMHooks)
		for _, calleeID := range fn.DirectCallees {
			walkRaw(calleeID)
		}
	}
	walkRaw(id)

	allVisited := make(map[string]bool)
	var walkAll func(string)
	walkAll = func(functionID string) {
		if allVisited[functionID] {
			return
		}
		fn, ok := a.functions[functionID]
		if !ok {
			return
		}
		allVisited[functionID] = true
		scan := a.cachedAllInvocationScan(fn)
		alwaysLSM.addAll(scan.lsmHooks)
		for _, calleeID := range a.resolvePrefixCallees(fn, scan.callees) {
			walkAll(calleeID)
		}
	}
	walkAll(id)

	validatedVisited := make(map[string]bool)
	var walkValidated func(string)
	walkValidated = func(functionID string) {
		if validatedVisited[functionID] {
			return
		}
		fn, ok := a.functions[functionID]
		if !ok {
			return
		}
		validatedVisited[functionID] = true
		scan := a.cachedValidatedScan(fn)
		for _, gap := range a.proofGapsForScan("lsm", fn, scan, nil, false) {
			addProofGap(&lsmProofGaps, lsmProofGapSeen, gap)
		}
		validatedLSM.addAll(scan.lsmHooks)
		validatedSig.addAll(scan.sigChecks)
		for _, calleeID := range a.resolvePrefixCallees(fn, scan.callees) {
			walkValidated(calleeID)
		}
	}
	walkValidated(id)
	validatedLSM.addAll(alwaysLSM.slice())
	validatedSig.addAll(alwaysSig.slice())

	successVisited := make(map[string]bool)
	successActive := make(map[string]bool)
	var walkSuccess func(string, map[string]string, []string, []signalEffectPathNode, *IndirectCallEvidence)
	walkSuccess = func(functionID string, constants map[string]string, path []string, effectPath []signalEffectPathNode, incomingIndirect *IndirectCallEvidence) {
		fn, ok := a.functions[functionID]
		if !ok || isDiagnosticBarrier(fn) {
			return
		}
		if a.signalEffectSourceState(functionID) == effectSourceNone &&
			a.lsmEffectSourceState(functionID) == effectSourceNone {
			normalPathFuncs.add(fn.DisplayName)
			return
		}
		contextKey := functionContextKey(fn, constants)
		if successActive[contextKey] {
			addSignalReachabilityGap(UnresolvedProofEdge{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "recursive_mandatory_cycle",
				Detail: "mandatory signal coverage is not guessed across a recursive cycle",
			})
			return
		}
		if successVisited[contextKey] {
			return
		}
		successVisited[contextKey] = true
		successActive[contextKey] = true
		defer delete(successActive, contextKey)
		path = append(append([]string(nil), path...), fn.DisplayName)
		effectPath = append(append([]signalEffectPathNode(nil), effectPath...), signalEffectPathNode{
			functionID:       functionID,
			constants:        cloneStringMap(constants),
			incomingIndirect: incomingIndirect,
		})
		normalPathFuncs.add(fn.DisplayName)
		scan := a.cachedContextSuccessScan(fn, constants)
		mustPassLSM.addAll(scan.lsmHooks)
		inactiveLSM.addAll(scan.inactiveLSMHooks)
		normalPathFuncs.addAll(scan.lsmHooks)
		body := substituteIdentifierConstants(fn.Body, constants)
		for _, check := range scan.sigChecks {
			for _, evidence := range a.signalCheckEvidences(
				fn,
				body,
				check,
				true,
				invocationCallSiteIDs(scan.calls, check),
			) {
				if evidence.relevance == signalSIGKILLIrrelevant {
					continue
				}
				if evidence.relevance == signalSIGKILLUnknown {
					addSignalReachabilityGap(UnresolvedProofEdge{
						Domain: "sigkill",
						Caller: fn.DisplayName,
						Kind:   "signal_state_unresolved",
						Symbol: check,
						Detail: "the mandatory signal callsite " + evidence.callSiteID + " has no compile-time state mask with proven SIGKILL semantics",
					})
					continue
				}
				alwaysSig.add(check)
				effect := a.analyzeSignalAbortEffect(
					effectPath,
					check,
					evidence.localSite,
					evidence.requireSpecificSite,
				)
				abortEffect := classifyFinalSignalAbortEffect(effect)
				if evidence.subject == "current-task" {
					currentAlwaysSignals.add(check)
					if abortEffect == "unknown" {
						addSignalAbortGap(UnresolvedProofEdge{
							Domain: "sigkill",
							Caller: fn.DisplayName,
							Kind:   "signal_abort_effect_unresolved",
							Symbol: check,
							Detail: "the current-task predicate at " + evidence.callSiteID + " is evaluated, but syscall termination is not proven",
						})
					}
				}
				candidate := SignalCheckPath{
					Check:             check,
					CallSiteID:        evidence.callSiteID,
					Category:          signalCheckCategory(check),
					SIGKILLRelevance:  evidence.relevance,
					Subject:           evidence.subject,
					Traversal:         "mandatory",
					Function:          fn.DisplayName,
					BlocksOperation:   effect.blocksOperation,
					TerminatesSyscall: effect.terminatesSyscall,
					ErrnoPropagation:  effect.errnoPropagation,
					FailureEncoding:   effect.failureEncoding,
					AbortEffect:       abortEffect,
					ProofPath:         append([]string(nil), path...),
				}
				pathKey := check + "\x00" + evidence.callSiteID + "\x00" + evidence.subject + "\x00" + abortEffect + "\x00" + fn.DisplayName
				if index, exists := alwaysSignalPathIndex[pathKey]; exists {
					if a.betterSignalCheckPath(candidate, alwaysSignalCheckPaths[index]) {
						alwaysSignalCheckPaths[index] = candidate
					}
				} else {
					alwaysSignalPathIndex[pathKey] = len(alwaysSignalCheckPaths)
					alwaysSignalCheckPaths = append(alwaysSignalCheckPaths, candidate)
				}
			}
		}
		for _, call := range a.resolveContextCallsInContext(fn, constants, scan) {
			child := a.functions[call.functionID]
			if child != nil && isSignalCheckName(child.Name) {
				continue
			}
			if a.signalEffectSourceState(call.functionID) == effectSourceNone &&
				a.lsmEffectSourceState(call.functionID) == effectSourceNone {
				if child != nil {
					normalPathFuncs.add(child.DisplayName)
				}
				continue
			}
			if call.indirect != nil {
				continue
			}
			walkSuccess(call.functionID, call.constants, path, effectPath, nil)
		}
	}
	walkSuccess(id, nil, nil, nil, nil)

	signalDominance := make(map[string][]signalDominanceState)
	signalActive := make(map[string]bool)
	signalPathIndex := make(map[string]int)
	signalCheckPaths := make([]SignalCheckPath, 0)
	signalStats := SignalTraversalStats{}
	signalStarted := time.Now()
	lastSignalProgress := signalStarted
	var walkSignals func(string, map[string]string, map[string][]string, []string, []signalEffectPathNode, *IndirectCallEvidence, []IndirectCallEvidence)
	walkSignals = func(functionID string, constants map[string]string, operationContext map[string][]string, path []string, effectPath []signalEffectPathNode, incomingIndirect *IndirectCallEvidence, indirectEdges []IndirectCallEvidence) {
		fn, ok := a.functions[functionID]
		if !ok || isSignalTraversalBarrier(fn) {
			return
		}
		if a.signalEffectSourceState(functionID) == effectSourceNone {
			signalPathFuncs.add(fn.DisplayName)
			return
		}
		activeKey := functionContextKey(fn, constants) + operationContextKey(operationContext)
		if signalActive[activeKey] {
			addSignalReachabilityGap(UnresolvedProofEdge{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "recursive_signal_cycle",
				Detail: "the recursive may-reach state was not expanded while the function was active",
			})
			return
		}
		if !a.admitSignalState(signalDominance, functionID, constants, operationContext, &signalStats) {
			return
		}
		signalActive[activeKey] = true
		defer delete(signalActive, activeKey)
		if signalStats.VisitedStates%1024 == 0 && time.Since(lastSignalProgress) >= 5*time.Second {
			fmt.Fprintf(
				os.Stderr,
				"signal traversal: root=%s states=%d dominance-skips=%d dominated=%d transition-cache-hits=%d transition-builds=%d active-depth=%d elapsed=%s\n",
				a.functions[id].DisplayName,
				signalStats.VisitedStates,
				signalStats.DominanceSkips,
				signalStats.DominatedStates,
				signalStats.TransitionCacheHits,
				signalStats.TransitionBuilds,
				len(signalActive),
				time.Since(signalStarted).Round(time.Second),
			)
			lastSignalProgress = time.Now()
		}
		signalPathFuncs.add(fn.DisplayName)
		path = append(append([]string(nil), path...), fn.DisplayName)
		effectPath = append(append([]signalEffectPathNode(nil), effectPath...), signalEffectPathNode{
			functionID:       functionID,
			constants:        cloneStringMap(constants),
			incomingIndirect: incomingIndirect,
		})
		scan := a.cachedContextSignalScan(fn, constants)
		for _, gap := range a.signalRelevantProofGaps(fn, scan, constants, operationContext) {
			addSignalReachabilityGap(gap)
		}
		body := substituteIdentifierConstants(fn.Body, constants)
		successScan := a.cachedContextSuccessScan(fn, constants)
		for _, check := range scan.sigChecks {
			for _, evidence := range a.signalCheckEvidences(
				fn,
				body,
				check,
				false,
				invocationCallSiteIDs(scan.calls, check),
			) {
				if evidence.relevance == signalSIGKILLIrrelevant {
					continue
				}
				if evidence.relevance == signalSIGKILLUnknown {
					addSignalReachabilityGap(UnresolvedProofEdge{
						Domain: "sigkill",
						Caller: fn.DisplayName,
						Kind:   "signal_state_unresolved",
						Symbol: check,
						Detail: "signal callsite " + evidence.callSiteID + " is reachable, but its task-state mask is not proven to observe SIGKILL",
					})
					continue
				}
				sigChecks.add(check)
				effect := a.analyzeSignalAbortEffect(
					effectPath,
					check,
					evidence.localSite,
					evidence.requireSpecificSite,
				)
				abortEffect := classifyFinalSignalAbortEffect(effect)
				if evidence.subject == "current-task" {
					currentReachableSignals.add(check)
					if abortEffect == "unknown" {
						addSignalAbortGap(UnresolvedProofEdge{
							Domain: "sigkill",
							Caller: fn.DisplayName,
							Kind:   "signal_abort_effect_unresolved",
							Symbol: check,
							Detail: "the signal predicate at " + evidence.callSiteID + " is reachable, but its abort is not proven to reach the syscall",
						})
					}
				} else {
					unknownSubjectSignals.add(check)
					if abortEffect != "not_effective" {
						addSignalReachabilityGap(UnresolvedProofEdge{
							Domain: "sigkill",
							Caller: fn.DisplayName,
							Kind:   "signal_subject_unresolved",
							Symbol: check,
							Detail: "the signal predicate subject at " + evidence.callSiteID + " is not proven to be current",
						})
					}
				}
				traversal := "unknown"
				switch {
				case evidence.callSiteID != "" &&
					containsString(fn.CFGMustSuccessCallSites, evidence.callSiteID):
					traversal = "locally-mandatory"
				case evidence.callSiteID == "" && containsString(successScan.sigChecks, check):
					traversal = "locally-mandatory"
				case fn.Frontend == "clang-ast-cfg" && fn.CFGComplete &&
					fn.CFGHasSuccessExit && !fn.FrontendVariantConflict:
					traversal = "locally-conditional"
				}
				candidate := SignalCheckPath{
					Check:             check,
					CallSiteID:        evidence.callSiteID,
					Category:          signalCheckCategory(check),
					SIGKILLRelevance:  evidence.relevance,
					Subject:           evidence.subject,
					Traversal:         traversal,
					Function:          fn.DisplayName,
					BlocksOperation:   effect.blocksOperation,
					TerminatesSyscall: effect.terminatesSyscall,
					ErrnoPropagation:  effect.errnoPropagation,
					FailureEncoding:   effect.failureEncoding,
					AbortEffect:       abortEffect,
					ProofPath:         append([]string(nil), path...),
					IndirectEdges:     cloneIndirectEvidence(indirectEdges),
				}
				pathKey := check + "\x00" + evidence.callSiteID + "\x00" + evidence.subject + "\x00" + traversal + "\x00" + abortEffect + "\x00" + fn.DisplayName
				if len(indirectEdges) > 0 {
					pathKey += "\x00indirect"
				}
				if index, ok := signalPathIndex[pathKey]; ok {
					if a.betterSignalCheckPath(candidate, signalCheckPaths[index]) {
						signalCheckPaths[index] = candidate
					}
					continue
				}
				signalPathIndex[pathKey] = len(signalCheckPaths)
				signalCheckPaths = append(signalCheckPaths, candidate)
			}
		}
		for _, call := range a.cachedSignalTransitions(fn, constants, scan, operationContext, &signalStats) {
			child := a.functions[call.functionID]
			if child != nil && isSignalCheckName(child.Name) {
				continue
			}
			if a.signalEffectSourceState(call.functionID) == effectSourceNone {
				continue
			}
			edgeEffect := a.signalTransitionEffect(fn, constants, call)
			effectClass := classifySignalAbortEffect(edgeEffect)
			if effectClass == "not_effective" {
				continue
			}
			nextEdges := indirectEdges
			if call.indirect != nil {
				nextEdges = append(cloneIndirectEvidence(indirectEdges), cloneIndirectEvidence([]IndirectCallEvidence{*call.indirect})...)
			}
			walkSignals(call.functionID, call.constants, call.operationContext, path, effectPath, call.indirect, nextEdges)
		}
	}
	if a.cfg.EmitRaw {
		walkSignals(id, nil, nil, nil, nil, nil, nil)
	} else {
		sigChecks.addAll(signalCoverage.checks)
		currentReachableSignals.addAll(signalCoverage.checks)
		signalPathFuncs.addAll(signalCoverage.proofFunctions)
		signalCheckPaths = mergeSignalCheckPaths(
			signalCheckPaths,
			signalCoverage.checkPaths,
		)
		for _, gap := range signalCoverage.unresolved {
			addSignalReachabilityGap(gap)
		}
	}
	strongSigChecks.addAll(strongSignalChecks(sigChecks.slice()))
	signalProofGaps := uniqueProofEdges(append(
		append([]UnresolvedProofEdge(nil), signalReachabilityGaps...),
		signalAbortGaps...,
	))

	summary := FunctionSummary{
		ReachableLSMHooks:       lsmHooks.slice(),
		ReachableSigChecks:      sigChecks.slice(),
		ReachableFuncs:          reachableFuncs.slice(),
		AlwaysLSMHooks:          alwaysLSM.slice(),
		AlwaysSigChecks:         alwaysSig.slice(),
		ValidatedLSMHooks:       validatedLSM.slice(),
		ValidatedSigChecks:      validatedSig.slice(),
		MustPassLSMHooks:        mustPassLSM.slice(),
		InactiveLSMHooks:        inactiveLSM.slice(),
		NormalPathFuncs:         normalPathFuncs.slice(),
		StrongSigChecks:         strongSigChecks.slice(),
		CurrentReachableSignals: currentReachableSignals.slice(),
		CurrentAlwaysSignals:    currentAlwaysSignals.slice(),
		UnknownSubjectSignals:   unknownSubjectSignals.slice(),
		SignalPathFuncs:         signalPathFuncs.slice(),
		SignalCheckPaths:        signalCheckPaths,
		AlwaysSignalCheckPaths:  alwaysSignalCheckPaths,
		LSMProofGaps:            sortedProofGaps(lsmProofGaps),
		SignalReachabilityGaps:  sortedProofGaps(signalReachabilityGaps),
		SignalAbortGaps:         sortedProofGaps(signalAbortGaps),
		SignalProofGaps:         sortedProofGaps(signalProofGaps),
		SignalStats:             signalStats,
	}
	a.summaryCache[id] = summary
	return summary
}

func isSignalTraversalBarrier(fn *FunctionInfo) bool {
	if isDiagnosticBarrier(fn) {
		return true
	}
	switch fn.Name {
	case "madvise_inject_error":
		return true
	case "schedule", "__schedule", "schedule_idle", "schedule_preempt_disabled",
		"preempt_schedule", "preempt_schedule_irq", "preempt_schedule_notrace",
		"cond_resched", "_cond_resched", "io_schedule", "io_schedule_timeout":
		return true
	default:
		return false
	}
}

func isDiagnosticBarrier(fn *FunctionInfo) bool {
	switch fn.Name {
	case "schedule_debug", "debug_hrtimer_init", "debug_init", "test_taint", "dynamic_debug_setup",
		"dump_stack", "dump_stack_lvl", "__dump_stack", "dump_stack_print_info", "print_tainted", "show_trace_log_lvl":
		return true
	default:
		return false
	}
}

func (a *Analyzer) signalTransitionEffect(parent *FunctionInfo, parentConstants map[string]string, call resolvedContextCall) localErrorEffect {
	child := a.functions[call.functionID]
	if parent == nil || child == nil {
		return unknownLocalErrorEffect()
	}
	body := substituteIdentifierConstants(parent.Body, parentConstants)
	if call.indirect != nil {
		return a.analyzeIndirectCallErrorEffect(parent, body, call.indirect.Expression)
	}
	return a.analyzeNamedCallErrorEffect(
		parent,
		body,
		child.Name,
		call.constants[contextReturnRequirementKey],
		parentConstants[contextReturnRequirementKey],
	)
}

func (a *Analyzer) analyzeNamedCallErrorEffect(
	fn *FunctionInfo,
	body, callee string,
	requirements ...string,
) localErrorEffect {
	effectiveRequirements := append([]string(nil), requirements...)
	if !a.buildingEffectSources && fn != nil &&
		(len(effectiveRequirements) == 0 || effectiveRequirements[0] == "") {
		if requirement := a.inferredCalleeFailureRequirement(fn, callee); requirement != "" {
			if len(effectiveRequirements) == 0 {
				effectiveRequirements = append(effectiveRequirements, requirement)
			} else {
				effectiveRequirements[0] = requirement
			}
		}
	}
	effect := analyzeNamedCallErrorEffect(body, callee, effectiveRequirements...)
	requirement := ""
	if len(effectiveRequirements) > 0 {
		requirement = effectiveRequirements[0]
	}
	if contract, ok := reviewedKernelCallFailureEffect(
		fn,
		callee,
		failureEncodingForRequirement(requirement),
	); ok {
		return contract
	}
	if classifySignalAbortEffect(effect) != "unknown" || fn == nil || fn.FrontendVariantConflict {
		return effect
	}
	if a.llvmCallMustReturnExact(fn, callee) {
		requirement := ""
		if len(effectiveRequirements) > 0 {
			requirement = effectiveRequirements[0]
		}
		return guaranteedEncodedLocalErrorEffect(
			"exact",
			failureEncodingForRequirement(requirement),
			nil,
		)
	}
	if (requirement == "" || requirement == "failure_false") &&
		a.llvmCallMustReturnNegative(fn, callee, requirement) {
		return guaranteedEncodedLocalErrorEffect(
			"normalized",
			failureReturnErrno,
			nil,
		)
	}
	if a.llvmCallResultDefinitelyIgnored(fn, callee) ||
		fn.callResultDefinitelyDiscarded(callee, "", true) {
		return ignoredLocalErrorEffect()
	}
	if cfgEffect := a.analyzeCFGNamedCallFailureEffect(
		fn,
		callee,
		requirement,
	); classifySignalAbortEffect(cfgEffect) == "guaranteed" {
		return cfgEffect
	}
	forwarded := make([]localErrorEffect, 0)
	for _, site := range findNamedCallSites(body, callee) {
		variable := assignedCallTarget(body, site.start)
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(variable) {
			return effect
		}
		statementEnd := findNextTopLevelSemicolon(body, site.end)
		if statementEnd < 0 {
			return effect
		}
		suffix := strings.TrimSpace(body[statementEnd+1:])
		match := regexp.MustCompile(`(?s)^return\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*;\s*$`).FindStringSubmatch(suffix)
		if len(match) != 3 {
			return effect
		}
		arguments := splitTopLevelCommaList(match[2])
		argumentIndex := -1
		for index, argument := range arguments {
			if compactExpression(argument) == variable {
				if argumentIndex >= 0 {
					return effect
				}
				argumentIndex = index
			}
		}
		if argumentIndex < 0 {
			return effect
		}
		ids, status := a.resolveCallee(fn, match[1])
		if status != "resolved" || len(ids) != 1 {
			return effect
		}
		wrapper := a.functions[ids[0]]
		if wrapper == nil || wrapper.Frontend != "clang-ast-cfg" ||
			!wrapper.CFGComplete || wrapper.FrontendVariantConflict ||
			argumentIndex >= len(wrapper.Parameters) {
			return effect
		}
		propagation := analyzeErrorParameterPropagation(wrapper.Body, wrapper.Parameters[argumentIndex])
		if classifySignalAbortEffect(propagation) != "guaranteed" {
			return effect
		}
		forwarded = append(forwarded, propagation)
	}
	if len(forwarded) == 0 {
		return effect
	}
	return mergeLocalErrorEffects(forwarded)
}

type cfgCallFailureState struct {
	blockID     int
	values      map[string]cfgPathValue
	constraints []successPathConstraint
	visited     map[int]bool
	injectCall  bool
}

func (a *Analyzer) analyzeCFGNamedCallFailureEffect(
	fn *FunctionInfo,
	callee, requirement string,
) localErrorEffect {
	if fn == nil || fn.Frontend != "clang-ast-cfg" ||
		!fn.CFGComplete || fn.FrontendVariantConflict ||
		callee == "" {
		return unknownLocalErrorEffect()
	}
	sites := make([]ClangCallSite, 0)
	for _, site := range fn.CallSites {
		if site.Direct && site.Reachable && site.HasBlock &&
			site.Name == callee {
			sites = append(sites, site)
		}
	}
	if len(sites) == 0 {
		return unknownLocalErrorEffect()
	}
	effects := make([]localErrorEffect, 0, len(sites))
	effectClass := ""
	for index := range sites {
		effect := a.analyzeCFGNamedCallSiteFailureEffect(
			fn,
			&sites[index],
			requirement,
		)
		currentClass := classifySignalAbortEffect(effect)
		if currentClass != "guaranteed" &&
			currentClass != "not_effective" {
			return unknownLocalErrorEffect()
		}
		if effectClass == "" {
			effectClass = currentClass
		} else if effectClass != currentClass {
			return unknownLocalErrorEffect()
		}
		effects = append(effects, effect)
	}
	return mergeLocalErrorEffects(effects)
}

func (a *Analyzer) analyzeCFGNamedCallSiteFailureEffect(
	fn *FunctionInfo,
	site *ClangCallSite,
	requirement string,
) localErrorEffect {
	if fn == nil || site == nil || site.ID == "" {
		return unknownLocalErrorEffect()
	}
	failureValue, ok := cfgCallFailureValue(site, requirement)
	if !ok {
		return unknownLocalErrorEffect()
	}
	source, ok := cfgBlockByID(fn, site.BlockID)
	if !ok || !cfgBlockHasSingleCallResultWrite(source, site.ID) {
		return unknownLocalErrorEffect()
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	queue := []cfgCallFailureState{{
		blockID:    source.ID,
		visited:    map[int]bool{source.ID: true},
		injectCall: true,
	}}
	encoding := ""
	sawFailureReturn := false
	sawSuccessReturn := false
	processed := 0
	const maxCallFailureStates = 4096
	for len(queue) > 0 {
		if processed >= maxCallFailureStates {
			return unknownLocalErrorEffect()
		}
		processed++
		state := queue[0]
		queue = queue[1:]
		block, exists := blocks[state.blockID]
		if !exists {
			return unknownLocalErrorEffect()
		}
		values, injected, valid := a.applyCFGCallFailureWrites(
			fn,
			block,
			state.values,
			site.ID,
			failureValue,
			state.injectCall,
		)
		if !valid || state.injectCall && !injected {
			return unknownLocalErrorEffect()
		}
		state.values = values
		if a.cfgFailureValuesHaveUnpreservedEscape(fn, values) {
			return unknownLocalErrorEffect()
		}
		if block.ReturnExpression != "" ||
			block.ReturnExpressionExpanded != "" {
			if !successPathConstraintsConsistent(
				fn,
				state.constraints,
			) {
				continue
			}
			outcome := cfgExpressionOutcomeWithValues(
				fn.ReturnType,
				fn.ReturnTypeBits,
				clangCFGReturnExpression(block),
				state.values,
				state.constraints,
			)
			candidateEncoding, guaranteed :=
				failureEncodingForReturnOutcome(outcome)
			if guaranteed {
				if encoding == "" {
					encoding = candidateEncoding
				} else if encoding != candidateEncoding {
					encoding = failureReturnUnknown
				}
				sawFailureReturn = true
				continue
			}
			successRequirement := defaultSuccessRequirement(
				fn.ReturnType,
			)
			if successRequirement == "" ||
				returnOutcomeCompatibility(
					outcome,
					successRequirement,
				) != "guaranteed" {
				return unknownLocalErrorEffect()
			}
			sawSuccessReturn = true
			continue
		}

		edges := allCFGSuccessorEdges(block)
		if len(edges) == 0 {
			return unknownLocalErrorEffect()
		}
		feasibleEdges := 0
		for _, edge := range edges {
			if !cfgFailureEdgeFeasible(
				block,
				edge,
				state.values,
			) {
				continue
			}
			feasibleEdges++
			if edge.blockID == fn.CFGExit {
				return unknownLocalErrorEffect()
			}
			if _, exists := blocks[edge.blockID]; !exists ||
				state.visited[edge.blockID] {
				return unknownLocalErrorEffect()
			}
			next := cfgCallFailureState{
				blockID: edge.blockID,
				values:  cloneCFGPathValues(state.values),
				constraints: append(
					[]successPathConstraint(nil),
					state.constraints...,
				),
				visited: make(
					map[int]bool,
					len(state.visited)+1,
				),
			}
			for blockID := range state.visited {
				next.visited[blockID] = true
			}
			next.visited[edge.blockID] = true
			if block.TerminatorCondition != "" &&
				(edge.branch == "true" ||
					edge.branch == "false") {
				next.constraints =
					canonicalSuccessPathConstraints(append(
						next.constraints,
						successPathConstraint{
							functionID: fn.ID,
							blockID:    block.ID,
							expression: strings.TrimSpace(
								block.TerminatorCondition,
							),
							required:   edge.branch == "true",
							pathStable: true,
						},
					))
			}
			queue = append(queue, next)
		}
		if feasibleEdges == 0 {
			return unknownLocalErrorEffect()
		}
	}
	if sawFailureReturn && sawSuccessReturn ||
		!sawFailureReturn && !sawSuccessReturn {
		return unknownLocalErrorEffect()
	}
	if sawSuccessReturn {
		return ignoredLocalErrorEffect()
	}
	if encoding == "" {
		encoding = failureReturnUnknown
	}
	return guaranteedEncodedLocalErrorEffect(
		"normalized",
		encoding,
		nil,
	)
}

func cfgCallFailureValue(
	site *ClangCallSite,
	requirement string,
) (cfgPathValue, bool) {
	if site == nil {
		return cfgPathValue{}, false
	}
	returnType := site.ReturnType
	if returnDomainForType(returnType) == returnDomainUnknown {
		returnType = semanticTypeForClangMetadata(
			site.ReturnTypeClass,
			site.ReturnTypeSigned,
		)
	}
	domain := returnDomainForType(returnType)
	expression := ""
	switch requirement {
	case "", "negative":
		if domain != returnDomainSigned {
			return cfgPathValue{}, false
		}
		expression = "-EACCES"
	case "failure_false":
		if domain != returnDomainBool &&
			domain != returnDomainSigned &&
			domain != returnDomainUnsigned {
			return cfgPathValue{}, false
		}
		expression = "0"
	case "nonnull":
		if domain != returnDomainPointer {
			return cfgPathValue{}, false
		}
		expression = "NULL"
	case "failure_err_ptr":
		if domain != returnDomainPointer {
			return cfgPathValue{}, false
		}
		expression = "ERR_PTR(-EACCES)"
	default:
		return cfgPathValue{}, false
	}
	typeClass := site.ReturnTypeClass
	typeSigned := site.ReturnTypeSigned
	if typeClass == "" {
		typeClass = domain
		typeSigned = domain == returnDomainSigned
	}
	return cfgPathValue{
		expression: expression,
		typeClass:  typeClass,
		typeSigned: typeSigned,
		typeBits:   site.ReturnTypeBits,
	}, true
}

func cfgBlockHasSingleCallResultWrite(
	block ClangCFGBlock,
	callSiteID string,
) bool {
	count := 0
	for _, write := range block.ValueWrites {
		if write.CallSiteID == callSiteID {
			count++
		}
	}
	return count == 1
}

func (a *Analyzer) applyCFGCallFailureWrites(
	fn *FunctionInfo,
	block ClangCFGBlock,
	input map[string]cfgPathValue,
	callSiteID string,
	failureValue cfgPathValue,
	inject bool,
) (map[string]cfgPathValue, bool, bool) {
	values := cloneCFGPathValues(input)
	injected := false
	for _, write := range block.ValueWrites {
		target := strings.TrimSpace(write.Target)
		if !regexp.MustCompile(
			`^[A-Za-z_][A-Za-z0-9_]*$`,
		).MatchString(target) {
			if inject && write.CallSiteID == callSiteID {
				return nil, false, false
			}
			continue
		}
		previous := values[target]
		delete(values, target)
		for name, value := range values {
			if expressionReferencesIdentifier(
				value.expression,
				target,
			) {
				delete(values, name)
			}
		}
		if inject && write.CallSiteID == callSiteID {
			if injected ||
				!a.cfgFailureVariableEscapePreserved(
					fn,
					target,
				) {
				return nil, false, false
			}
			forced := failureValue
			if forced.typeClass == "" {
				forced.typeClass = write.TargetTypeClass
				forced.typeSigned = write.TargetTypeSigned
				forced.typeBits = write.TargetTypeBits
			}
			if values == nil {
				values = make(map[string]cfgPathValue)
			}
			values[target] = forced
			injected = true
			continue
		}
		if write.Kind == "invalidate" ||
			strings.TrimSpace(write.Expression) == "" {
			continue
		}
		value, tracked := trackedCFGPathValue(
			write,
			values,
			previous,
		)
		if tracked {
			if !a.cfgFailureVariableEscapePreserved(
				fn,
				target,
			) {
				return nil, false, false
			}
			if values == nil {
				values = make(map[string]cfgPathValue)
			}
			values[target] = value
		}
	}
	if len(values) > 32 {
		return nil, false, false
	}
	return values, injected, true
}

func (a *Analyzer) cfgFailureValuesHaveUnpreservedEscape(
	fn *FunctionInfo,
	values map[string]cfgPathValue,
) bool {
	for identifier := range values {
		if !a.cfgFailureVariableEscapePreserved(
			fn,
			identifier,
		) {
			return true
		}
	}
	return false
}

func (a *Analyzer) cfgFailureVariableEscapePreserved(
	fn *FunctionInfo,
	identifier string,
) bool {
	if fn == nil || identifier == "" {
		return false
	}
	if !cfgVariableHasUnpreservedEscape(fn, identifier) {
		return true
	}
	addressPattern := regexp.MustCompile(
		`&\s*` + regexp.QuoteMeta(identifier) + `\b`,
	)
	addressUses := addressPattern.FindAllStringIndex(
		maskStringAndCharLiterals(fn.Body),
		-1,
	)
	if len(addressUses) == 0 {
		return false
	}
	closedUses := 0
	for _, site := range fn.CallSites {
		if !site.Direct || !site.Reachable {
			continue
		}
		ids, status := a.resolveCallee(fn, site.Name)
		if status != "resolved" || len(ids) != 1 {
			continue
		}
		child := a.functions[ids[0]]
		if child == nil {
			continue
		}
		for argumentIndex, argument := range site.Arguments {
			addressed, exact := exactAddressedIdentifier(argument)
			if !exact || addressed != identifier ||
				argumentIndex >= len(child.Parameters) ||
				!pointeeParameterWritesAreClosed(
					child,
					child.Parameters[argumentIndex],
				) {
				continue
			}
			closedUses++
		}
	}
	return closedUses == len(addressUses)
}

func cfgFailureEdgeFeasible(
	block ClangCFGBlock,
	edge cfgSuccessEdge,
	values map[string]cfgPathValue,
) bool {
	if block.TerminatorCondition == "" ||
		edge.branch != "true" && edge.branch != "false" {
		return true
	}
	condition := normalizedBranchExpression(
		block.TerminatorCondition,
	)
	required := edge.branch == "true"
	for identifier, value := range values {
		if !expressionReferencesIdentifier(
			condition,
			identifier,
		) {
			continue
		}
		returnType := semanticTypeForClangMetadata(
			value.typeClass,
			value.typeSigned,
		)
		if returnType == "unknown" {
			continue
		}
		outcome := cfgExpressionOutcomeWithValues(
			returnType,
			value.typeBits,
			identifier,
			values,
			nil,
		)
		requirement := outcomeRequirementFromCondition(
			returnType,
			condition,
			identifier,
			required,
		)
		if requirement == "" {
			continue
		}
		if returnOutcomeCompatibility(
			outcome,
			requirement,
		) == "impossible" {
			return false
		}
	}
	return true
}

func cfgExpressionOutcomeWithValues(
	returnType string,
	returnBits int,
	expression string,
	values map[string]cfgPathValue,
	constraints []successPathConstraint,
) returnOutcome {
	expression = stripSimpleCasts(compactExpression(expression))
	if identifier := expression; regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		if value, ok := values[identifier]; ok {
			valueType := semanticTypeForClangMetadata(
				value.typeClass,
				value.typeSigned,
			)
			if valueType == "unknown" {
				valueType = returnType
			}
			outcome := cfgExpressionOutcomeWithValues(
				valueType,
				value.typeBits,
				value.expression,
				valuesWithoutCFGIdentifier(values, identifier),
				constraints,
			)
			if returnDomainForType(valueType) ==
				returnDomainForType(returnType) {
				return outcome
			}
		}
	}
	if argument, ok := singleCallArgument(
		expression,
		"PTR_ERR",
	); ok && returnDomainForType(returnType) == returnDomainSigned {
		argumentOutcome := cfgExpressionOutcomeWithValues(
			"pointer",
			0,
			argument,
			values,
			constraints,
		)
		switch {
		case argumentOutcome.mask != 0 &&
			argumentOutcome.mask&^outcomePointerError == 0:
			return returnOutcome{
				domain: returnDomainSigned,
				mask:   outcomeNegative,
			}
		case argumentOutcome.mask != 0 &&
			argumentOutcome.mask&^outcomePointerNull == 0:
			return returnOutcome{
				domain: returnDomainSigned,
				mask:   outcomeZero,
			}
		}
	}
	if argument, ok := singleCallArgument(
		expression,
		"ERR_PTR",
	); ok && returnDomainForType(returnType) == returnDomainPointer {
		argumentOutcome := cfgExpressionOutcomeWithValues(
			"signed_integer",
			0,
			argument,
			values,
			constraints,
		)
		switch {
		case argumentOutcome.mask != 0 &&
			argumentOutcome.mask&^outcomeNegative == 0:
			return returnOutcome{
				domain: returnDomainPointer,
				mask:   outcomePointerError,
			}
		case argumentOutcome.mask != 0 &&
			argumentOutcome.mask&^outcomeZero == 0:
			return returnOutcome{
				domain: returnDomainPointer,
				mask:   outcomePointerNull,
			}
		}
	}
	if argument, ok := singleCallArgument(
		expression,
		"ERR_CAST",
	); ok && returnDomainForType(returnType) == returnDomainPointer {
		return cfgExpressionOutcomeWithValues(
			"pointer",
			returnBits,
			argument,
			values,
			constraints,
		)
	}
	function := &FunctionInfo{
		ReturnType:     returnType,
		ReturnTypeBits: returnBits,
	}
	return returnOutcomeFromExpression(
		function,
		expression,
		constraints,
		false,
		nil,
		"",
	)
}

func valuesWithoutCFGIdentifier(
	values map[string]cfgPathValue,
	identifier string,
) map[string]cfgPathValue {
	result := cloneCFGPathValues(values)
	delete(result, identifier)
	return result
}

const (
	failureReturnUnknown = "unknown"
	failureReturnNone    = "none"
	failureReturnErrno   = "errno"
	failureReturnFalse   = "false"
	failureReturnNull    = "null"
	failureReturnErrPtr  = "err_ptr"
)

func (a *Analyzer) inferredCalleeFailureRequirement(fn *FunctionInfo, callee string) string {
	ids, status := a.resolveCallee(fn, callee)
	if status != "resolved" && status != "ambiguous" || len(ids) == 0 {
		return ""
	}
	allFallibleAllocators := true
	for _, id := range ids {
		if !isCoreKernelFallibleAllocator(a.functions[id]) {
			allFallibleAllocators = false
			break
		}
	}
	if allFallibleAllocators {
		return "nonnull"
	}
	kinds := orderedSet(nil)
	for _, id := range ids {
		if a.lsmEffectSourcesBuilt && a.lsmEffectSourceCache[id] == effectSourcePossible {
			kinds.add(a.effectFailureReturnKind(id, "lsm", make(map[string]bool)))
		}
		if a.sigEffectSourcesBuilt && a.sigEffectSourceCache[id] == effectSourcePossible {
			kinds.add(a.effectFailureReturnKind(id, "sigkill", make(map[string]bool)))
		}
	}
	if len(kinds.items) != 1 {
		return ""
	}
	switch kinds.items[0] {
	case failureReturnFalse:
		return "failure_false"
	case failureReturnNull:
		return "nonnull"
	case failureReturnErrPtr:
		return "failure_err_ptr"
	default:
		return ""
	}
}

func (a *Analyzer) effectFailureReturnKind(
	functionID, domain string,
	active map[string]bool,
) string {
	cache := a.lsmFailureKindCache
	sourceCache := a.lsmEffectSourceCache
	if domain == "sigkill" {
		cache = a.sigFailureKindCache
		sourceCache = a.sigEffectSourceCache
	}
	if kind, ok := cache[functionID]; ok {
		return kind
	}
	switch sourceCache[functionID] {
	case effectSourceNone:
		cache[functionID] = failureReturnNone
		return failureReturnNone
	case effectSourceUnknown:
		cache[functionID] = failureReturnUnknown
		return failureReturnUnknown
	}
	if active[functionID] {
		return failureReturnUnknown
	}
	fn := a.functions[functionID]
	if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict {
		cache[functionID] = failureReturnUnknown
		return failureReturnUnknown
	}
	active[functionID] = true
	defer delete(active, functionID)

	kinds := orderedSet(nil)
	if domain == "lsm" {
		for _, hook := range fn.DirectLSMHooks {
			effect := analyzeNamedCallErrorEffect(fn.Body, hook)
			if a.classifyLSMHookKind(hook, effect) == "notification" ||
				classifySignalAbortEffect(effect) == "not_effective" {
				continue
			}
			kinds.add(a.mapCallFailureToFunctionReturn(
				fn,
				hook,
				failureReturnErrno,
			))
		}
	} else {
		for _, check := range fn.DirectSigChecks {
			relevance := a.signalCheckSIGKILLRelevance(fn, fn.Body, check, false)
			if relevance == signalSIGKILLIrrelevant {
				continue
			}
			if relevance == signalSIGKILLUnknown {
				kinds.add(failureReturnUnknown)
				continue
			}
			effect := analyzeSignalCheckLocalEffectForFunction(
				fn,
				fn.Body,
				check,
				nil,
			)
			switch classifySignalAbortEffect(effect) {
			case "guaranteed":
				kinds.add(effect.failureEncoding)
			case "conditional":
				if effect.failureEncoding == failureReturnErrno {
					kinds.add(failureReturnErrno)
				} else {
					kinds.add(failureReturnUnknown)
				}
			case "unknown":
				kinds.add(failureReturnUnknown)
			}
		}
	}

	for _, callee := range effectRelevantDirectCalls(fn) {
		if domain == "lsm" && strings.HasPrefix(callee, "security_") ||
			domain == "sigkill" && isSignalCheckName(callee) {
			continue
		}
		ids, status := a.resolveCallee(fn, callee)
		if status != "resolved" && status != "ambiguous" || len(ids) == 0 {
			continue
		}
		childKinds := orderedSet(nil)
		for _, id := range ids {
			if sourceCache[id] != effectSourcePossible {
				continue
			}
			childKinds.add(a.effectFailureReturnKind(id, domain, active))
		}
		if len(childKinds.items) == 0 {
			continue
		}
		if len(childKinds.items) != 1 {
			kinds.add(failureReturnUnknown)
			continue
		}
		kinds.add(a.mapCallFailureToFunctionReturn(
			fn,
			callee,
			childKinds.items[0],
		))
	}

	kind := failureReturnUnknown
	if len(kinds.items) == 1 {
		kind = kinds.items[0]
	}
	cache[functionID] = kind
	return kind
}

func (a *Analyzer) mapCallFailureToFunctionReturn(
	fn *FunctionInfo,
	callee, childKind string,
) string {
	if fn == nil || childKind == failureReturnUnknown || childKind == failureReturnNone {
		return failureReturnUnknown
	}
	if contract, ok := reviewedKernelCallFailureEffect(fn, callee, childKind); ok {
		return contract.failureEncoding
	}
	sites := findNamedCallSites(fn.Body, callee)
	if len(sites) == 0 {
		return failureReturnUnknown
	}
	kinds := orderedSet(nil)
	for _, site := range sites {
		if childKind == failureReturnErrno && mapsErrnoCallToFalse(fn.Body, site) {
			kinds.add(failureReturnFalse)
			continue
		}
		if kind := mapsCallFailureToPointerEncoding(fn.Body, site, childKind); kind != failureReturnUnknown {
			kinds.add(kind)
			continue
		}
		if expression, ok := enclosingReturnExpression(fn.Body, site); ok {
			if kind := preservedFailureReturnKind(expression, fn.Body[site.start:site.end], childKind); kind != failureReturnUnknown {
				kinds.add(kind)
				continue
			}
		}
		requirement := ""
		switch childKind {
		case failureReturnFalse:
			requirement = "failure_false"
		case failureReturnNull:
			requirement = "nonnull"
		case failureReturnErrPtr:
			requirement = "failure_err_ptr"
		}
		effect := analyzeNamedCallSite(fn.Body, callee, site, requirement, "")
		if classifySignalAbortEffect(effect) != "guaranteed" {
			kinds.add(failureReturnUnknown)
			continue
		}
		if effect.errnoPropagation == "exact" {
			kinds.add(exactMappedFailureKind(fn, site, childKind))
			continue
		}
		if fn.ReturnType == "pointer" {
			kinds.add(failureReturnUnknown)
			continue
		}
		kinds.add(failureReturnErrno)
	}
	if len(kinds.items) == 1 &&
		kinds.items[0] != failureReturnUnknown {
		return kinds.items[0]
	}
	requirement := failureRequirementForEncoding(childKind)
	if effect := a.analyzeCFGNamedCallFailureEffect(
		fn,
		callee,
		requirement,
	); classifySignalAbortEffect(effect) == "guaranteed" {
		return effect.failureEncoding
	}
	return failureReturnUnknown
}

func reviewedKernelCallFailureEffect(
	fn *FunctionInfo,
	callee, childKind string,
) (localErrorEffect, bool) {
	if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict || len(findNamedCallSites(fn.Body, callee)) != 1 {
		return localErrorEffect{}, false
	}
	file := filepath.ToSlash(fn.File)
	body := strings.Join(strings.Fields(fn.Body), "")
	matches := func(parts ...string) bool {
		for _, part := range parts {
			if !strings.Contains(body, part) {
				return false
			}
		}
		return true
	}
	exact := func(encoding string) (localErrorEffect, bool) {
		return guaranteedEncodedLocalErrorEffect("exact", encoding, nil), true
	}
	normalized := func(encoding string) (localErrorEffect, bool) {
		return guaranteedEncodedLocalErrorEffect("normalized", encoding, nil), true
	}

	if strings.HasSuffix(file, "/kernel/capability.c") {
		switch {
		case fn.Name == "ns_capable_common" &&
			callee == "security_capable" &&
			childKind == failureReturnErrno &&
			matches(
				"capable=security_capable(",
				"if(capable==0){",
				"returntrue;",
				"returnfalse;",
			):
			return normalized(failureReturnFalse)
		case fn.Name == "ns_capable" &&
			callee == "ns_capable_common" &&
			childKind == failureReturnFalse &&
			matches("returnns_capable_common("):
			return exact(failureReturnFalse)
		case fn.Name == "capable" &&
			callee == "ns_capable" &&
			childKind == failureReturnFalse &&
			matches("returnns_capable(&init_user_ns,cap);"):
			return exact(failureReturnFalse)
		}
	}

	if strings.HasSuffix(file, "/fs/namespace.c") &&
		fn.Name == "may_mount" &&
		callee == "ns_capable" &&
		childKind == failureReturnFalse &&
		matches("returnns_capable(", "CAP_SYS_ADMIN);") {
		return exact(failureReturnFalse)
	}

	if strings.HasSuffix(file, "/fs/file_table.c") {
		switch {
		case fn.Name == "__alloc_file" &&
			callee == "security_file_alloc" &&
			childKind == failureReturnErrno &&
			matches(
				"error=security_file_alloc(f);",
				"returnERR_PTR(error);",
				"returnf;",
			):
			return exact(failureReturnErrPtr)
		case fn.Name == "alloc_empty_file" &&
			callee == "__alloc_file" &&
			childKind == failureReturnErrPtr &&
			matches(
				"f=__alloc_file(flags,cred);",
				"if(!IS_ERR(f))",
				"returnf;",
			):
			return exact(failureReturnErrPtr)
		case fn.Name == "alloc_empty_file_noaccount" &&
			callee == "__alloc_file" &&
			childKind == failureReturnErrPtr &&
			matches(
				"f=__alloc_file(flags,cred);",
				"if(!IS_ERR(f))",
				"returnf;",
			):
			return exact(failureReturnErrPtr)
		case fn.Name == "alloc_file" &&
			callee == "alloc_empty_file" &&
			childKind == failureReturnErrPtr &&
			matches(
				"file=alloc_empty_file(flags,current_cred());",
				"if(IS_ERR(file))",
				"returnfile;",
			):
			return exact(failureReturnErrPtr)
		case fn.Name == "alloc_file_pseudo" &&
			callee == "alloc_file" &&
			childKind == failureReturnErrPtr &&
			matches(
				"file=alloc_file(&path,flags,fops);",
				"if(IS_ERR(file))",
				"returnfile;",
			):
			return exact(failureReturnErrPtr)
		}
	}

	if strings.HasSuffix(file, "/fs/open.c") &&
		fn.Name == "dentry_open" &&
		callee == "alloc_empty_file" &&
		childKind == failureReturnErrPtr &&
		matches(
			"f=alloc_empty_file(flags,cred);",
			"if(!IS_ERR(f))",
			"returnf;",
		) {
		return exact(failureReturnErrPtr)
	}

	if strings.HasSuffix(file, "/fs/anon_inodes.c") {
		switch {
		case fn.Name == "__anon_inode_getfile" &&
			callee == "alloc_file_pseudo" &&
			childKind == failureReturnErrPtr &&
			matches(
				"file=alloc_file_pseudo(",
				"if(IS_ERR(file))",
				"returnfile;",
			):
			return exact(failureReturnErrPtr)
		case fn.Name == "anon_inode_getfile" &&
			callee == "__anon_inode_getfile" &&
			childKind == failureReturnErrPtr &&
			matches("return__anon_inode_getfile("):
			return exact(failureReturnErrPtr)
		case fn.Name == "__anon_inode_getfd" &&
			callee == "__anon_inode_getfile" &&
			childKind == failureReturnErrPtr &&
			matches(
				"file=__anon_inode_getfile(",
				"if(IS_ERR(file)){",
				"error=PTR_ERR(file);",
				"returnerror;",
			):
			return exact(failureReturnErrno)
		case (fn.Name == "anon_inode_getfd" ||
			fn.Name == "anon_inode_getfd_secure") &&
			callee == "__anon_inode_getfd" &&
			childKind == failureReturnErrno &&
			matches("return__anon_inode_getfd("):
			return exact(failureReturnErrno)
		}
	}

	if strings.HasSuffix(file, "/mm/shmem.c") {
		switch {
		case fn.Name == "__shmem_file_setup" &&
			callee == "alloc_file_pseudo" &&
			childKind == failureReturnErrPtr &&
			matches(
				"res=alloc_file_pseudo(",
				"if(IS_ERR(res))",
				"returnres;",
			):
			return exact(failureReturnErrPtr)
		case (fn.Name == "shmem_file_setup" ||
			fn.Name == "shmem_file_setup_with_mnt") &&
			callee == "__shmem_file_setup" &&
			childKind == failureReturnErrPtr &&
			matches("return__shmem_file_setup("):
			return exact(failureReturnErrPtr)
		}
	}

	if strings.HasSuffix(file, "/fs/hugetlbfs/inode.c") &&
		fn.Name == "hugetlb_file_setup" &&
		callee == "alloc_file_pseudo" &&
		childKind == failureReturnErrPtr &&
		matches(
			"file=alloc_file_pseudo(",
			"if(!IS_ERR(file))",
			"returnfile;",
		) {
		return exact(failureReturnErrPtr)
	}

	if strings.HasSuffix(file, "/fs/eventpoll.c") &&
		fn.Name == "do_epoll_create" &&
		callee == "anon_inode_getfile" &&
		childKind == failureReturnErrPtr &&
		matches(
			"file=anon_inode_getfile(",
			"if(IS_ERR(file)){",
			"error=PTR_ERR(file);",
			"returnerror;",
		) {
		return exact(failureReturnErrno)
	}

	if strings.HasSuffix(file, "/ipc/mqueue.c") &&
		fn.Name == "do_mq_open" &&
		callee == "dentry_open" &&
		childKind == failureReturnErrPtr &&
		matches(
			"file=dentry_open(&path,oflag,current_cred());",
			"error=PTR_ERR(file);",
			"fd=error;",
			"returnfd;",
		) {
		return exact(failureReturnErrno)
	}

	if strings.HasSuffix(file, "/fs/fhandle.c") &&
		fn.Name == "do_handle_open" &&
		callee == "file_open_root" &&
		childKind == failureReturnErrPtr &&
		matches(
			"file=file_open_root(&path,\"\",open_flag,0);",
			"if(IS_ERR(file)){",
			"retval=PTR_ERR(file);",
			"returnretval;",
		) {
		return exact(failureReturnErrno)
	}

	return localErrorEffect{}, false
}

func failureRequirementForEncoding(encoding string) string {
	switch encoding {
	case failureReturnErrno:
		return ""
	case failureReturnFalse:
		return "failure_false"
	case failureReturnNull:
		return "nonnull"
	case failureReturnErrPtr:
		return "failure_err_ptr"
	default:
		return "unsupported"
	}
}

func propagatedFailureRequirement(
	effect localErrorEffect,
	fallback string,
) string {
	requirement := failureRequirementForEncoding(effect.failureEncoding)
	if requirement == "unsupported" {
		return fallback
	}
	return requirement
}

func mapsCallFailureToPointerEncoding(
	body string,
	site namedCallSite,
	childKind string,
) string {
	target := assignedCallTarget(body, site.start)
	if target == "" {
		return failureReturnUnknown
	}
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return failureReturnUnknown
	}
	continuation := body[statementEnd+1:]
	position := skipSpace(continuation, 0)
	if position >= len(continuation) || !hasKeywordPrefix(continuation[position:], "if") {
		return failureReturnUnknown
	}
	detail, ok := parseIfDetail(continuation, position)
	if !ok {
		return failureReturnUnknown
	}
	condition := normalizeCondition(detail.condText)
	failureBranch := false
	switch childKind {
	case failureReturnErrno, failureReturnErrPtr:
		failureBranch = conditionTrueForError(condition, target)
	case failureReturnFalse, failureReturnNull:
		failureBranch = conditionIndicatesFalsyExpression(condition, target)
	}
	if !failureBranch {
		return failureReturnUnknown
	}
	return terminalPointerFailureEncoding(detail.bodyText)
}

func terminalPointerFailureEncoding(body string) string {
	returns := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
	if len(returns) == 0 {
		return failureReturnUnknown
	}
	kind := ""
	for _, match := range returns {
		expression := normalizeCondition(strings.TrimSpace(match[1]))
		candidate := failureReturnUnknown
		switch {
		case expression == "NULL" || expression == "0":
			candidate = failureReturnNull
		case strings.HasPrefix(compactExpression(expression), "ERR_PTR("):
			candidate = failureReturnErrPtr
		}
		if candidate == failureReturnUnknown {
			return failureReturnUnknown
		}
		if kind != "" && kind != candidate {
			return failureReturnUnknown
		}
		kind = candidate
	}
	if kind == "" {
		return failureReturnUnknown
	}
	return kind
}

func exactMappedFailureKind(
	fn *FunctionInfo,
	site namedCallSite,
	childKind string,
) string {
	target := assignedCallTarget(fn.Body, site.start)
	if target == "" {
		return childKind
	}
	quoted := regexp.QuoteMeta(target)
	for _, match := range regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(fn.Body, -1) {
		expression := compactExpression(match[1])
		switch {
		case expression == compactExpression(target):
			return childKind
		case childKind == failureReturnErrno &&
			regexp.MustCompile(`^ERR_PTR\(`+quoted+`\)$`).MatchString(expression):
			return failureReturnErrPtr
		case childKind == failureReturnErrPtr &&
			regexp.MustCompile(`^PTR_ERR\(`+quoted+`\)$`).MatchString(expression):
			return failureReturnErrno
		}
	}
	return childKind
}

func mapsErrnoCallToFalse(body string, site namedCallSite) bool {
	target := assignedCallTarget(body, site.start)
	if target == "" {
		if expression, ok := enclosingReturnExpression(body, site); ok {
			call := compactExpression(body[site.start:site.end])
			expression = compactExpression(expression)
			return expression == "!"+call || expression == call+"==0" ||
				expression == "0=="+call
		}
		return false
	}
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return false
	}
	continuation := body[statementEnd+1:]
	position := skipSpace(continuation, 0)
	if position >= len(continuation) || !hasKeywordPrefix(continuation[position:], "if") {
		return false
	}
	detail, ok := parseIfDetail(continuation, position)
	if !ok || detail.hasElse || !conditionFalseForError(normalizeCondition(detail.condText), target) {
		return false
	}
	if !branchReturnsOnlyBoolean(detail.bodyText, true) {
		return false
	}
	return branchReturnsOnlyBoolean(continuation[detail.nextPos:], false)
}

func branchReturnsOnlyBoolean(body string, value bool) bool {
	returns := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
	if len(returns) == 0 {
		return false
	}
	expected := "false"
	if value {
		expected = "true"
	}
	for _, match := range returns {
		expression := normalizeCondition(strings.TrimSpace(match[1]))
		if expression == expected {
			continue
		}
		if value && expression == "1" || !value && expression == "0" {
			continue
		}
		return false
	}
	return true
}

func enclosingReturnExpression(body string, site namedCallSite) (string, bool) {
	statementStart := site.start
	for statementStart > 0 {
		previous := body[statementStart-1]
		if previous == ';' || previous == '{' || previous == '}' {
			break
		}
		statementStart--
	}
	prefix := strings.TrimSpace(body[statementStart:site.start])
	if !regexp.MustCompile(`^return\b`).MatchString(prefix) {
		return "", false
	}
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return "", false
	}
	statement := strings.TrimSpace(body[statementStart:statementEnd])
	return strings.TrimSpace(strings.TrimPrefix(statement, "return")), true
}

func preservedFailureReturnKind(expression, call string, childKind string) string {
	expression = compactExpression(expression)
	call = compactExpression(call)
	if expression == call {
		return childKind
	}
	switch childKind {
	case failureReturnFalse:
		if expression == "!!"+call {
			return failureReturnFalse
		}
		for _, term := range splitTopLevelBooleanTerms(expression, "&&") {
			term = compactExpression(term)
			if term == call || term == "!!"+call {
				return failureReturnFalse
			}
		}
	case failureReturnErrno:
		if expression == "ERR_PTR("+call+")" {
			return failureReturnErrPtr
		}
	case failureReturnErrPtr:
		if expression == "PTR_ERR("+call+")" {
			return failureReturnErrno
		}
	}
	return failureReturnUnknown
}

func (a *Analyzer) analyzeIndirectCallErrorEffect(
	fn *FunctionInfo,
	body, expression string,
) localErrorEffect {
	effect := analyzeCallExpressionErrorEffect(body, expression)
	if classifySignalAbortEffect(effect) != "unknown" || fn == nil || fn.FrontendVariantConflict {
		return effect
	}
	if fn.callResultDefinitelyDiscarded("", expression, false) {
		return ignoredLocalErrorEffect()
	}
	return effect
}

func (fn *FunctionInfo) callResultDefinitelyDiscarded(
	callee, expression string,
	direct bool,
) bool {
	if fn == nil || fn.Frontend != "clang-ast-cfg" || fn.FrontendVariantConflict {
		return false
	}
	normalizedExpression := normalizeIndirectExpression(expression)
	found := false
	foundReachable := false
	for _, site := range fn.CallSites {
		if site.Direct != direct {
			continue
		}
		if direct {
			if site.Name != callee {
				continue
			}
		} else if normalizeIndirectExpression(site.Expression) != normalizedExpression {
			continue
		}
		found = true
		foundReachable = foundReachable || site.Reachable
		if site.ReturnType != "void" && site.ResultUse != "discarded" {
			return false
		}
	}
	return found && foundReachable
}

func (a *Analyzer) llvmCallResultDefinitelyIgnored(fn *FunctionInfo, callee string) bool {
	groups, ok := a.llvmFactsByReachableCallSite(fn, callee)
	if !ok {
		return false
	}
	for _, facts := range groups {
		for _, fact := range facts {
			if fact.Verification != "ignored" || fact.ResultUsed {
				return false
			}
		}
	}
	return true
}

func (a *Analyzer) llvmCallMustReturnExact(fn *FunctionInfo, callee string) bool {
	groups, ok := a.llvmFactsByReachableCallSite(fn, callee)
	if !ok {
		return false
	}
	for _, facts := range groups {
		for _, fact := range facts {
			if !fact.MustReturnExact {
				return false
			}
		}
	}
	return true
}

func (a *Analyzer) llvmCallMustReturnNegative(
	fn *FunctionInfo,
	callee, requirement string,
) bool {
	groups, ok := a.llvmFactsByReachableCallSite(fn, callee)
	if !ok {
		return false
	}
	for _, facts := range groups {
		for _, fact := range facts {
			proven := fact.MustReturnNegativeOnError
			if requirement == "failure_false" {
				proven = fact.MustReturnNegativeOnFalse
			}
			if !proven {
				return false
			}
		}
	}
	return true
}

func (a *Analyzer) llvmCallMustReturnNegativeOnTrue(fn *FunctionInfo, callee string) bool {
	groups, ok := a.llvmFactsByReachableCallSite(fn, callee)
	if !ok {
		return false
	}
	for _, facts := range groups {
		for _, fact := range facts {
			if !fact.MustReturnNegativeOnTrue {
				return false
			}
		}
	}
	return true
}

func llvmFunctionSuccessProof(
	fn *FunctionInfo,
	requirement string,
) (string, bool) {
	if fn == nil || fn.FrontendVariantConflict ||
		len(fn.LLVMFunctionFacts) == 0 {
		return "", false
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	method := ""
	for _, fact := range fn.LLVMFunctionFacts {
		if fact.Kind != "function_summary" ||
			fact.SourceFunction != "" &&
				fact.SourceFunction != fn.Name {
			continue
		}
		proven := false
		candidateMethod := ""
		switch requirement {
		case "any", "returned":
			proven = fact.FunctionHasReturn
			candidateMethod = "llvm_all_returns_exist"
		case "nonnegative":
			proven = fact.FunctionMustReturnNonnegative
			candidateMethod = "llvm_all_returns_nonnegative"
		case "nonnull":
			proven = fact.FunctionMustReturnNonNull
			candidateMethod = "llvm_all_returns_nonnull"
		case "nonnull_valid_pointer":
			proven = fact.FunctionMustReturnValidPointer
			candidateMethod = "llvm_all_returns_valid_pointer"
		case "true":
			proven = fact.FunctionMustReturnTrue
			candidateMethod = "llvm_all_returns_true"
		}
		if !proven {
			return "", false
		}
		if method == "" {
			method = candidateMethod
		} else if method != candidateMethod {
			return "", false
		}
	}
	return method, method != ""
}

func constrainReturnOutcomeByLLVMFunctionFacts(
	fn *FunctionInfo,
	outcome returnOutcome,
) returnOutcome {
	if fn == nil || fn.FrontendVariantConflict ||
		outcome.domain != returnDomainSigned ||
		len(fn.LLVMFunctionFacts) == 0 {
		return outcome
	}
	seen := false
	allNonnegative := true
	allNonpositive := true
	for _, fact := range fn.LLVMFunctionFacts {
		if fact.Kind != "function_summary" ||
			fact.SourceFunction != "" &&
				fact.SourceFunction != fn.Name {
			continue
		}
		seen = true
		allNonnegative =
			allNonnegative && fact.FunctionHasReturn &&
				fact.FunctionMustReturnNonnegative
		allNonpositive =
			allNonpositive && fact.FunctionHasReturn &&
				fact.FunctionMustReturnNonpositive
	}
	if !seen {
		return outcome
	}
	if allNonnegative {
		outcome.mask &= outcomeZero | outcomePositive
	}
	if allNonpositive {
		outcome.mask &= outcomeNegative | outcomeZero
	}
	return outcome
}

func llvmFunctionRequirementImpossible(
	fn *FunctionInfo,
	requirement string,
) bool {
	if fn == nil {
		return false
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	outcome := constrainReturnOutcomeByLLVMFunctionFacts(
		fn,
		fullReturnOutcome(fn.ReturnType),
	)
	return returnOutcomeCompatibility(outcome, requirement) ==
		"impossible"
}

func llvmFunctionPreservesPointeeArgument(
	fn *FunctionInfo,
	argumentIndex int,
) bool {
	if fn == nil || argumentIndex < 0 ||
		fn.FrontendVariantConflict ||
		len(fn.LLVMFunctionFacts) == 0 {
		return false
	}
	seen := false
	for _, fact := range fn.LLVMFunctionFacts {
		if fact.Kind != "function_summary" ||
			fact.SourceFunction != "" &&
				fact.SourceFunction != fn.Name {
			continue
		}
		seen = true
		if !containsInt(
			fact.FunctionPreservedPointeeArguments,
			argumentIndex,
		) {
			return false
		}
	}
	return seen
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (a *Analyzer) llvmCallCannotContainEffectSource(fn *FunctionInfo, callee string) bool {
	groups, ok := a.llvmFactsByReachableCallSite(fn, callee)
	if !ok {
		return false
	}
	for _, facts := range groups {
		for _, fact := range facts {
			if !fact.DoesNotAccessMemory {
				return false
			}
		}
	}
	return true
}

func (a *Analyzer) llvmFactsByReachableCallSite(
	fn *FunctionInfo,
	callee string,
) ([][]LLVMCallFact, bool) {
	if fn == nil || fn.FrontendVariantConflict || callee == "" {
		return nil, false
	}
	sites := make([]ClangCallSite, 0)
	for _, site := range fn.CallSites {
		if site.Direct && site.Reachable && site.Name == callee {
			sites = append(sites, site)
		}
	}
	facts := make([]LLVMCallFact, 0)
	standaloneFacts := make([]LLVMCallFact, 0)
	for _, fact := range fn.LLVMCallFacts {
		if fact.Callee != callee {
			continue
		}
		if fact.SourceFunction != "" && fact.SourceFunction != fn.Name {
			continue
		}
		if fact.SourceFile != "" && filepath.Clean(fact.SourceFile) != filepath.Clean(fn.File) {
			continue
		}
		facts = append(facts, fact)
		if fact.Function == fn.Name && len(fact.InlinedAtFunctions) == 0 {
			standaloneFacts = append(standaloneFacts, fact)
		}
	}
	if len(standaloneFacts) > 0 {
		facts = standaloneFacts
	}
	if len(sites) == 0 || len(facts) == 0 {
		return nil, false
	}
	if len(sites) == 1 && len(facts) == 1 {
		return [][]LLVMCallFact{{facts[0]}}, true
	}
	result := make([][]LLVMCallFact, 0, len(sites))
	usedFacts := make(map[int]struct{})
	for _, site := range sites {
		matched := make([]LLVMCallFact, 0)
		matchedIndexes := make([]int, 0)
		for factIndex, fact := range facts {
			if fact.SourceLine == 0 || site.Line == 0 || fact.SourceLine != site.Line {
				continue
			}
			if fact.SourceColumn != 0 && site.Column != 0 &&
				fact.SourceColumn != site.Column {
				continue
			}
			matched = append(matched, fact)
			matchedIndexes = append(matchedIndexes, factIndex)
		}
		if len(matched) == 0 {
			return nil, false
		}
		for _, factIndex := range matchedIndexes {
			if _, reused := usedFacts[factIndex]; reused {
				return nil, false
			}
			usedFacts[factIndex] = struct{}{}
		}
		result = append(result, matched)
	}
	return result, true
}

func (a *Analyzer) llvmFactsForReachableCallSite(
	fn *FunctionInfo,
	callee string,
	site *ClangCallSite,
) ([]LLVMCallFact, bool) {
	if fn == nil || site == nil || site.ID == "" || !site.Direct ||
		!site.Reachable || site.Name != callee {
		return nil, false
	}
	sites := make([]ClangCallSite, 0)
	targetIndex := -1
	for _, candidate := range fn.CallSites {
		if !candidate.Direct || !candidate.Reachable ||
			candidate.Name != callee {
			continue
		}
		if candidate.ID == site.ID {
			if targetIndex >= 0 {
				return nil, false
			}
			targetIndex = len(sites)
		}
		sites = append(sites, candidate)
	}
	if targetIndex < 0 {
		return nil, false
	}

	facts := make([]LLVMCallFact, 0)
	standaloneFacts := make([]LLVMCallFact, 0)
	for _, fact := range fn.LLVMCallFacts {
		if fact.Callee != callee {
			continue
		}
		if fact.SourceFunction != "" && fact.SourceFunction != fn.Name {
			continue
		}
		if fact.SourceFile != "" &&
			filepath.Clean(fact.SourceFile) != filepath.Clean(fn.File) {
			continue
		}
		facts = append(facts, fact)
		if fact.Function == fn.Name && len(fact.InlinedAtFunctions) == 0 {
			standaloneFacts = append(standaloneFacts, fact)
		}
	}
	if len(standaloneFacts) > 0 {
		facts = standaloneFacts
	}
	if len(facts) == 0 {
		return nil, false
	}
	if len(sites) == 1 && len(facts) == 1 {
		return []LLVMCallFact{facts[0]}, true
	}

	target := sites[targetIndex]
	if target.Line == 0 {
		return nil, false
	}
	for index, candidate := range sites {
		if index == targetIndex || candidate.Line != target.Line {
			continue
		}
		if target.Column == 0 || candidate.Column == 0 ||
			candidate.Column == target.Column {
			return nil, false
		}
	}
	matched := make([]LLVMCallFact, 0)
	for _, fact := range facts {
		if fact.SourceLine == 0 || fact.SourceLine != target.Line {
			continue
		}
		if target.Column != 0 && fact.SourceColumn != 0 &&
			fact.SourceColumn != target.Column {
			continue
		}
		matched = append(matched, fact)
	}
	if len(matched) == 0 {
		return nil, false
	}
	return matched, true
}

func (a *Analyzer) llvmIntegerSuccessRequirementAtSite(
	fn, callee *FunctionInfo,
	calleeName string,
	site *ClangCallSite,
	callerRequirement string,
) (string, string, bool) {
	if fn == nil || callee == nil ||
		returnDomainForType(fn.ReturnType) != returnDomainSigned ||
		returnDomainForType(callee.ReturnType) != returnDomainSigned {
		return "", "", false
	}
	if callerRequirement == "" {
		callerRequirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if callerRequirement != "nonnegative" {
		return "", "", false
	}
	facts, ok := a.llvmFactsForReachableCallSite(fn, calleeName, site)
	if !ok {
		return "", "", false
	}
	allZero := true
	allPositive := true
	for _, fact := range facts {
		allZero = allZero && fact.MustReturnNonnegativeOnZero
		allPositive = allPositive &&
			fact.MustReturnNonnegativeOnPositive
	}
	switch {
	case allZero && allPositive:
		return "nonnegative",
			"llvm_ssa_nonnegative_success_preservation",
			true
	case allZero:
		return "zero",
			"llvm_ssa_zero_success_preservation",
			true
	case allPositive:
		return "positive",
			"llvm_ssa_positive_success_preservation",
			true
	default:
		return "", "", false
	}
}

func (a *Analyzer) llvmCallPreservesValidPointerSuccessAtSite(
	fn, callee *FunctionInfo,
	calleeName string,
	site *ClangCallSite,
	callerRequirement string,
) bool {
	if fn == nil || callee == nil ||
		returnDomainForType(fn.ReturnType) != returnDomainPointer ||
		returnDomainForType(callee.ReturnType) != returnDomainPointer ||
		callerRequirement != "nonnull_valid_pointer" {
		return false
	}
	facts, ok := a.llvmFactsForReachableCallSite(fn, calleeName, site)
	if !ok {
		return false
	}
	for _, fact := range facts {
		if !fact.MustReturnValidPointerOnValidPointer ||
			!fact.MustPreserveValidPointerSuccess {
			return false
		}
	}
	return true
}

func analyzeErrorParameterPropagation(body, parameter string) localErrorEffect {
	if parameter == "" || addressEscapesVariable(body, parameter) ||
		hasUnsupportedScalarMutation(body, parameter) ||
		regexp.MustCompile(`\b(?:__asm__|asm)\b`).MatchString(body) {
		return unknownLocalErrorEffect()
	}
	errno := "exact"
	assignmentPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(parameter) + `\s*=\s*([^;]+);`)
	for _, match := range assignmentPattern.FindAllStringSubmatch(body, -1) {
		expression := strings.TrimSpace(match[1])
		if strings.HasPrefix(expression, "=") {
			continue
		}
		assignmentEffect := returnTaintedErrorEffect(expression, parameter)
		if classifySignalAbortEffect(assignmentEffect) != "guaranteed" {
			return unknownLocalErrorEffect()
		}
		errno = mergeAlternativeErrno(errno, assignmentEffect.errnoPropagation)
		if errno == "unknown" || errno == "ignored" {
			return unknownLocalErrorEffect()
		}
	}
	returns := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
	if len(returns) == 0 {
		return unknownLocalErrorEffect()
	}
	for _, match := range returns {
		returnEffect := returnTaintedErrorEffect(strings.TrimSpace(match[1]), parameter)
		if classifySignalAbortEffect(returnEffect) != "guaranteed" {
			return unknownLocalErrorEffect()
		}
		errno = mergeAlternativeErrno(errno, returnEffect.errnoPropagation)
		if errno == "unknown" || errno == "ignored" {
			return unknownLocalErrorEffect()
		}
	}
	return guaranteedLocalErrorEffect(errno, nil)
}

func effectRelevantDirectCalls(fn *FunctionInfo) []string {
	if fn == nil {
		return nil
	}
	return filterInternalCallees(uniqueStrings(append(
		append([]string(nil), fn.CFGReachableCalls...),
		fn.RawCallees...,
	)))
}

func effectRelevantIndirectCalls(fn *FunctionInfo) []string {
	if fn == nil {
		return nil
	}
	return uniqueStrings(append(
		append([]string(nil), fn.CFGReachableIndirect...),
		fn.IndirectCalls...,
	))
}

func (a *Analyzer) lsmEffectSourceState(functionID string) effectSourceState {
	if !a.lsmEffectSourcesBuilt {
		a.buildEffectSourceStates("lsm")
	}
	if state, ok := a.lsmEffectSourceCache[functionID]; ok {
		return state
	}
	return effectSourceUnknown
}

func (a *Analyzer) signalEffectSourceState(functionID string) effectSourceState {
	if !a.sigEffectSourcesBuilt {
		a.buildEffectSourceStates("sigkill")
	}
	if state, ok := a.sigEffectSourceCache[functionID]; ok {
		return state
	}
	return effectSourceUnknown
}

type effectSourceGraphNode struct {
	dependencies []string
	possible     bool
	unknown      bool
	witness      string
}

func (a *Analyzer) buildEffectSourceStates(domain string) {
	previousBuildingState := a.buildingEffectSources
	a.buildingEffectSources = true
	defer func() {
		a.buildingEffectSources = previousBuildingState
	}()

	nodes := make(map[string]*effectSourceGraphNode)
	analysisSyscalls := a.effectAnalysisSyscalls()
	pending := make([]string, 0, len(analysisSyscalls))
	scheduled := make(map[string]bool)
	schedule := func(functionID string) {
		if functionID == "" || scheduled[functionID] {
			return
		}
		scheduled[functionID] = true
		pending = append(pending, functionID)
	}
	for _, entry := range analysisSyscalls {
		if functionID, ok := a.resolveStartFunction(entry); ok {
			schedule(functionID)
		}
	}
	if len(pending) == 0 {
		for functionID := range a.functions {
			schedule(functionID)
		}
	}

	for cursor := 0; cursor < len(pending); cursor++ {
		functionID := pending[cursor]
		fn := a.functions[functionID]
		node := &effectSourceGraphNode{}
		nodes[functionID] = node
		if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete {
			node.unknown = true
			node.witness = "frontend-or-cfg-incomplete:" + functionID
			continue
		}

		body := fn.Body
		if domain == "lsm" {
			for _, hook := range fn.DirectLSMHooks {
				effect := analyzeNamedCallErrorEffect(body, hook)
				kind := a.classifyLSMHookKind(hook, effect)
				if !fn.FrontendVariantConflict &&
					(kind == "notification" || classifySignalAbortEffect(effect) == "not_effective") {
					continue
				}
				node.possible = true
				break
			}
		} else {
			for _, check := range fn.DirectSigChecks {
				relevance := a.signalCheckSIGKILLRelevance(fn, body, check, false)
				if relevance == signalSIGKILLIrrelevant {
					continue
				}
				if relevance == signalSIGKILLUnknown {
					node.unknown = true
					if node.witness == "" {
						node.witness = "signal-state-unresolved:" + fn.DisplayName + "->" + check
					}
					continue
				}
				if !fn.FrontendVariantConflict &&
					classifySignalAbortEffect(analyzeSignalCheckLocalEffect(body, check)) == "not_effective" {
					continue
				}
				node.possible = true
				break
			}
		}
		for _, callee := range effectRelevantDirectCalls(fn) {
			if domain == "lsm" && strings.HasPrefix(callee, "security_") {
				continue
			}
			if domain == "sigkill" && isSignalCheckName(callee) {
				continue
			}
			if !fn.FrontendVariantConflict &&
				classifySignalAbortEffect(a.analyzeNamedCallErrorEffect(fn, body, callee)) == "not_effective" {
				continue
			}
			ids, status := a.resolveCallee(fn, callee)
			if (status == "resolved" || status == "ambiguous") && len(ids) > 0 {
				node.dependencies = append(node.dependencies, ids...)
				for _, id := range ids {
					schedule(id)
				}
				continue
			}
			if a.llvmCallCannotContainEffectSource(fn, callee) {
				continue
			}
			node.unknown = true
			if node.witness == "" {
				node.witness = "unresolved-direct:" + fn.DisplayName + "->" + callee
			}
		}
		for _, expression := range effectRelevantIndirectCalls(fn) {
			if !fn.FrontendVariantConflict &&
				classifySignalAbortEffect(a.analyzeIndirectCallErrorEffect(fn, body, expression)) == "not_effective" {
				continue
			}
			if invocation, ok := findIndirectInvocation(body, expression); ok &&
				a.indirectTargetSetClosed(fn, invocation, nil) {
				for _, target := range a.resolveIndirectInvocation(fn, invocation, nil) {
					node.dependencies = append(node.dependencies, target.functionID)
					schedule(target.functionID)
				}
				continue
			}
			node.unknown = true
			if node.witness == "" {
				node.witness = "unresolved-indirect:" + fn.DisplayName + "->" + expression
			}
		}
		node.dependencies = uniqueStrings(node.dependencies)
	}

	reverse := make(map[string][]string, len(nodes))
	for functionID, node := range nodes {
		for _, dependency := range node.dependencies {
			if _, ok := nodes[dependency]; !ok {
				node.unknown = true
				if node.witness == "" {
					node.witness = "missing-dependency:" + functionID + "->" + dependency
				}
				continue
			}
			reverse[dependency] = appendUnique(reverse[dependency], functionID)
		}
	}

	possible := make(map[string]bool, len(nodes))
	queue := make([]string, 0)
	for functionID, node := range nodes {
		if node.possible {
			possible[functionID] = true
			queue = append(queue, functionID)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, caller := range reverse[current] {
			if possible[caller] {
				continue
			}
			possible[caller] = true
			queue = append(queue, caller)
		}
	}

	unknown := make(map[string]bool, len(nodes))
	witnesses := make(map[string]string, len(nodes))
	queue = queue[:0]
	for functionID, node := range nodes {
		if !possible[functionID] && node.unknown {
			unknown[functionID] = true
			witnesses[functionID] = node.witness
			queue = append(queue, functionID)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, caller := range reverse[current] {
			if possible[caller] || unknown[caller] {
				continue
			}
			unknown[caller] = true
			witnesses[caller] = witnesses[current]
			queue = append(queue, caller)
		}
	}

	cache := a.lsmEffectSourceCache
	witnessCache := a.lsmEffectWitnessCache
	if domain == "sigkill" {
		cache = a.sigEffectSourceCache
		witnessCache = a.sigEffectWitnessCache
	}
	clear(cache)
	clear(witnessCache)
	for functionID := range nodes {
		fn := a.functions[functionID]
		switch {
		case possible[functionID]:
			cache[functionID] = effectSourcePossible
			if fn != nil {
				if domain == "lsm" {
					fn.LSMEffectSourceState = "possible"
					fn.LSMEffectUnknownWitness = ""
				} else {
					fn.SIGEffectSourceState = "possible"
					fn.SIGEffectUnknownWitness = ""
				}
			}
		case unknown[functionID]:
			cache[functionID] = effectSourceUnknown
			witnessCache[functionID] = witnesses[functionID]
			if fn != nil {
				if domain == "lsm" {
					fn.LSMEffectSourceState = "unknown"
					fn.LSMEffectUnknownWitness = witnesses[functionID]
				} else {
					fn.SIGEffectSourceState = "unknown"
					fn.SIGEffectUnknownWitness = witnesses[functionID]
				}
			}
		default:
			cache[functionID] = effectSourceNone
			if fn != nil {
				if domain == "lsm" {
					fn.LSMEffectSourceState = "none"
					fn.LSMEffectUnknownWitness = ""
				} else {
					fn.SIGEffectSourceState = "none"
					fn.SIGEffectUnknownWitness = ""
				}
			}
		}
	}
	if domain == "lsm" {
		a.lsmEffectSourcesBuilt = true
	} else {
		a.sigEffectSourcesBuilt = true
	}
}

func isSignalCheckName(name string) bool {
	switch name {
	case "fatal_signal_pending", "signal_pending", "__fatal_signal_pending",
		"task_sigpending", "signal_group_exit", "signal_pending_state",
		"SIGNAL_GROUP_EXIT":
		return true
	default:
		return false
	}
}

func (a *Analyzer) resolvedTargetsHaveNoLSMEffect(fn *FunctionInfo, callee string) bool {
	ids, status := a.resolveCallee(fn, callee)
	if status != "resolved" && status != "ambiguous" || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if a.lsmEffectSourceState(id) != effectSourceNone {
			return false
		}
	}
	return true
}

func (a *Analyzer) resolvedTargetsHaveNoSignalEffect(fn *FunctionInfo, callee string) bool {
	ids, status := a.resolveCallee(fn, callee)
	if status != "resolved" && status != "ambiguous" || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if a.signalEffectSourceState(id) != effectSourceNone {
			return false
		}
	}
	return true
}

func (a *Analyzer) signalRelevantProofGaps(
	fn *FunctionInfo,
	scan prefixScanResult,
	constants map[string]string,
	operationContext map[string][]string,
) []UnresolvedProofEdge {
	if a.signalEffectSourceState(fn.ID) == effectSourceNone {
		return nil
	}
	result := make([]UnresolvedProofEdge, 0)
	add := func(kind, symbol, expression, detail string) {
		result = append(result, UnresolvedProofEdge{
			Domain:     "sigkill",
			Caller:     fn.DisplayName,
			Kind:       kind,
			Symbol:     symbol,
			Expression: expression,
			Detail:     detail,
		})
	}
	if fn.Frontend != "clang-ast-cfg" {
		add("legacy_frontend", "", "", "the signal-effect proof requires Clang AST/CFG facts")
	} else if !fn.CFGComplete {
		add("cfg_incomplete", "", "", "Clang CFG construction was incomplete")
	}
	if fn.FrontendVariantConflict {
		add("translation_unit_variant_conflict", "", "", "the signal-relevant function differs across translation units")
	}
	body := substituteIdentifierConstants(fn.Body, constants)
	for _, check := range scan.sigChecks {
		for _, evidence := range a.signalCheckEvidences(
			fn,
			body,
			check,
			false,
			invocationCallSiteIDs(scan.calls, check),
		) {
			if evidence.relevance != signalSIGKILLUnknown {
				continue
			}
			add(
				"signal_state_unresolved",
				check,
				evidence.callSiteID,
				"the signal_pending_state callsite mask is not proven to include TASK_INTERRUPTIBLE or TASK_WAKEKILL",
			)
		}
	}
	for _, call := range scan.unmatchedCalls {
		if fn.Frontend == "clang-ast-cfg" &&
			!clangHasDirectCallSite(fn, call.name) {
			continue
		}
		if isSignalCheckName(call.name) {
			add(
				"cfg_callsite_match_unresolved",
				call.name,
				"",
				"a context-feasible signal call could not be matched to one Clang callsite",
			)
			continue
		}
		if a.llvmCallCannotContainEffectSource(fn, call.name) ||
			a.resolvedTargetsHaveNoSignalEffect(fn, call.name) ||
			classifySignalAbortEffect(
				a.analyzeNamedCallErrorEffect(fn, fn.Body, call.name),
			) == "not_effective" {
			continue
		}
		add(
			"cfg_callsite_match_unresolved",
			call.name,
			"",
			"a context-feasible call could not be matched to one Clang callsite and may contain a signal checkpoint",
		)
	}
	if len(fn.CFGUnplacedCallSites) > 0 {
		byID := make(map[string]ClangCallSite, len(fn.CallSites))
		for _, site := range fn.CallSites {
			byID[site.ID] = site
		}
		for _, callSiteID := range fn.CFGUnplacedCallSites {
			site, ok := byID[callSiteID]
			if !ok || !site.Direct || !isSignalCheckName(site.Name) {
				continue
			}
			if signalCallSiteSIGKILLRelevance(site, site.Name, site.Arguments) ==
				signalSIGKILLIrrelevant {
				continue
			}
			add(
				"cfg_event_unplaced",
				site.Name,
				"",
				"the signal check callsite cannot be assigned to one CFG block",
			)
		}
	}
	for _, event := range fn.CFGUnplacedEvents {
		if strings.HasPrefix(event, "call:security_") {
			continue
		}
		if strings.HasPrefix(event, "call:") {
			callee := strings.TrimPrefix(event, "call:")
			if isSignalCheckName(callee) {
				continue
			}
			if a.llvmCallCannotContainEffectSource(fn, callee) {
				continue
			}
			if a.resolvedTargetsHaveNoSignalEffect(fn, callee) {
				continue
			}
			if classifySignalAbortEffect(a.analyzeNamedCallErrorEffect(fn, fn.Body, callee)) == "not_effective" {
				continue
			}
		}
		if strings.HasPrefix(event, "indirect:") {
			expression := strings.TrimPrefix(event, "indirect:")
			if classifySignalAbortEffect(a.analyzeIndirectCallErrorEffect(fn, fn.Body, expression)) == "not_effective" {
				continue
			}
		}
		add(
			"cfg_event_unplaced",
			strings.TrimPrefix(strings.TrimPrefix(event, "call:"), "signal:"),
			"",
			"the signal-relevant AST event cannot be assigned to one CFG block",
		)
	}

	body = substituteIdentifierConstants(fn.Body, constants)
	for _, callee := range scan.callees {
		if isSignalCheckName(callee) {
			continue
		}
		if a.llvmCallCannotContainEffectSource(fn, callee) {
			continue
		}
		if a.resolvedTargetsHaveNoSignalEffect(fn, callee) {
			continue
		}
		effect := a.analyzeNamedCallErrorEffect(fn, body, callee)
		if classifySignalAbortEffect(effect) == "not_effective" {
			continue
		}
		ids, status := a.resolveCallee(fn, callee)
		switch status {
		case "ambiguous":
			targets := make([]string, 0, len(ids))
			for _, id := range ids {
				if target := a.functions[id]; target != nil {
					targets = append(targets, target.DisplayName)
				}
			}
			add("direct_call_ambiguous", callee, "", "multiple signal-relevant definitions remain possible: "+strings.Join(targets, ","))
		case "unresolved":
			add(
				"direct_call_unresolved",
				callee,
				"",
				"the unresolved callee may contain an effective current-task signal checkpoint",
			)
		}
	}
	for _, invocation := range scan.indirectCalls {
		expression := invocation.expression
		if expression == "" {
			expression = invocation.fallback
		}
		effect := a.analyzeIndirectCallErrorEffect(fn, body, expression)
		if classifySignalAbortEffect(effect) == "not_effective" {
			continue
		}
		if a.indirectTargetSetClosedWithContext(
			fn,
			invocation,
			operationContext,
			constants,
		) {
			continue
		}
		targets := a.resolveIndirectInvocationWithContext(
			fn,
			invocation,
			operationContext,
			constants,
		)
		detail := "a complete runtime function-pointer target set is not proven"
		if len(targets) == 0 {
			detail += " and no configured target was resolved"
		}
		add("indirect_signal_target_set_unproven", "", expression, detail)
	}
	return uniqueProofEdges(result)
}

func (a *Analyzer) proofGapsForScan(
	domain string,
	fn *FunctionInfo,
	scan prefixScanResult,
	operationContext map[string][]string,
	resolveIndirect bool,
) []UnresolvedProofEdge {
	if domain == "lsm" && a.lsmEffectSourceState(fn.ID) == effectSourceNone {
		return nil
	}
	result := make([]UnresolvedProofEdge, 0)
	add := func(kind, symbol, expression, detail string) {
		result = append(result, UnresolvedProofEdge{
			Domain:     domain,
			Caller:     fn.DisplayName,
			Kind:       kind,
			Symbol:     symbol,
			Expression: expression,
			Detail:     detail,
		})
	}

	if fn.Frontend != "clang-ast-cfg" {
		add("legacy_frontend", "", "", "the function was indexed by the legacy text frontend")
	} else if !fn.CFGComplete {
		detail := "Clang CFG construction was incomplete"
		if fn.CFGFailure != "" {
			detail += ": " + fn.CFGFailure
		}
		add("cfg_incomplete", "", "", detail)
	}
	if fn.FrontendVariantConflict {
		add("translation_unit_variant_conflict", "", "", "the inline/function body differs across translation units")
	}
	for _, event := range fn.CFGUnplacedEvents {
		switch {
		case strings.HasPrefix(event, "signal:") && domain != "sigkill":
			continue
		case strings.HasPrefix(event, "call:security_") && domain != "lsm":
			continue
		}
		if domain == "lsm" && strings.HasPrefix(event, "call:") {
			callee := strings.TrimPrefix(event, "call:")
			if strings.HasPrefix(callee, "security_") {
				if classifySignalAbortEffect(analyzeNamedCallErrorEffect(fn.Body, callee)) == "not_effective" {
					continue
				}
			} else {
				if a.llvmCallCannotContainEffectSource(fn, callee) {
					continue
				}
				if a.resolvedTargetsHaveNoLSMEffect(fn, callee) {
					continue
				}
				if classifySignalAbortEffect(a.analyzeNamedCallErrorEffect(fn, fn.Body, callee)) == "not_effective" {
					continue
				}
			}
		}
		if domain == "lsm" && strings.HasPrefix(event, "indirect:") {
			expression := strings.TrimPrefix(event, "indirect:")
			if classifySignalAbortEffect(a.analyzeIndirectCallErrorEffect(fn, fn.Body, expression)) == "not_effective" {
				continue
			}
		}
		add("cfg_event_unplaced", strings.TrimPrefix(strings.TrimPrefix(event, "call:"), "signal:"), "", "Clang could not assign the AST event to one unambiguous CFG block")
	}

	for _, callee := range scan.callees {
		if domain == "lsm" {
			if strings.HasPrefix(callee, "security_") {
				continue
			}
			if a.llvmCallCannotContainEffectSource(fn, callee) {
				continue
			}
			if a.resolvedTargetsHaveNoLSMEffect(fn, callee) {
				continue
			}
			if classifySignalAbortEffect(a.analyzeNamedCallErrorEffect(fn, fn.Body, callee)) == "not_effective" {
				continue
			}
		}
		ids, status := a.resolveCallee(fn, callee)
		switch status {
		case "ambiguous":
			targets := make([]string, 0, len(ids))
			for _, id := range ids {
				if target := a.functions[id]; target != nil {
					targets = append(targets, target.DisplayName)
				}
			}
			add("direct_call_ambiguous", callee, "", "multiple definitions remain possible: "+strings.Join(targets, ","))
		case "unresolved":
			add("direct_call_unresolved", callee, "", "no configured translation-unit definition was found")
		}
	}

	for _, invocation := range scan.indirectCalls {
		expression := invocation.expression
		if expression == "" {
			expression = invocation.fallback
		}
		if domain == "lsm" &&
			classifySignalAbortEffect(a.analyzeIndirectCallErrorEffect(fn, fn.Body, expression)) == "not_effective" {
			continue
		}
		if resolveIndirect && a.indirectTargetSetClosed(fn, invocation, operationContext) {
			continue
		}
		if !resolveIndirect {
			add("indirect_success_edge_unmodeled", "", expression, "mandatory LSM traversal does not guess through this indirect call")
			continue
		}
		targets := a.resolveIndirectInvocation(fn, invocation, operationContext)
		if len(targets) > 0 {
			for _, candidate := range invocation.explicitTargets {
				if len(a.resolveNamedTarget(fn.File, candidate)) == 0 {
					add("indirect_macro_target_unresolved", candidate, expression, "an explicit INDIRECT_CALL target has no indexed definition")
				}
			}
			continue
		}
		operationExpression := invocation.expression
		if invocation.fallback != "" {
			operationExpression = invocation.fallback
		}
		structType, field, typed := a.inferOperationType(fn, operationExpression)
		switch {
		case typed && !supportedOperationTableType(structType):
			add("unsupported_ops_table", structType+"."+field, expression, "only proto_ops and proto tables are resolved")
		case typed:
			add("ops_table_targets_missing", structType+"."+field, expression, "no configured operation-table targets were indexed")
		default:
			add("function_pointer_unresolved", "", expression, "the function pointer target cannot be established statically")
		}
	}
	return result
}

func clangHasDirectCallSite(fn *FunctionInfo, name string) bool {
	if fn == nil {
		return false
	}
	for _, site := range fn.CallSites {
		if site.Direct && site.Name == name {
			return true
		}
	}
	return false
}

func addProofGap(gaps *[]UnresolvedProofEdge, seen map[string]struct{}, gap UnresolvedProofEdge) {
	gap = classifyUnresolvedProofEdge(gap)
	key := gap.Domain + "\x00" + gap.Caller + "\x00" + gap.Kind + "\x00" + gap.Symbol + "\x00" + gap.Expression
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*gaps = append(*gaps, gap)
}

func sortedProofGaps(gaps []UnresolvedProofEdge) []UnresolvedProofEdge {
	for index := range gaps {
		gaps[index] = classifyUnresolvedProofEdge(gaps[index])
	}
	sort.Slice(gaps, func(left, right int) bool {
		leftKey := gaps[left].Domain + "\x00" + gaps[left].Caller + "\x00" + gaps[left].Kind + "\x00" + gaps[left].Symbol + "\x00" + gaps[left].Expression
		rightKey := gaps[right].Domain + "\x00" + gaps[right].Caller + "\x00" + gaps[right].Kind + "\x00" + gaps[right].Symbol + "\x00" + gaps[right].Expression
		return leftKey < rightKey
	})
	return gaps
}

func (a *Analyzer) signalCheckSubject(fn *FunctionInfo, body, check string) string {
	current := false
	unknown := false
	if check == "SIGNAL_GROUP_EXIT" {
		masked := maskStringAndCharLiterals(body)
		pattern := regexp.MustCompile(`\bSIGNAL_GROUP_EXIT\b`)
		for _, location := range pattern.FindAllStringIndex(masked, -1) {
			start := strings.LastIndexAny(masked[:location[0]], ";{}\n") + 1
			endOffset := strings.IndexAny(masked[location[1]:], ";{}\n")
			end := len(masked)
			if endOffset >= 0 {
				end = location[1] + endOffset
			}
			if regexp.MustCompile(`\bcurrent\b|\bget_current\s*\(`).MatchString(body[start:end]) {
				current = true
			} else {
				unknown = true
			}
		}
	} else {
		for _, site := range findNamedCallSites(body, check) {
			arguments, ok := callSiteArguments(body, site)
			argumentIndex := 0
			if check == "signal_pending_state" {
				argumentIndex = 1
			}
			if !ok || argumentIndex >= len(arguments) {
				unknown = true
				continue
			}
			if signalArgumentIsCurrentInBody(body, arguments[argumentIndex]) {
				current = true
			} else {
				unknown = true
			}
		}
	}
	subject := "other-or-unknown-task"
	if current && !unknown {
		subject = "current-task"
	} else if current {
		subject = "mixed-or-unknown-task"
	}
	return subject
}

func (a *Analyzer) signalCheckEvidences(
	fn *FunctionInfo,
	body, check string,
	mandatory bool,
	constrainedCallSiteIDs []string,
) []signalCheckEvidence {
	if check == "SIGNAL_GROUP_EXIT" ||
		fn == nil ||
		fn.Frontend != "clang-ast-cfg" ||
		fn.FrontendVariantConflict {
		localSites := findNamedCallSites(body, check)
		var localSite *namedCallSite
		requireSpecific := false
		if check != "SIGNAL_GROUP_EXIT" {
			if len(localSites) == 1 {
				site := localSites[0]
				localSite = &site
			} else if len(localSites) > 1 {
				requireSpecific = true
			}
		}
		return []signalCheckEvidence{{
			relevance:           a.signalCheckSIGKILLRelevance(fn, body, check, mandatory),
			subject:             a.signalCheckSubject(fn, body, check),
			localSite:           localSite,
			requireSpecificSite: requireSpecific,
		}}
	}

	eligibleIDs := constrainedCallSiteIDs
	if eligibleIDs == nil {
		eligibleIDs = fn.CFGReachableCallSites
		if mandatory {
			eligibleIDs = fn.CFGMustSuccessCallSites
		}
	}
	eligible := make(map[string]struct{}, len(eligibleIDs))
	for _, id := range eligibleIDs {
		eligible[id] = struct{}{}
	}
	allSites := make([]ClangCallSite, 0)
	for _, site := range fn.CallSites {
		if site.Direct && site.Name == check {
			allSites = append(allSites, site)
		}
	}
	sort.Slice(allSites, func(left, right int) bool {
		if allSites[left].Line != allSites[right].Line {
			return allSites[left].Line < allSites[right].Line
		}
		if allSites[left].Column != allSites[right].Column {
			return allSites[left].Column < allSites[right].Column
		}
		return allSites[left].ID < allSites[right].ID
	})
	localSites := findNamedCallSites(body, check)
	mappingReliable := len(allSites) == len(localSites)
	for index := 1; mappingReliable && index < len(allSites); index++ {
		if allSites[index-1].Line == allSites[index].Line &&
			allSites[index-1].Column == allSites[index].Column {
			mappingReliable = false
		}
	}

	result := make([]signalCheckEvidence, 0)
	for index, site := range allSites {
		if _, ok := eligible[site.ID]; !ok {
			continue
		}
		arguments := append([]string(nil), site.Arguments...)
		var localSite *namedCallSite
		if mappingReliable {
			mapped := localSites[index]
			if mappedArguments, ok := callSiteArguments(body, mapped); ok {
				arguments = mappedArguments
				localSite = &mapped
			} else {
				mappingReliable = false
			}
		}
		relevance := signalCallSiteSIGKILLRelevance(site, check, arguments)
		result = append(result, signalCheckEvidence{
			callSiteID:          site.ID,
			relevance:           relevance,
			subject:             signalCheckSubjectForArguments(body, check, arguments),
			localSite:           localSite,
			requireSpecificSite: localSite == nil,
		})
	}
	if len(result) == 0 {
		return []signalCheckEvidence{{
			relevance:           signalSIGKILLUnknown,
			subject:             "other-or-unknown-task",
			requireSpecificSite: true,
		}}
	}
	return result
}

func invocationCallSiteIDs(calls []callInvocation, name string) []string {
	result := make([]string, 0)
	for _, call := range calls {
		if call.name == name && call.callSiteID != "" {
			result = appendUnique(result, call.callSiteID)
		}
	}
	return result
}

func signalCallSiteSIGKILLRelevance(
	site ClangCallSite,
	check string,
	arguments []string,
) string {
	if check != "signal_pending_state" {
		return signalSIGKILLRelevant
	}
	if len(arguments) > 0 {
		if state, ok := unsignedBitwiseOrConstant(arguments[0]); ok {
			if state&(0x0001|0x0100) != 0 {
				return signalSIGKILLRelevant
			}
			return signalSIGKILLIrrelevant
		}
	}
	if len(site.ArgumentConstants) == 0 || site.ArgumentConstants[0] == "" {
		return signalSIGKILLUnknown
	}
	state, ok := parseClangIntegerConstant(site.ArgumentConstants[0])
	if !ok {
		return signalSIGKILLUnknown
	}
	if state&(0x0001|0x0100) != 0 {
		return signalSIGKILLRelevant
	}
	return signalSIGKILLIrrelevant
}

func signalCheckSubjectForArguments(
	body, check string,
	arguments []string,
) string {
	argumentIndex := 0
	if check == "signal_pending_state" {
		argumentIndex = 1
	}
	if argumentIndex >= len(arguments) ||
		!signalArgumentIsCurrentInBody(body, arguments[argumentIndex]) {
		return "other-or-unknown-task"
	}
	return "current-task"
}

func signalArgumentIsCurrent(expression string) bool {
	expression = strings.Join(strings.Fields(strings.TrimSpace(expression)), "")
	for len(expression) >= 2 && expression[0] == '(' {
		closeParen, ok := findMatchingParenForward(expression, 0)
		if !ok || closeParen != len(expression)-1 {
			break
		}
		expression = expression[1:closeParen]
	}
	return regexp.MustCompile(`^(?:current|get_current\(\))(?:->(?:signal|sighand))?$`).MatchString(expression)
}

func signalArgumentIsCurrentInBody(body, expression string) bool {
	if signalArgumentIsCurrent(expression) {
		return true
	}
	compact := strings.Join(strings.Fields(strings.TrimSpace(expression)), "")
	match := regexp.MustCompile(
		`^([A-Za-z_][A-Za-z0-9_]*)(?:->(?:signal|sighand))?$`,
	).FindStringSubmatch(compact)
	if len(match) != 2 {
		return false
	}
	alias := match[1]
	quoted := regexp.QuoteMeta(alias)
	assignmentPattern := regexp.MustCompile(
		`\b` + quoted + `\s*=\s*(?:current|get_current\s*\(\s*\))\s*;`,
	)
	if len(assignmentPattern.FindAllStringIndex(body, -1)) != 1 {
		return false
	}
	if len(regexp.MustCompile(`\b`+quoted+`\s*=`).FindAllStringIndex(body, -1)) != 1 {
		return false
	}
	if regexp.MustCompile(`&\s*` + quoted + `\b`).MatchString(body) {
		return false
	}
	return true
}

const (
	signalSIGKILLRelevant   = "proven_relevant"
	signalSIGKILLIrrelevant = "proven_irrelevant"
	signalSIGKILLUnknown    = "unknown"
)

func signalCheckSIGKILLRelevance(body, check string) string {
	if check != "signal_pending_state" {
		return signalSIGKILLRelevant
	}
	sites := findNamedCallSites(body, check)
	if len(sites) == 0 {
		return signalSIGKILLUnknown
	}
	sawUnknown := false
	for _, site := range sites {
		arguments, ok := callSiteArguments(body, site)
		if !ok || len(arguments) < 2 {
			sawUnknown = true
			continue
		}
		state, ok := unsignedBitwiseOrConstant(arguments[0])
		if !ok {
			sawUnknown = true
			continue
		}
		if state&(0x0001|0x0100) != 0 {
			return signalSIGKILLRelevant
		}
	}
	if sawUnknown {
		return signalSIGKILLUnknown
	}
	return signalSIGKILLIrrelevant
}

func (a *Analyzer) signalCheckSIGKILLRelevance(
	fn *FunctionInfo,
	body, check string,
	mandatory bool,
) string {
	if check != "signal_pending_state" {
		return signalSIGKILLRelevant
	}
	if fn == nil || fn.Frontend != "clang-ast-cfg" || fn.FrontendVariantConflict {
		return signalCheckSIGKILLRelevance(body, check)
	}
	eligibleIDs := fn.CFGReachableCallSites
	if mandatory {
		eligibleIDs = fn.CFGMustSuccessCallSites
	}
	eligible := make(map[string]struct{}, len(eligibleIDs))
	for _, id := range eligibleIDs {
		eligible[id] = struct{}{}
	}
	sawSite := false
	sawUnknown := false
	for _, site := range fn.CallSites {
		if !site.Direct || site.Name != check {
			continue
		}
		if _, ok := eligible[site.ID]; !ok {
			continue
		}
		sawSite = true
		if len(site.ArgumentConstants) == 0 || site.ArgumentConstants[0] == "" {
			sawUnknown = true
			continue
		}
		state, ok := parseClangIntegerConstant(site.ArgumentConstants[0])
		if !ok {
			sawUnknown = true
			continue
		}
		if state&(0x0001|0x0100) != 0 {
			return signalSIGKILLRelevant
		}
	}
	if !sawSite {
		return signalCheckSIGKILLRelevance(body, check)
	}
	if sawUnknown {
		return signalSIGKILLUnknown
	}
	return signalSIGKILLIrrelevant
}

func parseClangIntegerConstant(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if signed, err := strconv.ParseInt(value, 0, 64); err == nil {
		return uint64(signed), true
	}
	unsigned, err := strconv.ParseUint(value, 0, 64)
	return unsigned, err == nil
}

func (a *Analyzer) cachedAllInvocationScan(fn *FunctionInfo) prefixScanResult {
	if cached, ok := a.allScanCache[fn.ID]; ok {
		return cached
	}
	scan := allInvocationPrefixScan(fn.Body)
	if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete {
		if fn.FrontendVariantConflict {
			scan = clangMustSuccessScan(fn)
		} else {
			scan = constrainScanToClang(fn, scan, true, nil)
		}
	}
	scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
	a.allScanCache[fn.ID] = scan
	return scan
}

func (a *Analyzer) cachedValidatedScan(fn *FunctionInfo) prefixScanResult {
	if cached, ok := a.validScanCache[fn.ID]; ok {
		return cached
	}
	scan := validatedPrefixScan(fn.Body)
	if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete {
		if fn.FrontendVariantConflict {
			scan = clangMustSuccessScan(fn)
		} else {
			scan = constrainScanToClang(fn, scan, true, nil)
		}
	}
	scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
	a.validScanCache[fn.ID] = scan
	return scan
}

func (a *Analyzer) cachedSuccessScan(fn *FunctionInfo) prefixScanResult {
	if cached, ok := a.successCache[fn.ID]; ok {
		return cached
	}
	scan := mustPassPrefixScan(fn.Body)
	if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete {
		if fn.FrontendVariantConflict {
			scan = clangMustSuccessScan(fn)
		} else {
			scan = constrainScanToClang(fn, scan, true, nil)
		}
	}
	scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
	a.successCache[fn.ID] = scan
	return scan
}

func (a *Analyzer) cachedContextSuccessScan(fn *FunctionInfo, constants map[string]string) prefixScanResult {
	if len(constants) == 0 {
		return a.cachedSuccessScan(fn)
	}
	key := functionContextKey(fn, constants)
	if cached, ok := a.contextScanCache[key]; ok {
		return cached
	}
	body := substituteIdentifierConstants(fn.Body, constants)
	scan := mustPassPrefixScan(body, constants[contextReturnRequirementKey])
	if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete {
		if fn.FrontendVariantConflict {
			scan = clangMustSuccessScan(fn)
		} else {
			scan = constrainScanToClang(fn, scan, true, constants)
		}
	}
	scan.returnRequirement = constants[contextReturnRequirementKey]
	scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
	a.contextScanCache[key] = scan
	return scan
}

func (a *Analyzer) cachedContextKernelSuccessScan(fn *FunctionInfo, constants map[string]string) prefixScanResult {
	if len(constants) == 0 {
		if cached, ok := a.kernelSuccessCache[fn.ID]; ok {
			return cached
		}
		scan := mustPassPrefixScan(fn.Body)
		scan = a.constrainKernelSuccessScan(fn, scan, nil)
		scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
		a.kernelSuccessCache[fn.ID] = scan
		return scan
	}
	key := functionContextKey(fn, constants)
	if cached, ok := a.kernelContextCache[key]; ok {
		return cached
	}
	body := substituteIdentifierConstants(fn.Body, constants)
	scan := mustPassPrefixScan(body, constants[contextReturnRequirementKey])
	scan = a.constrainKernelSuccessScan(fn, scan, constants)
	scan.returnRequirement = constants[contextReturnRequirementKey]
	scan.lsmHooks, scan.inactiveLSMHooks = a.partitionConfiguredLSMHooks(scan.lsmHooks)
	a.kernelContextCache[key] = scan
	return scan
}

func (a *Analyzer) constrainKernelSuccessScan(
	fn *FunctionInfo,
	scan prefixScanResult,
	constants map[string]string,
) prefixScanResult {
	if fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete {
		return prefixScanResult{}
	}
	if fn.FrontendVariantConflict {
		return clangMustSuccessScan(fn)
	}
	scan.calls, scan.unmatchedCalls = filterInvocationsByClangCallSites(
		fn,
		scan.calls,
		fn.CFGReachableCallSites,
		constants,
	)
	scan.callees = invocationNames(scan.calls)
	scan.lsmHooks = intersectStrings(scan.lsmHooks, fn.DirectLSMHooks)
	scan.sigChecks = nil
	scan.indirectCalls = filterIndirectInvocationsByExpressions(scan.indirectCalls, fn.CFGReachableIndirect)
	scan.calls = append(
		scan.calls,
		clangDirectInvocations(fn, fn.CFGMustSuccessCallSites)...,
	)
	scan.callees = invocationNames(scan.calls)
	scan.lsmHooks = uniqueStrings(append(scan.lsmHooks, fn.CFGMustSuccessLSM...))
	mandatoryIndirect := filterIndirectInvocationsByExpressions(
		extractIndirectInvocations(fn.Body),
		fn.CFGMustSuccessIndirect,
	)
	scan.indirectCalls = uniqueIndirectInvocations(append(scan.indirectCalls, mandatoryIndirect...))
	return finalizeClangScan(scan)
}

func filterInvocationsByClangCallSites(
	fn *FunctionInfo,
	calls []callInvocation,
	callSiteIDs []string,
	constants map[string]string,
) ([]callInvocation, []callInvocation) {
	if fn == nil || len(calls) == 0 || len(callSiteIDs) == 0 {
		return nil, append([]callInvocation(nil), calls...)
	}
	allowed := make(map[string]struct{}, len(callSiteIDs))
	for _, id := range callSiteIDs {
		allowed[id] = struct{}{}
	}
	byName := make(map[string][]ClangCallSite)
	for _, site := range fn.CallSites {
		if !site.Direct {
			continue
		}
		if _, ok := allowed[site.ID]; !ok {
			continue
		}
		byName[site.Name] = append(byName[site.Name], site)
	}
	result := make([]callInvocation, 0, len(calls))
	unmatched := make([]callInvocation, 0)
	for _, call := range calls {
		candidates := byName[call.name]
		matches := make([]ClangCallSite, 0, len(candidates))
		for _, candidate := range candidates {
			arguments := make([]string, 0, len(candidate.Arguments))
			for _, argument := range candidate.Arguments {
				arguments = append(
					arguments,
					substituteIdentifierConstants(argument, constants),
				)
			}
			if sameCallArguments(arguments, call.arguments) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			unmatched = append(unmatched, call)
			continue
		}
		call.callSiteID = matches[0].ID
		result = append(result, call)
	}
	return result, unmatched
}

func (a *Analyzer) cachedContextSignalScan(fn *FunctionInfo, constants map[string]string) prefixScanResult {
	key := functionContextKey(fn, constants)
	if cached, ok := a.signalScanCache[key]; ok {
		return cached
	}
	var scan prefixScanResult
	if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete && len(constants) == 0 {
		scan = clangReachableScan(fn)
	} else {
		body := substituteIdentifierConstants(fn.Body, constants)
		scan = feasibleMayReachScan(body)
		if fn.Frontend == "clang-ast-cfg" && fn.CFGComplete {
			scan = constrainScanToClang(fn, scan, false, constants)
		}
	}
	a.signalScanCache[key] = scan
	return scan
}

func clangMustSuccessScan(fn *FunctionInfo) prefixScanResult {
	result := prefixScanResult{
		lsmHooks:  uniqueStrings(fn.CFGMustSuccessLSM),
		sigChecks: uniqueStrings(fn.CFGMustSuccessSignals),
		indirectCalls: completeIndirectInvocations(
			fn.Body,
			filterIndirectInvocationsByExpressions(
				extractIndirectInvocations(fn.Body),
				fn.CFGMustSuccessIndirect,
			),
			fn.CFGMustSuccessIndirect,
		),
	}
	result.calls = clangDirectInvocations(fn, fn.CFGMustSuccessCallSites)
	if len(result.calls) == 0 && len(fn.CFGMustSuccessCallSites) == 0 {
		result.calls = filterInvocations(
			extractDirectInvocations(fn.Body),
			fn.CFGMustSuccessCalls,
		)
	}
	result.callees = invocationNames(result.calls)
	return finalizeClangScan(result)
}

func clangReachableScan(fn *FunctionInfo) prefixScanResult {
	result := prefixScanResult{
		lsmHooks:  uniqueStrings(fn.DirectLSMHooks),
		sigChecks: uniqueStrings(fn.DirectSigChecks),
		indirectCalls: completeIndirectInvocations(
			fn.Body,
			filterIndirectInvocationsByExpressions(
				extractIndirectInvocations(fn.Body),
				fn.CFGReachableIndirect,
			),
			fn.CFGReachableIndirect,
		),
	}
	result.calls = clangDirectInvocations(fn, fn.CFGReachableCallSites)
	if len(result.calls) == 0 && len(fn.CFGReachableCallSites) == 0 {
		result.calls = filterInvocations(
			extractDirectInvocations(fn.Body),
			fn.CFGReachableCalls,
		)
	}
	result.callees = invocationNames(result.calls)
	return finalizeClangScan(result)
}

func constrainScanToClang(
	fn *FunctionInfo,
	scan prefixScanResult,
	includeMust bool,
	constants map[string]string,
) prefixScanResult {
	if includeMust {
		scan.calls = clangDirectInvocations(fn, fn.CFGMustSuccessCallSites)
		if len(scan.calls) == 0 && len(fn.CFGMustSuccessCallSites) == 0 {
			scan.calls = filterInvocations(
				append(scan.calls, extractDirectInvocations(fn.Body)...),
				fn.CFGMustSuccessCalls,
			)
		}
		scan.callees = invocationNames(scan.calls)
		scan.lsmHooks = uniqueStrings(fn.CFGMustSuccessLSM)
		scan.sigChecks = uniqueStrings(fn.CFGMustSuccessSignals)
		scan.indirectCalls = completeIndirectInvocations(
			fn.Body,
			filterIndirectInvocationsByExpressions(extractIndirectInvocations(fn.Body), fn.CFGMustSuccessIndirect),
			fn.CFGMustSuccessIndirect,
		)
	} else {
		scan.calls, scan.unmatchedCalls = filterInvocationsByClangCallSites(
			fn,
			scan.calls,
			fn.CFGReachableCallSites,
			constants,
		)
		if len(scan.calls) == 0 && len(fn.CFGReachableCallSites) == 0 {
			scan.calls = filterInvocations(
				extractDirectInvocations(fn.Body),
				intersectStrings(scan.callees, fn.CFGReachableCalls),
			)
		}
		scan.callees = invocationNames(scan.calls)
		scan.lsmHooks = intersectStrings(scan.lsmHooks, fn.DirectLSMHooks)
		scan.sigChecks = intersectStrings(scan.sigChecks, fn.DirectSigChecks)
		scan.indirectCalls = completeIndirectInvocations(
			fn.Body,
			filterIndirectInvocationsByExpressions(scan.indirectCalls, fn.CFGReachableIndirect),
			fn.CFGReachableIndirect,
		)
	}
	return finalizeClangScan(scan)
}

func clangDirectInvocations(
	fn *FunctionInfo,
	callSiteIDs []string,
) []callInvocation {
	if fn == nil || len(callSiteIDs) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(callSiteIDs))
	for _, id := range callSiteIDs {
		allowed[id] = struct{}{}
	}
	result := make([]callInvocation, 0, len(callSiteIDs))
	for _, site := range fn.CallSites {
		if !site.Direct {
			continue
		}
		if _, ok := allowed[site.ID]; !ok {
			continue
		}
		result = append(result, callInvocation{
			name:       site.Name,
			arguments:  append([]string(nil), site.Arguments...),
			callSiteID: site.ID,
		})
	}
	return result
}

func invocationNames(calls []callInvocation) []string {
	result := orderedSet(nil)
	for _, call := range calls {
		result.add(call.name)
	}
	return result.slice()
}

func filterIndirectInvocationsByExpressions(invocations []indirectCallInvocation, expressions []string) []indirectCallInvocation {
	if len(expressions) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(expressions))
	for _, expression := range expressions {
		allowed[normalizeIndirectExpression(expression)] = struct{}{}
	}
	result := make([]indirectCallInvocation, 0, len(invocations))
	for _, invocation := range invocations {
		candidates := []string{invocation.expression, invocation.fallback}
		matched := false
		for _, candidate := range candidates {
			if _, ok := allowed[normalizeIndirectExpression(candidate)]; ok {
				matched = true
				break
			}
		}
		if matched {
			result = append(result, invocation)
		}
	}
	return uniqueIndirectInvocations(result)
}

func completeIndirectInvocations(
	body string,
	invocations []indirectCallInvocation,
	expressions []string,
) []indirectCallInvocation {
	result := append([]indirectCallInvocation(nil), invocations...)
	present := make(map[string]struct{}, len(invocations))
	for _, invocation := range invocations {
		expression := invocation.expression
		if expression == "" {
			expression = invocation.fallback
		}
		present[normalizeIndirectExpression(expression)] = struct{}{}
	}
	for _, expression := range expressions {
		normalized := normalizeIndirectExpression(expression)
		if normalized == "" {
			continue
		}
		if _, ok := present[normalized]; ok {
			continue
		}
		added := false
		for _, site := range findExpressionCallSites(body, expression) {
			arguments, ok := callSiteArguments(body, site)
			if !ok {
				continue
			}
			result = append(result, indirectCallInvocation{
				expression: expression,
				arguments:  arguments,
			})
			added = true
		}
		if !added {
			result = append(result, indirectCallInvocation{expression: expression})
		}
		present[normalized] = struct{}{}
	}
	return uniqueIndirectInvocations(result)
}

func normalizeIndirectExpression(expression string) string {
	expression = normalizeMemberExpression(expression)
	expression = strings.Join(strings.Fields(expression), "")
	return strings.Trim(expression, "()")
}

func finalizeClangScan(result prefixScanResult) prefixScanResult {
	result.callees = filterInternalCallees(result.callees)
	result.calls = filterInvocations(result.calls, result.callees)
	result.indirectCalls = uniqueIndirectInvocations(result.indirectCalls)
	result.lsmHooks = uniqueStrings(result.lsmHooks)
	result.sigChecks = uniqueStrings(result.sigChecks)
	return result
}

type resolvedContextCall struct {
	functionID       string
	constants        map[string]string
	operationContext map[string][]string
	indirect         *IndirectCallEvidence
}

type resolvedIndirectTarget struct {
	functionID string
	arguments  []string
	evidence   IndirectCallEvidence
}

func (a *Analyzer) resolveContextCalls(fn *FunctionInfo, scan prefixScanResult) []resolvedContextCall {
	return a.resolveContextCallsWithOperations(fn, nil, scan, nil)
}

func (a *Analyzer) resolveContextCallsInContext(
	fn *FunctionInfo,
	constants map[string]string,
	scan prefixScanResult,
) []resolvedContextCall {
	return a.resolveContextCallsWithOperations(fn, constants, scan, nil)
}

func (a *Analyzer) cachedSignalTransitions(
	fn *FunctionInfo,
	constants map[string]string,
	scan prefixScanResult,
	operationContext map[string][]string,
	stats *SignalTraversalStats,
) []resolvedContextCall {
	key := functionContextKey(fn, constants) + "\x1e" + operationConstraintsKey(a.effectiveOperationConstraints(operationContext))
	if cached, ok := a.signalTransitionCache[key]; ok {
		stats.TransitionCacheHits++
		return cached
	}
	resolved := a.resolveContextCallsWithOperations(fn, constants, scan, operationContext)
	a.signalTransitionCache[key] = resolved
	stats.TransitionBuilds++
	return resolved
}

func (a *Analyzer) resolveContextCallsWithOperations(
	fn *FunctionInfo,
	parentConstants map[string]string,
	scan prefixScanResult,
	operationContext map[string][]string,
) []resolvedContextCall {
	result := make([]resolvedContextCall, 0, len(scan.callees)+len(scan.indirectCalls))
	seenNames := make(map[string]struct{}, len(scan.calls))
	seenContexts := make(map[string]struct{}, len(scan.calls))
	for _, call := range scan.calls {
		seenNames[call.name] = struct{}{}
		ids, status := a.resolveCallee(fn, call.name)
		if status != "resolved" {
			continue
		}
		for _, id := range ids {
			callee := a.functions[id]
			if callee == nil {
				continue
			}
			arguments := make([]string, 0, len(call.arguments))
			for _, argument := range call.arguments {
				arguments = append(
					arguments,
					substituteIdentifierConstants(argument, parentConstants),
				)
			}
			constants := a.bindCallAnalysisContext(
				fn,
				parentConstants,
				callee,
				arguments,
				clangCallSiteByID(fn, call.callSiteID),
			)
			contextCall := call
			contextCall.arguments = arguments
			constants = bindCallStructConstants(constants, fn.Body, contextCall, callee.Parameters)
			constants = bindCallReturnRequirement(
				constants,
				callee,
				requiredCallReturnForSite(
					fn,
					callee,
					fn.Body,
					call.name,
					clangCallSiteByID(fn, call.callSiteID),
					scan.returnRequirement,
				),
			)
			key := functionContextKey(callee, constants)
			if _, ok := seenContexts[key]; ok {
				continue
			}
			seenContexts[key] = struct{}{}
			result = append(result, resolvedContextCall{functionID: id, constants: constants, operationContext: cloneOperationContext(operationContext)})
		}
	}
	for _, name := range scan.callees {
		if _, ok := seenNames[name]; ok {
			continue
		}
		ids, status := a.resolveCallee(fn, name)
		if status != "resolved" {
			continue
		}
		for _, id := range ids {
			callee := a.functions[id]
			if callee == nil {
				continue
			}
			constants := bindCallReturnRequirement(
				nil,
				callee,
				requiredCallReturnForSite(
					fn,
					callee,
					fn.Body,
					name,
					nil,
					scan.returnRequirement,
				),
			)
			key := functionContextKey(callee, constants)
			if _, ok := seenContexts[key]; ok {
				continue
			}
			seenContexts[key] = struct{}{}
			result = append(result, resolvedContextCall{functionID: id, constants: constants, operationContext: cloneOperationContext(operationContext)})
		}
	}
	for _, invocation := range scan.indirectCalls {
		for _, target := range a.resolveIndirectInvocationWithContext(
			fn,
			invocation,
			operationContext,
			parentConstants,
		) {
			callee := a.functions[target.functionID]
			if callee == nil {
				continue
			}
			constants := a.bindCallAnalysisContext(
				fn,
				parentConstants,
				callee,
				target.arguments,
			)
			evidence := target.evidence
			nextOperationContext := extendOperationContext(operationContext, evidence)
			key := functionContextKey(callee, constants) + operationContextKey(nextOperationContext)
			if _, ok := seenContexts[key]; ok {
				continue
			}
			seenContexts[key] = struct{}{}
			result = append(result, resolvedContextCall{
				functionID:       target.functionID,
				constants:        constants,
				operationContext: nextOperationContext,
				indirect:         &evidence,
			})
		}
	}
	return result
}

func (a *Analyzer) buildIndirectCallResolutions(fn *FunctionInfo) []IndirectCallResolution {
	byKey := make(map[string]int)
	result := make([]IndirectCallResolution, 0)
	for _, invocation := range extractIndirectInvocations(fn.Body) {
		for _, target := range a.resolveIndirectInvocation(fn, invocation, nil) {
			evidence := target.evidence
			key := evidence.Expression + "\x00" + evidence.Kind + "\x00" + evidence.TableType + "\x00" + evidence.Field
			index, ok := byKey[key]
			if !ok {
				index = len(result)
				byKey[key] = index
				result = append(result, IndirectCallResolution{
					Expression:      evidence.Expression,
					Kind:            evidence.Kind,
					TableType:       evidence.TableType,
					Field:           evidence.Field,
					TargetSetClosed: evidence.TargetSetClosed,
				})
			}
			result[index].TargetSetClosed = result[index].TargetSetClosed || evidence.TargetSetClosed
			callee := a.functions[target.functionID]
			if callee != nil {
				result[index].Targets = appendUnique(result[index].Targets, callee.DisplayName)
			}
			for _, table := range evidence.Tables {
				result[index].Tables = appendUnique(result[index].Tables, table)
			}
		}
	}
	return result
}

func (a *Analyzer) resolveIndirectInvocation(fn *FunctionInfo, invocation indirectCallInvocation, operationContext map[string][]string) []resolvedIndirectTarget {
	return a.resolveIndirectInvocationWithContext(fn, invocation, operationContext, nil)
}

func (a *Analyzer) resolveIndirectInvocationWithContext(
	fn *FunctionInfo,
	invocation indirectCallInvocation,
	operationContext map[string][]string,
	constants map[string]string,
) []resolvedIndirectTarget {
	result := make([]resolvedIndirectTarget, 0)
	targetSetClosed := a.indirectTargetSetClosedWithContext(
		fn,
		invocation,
		operationContext,
		constants,
	)
	seen := make(map[string]int)
	add := func(functionID string, arguments []string, evidence IndirectCallEvidence) {
		if functionID == "" {
			return
		}
		if index, ok := seen[functionID]; ok {
			if result[index].evidence.TableType == "" && evidence.TableType != "" {
				result[index].evidence.TableType = evidence.TableType
				result[index].evidence.Field = evidence.Field
			}
			for _, table := range evidence.Tables {
				result[index].evidence.Tables = appendUnique(result[index].evidence.Tables, table)
			}
			return
		}
		evidence.Caller = fn.DisplayName
		evidence.Target = a.functions[functionID].DisplayName
		seen[functionID] = len(result)
		result = append(result, resolvedIndirectTarget{
			functionID: functionID,
			arguments:  append([]string(nil), arguments...),
			evidence:   evidence,
		})
	}

	if callbackTargets, ok := a.callbackTargetsFromContext(invocation, constants); ok {
		for _, functionID := range callbackTargets {
			if a.functions[functionID] == nil {
				continue
			}
			add(functionID, invocation.arguments, IndirectCallEvidence{
				Expression:      invocation.expression,
				Kind:            "callback-argument",
				TargetSetClosed: true,
			})
		}
		return result
	}

	if invocation.macro != "" {
		fallbackTargets := a.resolveOperationExpression(fn, invocation.fallback, invocation.arguments, operationContext)
		for _, candidate := range invocation.explicitTargets {
			for _, functionID := range a.resolveNamedTarget(fn.File, candidate) {
				add(functionID, invocation.arguments, IndirectCallEvidence{
					Expression:      invocation.expression,
					Kind:            "indirect-macro",
					TargetSetClosed: targetSetClosed,
				})
			}
		}
		for _, target := range fallbackTargets {
			target.evidence.TargetSetClosed = targetSetClosed
			add(target.functionID, target.arguments, target.evidence)
		}
		return result
	}

	for _, target := range a.resolveOperationExpression(fn, invocation.expression, invocation.arguments, operationContext) {
		target.evidence.TargetSetClosed = targetSetClosed
		add(target.functionID, target.arguments, target.evidence)
	}
	return result
}

func (a *Analyzer) resolveOperationExpression(fn *FunctionInfo, expression string, arguments []string, operationContext map[string][]string) []resolvedIndirectTarget {
	structType, field, ok := a.inferOperationType(fn, expression)
	if !ok || !supportedOperationTableType(structType) &&
		!a.operationExpressionTargetSetClosed(expression, structType, field, operationContext) {
		return nil
	}
	targets := a.operationTargets[structMemberKey(structType, field)]
	allowedTables := a.linkedOperationTables(operationContext, structType)
	for _, table := range operationContext[structType] {
		allowedTables[table] = struct{}{}
	}
	if len(allowedTables) == 0 {
		parts := regexp.MustCompile(`(?:->|\.)`).Split(normalizeMemberExpression(expression), -1)
		if len(parts) == 2 && len(a.operationTablesByName[strings.TrimSpace(parts[0])]) == 1 {
			allowedTables[strings.TrimSpace(parts[0])] = struct{}{}
		}
	}
	result := make([]resolvedIndirectTarget, 0, len(targets))
	byFunction := make(map[string]int)
	for _, target := range targets {
		if len(allowedTables) > 0 {
			if _, ok := allowedTables[target.Table]; !ok {
				continue
			}
		}
		for _, functionID := range a.resolveNamedTarget(target.File, target.Function) {
			if index, ok := byFunction[functionID]; ok {
				result[index].evidence.Tables = appendUnique(result[index].evidence.Tables, target.Table)
				continue
			}
			byFunction[functionID] = len(result)
			result = append(result, resolvedIndirectTarget{
				functionID: functionID,
				arguments:  append([]string(nil), arguments...),
				evidence: IndirectCallEvidence{
					Caller:     fn.DisplayName,
					Expression: expression,
					Kind:       "ops-table",
					TableType:  structType,
					Field:      field,
					Target:     a.functions[functionID].DisplayName,
					Tables:     []string{target.Table},
				},
			})
		}
	}
	return result
}

func (a *Analyzer) indirectTargetSetClosed(
	fn *FunctionInfo,
	invocation indirectCallInvocation,
	operationContext map[string][]string,
) bool {
	return a.indirectTargetSetClosedWithContext(fn, invocation, operationContext, nil)
}

func (a *Analyzer) indirectTargetSetClosedWithContext(
	fn *FunctionInfo,
	invocation indirectCallInvocation,
	operationContext map[string][]string,
	constants map[string]string,
) bool {
	if targets, ok := a.callbackTargetsFromContext(invocation, constants); ok {
		if len(targets) == 0 {
			return false
		}
		for _, functionID := range targets {
			if a.functions[functionID] == nil {
				return false
			}
		}
		return true
	}
	if !a.cfg.ScanAll || a.cfg.CompileDB == "" || fn == nil {
		return false
	}
	expression := invocation.expression
	if invocation.fallback != "" {
		expression = invocation.fallback
	}
	structType, field, ok := a.inferOperationType(fn, expression)
	if !ok || !a.operationExpressionTargetSetClosed(expression, structType, field, operationContext) {
		return false
	}
	for _, candidate := range invocation.explicitTargets {
		if len(a.resolveNamedTarget(fn.File, candidate)) == 0 {
			return false
		}
	}
	return true
}

func (a *Analyzer) callbackTargetsFromContext(
	invocation indirectCallInvocation,
	constants map[string]string,
) ([]string, bool) {
	if len(constants) == 0 {
		return nil, false
	}
	expression := normalizeIndirectExpression(invocation.expression)
	if expression == "" {
		expression = normalizeIndirectExpression(invocation.fallback)
	}
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(expression) {
		return nil, false
	}
	encoded, ok := constants[contextCallbackPrefix+expression]
	if !ok || encoded == "" {
		return nil, false
	}
	return uniqueStrings(strings.Split(encoded, contextCallbackSeparator)), true
}

func (a *Analyzer) operationExpressionTargetSetClosed(
	expression, structType, field string,
	operationContext map[string][]string,
) bool {
	if !a.cfg.ScanAll || a.cfg.CompileDB == "" || structType == "" || field == "" {
		return false
	}
	tableNames := orderedSet(operationContext[structType])
	for table := range a.linkedOperationTables(operationContext, structType) {
		tableNames.add(table)
	}
	if len(tableNames.items) == 0 {
		parts := regexp.MustCompile(`(?:->|\.)`).Split(normalizeMemberExpression(expression), -1)
		if len(parts) == 2 {
			tableNames.add(strings.TrimSpace(parts[0]))
		}
	}
	if len(tableNames.items) == 0 {
		return false
	}
	for _, table := range tableNames.items {
		keys := a.operationTablesByName[table]
		if len(keys) != 1 {
			return false
		}
		info := a.operationTables[keys[0]]
		if !operationTableFieldTargetSetClosed(
			info,
			structType,
			field,
		) {
			return false
		}
		if function := info.FieldTargets[field]; function != "" {
			targetFile := info.FieldTargetFiles[field]
			if targetFile == "" {
				targetFile = info.File
			}
			if len(a.resolveNamedTarget(targetFile, function)) == 0 {
				return false
			}
		}
	}
	return true
}

func operationTableFieldTargetSetClosed(
	info *OperationTableInfo,
	structType, field string,
) bool {
	if info == nil || info.StructType != structType || !info.Const ||
		info.UnknownFields[field] {
		return false
	}
	if info.FieldTargets[field] == "" && !info.NullFields[field] {
		return false
	}
	if info.VerifiedByClang {
		return true
	}
	return info.Complete
}

func (a *Analyzer) inferOperationType(fn *FunctionInfo, expression string) (string, string, bool) {
	if target, ok := fn.TypedIndirectCalls[normalizeIndirectExpression(expression)]; ok {
		if target.StructType != "" && target.Field != "" {
			return target.StructType, target.Field, true
		}
	}
	parts := regexp.MustCompile(`(?:->|\.)`).Split(normalizeMemberExpression(expression), -1)
	if len(parts) < 2 {
		return "", "", false
	}
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(parts[index]) {
			return "", "", false
		}
	}
	structType, ok := fn.StructVariables[parts[0]]
	if !ok {
		return "", "", false
	}
	for _, member := range parts[1 : len(parts)-1] {
		nextType, ok := a.resolveStructMemberType(structType, member)
		if !ok {
			return "", "", false
		}
		structType = nextType
	}
	return structType, parts[len(parts)-1], true
}

func (a *Analyzer) resolveStructMemberType(owner, member string) (string, bool) {
	candidateTypes := uniqueStrings(a.structMembers[structMemberKey(owner, member)])
	if len(candidateTypes) == 1 {
		return candidateTypes[0], true
	}
	aliases := a.memberAliases[member]
	if len(aliases) != 1 {
		return "", false
	}
	current := owner
	for _, aliasMember := range aliases[0] {
		candidateTypes = uniqueStrings(a.structMembers[structMemberKey(current, aliasMember)])
		if len(candidateTypes) != 1 {
			return "", false
		}
		current = candidateTypes[0]
	}
	return current, true
}

func supportedOperationTableType(structType string) bool {
	switch structType {
	case "proto_ops", "proto":
		return true
	default:
		return false
	}
}

func (a *Analyzer) resolveNamedTarget(file, name string) []string {
	if byFile, ok := a.staticIndex[file]; ok {
		if ids := byFile[name]; len(ids) == 1 {
			return []string{ids[0]}
		}
	}
	if ids := a.globalIndex[name]; len(ids) == 1 {
		return []string{ids[0]}
	}
	return nil
}

func bindCallConstants(parameters, arguments []string) map[string]string {
	if len(parameters) == 0 || len(parameters) != len(arguments) {
		return nil
	}
	constants := make(map[string]string)
	for index, parameter := range parameters {
		if value, ok := constantExpression(arguments[index]); ok {
			constants[parameter] = value
		}
	}
	if len(constants) == 0 {
		return nil
	}
	return constants
}

func (a *Analyzer) bindCallAnalysisContext(
	caller *FunctionInfo,
	parentConstants map[string]string,
	callee *FunctionInfo,
	arguments []string,
	callSites ...*ClangCallSite,
) map[string]string {
	if callee == nil {
		return nil
	}
	constants := bindCallConstants(callee.Parameters, arguments)
	if caller == nil || len(callee.Parameters) == 0 ||
		len(callee.Parameters) != len(arguments) {
		return constants
	}
	var callSite *ClangCallSite
	if len(callSites) > 0 {
		callSite = callSites[0]
	}
	for index, parameter := range callee.Parameters {
		if callback, ok := clangCallbackArgumentAt(callSite, index); ok &&
			callback.Complete {
			resolved := make([]string, 0, len(callback.Targets))
			for _, target := range callback.Targets {
				if target.FunctionID == "" ||
					a.functions[target.FunctionID] == nil {
					resolved = nil
					break
				}
				resolved = appendUnique(resolved, target.FunctionID)
			}
			if len(resolved) > 0 {
				if constants == nil {
					constants = make(map[string]string)
				}
				constants[contextCallbackPrefix+parameter] =
					strings.Join(
						uniqueStrings(resolved),
						contextCallbackSeparator,
					)
				continue
			}
		}
		argument := compactExpression(arguments[index])
		if strings.HasPrefix(argument, "&") {
			argument = compactExpression(strings.TrimSpace(argument[1:]))
		}
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(argument) {
			continue
		}
		if encoded := parentConstants[contextCallbackPrefix+argument]; encoded != "" {
			if constants == nil {
				constants = make(map[string]string)
			}
			constants[contextCallbackPrefix+parameter] = encoded
			continue
		}
		if containsString(caller.Parameters, argument) {
			continue
		}
		typedTargets := caller.TypedCallees[argument]
		if len(typedTargets) == 0 {
			continue
		}
		resolved := make([]string, 0, len(typedTargets))
		for _, functionID := range typedTargets {
			if a.functions[functionID] == nil {
				resolved = nil
				break
			}
			resolved = appendUnique(resolved, functionID)
		}
		if len(resolved) == 0 {
			continue
		}
		if constants == nil {
			constants = make(map[string]string)
		}
		constants[contextCallbackPrefix+parameter] =
			strings.Join(uniqueStrings(resolved), contextCallbackSeparator)
	}
	return constants
}

func clangCallbackArgumentAt(
	site *ClangCallSite,
	index int,
) (ClangCallbackArgument, bool) {
	if site == nil {
		return ClangCallbackArgument{}, false
	}
	for _, argument := range site.CallbackArguments {
		if argument.Index == index {
			return argument, true
		}
	}
	return ClangCallbackArgument{}, false
}

func bindCallReturnRequirement(constants map[string]string, callee *FunctionInfo, requirement string) map[string]string {
	if requirement == "" || callee == nil ||
		returnDomainForType(callee.ReturnType) == returnDomainUnknown {
		return constants
	}
	if constants == nil {
		constants = make(map[string]string)
	}
	constants[contextReturnRequirementKey] = requirement
	return constants
}

func successAssumptionKey(parameter string) string {
	return contextSuccessAssumePrefix + parameter
}

func successRequirementWitnessExpression(
	returnType, requirement string,
) (string, bool) {
	domain := returnDomainForType(returnType)
	switch requirement {
	case "any", "returned":
		switch domain {
		case returnDomainSigned, returnDomainUnsigned:
			return "0", true
		case returnDomainBool:
			return "false", true
		case returnDomainPointer:
			return "NULL", true
		case returnDomainRecord:
			return "record_value", true
		case returnDomainVoid:
			return "", true
		}
	case "negative":
		if domain == returnDomainSigned {
			return "-1", true
		}
	case "zero", "false":
		if domain == returnDomainSigned ||
			domain == returnDomainUnsigned ||
			domain == returnDomainBool {
			return "0", true
		}
	case "positive", "nonzero", "true":
		if domain == returnDomainSigned ||
			domain == returnDomainUnsigned ||
			domain == returnDomainBool {
			return "1", true
		}
	case "nonnegative":
		if domain == returnDomainSigned ||
			domain == returnDomainUnsigned {
			return "0", true
		}
	case "nonpositive":
		if domain == returnDomainSigned {
			return "0", true
		}
	case "null":
		if domain == returnDomainPointer {
			return "NULL", true
		}
	case "nonnull", "valid_pointer", "non_error_pointer",
		"nonnull_valid_pointer":
		if domain == returnDomainPointer {
			return "&__systematic_success_object", true
		}
	case "error_pointer":
		if domain == returnDomainPointer {
			return "ERR_PTR(-1)", true
		}
	}
	return "", false
}

func bindCallStructConstants(constants map[string]string, callerBody string, call callInvocation, parameters []string) map[string]string {
	if call.name != "notify_change" || len(parameters) == 0 || len(parameters) != len(call.arguments) {
		return constants
	}
	sites := findNamedCallSites(callerBody, call.name)
	for argumentIndex, argument := range call.arguments {
		match := regexp.MustCompile(`^&\s*([A-Za-z_][A-Za-z0-9_]*)$`).FindStringSubmatch(strings.TrimSpace(argument))
		if len(match) != 2 {
			continue
		}
		variable := match[1]
		var common map[string]string
		matchedSites := 0
		for _, site := range sites {
			arguments, ok := callSiteArguments(callerBody, site)
			if !ok || !sameCallArguments(arguments, call.arguments) {
				continue
			}
			facts := lastStructFieldAssignments(callerBody[:site.start], variable)
			if len(facts) == 0 {
				common = nil
				matchedSites = 0
				break
			}
			if matchedSites == 0 {
				common = facts
			} else {
				for field, value := range common {
					if facts[field] != value {
						delete(common, field)
					}
				}
			}
			matchedSites++
		}
		if matchedSites == 0 || len(common) == 0 {
			continue
		}
		if constants == nil {
			constants = make(map[string]string)
		}
		for field, value := range common {
			constants[parameters[argumentIndex]+"->"+field] = value
		}
	}
	return constants
}

func callSiteArguments(body string, site namedCallSite) ([]string, bool) {
	openParen := strings.Index(body[site.start:site.end], "(")
	if openParen < 0 {
		return nil, false
	}
	openParen += site.start
	closeParen, ok := findMatchingParenForward(maskStringAndCharLiterals(body), openParen)
	if !ok || closeParen >= site.end {
		return nil, false
	}
	arguments := splitTopLevelCommaList(body[openParen+1 : closeParen])
	if len(arguments) == 1 && arguments[0] == "" {
		arguments = nil
	}
	return arguments, true
}

func sameCallArguments(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if strings.Join(strings.Fields(left[index]), "") != strings.Join(strings.Fields(right[index]), "") {
			return false
		}
	}
	return true
}

func lastStructFieldAssignments(prefix, variable string) map[string]string {
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);`)
	result := make(map[string]string)
	for _, match := range pattern.FindAllStringSubmatch(prefix, -1) {
		if match[1] != "ia_valid" {
			continue
		}
		value := strings.TrimSpace(match[2])
		if !isSymbolicScalarExpression(value) {
			continue
		}
		result[match[1]] = value
	}
	return result
}

func isSymbolicScalarExpression(expression string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9_()|~\s]+$`).MatchString(expression)
}

func requiredCallReturnForSite(
	fn, callee *FunctionInfo,
	body, calleeName string,
	site *ClangCallSite,
	callerRequirement string,
) string {
	if fn == nil || callee == nil {
		return ""
	}
	if site == nil {
		requirements := orderedSet(nil)
		for index := range fn.CallSites {
			candidate := &fn.CallSites[index]
			if !candidate.Direct || candidate.Name != calleeName ||
				!candidate.Reachable {
				continue
			}
			requirement := requiredCallReturnForSite(
				fn,
				callee,
				body,
				calleeName,
				candidate,
				callerRequirement,
			)
			if requirement == "" {
				return ""
			}
			requirements.add(requirement)
		}
		if len(requirements.items) == 1 {
			return requirements.items[0]
		}
		return ""
	}

	if site.ResultUse == "discarded" {
		return "any"
	}
	if requirement := cfgCallReturnRequirementOnSuccessfulEdge(
		fn,
		callee,
		site,
		callerRequirement,
	); requirement != "" {
		return requirement
	}
	namedSite, ok := namedCallSiteForClangSite(
		body,
		calleeName,
		site,
	)
	if !ok {
		return ""
	}
	if expression, returned := enclosingReturnExpression(body, namedSite); returned {
		call := compactExpression(body[namedSite.start:namedSite.end])
		if stripSimpleCasts(compactExpression(expression)) != call {
			return ""
		}
		requirement := callerRequirement
		if requirement == "" {
			requirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if requirementsCompatibleAcrossFunctions(
			fn,
			callee,
			requirement,
		) {
			return requirement
		}
		return ""
	}

	target := assignedCallTarget(body, namedSite.start)
	operand := target
	if operand == "" && site.ResultUse == "condition" {
		operand = compactExpression(body[namedSite.start:namedSite.end])
	}
	if operand == "" {
		return ""
	}
	statementEnd := findNextTopLevelSemicolon(body, namedSite.end)
	guardStart := namedSite.end
	if statementEnd >= 0 {
		guardStart = statementEnd + 1
	}
	guardStart = skipSpace(body, guardStart)
	if guardStart >= len(body) ||
		!hasKeywordPrefix(body[guardStart:], "if") {
		if detail, found := enclosingIfCondition(
			body,
			namedSite.start,
		); found {
			return survivingConditionRequirement(
				fn,
				callee,
				body,
				detail,
				operand,
				callerRequirement,
			)
		}
		return ""
	}
	detail, ok := parseIfDetail(body, guardStart)
	if !ok {
		return ""
	}
	return survivingConditionRequirement(
		fn,
		callee,
		body,
		detail,
		operand,
		callerRequirement,
	)
}

func cfgCallReturnRequirementOnSuccessfulEdge(
	fn, callee *FunctionInfo,
	site *ClangCallSite,
	callerRequirement string,
) string {
	if fn == nil || callee == nil || site == nil ||
		!site.Direct || !site.HasBlock {
		return ""
	}
	defaultRequirement := defaultSuccessRequirement(fn.ReturnType)
	if callerRequirement != "" &&
		callerRequirement != defaultRequirement {
		return ""
	}
	block, ok := cfgBlockByID(fn, site.BlockID)
	if !ok {
		return ""
	}
	resultVariable, ok := exactCFGCallResultVariable(
		fn,
		callee,
		block,
		site,
	)
	if !ok || block.TerminatorCondition == "" ||
		!expressionReferencesIdentifier(
			block.TerminatorCondition,
			resultVariable,
		) ||
		len(block.SuccessSuccessors) == 0 ||
		len(block.SuccessSuccessors) !=
			len(block.SuccessSuccessorBranches) {
		return ""
	}
	var requiredBranch bool
	branchKnown := false
	for index, branch := range block.SuccessSuccessorBranches {
		if cfgSuccessEdgeProvenReturnIncompatible(
			fn,
			block,
			block.SuccessSuccessors[index],
			defaultRequirement,
		) {
			continue
		}
		var value bool
		switch branch {
		case "true":
			value = true
		case "false":
			value = false
		default:
			return ""
		}
		if branchKnown && value != requiredBranch {
			return ""
		}
		requiredBranch = value
		branchKnown = true
	}
	if !branchKnown {
		return ""
	}
	requirement := outcomeRequirementFromCondition(
		callee.ReturnType,
		block.TerminatorCondition,
		resultVariable,
		requiredBranch,
	)
	if requirement != "" {
		return requirement
	}
	if isX86PKeyMinusOneSentinelAllocator(callee) &&
		conditionExcludesSignedIntegerSentinel(
			block.TerminatorCondition,
			resultVariable,
			requiredBranch,
			-1,
		) {
		return "nonnegative"
	}
	return ""
}

func cfgSuccessEdgeProvenReturnIncompatible(
	fn *FunctionInfo,
	source ClangCFGBlock,
	successor int,
	requirement string,
) bool {
	if fn == nil || requirement == "" ||
		successor == fn.CFGExit {
		return false
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	if _, ok := blocks[successor]; !ok {
		return false
	}
	initial := applyCFGValueWritesToAlternatives(
		fn,
		source,
		nonEnforcingLSMAlternatives(),
	)
	if len(initial) != 1 {
		return false
	}
	type returnFeasibilityState struct {
		blockID int
		values  map[string]cfgPathValue
	}
	queue := []returnFeasibilityState{{
		blockID: successor,
		values:  cloneCFGPathValues(initial[0].bypassValues),
	}}
	seen := make(map[string]bool)
	sawIncompatibleReturn := false
	const maxReturnFeasibilityStates = 512
	processed := 0
	for len(queue) > 0 {
		if processed >= maxReturnFeasibilityStates {
			return false
		}
		processed++
		state := queue[0]
		queue = queue[1:]
		block, ok := blocks[state.blockID]
		if !ok {
			return false
		}
		valueState := applyCFGValueWritesToAlternatives(
			fn,
			block,
			[]lsmPathAlternative{{
				bypassValues: state.values,
			}},
		)
		if len(valueState) != 1 {
			return false
		}
		state.values = valueState[0].bypassValues
		stateKey := fmt.Sprintf(
			"%d\x00%s",
			state.blockID,
			cfgPathValuesKey(state.values),
		)
		if seen[stateKey] {
			continue
		}
		seen[stateKey] = true
		if block.PotentialSuccessExit {
			expression := resolvedCFGConstantReturnExpression(
				strings.TrimSpace(
					clangCFGReturnExpression(block),
				),
				state.values,
			)
			outcome := returnOutcomeFromExpression(
				fn,
				expression,
				nil,
				false,
				nil,
				requirement,
			)
			if returnOutcomeCompatibility(
				outcome,
				requirement,
			) != "impossible" {
				return false
			}
			sawIncompatibleReturn = true
			continue
		}
		edges := successSuccessorEdgesForConstants(block, nil)
		if len(edges) == 0 {
			return false
		}
		for _, edge := range edges {
			if edge.blockID == fn.CFGExit {
				return false
			}
			if _, ok := blocks[edge.blockID]; !ok {
				return false
			}
			next := returnFeasibilityState{
				blockID: edge.blockID,
				values:  cloneCFGPathValues(state.values),
			}
			queue = append(queue, next)
		}
	}
	return sawIncompatibleReturn
}

func exactCFGCallResultVariable(
	fn, callee *FunctionInfo,
	block ClangCFGBlock,
	site *ClangCallSite,
) (string, bool) {
	if fn == nil || callee == nil || site == nil ||
		!site.Direct || site.ID == "" {
		return "", false
	}
	if site.ResultVariable != "" {
		matchingWrites := 0
		for _, write := range block.ValueWrites {
			if write.Target != site.ResultVariable {
				continue
			}
			matchingWrites++
			if write.CallSiteID != site.ID {
				return "", false
			}
		}
		return site.ResultVariable, matchingWrites == 1
	}
	if returnDomainForType(site.ReturnType) != returnDomainPointer ||
		returnDomainForType(callee.ReturnType) != returnDomainPointer ||
		countString(block.CallSiteIDs, site.ID) != 1 {
		return "", false
	}
	matchingSites := 0
	for index := range fn.CallSites {
		candidate := &fn.CallSites[index]
		if !candidate.Direct || !candidate.Reachable ||
			!candidate.HasBlock || candidate.BlockID != block.ID ||
			candidate.Name != site.Name ||
			!sameCallArguments(candidate.Arguments, site.Arguments) {
			continue
		}
		matchingSites++
		if candidate.ID != site.ID {
			return "", false
		}
	}
	if matchingSites != 1 {
		return "", false
	}
	resultVariable := ""
	for _, write := range block.ValueWrites {
		if !regexp.MustCompile(
			`^[A-Za-z_][A-Za-z0-9_]*$`,
		).MatchString(strings.TrimSpace(write.Target)) ||
			!valuePreservingAssignmentMatchesCall(
				write.Expression,
				write.Target,
				site,
			) {
			continue
		}
		if write.CallSiteID != "" && write.CallSiteID != site.ID {
			return "", false
		}
		if resultVariable != "" {
			return "", false
		}
		resultVariable = strings.TrimSpace(write.Target)
	}
	if resultVariable == "" {
		return "", false
	}
	matchingWrites := 0
	for _, write := range block.ValueWrites {
		if strings.TrimSpace(write.Target) == resultVariable {
			matchingWrites++
		}
	}
	return resultVariable, matchingWrites == 1
}

func valuePreservingAssignmentMatchesCall(
	expression string,
	resultVariable string,
	site *ClangCallSite,
) bool {
	if site == nil || !site.Direct || site.Name == "" ||
		resultVariable == "" {
		return false
	}
	terminal, ok := nestedPointerAssignmentResult(
		expression,
		resultVariable,
	)
	if !ok || strings.HasPrefix(terminal, "(") {
		return false
	}
	callee, arguments, direct := directReturnedCall(terminal)
	return direct && callee == site.Name &&
		sameCallArguments(arguments, site.Arguments)
}

func nestedPointerAssignmentResult(
	expression, resultVariable string,
) (string, bool) {
	expression = compactExpression(expression)
	resultVariable = strings.TrimSpace(resultVariable)
	if expression == "" || !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(resultVariable) {
		return "", false
	}
	foundAssignment := false
	for depth := 0; depth < 8; depth++ {
		assignment, found := topLevelSimpleAssignmentIndex(expression)
		if !found {
			return expression, foundAssignment
		}
		target := compactExpression(expression[:assignment])
		if !isSimpleAssignmentTarget(target) {
			return "", false
		}
		if !foundAssignment && !regexp.MustCompile(
			`^`+regexp.QuoteMeta(resultVariable)+
				`->[A-Za-z_][A-Za-z0-9_]*`+
				`(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*$`,
		).MatchString(target) {
			return "", false
		}
		foundAssignment = true
		expression = compactExpression(expression[assignment+1:])
		if expression == "" {
			return "", false
		}
	}
	if _, found := topLevelSimpleAssignmentIndex(expression); found {
		return "", false
	}
	return expression, foundAssignment
}

func topLevelSimpleAssignmentIndex(
	expression string,
) (int, bool) {
	masked := maskStringAndCharLiterals(expression)
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '=':
			if parenDepth != 0 || bracketDepth != 0 ||
				braceDepth != 0 {
				continue
			}
			var previous byte
			if index > 0 {
				previous = masked[index-1]
			}
			var next byte
			if index+1 < len(masked) {
				next = masked[index+1]
			}
			if next == '=' ||
				strings.ContainsRune("=!<>+-*/%&|^", rune(previous)) {
				continue
			}
			return index, true
		}
	}
	return -1, false
}

func isSimpleAssignmentTarget(expression string) bool {
	expression = compactExpression(expression)
	return regexp.MustCompile(
		`^(?:\*+)?[A-Za-z_][A-Za-z0-9_]*` +
			`(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*$`,
	).MatchString(expression)
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func conditionExcludesSignedIntegerSentinel(
	condition, operand string,
	required bool,
	sentinel int64,
) bool {
	condition = normalizedBranchExpression(condition)
	operand = compactExpression(operand)
	comparison := regexp.MustCompile(
		`^(.+?)(==|!=)(.+)$`,
	).FindStringSubmatch(compactExpression(condition))
	if len(comparison) != 4 {
		return false
	}
	left, operator, right := comparison[1], comparison[2], comparison[3]
	if right == operand {
		left, right = right, left
	}
	if left != operand {
		return false
	}
	value, known := signedIntegerConstant(right)
	if !known || value != sentinel {
		return false
	}
	return operator == "==" && !required ||
		operator == "!=" && required
}

func namedCallSiteForClangSite(
	body, callee string,
	metadata *ClangCallSite,
) (namedCallSite, bool) {
	sites := findNamedCallSites(body, callee)
	if len(sites) == 1 {
		return sites[0], true
	}
	matches := make([]namedCallSite, 0, 1)
	for _, site := range sites {
		arguments, ok := callSiteArguments(body, site)
		if !ok || !sameCallArguments(arguments, metadata.Arguments) {
			continue
		}
		matches = append(matches, site)
	}
	if len(matches) != 1 {
		return namedCallSite{}, false
	}
	return matches[0], true
}

func requiredIndirectCallReturnForSite(
	fn, callee *FunctionInfo,
	body string,
	site *ClangCallSite,
	callerRequirement string,
) string {
	if fn == nil || callee == nil || site == nil || site.Direct {
		return ""
	}
	if site.ResultUse == "discarded" {
		return "any"
	}
	sites := findExpressionCallSites(body, site.Expression)
	matches := make([]namedCallSite, 0, 1)
	for _, candidate := range sites {
		arguments, ok := callSiteArguments(body, candidate)
		if !ok || !sameCallArguments(arguments, site.Arguments) {
			continue
		}
		matches = append(matches, candidate)
	}
	if len(matches) != 1 {
		return ""
	}
	sourceSite := matches[0]
	if expression, returned := enclosingReturnExpression(
		body,
		sourceSite,
	); returned {
		call := compactExpression(
			body[sourceSite.start:sourceSite.end],
		)
		if stripSimpleCasts(compactExpression(expression)) != call {
			return ""
		}
		requirement := callerRequirement
		if requirement == "" {
			requirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if requirementsCompatibleAcrossFunctions(
			fn,
			callee,
			requirement,
		) {
			return requirement
		}
		return ""
	}
	target := assignedCallTarget(body, sourceSite.start)
	operand := target
	if operand == "" && site.ResultUse == "condition" {
		operand = compactExpression(
			body[sourceSite.start:sourceSite.end],
		)
	}
	if operand == "" {
		return ""
	}
	statementEnd := findNextTopLevelSemicolon(body, sourceSite.end)
	guardStart := sourceSite.end
	if statementEnd >= 0 {
		guardStart = statementEnd + 1
	}
	guardStart = skipSpace(body, guardStart)
	if guardStart < len(body) &&
		hasKeywordPrefix(body[guardStart:], "if") {
		if detail, ok := parseIfDetail(body, guardStart); ok {
			return survivingConditionRequirement(
				fn,
				callee,
				body,
				detail,
				operand,
				callerRequirement,
			)
		}
	}
	if detail, ok := enclosingIfCondition(
		body,
		sourceSite.start,
	); ok {
		return survivingConditionRequirement(
			fn,
			callee,
			body,
			detail,
			operand,
			callerRequirement,
		)
	}
	return ""
}

func requirementsCompatibleAcrossReturnTypes(
	parentType, childType, requirement string,
) bool {
	parentDomain := returnDomainForType(parentType)
	childDomain := returnDomainForType(childType)
	if parentDomain == returnDomainUnknown ||
		childDomain == returnDomainUnknown {
		return false
	}
	if parentDomain == childDomain {
		_, ok := requirementMask(childDomain, requirement)
		return ok
	}
	return false
}

func requirementsCompatibleAcrossFunctions(
	parent, child *FunctionInfo,
	requirement string,
) bool {
	if parent == nil || child == nil {
		return false
	}
	parentDomain := returnDomainForType(parent.ReturnType)
	childDomain := returnDomainForType(child.ReturnType)
	if parentDomain == childDomain &&
		parent.ReturnTypeBits > 0 &&
		child.ReturnTypeBits > 0 {
		switch parentDomain {
		case returnDomainSigned:
			if parent.ReturnTypeBits >= child.ReturnTypeBits {
				_, ok := requirementMask(childDomain, requirement)
				return ok
			}
			return requirement == "zero"
		case returnDomainUnsigned:
			if requirement == "any" || requirement == "returned" ||
				requirement == "zero" {
				return true
			}
			if parent.ReturnTypeBits >= child.ReturnTypeBits {
				_, ok := requirementMask(childDomain, requirement)
				return ok
			}
			return false
		case returnDomainPointer:
			return parent.ReturnTypeBits == child.ReturnTypeBits &&
				requirementsCompatibleAcrossReturnTypes(
					parent.ReturnType,
					child.ReturnType,
					requirement,
				)
		case returnDomainBool, returnDomainVoid:
			return requirementsCompatibleAcrossReturnTypes(
				parent.ReturnType,
				child.ReturnType,
				requirement,
			)
		}
	}
	if requirementsCompatibleAcrossReturnTypes(
		parent.ReturnType,
		child.ReturnType,
		requirement,
	) {
		return true
	}
	if parentDomain != returnDomainSigned ||
		childDomain != returnDomainUnsigned ||
		parent.ReturnTypeBits <= 0 ||
		child.ReturnTypeBits <= 0 ||
		parent.ReturnTypeBits <= child.ReturnTypeBits {
		return false
	}
	switch requirement {
	case "any", "returned", "zero", "positive", "nonnegative",
		"nonzero":
		_, ok := requirementMask(childDomain, requirement)
		return ok
	default:
		return false
	}
}

func survivingConditionRequirement(
	fn, callee *FunctionInfo,
	body string,
	detail ifDetail,
	operand, callerRequirement string,
) string {
	parentRequirement := callerRequirement
	if parentRequirement == "" {
		parentRequirement = defaultSuccessRequirement(fn.ReturnType)
	}
	trueFailure := branchDefinitelyFailsRequirement(
		fn,
		callee,
		body,
		detail.bodyText,
		detail.condText,
		operand,
		true,
		parentRequirement,
	)
	falseFailure := detail.hasElse && branchDefinitelyFailsRequirement(
		fn,
		callee,
		body,
		detail.elseText,
		detail.condText,
		operand,
		false,
		parentRequirement,
	)
	switch {
	case trueFailure && !falseFailure:
		return outcomeRequirementFromCondition(
			callee.ReturnType,
			detail.condText,
			operand,
			false,
		)
	case falseFailure && !trueFailure:
		return outcomeRequirementFromCondition(
			callee.ReturnType,
			detail.condText,
			operand,
			true,
		)
	default:
		return ""
	}
}

func branchDefinitelyFailsRequirement(
	fn, callee *FunctionInfo,
	fullBody, branch, condition, operand string,
	conditionTruth bool,
	parentRequirement string,
) bool {
	if !branchTerminates(branch) {
		return false
	}
	returns := regexp.MustCompile(
		`\breturn\s+([^;]+);`,
	).FindAllStringSubmatch(branch, -1)
	gotos := regexp.MustCompile(
		`\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;`,
	).FindAllStringSubmatch(branch, -1)
	if len(returns) == 0 && len(gotos) == 0 {
		return false
	}
	conditionRequirement := outcomeRequirementFromCondition(
		callee.ReturnType,
		condition,
		operand,
		conditionTruth,
	)
	childMask, childMaskKnown := requirementMask(
		returnDomainForType(callee.ReturnType),
		conditionRequirement,
	)
	if childMaskKnown {
		constrained := constrainReturnOutcomeByLLVMFunctionFacts(
			callee,
			returnOutcome{
				domain: returnDomainForType(callee.ReturnType),
				mask:   childMask,
			},
		)
		childMask = constrained.mask
	}
	if childMaskKnown && childMask == 0 {
		return true
	}
	for _, match := range returns {
		if !returnExpressionDefinitelyFailsRequirement(
			fn,
			callee,
			strings.TrimSpace(match[1]),
			operand,
			childMask,
			childMaskKnown,
			parentRequirement,
		) {
			return false
		}
	}
	for _, match := range gotos {
		expression, ok := terminalGotoReturnExpression(
			fullBody,
			match[1],
		)
		if !ok || !returnExpressionDefinitelyFailsRequirement(
			fn,
			callee,
			expression,
			operand,
			childMask,
			childMaskKnown,
			parentRequirement,
		) {
			return false
		}
	}
	return true
}

func returnExpressionDefinitelyFailsRequirement(
	fn, callee *FunctionInfo,
	expression, operand string,
	childMask uint16,
	childMaskKnown bool,
	parentRequirement string,
) bool {
	expression = stripSimpleCasts(compactExpression(expression))
	var outcome returnOutcome
	if expression == compactExpression(operand) &&
		childMaskKnown &&
		returnDomainForType(fn.ReturnType) ==
			returnDomainForType(callee.ReturnType) {
		outcome = returnOutcome{
			domain: returnDomainForType(callee.ReturnType),
			mask:   childMask,
		}
	} else if argument, ok := singleCallArgument(
		expression,
		"PTR_ERR",
	); ok &&
		compactExpression(argument) == compactExpression(operand) &&
		childMaskKnown &&
		returnDomainForType(callee.ReturnType) ==
			returnDomainPointer &&
		childMask&^outcomePointerError == 0 {
		outcome = returnOutcome{
			domain: returnDomainSigned,
			mask:   outcomeNegative,
		}
	} else {
		outcome = returnOutcomeFromExpression(
			fn,
			expression,
			nil,
			false,
			nil,
			parentRequirement,
		)
	}
	return returnOutcomeCompatibility(outcome, parentRequirement) ==
		"impossible"
}

func terminalGotoReturnExpression(
	body, label string,
) (string, bool) {
	labelPattern := regexp.MustCompile(
		`(?m)^\s*` + regexp.QuoteMeta(label) + `\s*:\s*`,
	)
	location := labelPattern.FindStringIndex(body)
	if location == nil {
		return "", false
	}
	suffix := body[location[1]:]
	nextLabel := regexp.MustCompile(
		`(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*`,
	).FindStringIndex(suffix)
	if nextLabel != nil {
		suffix = suffix[:nextLabel[0]]
	}
	returns := regexp.MustCompile(
		`\breturn\s+([^;]+);`,
	).FindAllStringSubmatch(suffix, -1)
	if len(returns) != 1 {
		return "", false
	}
	return strings.TrimSpace(returns[0][1]), true
}

func assignedCallTarget(body string, callStart int) string {
	prefixStart := max(0, callStart-256)
	prefix := body[prefixStart:callStart]
	match := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*$`).FindStringSubmatch(prefix)
	if len(match) != 2 {
		return ""
	}
	return strings.Join(strings.Fields(match[1]), "")
}

func callSiteRequiresNonNull(body string, site namedCallSite, target, callerRequirement string) bool {
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return false
	}
	guardStart := skipSpace(body, statementEnd+1)
	if guardStart >= len(body) || !hasKeywordPrefix(body[guardStart:], "if") {
		return false
	}
	detail, ok := parseIfDetail(body, guardStart)
	if !ok {
		return false
	}
	condition := normalizeCondition(detail.condText)
	if conditionIndicatesFalsyExpression(condition, target) && branchFailsRequiredReturn(detail.bodyText, target, callerRequirement) {
		return true
	}
	if conditionIndicatesTruthyExpression(condition, target) && remainderHasExplicitFailure(body[detail.nextPos:]) {
		return true
	}
	return false
}

func branchFailsRequiredReturn(body, target, callerRequirement string) bool {
	if !branchTerminates(body) {
		return false
	}
	returns := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
	if len(returns) == 0 {
		return false
	}
	for _, match := range returns {
		expression := normalizeCondition(strings.TrimSpace(match[1]))
		if returnExpressionIsFailure(expression, "", "") {
			continue
		}
		if callerRequirement == "nonnull" && (expression == "NULL" || expression == "0" || expression == target) {
			continue
		}
		return false
	}
	return true
}

func remainderHasExplicitFailure(remainder string) bool {
	match := regexp.MustCompile(`(?s)\breturn\s+([^;]+);\s*$`).FindStringSubmatch(strings.TrimSpace(remainder))
	return len(match) == 2 && returnExpressionIsFailure(strings.TrimSpace(match[1]), "", "")
}

func constantExpression(expression string) (string, bool) {
	expression = normalizeCondition(strings.TrimSpace(expression))
	switch expression {
	case "true", "false", "NULL", "current", "get_current()",
		"current->signal", "current->sighand",
		"get_current()->signal", "get_current()->sighand":
		return expression, true
	}
	if _, err := strconv.ParseInt(expression, 0, 64); err == nil {
		return expression, true
	}
	if _, err := strconv.ParseUint(expression, 0, 64); err == nil {
		return expression, true
	}
	if value, ok := unsignedBitwiseOrConstant(expression); ok {
		return strconv.FormatUint(value, 10), true
	}
	return "", false
}

func unsignedBitwiseOrConstant(expression string) (uint64, bool) {
	expression = compactExpression(expression)
	if expression == "" {
		return 0, false
	}
	depth := 0
	start := 0
	parts := make([]string, 0, 2)
	for index := 0; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return 0, false
			}
			depth--
		case '|':
			if index+1 < len(expression) && expression[index+1] == '|' ||
				index > 0 && expression[index-1] == '|' {
				return 0, false
			}
			if depth != 0 {
				continue
			}
			parts = append(parts, expression[start:index])
			start = index + 1
		}
	}
	if depth != 0 {
		return 0, false
	}
	if len(parts) > 0 {
		parts = append(parts, expression[start:])
		var result uint64
		for _, part := range parts {
			value, ok := unsignedBitwiseOrConstant(part)
			if !ok {
				return 0, false
			}
			result |= value
		}
		return result, true
	}
	literal := strings.TrimRight(strings.TrimSpace(expression), "uUlL")
	if literal == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(literal, 0, 64)
	return value, err == nil
}

func functionContextKey(fn *FunctionInfo, constants map[string]string) string {
	if len(constants) == 0 {
		return fn.ID
	}
	var builder strings.Builder
	builder.WriteString(fn.ID)
	for _, parameter := range fn.Parameters {
		value, ok := constants[parameter]
		if !ok {
			continue
		}
		builder.WriteByte('\x1f')
		builder.WriteString(parameter)
		builder.WriteByte('=')
		builder.WriteString(value)
	}
	if requirement := constants[contextReturnRequirementKey]; requirement != "" {
		builder.WriteByte('\x1f')
		builder.WriteString(contextReturnRequirementKey)
		builder.WriteByte('=')
		builder.WriteString(requirement)
	}
	extraKeys := make([]string, 0, len(constants))
	for key := range constants {
		if key == contextReturnRequirementKey || containsString(fn.Parameters, key) {
			continue
		}
		extraKeys = append(extraKeys, key)
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		builder.WriteByte('\x1f')
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(constants[key])
	}
	return builder.String()
}

func substituteIdentifierConstants(body string, constants map[string]string) string {
	if len(constants) == 0 {
		return body
	}
	memberKeys := make([]string, 0, len(constants))
	for key := range constants {
		if strings.Contains(key, "->") {
			memberKeys = append(memberKeys, key)
		}
	}
	sort.Strings(memberKeys)
	for _, key := range memberKeys {
		parts := strings.Split(key, "->")
		if len(parts) != 2 {
			continue
		}
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(parts[0]) + `\s*->\s*` + regexp.QuoteMeta(parts[1]) + `\b`)
		body = pattern.ReplaceAllString(body, "("+constants[key]+")")
	}
	masked := maskStringAndCharLiterals(body)
	var builder strings.Builder
	builder.Grow(len(body))
	last := 0
	for index := 0; index < len(masked); {
		if !isIdentStart(masked[index]) {
			index++
			continue
		}
		end := index + 1
		for end < len(masked) && isIdentChar(masked[end]) {
			end++
		}
		identifier := masked[index:end]
		value, ok := constants[identifier]
		if ok && !isMemberIdentifier(masked, index) {
			builder.WriteString(body[last:index])
			builder.WriteString(value)
			last = end
		}
		index = end
	}
	builder.WriteString(body[last:])
	return builder.String()
}

func isIdentStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isMemberIdentifier(body string, start int) bool {
	previous := start - 1
	for previous >= 0 && unicode.IsSpace(rune(body[previous])) {
		previous--
	}
	return previous >= 0 && (body[previous] == '.' || body[previous] == '>')
}

type localErrorEffect struct {
	blocksOperation   string
	terminatesSyscall string
	errnoPropagation  string
	failureEncoding   string
	overwriteSites    []string
}

type returnOutcome struct {
	domain string
	mask   uint16
}

const (
	returnDomainUnknown  = ""
	returnDomainSigned   = "signed_integer"
	returnDomainUnsigned = "unsigned_integer"
	returnDomainPointer  = "pointer"
	returnDomainBool     = "bool"
	returnDomainRecord   = "record"
	returnDomainVoid     = "void"
)

const (
	outcomeNegative uint16 = 1 << iota
	outcomeZero
	outcomePositive
	outcomePointerNull
	outcomePointerValue
	outcomePointerError
	outcomeBoolFalse
	outcomeBoolTrue
	outcomeVoidReturn
)

type effectSourceState uint8

const (
	effectSourceUnknown effectSourceState = iota
	effectSourceNone
	effectSourcePossible
)

const (
	lsmPathNonEnforcing uint8 = 1 << iota
	lsmPathUnresolved
	lsmPathEnforcing
)

type lsmCoverageResult struct {
	state              string
	hooks              []string
	alternatives       []lsmPathAlternative
	proofMethods       []string
	proofFunctions     []string
	hookProofPaths     map[string][]string
	bypassProofPath    []string
	bypassProofMethod  string
	unprovenBypassPath []string
	reasons            []string
	unresolved         []UnresolvedProofEdge
	coveredUnresolved  []UnresolvedProofEdge
}

type lsmCoverageEvent struct {
	states         uint8
	hooks          []string
	alternatives   []lsmPathAlternative
	proofFunctions []string
	hookProofPaths map[string][]string
	reasons        []string
	unresolved     []UnresolvedProofEdge
}

type lsmPathAlternative struct {
	hooks                 []string
	unresolved            bool
	returnOutcome         returnOutcome
	bypassPath            []string
	bypassSuccessProven   bool
	bypassSuccessMethod   string
	bypassConstraints     []successPathConstraint
	bypassValues          map[string]cfgPathValue
	bypassCyclic          bool
	bypassDerivedEffect   bool
	bypassSuccessfulCalls []successfulCallConstraint
}

type functionSuccessWitness struct {
	proven bool
	method string
	path   []string
}

type successPathConstraint struct {
	functionID string
	blockID    int
	expression string
	required   bool
	pathStable bool
}

type cfgPathValue struct {
	expression         string
	callSiteID         string
	lineage            []cfgPathCallStep
	typeClass          string
	typeSigned         bool
	typeBits           int
	provenNonnegative  bool
	provenValidPointer bool
	runtimeZeroSuccess bool
	runtimeSuccessKind string
	outParameter       bool
	outParameterIndex  int
}

type cfgPathCallStep struct {
	expression     string
	callSiteID     string
	sourceArgument int
}

type successfulCallConstraint struct {
	functionID             string
	callSiteID             string
	callee                 string
	resultVariable         string
	returnType             string
	requirement            string
	callerRequirement      string
	provenCalleeSuccess    bool
	certifiesCallerSuccess bool
	method                 string
}

func nonEnforcingLSMAlternatives(path ...string) []lsmPathAlternative {
	return []lsmPathAlternative{{bypassPath: uniqueStrings(path)}}
}

func provenNonEnforcingLSMAlternatives(
	witness functionSuccessWitness,
	path ...string,
) []lsmPathAlternative {
	return []lsmPathAlternative{{
		bypassPath:          uniqueStrings(append(path, witness.path...)),
		bypassSuccessProven: witness.proven,
		bypassSuccessMethod: witness.method,
	}}
}

func unresolvedLSMAlternatives() []lsmPathAlternative {
	return []lsmPathAlternative{{unresolved: true}}
}

func enforcingLSMAlternatives(hooks ...string) []lsmPathAlternative {
	return []lsmPathAlternative{{hooks: uniqueStrings(hooks)}}
}

func eventLSMAlternatives(event lsmCoverageEvent) []lsmPathAlternative {
	if len(event.alternatives) > 0 {
		return cloneLSMAlternatives(event.alternatives)
	}
	result := make([]lsmPathAlternative, 0, 3)
	if event.states&lsmPathNonEnforcing != 0 {
		result = append(result, lsmPathAlternative{})
	}
	if event.states&lsmPathUnresolved != 0 {
		result = append(result, lsmPathAlternative{unresolved: true})
	}
	if event.states&lsmPathEnforcing != 0 {
		result = append(result, lsmPathAlternative{hooks: uniqueStrings(event.hooks)})
	}
	return canonicalLSMAlternatives(result)
}

func cloneLSMAlternatives(values []lsmPathAlternative) []lsmPathAlternative {
	result := make([]lsmPathAlternative, 0, len(values))
	for _, value := range values {
		value.hooks = append([]string(nil), value.hooks...)
		value.bypassPath = append([]string(nil), value.bypassPath...)
		value.bypassConstraints = append(
			[]successPathConstraint(nil),
			value.bypassConstraints...,
		)
		value.bypassValues = cloneCFGPathValues(value.bypassValues)
		value.bypassSuccessfulCalls = append(
			[]successfulCallConstraint(nil),
			value.bypassSuccessfulCalls...,
		)
		result = append(result, value)
	}
	return result
}

func cloneCFGPathValues(
	values map[string]cfgPathValue,
) map[string]cfgPathValue {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]cfgPathValue, len(values))
	for name, value := range values {
		value.lineage = append([]cfgPathCallStep(nil), value.lineage...)
		result[name] = value
	}
	return result
}

func mergeCFGPathValues(
	left, right map[string]cfgPathValue,
) map[string]cfgPathValue {
	if len(left) == 0 {
		return cloneCFGPathValues(right)
	}
	if len(right) == 0 {
		return cloneCFGPathValues(left)
	}
	result := cloneCFGPathValues(left)
	for name, value := range right {
		if existing, ok := result[name]; ok &&
			!cfgPathValueEqual(existing, value) {
			delete(result, name)
			continue
		}
		value.lineage = append([]cfgPathCallStep(nil), value.lineage...)
		result[name] = value
	}
	return result
}

func cfgPathValueEqual(left, right cfgPathValue) bool {
	if left.expression != right.expression ||
		left.callSiteID != right.callSiteID ||
		left.typeClass != right.typeClass ||
		left.typeSigned != right.typeSigned ||
		left.typeBits != right.typeBits ||
		left.provenNonnegative != right.provenNonnegative ||
		left.provenValidPointer != right.provenValidPointer ||
		left.runtimeZeroSuccess != right.runtimeZeroSuccess ||
		left.runtimeSuccessKind != right.runtimeSuccessKind ||
		left.outParameter != right.outParameter ||
		left.outParameterIndex != right.outParameterIndex ||
		len(left.lineage) != len(right.lineage) {
		return false
	}
	for index := range left.lineage {
		if left.lineage[index] != right.lineage[index] {
			return false
		}
	}
	return true
}

func cfgPathValuesKey(values map[string]cfgPathValue) string {
	if len(values) == 0 {
		return ""
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		value := values[name]
		lineage := make([]string, 0, len(value.lineage))
		for _, step := range value.lineage {
			lineage = append(lineage, strings.Join(
				[]string{
					compactExpression(step.expression),
					step.callSiteID,
					strconv.Itoa(step.sourceArgument),
				},
				"\x1d",
			))
		}
		parts = append(parts, strings.Join(
			[]string{
				name,
				compactExpression(value.expression),
				value.callSiteID,
				value.typeClass,
				strconv.FormatBool(value.typeSigned),
				strconv.Itoa(value.typeBits),
				strconv.FormatBool(value.provenNonnegative),
				strconv.FormatBool(value.provenValidPointer),
				strconv.FormatBool(value.runtimeZeroSuccess),
				value.runtimeSuccessKind,
				strconv.FormatBool(value.outParameter),
				strconv.Itoa(value.outParameterIndex),
				strings.Join(lineage, "\x1c"),
			},
			"\x1e",
		))
	}
	return strings.Join(parts, "\x1f")
}

func sequenceLSMAlternatives(
	paths, event []lsmPathAlternative,
) []lsmPathAlternative {
	if len(paths) == 0 || len(event) == 0 {
		return nil
	}
	result := make([]lsmPathAlternative, 0, len(paths)*len(event))
	for _, path := range paths {
		for _, item := range event {
			hooks := uniqueStrings(append(
				append([]string(nil), path.hooks...),
				item.hooks...,
			))
			unresolved := path.unresolved || item.unresolved
			if len(hooks) > 0 {
				unresolved = false
			}
			bypassPath := uniqueStrings(append(
				append([]string(nil), path.bypassPath...),
				item.bypassPath...,
			))
			bypassConstraints := canonicalSuccessPathConstraints(append(
				append(
					[]successPathConstraint(nil),
					path.bypassConstraints...,
				),
				item.bypassConstraints...,
			))
			bypassCyclic := path.bypassCyclic || item.bypassCyclic
			bypassValues := mergeCFGPathValues(
				path.bypassValues,
				item.bypassValues,
			)
			bypassDerivedEffect := path.bypassDerivedEffect ||
				item.bypassDerivedEffect
			bypassSuccessfulCalls := canonicalSuccessfulCallConstraints(
				append(
					append(
						[]successfulCallConstraint(nil),
						path.bypassSuccessfulCalls...,
					),
					item.bypassSuccessfulCalls...,
				),
			)
			if len(hooks) > 0 || unresolved {
				bypassPath = nil
				bypassDerivedEffect = false
			}
			result = append(result, lsmPathAlternative{
				hooks:                 hooks,
				unresolved:            unresolved,
				returnOutcome:         returnOutcome{},
				bypassPath:            bypassPath,
				bypassSuccessProven:   false,
				bypassSuccessMethod:   "",
				bypassConstraints:     bypassConstraints,
				bypassValues:          bypassValues,
				bypassCyclic:          bypassCyclic,
				bypassDerivedEffect:   bypassDerivedEffect,
				bypassSuccessfulCalls: bypassSuccessfulCalls,
			})
		}
	}
	return canonicalLSMAlternatives(result)
}

func mergeLSMAlternatives(
	left, right []lsmPathAlternative,
) []lsmPathAlternative {
	return canonicalLSMAlternatives(append(
		cloneLSMAlternatives(left),
		cloneLSMAlternatives(right)...,
	))
}

type keyedLSMAlternative struct {
	value             lsmPathAlternative
	pathConstraintKey string
	callConstraintKey string
	pathValuesKey     string
	outcomeKey        string
	dominanceGroupKey string
	deduplicationKey  string
	sortKey           string
}

func keyLSMAlternative(
	value lsmPathAlternative,
) keyedLSMAlternative {
	pathConstraintKey := canonicalSuccessPathConstraintKey(
		value.bypassConstraints,
		value.bypassCyclic,
	)
	callConstraintKey := canonicalSuccessfulCallConstraintKey(
		value.bypassSuccessfulCalls,
	)
	pathValuesKey := cfgPathValuesKey(value.bypassValues)
	outcomeKey := returnOutcomeKey(value.returnOutcome)
	derivedKey := pathConstraintKey
	if value.bypassDerivedEffect {
		derivedKey += "\x1fderived-effect"
	}
	return keyedLSMAlternative{
		value:             value,
		pathConstraintKey: pathConstraintKey,
		callConstraintKey: callConstraintKey,
		pathValuesKey:     pathValuesKey,
		outcomeKey:        outcomeKey,
		dominanceGroupKey: strings.Join([]string{
			strconv.FormatBool(value.unresolved),
			pathConstraintKey,
			callConstraintKey,
			pathValuesKey,
			outcomeKey,
		}, "\x00"),
		deduplicationKey: strings.Join([]string{
			strconv.FormatBool(value.unresolved),
			strings.Join(value.hooks, "\x00"),
			derivedKey,
			callConstraintKey,
			pathValuesKey,
			outcomeKey,
		}, "\x00"),
	}
}

func keyedLSMAlternativeSortKey(
	value keyedLSMAlternative,
) string {
	return strings.Join([]string{
		strconv.FormatBool(value.value.unresolved),
		strconv.FormatBool(value.value.bypassSuccessProven),
		strings.Join(value.value.hooks, ","),
		value.pathConstraintKey +
			strconv.FormatBool(value.value.bypassDerivedEffect),
		value.callConstraintKey,
		value.pathValuesKey,
		value.outcomeKey,
	}, ":")
}

func preferProvenBypassAlternative(
	candidate, current lsmPathAlternative,
) bool {
	if candidate.bypassDerivedEffect != current.bypassDerivedEffect {
		return !candidate.bypassDerivedEffect
	}
	if len(current.bypassPath) == 0 {
		return len(candidate.bypassPath) > 0
	}
	return len(candidate.bypassPath) > 0 &&
		len(candidate.bypassPath) < len(current.bypassPath)
}

func canonicalLSMAlternatives(values []lsmPathAlternative) []lsmPathAlternative {
	normalized := make([]keyedLSMAlternative, 0, len(values))
	seen := make(map[string]int)
	for _, value := range values {
		value.hooks = uniqueStrings(value.hooks)
		sort.Strings(value.hooks)
		if len(value.hooks) > 1 {
			value.hooks = append([]string(nil), value.hooks[:1]...)
		}
		if len(value.hooks) > 0 {
			value.unresolved = false
		}
		if len(value.hooks) > 0 {
			value.bypassPath = nil
			value.bypassSuccessProven = false
			value.bypassSuccessMethod = ""
			value.bypassConstraints = nil
			value.bypassValues = nil
			value.bypassCyclic = false
			value.bypassDerivedEffect = false
			value.bypassSuccessfulCalls = nil
		} else if value.unresolved {
			value.bypassSuccessProven = false
			value.bypassSuccessMethod = ""
			value.bypassDerivedEffect = false
			value.bypassValues = nil
		}
		value.bypassConstraints = canonicalSuccessPathConstraints(
			value.bypassConstraints,
		)
		value.bypassSuccessfulCalls = canonicalSuccessfulCallConstraints(
			value.bypassSuccessfulCalls,
		)
		keyed := keyLSMAlternative(value)
		if existingIndex, ok := seen[keyed.deduplicationKey]; ok {
			if value.bypassSuccessProven &&
				!normalized[existingIndex].value.bypassSuccessProven {
				normalized[existingIndex].value.bypassSuccessProven = true
				normalized[existingIndex].value.bypassSuccessMethod = value.bypassSuccessMethod
				normalized[existingIndex].value.bypassPath = append(
					[]string(nil),
					value.bypassPath...,
				)
			}
			if value.bypassSuccessProven ==
				normalized[existingIndex].value.bypassSuccessProven &&
				len(value.bypassPath) > 0 &&
				(len(normalized[existingIndex].value.bypassPath) == 0 ||
					len(value.bypassPath) <
						len(normalized[existingIndex].value.bypassPath)) {
				normalized[existingIndex].value.bypassPath =
					append([]string(nil), value.bypassPath...)
			}
			continue
		}
		seen[keyed.deduplicationKey] = len(normalized)
		normalized = append(normalized, keyed)
	}

	groups := make(map[string][]int)
	for index, value := range normalized {
		groups[value.dominanceGroupKey] = append(
			groups[value.dominanceGroupKey],
			index,
		)
	}
	keep := make([]bool, len(normalized))
	for _, indexes := range groups {
		dominantBypass := -1
		for _, index := range indexes {
			value := normalized[index].value
			if len(value.hooks) != 0 ||
				!value.bypassSuccessProven {
				continue
			}
			if dominantBypass < 0 ||
				preferProvenBypassAlternative(
					value,
					normalized[dominantBypass].value,
				) {
				dominantBypass = index
			}
		}
		if dominantBypass >= 0 {
			keep[dominantBypass] = true
			continue
		}
		for _, index := range indexes {
			keep[index] = true
		}
	}

	result := make([]keyedLSMAlternative, 0, len(normalized))
	for index, value := range normalized {
		if keep[index] {
			value.sortKey = keyedLSMAlternativeSortKey(value)
			result = append(result, value)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].sortKey < result[right].sortKey
	})
	alternatives := make([]lsmPathAlternative, 0, len(result))
	for _, value := range result {
		alternatives = append(alternatives, value.value)
	}
	return alternatives
}

func lsmAlternativesEqual(left, right []lsmPathAlternative) bool {
	left = canonicalLSMAlternatives(left)
	right = canonicalLSMAlternatives(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].unresolved != right[index].unresolved ||
			returnOutcomeKey(left[index].returnOutcome) !=
				returnOutcomeKey(right[index].returnOutcome) ||
			left[index].bypassSuccessProven != right[index].bypassSuccessProven ||
			left[index].bypassCyclic != right[index].bypassCyclic ||
			left[index].bypassDerivedEffect !=
				right[index].bypassDerivedEffect ||
			successfulCallConstraintKey(
				left[index].bypassSuccessfulCalls,
			) != successfulCallConstraintKey(
				right[index].bypassSuccessfulCalls,
			) ||
			cfgPathValuesKey(left[index].bypassValues) !=
				cfgPathValuesKey(right[index].bypassValues) ||
			successPathConstraintKey(
				left[index].bypassConstraints,
				left[index].bypassCyclic,
			) != successPathConstraintKey(
				right[index].bypassConstraints,
				right[index].bypassCyclic,
			) ||
			!stringSlicesEqual(left[index].hooks, right[index].hooks) {
			return false
		}
	}
	return true
}

func classifyLSMAlternatives(values []lsmPathAlternative) string {
	if len(values) == 0 {
		return "uncertain"
	}
	allEnforcing := true
	for _, value := range values {
		if len(value.hooks) == 0 && !value.unresolved {
			return "non_enforcing"
		}
		if len(value.hooks) == 0 || value.unresolved {
			allEnforcing = false
		}
	}
	if allEnforcing {
		return "enforcing"
	}
	return "uncertain"
}

func allPathAlternativesEnforcing(values []lsmPathAlternative) bool {
	return classifyLSMAlternatives(values) == "enforcing"
}

func classifySuccessExitLSMAlternatives(values []lsmPathAlternative) string {
	if len(values) == 0 {
		return "uncertain"
	}
	allEnforcing := true
	for _, value := range canonicalLSMAlternatives(values) {
		if len(value.hooks) == 0 && !value.unresolved &&
			value.bypassSuccessProven {
			return "non_enforcing"
		}
		if len(value.hooks) == 0 || value.unresolved {
			allEnforcing = false
		}
	}
	if allEnforcing {
		return "enforcing"
	}
	return "uncertain"
}

func lsmAlternativeHookSets(values []lsmPathAlternative) [][]string {
	result := make([][]string, 0, len(values))
	for _, value := range canonicalLSMAlternatives(values) {
		result = append(result, append([]string(nil), value.hooks...))
	}
	return result
}

func firstLSMBypassPath(values []lsmPathAlternative) []string {
	for _, value := range canonicalLSMAlternatives(values) {
		if len(value.hooks) == 0 && !value.unresolved &&
			value.bypassSuccessProven {
			return append([]string(nil), value.bypassPath...)
		}
	}
	return nil
}

func firstLSMBypassMethod(values []lsmPathAlternative) string {
	for _, value := range canonicalLSMAlternatives(values) {
		if len(value.hooks) == 0 && !value.unresolved &&
			value.bypassSuccessProven {
			return value.bypassSuccessMethod
		}
	}
	return ""
}

func firstUnprovenLSMBypassPath(values []lsmPathAlternative) []string {
	for _, value := range canonicalLSMAlternatives(values) {
		if len(value.hooks) == 0 && !value.unresolved &&
			!value.bypassSuccessProven {
			return append([]string(nil), value.bypassPath...)
		}
	}
	return nil
}

func bypassProofPathAtBlock(path []string, function string, blockID int) []string {
	return uniqueStrings(append(
		append([]string(nil), path...),
		fmt.Sprintf("%s#cfg-block-%d", function, blockID),
	))
}

func (a *Analyzer) proveFunctionSuccessfulExecution(
	functionID string,
	constants map[string]string,
	active map[string]bool,
) functionSuccessWitness {
	fn := a.functions[functionID]
	if fn == nil {
		return functionSuccessWitness{}
	}
	cacheKey := functionContextKey(fn, constants)
	if a.successWitnessCache == nil {
		a.successWitnessCache = make(map[string]functionSuccessWitness)
	}
	if cached, ok := a.successWitnessCache[cacheKey]; ok {
		return cached
	}
	if active == nil {
		active = make(map[string]bool)
	}
	if active[cacheKey] {
		return functionSuccessWitness{}
	}
	if fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict || !fn.CFGHasSuccessExit {
		a.successWitnessCache[cacheKey] = functionSuccessWitness{}
		return functionSuccessWitness{}
	}
	if llvmFunctionRequirementImpossible(
		fn,
		constants[contextReturnRequirementKey],
	) {
		a.successWitnessCache[cacheKey] = functionSuccessWitness{}
		return functionSuccessWitness{}
	}
	if method, proven := llvmFunctionSuccessProof(
		fn,
		constants[contextReturnRequirementKey],
	); proven {
		witness := functionSuccessWitness{
			proven: true,
			method: method,
			path: []string{
				fn.DisplayName + "#llvm-function-return-summary",
			},
		}
		a.successWitnessCache[cacheKey] = witness
		return witness
	}
	if witness := sourceDefaultSuccessWitness(
		fn,
		constants[contextReturnRequirementKey],
	); witness.proven {
		a.successWitnessCache[cacheKey] = witness
		return witness
	}
	if witness := kernelRuntimeSuccessContractWitness(
		fn,
		constants[contextReturnRequirementKey],
	); witness.proven {
		a.successWitnessCache[cacheKey] = witness
		return witness
	}

	active[cacheKey] = true
	defer delete(active, cacheKey)
	reachable := successReachableCFGBlocks(fn, constants)
	if witness := a.proveLLVMPreservedChildSuccess(
		fn,
		constants,
		reachable,
		active,
	); witness.proven {
		a.successWitnessCache[cacheKey] = witness
		return witness
	}
	for _, state := range successConstraintPathStates(fn, constants) {
		block, ok := cfgBlockByID(fn, state.blockID)
		if !ok || !block.PotentialSuccessExit {
			continue
		}
		witness := a.proveSuccessfulReturnBlockAlongPathWithValues(
			fn,
			block,
			constants,
			active,
			state.constraints,
			state.cyclic,
			true,
			nil,
			state.values,
		)
		if witness.proven {
			a.successWitnessCache[cacheKey] = witness
			return witness
		}
	}
	a.successWitnessCache[cacheKey] = functionSuccessWitness{}
	return functionSuccessWitness{}
}

func sourceDefaultSuccessWitness(
	fn *FunctionInfo,
	requirement string,
) functionSuccessWitness {
	if fn == nil || fn.FrontendVariantConflict ||
		fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete {
		return functionSuccessWitness{}
	}
	returns := regexp.MustCompile(
		`\breturn\s+([^;]+)\s*;`,
	).FindAllStringSubmatch(fn.Body, -1)
	if len(returns) != 1 {
		return functionSuccessWitness{}
	}
	callee, arguments, ok := directReturnedCall(returns[0][1])
	if !ok || callee != "call_int_hook" || len(arguments) < 2 {
		return functionSuccessWitness{}
	}
	defaultReturn := strings.TrimSpace(arguments[1])
	if !returnExpressionProvesSuccess(
		fn.ReturnType,
		defaultReturn,
		requirement,
	) {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "source_dispatch_default_success",
		path: []string{
			fn.DisplayName + "#call_int_hook-default[" +
				compactExpression(defaultReturn) + "]",
		},
	}
}

func kernelRuntimeSuccessContractWitness(
	fn *FunctionInfo,
	requirement string,
) functionSuccessWitness {
	if fn == nil || fn.FrontendVariantConflict {
		return functionSuccessWitness{}
	}
	if isX86PKeyMinusOneSentinelAllocator(fn) &&
		requirement == "nonnegative" {
		return functionSuccessWitness{
			proven: true,
			method: "kernel_minus_one_sentinel_success_contract",
			path: []string{
				fn.DisplayName + "#runtime-pkey-available",
			},
		}
	}
	if returnDomainForType(fn.ReturnType) != returnDomainPointer {
		return functionSuccessWitness{}
	}
	if !isCoreKernelFallibleAllocator(fn) {
		return functionSuccessWitness{}
	}
	if requirement == "" {
		requirement = "nonnull_valid_pointer"
	}
	requiredMask, ok := requirementMask(
		returnDomainPointer,
		requirement,
	)
	if !ok || requiredMask&outcomePointerValue == 0 {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "kernel_fallible_allocator_success_contract",
		path: []string{
			fn.DisplayName + "#runtime-resource-available",
		},
	}
}

func isX86PKeyMinusOneSentinelAllocator(fn *FunctionInfo) bool {
	if fn == nil || fn.Name != "mm_pkey_alloc" ||
		returnDomainForType(fn.ReturnType) != returnDomainSigned {
		return false
	}
	return strings.HasSuffix(
		filepath.ToSlash(fn.File),
		"/arch/x86/include/asm/pkeys.h",
	)
}

func isCoreKernelFallibleAllocator(fn *FunctionInfo) bool {
	if fn == nil {
		return false
	}
	file := filepath.ToSlash(fn.File)
	if !strings.Contains(file, "/include/linux/slab.h") &&
		!strings.Contains(file, "/include/linux/mm.h") &&
		!strings.Contains(file, "/mm/") {
		return false
	}
	switch fn.Name {
	case "kmalloc", "kzalloc", "kcalloc", "kmalloc_array",
		"krealloc", "kmemdup", "kmemdup_nul",
		"kmalloc_node", "kzalloc_node", "kcalloc_node",
		"kmem_cache_alloc", "kmem_cache_zalloc",
		"vmalloc", "vzalloc", "kvmalloc", "kvzalloc",
		"kvmalloc_array", "kvcalloc", "__kmalloc",
		"__kmalloc_node", "__kmalloc_track_caller",
		"kmem_cache_alloc_trace", "kmem_cache_alloc_node_trace",
		"alloc_pages", "__alloc_pages", "__alloc_pages_node":
		return true
	default:
		return false
	}
}

func kernelRuntimeEffectFreeSuccessContractWitness(
	fn *FunctionInfo,
	requirement string,
	domain string,
) functionSuccessWitness {
	if domain != "lsm" && domain != "sigkill" {
		return functionSuccessWitness{}
	}
	success := kernelRuntimeSuccessContractWitness(fn, requirement)
	if !success.proven {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "kernel_fallible_allocator_effect_free_fast_path_contract",
		path: []string{
			fn.DisplayName + "#runtime-resource-available[" +
				domain + "-effect-free-fast-path]",
		},
	}
}

func (a *Analyzer) proveLLVMPreservedChildSuccess(
	fn *FunctionInfo,
	constants map[string]string,
	reachable map[int]bool,
	active map[string]bool,
) functionSuccessWitness {
	if fn == nil {
		return functionSuccessWitness{}
	}
	callerRequirement := constants[contextReturnRequirementKey]
	if callerRequirement == "" {
		callerRequirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if callerRequirement != "nonnegative" &&
		callerRequirement != "nonnull_valid_pointer" {
		return functionSuccessWitness{}
	}
	body := substituteIdentifierConstants(fn.Body, constants)
	for index := range fn.CallSites {
		site := &fn.CallSites[index]
		if !site.Direct || !site.Reachable || !site.HasBlock ||
			!reachable[site.BlockID] || site.ResultUse == "discarded" {
			continue
		}
		ids, status := a.resolveCallee(fn, site.Name)
		if status != "resolved" || len(ids) != 1 {
			continue
		}
		child := a.functions[ids[0]]
		constraint, ok := a.successfulCallConstraintForSite(
			fn,
			child,
			site.Name,
			site,
			callerRequirement,
		)
		if !ok || constraint.method !=
			"llvm_ssa_nonnegative_success_preservation" &&
			constraint.method !=
				"llvm_ssa_zero_success_preservation" &&
			constraint.method !=
				"llvm_ssa_positive_success_preservation" &&
			constraint.method !=
				"llvm_ssa_valid_pointer_success_preservation" {
			continue
		}
		arguments := make([]string, 0, len(site.Arguments))
		for _, argument := range site.Arguments {
			arguments = append(
				arguments,
				substituteIdentifierConstants(argument, constants),
			)
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			child,
			arguments,
			site,
		)
		childConstants = bindCallStructConstants(
			childConstants,
			body,
			callInvocation{
				name:       site.Name,
				arguments:  arguments,
				callSiteID: site.ID,
			},
			child.Parameters,
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			child,
			constraint.requirement,
		)
		childWitness := a.proveFunctionSuccessfulExecution(
			child.ID,
			childConstants,
			active,
		)
		if !childWitness.proven {
			continue
		}
		return functionSuccessWitness{
			proven: true,
			method: constraint.method,
			path: uniqueStrings(append(
				append([]string(nil), childWitness.path...),
				fmt.Sprintf("%s#%s", fn.DisplayName, site.ID),
			)),
		}
	}
	return functionSuccessWitness{}
}

type effectFreePathState struct {
	blockID         int
	constraints     []successPathConstraint
	successfulCalls []successfulCallConstraint
	values          map[string]cfgPathValue
	visited         map[int]bool
	path            []string
}

func (a *Analyzer) proveEffectFreeSuccessfulExecution(
	functionID string,
	constants map[string]string,
	operationContext map[string][]string,
	domain string,
	active map[string]bool,
) functionSuccessWitness {
	fn := a.functions[functionID]
	if fn == nil || (domain != "lsm" && domain != "sigkill") {
		return functionSuccessWitness{}
	}
	cacheKey := domain + "\x1e" + functionContextKey(fn, constants) +
		operationContextKey(operationContext)
	if a.effectFreeSuccessCache == nil {
		a.effectFreeSuccessCache =
			make(map[string]functionSuccessWitness)
	}
	if cached, ok := a.effectFreeSuccessCache[cacheKey]; ok {
		return cached
	}
	if active == nil {
		active = make(map[string]bool)
	}
	if active[cacheKey] || fn.Frontend != "clang-ast-cfg" ||
		!fn.CFGComplete || fn.FrontendVariantConflict ||
		!fn.CFGHasSuccessExit {
		return functionSuccessWitness{}
	}
	if witness := kernelRuntimeEffectFreeSuccessContractWitness(
		fn,
		constants[contextReturnRequirementKey],
		domain,
	); witness.proven {
		a.effectFreeSuccessCache[cacheKey] = witness
		return witness
	}
	if a.unplacedEffectMayMatter(fn, domain) {
		a.effectFreeSuccessCache[cacheKey] = functionSuccessWitness{}
		return functionSuccessWitness{}
	}

	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	if _, ok := blocks[fn.CFGEntry]; !ok {
		a.effectFreeSuccessCache[cacheKey] = functionSuccessWitness{}
		return functionSuccessWitness{}
	}

	active[cacheKey] = true
	defer delete(active, cacheKey)
	queue := []effectFreePathState{{
		blockID: fn.CFGEntry,
		visited: map[int]bool{fn.CFGEntry: true},
		path:    []string{fn.DisplayName},
	}}
	seen := make(map[string][]map[int]bool)
	admitCFGVisitedState(
		seen,
		fmt.Sprintf("%d\x00\x00\x00", fn.CFGEntry),
		map[int]bool{fn.CFGEntry: true},
	)
	const maxEffectFreeStates = 4096
	for len(queue) > 0 && len(seen) < maxEffectFreeStates {
		blockQueue := make([]int, 0, len(queue))
		for _, candidate := range queue {
			blockQueue = append(blockQueue, candidate.blockID)
		}
		nextIndex := a.prioritizedCFGQueueIndex(
			fn,
			blocks,
			blockQueue,
			domain,
		)
		state := queue[nextIndex]
		queue = append(queue[:nextIndex], queue[nextIndex+1:]...)
		block := blocks[state.blockID]
		blockPath, blockSuccessfulCalls, ok := a.effectFreeBlockPath(
			fn,
			block,
			constants,
			operationContext,
			domain,
			active,
		)
		if !ok {
			continue
		}
		state.path = uniqueStrings(append(state.path, blockPath...))
		state.successfulCalls = canonicalSuccessfulCallConstraints(append(
			state.successfulCalls,
			blockSuccessfulCalls...,
		))
		valueState := applyCFGValueWritesToAlternatives(
			fn,
			block,
			[]lsmPathAlternative{{
				bypassConstraints: state.constraints,
				bypassValues:      state.values,
			}},
		)
		if len(valueState) != 1 {
			continue
		}
		state.constraints = valueState[0].bypassConstraints
		state.values = valueState[0].bypassValues
		if block.PotentialSuccessExit {
			witness := a.proveSuccessfulReturnBlockAlongPathWithValues(
				fn,
				block,
				constants,
				make(map[string]bool),
				state.constraints,
				false,
				false,
				state.successfulCalls,
				state.values,
			)
			if witness.proven {
				successMethod := witness.method
				witness.method = "cfg_effect_free_fast_success_path"
				if successMethod != "" &&
					successMethod != "explicit_success_return" {
					witness.method += "+" + successMethod
				}
				witness.path = uniqueStrings(append(
					state.path,
					witness.path...,
				))
				a.effectFreeSuccessCache[cacheKey] = witness
				return witness
			}
		}
		for _, edge := range a.prioritizedSuccessSuccessorEdges(
			fn,
			blocks,
			block,
			constants,
			domain,
		) {
			if edge.blockID == fn.CFGExit ||
				state.visited[edge.blockID] {
				continue
			}
			if _, ok := blocks[edge.blockID]; !ok {
				continue
			}
			next := effectFreePathState{
				blockID: edge.blockID,
				constraints: append(
					[]successPathConstraint(nil),
					state.constraints...,
				),
				successfulCalls: append(
					[]successfulCallConstraint(nil),
					state.successfulCalls...,
				),
				values:  cloneCFGPathValues(state.values),
				visited: make(map[int]bool, len(state.visited)+1),
				path:    append([]string(nil), state.path...),
			}
			for blockID := range state.visited {
				next.visited[blockID] = true
			}
			next.visited[edge.blockID] = true
			if block.TerminatorCondition != "" &&
				(edge.branch == "true" || edge.branch == "false") &&
				(cfgBranchMayConstrainFunctionReturn(
					fn,
					block.TerminatorCondition,
					edge.branch == "true",
				) || cfgBranchConstrainsTrackedCallValue(
					fn,
					block.TerminatorCondition,
					edge.branch == "true",
					state.values,
				)) {
				next.constraints = canonicalSuccessPathConstraints(
					append(
						next.constraints,
						successPathConstraint{
							functionID: fn.ID,
							blockID:    block.ID,
							expression: strings.TrimSpace(
								block.TerminatorCondition,
							),
							required:   edge.branch == "true",
							pathStable: true,
						},
					),
				)
			}
			key := fmt.Sprintf(
				"%d\x00%s\x00%s\x00%s",
				next.blockID,
				successPathConstraintKey(next.constraints, false),
				successfulCallConstraintKey(next.successfulCalls),
				cfgPathValuesKey(next.values),
			)
			if !admitCFGVisitedState(
				seen,
				key,
				next.visited,
			) {
				continue
			}
			queue = append(queue, next)
		}
	}
	a.effectFreeSuccessCache[cacheKey] = functionSuccessWitness{}
	return functionSuccessWitness{}
}

func (a *Analyzer) unplacedEffectMayMatter(
	fn *FunctionInfo,
	domain string,
) bool {
	if fn == nil {
		return true
	}
	for _, siteID := range fn.CFGUnplacedCallSites {
		site := clangCallSiteByID(fn, siteID)
		if site == nil {
			return true
		}
		if a.callSiteMayContainDomainEffect(fn, *site, domain) {
			return true
		}
	}
	for _, event := range fn.CFGUnplacedEvents {
		switch domain {
		case "lsm":
			if strings.HasPrefix(event, "call:security_") ||
				strings.HasPrefix(event, "indirect:") {
				return true
			}
		case "sigkill":
			if strings.HasPrefix(event, "signal:") ||
				strings.HasPrefix(event, "indirect:") {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) callSiteMayContainDomainEffect(
	fn *FunctionInfo,
	site ClangCallSite,
	domain string,
) bool {
	if !site.Direct {
		return true
	}
	if domain == "lsm" && strings.HasPrefix(site.Name, "security_") {
		return true
	}
	if domain == "sigkill" && isSignalCheckName(site.Name) {
		return true
	}
	ids, status := a.resolveCallee(fn, site.Name)
	if status != "resolved" || len(ids) != 1 {
		return true
	}
	if domain == "lsm" {
		return a.lsmEffectSourceState(ids[0]) != effectSourceNone
	}
	return a.signalEffectSourceState(ids[0]) != effectSourceNone
}

func (a *Analyzer) effectFreeBlockPath(
	fn *FunctionInfo,
	block ClangCFGBlock,
	constants map[string]string,
	operationContext map[string][]string,
	domain string,
	active map[string]bool,
) ([]string, []successfulCallConstraint, bool) {
	byID := make(map[string]ClangCallSite, len(fn.CallSites))
	for _, site := range fn.CallSites {
		byID[site.ID] = site
	}
	path := []string{
		fmt.Sprintf("%s#cfg-block-%d", fn.DisplayName, block.ID),
	}
	successfulCalls := make([]successfulCallConstraint, 0)
	if len(block.CallSiteIDs) == 0 {
		if domain == "lsm" && len(block.LSMHooks) > 0 ||
			domain == "sigkill" && len(block.SignalChecks) > 0 ||
			len(block.IndirectCalls) > 0 {
			return nil, nil, false
		}
		for _, callee := range filterInternalCallees(block.Calls) {
			ids, status := a.resolveCallee(fn, callee)
			if status != "resolved" || len(ids) != 1 {
				return nil, nil, false
			}
			if domain == "lsm" &&
				a.lsmEffectSourceState(ids[0]) == effectSourceNone ||
				domain == "sigkill" &&
					a.signalEffectSourceState(ids[0]) ==
						effectSourceNone {
				continue
			}
			witness := a.proveEffectFreeSuccessfulExecution(
				ids[0],
				nil,
				operationContext,
				domain,
				active,
			)
			if !witness.proven {
				return nil, nil, false
			}
			path = uniqueStrings(append(path, witness.path...))
		}
		return path, successfulCalls, true
	}

	body := substituteIdentifierConstants(fn.Body, constants)
	representedLSM := make(map[string]bool)
	representedSignals := make(map[string]bool)
	for _, callSiteID := range block.CallSiteIDs {
		site, ok := byID[callSiteID]
		if !ok {
			return nil, nil, false
		}
		if !site.Direct {
			invocation, found := findIndirectInvocation(
				body,
				site.Expression,
			)
			if !found || !a.indirectTargetSetClosedWithContext(
				fn,
				invocation,
				operationContext,
				constants,
			) {
				return nil, nil, false
			}
			targets := a.resolveIndirectInvocationWithContext(
				fn,
				invocation,
				operationContext,
				constants,
			)
			if len(targets) == 0 {
				return nil, nil, false
			}
			for _, target := range targets {
				child := a.functions[target.functionID]
				if child == nil {
					return nil, nil, false
				}
				childConstants := a.bindCallAnalysisContext(
					fn,
					constants,
					child,
					target.arguments,
					&site,
				)
				childConstants = bindCallReturnRequirement(
					childConstants,
					child,
					requiredIndirectCallReturnForSite(
						fn,
						child,
						body,
						&site,
						constants[contextReturnRequirementKey],
					),
				)
				witness := a.proveEffectFreeSuccessfulExecution(
					target.functionID,
					childConstants,
					extendOperationContext(
						operationContext,
						target.evidence,
					),
					domain,
					active,
				)
				if !witness.proven {
					return nil, nil, false
				}
				path = uniqueStrings(append(path, witness.path...))
			}
			continue
		}
		if domain == "lsm" &&
			strings.HasPrefix(site.Name, "security_") {
			representedLSM[site.Name] = true
			event := a.localLSMCoverageEventForBody(
				fn,
				body,
				site.Name,
			)
			if event.states != lsmPathNonEnforcing {
				return nil, nil, false
			}
			continue
		}
		if domain == "sigkill" && isSignalCheckName(site.Name) {
			representedSignals[site.Name] = true
			event := a.localSignalCoverageEvent(
				fn,
				body,
				site.Name,
				site.ID,
			)
			if event.states != lsmPathNonEnforcing {
				return nil, nil, false
			}
			continue
		}
		if site.ResultUse == "discarded" {
			continue
		}
		ids, status := a.resolveCallee(fn, site.Name)
		if status != "resolved" || len(ids) != 1 {
			return nil, nil, false
		}
		child := a.functions[ids[0]]
		if child == nil {
			return nil, nil, false
		}
		arguments := make([]string, 0, len(site.Arguments))
		for _, argument := range site.Arguments {
			arguments = append(
				arguments,
				substituteIdentifierConstants(argument, constants),
			)
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			child,
			arguments,
			&site,
		)
		childConstants = bindCallStructConstants(
			childConstants,
			body,
			callInvocation{
				name:       site.Name,
				arguments:  arguments,
				callSiteID: site.ID,
			},
			child.Parameters,
		)
		childRequirement := requiredCallReturnForSite(
			fn,
			child,
			body,
			site.Name,
			&site,
			constants[contextReturnRequirementKey],
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			child,
			childRequirement,
		)
		sourceFree := domain == "lsm" &&
			a.lsmEffectSourceState(ids[0]) == effectSourceNone ||
			domain == "sigkill" &&
				a.signalEffectSourceState(ids[0]) == effectSourceNone
		var witness functionSuccessWitness
		if sourceFree {
			if constraint, canCorrelate :=
				a.successfulCallConstraintForSite(
					fn,
					child,
					site.Name,
					&site,
					constants[contextReturnRequirementKey],
				); canCorrelate {
				childConstants = bindCallReturnRequirement(
					childConstants,
					child,
					constraint.requirement,
				)
				witness = a.proveFunctionSuccessfulExecution(
					ids[0],
					childConstants,
					make(map[string]bool),
				)
				if witness.proven {
					successfulCalls =
						canonicalSuccessfulCallConstraints(append(
							successfulCalls,
							constraint,
						))
					path = uniqueStrings(append(
						path,
						witness.path...,
					))
				}
			}
			continue
		}
		witness = a.proveEffectFreeSuccessfulExecution(
			ids[0],
			childConstants,
			operationContext,
			domain,
			active,
		)
		if !witness.proven {
			return nil, nil, false
		}
		path = uniqueStrings(append(path, witness.path...))
		if constraint, canCorrelate :=
			a.successfulCallConstraintForSite(
				fn,
				child,
				site.Name,
				&site,
				constants[contextReturnRequirementKey],
			); canCorrelate {
			successfulCalls = canonicalSuccessfulCallConstraints(append(
				successfulCalls,
				constraint,
			))
		}
	}
	if domain == "lsm" {
		for _, hook := range block.LSMHooks {
			if representedLSM[hook] {
				continue
			}
			event := a.localLSMCoverageEventForBody(
				fn,
				body,
				hook,
			)
			if event.states != lsmPathNonEnforcing {
				return nil, nil, false
			}
		}
	}
	if domain == "sigkill" {
		for _, check := range block.SignalChecks {
			if representedSignals[check] {
				continue
			}
			event := a.localSignalCoverageEvent(
				fn,
				body,
				check,
				"",
			)
			if event.states != lsmPathNonEnforcing {
				return nil, nil, false
			}
		}
	}
	return path, successfulCalls, true
}

func successReachableCFGBlocks(
	fn *FunctionInfo,
	constants map[string]string,
) map[int]bool {
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	reachable := make(map[int]bool)
	if _, ok := blocks[fn.CFGEntry]; !ok {
		return reachable
	}
	queue := []int{fn.CFGEntry}
	reachable[fn.CFGEntry] = true
	for len(queue) > 0 {
		blockID := queue[0]
		queue = queue[1:]
		for _, successor := range successSuccessorsForConstants(
			blocks[blockID],
			constants,
		) {
			if successor == fn.CFGExit || reachable[successor] {
				continue
			}
			if _, ok := blocks[successor]; !ok {
				continue
			}
			reachable[successor] = true
			queue = append(queue, successor)
		}
	}
	return reachable
}

func (a *Analyzer) proveSuccessfulReturnBlockAlongPathWithValues(
	fn *FunctionInfo,
	block ClangCFGBlock,
	constants map[string]string,
	active map[string]bool,
	constraints []successPathConstraint,
	cyclic bool,
	allowForwarded bool,
	successfulCalls []successfulCallConstraint,
	values map[string]cfgPathValue,
) functionSuccessWitness {
	rawExpression := substituteIdentifierConstants(
		strings.TrimSpace(clangCFGReturnExpression(block)),
		constants,
	)
	expression := resolvedCFGConstantReturnExpression(
		rawExpression,
		values,
	)
	expression = resolveAssumedSuccessfulReturnExpression(
		fn,
		expression,
		constants,
		constraints,
	)
	blockPath := fmt.Sprintf("%s#cfg-block-%d", fn.DisplayName, block.ID)
	feasibilityPath, feasible := a.proveTrackedCallPathRequirements(
		fn,
		constants,
		constraints,
		values,
		active,
	)
	if !feasible {
		return functionSuccessWitness{}
	}
	withFeasibility := func(
		witness functionSuccessWitness,
	) functionSuccessWitness {
		if !witness.proven {
			return witness
		}
		witness.path = uniqueStrings(append(
			append([]string(nil), feasibilityPath...),
			witness.path...,
		))
		return witness
	}
	if syscallReturnIsExplicitlyForcedSuccessful(fn, block) {
		return withFeasibility(functionSuccessWitness{
			proven: true,
			method: "force_successful_syscall_return",
			path:   []string{blockPath + "[forced-success]"},
		})
	}
	if returnExpressionProvesSuccess(
		fn.ReturnType,
		expression,
		constants[contextReturnRequirementKey],
	) {
		return withFeasibility(functionSuccessWitness{
			proven: true,
			method: "explicit_success_return",
			path:   []string{blockPath},
		})
	}
	if witness := kernelUserAccessReturnSuccessWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		return withFeasibility(witness)
	}
	if witness := clangNonnegativeReturnWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		return withFeasibility(witness)
	}
	if witness := clangValidPointerReturnWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		return withFeasibility(witness)
	}
	if witness := trackedKernelRuntimeSuccessWitness(
		fn,
		block,
		rawExpression,
		values,
		constraints,
		constants[contextReturnRequirementKey],
	); witness.proven {
		return withFeasibility(witness)
	}
	if typedOutcome, ok := trackedCFGTypedReturnOutcome(
		fn,
		rawExpression,
		values,
	); ok {
		requirement := constants[contextReturnRequirementKey]
		if requirement == "" {
			requirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if returnOutcomeCompatibility(typedOutcome, requirement) ==
			"guaranteed" {
			return withFeasibility(functionSuccessWitness{
				proven: true,
				method: "clang_typed_value_range",
				path: []string{
					blockPath + "[typed-nonnegative]",
				},
			})
		}
	}
	if outParameterOutcome, proofPath, ok :=
		a.constrainedOutParameterReturnOutcome(
			fn,
			rawExpression,
			constraints,
			values,
		); ok {
		requirement := constants[contextReturnRequirementKey]
		if requirement == "" {
			requirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if returnOutcomeCompatibility(
			outParameterOutcome,
			requirement,
		) == "guaranteed" {
			return withFeasibility(functionSuccessWitness{
				proven: true,
				method: "clang_cfg_out_parameter_postcondition",
				path: uniqueStrings(append(
					proofPath,
					blockPath,
				)),
			})
		}
	}
	if !cyclic && returnExpressionProvesSuccessOnCFGPath(
		fn,
		rawExpression,
		constants[contextReturnRequirementKey],
		constraints,
	) {
		return withFeasibility(functionSuccessWitness{
			proven: true,
			method: "cfg_branch_constrained_success_return",
			path: append(
				successConstraintProofPath(fn, constraints),
				blockPath,
			),
		})
	}
	if !cyclic {
		for _, candidate := range clangCFGReturnExpressions(block) {
			candidate = substituteIdentifierConstants(
				strings.TrimSpace(candidate),
				constants,
			)
			if candidate == rawExpression {
				continue
			}
			candidate = resolvedCFGConstantReturnExpression(
				candidate,
				values,
			)
			candidate = resolveAssumedSuccessfulReturnExpression(
				fn,
				candidate,
				constants,
				constraints,
			)
			if !returnExpressionProvesSuccessOnCFGPath(
				fn,
				candidate,
				constants[contextReturnRequirementKey],
				constraints,
			) {
				continue
			}
			return withFeasibility(functionSuccessWitness{
				proven: true,
				method: "cfg_source_branch_constrained_success_return",
				path: append(
					successConstraintProofPath(fn, constraints),
					blockPath,
				),
			})
		}
	}
	if !cyclic {
		witness := a.proveTrackedSentinelCallSuccess(
			fn,
			rawExpression,
			constants,
			constraints,
			values,
			block,
		)
		if witness.proven {
			return withFeasibility(witness)
		}
	}
	if !cyclic {
		outcome := returnOutcomeFromExpression(
			fn,
			resolvedCFGConstantReturnExpression(
				rawExpression,
				values,
			),
			constraints,
			false,
			successfulCalls,
			constants[contextReturnRequirementKey],
		)
		requirement := constants[contextReturnRequirementKey]
		if requirement == "" {
			requirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if returnOutcomeCompatibility(outcome, requirement) ==
			"guaranteed" {
			witness := correlatedSuccessfulCallWitness(
				fn,
				block,
				expression,
				successfulCalls,
			)
			if witness.proven {
				return withFeasibility(witness)
			}
		}
	}
	if method, proven := llvmFunctionSuccessProof(
		fn,
		constants[contextReturnRequirementKey],
	); proven {
		return withFeasibility(functionSuccessWitness{
			proven: true,
			method: method,
			path: []string{
				blockPath + "[llvm-all-returns-success]",
			},
		})
	}
	if lineageWitness := a.proveCFGCallLineageSuccess(
		fn,
		rawExpression,
		constants,
		constraints,
		successfulCalls,
		values,
		active,
	); lineageWitness.proven {
		return withFeasibility(lineageWitness)
	}
	if !allowForwarded {
		return functionSuccessWitness{}
	}

	forwardedExpression, forwardedSite := forwardedCFGCallExpression(
		fn,
		rawExpression,
		values,
	)
	callee, arguments, ok := directReturnedCall(forwardedExpression)
	if !ok {
		return functionSuccessWitness{}
	}
	ids, status := a.resolveCallee(fn, callee)
	if status != "resolved" || len(ids) != 1 {
		return functionSuccessWitness{}
	}
	child := a.functions[ids[0]]
	if child == nil || !compatibleSuccessReturnFunctions(fn, child) {
		return functionSuccessWitness{}
	}
	var returnedSite *ClangCallSite
	if forwardedSite != nil {
		returnedSite = forwardedSite
		if len(returnedSite.Arguments) == len(arguments) {
			arguments = append(
				[]string(nil),
				returnedSite.Arguments...,
			)
		}
	} else {
		for index := range fn.CallSites {
			site := &fn.CallSites[index]
			if !site.Direct || site.Name != callee || !site.HasBlock ||
				site.BlockID != block.ID {
				continue
			}
			if len(site.Arguments) == len(arguments) {
				arguments = append([]string(nil), site.Arguments...)
			}
			returnedSite = site
			break
		}
	}
	for index := range arguments {
		arguments[index] = substituteIdentifierConstants(arguments[index], constants)
	}
	childConstants := a.bindCallAnalysisContext(
		fn,
		constants,
		child,
		arguments,
		returnedSite,
	)
	childConstants = bindCallStructConstants(
		childConstants,
		fn.Body,
		callInvocation{name: callee, arguments: arguments},
		child.Parameters,
	)
	childRequirement := requiredCallReturnForSite(
		fn,
		child,
		fn.Body,
		callee,
		returnedSite,
		constants[contextReturnRequirementKey],
	)
	if childRequirement == "" {
		parentRequirement := constants[contextReturnRequirementKey]
		if parentRequirement == "" {
			parentRequirement = defaultSuccessRequirement(fn.ReturnType)
		}
		if requirementsCompatibleAcrossFunctions(
			fn,
			child,
			parentRequirement,
		) {
			childRequirement = parentRequirement
		}
	}
	parentRequirement := constants[contextReturnRequirementKey]
	if parentRequirement == "" {
		parentRequirement = defaultSuccessRequirement(fn.ReturnType)
	}
	pathRequirement, pathCompatible := successfulRequirementOnCFGPath(
		fn,
		rawExpression,
		parentRequirement,
		constraints,
		successfulCalls,
		values,
	)
	if !pathCompatible {
		return functionSuccessWitness{}
	}
	childRequirement, pathCompatible = intersectReturnRequirements(
		child.ReturnType,
		childRequirement,
		pathRequirement,
	)
	if !pathCompatible {
		return functionSuccessWitness{}
	}
	childConstants = bindCallReturnRequirement(
		childConstants,
		child,
		childRequirement,
	)
	childWitness := a.proveFunctionSuccessfulExecution(
		ids[0],
		childConstants,
		active,
	)
	if !childWitness.proven {
		return functionSuccessWitness{}
	}
	return withFeasibility(functionSuccessWitness{
		proven: true,
		method: "forwarded_proven_success_return",
		path: uniqueStrings(append(
			append([]string(nil), childWitness.path...),
			blockPath,
		)),
	})
}

func (a *Analyzer) proveTrackedSentinelCallSuccess(
	fn *FunctionInfo,
	returnExpression string,
	constants map[string]string,
	constraints []successPathConstraint,
	values map[string]cfgPathValue,
	block ClangCFGBlock,
) functionSuccessWitness {
	if fn == nil {
		return functionSuccessWitness{}
	}
	requirement := constants[contextReturnRequirementKey]
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if requirement != "nonnegative" {
		return functionSuccessWitness{}
	}
	resultVariable, site := trackedCallSourceForReturnExpression(
		fn,
		returnExpression,
		values,
	)
	if site == nil {
		return functionSuccessWitness{}
	}
	excludesSentinel := false
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			!constraint.pathStable ||
			!expressionReferencesIdentifier(
				constraint.expression,
				resultVariable,
			) {
			continue
		}
		if conditionExcludesSignedIntegerSentinel(
			constraint.expression,
			resultVariable,
			constraint.required,
			-1,
		) {
			excludesSentinel = true
			break
		}
	}
	if !excludesSentinel {
		return functionSuccessWitness{}
	}
	ids, status := a.resolveCallee(fn, site.Name)
	if status != "resolved" || len(ids) != 1 {
		return functionSuccessWitness{}
	}
	child := a.functions[ids[0]]
	if !isX86PKeyMinusOneSentinelAllocator(child) {
		return functionSuccessWitness{}
	}
	childWitness := kernelRuntimeSuccessContractWitness(
		child,
		"nonnegative",
	)
	if !childWitness.proven {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: childWitness.method,
		path: uniqueStrings(append(
			append([]string(nil), childWitness.path...),
			fmt.Sprintf(
				"%s#cfg-block-%d[%s-excludes--1]",
				fn.DisplayName,
				block.ID,
				resultVariable,
			),
		)),
	}
}

func trackedCallSourceForReturnExpression(
	fn *FunctionInfo,
	expression string,
	values map[string]cfgPathValue,
) (string, *ClangCallSite) {
	identifier := stripSimpleCasts(compactExpression(expression))
	seen := make(map[string]bool)
	identifierPattern := regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	)
	for identifierPattern.MatchString(identifier) &&
		!seen[identifier] {
		seen[identifier] = true
		value, ok := values[identifier]
		if !ok {
			return "", nil
		}
		if value.callSiteID != "" {
			site := clangCallSiteByID(fn, value.callSiteID)
			if !callSiteMatchesTrackedResult(site, identifier) {
				return "", nil
			}
			return identifier, site
		}
		identifier = stripSimpleCasts(
			compactExpression(value.expression),
		)
	}
	return "", nil
}

func (a *Analyzer) proveCFGCallLineageSuccess(
	fn *FunctionInfo,
	returnExpression string,
	constants map[string]string,
	constraints []successPathConstraint,
	successfulCalls []successfulCallConstraint,
	values map[string]cfgPathValue,
	active map[string]bool,
) functionSuccessWitness {
	if fn == nil {
		return functionSuccessWitness{}
	}
	identifier := stripSimpleCasts(compactExpression(returnExpression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return functionSuccessWitness{}
	}
	value, ok := values[identifier]
	if !ok || len(value.lineage) == 0 {
		return functionSuccessWitness{}
	}
	requirement := constants[contextReturnRequirementKey]
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if requirement == "" {
		return functionSuccessWitness{}
	}
	lineageRequirement, ok := successfulRequirementOnCFGPath(
		fn,
		returnExpression,
		requirement,
		constraints,
		successfulCalls,
		values,
	)
	if !ok {
		return functionSuccessWitness{}
	}
	proofPath := make([]string, 0)
	for index, step := range value.lineage {
		site := clangCallSiteByID(fn, step.callSiteID)
		if site == nil || !site.Direct {
			return functionSuccessWitness{}
		}
		callee, arguments, direct := directReturnedCall(step.expression)
		if !direct || callee != site.Name {
			return functionSuccessWitness{}
		}
		ids, status := a.resolveCallee(fn, callee)
		if status != "resolved" || len(ids) != 1 {
			return functionSuccessWitness{}
		}
		child := a.functions[ids[0]]
		if child == nil || !compatibleSuccessReturnFunctions(fn, child) {
			return functionSuccessWitness{}
		}
		if index > 0 {
			if step.sourceArgument < 0 ||
				step.sourceArgument >= len(child.Parameters) ||
				!functionMustReturnParameter(
					child,
					child.Parameters[step.sourceArgument],
				) {
				return functionSuccessWitness{}
			}
			proofPath = appendUnique(
				proofPath,
				fmt.Sprintf(
					"%s#%s[exact-argument-%d]",
					fn.DisplayName,
					site.ID,
					step.sourceArgument,
				),
			)
			continue
		}
		if len(site.Arguments) == len(arguments) {
			arguments = append([]string(nil), site.Arguments...)
		}
		for argumentIndex := range arguments {
			arguments[argumentIndex] = substituteIdentifierConstants(
				arguments[argumentIndex],
				constants,
			)
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			child,
			arguments,
			site,
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			child,
			lineageRequirement,
		)
		childWitness := a.proveFunctionSuccessfulExecution(
			child.ID,
			childConstants,
			active,
		)
		if !childWitness.proven {
			return functionSuccessWitness{}
		}
		proofPath = uniqueStrings(append(
			proofPath,
			childWitness.path...,
		))
	}
	method := "cfg_exact_call_result_alias"
	if len(value.lineage) > 1 {
		method = "cfg_exact_argument_call_lineage"
	}
	return functionSuccessWitness{
		proven: true,
		method: method,
		path:   proofPath,
	}
}

func successfulRequirementOnCFGPath(
	fn *FunctionInfo,
	returnExpression, requirement string,
	constraints []successPathConstraint,
	successfulCalls []successfulCallConstraint,
	values map[string]cfgPathValue,
) (string, bool) {
	if fn == nil || requirement == "" {
		return "", false
	}
	domain := returnDomainForType(fn.ReturnType)
	requiredMask, ok := requirementMask(domain, requirement)
	if !ok {
		return "", false
	}
	expression := resolvedCFGConstantReturnExpression(
		returnExpression,
		values,
	)
	outcome := returnOutcomeFromExpression(
		fn,
		expression,
		constraints,
		false,
		successfulCalls,
		requirement,
	)
	outcome = constrainReturnOutcomeByLLVMFunctionFacts(fn, outcome)
	if outcome.domain != domain {
		return "", false
	}
	mask := outcome.mask & requiredMask
	if mask == 0 {
		return "", false
	}
	pathRequirement, representable := requirementForOutcomeMask(
		domain,
		mask,
	)
	return pathRequirement, representable
}

func intersectReturnRequirements(
	returnType string,
	requirements ...string,
) (string, bool) {
	domain := returnDomainForType(returnType)
	outcome := fullReturnOutcome(returnType)
	if domain == returnDomainUnknown || outcome.mask == 0 {
		return "", false
	}
	mask := outcome.mask
	found := false
	for _, requirement := range requirements {
		if requirement == "" {
			continue
		}
		requiredMask, ok := requirementMask(domain, requirement)
		if !ok {
			return "", false
		}
		mask &= requiredMask
		found = true
	}
	if !found || mask == 0 {
		return "", false
	}
	requirement, representable := requirementForOutcomeMask(domain, mask)
	return requirement, representable
}

func functionMustReturnParameter(
	fn *FunctionInfo,
	parameter string,
) bool {
	if fn == nil || parameter == "" ||
		fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict ||
		!containsString(fn.Parameters, parameter) {
		return false
	}
	sawReturn := false
	for _, block := range fn.CFGBlocks {
		returnExpression := clangCFGReturnExpression(block)
		if strings.TrimSpace(returnExpression) == "" {
			continue
		}
		sawReturn = true
		if stripSimpleCasts(
			compactExpression(returnExpression),
		) != parameter {
			return false
		}
	}
	return sawReturn
}

func (a *Analyzer) proveExplicitSuccessfulReturnBlock(
	fn *FunctionInfo,
	block ClangCFGBlock,
	constants map[string]string,
	constraints []successPathConstraint,
	values map[string]cfgPathValue,
	successfulCalls []successfulCallConstraint,
) functionSuccessWitness {
	if fn == nil {
		return functionSuccessWitness{}
	}
	rawExpression := substituteIdentifierConstants(
		strings.TrimSpace(clangCFGReturnExpression(block)),
		constants,
	)
	expression := resolvedCFGConstantReturnExpression(
		rawExpression,
		values,
	)
	expression = resolveAssumedSuccessfulReturnExpression(
		fn,
		expression,
		constants,
		constraints,
	)
	feasibilityPath, feasible := a.proveTrackedCallPathRequirements(
		fn,
		constants,
		constraints,
		values,
		make(map[string]bool),
	)
	if !feasible {
		return functionSuccessWitness{}
	}
	blockPath := fmt.Sprintf(
		"%s#cfg-block-%d",
		fn.DisplayName,
		block.ID,
	)
	if syscallReturnIsExplicitlyForcedSuccessful(fn, block) {
		return functionSuccessWitness{
			proven: true,
			method: "force_successful_syscall_return",
			path: uniqueStrings(append(
				feasibilityPath,
				blockPath+"[forced-success]",
			)),
		}
	}
	if returnExpressionProvesSuccess(
		fn.ReturnType,
		expression,
		constants[contextReturnRequirementKey],
	) {
		return functionSuccessWitness{
			proven: true,
			method: "explicit_success_return",
			path: uniqueStrings(append(
				feasibilityPath,
				blockPath,
			)),
		}
	}
	for _, candidate := range clangCFGReturnExpressions(block) {
		candidate = substituteIdentifierConstants(
			strings.TrimSpace(candidate),
			constants,
		)
		if candidate == rawExpression {
			continue
		}
		candidate = resolvedCFGConstantReturnExpression(
			candidate,
			values,
		)
		candidate = resolveAssumedSuccessfulReturnExpression(
			fn,
			candidate,
			constants,
			constraints,
		)
		if !returnExpressionProvesSuccessOnCFGPath(
			fn,
			candidate,
			constants[contextReturnRequirementKey],
			constraints,
		) {
			continue
		}
		return functionSuccessWitness{
			proven: true,
			method: "cfg_source_branch_constrained_success_return",
			path: uniqueStrings(append(
				feasibilityPath,
				append(
					successConstraintProofPath(fn, constraints),
					blockPath,
				)...,
			)),
		}
	}
	if witness := kernelUserAccessReturnSuccessWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		witness.path = uniqueStrings(append(
			feasibilityPath,
			witness.path...,
		))
		return witness
	}
	if witness := clangNonnegativeReturnWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		witness.path = uniqueStrings(append(
			feasibilityPath,
			witness.path...,
		))
		return witness
	}
	if witness := clangValidPointerReturnWitness(
		fn,
		block,
		constants[contextReturnRequirementKey],
	); witness.proven {
		witness.path = uniqueStrings(append(
			feasibilityPath,
			witness.path...,
		))
		return witness
	}
	if witness := trackedKernelRuntimeSuccessWitness(
		fn,
		block,
		rawExpression,
		values,
		constraints,
		constants[contextReturnRequirementKey],
	); witness.proven {
		witness.path = uniqueStrings(append(
			feasibilityPath,
			witness.path...,
		))
		return witness
	}
	requirement := constants[contextReturnRequirementKey]
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	outcome := returnOutcomeFromExpression(
		fn,
		substituteIdentifierConstants(
			rawExpression,
			constants,
		),
		constraints,
		false,
		successfulCalls,
		requirement,
	)
	outcome = constrainReturnOutcomeByLLVMFunctionFacts(fn, outcome)
	if returnOutcomeCompatibility(outcome, requirement) != "guaranteed" {
		return functionSuccessWitness{}
	}
	if witness := correlatedSuccessfulCallWitness(
		fn,
		block,
		expression,
		successfulCalls,
	); witness.proven {
		witness.path = uniqueStrings(append(
			feasibilityPath,
			witness.path...,
		))
		return witness
	}
	if !returnVariableHasTrackedCallSource(rawExpression, values) {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "tracked_call_cfg_success_return",
		path: uniqueStrings(append(
			feasibilityPath,
			append(
				successConstraintProofPath(fn, constraints),
				blockPath,
			)...,
		)),
	}
}

func kernelUserAccessReturnSuccessWitness(
	fn *FunctionInfo,
	block ClangCFGBlock,
	requirement string,
) functionSuccessWitness {
	if fn == nil || fn.FrontendVariantConflict {
		return functionSuccessWitness{}
	}
	callee, arguments, direct := directReturnedCall(
		block.ReturnExpression,
	)
	if !direct || len(arguments) != 2 {
		return functionSuccessWitness{}
	}
	expanded := block.ReturnExpressionExpanded
	validExpansion := false
	switch callee {
	case "put_user", "__put_user":
		validExpansion = strings.Contains(expanded, "__ret_pu") &&
			strings.Contains(expanded, "__put_user_")
	case "get_user", "__get_user":
		validExpansion = strings.Contains(expanded, "__ret_gu") &&
			strings.Contains(expanded, "__get_user_")
	default:
		return functionSuccessWitness{}
	}
	if !validExpansion {
		return functionSuccessWitness{}
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if !returnExpressionProvesSuccess(
		fn.ReturnType,
		"0",
		requirement,
	) {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "x86_user_access_zero_success_contract",
		path: []string{
			fmt.Sprintf(
				"%s#cfg-block-%d[%s-valid-user-memory]",
				fn.DisplayName,
				block.ID,
				callee,
			),
		},
	}
}

func clangValidPointerReturnWitness(
	fn *FunctionInfo,
	block ClangCFGBlock,
	requirement string,
) functionSuccessWitness {
	if fn == nil || !block.ReturnDefinitelyValidPointer ||
		returnDomainForType(fn.ReturnType) != returnDomainPointer {
		return functionSuccessWitness{}
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	required, ok := requirementMask(
		returnDomainPointer,
		requirement,
	)
	if !ok || required&outcomePointerValue == 0 {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "clang_ast_valid_pointer_return",
		path: []string{
			fmt.Sprintf(
				"%s#cfg-block-%d[address-result]",
				fn.DisplayName,
				block.ID,
			),
		},
	}
}

func clangNonnegativeReturnWitness(
	fn *FunctionInfo,
	block ClangCFGBlock,
	requirement string,
) functionSuccessWitness {
	if fn == nil || !block.ReturnDefinitelyNonnegative {
		return functionSuccessWitness{}
	}
	domain := returnDomainForType(fn.ReturnType)
	if domain != returnDomainSigned &&
		domain != returnDomainUnsigned &&
		domain != returnDomainBool {
		return functionSuccessWitness{}
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	outcome := returnOutcome{
		domain: domain,
		mask:   outcomeZero | outcomePositive,
	}
	if domain == returnDomainBool {
		outcome.mask = outcomeBoolFalse | outcomeBoolTrue
	}
	if returnOutcomeCompatibility(outcome, requirement) != "guaranteed" {
		return functionSuccessWitness{}
	}
	return functionSuccessWitness{
		proven: true,
		method: "clang_ast_nonnegative_return",
		path: []string{
			fmt.Sprintf(
				"%s#cfg-block-%d[nonnegative-result]",
				fn.DisplayName,
				block.ID,
			),
		},
	}
}

func trackedKernelRuntimeSuccessWitness(
	fn *FunctionInfo,
	block ClangCFGBlock,
	expression string,
	values map[string]cfgPathValue,
	constraints []successPathConstraint,
	requirement string,
) functionSuccessWitness {
	if fn == nil {
		return functionSuccessWitness{}
	}
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) ||
		cfgVariableHasUnpreservedEscape(fn, identifier) {
		return functionSuccessWitness{}
	}
	value, ok := values[identifier]
	if !ok || !value.runtimeZeroSuccess ||
		value.runtimeSuccessKind == "" {
		return functionSuccessWitness{}
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	zeroOutcome := returnOutcomeFromExpression(
		fn,
		"0",
		nil,
		false,
		nil,
		requirement,
	)
	if returnOutcomeCompatibility(
		zeroOutcome,
		requirement,
	) != "guaranteed" {
		return functionSuccessWitness{}
	}
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			!constraint.pathStable ||
			!expressionReferencesIdentifier(
				constraint.expression,
				identifier,
			) {
			continue
		}
		constrainedRequirement := outcomeRequirementFromCondition(
			fn.ReturnType,
			constraint.expression,
			identifier,
			constraint.required,
		)
		if constrainedRequirement == "" ||
			returnOutcomeCompatibility(
				zeroOutcome,
				constrainedRequirement,
			) == "impossible" {
			return functionSuccessWitness{}
		}
	}
	return functionSuccessWitness{
		proven: true,
		method: "x86_user_access_tracked_zero_success_contract",
		path: []string{
			fmt.Sprintf(
				"%s#cfg-block-%d[%s=%s-success]",
				fn.DisplayName,
				block.ID,
				identifier,
				value.runtimeSuccessKind,
			),
		},
	}
}

func returnVariableHasTrackedCallSource(
	expression string,
	values map[string]cfgPathValue,
) bool {
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return false
	}
	value, ok := values[identifier]
	return ok && value.callSiteID != ""
}

func syscallReturnIsExplicitlyForcedSuccessful(
	fn *FunctionInfo,
	block ClangCFGBlock,
) bool {
	if fn == nil || !isSyscallBodyName(fn.Name) {
		return false
	}
	returnExpression := compactExpression(
		strings.TrimSpace(clangCFGReturnExpression(block)),
	)
	if returnExpression == "" {
		return false
	}
	marker := regexp.MustCompile(
		`\bforce_successful_syscall_return\s*\(\s*\)\s*;`,
	)
	returnStatement := regexp.MustCompile(`\breturn\s+([^;]+)\s*;`)
	for _, markerLocation := range marker.FindAllStringIndex(fn.Body, -1) {
		remaining := fn.Body[markerLocation[1]:]
		returnLocation := returnStatement.FindStringSubmatchIndex(remaining)
		if returnLocation == nil ||
			strings.TrimSpace(remaining[:returnLocation[0]]) != "" {
			continue
		}
		expression := compactExpression(
			remaining[returnLocation[2]:returnLocation[3]],
		)
		if expression == returnExpression {
			return true
		}
	}
	return false
}

func correlatedSuccessfulCallWitness(
	fn *FunctionInfo,
	block ClangCFGBlock,
	expression string,
	constraints []successfulCallConstraint,
) functionSuccessWitness {
	if fn == nil || len(constraints) == 0 {
		return functionSuccessWitness{}
	}
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID {
			continue
		}
		site := clangCallSiteByID(fn, constraint.callSiteID)
		if site == nil || !site.Direct || site.Name != constraint.callee {
			continue
		}
		_, applies := successfulCallConstraintReturnRequirement(
			fn,
			expression,
			constraint,
		)
		if !applies ||
			!constraint.certifiesCallerSuccess &&
				!constraint.provenCalleeSuccess {
			continue
		}
		method := constraint.method
		if method == "" {
			method = "correlated_forwarded_success_return"
		}
		return functionSuccessWitness{
			proven: true,
			method: method,
			path: []string{
				fmt.Sprintf(
					"%s#%s",
					fn.DisplayName,
					site.ID,
				),
				fmt.Sprintf(
					"%s#cfg-block-%d",
					fn.DisplayName,
					block.ID,
				),
			},
		}
	}
	return functionSuccessWitness{}
}

func successfulCallConstraintReturnRequirement(
	fn *FunctionInfo,
	expression string,
	constraint successfulCallConstraint,
) (string, bool) {
	if fn == nil || constraint.functionID != fn.ID {
		return "", false
	}
	site := clangCallSiteByID(fn, constraint.callSiteID)
	if site == nil || !site.Direct || site.Name != constraint.callee {
		return "", false
	}
	if !constraint.provenCalleeSuccess &&
		!constraint.certifiesCallerSuccess &&
		constraint.method != "child_return_outcome" {
		return "", false
	}
	if constraint.certifiesCallerSuccess &&
		strings.HasPrefix(constraint.method, "llvm_ssa_") &&
		constraint.callerRequirement != "" {
		return constraint.callerRequirement, true
	}
	expression = stripSimpleCasts(compactExpression(expression))
	if constraint.resultVariable != "" &&
		expression == compactExpression(constraint.resultVariable) {
		return constraint.requirement, constraint.requirement != ""
	}
	returnedCallee, _, direct := directReturnedCall(expression)
	if direct && returnedCallee == constraint.callee &&
		constraint.certifiesCallerSuccess &&
		constraint.method == "direct_forwarded_success_return" {
		return constraint.requirement, constraint.requirement != ""
	}
	return "", false
}

func directReturnedCall(expression string) (string, []string, bool) {
	expression = stripSimpleCasts(compactExpression(expression))
	openParen := strings.IndexByte(expression, '(')
	if openParen <= 0 {
		return "", nil, false
	}
	name := expression[:openParen]
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) {
		return "", nil, false
	}
	closeParen, ok := findMatchingParenForward(
		maskStringAndCharLiterals(expression),
		openParen,
	)
	if !ok || closeParen != len(expression)-1 {
		return "", nil, false
	}
	arguments := splitTopLevelCommaList(expression[openParen+1 : closeParen])
	if len(arguments) == 1 && arguments[0] == "" {
		arguments = nil
	}
	return name, arguments, true
}

func resolvedCFGConstantReturnExpression(
	expression string,
	values map[string]cfgPathValue,
) string {
	resolved := resolvedCFGPathExpression(
		expression,
		values,
		make(map[string]bool),
	)
	if compactExpression(resolved) != compactExpression(expression) {
		return resolved
	}
	constants := make(map[string]string)
	for identifier := range values {
		value := resolvedCFGPathExpression(
			identifier,
			values,
			make(map[string]bool),
		)
		if compactExpression(value) == compactExpression(identifier) ||
			!isTrackableCFGConstant(value) {
			continue
		}
		constants[identifier] = value
	}
	if len(constants) == 0 {
		return expression
	}
	return substituteIdentifierConstants(expression, constants)
}

func trackedCFGTypedReturnOutcome(
	fn *FunctionInfo,
	expression string,
	values map[string]cfgPathValue,
) (returnOutcome, bool) {
	if fn == nil {
		return returnOutcome{}, false
	}
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return returnOutcome{}, false
	}
	value, ok := values[identifier]
	if !ok {
		return returnOutcome{}, false
	}
	switch returnDomainForType(fn.ReturnType) {
	case returnDomainPointer:
		if value.provenValidPointer {
			return returnOutcome{
				domain: returnDomainPointer,
				mask:   outcomePointerValue,
			}, true
		}
	case returnDomainSigned:
		if !value.provenNonnegative {
			return returnOutcome{}, false
		}
		if value.typeClass == "signed_integer" ||
			(value.typeClass == "unsigned_integer" &&
				fn.ReturnTypeBits > value.typeBits) ||
			value.typeClass == "bool" {
			return returnOutcome{
				domain: returnDomainSigned,
				mask:   outcomeZero | outcomePositive,
			}, true
		}
	case returnDomainUnsigned:
		if !value.provenNonnegative {
			return returnOutcome{}, false
		}
		return returnOutcome{
			domain: returnDomainUnsigned,
			mask:   outcomeZero | outcomePositive,
		}, true
	}
	return returnOutcome{}, false
}

func (a *Analyzer) constrainedOutParameterReturnOutcome(
	fn *FunctionInfo,
	expression string,
	constraints []successPathConstraint,
	values map[string]cfgPathValue,
) (returnOutcome, []string, bool) {
	if fn == nil {
		return returnOutcome{}, nil, false
	}
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return returnOutcome{}, nil, false
	}
	value, ok := values[identifier]
	if !ok || !value.outParameter || value.callSiteID == "" ||
		value.outParameterIndex < 0 {
		return returnOutcome{}, nil, false
	}
	site := clangCallSiteByID(fn, value.callSiteID)
	if site == nil || !site.Direct ||
		value.outParameterIndex >= len(site.Arguments) ||
		site.ResultVariable == "" {
		return returnOutcome{}, nil, false
	}
	ids, status := a.resolveCallee(fn, site.Name)
	if status != "resolved" || len(ids) != 1 {
		return returnOutcome{}, nil, false
	}
	child := a.functions[ids[0]]
	if child == nil ||
		value.outParameterIndex >= len(child.Parameters) {
		return returnOutcome{}, nil, false
	}

	childRequirement := ""
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			!constraint.pathStable ||
			!expressionReferencesIdentifier(
				constraint.expression,
				site.ResultVariable,
			) {
			continue
		}
		requirement := outcomeRequirementFromCondition(
			site.ReturnType,
			constraint.expression,
			site.ResultVariable,
			constraint.required,
		)
		if requirement == "" {
			continue
		}
		var compatible bool
		childRequirement, compatible = intersectReturnRequirements(
			child.ReturnType,
			childRequirement,
			requirement,
		)
		if !compatible {
			return returnOutcome{}, nil, false
		}
	}
	if childRequirement == "" {
		return returnOutcome{}, nil, false
	}
	pointeeOutcome, proofPath, proven :=
		a.provePointeeOutcomeForReturnRequirement(
			child,
			value.outParameterIndex,
			childRequirement,
		)
	if !proven ||
		returnDomainForType(fn.ReturnType) != pointeeOutcome.domain {
		return returnOutcome{}, nil, false
	}
	return pointeeOutcome, append(
		proofPath,
		fmt.Sprintf(
			"%s#%s[arg=%d,%s]",
			fn.DisplayName,
			site.ID,
			value.outParameterIndex,
			childRequirement,
		),
	), true
}

type pointeeOutcomePathState struct {
	blockID     int
	constraints []successPathConstraint
	values      map[string]cfgPathValue
	pointee     cfgPathValue
	hasPointee  bool
	visited     map[int]bool
}

func (a *Analyzer) provePointeeOutcomeForReturnRequirement(
	fn *FunctionInfo,
	argumentIndex int,
	returnRequirement string,
) (returnOutcome, []string, bool) {
	if fn == nil || argumentIndex < 0 ||
		argumentIndex >= len(fn.Parameters) ||
		fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict || returnRequirement == "" {
		return returnOutcome{}, nil, false
	}
	parameter := fn.Parameters[argumentIndex]
	if !pointeeParameterWritesAreClosed(fn, parameter) {
		return returnOutcome{}, nil, false
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	if _, ok := blocks[fn.CFGEntry]; !ok {
		return returnOutcome{}, nil, false
	}
	queue := []pointeeOutcomePathState{{
		blockID: fn.CFGEntry,
		visited: map[int]bool{fn.CFGEntry: true},
	}}
	var combined returnOutcome
	sawMatchingReturn := false
	processed := 0
	const maxPointeeOutcomeStates = 1024
	for len(queue) > 0 {
		if processed >= maxPointeeOutcomeStates {
			return returnOutcome{}, nil, false
		}
		processed++
		state := queue[0]
		queue = queue[1:]
		block, ok := blocks[state.blockID]
		if !ok {
			return returnOutcome{}, nil, false
		}
		valueState := applyCFGValueWritesToAlternatives(
			fn,
			block,
			[]lsmPathAlternative{{
				bypassConstraints: state.constraints,
				bypassValues:      state.values,
			}},
		)
		if len(valueState) != 1 {
			return returnOutcome{}, nil, false
		}
		state.constraints = valueState[0].bypassConstraints
		state.values = valueState[0].bypassValues
		for _, write := range block.PointeeWrites {
			if write.Parameter != parameter {
				continue
			}
			if write.Kind == "invalidate" ||
				strings.TrimSpace(write.Expression) == "" {
				state.hasPointee = false
				continue
			}
			state.pointee = typedCFGPathValue(
				cfgPathValue{
					expression: write.Expression,
				},
				ClangCFGValueWrite{
					Target:                       parameter,
					Expression:                   write.Expression,
					Kind:                         write.Kind,
					SourceDefinitelyNonnegative:  write.SourceDefinitelyNonnegative,
					SourceDefinitelyValidPointer: write.SourceDefinitelyValidPointer,
					SourceTypeClass:              write.SourceTypeClass,
					SourceTypeSigned:             write.SourceTypeSigned,
					SourceTypeBits:               write.SourceTypeBits,
					TargetTypeClass:              write.TargetTypeClass,
					TargetTypeSigned:             write.TargetTypeSigned,
					TargetTypeBits:               write.TargetTypeBits,
				},
				state.values,
				state.pointee,
			)
			state.hasPointee = true
		}
		if block.ReturnExpression != "" ||
			block.ReturnExpressionExpanded != "" {
			if !successPathConstraintsConsistent(
				fn,
				state.constraints,
			) {
				continue
			}
			returnExpression := resolvedCFGConstantReturnExpression(
				clangCFGReturnExpression(block),
				state.values,
			)
			childReturnOutcome := returnOutcomeFromExpression(
				fn,
				returnExpression,
				state.constraints,
				false,
				nil,
				returnRequirement,
			)
			compatibility := returnOutcomeCompatibility(
				childReturnOutcome,
				returnRequirement,
			)
			switch compatibility {
			case "impossible":
				continue
			case "guaranteed":
			default:
				return returnOutcome{}, nil, false
			}
			if !state.hasPointee {
				return returnOutcome{}, nil, false
			}
			pointeeType := semanticTypeForClangMetadata(
				state.pointee.typeClass,
				state.pointee.typeSigned,
			)
			pointeeFunction := &FunctionInfo{
				ReturnType:     pointeeType,
				ReturnTypeBits: state.pointee.typeBits,
			}
			pointeeExpression := resolvedCFGConstantReturnExpression(
				state.pointee.expression,
				state.values,
			)
			pointeeOutcome := returnOutcomeFromExpression(
				pointeeFunction,
				pointeeExpression,
				state.constraints,
				false,
				nil,
				"",
			)
			if typedOutcome, known := trackedCFGTypedReturnOutcome(
				pointeeFunction,
				parameter,
				map[string]cfgPathValue{
					parameter: state.pointee,
				},
			); known && typedOutcome.domain == pointeeOutcome.domain {
				pointeeOutcome.mask &= typedOutcome.mask
			}
			if pointeeOutcome.domain == returnDomainUnknown ||
				pointeeOutcome.mask == 0 {
				return returnOutcome{}, nil, false
			}
			if !sawMatchingReturn {
				combined = pointeeOutcome
			} else if combined.domain != pointeeOutcome.domain {
				return returnOutcome{}, nil, false
			} else {
				combined.mask |= pointeeOutcome.mask
			}
			sawMatchingReturn = true
			continue
		}
		edges := allCFGSuccessorEdges(block)
		if len(edges) == 0 {
			return returnOutcome{}, nil, false
		}
		for _, edge := range edges {
			if edge.blockID == fn.CFGExit {
				return returnOutcome{}, nil, false
			}
			if _, ok := blocks[edge.blockID]; !ok ||
				state.visited[edge.blockID] {
				return returnOutcome{}, nil, false
			}
			next := pointeeOutcomePathState{
				blockID: edge.blockID,
				constraints: append(
					[]successPathConstraint(nil),
					state.constraints...,
				),
				values:     cloneCFGPathValues(state.values),
				pointee:    state.pointee,
				hasPointee: state.hasPointee,
				visited: make(
					map[int]bool,
					len(state.visited)+1,
				),
			}
			for blockID := range state.visited {
				next.visited[blockID] = true
			}
			next.visited[edge.blockID] = true
			if block.TerminatorCondition != "" &&
				(edge.branch == "true" ||
					edge.branch == "false") {
				next.constraints =
					canonicalSuccessPathConstraints(append(
						next.constraints,
						successPathConstraint{
							functionID: fn.ID,
							blockID:    block.ID,
							expression: strings.TrimSpace(
								block.TerminatorCondition,
							),
							required:   edge.branch == "true",
							pathStable: true,
						},
					))
			}
			queue = append(queue, next)
		}
	}
	if !sawMatchingReturn {
		return returnOutcome{}, nil, false
	}
	return combined, []string{
		fmt.Sprintf(
			"%s#pointee-postcondition[%s,%s]",
			fn.DisplayName,
			parameter,
			returnRequirement,
		),
	}, true
}

func semanticTypeForClangMetadata(
	class string,
	signed bool,
) string {
	switch class {
	case "signed_integer":
		if signed {
			return "signed_integer"
		}
	case "unsigned_integer", "bool", "pointer", "record", "void":
		return class
	}
	return "unknown"
}

func pointeeParameterWritesAreClosed(
	fn *FunctionInfo,
	parameter string,
) bool {
	if fn == nil || parameter == "" {
		return false
	}
	masked := maskStringAndCharLiterals(fn.Body)
	writePattern := regexp.MustCompile(
		`(?s)(?:\(\s*)?\*\s*` +
			regexp.QuoteMeta(parameter) +
			`\s*(?:\)\s*)?=\s*[^;]+;`,
	)
	writes := writePattern.FindAllStringIndex(masked, -1)
	extractedWrites := 0
	for _, block := range fn.CFGBlocks {
		for _, write := range block.PointeeWrites {
			if write.Parameter != parameter ||
				write.Kind != "assign" {
				continue
			}
			extractedWrites++
		}
	}
	if len(writes) == 0 || len(writes) != extractedWrites {
		return false
	}
	remaining := []byte(masked)
	for _, location := range writes {
		for index := location[0]; index < location[1]; index++ {
			remaining[index] = ' '
		}
	}
	return !regexp.MustCompile(
		`\b` + regexp.QuoteMeta(parameter) + `\b`,
	).Match(remaining)
}

func resolvedCFGPathExpression(
	expression string,
	values map[string]cfgPathValue,
	seen map[string]bool,
) string {
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return expression
	}
	if seen[identifier] {
		return expression
	}
	value, ok := values[identifier]
	if !ok || value.callSiteID != "" &&
		!isTrackableCFGSymbolicValue(value.expression, values) {
		return expression
	}
	seen[identifier] = true
	defer delete(seen, identifier)
	if isTrackableCFGConstant(value.expression) ||
		isTrackableCFGSymbolicValue(value.expression, values) {
		return value.expression
	}
	return resolvedCFGPathExpression(value.expression, values, seen)
}

func resolveAssumedSuccessfulReturnExpression(
	fn *FunctionInfo,
	expression string,
	constants map[string]string,
	constraints []successPathConstraint,
) string {
	if fn == nil {
		return expression
	}
	parameter := stripSimpleCasts(compactExpression(expression))
	if !containsString(fn.Parameters, parameter) {
		return expression
	}
	requirement := constants[successAssumptionKey(parameter)]
	if requirement == "" {
		return expression
	}
	domain := returnDomainForType(fn.ReturnType)
	requiredMask, ok := requirementMask(domain, requirement)
	if !ok {
		return expression
	}
	possibleMask := fullReturnOutcome(fn.ReturnType).mask
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			!expressionReferencesIdentifier(
				constraint.expression,
				parameter,
			) {
			continue
		}
		constrainedRequirement := outcomeRequirementFromCondition(
			fn.ReturnType,
			constraint.expression,
			parameter,
			constraint.required,
		)
		if constrainedRequirement == "" {
			continue
		}
		mask, known := requirementMask(
			domain,
			constrainedRequirement,
		)
		if !known {
			return expression
		}
		possibleMask &= mask
	}
	if possibleMask&requiredMask == 0 {
		return expression
	}
	witness, ok := successRequirementWitnessExpression(
		fn.ReturnType,
		requirement,
	)
	if !ok {
		return expression
	}
	return witness
}

func forwardedCFGCallExpression(
	fn *FunctionInfo,
	expression string,
	values map[string]cfgPathValue,
) (string, *ClangCallSite) {
	if _, _, ok := directReturnedCall(expression); ok {
		return expression, nil
	}
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return expression, nil
	}
	value, ok := values[identifier]
	if !ok || value.callSiteID == "" {
		return expression, nil
	}
	site := clangCallSiteByID(fn, value.callSiteID)
	if !callSiteMatchesTrackedResult(site, identifier) {
		return expression, nil
	}
	callee, _, ok := directReturnedCall(value.expression)
	if !ok || callee != site.Name {
		return expression, nil
	}
	return value.expression, site
}

func (a *Analyzer) proveTrackedCallPathRequirements(
	fn *FunctionInfo,
	constants map[string]string,
	constraints []successPathConstraint,
	values map[string]cfgPathValue,
	active map[string]bool,
) ([]string, bool) {
	if fn == nil || len(values) == 0 || len(constraints) == 0 {
		return nil, true
	}
	proofPath := make([]string, 0)
	body := substituteIdentifierConstants(fn.Body, constants)
	for identifier, value := range values {
		if value.callSiteID == "" {
			continue
		}
		site := clangCallSiteByID(fn, value.callSiteID)
		if !callSiteMatchesTrackedResult(site, identifier) {
			return nil, false
		}
		outcome := fullReturnOutcome(site.ReturnType)
		if outcome.domain == returnDomainUnknown || outcome.mask == 0 {
			return nil, false
		}
		requiredMask := outcome.mask
		constrained := false
		for _, constraint := range constraints {
			if constraint.functionID != fn.ID ||
				!expressionReferencesIdentifier(
					constraint.expression,
					identifier,
				) {
				continue
			}
			requirement := outcomeRequirementFromCondition(
				site.ReturnType,
				constraint.expression,
				identifier,
				constraint.required,
			)
			if requirement == "" {
				continue
			}
			mask, ok := requirementMask(
				outcome.domain,
				requirement,
			)
			if !ok {
				return nil, false
			}
			requiredMask &= mask
			constrained = true
		}
		if !constrained {
			continue
		}
		if requiredMask == 0 {
			return nil, false
		}
		requirement, ok := requirementForOutcomeMask(
			outcome.domain,
			requiredMask,
		)
		if !ok {
			return nil, false
		}
		callee, _, ok := directReturnedCall(value.expression)
		if !ok || callee != site.Name {
			return nil, false
		}
		ids, status := a.resolveCallee(fn, site.Name)
		if status != "resolved" || len(ids) != 1 {
			return nil, false
		}
		child := a.functions[ids[0]]
		if child == nil {
			return nil, false
		}
		arguments := make([]string, 0, len(site.Arguments))
		for _, argument := range site.Arguments {
			arguments = append(
				arguments,
				substituteIdentifierConstants(argument, constants),
			)
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			child,
			arguments,
			site,
		)
		childConstants = bindCallStructConstants(
			childConstants,
			body,
			callInvocation{
				name:       site.Name,
				arguments:  arguments,
				callSiteID: site.ID,
			},
			child.Parameters,
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			child,
			requirement,
		)
		childConstants = a.bindSymbolicSuccessParameterAssumptions(
			fn,
			child,
			arguments,
			constants,
			constraints,
			values,
			requirement,
			childConstants,
		)
		witness := a.proveFunctionSuccessfulExecution(
			child.ID,
			childConstants,
			active,
		)
		if !witness.proven {
			return nil, false
		}
		proofPath = uniqueStrings(append(
			proofPath,
			witness.path...,
		))
		proofPath = uniqueStrings(append(
			proofPath,
			fmt.Sprintf("%s#%s[%s]", fn.DisplayName, site.ID, requirement),
		))
	}
	return proofPath, true
}

func callSiteMatchesTrackedResult(
	site *ClangCallSite,
	identifier string,
) bool {
	return site != nil && site.Direct && identifier != "" &&
		(site.ResultVariable == "" ||
			site.ResultVariable == identifier)
}

func (a *Analyzer) bindSymbolicSuccessParameterAssumptions(
	caller, callee *FunctionInfo,
	arguments []string,
	parentConstants map[string]string,
	constraints []successPathConstraint,
	values map[string]cfgPathValue,
	requirement string,
	constants map[string]string,
) map[string]string {
	if caller == nil || callee == nil || requirement == "" ||
		callee.Frontend != "clang-ast-cfg" || !callee.CFGComplete ||
		callee.FrontendVariantConflict ||
		len(arguments) != len(callee.Parameters) {
		return constants
	}
	for index, parameter := range callee.Parameters {
		if !functionPotentiallyReturnsParameter(callee, parameter) {
			continue
		}
		argument := substituteIdentifierConstants(
			arguments[index],
			parentConstants,
		)
		argument = resolvedCFGConstantReturnExpression(
			argument,
			values,
		)
		if !symbolicArgumentMaySatisfyRequirement(
			caller,
			argument,
			callee.ReturnType,
			requirement,
			parentConstants,
			constraints,
		) {
			continue
		}
		if constants == nil {
			constants = make(map[string]string)
		}
		constants[successAssumptionKey(parameter)] = requirement
	}
	return constants
}

func functionPotentiallyReturnsParameter(
	fn *FunctionInfo,
	parameter string,
) bool {
	if fn == nil || parameter == "" ||
		!containsString(fn.Parameters, parameter) {
		return false
	}
	for _, block := range fn.CFGBlocks {
		if !block.PotentialSuccessExit {
			continue
		}
		expression := stripSimpleCasts(
			compactExpression(clangCFGReturnExpression(block)),
		)
		if expression == parameter {
			return true
		}
	}
	return false
}

func symbolicArgumentMaySatisfyRequirement(
	caller *FunctionInfo,
	argument, returnType, requirement string,
	parentConstants map[string]string,
	constraints []successPathConstraint,
) bool {
	argument = stripSimpleCasts(compactExpression(argument))
	if argument == "" {
		return false
	}
	if returnExpressionProvesSuccess(
		returnType,
		argument,
		requirement,
	) {
		return true
	}
	if caller == nil || !containsString(caller.Parameters, argument) {
		return false
	}
	domain := returnDomainForType(returnType)
	requiredMask, ok := requirementMask(domain, requirement)
	if !ok {
		return false
	}
	possibleMask := fullReturnOutcome(returnType).mask
	if assumed := parentConstants[successAssumptionKey(argument)]; assumed != "" {
		mask, known := requirementMask(domain, assumed)
		if !known {
			return false
		}
		possibleMask &= mask
	}
	for _, constraint := range constraints {
		if constraint.functionID != caller.ID ||
			!expressionReferencesIdentifier(
				constraint.expression,
				argument,
			) {
			continue
		}
		constrainedRequirement := outcomeRequirementFromCondition(
			returnType,
			constraint.expression,
			argument,
			constraint.required,
		)
		if constrainedRequirement == "" {
			continue
		}
		mask, known := requirementMask(
			domain,
			constrainedRequirement,
		)
		if !known {
			return false
		}
		possibleMask &= mask
	}
	return possibleMask&requiredMask != 0
}

func requirementForOutcomeMask(
	domain string,
	mask uint16,
) (string, bool) {
	candidates := []string{
		"negative",
		"zero",
		"positive",
		"nonnegative",
		"nonpositive",
		"nonzero",
		"null",
		"error_pointer",
		"nonnull_valid_pointer",
		"valid_pointer",
		"nonnull",
		"true",
		"false",
		"returned",
	}
	if domain == returnDomainPointer {
		candidates = []string{
			"null",
			"error_pointer",
			"null_or_error_pointer",
			"nonnull_valid_pointer",
			"valid_pointer",
			"non_error_pointer",
			"nonnull",
			"nonzero",
			"any",
			"returned",
		}
	}
	for _, requirement := range candidates {
		candidateMask, ok := requirementMask(domain, requirement)
		if ok && candidateMask == mask {
			return requirement, true
		}
	}
	return "", false
}

func returnDomainForType(returnType string) string {
	switch returnType {
	case "int", "long", "ssize_t", "signed_integer":
		return returnDomainSigned
	case "unsigned", "size_t", "unsigned_integer":
		return returnDomainUnsigned
	case "pointer":
		return returnDomainPointer
	case "bool":
		return returnDomainBool
	case "record":
		return returnDomainRecord
	case "void":
		return returnDomainVoid
	default:
		return returnDomainUnknown
	}
}

func fullReturnOutcome(returnType string) returnOutcome {
	switch returnDomainForType(returnType) {
	case returnDomainSigned:
		return returnOutcome{
			domain: returnDomainSigned,
			mask:   outcomeNegative | outcomeZero | outcomePositive,
		}
	case returnDomainUnsigned:
		return returnOutcome{
			domain: returnDomainUnsigned,
			mask:   outcomeZero | outcomePositive,
		}
	case returnDomainPointer:
		return returnOutcome{
			domain: returnDomainPointer,
			mask: outcomePointerNull |
				outcomePointerValue |
				outcomePointerError,
		}
	case returnDomainBool:
		return returnOutcome{
			domain: returnDomainBool,
			mask:   outcomeBoolFalse | outcomeBoolTrue,
		}
	case returnDomainRecord:
		return returnOutcome{
			domain: returnDomainRecord,
			mask:   outcomeVoidReturn,
		}
	case returnDomainVoid:
		return returnOutcome{
			domain: returnDomainVoid,
			mask:   outcomeVoidReturn,
		}
	default:
		return returnOutcome{}
	}
}

func defaultSuccessRequirement(returnType string) string {
	switch returnDomainForType(returnType) {
	case returnDomainSigned:
		return "nonnegative"
	case returnDomainUnsigned:
		return "any"
	case returnDomainBool:
		return "true"
	case returnDomainRecord:
		return "returned"
	case returnDomainVoid:
		return "returned"
	default:
		return ""
	}
}

func requirementMask(domain, requirement string) (uint16, bool) {
	switch requirement {
	case "any", "returned":
		switch domain {
		case returnDomainSigned:
			return outcomeNegative | outcomeZero | outcomePositive, true
		case returnDomainUnsigned:
			return outcomeZero | outcomePositive, true
		case returnDomainPointer:
			return outcomePointerNull |
				outcomePointerValue |
				outcomePointerError, true
		case returnDomainBool:
			return outcomeBoolFalse | outcomeBoolTrue, true
		case returnDomainRecord, returnDomainVoid:
			return outcomeVoidReturn, true
		}
	case "negative":
		return outcomeNegative, domain == returnDomainSigned
	case "zero":
		switch domain {
		case returnDomainSigned, returnDomainUnsigned:
			return outcomeZero, true
		case returnDomainBool:
			return outcomeBoolFalse, true
		case returnDomainPointer:
			return outcomePointerNull, true
		}
	case "positive":
		if domain == returnDomainSigned || domain == returnDomainUnsigned {
			return outcomePositive, true
		}
	case "nonnegative":
		if domain == returnDomainSigned || domain == returnDomainUnsigned {
			return outcomeZero | outcomePositive, true
		}
	case "nonpositive":
		if domain == returnDomainSigned {
			return outcomeNegative | outcomeZero, true
		}
	case "nonzero":
		switch domain {
		case returnDomainSigned:
			return outcomeNegative | outcomePositive, true
		case returnDomainUnsigned:
			return outcomePositive, true
		case returnDomainBool:
			return outcomeBoolTrue, true
		case returnDomainPointer:
			return outcomePointerValue | outcomePointerError, true
		}
	case "nonnull":
		if domain == returnDomainPointer {
			return outcomePointerValue | outcomePointerError, true
		}
	case "valid_pointer", "non_error_pointer":
		if domain == returnDomainPointer {
			return outcomePointerNull | outcomePointerValue, true
		}
	case "nonnull_valid_pointer":
		if domain == returnDomainPointer {
			return outcomePointerValue, true
		}
	case "null":
		if domain == returnDomainPointer {
			return outcomePointerNull, true
		}
	case "error_pointer":
		if domain == returnDomainPointer {
			return outcomePointerError, true
		}
	case "null_or_error_pointer":
		if domain == returnDomainPointer {
			return outcomePointerNull | outcomePointerError, true
		}
	case "true":
		if domain == returnDomainBool {
			return outcomeBoolTrue, true
		}
	case "false":
		if domain == returnDomainBool {
			return outcomeBoolFalse, true
		}
	}
	return 0, false
}

func returnOutcomeCompatibility(
	outcome returnOutcome,
	requirement string,
) string {
	if outcome.domain == returnDomainUnknown || outcome.mask == 0 ||
		requirement == "" {
		return "unknown"
	}
	required, ok := requirementMask(outcome.domain, requirement)
	if !ok {
		return "unknown"
	}
	intersection := outcome.mask & required
	if intersection == 0 {
		return "impossible"
	}
	if outcome.mask&^required == 0 {
		return "guaranteed"
	}
	return "conditional"
}

func returnOutcomeKey(outcome returnOutcome) string {
	if outcome.domain == returnDomainUnknown || outcome.mask == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%x", outcome.domain, outcome.mask)
}

func returnOutcomeFromExpression(
	fn *FunctionInfo,
	expression string,
	constraints []successPathConstraint,
	cyclic bool,
	successfulCalls []successfulCallConstraint,
	requirement string,
) returnOutcome {
	if fn == nil {
		return returnOutcome{}
	}
	outcome := fullReturnOutcome(fn.ReturnType)
	if outcome.domain == returnDomainUnknown {
		return outcome
	}
	expression = stripSimpleCasts(compactExpression(expression))
	if outcome.domain == returnDomainVoid {
		if expression == "" {
			return outcome
		}
		return returnOutcome{}
	}
	if outcome.domain == returnDomainRecord {
		if expression != "" {
			return outcome
		}
		return returnOutcome{}
	}
	if condition, trueExpression, falseExpression, ok :=
		splitTopLevelTernary(expression); ok {
		if selected, known := ternarySelectionFromConstraints(
			fn,
			condition,
			constraints,
		); known {
			selectedExpression := falseExpression
			if selected {
				selectedExpression = trueExpression
			}
			return returnOutcomeFromExpression(
				fn,
				selectedExpression,
				constraints,
				cyclic,
				successfulCalls,
				requirement,
			)
		}
		trueOutcome := returnOutcomeFromExpression(
			fn,
			trueExpression,
			constraints,
			cyclic,
			successfulCalls,
			requirement,
		)
		falseOutcome := returnOutcomeFromExpression(
			fn,
			falseExpression,
			constraints,
			cyclic,
			successfulCalls,
			requirement,
		)
		if trueOutcome.domain == falseOutcome.domain &&
			trueOutcome.domain != returnDomainUnknown {
			return returnOutcome{
				domain: trueOutcome.domain,
				mask:   trueOutcome.mask | falseOutcome.mask,
			}
		}
		return outcome
	}

	switch outcome.domain {
	case returnDomainBool:
		switch expression {
		case "false", "0":
			outcome.mask = outcomeBoolFalse
			return outcome
		case "true", "1":
			outcome.mask = outcomeBoolTrue
			return outcome
		}
	case returnDomainPointer:
		switch {
		case expression == "NULL" || expression == "0":
			outcome.mask = outcomePointerNull
			return outcome
		case expression == "current" || expression == "get_current()":
			outcome.mask = outcomePointerValue
			return outcome
		case isPositiveIntegerConstant(expression):
			outcome.mask = outcomePointerValue
			return outcome
		case strings.HasPrefix(expression, "ERR_PTR("):
			if argument, ok := singleCallArgument(
				expression,
				"ERR_PTR",
			); ok {
				switch {
				case isExplicitNegativeError(argument):
					outcome.mask = outcomePointerError
					return outcome
				case compactExpression(argument) == "0":
					outcome.mask = outcomePointerNull
					return outcome
				}
				if !cyclic {
					argumentOutcome := constrainedOperandOutcome(
						fn,
						returnDomainSigned,
						argument,
						constraints,
						successfulCalls,
					)
					switch {
					case argumentOutcome.mask != 0 &&
						argumentOutcome.mask&^outcomeNegative == 0:
						outcome.mask = outcomePointerError
						return outcome
					case argumentOutcome.mask != 0 &&
						argumentOutcome.mask&^outcomeZero == 0:
						outcome.mask = outcomePointerNull
						return outcome
					case argumentOutcome.mask != 0 &&
						argumentOutcome.mask&^(outcomeNegative|outcomeZero) == 0:
						outcome.mask = outcomePointerError |
							outcomePointerNull
						return outcome
					}
				}
			}
			outcome.mask = outcomePointerError
			return outcome
		case strings.HasPrefix(expression, "ERR_CAST("):
			if argument, ok := singleCallArgument(
				expression,
				"ERR_CAST",
			); ok && !cyclic {
				argumentOutcome := constrainedOperandOutcome(
					fn,
					returnDomainPointer,
					argument,
					constraints,
					successfulCalls,
				)
				if argumentOutcome.mask != 0 {
					return argumentOutcome
				}
			}
		case isDefinitelyValidAddressExpression(expression):
			outcome.mask = outcomePointerValue
			return outcome
		}
	case returnDomainSigned, returnDomainUnsigned:
		if isExplicitNegativeError(expression) {
			if outcome.domain == returnDomainSigned {
				outcome.mask = outcomeNegative
				return outcome
			}
		}
		if bits, ok := unsignedLocalScalarBits(
			fn.Body,
			expression,
		); ok && (outcome.domain == returnDomainUnsigned ||
			fn.ReturnTypeBits > bits) {
			outcome.mask = outcomeZero | outcomePositive
			return outcome
		}
		if value, ok := signedIntegerConstant(expression); ok {
			switch {
			case value < 0 && outcome.domain == returnDomainSigned:
				outcome.mask = outcomeNegative
			case value == 0:
				outcome.mask = outcomeZero
			case value > 0:
				outcome.mask = outcomePositive
			default:
				return returnOutcome{}
			}
			return outcome
		}
		if argument, ok := singleCallArgument(
			expression,
			"PTR_ERR",
		); ok && outcome.domain == returnDomainSigned && !cyclic {
			argumentOutcome := constrainedOperandOutcome(
				fn,
				returnDomainPointer,
				argument,
				constraints,
				successfulCalls,
			)
			switch {
			case argumentOutcome.mask != 0 &&
				argumentOutcome.mask&^outcomePointerError == 0:
				outcome.mask = outcomeNegative
				return outcome
			case argumentOutcome.mask != 0 &&
				argumentOutcome.mask&^outcomePointerNull == 0:
				outcome.mask = outcomeZero
				return outcome
			case argumentOutcome.mask != 0 &&
				argumentOutcome.mask&^(outcomePointerError|outcomePointerNull) == 0:
				outcome.mask = outcomeNegative | outcomeZero
				return outcome
			}
		}
	}

	if !cyclic {
		appliedSuccessfulCall := false
		for _, constraint := range successfulCalls {
			constraintRequirement, applies :=
				successfulCallConstraintReturnRequirement(
					fn,
					expression,
					constraint,
				)
			if !applies {
				continue
			}
			if constraintRequirement == "" {
				constraintRequirement = requirement
			}
			if mask, ok := requirementMask(
				outcome.domain,
				constraintRequirement,
			); ok {
				outcome.mask &= mask
				appliedSuccessfulCall = true
			}
		}
		if appliedSuccessfulCall && outcome.mask == 0 {
			return outcome
		}
	}
	if cyclic ||
		!regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(
			expression,
		) {
		return outcome
	}
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			!cfgConstraintStableUntilReturn(
				fn,
				expression,
				constraint,
			) {
			continue
		}
		required := outcomeRequirementFromCondition(
			fn.ReturnType,
			constraint.expression,
			expression,
			constraint.required,
		)
		mask, ok := requirementMask(outcome.domain, required)
		if !ok {
			continue
		}
		outcome.mask &= mask
	}
	return outcome
}

func unsignedLocalScalarBits(
	body, expression string,
) (int, bool) {
	identifier := stripSimpleCasts(compactExpression(expression))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return 0, false
	}
	typePattern := `(?:` +
		`unsigned(?:\s+int)?|` +
		`unsigned\s+char|` +
		`unsigned\s+short(?:\s+int)?|` +
		`u8|u16|u32|u64|__u8|__u16|__u32|__u64` +
		`)`
	pattern := regexp.MustCompile(
		`(?m)(?:^|[;{}])\s*` +
			`(?:(?:const|volatile)\s+)*(` + typePattern + `)` +
			`\s+` + regexp.QuoteMeta(identifier) +
			`\s*(?:=[^;]*)?;`,
	)
	matches := pattern.FindAllStringSubmatch(body, -1)
	if len(matches) != 1 {
		return 0, false
	}
	switch strings.Join(strings.Fields(matches[0][1]), " ") {
	case "unsigned char", "u8", "__u8":
		return 8, true
	case "unsigned short", "unsigned short int", "u16", "__u16":
		return 16, true
	case "unsigned", "unsigned int", "u32", "__u32":
		return 32, true
	case "u64", "__u64":
		return 64, true
	default:
		return 0, false
	}
}

func constrainedOperandOutcome(
	fn *FunctionInfo,
	domain, operand string,
	constraints []successPathConstraint,
	successfulCalls []successfulCallConstraint,
) returnOutcome {
	if fn == nil {
		return returnOutcome{}
	}
	operand = stripSimpleCasts(compactExpression(operand))
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(operand) {
		return returnOutcome{}
	}
	returnType := domain
	outcome := fullReturnOutcome(returnType)
	if outcome.domain == returnDomainUnknown || outcome.mask == 0 {
		return returnOutcome{}
	}
	for _, constraint := range successfulCalls {
		if constraint.functionID != fn.ID ||
			constraint.resultVariable != operand ||
			constraint.requirement == "" {
			continue
		}
		mask, ok := requirementMask(
			outcome.domain,
			constraint.requirement,
		)
		if ok {
			outcome.mask &= mask
		}
	}
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID || !constraint.pathStable ||
			!expressionReferencesIdentifier(
				constraint.expression,
				operand,
			) {
			continue
		}
		requirement := outcomeRequirementFromCondition(
			returnType,
			constraint.expression,
			operand,
			constraint.required,
		)
		mask, ok := requirementMask(outcome.domain, requirement)
		if ok {
			outcome.mask &= mask
		}
	}
	return outcome
}

func ternarySelectionFromConstraints(
	fn *FunctionInfo,
	condition string,
	constraints []successPathConstraint,
) (bool, bool) {
	if fn == nil {
		return false, false
	}
	condition = normalizedBranchExpression(condition)
	if value, known := constantConditionValue(condition); known {
		return value, true
	}
	for index := len(constraints) - 1; index >= 0; index-- {
		constraint := constraints[index]
		if constraint.functionID != fn.ID || !constraint.pathStable {
			continue
		}
		if normalizedBranchExpression(constraint.expression) == condition {
			return constraint.required, true
		}
	}
	return false, false
}

func normalizedBranchExpression(expression string) string {
	expression = compactExpression(expression)
	for {
		unwrapped, ok := unwrapSingleCallWrapper(expression, "likely")
		if !ok {
			unwrapped, ok = unwrapSingleCallWrapper(
				expression,
				"unlikely",
			)
		}
		if !ok {
			return expression
		}
		expression = compactExpression(unwrapped)
	}
}

func singleCallArgument(
	expression, callee string,
) (string, bool) {
	expression = compactExpression(expression)
	prefix := callee + "("
	if !strings.HasPrefix(expression, prefix) {
		return "", false
	}
	closeParen, ok := findMatchingParenForward(
		maskStringAndCharLiterals(expression),
		len(callee),
	)
	if !ok || closeParen != len(expression)-1 {
		return "", false
	}
	arguments := splitTopLevelCommaList(
		expression[len(prefix):closeParen],
	)
	if len(arguments) != 1 {
		return "", false
	}
	return strings.TrimSpace(arguments[0]), true
}

func signedIntegerConstant(expression string) (int64, bool) {
	expression = strings.TrimSpace(strings.TrimRight(expression, "uUlL"))
	if expression == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(expression, 0, 64)
	return value, err == nil
}

func isPositiveIntegerConstant(expression string) bool {
	value, known := signedIntegerConstant(expression)
	return known && value > 0
}

func isDefinitelyValidAddressExpression(expression string) bool {
	return regexp.MustCompile(
		`^&[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(compactExpression(expression))
}

func stripSimpleCasts(expression string) string {
	for strings.HasPrefix(expression, "(") {
		closeParen, ok := findMatchingParenForward(expression, 0)
		if !ok || closeParen <= 1 || closeParen == len(expression)-1 {
			break
		}
		cast := strings.TrimSpace(expression[1:closeParen])
		if !regexp.MustCompile(
			`^(?:(?:const|volatile|signed|unsigned|long|short|struct|enum)\s+)*` +
				`[A-Za-z_][A-Za-z0-9_]*(?:\s*\*)*$`,
		).MatchString(cast) {
			break
		}
		expression = strings.TrimSpace(expression[closeParen+1:])
	}
	return expression
}

func outcomeRequirementFromCondition(
	returnType, condition, operand string,
	required bool,
) string {
	condition = normalizedBranchExpression(
		normalizeCondition(condition),
	)
	operand = compactExpression(operand)
	if condition == "" || operand == "" {
		return ""
	}
	if parts := splitTopLevelLogical(condition, "&&"); len(parts) > 1 && required {
		return combinedMandatoryOutcomeRequirement(
			returnType,
			operand,
			parts,
			true,
		)
	}
	if parts := splitTopLevelLogical(condition, "||"); len(parts) > 1 && !required {
		return combinedMandatoryOutcomeRequirement(
			returnType,
			operand,
			parts,
			false,
		)
	}
	if strings.HasPrefix(condition, "!") &&
		!strings.HasPrefix(condition, "!=") {
		return outcomeRequirementFromCondition(
			returnType,
			strings.TrimSpace(condition[1:]),
			operand,
			!required,
		)
	}
	compact := compactExpression(condition)
	quoted := regexp.QuoteMeta(operand)
	if regexp.MustCompile(`^IS_ERR\(` + quoted + `\)$`).MatchString(compact) {
		if required {
			return "error_pointer"
		}
		return "non_error_pointer"
	}
	if regexp.MustCompile(`^IS_ERR_OR_NULL\(` + quoted + `\)$`).MatchString(compact) {
		if required {
			return "null_or_error_pointer"
		}
		return "nonnull_valid_pointer"
	}
	if compact == operand {
		switch returnDomainForType(returnType) {
		case returnDomainPointer:
			if required {
				return "nonnull"
			}
			return "null"
		case returnDomainBool:
			if required {
				return "true"
			}
			return "false"
		case returnDomainSigned, returnDomainUnsigned:
			if required {
				return "nonzero"
			}
			return "zero"
		}
	}

	comparison := regexp.MustCompile(
		`^(.+?)(==|!=|<=|>=|<|>)(.+)$`,
	).FindStringSubmatch(compact)
	if len(comparison) != 4 {
		return ""
	}
	left, operator, right := comparison[1], comparison[2], comparison[3]
	if right == operand {
		left, right = right, left
		operator = reverseComparisonOperator(operator)
	}
	if left != operand {
		return ""
	}
	domain := returnDomainForType(returnType)
	if domain == returnDomainPointer {
		if right != "NULL" && right != "0" {
			return ""
		}
		switch {
		case operator == "==" && required,
			operator == "!=" && !required:
			return "null"
		case operator == "!=" && required,
			operator == "==" && !required:
			return "nonnull"
		default:
			return ""
		}
	}
	if domain == returnDomainBool {
		switch right {
		case "true", "1":
			if operator == "==" && required ||
				operator == "!=" && !required {
				return "true"
			}
			if operator == "!=" && required ||
				operator == "==" && !required {
				return "false"
			}
		case "false", "0":
			if operator == "==" && required ||
				operator == "!=" && !required {
				return "false"
			}
			if operator == "!=" && required ||
				operator == "==" && !required {
				return "true"
			}
		}
		return ""
	}
	if domain != returnDomainSigned && domain != returnDomainUnsigned ||
		right != "0" {
		return ""
	}
	switch operator {
	case "==":
		if required {
			return "zero"
		}
		return "nonzero"
	case "!=":
		if required {
			return "nonzero"
		}
		return "zero"
	case "<":
		if required {
			return "negative"
		}
		return "nonnegative"
	case ">=":
		if required {
			return "nonnegative"
		}
		return "negative"
	case ">":
		if required {
			return "positive"
		}
		return "nonpositive"
	case "<=":
		if required {
			return "nonpositive"
		}
		return "positive"
	default:
		return ""
	}
}

func combinedMandatoryOutcomeRequirement(
	returnType, operand string,
	conditions []string,
	required bool,
) string {
	domain := returnDomainForType(returnType)
	outcome := fullReturnOutcome(returnType)
	if domain == returnDomainUnknown || outcome.mask == 0 {
		return ""
	}
	mask := outcome.mask
	found := false
	for _, condition := range conditions {
		requirement := outcomeRequirementFromCondition(
			returnType,
			condition,
			operand,
			required,
		)
		if requirement == "" {
			continue
		}
		requiredMask, ok := requirementMask(
			domain,
			requirement,
		)
		if !ok {
			return ""
		}
		mask &= requiredMask
		found = true
	}
	if !found || mask == 0 {
		return ""
	}
	requirement, ok := requirementForOutcomeMask(domain, mask)
	if !ok {
		return ""
	}
	return requirement
}

func returnExpressionProvesSuccess(
	returnType, expression, requirement string,
) bool {
	if requirement == "" {
		requirement = defaultSuccessRequirement(returnType)
	}
	fn := &FunctionInfo{ReturnType: returnType}
	outcome := returnOutcomeFromExpression(
		fn,
		expression,
		nil,
		false,
		nil,
		requirement,
	)
	return returnOutcomeCompatibility(outcome, requirement) == "guaranteed"
}

func returnExpressionProvesSuccessOnCFGPath(
	fn *FunctionInfo,
	expression, requirement string,
	constraints []successPathConstraint,
) bool {
	if fn == nil {
		return false
	}
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	outcome := returnOutcomeFromExpression(
		fn,
		expression,
		constraints,
		false,
		nil,
		requirement,
	)
	return returnOutcomeCompatibility(outcome, requirement) == "guaranteed"
}

func cfgConstraintStableUntilReturn(
	fn *FunctionInfo,
	returnVariable string,
	constraint successPathConstraint,
) bool {
	if fn == nil || constraint.functionID != fn.ID ||
		!functionOwnsIdentifier(fn, returnVariable) {
		return false
	}
	if constraint.pathStable {
		return !cfgVariableHasUnpreservedEscape(
			fn,
			returnVariable,
		)
	}
	condition := strings.TrimSpace(constraint.expression)
	if condition == "" || strings.Count(fn.Body, condition) != 1 {
		return false
	}
	conditionStart := strings.Index(fn.Body, condition)
	if conditionStart < 0 {
		return false
	}
	returnPattern := regexp.MustCompile(
		`\breturn\s+` + regexp.QuoteMeta(returnVariable) + `\s*;`,
	)
	returnSites := returnPattern.FindAllStringIndex(fn.Body, -1)
	if len(returnSites) != 1 || conditionStart+len(condition) > returnSites[0][0] {
		return false
	}
	if regexp.MustCompile(
		`&\s*` + regexp.QuoteMeta(returnVariable) + `\b`,
	).MatchString(fn.Body[:returnSites[0][0]]) {
		return false
	}
	between := fn.Body[conditionStart+len(condition) : returnSites[0][0]]
	return !identifierMayBeModified(between, returnVariable)
}

func cfgVariableHasUnpreservedEscape(
	fn *FunctionInfo,
	identifier string,
) bool {
	return fn != nil &&
		containsString(fn.CFGEscapedVariables, identifier) &&
		!containsString(fn.CFGPreservedEscapes, identifier)
}

func functionOwnsIdentifier(
	fn *FunctionInfo,
	identifier string,
) bool {
	if containsString(fn.Parameters, identifier) {
		return true
	}
	pattern := regexp.MustCompile(
		`(?m)(?:^|[;{}])\s*` +
			`(?:(?:const|volatile|unsigned|signed|struct\s+[A-Za-z_][A-Za-z0-9_]*|` +
			`union\s+[A-Za-z_][A-Za-z0-9_]*|enum\s+[A-Za-z_][A-Za-z0-9_]*|` +
			`[A-Za-z_][A-Za-z0-9_]*)\s+)+` +
			`[^;{}()]*\b` + regexp.QuoteMeta(identifier) +
			`\s*(?:[=,;])`,
	)
	return pattern.MatchString(fn.Body)
}

func identifierMayBeModified(body, identifier string) bool {
	quoted := regexp.QuoteMeta(identifier)
	patterns := []string{
		`\b` + quoted + `\s*(?:\+\+|--|[+\-*/%&|^]?=)`,
		`(?:\+\+|--)\s*\b` + quoted + `\b`,
		`&\s*` + quoted + `\b`,
	}
	return matchesAny(body, patterns)
}

func reverseComparisonOperator(operator string) string {
	switch operator {
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">":
		return "<"
	case ">=":
		return "<="
	default:
		return operator
	}
}

func splitTopLevelLogical(expression, operator string) []string {
	masked := maskStringAndCharLiterals(expression)
	parts := make([]string, 0, 2)
	start := 0
	parenDepth := 0
	for index := 0; index+len(operator) <= len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		}
		if parenDepth == 0 &&
			strings.HasPrefix(masked[index:], operator) {
			parts = append(parts, strings.TrimSpace(expression[start:index]))
			index += len(operator) - 1
			start = index + 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	parts = append(parts, strings.TrimSpace(expression[start:]))
	return parts
}

func compatibleSuccessReturnTypes(parentType, childType string) bool {
	if parentType == childType {
		return true
	}
	return returnDomainForType(parentType) == returnDomainSigned &&
		returnDomainForType(childType) == returnDomainSigned
}

func compatibleSuccessReturnFunctions(
	parent, child *FunctionInfo,
) bool {
	if parent == nil || child == nil {
		return false
	}
	requirement := defaultSuccessRequirement(parent.ReturnType)
	if requirement != "" && requirementsCompatibleAcrossFunctions(
		parent,
		child,
		requirement,
	) {
		return true
	}
	return compatibleSuccessReturnTypes(
		parent.ReturnType,
		child.ReturnType,
	) &&
		(parent.ReturnTypeBits <= 0 ||
			child.ReturnTypeBits <= 0 ||
			parent.ReturnTypeBits >= child.ReturnTypeBits)
}

func (a *Analyzer) finalizeSuccessExitAlternatives(
	fn *FunctionInfo,
	block ClangCFGBlock,
	constants map[string]string,
	alternatives []lsmPathAlternative,
) []lsmPathAlternative {
	requirement := constants[contextReturnRequirementKey]
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	candidates := cloneLSMAlternatives(alternatives)
	result := make([]lsmPathAlternative, 0, len(candidates))
	for index := range candidates {
		if !successPathConstraintsConsistent(
			fn,
			candidates[index].bypassConstraints,
		) || !successfulCallConstraintsCompatibleWithPath(
			fn,
			candidates[index].bypassConstraints,
			candidates[index].bypassSuccessfulCalls,
			candidates[index].bypassValues,
		) {
			continue
		}
		outcome := returnOutcomeFromExpression(
			fn,
			resolveAssumedSuccessfulReturnExpression(
				fn,
				resolvedCFGConstantReturnExpression(
					substituteIdentifierConstants(
						strings.TrimSpace(
							clangCFGReturnExpression(block),
						),
						constants,
					),
					candidates[index].bypassValues,
				),
				constants,
				candidates[index].bypassConstraints,
			),
			candidates[index].bypassConstraints,
			candidates[index].bypassCyclic,
			candidates[index].bypassSuccessfulCalls,
			requirement,
		)
		if typedOutcome, ok := trackedCFGTypedReturnOutcome(
			fn,
			substituteIdentifierConstants(
				strings.TrimSpace(
					clangCFGReturnExpression(block),
				),
				constants,
			),
			candidates[index].bypassValues,
		); ok && typedOutcome.domain == outcome.domain {
			outcome.mask &= typedOutcome.mask
		}
		if outParameterOutcome, _, ok :=
			a.constrainedOutParameterReturnOutcome(
				fn,
				substituteIdentifierConstants(
					strings.TrimSpace(
						clangCFGReturnExpression(block),
					),
					constants,
				),
				candidates[index].bypassConstraints,
				candidates[index].bypassValues,
			); ok {
			outcome = outParameterOutcome
		}
		outcome = constrainReturnOutcomeByLLVMFunctionFacts(fn, outcome)
		compatibility := returnOutcomeCompatibility(outcome, requirement)
		if compatibility == "impossible" {
			continue
		}
		candidates[index].returnOutcome = outcome
		if len(candidates[index].hooks) > 0 ||
			candidates[index].unresolved {
			result = append(result, candidates[index])
			continue
		}
		witness := functionSuccessWitness{}
		if candidates[index].bypassDerivedEffect {
			witness = a.proveExplicitSuccessfulReturnBlock(
				fn,
				block,
				constants,
				candidates[index].bypassConstraints,
				candidates[index].bypassValues,
				candidates[index].bypassSuccessfulCalls,
			)
		} else {
			witness = a.proveSuccessfulReturnBlockAlongPathWithValues(
				fn,
				block,
				constants,
				make(map[string]bool),
				candidates[index].bypassConstraints,
				candidates[index].bypassCyclic,
				false,
				candidates[index].bypassSuccessfulCalls,
				candidates[index].bypassValues,
			)
			if !witness.proven && !candidates[index].bypassCyclic {
				witness = correlatedSuccessfulCallWitness(
					fn,
					block,
					resolvedCFGConstantReturnExpression(
						substituteIdentifierConstants(
							strings.TrimSpace(
								clangCFGReturnExpression(block),
							),
							constants,
						),
						candidates[index].bypassValues,
					),
					candidates[index].bypassSuccessfulCalls,
				)
			}
			if !witness.proven && compatibility == "guaranteed" {
				witness = functionSuccessWitness{
					proven: true,
					method: "return_outcome_constrained_success",
					path: []string{
						fmt.Sprintf(
							"%s#cfg-block-%d[outcome=%s]",
							fn.DisplayName,
							block.ID,
							returnOutcomeKey(outcome),
						),
					},
				}
			}
		}
		candidates[index].bypassPath = bypassProofPathAtBlock(
			candidates[index].bypassPath,
			fn.DisplayName,
			block.ID,
		)
		candidates[index].bypassSuccessProven = witness.proven
		candidates[index].bypassSuccessMethod = witness.method
		if witness.proven {
			candidates[index].bypassPath = uniqueStrings(append(
				candidates[index].bypassPath,
				witness.path...,
			))
		}
		result = append(result, candidates[index])
	}
	return canonicalLSMAlternatives(result)
}

func successfulExecutionUnprovenEdge(
	domain string,
	fn *FunctionInfo,
) UnresolvedProofEdge {
	return UnresolvedProofEdge{
		Domain:          domain,
		Caller:          fn.DisplayName,
		Kind:            "successful_execution_unproven",
		Category:        "success_value_or_path_feasibility",
		ResolutionScope: "implementation_improvable",
		Detail:          "a checkpoint-free path reaches a potential return, but a normal successful operation return is not proven",
	}
}

func certifiedEffectFreeLSMBypass(
	fn *FunctionInfo,
	witness functionSuccessWitness,
) lsmCoverageResult {
	alternatives := provenNonEnforcingLSMAlternatives(
		witness,
		fn.DisplayName,
	)
	return lsmCoverageResult{
		state:              "non_enforcing",
		alternatives:       alternatives,
		proofMethods:       []string{"cfg_effect_free_success_witness", witness.method},
		bypassProofPath:    firstLSMBypassPath(alternatives),
		bypassProofMethod:  witness.method,
		reasons:            []string{"a proven normal successful operation path bypasses every syscall-terminating LSM denial"},
		unresolved:         nil,
		coveredUnresolved:  nil,
		unprovenBypassPath: nil,
		hooks:              nil,
		proofFunctions:     nil,
		hookProofPaths:     nil,
	}
}

func certifiedEffectFreeSIGKILLBypass(
	fn *FunctionInfo,
	witness functionSuccessWitness,
) signalCoverageResult {
	alternatives := provenNonEnforcingLSMAlternatives(
		witness,
		fn.DisplayName,
	)
	return signalCoverageResult{
		state:              "non_enforcing",
		alternatives:       alternatives,
		proofMethods:       []string{"cfg_effect_free_success_witness", witness.method},
		bypassProofPath:    firstLSMBypassPath(alternatives),
		bypassProofMethod:  witness.method,
		reasons:            []string{"a proven normal successful operation path bypasses every effective current-task SIGKILL checkpoint"},
		unresolved:         nil,
		coveredUnresolved:  nil,
		unprovenBypassPath: nil,
		checks:             nil,
		proofFunctions:     nil,
		checkProofPaths:    nil,
		checkPaths:         nil,
	}
}

func applyCFGValueWritesToAlternatives(
	fn *FunctionInfo,
	block ClangCFGBlock,
	alternatives []lsmPathAlternative,
) []lsmPathAlternative {
	result := cloneLSMAlternatives(alternatives)
	for index := range result {
		if len(result[index].hooks) > 0 || result[index].unresolved {
			continue
		}
		if result[index].bypassCyclic {
			result[index].bypassValues = nil
			result[index].bypassConstraints =
				dropPathStableConstraints(
					result[index].bypassConstraints,
				)
			continue
		}
		values := cloneCFGPathValues(result[index].bypassValues)
		constraints := append(
			[]successPathConstraint(nil),
			result[index].bypassConstraints...,
		)
		for _, write := range block.ValueWrites {
			target := strings.TrimSpace(write.Target)
			if target == "" {
				continue
			}
			result[index].bypassSuccessfulCalls =
				successfulCallConstraintsAfterWrite(
					result[index].bypassSuccessfulCalls,
					target,
					write.CallSiteID,
				)
			previous := values[target]
			delete(values, target)
			constraints = dropConstraintsForIdentifier(
				constraints,
				target,
			)
			for name, value := range values {
				if !expressionReferencesIdentifier(
					value.expression,
					target,
				) {
					continue
				}
				delete(values, name)
				constraints = dropConstraintsForIdentifier(
					constraints,
					name,
				)
				result[index].bypassSuccessfulCalls =
					successfulCallConstraintsAfterWrite(
						result[index].bypassSuccessfulCalls,
						name,
						"",
					)
			}
			if fn == nil ||
				cfgVariableHasUnpreservedEscape(fn, target) ||
				write.Kind == "invalidate" ||
				!cfgValueRelevantToSuccess(fn, target) {
				continue
			}
			value, ok := trackedCFGPathValue(
				write,
				values,
				previous,
			)
			if ok {
				if values == nil {
					values = make(map[string]cfgPathValue)
				}
				values[target] = value
			}
		}
		values, constraints, result[index].bypassSuccessfulCalls =
			applyCFGOutParameterWrites(
				fn,
				block,
				values,
				constraints,
				result[index].bypassSuccessfulCalls,
			)
		if len(values) > 24 {
			values = nil
		}
		result[index].bypassValues = values
		result[index].bypassConstraints =
			canonicalSuccessPathConstraints(constraints)
	}
	return canonicalLSMAlternatives(result)
}

type cfgOutParameterWrite struct {
	callSiteID    string
	argumentIndex int
}

func applyCFGOutParameterWrites(
	fn *FunctionInfo,
	block ClangCFGBlock,
	values map[string]cfgPathValue,
	constraints []successPathConstraint,
	successfulCalls []successfulCallConstraint,
) (
	map[string]cfgPathValue,
	[]successPathConstraint,
	[]successfulCallConstraint,
) {
	if fn == nil || len(block.CallSiteIDs) == 0 {
		return values, constraints, successfulCalls
	}
	localWrites := make(map[string]bool)
	for _, write := range block.ValueWrites {
		localWrites[strings.TrimSpace(write.Target)] = true
	}
	candidates := make(map[string][]cfgOutParameterWrite)
	for _, callSiteID := range block.CallSiteIDs {
		site := clangCallSiteByID(fn, callSiteID)
		if site == nil || !site.Direct || !site.Reachable {
			continue
		}
		for argumentIndex, argument := range site.Arguments {
			identifier, ok := exactAddressedIdentifier(argument)
			if !ok || !functionOwnsIdentifier(fn, identifier) ||
				!cfgValueRelevantToSuccess(fn, identifier) {
				continue
			}
			candidates[identifier] = append(
				candidates[identifier],
				cfgOutParameterWrite{
					callSiteID:    site.ID,
					argumentIndex: argumentIndex,
				},
			)
		}
	}
	for target, writes := range candidates {
		delete(values, target)
		constraints = dropConstraintsForIdentifier(
			constraints,
			target,
		)
		successfulCalls = successfulCallConstraintsAfterWrite(
			successfulCalls,
			target,
			"",
		)
		for name, value := range values {
			if !expressionReferencesIdentifier(
				value.expression,
				target,
			) {
				continue
			}
			delete(values, name)
			constraints = dropConstraintsForIdentifier(
				constraints,
				name,
			)
			successfulCalls = successfulCallConstraintsAfterWrite(
				successfulCalls,
				name,
				"",
			)
		}
		if localWrites[target] || len(writes) != 1 {
			continue
		}
		if values == nil {
			values = make(map[string]cfgPathValue)
		}
		values[target] = cfgPathValue{
			callSiteID:        writes[0].callSiteID,
			outParameter:      true,
			outParameterIndex: writes[0].argumentIndex,
		}
	}
	return values, constraints, successfulCalls
}

func exactAddressedIdentifier(
	expression string,
) (string, bool) {
	expression = compactExpression(stripSimpleCasts(expression))
	if !strings.HasPrefix(expression, "&") {
		return "", false
	}
	identifier := stripSimpleCasts(
		strings.TrimPrefix(expression, "&"),
	)
	if !regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		return "", false
	}
	return identifier, true
}

func successfulCallConstraintsAfterWrite(
	constraints []successfulCallConstraint,
	target, callSiteID string,
) []successfulCallConstraint {
	result := make([]successfulCallConstraint, 0, len(constraints))
	for _, constraint := range constraints {
		if constraint.resultVariable != target ||
			callSiteID != "" && constraint.callSiteID == callSiteID {
			result = append(result, constraint)
		}
	}
	return canonicalSuccessfulCallConstraints(result)
}

func cfgValueRelevantToSuccess(
	fn *FunctionInfo,
	target string,
) bool {
	if fn == nil || target == "" {
		return false
	}
	relevant := make(map[string]bool)
	writeTargets := make(map[string]bool)
	for _, block := range fn.CFGBlocks {
		for _, write := range block.ValueWrites {
			if candidate := strings.TrimSpace(write.Target); candidate != "" {
				writeTargets[candidate] = true
			}
		}
	}
	for _, block := range fn.CFGBlocks {
		expression := stripSimpleCasts(
			compactExpression(clangCFGReturnExpression(block)),
		)
		if identifier, ok := exactCFGValueDependency(expression); ok {
			relevant[identifier] = true
		}
		for candidate := range writeTargets {
			if expressionReferencesIdentifier(expression, candidate) {
				relevant[candidate] = true
			}
		}
	}
	for _, site := range fn.CallSites {
		if site.ResultVariable == "" {
			continue
		}
		for _, block := range fn.CFGBlocks {
			if expressionReferencesIdentifier(
				block.TerminatorCondition,
				site.ResultVariable,
			) {
				relevant[site.ResultVariable] = true
				break
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, block := range fn.CFGBlocks {
			for _, write := range block.ValueWrites {
				if !relevant[strings.TrimSpace(write.Target)] {
					continue
				}
				dependency, ok := exactCFGValueDependency(
					write.Expression,
				)
				if !ok || relevant[dependency] {
					continue
				}
				relevant[dependency] = true
				changed = true
			}
		}
	}
	return relevant[target]
}

func exactCFGValueDependency(
	expression string,
) (string, bool) {
	expression = stripSimpleCasts(compactExpression(expression))
	if regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(expression) {
		return expression, true
	}
	for _, wrapper := range []string{"PTR_ERR", "ERR_PTR", "ERR_CAST"} {
		argument, ok := singleCallArgument(expression, wrapper)
		if !ok {
			continue
		}
		identifier := stripSimpleCasts(compactExpression(argument))
		if regexp.MustCompile(
			`^[A-Za-z_][A-Za-z0-9_]*$`,
		).MatchString(identifier) {
			return identifier, true
		}
	}
	return "", false
}

func trackedCFGPathValue(
	write ClangCFGValueWrite,
	values map[string]cfgPathValue,
	previous cfgPathValue,
) (cfgPathValue, bool) {
	expression := strings.TrimSpace(write.Expression)
	if expression == "" {
		return cfgPathValue{}, false
	}
	if write.CallSiteID == "" {
		expanded := strings.TrimSpace(write.ExpressionExpanded)
		if isTrackableCFGConstant(expression) &&
			isTrackableCFGConstant(expanded) {
			expression = expanded
		}
	}
	constants := make(map[string]string)
	for name, value := range values {
		if value.callSiteID == "" &&
			isTrackableCFGConstant(value.expression) {
			constants[name] = value.expression
		}
	}
	expression = substituteIdentifierConstants(expression, constants)
	if write.CallSiteID != "" {
		_, arguments, ok := directReturnedCall(expression)
		if !ok {
			return cfgPathValue{}, false
		}
		lineage := make([]cfgPathCallStep, 0)
		sourceArgument := -1
		for index, argument := range arguments {
			identifier := stripSimpleCasts(
				compactExpression(argument),
			)
			var source cfgPathValue
			switch {
			case identifier == strings.TrimSpace(write.Target):
				source = previous
			case values != nil:
				source = values[identifier]
			}
			if len(source.lineage) == 0 {
				continue
			}
			if sourceArgument >= 0 {
				lineage = nil
				sourceArgument = -1
				break
			}
			lineage = append(
				lineage,
				source.lineage...,
			)
			sourceArgument = index
		}
		lineage = append(lineage, cfgPathCallStep{
			expression:     expression,
			callSiteID:     write.CallSiteID,
			sourceArgument: sourceArgument,
		})
		return typedCFGPathValue(cfgPathValue{
			expression: expression,
			callSiteID: write.CallSiteID,
			lineage:    lineage,
		}, write, values, previous), true
	}
	if identifier := stripSimpleCasts(
		compactExpression(expression),
	); regexp.MustCompile(
		`^[A-Za-z_][A-Za-z0-9_]*$`,
	).MatchString(identifier) {
		if identifier != strings.TrimSpace(write.Target) {
			value := cfgPathValue{expression: identifier}
			if source, ok := values[identifier]; ok {
				value.runtimeZeroSuccess =
					source.runtimeZeroSuccess
				value.runtimeSuccessKind =
					source.runtimeSuccessKind
				switch {
				case len(source.lineage) > 0:
					value.lineage = append(
						[]cfgPathCallStep(nil),
						source.lineage...,
					)
				case source.callSiteID != "":
					if _, _, direct := directReturnedCall(
						source.expression,
					); direct {
						value.lineage = []cfgPathCallStep{{
							expression:     source.expression,
							callSiteID:     source.callSiteID,
							sourceArgument: -1,
						}}
					}
				}
			}
			return typedCFGPathValue(
				value,
				write,
				values,
				previous,
			), true
		}
	}
	if kind, ok := kernelUserAccessWriteSuccessContract(write); ok {
		return typedCFGPathValue(
			cfgPathValue{
				expression:         expression,
				runtimeZeroSuccess: true,
				runtimeSuccessKind: kind,
			},
			write,
			values,
			previous,
		), true
	}
	if write.SourceDefinitelyValidPointer &&
		write.TargetTypeClass == "pointer" {
		return typedCFGPathValue(
			cfgPathValue{expression: expression},
			write,
			values,
			previous,
		), true
	}
	if isTrackableCFGSymbolicValue(expression, values) {
		return typedCFGPathValue(
			cfgPathValue{expression: expression},
			write,
			values,
			previous,
		), true
	}
	if cfgTypeMetadataProvesNonnegative(write) {
		return typedCFGPathValue(
			cfgPathValue{expression: expression},
			write,
			values,
			previous,
		), true
	}
	if !isTrackableCFGConstant(expression) {
		return cfgPathValue{}, false
	}
	return typedCFGPathValue(
		cfgPathValue{expression: expression},
		write,
		values,
		previous,
	), true
}

func kernelUserAccessWriteSuccessContract(
	write ClangCFGValueWrite,
) (string, bool) {
	callee, arguments, direct := directReturnedCall(
		write.Expression,
	)
	if !direct || len(arguments) != 2 {
		return "", false
	}
	expanded := write.ExpressionExpanded
	switch callee {
	case "put_user", "__put_user":
		return callee,
			strings.Contains(expanded, "__ret_pu") &&
				strings.Contains(expanded, "__put_user_")
	case "get_user", "__get_user":
		return callee,
			strings.Contains(expanded, "__ret_gu") &&
				strings.Contains(expanded, "__get_user_")
	default:
		return "", false
	}
}

func typedCFGPathValue(
	value cfgPathValue,
	write ClangCFGValueWrite,
	values map[string]cfgPathValue,
	previous cfgPathValue,
) cfgPathValue {
	value.typeClass = write.TargetTypeClass
	value.typeSigned = write.TargetTypeSigned
	value.typeBits = write.TargetTypeBits

	sourceNonnegative := write.SourceDefinitelyNonnegative ||
		write.SourceTypeClass == "unsigned_integer" ||
		write.SourceTypeClass == "bool"
	sourceBits := write.SourceTypeBits
	sourceExpression := stripSimpleCasts(
		compactExpression(write.Expression),
	)
	if source, ok := values[sourceExpression]; ok {
		sourceNonnegative = source.provenNonnegative ||
			source.typeClass == "unsigned_integer" ||
			source.typeClass == "bool"
		value.provenValidPointer =
			source.provenValidPointer
		if source.typeBits > 0 {
			sourceBits = source.typeBits
		}
	}
	if sourceExpression == strings.TrimSpace(write.Target) &&
		previous.provenNonnegative {
		sourceNonnegative = true
		if previous.typeBits > 0 {
			sourceBits = previous.typeBits
		}
	}
	if constant, ok := signedIntegerConstant(sourceExpression); ok &&
		constant >= 0 {
		sourceNonnegative = true
	}
	if write.TargetTypeClass == "pointer" &&
		write.SourceDefinitelyValidPointer {
		value.provenValidPointer = true
	}

	switch write.TargetTypeClass {
	case "unsigned_integer", "bool":
		value.provenNonnegative = true
	case "signed_integer":
		value.provenNonnegative =
			write.SourceDefinitelyNonnegative ||
				sourceNonnegative &&
					sourceBits > 0 &&
					write.TargetTypeBits > sourceBits
	}
	return value
}

func cfgTypeMetadataProvesNonnegative(
	write ClangCFGValueWrite,
) bool {
	switch write.TargetTypeClass {
	case "unsigned_integer", "bool":
		return true
	case "signed_integer":
		return write.SourceDefinitelyNonnegative ||
			(write.SourceTypeClass == "unsigned_integer" ||
				write.SourceTypeClass == "bool") &&
				write.SourceTypeBits > 0 &&
				write.TargetTypeBits > write.SourceTypeBits
	default:
		return false
	}
}

func isTrackableCFGSymbolicValue(
	expression string,
	values map[string]cfgPathValue,
) bool {
	for _, wrapper := range []string{"PTR_ERR", "ERR_PTR", "ERR_CAST"} {
		argument, ok := singleCallArgument(expression, wrapper)
		if !ok {
			continue
		}
		identifier := stripSimpleCasts(compactExpression(argument))
		if !regexp.MustCompile(
			`^[A-Za-z_][A-Za-z0-9_]*$`,
		).MatchString(identifier) {
			return false
		}
		_, tracked := values[identifier]
		return tracked
	}
	return false
}

func isTrackableCFGConstant(expression string) bool {
	expression = stripSimpleCasts(strings.TrimSpace(expression))
	if expression == "NULL" || expression == "true" ||
		expression == "false" ||
		isDefinitelyValidAddressExpression(expression) {
		return true
	}
	if isExplicitNegativeError(expression) {
		return true
	}
	if _, ok := signedIntegerConstant(expression); ok {
		return true
	}
	if strings.HasPrefix(expression, "ERR_PTR(") {
		argument, ok := singleCallArgument(expression, "ERR_PTR")
		return ok && (isExplicitNegativeError(argument) ||
			compactExpression(argument) == "0")
	}
	return false
}

func dropConstraintsForIdentifier(
	constraints []successPathConstraint,
	identifier string,
) []successPathConstraint {
	result := make([]successPathConstraint, 0, len(constraints))
	for _, constraint := range constraints {
		if expressionReferencesIdentifier(
			constraint.expression,
			identifier,
		) {
			continue
		}
		result = append(result, constraint)
	}
	return result
}

func dropPathStableConstraints(
	constraints []successPathConstraint,
) []successPathConstraint {
	result := make([]successPathConstraint, 0, len(constraints))
	for _, constraint := range constraints {
		if !constraint.pathStable {
			result = append(result, constraint)
		}
	}
	return result
}

func expressionReferencesIdentifier(
	expression, identifier string,
) bool {
	if expression == "" || identifier == "" {
		return false
	}
	return regexp.MustCompile(
		`\b` + regexp.QuoteMeta(identifier) + `\b`,
	).MatchString(expression)
}

func successSuccessorsForConstants(
	block ClangCFGBlock,
	constants map[string]string,
) []int {
	edges := successSuccessorEdgesForConstants(block, constants)
	result := make([]int, 0, len(edges))
	for _, edge := range edges {
		result = append(result, edge.blockID)
	}
	return result
}

type cfgSuccessEdge struct {
	blockID int
	branch  string
}

func allCFGSuccessorEdges(
	block ClangCFGBlock,
) []cfgSuccessEdge {
	result := make([]cfgSuccessEdge, 0, len(block.Successors))
	for index, successor := range block.Successors {
		branch := "unconditional"
		if len(block.SuccessorBranches) == len(block.Successors) {
			branch = block.SuccessorBranches[index]
		} else if block.TerminatorCondition != "" {
			switch index {
			case 0:
				branch = "true"
			case 1:
				branch = "false"
			default:
				branch = "unknown"
			}
		}
		result = append(result, cfgSuccessEdge{
			blockID: successor,
			branch:  branch,
		})
	}
	return result
}

type cfgExplorationPriority struct {
	localEffects    int
	effectCalls     int
	unresolvedCalls int
	indirectCalls   int
	successExit     int
	directCalls     int
	calleeCost      int
	blockCost       int
}

func (left cfgExplorationPriority) less(
	right cfgExplorationPriority,
) bool {
	switch {
	case left.localEffects != right.localEffects:
		return left.localEffects < right.localEffects
	case left.effectCalls != right.effectCalls:
		return left.effectCalls < right.effectCalls
	case left.unresolvedCalls != right.unresolvedCalls:
		return left.unresolvedCalls < right.unresolvedCalls
	case left.indirectCalls != right.indirectCalls:
		return left.indirectCalls < right.indirectCalls
	case left.successExit != right.successExit:
		return left.successExit < right.successExit
	case left.directCalls != right.directCalls:
		return left.directCalls < right.directCalls
	case left.calleeCost != right.calleeCost:
		return left.calleeCost < right.calleeCost
	default:
		return left.blockCost < right.blockCost
	}
}

func (a *Analyzer) prioritizedSuccessSuccessorEdges(
	fn *FunctionInfo,
	blocks map[int]ClangCFGBlock,
	block ClangCFGBlock,
	constants map[string]string,
	domain string,
) []cfgSuccessEdge {
	edges := successSuccessorEdgesForConstants(block, constants)
	if len(edges) < 2 {
		return edges
	}
	type rankedEdge struct {
		edge     cfgSuccessEdge
		priority cfgExplorationPriority
	}
	ranked := make([]rankedEdge, 0, len(edges))
	for _, edge := range edges {
		ranked = append(ranked, rankedEdge{
			edge: edge,
			priority: a.cfgBlockExplorationPriority(
				fn,
				blocks[edge.blockID],
				domain,
			),
		})
	}
	sort.SliceStable(ranked, func(left, right int) bool {
		return ranked[left].priority.less(ranked[right].priority)
	})
	result := make([]cfgSuccessEdge, 0, len(ranked))
	for _, candidate := range ranked {
		result = append(result, candidate.edge)
	}
	return result
}

func (a *Analyzer) prioritizedCFGQueueIndex(
	fn *FunctionInfo,
	blocks map[int]ClangCFGBlock,
	queue []int,
	domain string,
) int {
	bestIndex := 0
	bestPriority := a.cfgBlockExplorationPriority(
		fn,
		blocks[queue[0]],
		domain,
	)
	for index := 1; index < len(queue); index++ {
		priority := a.cfgBlockExplorationPriority(
			fn,
			blocks[queue[index]],
			domain,
		)
		if priority.less(bestPriority) {
			bestIndex = index
			bestPriority = priority
		}
	}
	return bestIndex
}

func (a *Analyzer) cfgBlockExplorationPriority(
	fn *FunctionInfo,
	block ClangCFGBlock,
	domain string,
) cfgExplorationPriority {
	priority := cfgExplorationPriority{
		successExit: 1,
		blockCost: len(block.ValueWrites) +
			len(block.SuccessSuccessors),
	}
	if block.PotentialSuccessExit {
		priority.successExit = 0
	}
	if len(block.CallSiteIDs) == 0 {
		priority.indirectCalls = len(block.IndirectCalls)
	}
	switch domain {
	case "lsm":
		priority.localEffects = len(block.LSMHooks)
	case "sigkill":
		priority.localEffects = len(block.SignalChecks)
	}
	addCall := func(name string) {
		if name == "" {
			priority.unresolvedCalls++
			return
		}
		if domain == "lsm" && strings.HasPrefix(name, "security_") ||
			domain == "sigkill" && isSignalCheckName(name) {
			priority.localEffects++
			return
		}
		priority.directCalls++
		ids, status := a.resolveCallee(fn, name)
		if status != "resolved" || len(ids) != 1 {
			priority.unresolvedCalls++
			return
		}
		child := a.functions[ids[0]]
		if child == nil {
			priority.unresolvedCalls++
			return
		}
		switch domain {
		case "lsm":
			if a.lsmEffectSourceState(child.ID) != effectSourceNone {
				priority.effectCalls++
			}
		case "sigkill":
			if a.signalEffectSourceState(child.ID) != effectSourceNone {
				priority.effectCalls++
			}
		}
		priority.calleeCost += 1 +
			len(child.CFGBlocks)*4 +
			len(child.CallSites)*2 +
			len(child.CFGReachableCalls)
	}
	if len(block.CallSiteIDs) > 0 {
		for _, callSiteID := range block.CallSiteIDs {
			site := clangCallSiteByID(fn, callSiteID)
			if site == nil {
				priority.unresolvedCalls++
				continue
			}
			if !site.Direct {
				priority.indirectCalls++
				continue
			}
			addCall(site.Name)
		}
		return priority
	}
	for _, name := range filterInternalCallees(block.Calls) {
		addCall(name)
	}
	return priority
}

func successSuccessorEdgesForConstants(
	block ClangCFGBlock,
	constants map[string]string,
) []cfgSuccessEdge {
	if block.TerminatorCondition == "" ||
		len(block.SuccessSuccessorBranches) != len(block.SuccessSuccessors) {
		result := make([]cfgSuccessEdge, 0, len(block.SuccessSuccessors))
		for _, successor := range block.SuccessSuccessors {
			result = append(result, cfgSuccessEdge{
				blockID: successor,
				branch:  "unknown",
			})
		}
		return result
	}
	condition := substituteIdentifierConstants(block.TerminatorCondition, constants)
	value, known := constantConditionValue(condition)
	if !known {
		result := make([]cfgSuccessEdge, 0, len(block.SuccessSuccessors))
		for index, successor := range block.SuccessSuccessors {
			result = append(result, cfgSuccessEdge{
				blockID: successor,
				branch:  block.SuccessSuccessorBranches[index],
			})
		}
		return result
	}
	required := "false"
	if value {
		required = "true"
	}
	result := make([]cfgSuccessEdge, 0, len(block.SuccessSuccessors))
	for index, successor := range block.SuccessSuccessors {
		branch := block.SuccessSuccessorBranches[index]
		if branch == "unconditional" || branch == "unknown" || branch == required {
			result = append(result, cfgSuccessEdge{
				blockID: successor,
				branch:  branch,
			})
		}
	}
	return result
}

func (a *Analyzer) constrainAlternativesForCFGEdge(
	alternatives []lsmPathAlternative,
	fn *FunctionInfo,
	block ClangCFGBlock,
	edge cfgSuccessEdge,
) []lsmPathAlternative {
	result := cloneLSMAlternatives(alternatives)
	cyclicEdge := a.cfgEdgeParticipatesInCycle(
		fn,
		block.ID,
		edge.blockID,
	)
	for index := range result {
		if len(result[index].hooks) > 0 {
			continue
		}
		if cyclicEdge {
			result[index].bypassCyclic = true
		}
	}
	if fn == nil || block.TerminatorCondition == "" ||
		edge.branch != "true" && edge.branch != "false" {
		return canonicalLSMAlternatives(result)
	}
	required := edge.branch == "true"
	constrainsReturn := cfgBranchMayConstrainFunctionReturn(
		fn,
		block.TerminatorCondition,
		required,
	)
	for index := range result {
		if len(result[index].hooks) > 0 {
			continue
		}
		if !constrainsReturn &&
			!cfgBranchConstrainsTrackedCallValue(
				fn,
				block.TerminatorCondition,
				required,
				result[index].bypassValues,
			) &&
			!cfgBranchConstrainsSuccessfulCallValue(
				fn,
				block.TerminatorCondition,
				required,
				result[index].bypassSuccessfulCalls,
			) {
			continue
		}
		constraint := successPathConstraint{
			functionID: fn.ID,
			blockID:    block.ID,
			expression: strings.TrimSpace(block.TerminatorCondition),
			required:   required,
			pathStable: true,
		}
		for _, existing := range result[index].bypassConstraints {
			if existing.functionID == constraint.functionID &&
				existing.blockID == constraint.blockID {
				result[index].bypassCyclic = true
				break
			}
		}
		result[index].bypassConstraints = canonicalSuccessPathConstraints(
			append(result[index].bypassConstraints, constraint),
		)
		result[index].bypassPath = uniqueStrings(append(
			result[index].bypassPath,
			fmt.Sprintf(
				"%s#cfg-block-%d[%s=%t]",
				fn.DisplayName,
				block.ID,
				compactExpression(constraint.expression),
				constraint.required,
			),
		))
	}
	return feasibleLSMAlternativesForPath(result, fn)
}

func feasibleLSMAlternativesForPath(
	alternatives []lsmPathAlternative,
	fn *FunctionInfo,
) []lsmPathAlternative {
	result := make([]lsmPathAlternative, 0, len(alternatives))
	for _, alternative := range alternatives {
		if !successPathConstraintsConsistent(
			fn,
			alternative.bypassConstraints,
		) || !successfulCallConstraintsCompatibleWithPath(
			fn,
			alternative.bypassConstraints,
			alternative.bypassSuccessfulCalls,
			alternative.bypassValues,
		) {
			continue
		}
		result = append(result, alternative)
	}
	return canonicalLSMAlternatives(result)
}

func successPathConstraintsConsistent(
	fn *FunctionInfo,
	constraints []successPathConstraint,
) bool {
	if fn == nil {
		return true
	}
	seen := make(map[string]bool)
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID {
			continue
		}
		key := fmt.Sprintf(
			"%d\x00%s",
			constraint.blockID,
			normalizedBranchExpression(constraint.expression),
		)
		if previous, ok := seen[key]; ok &&
			previous != constraint.required {
			return false
		}
		seen[key] = constraint.required
	}
	return true
}

func successfulCallConstraintsCompatibleWithPath(
	fn *FunctionInfo,
	pathConstraints []successPathConstraint,
	callConstraints []successfulCallConstraint,
	values map[string]cfgPathValue,
) bool {
	if fn == nil {
		return true
	}
	for _, callConstraint := range callConstraints {
		if callConstraint.functionID != fn.ID ||
			callConstraint.resultVariable == "" ||
			callConstraint.requirement == "" {
			continue
		}
		returnType := callConstraint.returnType
		if returnType == "" {
			if site := clangCallSiteByID(
				fn,
				callConstraint.callSiteID,
			); site != nil {
				returnType = site.ReturnType
			}
		}
		domain := returnDomainForType(returnType)
		mask, ok := requirementMask(
			domain,
			callConstraint.requirement,
		)
		if !ok {
			continue
		}
		for _, pathConstraint := range pathConstraints {
			if pathConstraint.functionID != fn.ID ||
				!expressionReferencesIdentifier(
					pathConstraint.expression,
					callConstraint.resultVariable,
				) {
				continue
			}
			requirement := outcomeRequirementFromCondition(
				returnType,
				pathConstraint.expression,
				callConstraint.resultVariable,
				pathConstraint.required,
			)
			if requirement == "" {
				continue
			}
			requiredMask, known := requirementMask(domain, requirement)
			if !known {
				continue
			}
			mask &= requiredMask
		}
		if value, tracked := values[callConstraint.resultVariable]; tracked {
			switch {
			case value.callSiteID == callConstraint.callSiteID:
			case value.callSiteID != "":
				continue
			case isTrackableCFGConstant(value.expression):
				valueOutcome := returnOutcomeFromExpression(
					&FunctionInfo{ReturnType: returnType},
					value.expression,
					nil,
					false,
					nil,
					"",
				)
				if valueOutcome.domain == domain {
					mask &= valueOutcome.mask
				}
			}
		}
		if mask == 0 {
			return false
		}
	}
	return true
}

func (a *Analyzer) cfgEdgeParticipatesInCycle(
	fn *FunctionInfo,
	from, to int,
) bool {
	if fn == nil {
		return false
	}
	key := fmt.Sprintf("%s\x00%d\x00%d", fn.ID, from, to)
	if a.cfgCycleEdgeCache == nil {
		a.cfgCycleEdgeCache = make(map[string]bool)
	}
	if result, ok := a.cfgCycleEdgeCache[key]; ok {
		return result
	}
	if from == to {
		a.cfgCycleEdgeCache[key] = true
		return true
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	queue := []int{to}
	visited := map[int]bool{to: true}
	result := false
	for len(queue) > 0 {
		blockID := queue[0]
		queue = queue[1:]
		if blockID == from {
			result = true
			break
		}
		block, ok := blocks[blockID]
		if !ok {
			continue
		}
		for _, successor := range block.SuccessSuccessors {
			if successor == fn.CFGExit || visited[successor] {
				continue
			}
			visited[successor] = true
			queue = append(queue, successor)
		}
	}
	a.cfgCycleEdgeCache[key] = result
	return result
}

func canonicalSuccessPathConstraints(
	values []successPathConstraint,
) []successPathConstraint {
	result := append([]successPathConstraint(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].functionID != result[right].functionID {
			return result[left].functionID < result[right].functionID
		}
		if result[left].blockID != result[right].blockID {
			return result[left].blockID < result[right].blockID
		}
		if result[left].expression != result[right].expression {
			return result[left].expression < result[right].expression
		}
		if result[left].pathStable != result[right].pathStable {
			return !result[left].pathStable && result[right].pathStable
		}
		return !result[left].required && result[right].required
	})
	compacted := result[:0]
	for _, value := range result {
		if len(compacted) > 0 {
			previous := compacted[len(compacted)-1]
			if previous == value {
				continue
			}
		}
		compacted = append(compacted, value)
	}
	return compacted
}

func successPathConstraintKey(
	values []successPathConstraint,
	cyclic bool,
) string {
	return canonicalSuccessPathConstraintKey(
		canonicalSuccessPathConstraints(values),
		cyclic,
	)
}

func canonicalSuccessPathConstraintKey(
	values []successPathConstraint,
	cyclic bool,
) string {
	parts := make([]string, 0, len(values)+1)
	if cyclic {
		parts = append(parts, "cyclic")
	}
	for _, value := range values {
		parts = append(parts, fmt.Sprintf(
			"%s:%d:%t:%t:%s",
			value.functionID,
			value.blockID,
			value.required,
			value.pathStable,
			compactExpression(value.expression),
		))
	}
	return strings.Join(parts, "\x1f")
}

func canonicalSuccessfulCallConstraints(
	values []successfulCallConstraint,
) []successfulCallConstraint {
	result := append([]successfulCallConstraint(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].functionID != result[right].functionID {
			return result[left].functionID < result[right].functionID
		}
		if result[left].callSiteID != result[right].callSiteID {
			return result[left].callSiteID < result[right].callSiteID
		}
		if result[left].callee != result[right].callee {
			return result[left].callee < result[right].callee
		}
		if result[left].resultVariable != result[right].resultVariable {
			return result[left].resultVariable < result[right].resultVariable
		}
		if result[left].returnType != result[right].returnType {
			return result[left].returnType < result[right].returnType
		}
		if result[left].requirement != result[right].requirement {
			return result[left].requirement < result[right].requirement
		}
		if result[left].callerRequirement != result[right].callerRequirement {
			return result[left].callerRequirement <
				result[right].callerRequirement
		}
		if result[left].provenCalleeSuccess !=
			result[right].provenCalleeSuccess {
			return !result[left].provenCalleeSuccess
		}
		if result[left].certifiesCallerSuccess !=
			result[right].certifiesCallerSuccess {
			return !result[left].certifiesCallerSuccess
		}
		return result[left].method < result[right].method
	})
	compacted := result[:0]
	for _, value := range result {
		if len(compacted) > 0 && compacted[len(compacted)-1] == value {
			continue
		}
		compacted = append(compacted, value)
	}
	return compacted
}

func successfulCallConstraintKey(
	values []successfulCallConstraint,
) string {
	return canonicalSuccessfulCallConstraintKey(
		canonicalSuccessfulCallConstraints(values),
	)
}

func canonicalSuccessfulCallConstraintKey(
	values []successfulCallConstraint,
) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strings.Join(
			[]string{
				value.functionID,
				value.callSiteID,
				value.callee,
				value.resultVariable,
				value.returnType,
				value.requirement,
				value.callerRequirement,
				strconv.FormatBool(value.provenCalleeSuccess),
				strconv.FormatBool(value.certifiesCallerSuccess),
				value.method,
			},
			"\x1e",
		))
	}
	return strings.Join(parts, "\x1f")
}

func successConstraintProofPath(
	fn *FunctionInfo,
	values []successPathConstraint,
) []string {
	result := make([]string, 0, len(values))
	for _, value := range canonicalSuccessPathConstraints(values) {
		if fn == nil || value.functionID != fn.ID {
			continue
		}
		result = append(result, fmt.Sprintf(
			"%s#cfg-block-%d[%s=%t]",
			fn.DisplayName,
			value.blockID,
			compactExpression(value.expression),
			value.required,
		))
	}
	return result
}

type successConstraintPathState struct {
	blockID     int
	constraints []successPathConstraint
	values      map[string]cfgPathValue
	visited     map[int]bool
	cyclic      bool
}

func successConstraintPathStates(
	fn *FunctionInfo,
	constants map[string]string,
) []successConstraintPathState {
	if fn == nil {
		return nil
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	if _, ok := blocks[fn.CFGEntry]; !ok {
		return nil
	}
	queue := []successConstraintPathState{{
		blockID: fn.CFGEntry,
		visited: map[int]bool{fn.CFGEntry: true},
	}}
	result := make([]successConstraintPathState, 0)
	seen := make(map[string][]map[int]bool)
	admitCFGVisitedState(
		seen,
		fmt.Sprintf("%d\x00\x00", fn.CFGEntry),
		map[int]bool{fn.CFGEntry: true},
	)
	const maxSuccessConstraintStates = 4096
	for len(queue) > 0 && len(seen) < maxSuccessConstraintStates {
		state := queue[0]
		queue = queue[1:]
		block := blocks[state.blockID]
		valueState := applyCFGValueWritesToAlternatives(
			fn,
			block,
			[]lsmPathAlternative{{
				bypassConstraints: state.constraints,
				bypassValues:      state.values,
				bypassCyclic:      state.cyclic,
			}},
		)
		if len(valueState) != 1 {
			continue
		}
		state.constraints = valueState[0].bypassConstraints
		state.values = valueState[0].bypassValues
		if block.PotentialSuccessExit {
			result = append(result, state)
		}
		for _, edge := range successSuccessorEdgesForConstants(
			block,
			constants,
		) {
			if edge.blockID == fn.CFGExit {
				continue
			}
			if _, ok := blocks[edge.blockID]; !ok || state.visited[edge.blockID] {
				continue
			}
			next := successConstraintPathState{
				blockID: edge.blockID,
				constraints: append(
					[]successPathConstraint(nil),
					state.constraints...,
				),
				visited: make(map[int]bool, len(state.visited)+1),
				cyclic:  state.cyclic,
				values:  cloneCFGPathValues(state.values),
			}
			for blockID := range state.visited {
				next.visited[blockID] = true
			}
			next.visited[edge.blockID] = true
			if block.TerminatorCondition != "" &&
				(edge.branch == "true" || edge.branch == "false") &&
				(cfgBranchMayConstrainFunctionReturn(
					fn,
					block.TerminatorCondition,
					edge.branch == "true",
				) || cfgBranchConstrainsTrackedCallValue(
					fn,
					block.TerminatorCondition,
					edge.branch == "true",
					state.values,
				)) {
				next.constraints = canonicalSuccessPathConstraints(append(
					next.constraints,
					successPathConstraint{
						functionID: fn.ID,
						blockID:    block.ID,
						expression: strings.TrimSpace(
							block.TerminatorCondition,
						),
						required:   edge.branch == "true",
						pathStable: true,
					},
				))
			}
			key := fmt.Sprintf(
				"%d\x00%s\x00%s",
				next.blockID,
				successPathConstraintKey(next.constraints, next.cyclic),
				cfgPathValuesKey(next.values),
			)
			if !admitCFGVisitedState(
				seen,
				key,
				next.visited,
			) {
				continue
			}
			queue = append(queue, next)
		}
	}
	return result
}

func admitCFGVisitedState(
	seen map[string][]map[int]bool,
	key string,
	visited map[int]bool,
) bool {
	states := seen[key]
	for _, existing := range states {
		if cfgVisitedSetSubset(existing, visited) {
			return false
		}
	}
	filtered := states[:0]
	for _, existing := range states {
		if cfgVisitedSetSubset(visited, existing) {
			continue
		}
		filtered = append(filtered, existing)
	}
	filtered = append(filtered, cloneBoolMap(visited))
	seen[key] = filtered
	return true
}

func cfgVisitedSetSubset(
	left, right map[int]bool,
) bool {
	if len(left) > len(right) {
		return false
	}
	for blockID := range left {
		if !right[blockID] {
			return false
		}
	}
	return true
}

func cloneBoolMap(values map[int]bool) map[int]bool {
	result := make(map[int]bool, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cfgBranchMayConstrainFunctionReturn(
	fn *FunctionInfo,
	condition string,
	required bool,
) bool {
	if fn == nil || strings.TrimSpace(condition) == "" {
		return false
	}
	for _, block := range fn.CFGBlocks {
		if !block.PotentialSuccessExit {
			continue
		}
		for _, returnExpression := range clangCFGReturnExpressions(block) {
			if ternaryCondition, _, _, ok := splitTopLevelTernary(
				strings.TrimSpace(returnExpression),
			); ok &&
				normalizedBranchExpression(ternaryCondition) ==
					normalizedBranchExpression(condition) {
				return true
			}
		}
		expression := stripSimpleCasts(
			compactExpression(clangCFGReturnExpression(block)),
		)
		if !regexp.MustCompile(
			`^[A-Za-z_][A-Za-z0-9_]*$`,
		).MatchString(expression) ||
			cfgVariableHasUnpreservedEscape(fn, expression) ||
			!functionOwnsIdentifier(fn, expression) {
			continue
		}
		if outcomeRequirementFromCondition(
			fn.ReturnType,
			condition,
			expression,
			required,
		) != "" {
			return true
		}
	}
	return false
}

func cfgBranchConstrainsTrackedCallValue(
	fn *FunctionInfo,
	condition string,
	required bool,
	values map[string]cfgPathValue,
) bool {
	for identifier, value := range values {
		if value.callSiteID == "" ||
			!expressionReferencesIdentifier(condition, identifier) {
			continue
		}
		site := clangCallSiteByID(fn, value.callSiteID)
		if !callSiteMatchesTrackedResult(site, identifier) {
			continue
		}
		if outcomeRequirementFromCondition(
			site.ReturnType,
			condition,
			identifier,
			required,
		) != "" || conditionComparesSignedOperandToConstant(
			site.ReturnType,
			condition,
			identifier,
		) {
			return true
		}
	}
	return false
}

func conditionComparesSignedOperandToConstant(
	returnType, condition, operand string,
) bool {
	if returnDomainForType(returnType) != returnDomainSigned {
		return false
	}
	condition = normalizedBranchExpression(condition)
	operand = compactExpression(operand)
	comparison := regexp.MustCompile(
		`^(.+?)(==|!=|<=|>=|<|>)(.+)$`,
	).FindStringSubmatch(compactExpression(condition))
	if len(comparison) != 4 {
		return false
	}
	left, right := comparison[1], comparison[3]
	if right == operand {
		left, right = right, left
	}
	if left != operand {
		return false
	}
	_, known := signedIntegerConstant(right)
	return known
}

func cfgBranchConstrainsSuccessfulCallValue(
	fn *FunctionInfo,
	condition string,
	required bool,
	constraints []successfulCallConstraint,
) bool {
	for _, constraint := range constraints {
		if constraint.functionID != fn.ID ||
			constraint.resultVariable == "" ||
			!expressionReferencesIdentifier(
				condition,
				constraint.resultVariable,
			) {
			continue
		}
		returnType := constraint.returnType
		if returnType == "" {
			if site := clangCallSiteByID(
				fn,
				constraint.callSiteID,
			); site != nil {
				returnType = site.ReturnType
			}
		}
		if outcomeRequirementFromCondition(
			returnType,
			condition,
			constraint.resultVariable,
			required,
		) != "" {
			return true
		}
	}
	return false
}

func cfgBlockByID(
	fn *FunctionInfo,
	blockID int,
) (ClangCFGBlock, bool) {
	if fn == nil {
		return ClangCFGBlock{}, false
	}
	for _, block := range fn.CFGBlocks {
		if block.ID == blockID {
			return block, true
		}
	}
	return ClangCFGBlock{}, false
}

func clangCFGReturnExpression(block ClangCFGBlock) string {
	if strings.TrimSpace(block.ReturnExpressionExpanded) != "" {
		return block.ReturnExpressionExpanded
	}
	return block.ReturnExpression
}

func clangCFGReturnExpressions(block ClangCFGBlock) []string {
	result := make([]string, 0, 2)
	for _, expression := range []string{
		clangCFGReturnExpression(block),
		block.ReturnExpression,
		block.ReturnExpressionExpanded,
	} {
		expression = strings.TrimSpace(expression)
		if expression == "" || containsString(result, expression) {
			continue
		}
		result = append(result, expression)
	}
	return result
}

func clangCallSiteByID(
	fn *FunctionInfo,
	callSiteID string,
) *ClangCallSite {
	if fn == nil || callSiteID == "" {
		return nil
	}
	for index := range fn.CallSites {
		if fn.CallSites[index].ID == callSiteID {
			return &fn.CallSites[index]
		}
	}
	return nil
}

func (a *Analyzer) analyzeLSMPathCoverage(start string) lsmCoverageResult {
	return a.analyzeFunctionLSMCoverage(start, nil, nil, make(map[string]bool))
}

func (a *Analyzer) analyzeFunctionLSMCoverage(
	functionID string,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) lsmCoverageResult {
	fn := a.functions[functionID]
	if fn == nil {
		return lsmCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedLSMAlternatives(),
			reasons:      []string{"function is not indexed: " + functionID},
			unresolved: []UnresolvedProofEdge{{
				Domain: "lsm",
				Caller: functionID,
				Kind:   "function_unresolved",
				Detail: "the function required by LSM path coverage is not indexed",
			}},
		}
	}
	cacheKey := functionContextKey(fn, constants) + operationContextKey(operationContext)
	if cached, ok := a.lsmCoverageCache[cacheKey]; ok {
		return cached
	}
	if a.lsmEffectSourceState(functionID) == effectSourceNone {
		witness := a.proveFunctionSuccessfulExecution(
			functionID,
			constants,
			make(map[string]bool),
		)
		result := lsmCoverageResult{
			state:        "uncertain",
			alternatives: nonEnforcingLSMAlternatives(fn.DisplayName),
			proofMethods: []string{"closed_effect_source_absence"},
			reasons: []string{
				"the closed function cone contains no syscall-terminating LSM denial source, but a normal successful operation return is not proven",
			},
			unresolved: []UnresolvedProofEdge{
				successfulExecutionUnprovenEdge("lsm", fn),
			},
			unprovenBypassPath: []string{fn.DisplayName},
		}
		if witness.proven {
			result.state = "non_enforcing"
			result.alternatives = provenNonEnforcingLSMAlternatives(
				witness,
				fn.DisplayName,
			)
			result.proofMethods = []string{
				"closed_effect_source_absence",
				witness.method,
			}
			result.bypassProofPath = firstLSMBypassPath(result.alternatives)
			result.bypassProofMethod = witness.method
			result.unprovenBypassPath = nil
			result.reasons = []string{
				"a proven normal successful operation path has no syscall-terminating LSM denial source",
			}
			result.unresolved = nil
		}
		a.lsmCoverageCache[cacheKey] = result
		return result
	}
	if active[cacheKey] {
		return lsmCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedLSMAlternatives(),
			reasons:      []string{"recursive LSM coverage cycle: " + fn.DisplayName},
			unresolved: []UnresolvedProofEdge{{
				Domain: "lsm",
				Caller: fn.DisplayName,
				Kind:   "recursive_coverage_cycle",
				Detail: "the recursive cycle has no independently established coverage summary",
			}},
		}
	}
	if fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete || len(fn.CFGBlocks) == 0 || !fn.CFGHasSuccessExit {
		reason := "complete Clang CFG with a potential success exit is required"
		result := lsmCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedLSMAlternatives(),
			reasons:      []string{fn.DisplayName + ": " + reason},
			unresolved: []UnresolvedProofEdge{{
				Domain: "lsm",
				Caller: fn.DisplayName,
				Kind:   "cfg_incomplete",
				Detail: reason,
			}},
		}
		a.lsmCoverageCache[cacheKey] = result
		return result
	}
	if fn.FrontendVariantConflict {
		result := lsmCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedLSMAlternatives(),
			reasons:      []string{fn.DisplayName + ": translation-unit variants have different CFG facts"},
			unresolved: []UnresolvedProofEdge{{
				Domain: "lsm",
				Caller: fn.DisplayName,
				Kind:   "translation_unit_variant_conflict",
				Detail: "coverage is not guessed across differing translation-unit variants",
			}},
		}
		a.lsmCoverageCache[cacheKey] = result
		return result
	}
	if witness := a.proveEffectFreeSuccessfulExecution(
		functionID,
		constants,
		operationContext,
		"lsm",
		make(map[string]bool),
	); witness.proven {
		result := certifiedEffectFreeLSMBypass(fn, witness)
		a.lsmCoverageCache[cacheKey] = result
		return result
	}

	active[cacheKey] = true
	defer delete(active, cacheKey)
	body := substituteIdentifierConstants(fn.Body, constants)

	blockByID := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blockByID[block.ID] = block
	}
	if _, ok := blockByID[fn.CFGEntry]; !ok {
		result := lsmCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedLSMAlternatives(),
			reasons:      []string{fn.DisplayName + ": CFG entry block is missing"},
		}
		a.lsmCoverageCache[cacheKey] = result
		return result
	}

	initialAlternatives := nonEnforcingLSMAlternatives(fn.DisplayName)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	unplacedSites := make(map[string]ClangCallSite)
	for _, site := range fn.CallSites {
		if containsString(fn.CFGUnplacedCallSites, site.ID) {
			unplacedSites[site.ID] = site
		}
	}
	for _, siteID := range fn.CFGUnplacedCallSites {
		site, ok := unplacedSites[siteID]
		if !ok {
			continue
		}
		var coverage lsmCoverageEvent
		symbol := site.Name
		switch {
		case site.Direct && strings.HasPrefix(site.Name, "security_"):
			coverage = a.localLSMCoverageEventForBody(fn, body, site.Name)
		case site.Direct && !isSignalCheckName(site.Name):
			coverage = a.directCallLSMCoverageEvent(
				fn,
				body,
				site.Name,
				&site,
				constants,
				operationContext,
				active,
			)
		case !site.Direct:
			coverage = lsmCoverageEvent{
				states:       lsmPathUnresolved,
				alternatives: unresolvedLSMAlternatives(),
			}
			symbol = site.Expression
		default:
			continue
		}
		if coverage.states == lsmPathNonEnforcing {
			continue
		}
		initialAlternatives = unresolvedLSMAlternatives()
		reasons.add(fn.DisplayName + ": unplaced CFG callsite " + siteID)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain: "lsm",
			Caller: fn.DisplayName,
			Kind:   "cfg_event_unplaced",
			Symbol: symbol,
			Detail: "the event cannot be assigned to one CFG block without guessing",
		})
	}
	if len(fn.CFGUnplacedCallSites) == 0 {
		for _, event := range fn.CFGUnplacedEvents {
			if strings.HasPrefix(event, "signal:") {
				continue
			}
			symbol := strings.TrimPrefix(event, "call:")
			if strings.HasPrefix(event, "call:") && !strings.HasPrefix(event, "call:security_") {
				coverage := a.directCallLSMCoverageEvent(
					fn,
					body,
					symbol,
					nil,
					constants,
					operationContext,
					active,
				)
				if coverage.states == lsmPathNonEnforcing {
					continue
				}
			}
			initialAlternatives = unresolvedLSMAlternatives()
			reasons.add(fn.DisplayName + ": unplaced CFG event " + event)
			unresolved = append(unresolved, UnresolvedProofEdge{
				Domain: "lsm",
				Caller: fn.DisplayName,
				Kind:   "cfg_event_unplaced",
				Symbol: symbol,
				Detail: "the event cannot be assigned to one CFG block without guessing",
			})
		}
	}

	inAlternatives := map[int][]lsmPathAlternative{
		fn.CFGEntry: initialAlternatives,
	}
	outAlternatives := make(map[int][]lsmPathAlternative)
	exitAlternativesByBlock := make(map[int][]lsmPathAlternative)
	queue := []int{fn.CFGEntry}
	queued := map[int]bool{fn.CFGEntry: true}
	hooks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	hookProofPaths := make(map[string][]string)

	for len(queue) > 0 {
		nextIndex := a.prioritizedCFGQueueIndex(
			fn,
			blockByID,
			queue,
			"lsm",
		)
		blockID := queue[nextIndex]
		queue = append(queue[:nextIndex], queue[nextIndex+1:]...)
		delete(queued, blockID)
		block, ok := blockByID[blockID]
		if !ok {
			continue
		}
		alternatives := cloneLSMAlternatives(inAlternatives[blockID])
		if !allPathAlternativesEnforcing(alternatives) {
			a.visitLSMCoverageEventsForBlock(
				fn,
				body,
				block,
				constants,
				operationContext,
				active,
				func(event lsmCoverageEvent) bool {
					alternatives = sequenceLSMAlternatives(
						alternatives,
						eventLSMAlternatives(event),
					)
					hooks.addAll(event.hooks)
					proofFunctions.addAll(event.proofFunctions)
					mergeHookProofPaths(hookProofPaths, event.hookProofPaths)
					reasons.addAll(event.reasons)
					unresolved = append(unresolved, event.unresolved...)
					return !allPathAlternativesEnforcing(alternatives)
				},
			)
		}
		alternatives = applyCFGValueWritesToAlternatives(
			fn,
			block,
			alternatives,
		)
		if block.PotentialSuccessExit {
			exitAlternatives := a.finalizeSuccessExitAlternatives(
				fn,
				block,
				constants,
				alternatives,
			)
			exitAlternativesByBlock[block.ID] = exitAlternatives
			if classifySuccessExitLSMAlternatives(exitAlternatives) ==
				"non_enforcing" {
				result := lsmCoverageResult{
					state:           "non_enforcing",
					hooks:           hooks.slice(),
					alternatives:    exitAlternatives,
					proofMethods:    []string{"clang_cfg_bypass_witness", "early_exit_short_circuit"},
					proofFunctions:  proofFunctions.slice(),
					hookProofPaths:  hookProofPaths,
					bypassProofPath: firstLSMBypassPath(exitAlternatives),
					bypassProofMethod: firstLSMBypassMethod(
						exitAlternatives,
					),
					reasons:           []string{"at least one modeled feasible success path bypasses every syscall-terminating LSM denial"},
					coveredUnresolved: sortedProofGaps(uniqueProofEdges(unresolved)),
				}
				a.lsmCoverageCache[cacheKey] = result
				return result
			}
		}
		if lsmAlternativesEqual(outAlternatives[blockID], alternatives) {
			continue
		}
		outAlternatives[blockID] = alternatives
		for _, edge := range a.prioritizedSuccessSuccessorEdges(
			fn,
			blockByID,
			block,
			constants,
			"lsm",
		) {
			if edge.blockID == fn.CFGExit {
				continue
			}
			edgeAlternatives := a.constrainAlternativesForCFGEdge(
				alternatives,
				fn,
				block,
				edge,
			)
			next := mergeLSMAlternatives(
				inAlternatives[edge.blockID],
				edgeAlternatives,
			)
			if lsmAlternativesEqual(next, inAlternatives[edge.blockID]) {
				continue
			}
			inAlternatives[edge.blockID] = next
			if !queued[edge.blockID] {
				queue = append(queue, edge.blockID)
				queued[edge.blockID] = true
			}
		}
	}

	exitAlternatives := make([]lsmPathAlternative, 0)
	for _, block := range fn.CFGBlocks {
		if !block.PotentialSuccessExit {
			continue
		}
		exitAlternatives = mergeLSMAlternatives(
			exitAlternatives,
			exitAlternativesByBlock[block.ID],
		)
	}
	unprovenBypassPath := firstUnprovenLSMBypassPath(exitAlternatives)
	if len(unprovenBypassPath) > 0 {
		reasons.add(fn.DisplayName + ": a checkpoint-free potential return is not proven to be a normal successful operation return")
		unresolved = append(
			unresolved,
			successfulExecutionUnprovenEdge("lsm", fn),
		)
	}
	result := lsmCoverageResult{
		state:           classifySuccessExitLSMAlternatives(exitAlternatives),
		hooks:           hooks.slice(),
		alternatives:    canonicalLSMAlternatives(exitAlternatives),
		proofMethods:    []string{"clang_cfg_coverage"},
		proofFunctions:  proofFunctions.slice(),
		hookProofPaths:  hookProofPaths,
		bypassProofPath: firstLSMBypassPath(exitAlternatives),
		bypassProofMethod: firstLSMBypassMethod(
			exitAlternatives,
		),
		unprovenBypassPath: unprovenBypassPath,
		reasons:            reasons.slice(),
		unresolved:         sortedProofGaps(uniqueProofEdges(unresolved)),
	}
	if result.state == "enforcing" {
		result.coveredUnresolved = result.unresolved
		result.reasons = nil
		result.unresolved = nil
	} else if result.state == "non_enforcing" {
		result.proofMethods = uniqueStrings([]string{
			"clang_cfg_bypass_witness",
			result.bypassProofMethod,
		})
		result.reasons = []string{"at least one modeled feasible success path bypasses every syscall-terminating LSM denial"}
		result.coveredUnresolved = result.unresolved
		result.unresolved = nil
	} else if len(exitAlternatives) == 0 {
		result.reasons = uniqueStrings(append(result.reasons, fn.DisplayName+": no modeled potential-success exit was reachable"))
	} else if len(result.reasons) == 0 {
		result.reasons = []string{fn.DisplayName + ": success exits contain enforcing and unresolved path states without a certified bypass"}
	}
	a.lsmCoverageCache[cacheKey] = result
	return result
}

func (a *Analyzer) visitLSMCoverageEventsForBlock(
	fn *FunctionInfo,
	body string,
	block ClangCFGBlock,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
	visit func(lsmCoverageEvent) bool,
) {
	if len(block.CallSiteIDs) > 0 {
		byID := make(map[string]ClangCallSite, len(fn.CallSites))
		for _, site := range fn.CallSites {
			byID[site.ID] = site
		}
		for _, callSiteID := range block.CallSiteIDs {
			site, ok := byID[callSiteID]
			if !ok {
				if !visit(lsmCoverageEvent{
					states:       lsmPathUnresolved,
					alternatives: unresolvedLSMAlternatives(),
					reasons: []string{
						fn.DisplayName + ": CFG callsite record is missing: " + callSiteID,
					},
					unresolved: []UnresolvedProofEdge{{
						Domain: "lsm",
						Caller: fn.DisplayName,
						Kind:   "cfg_callsite_missing",
						Symbol: callSiteID,
						Detail: "the CFG refers to a callsite that is absent from the Clang callsite index",
					}},
				}) {
					return
				}
				continue
			}
			event, relevant := a.lsmCoverageEventForCallSite(
				fn,
				body,
				site,
				constants,
				operationContext,
				active,
			)
			if relevant && !visit(event) {
				return
			}
		}
		return
	}

	hookSet := make(map[string]struct{}, len(block.LSMHooks))
	for _, hook := range block.LSMHooks {
		hookSet[hook] = struct{}{}
		if !visit(a.localLSMCoverageEventForBody(fn, body, hook)) {
			return
		}
	}
	for _, callee := range filterInternalCallees(block.Calls) {
		if _, hook := hookSet[callee]; hook || strings.HasPrefix(callee, "security_") {
			continue
		}
		if !visit(a.directCallLSMCoverageEvent(
			fn,
			body,
			callee,
			nil,
			constants,
			operationContext,
			active,
		)) {
			return
		}
	}
	for _, expression := range block.IndirectCalls {
		effect := a.analyzeIndirectCallErrorEffect(fn, body, expression)
		if effect.blocksOperation == "no" || effect.errnoPropagation == "ignored" {
			continue
		}
		if invocation, ok := findIndirectInvocation(body, expression); ok &&
			a.indirectTargetSetClosedWithContext(fn, invocation, operationContext, constants) {
			if !visit(a.closedIndirectLSMCoverageEvent(
				fn,
				body,
				invocation,
				nil,
				constants,
				operationContext,
				active,
			)) {
				return
			}
			continue
		}
		if !visit(lsmCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedLSMAlternatives(),
			reasons: []string{
				fn.DisplayName + ": indirect call may affect LSM denial propagation: " + expression,
			},
			unresolved: []UnresolvedProofEdge{{
				Domain:     "lsm",
				Caller:     fn.DisplayName,
				Kind:       "indirect_coverage_edge_unresolved",
				Expression: expression,
				Detail:     "strict coverage does not assume a complete runtime function-pointer target set",
			}},
		}) {
			return
		}
	}
}

func (a *Analyzer) lsmCoverageEventForCallSite(
	fn *FunctionInfo,
	body string,
	site ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) (lsmCoverageEvent, bool) {
	if site.Direct {
		if strings.HasPrefix(site.Name, "security_") {
			return a.localLSMCoverageEventForBody(fn, body, site.Name), true
		}
		if isSignalCheckName(site.Name) ||
			len(filterInternalCallees([]string{site.Name})) == 0 {
			return lsmCoverageEvent{}, false
		}
		return a.directCallLSMCoverageEvent(
			fn,
			body,
			site.Name,
			&site,
			constants,
			operationContext,
			active,
		), true
	}
	if site.ResultUse == "discarded" {
		return lsmCoverageEvent{}, false
	}
	effect := a.analyzeIndirectCallErrorEffect(fn, body, site.Expression)
	if effect.blocksOperation == "no" || effect.errnoPropagation == "ignored" {
		return lsmCoverageEvent{}, false
	}
	if invocation, ok := findIndirectInvocation(body, site.Expression); ok &&
		a.indirectTargetSetClosedWithContext(fn, invocation, operationContext, constants) {
		return a.closedIndirectLSMCoverageEvent(
			fn,
			body,
			invocation,
			&site,
			constants,
			operationContext,
			active,
		), true
	}
	return lsmCoverageEvent{
		states:       lsmPathUnresolved,
		alternatives: unresolvedLSMAlternatives(),
		reasons: []string{
			fn.DisplayName + ": indirect call may affect LSM denial propagation: " + site.Expression,
		},
		unresolved: []UnresolvedProofEdge{{
			Domain:     "lsm",
			Caller:     fn.DisplayName,
			Kind:       "indirect_coverage_edge_unresolved",
			Expression: site.Expression,
			Detail:     "strict coverage does not assume a complete runtime function-pointer target set",
		}},
	}, true
}

func findIndirectInvocation(body, expression string) (indirectCallInvocation, bool) {
	normalized := normalizeIndirectExpression(expression)
	invocations := completeIndirectInvocations(
		body,
		extractIndirectInvocations(body),
		[]string{expression},
	)
	for _, invocation := range invocations {
		candidate := invocation.expression
		if candidate == "" {
			candidate = invocation.fallback
		}
		if normalizeIndirectExpression(candidate) == normalized {
			return invocation, true
		}
	}
	return indirectCallInvocation{}, false
}

func (a *Analyzer) closedIndirectLSMCoverageEvent(
	fn *FunctionInfo,
	body string,
	invocation indirectCallInvocation,
	site *ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) lsmCoverageEvent {
	targets := a.resolveIndirectInvocationWithContext(
		fn,
		invocation,
		operationContext,
		constants,
	)
	if len(targets) == 0 {
		return lsmCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedLSMAlternatives(),
			reasons: []string{
				fn.DisplayName + ": closed indirect table contains no modeled callable target",
			},
		}
	}
	targetStates := uint8(0)
	hooks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	hookProofPaths := make(map[string][]string)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	targetAlternatives := make([]lsmPathAlternative, 0)
	for _, target := range targets {
		callee := a.functions[target.functionID]
		if callee == nil {
			targetAlternatives = mergeLSMAlternatives(
				targetAlternatives,
				unresolvedLSMAlternatives(),
			)
			continue
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			callee,
			target.arguments,
			site,
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			callee,
			requiredIndirectCallReturnForSite(
				fn,
				callee,
				body,
				site,
				constants[contextReturnRequirementKey],
			),
		)
		nextOperationContext := extendOperationContext(
			operationContext,
			target.evidence,
		)
		if witness := a.proveEffectFreeSuccessfulExecution(
			target.functionID,
			childConstants,
			nextOperationContext,
			"lsm",
			make(map[string]bool),
		); witness.proven {
			targetAlternatives = mergeLSMAlternatives(
				targetAlternatives,
				provenNonEnforcingLSMAlternatives(
					witness,
					callee.DisplayName,
				),
			)
			continue
		}
		child := a.analyzeFunctionLSMCoverage(
			target.functionID,
			childConstants,
			nextOperationContext,
			active,
		)
		targetAlternatives = mergeLSMAlternatives(
			targetAlternatives,
			projectChildAlternativesForCaller(child.alternatives),
		)
		switch child.state {
		case "enforcing":
			targetStates |= lsmPathEnforcing
		case "non_enforcing":
			targetStates |= lsmPathNonEnforcing
		default:
			targetStates |= lsmPathUnresolved
		}
		hooks.addAll(child.hooks)
		proofFunctions.addAll(child.proofFunctions)
		for hook, path := range child.hookProofPaths {
			extended := append(append([]string(nil), path...), fn.DisplayName)
			mergeHookProofPaths(hookProofPaths, map[string][]string{hook: extended})
		}
		reasons.addAll(child.reasons)
		unresolved = append(unresolved, child.unresolved...)
	}
	expression := invocation.expression
	if expression == "" {
		expression = invocation.fallback
	}
	edgeEffect := a.analyzeIndirectCallErrorEffect(fn, body, expression)
	targetAlternatives = composeLSMAlternativesWithEdge(
		targetAlternatives,
		edgeEffect,
		fn.DisplayName,
	)
	targetStates = lsmStatesForAlternatives(targetAlternatives)
	if targetStates&lsmPathUnresolved != 0 {
		reasons.add(fn.DisplayName + ": closed indirect callee denial propagation is unresolved: " + expression)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain:     "lsm",
			Caller:     fn.DisplayName,
			Kind:       "closed_indirect_denial_propagation_unresolved",
			Expression: expression,
			Detail:     "the target set is closed, but at least one denial-propagation alternative remains unresolved",
		})
	}
	if targetStates&lsmPathEnforcing != 0 {
		proofFunctions.add(fn.DisplayName)
	}
	return lsmCoverageEvent{
		states:         targetStates,
		hooks:          hooks.slice(),
		alternatives:   targetAlternatives,
		proofFunctions: proofFunctions.slice(),
		hookProofPaths: hookProofPaths,
		reasons:        reasons.slice(),
		unresolved:     uniqueProofEdges(unresolved),
	}
}

func (a *Analyzer) localLSMCoverageEventForBody(
	fn *FunctionInfo,
	body, hook string,
) lsmCoverageEvent {
	if !a.isConfiguredLSMHookActive(hook) {
		return lsmCoverageEvent{
			states:       lsmPathNonEnforcing,
			alternatives: nonEnforcingLSMAlternatives(fn.DisplayName),
		}
	}
	effect := a.localLSMErrorEffectForBody(fn, body, hook)
	kind := a.classifyLSMHookKind(hook, effect)
	if kind == "notification" || effect.blocksOperation == "no" || effect.terminatesSyscall == "no" || effect.errnoPropagation == "ignored" {
		return lsmCoverageEvent{
			states:       lsmPathNonEnforcing,
			alternatives: nonEnforcingLSMAlternatives(hook, fn.DisplayName),
		}
	}
	verification := classifyLLVMVerification(a.llvmFactsForHook(fn, hook))
	if kind == "error-return" &&
		effect.blocksOperation == "guaranteed" &&
		effect.terminatesSyscall == "guaranteed" &&
		effect.errnoPropagation != "unknown" &&
		effect.errnoPropagation != "ignored" &&
		verification != "contradicted_ignored" {
		return lsmCoverageEvent{
			states:         lsmPathEnforcing,
			hooks:          []string{hook},
			alternatives:   enforcingLSMAlternatives(hook),
			proofFunctions: []string{fn.DisplayName},
			hookProofPaths: map[string][]string{
				hook: {hook, fn.DisplayName},
			},
		}
	}
	if kind == "error-return" &&
		classifySignalAbortEffect(effect) == "conditional" &&
		verification != "contradicted_ignored" {
		return lsmCoverageEvent{
			states: lsmPathEnforcing | lsmPathNonEnforcing,
			hooks:  []string{hook},
			alternatives: mergeLSMAlternatives(
				enforcingLSMAlternatives(hook),
				[]lsmPathAlternative{{
					bypassPath: uniqueStrings(
						[]string{hook, fn.DisplayName},
					),
					bypassDerivedEffect: true,
				}},
			),
			proofFunctions: []string{fn.DisplayName},
			hookProofPaths: map[string][]string{
				hook: {hook, fn.DisplayName},
			},
		}
	}
	return lsmCoverageEvent{
		states:       lsmPathUnresolved,
		alternatives: unresolvedLSMAlternatives(),
		reasons: []string{
			fn.DisplayName + ": LSM denial effect is unresolved for " + hook,
		},
		unresolved: []UnresolvedProofEdge{{
			Domain: "lsm",
			Caller: fn.DisplayName,
			Kind:   "lsm_denial_effect_unresolved",
			Symbol: hook,
			Detail: "the hook result is present but operation blocking and syscall termination are not both proven",
		}},
	}
}

func (a *Analyzer) localLSMErrorEffectForBody(
	fn *FunctionInfo,
	body, hook string,
) localErrorEffect {
	contextual := *fn
	contextual.Body = body
	effect := a.analyzeNamedCallErrorEffect(&contextual, body, hook)
	if classifySignalAbortEffect(effect) != "unknown" {
		return effect
	}
	kind := a.mapCallFailureToFunctionReturn(
		&contextual,
		hook,
		failureReturnErrno,
	)
	if kind == failureReturnUnknown || kind == failureReturnNone {
		return effect
	}
	return guaranteedEncodedLocalErrorEffect("exact", kind, nil)
}

func (a *Analyzer) directCallLSMCoverageEvent(
	fn *FunctionInfo,
	body, callee string,
	site *ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) lsmCoverageEvent {
	if site != nil && site.ResultUse == "discarded" {
		return lsmCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: nonEnforcingLSMAlternatives(
				fn.DisplayName,
			),
			proofFunctions: []string{fn.DisplayName},
		}
	}
	if a.llvmCallCannotContainEffectSource(fn, callee) {
		return lsmCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: a.sourceFreeCallAlternatives(
				fn,
				body,
				callee,
				site,
				constants,
				nil,
			),
		}
	}
	ids, status := a.resolveCallee(fn, callee)
	if (status == "resolved" || status == "ambiguous") && len(ids) > 0 {
		sourceFree := true
		for _, id := range ids {
			if a.lsmEffectSourceState(id) != effectSourceNone {
				sourceFree = false
				break
			}
		}
		if sourceFree {
			return lsmCoverageEvent{
				states: lsmPathNonEnforcing,
				alternatives: a.sourceFreeCallAlternatives(
					fn,
					body,
					callee,
					site,
					constants,
					ids,
				),
			}
		}
	}
	edgeEffect := a.analyzeNamedCallErrorEffect(fn, body, callee)
	if edgeEffect.blocksOperation == "no" || edgeEffect.terminatesSyscall == "no" || edgeEffect.errnoPropagation == "ignored" {
		return lsmCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: a.sourceFreeCallAlternatives(
				fn,
				body,
				callee,
				site,
				constants,
				ids,
			),
		}
	}
	typedTargetSetClosed := status == "ambiguous" &&
		len(fn.TypedCallees[callee]) > 0 &&
		len(ids) > 0
	if (status != "resolved" && !typedTargetSetClosed) || len(ids) == 0 {
		kind := "direct_call_unresolved"
		if status == "ambiguous" {
			kind = "direct_call_ambiguous"
		}
		return lsmCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedLSMAlternatives(),
			reasons: []string{
				fn.DisplayName + ": LSM-relevant call target is " + status + ": " + callee,
			},
			unresolved: []UnresolvedProofEdge{{
				Domain: "lsm",
				Caller: fn.DisplayName,
				Kind:   kind,
				Symbol: callee,
				Detail: "the call can influence syscall termination, so it cannot be removed from the LSM proof cone",
			}},
		}
	}

	targetStates := uint8(0)
	hooks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	hookProofPaths := make(map[string][]string)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	targetAlternatives := make([]lsmPathAlternative, 0)
	for _, id := range ids {
		childFn := a.functions[id]
		if childFn == nil {
			targetAlternatives = mergeLSMAlternatives(
				targetAlternatives,
				unresolvedLSMAlternatives(),
			)
			continue
		}
		childConstants := map[string]string(nil)
		if site != nil {
			arguments := make([]string, 0, len(site.Arguments))
			for _, argument := range site.Arguments {
				arguments = append(
					arguments,
					substituteIdentifierConstants(argument, constants),
				)
			}
			childConstants = a.bindCallAnalysisContext(
				fn,
				constants,
				childFn,
				arguments,
				site,
			)
			contextCall := callInvocation{
				name:       callee,
				arguments:  arguments,
				callSiteID: site.ID,
			}
			childConstants = bindCallStructConstants(
				childConstants,
				body,
				contextCall,
				childFn.Parameters,
			)
		}
		childConstants = bindCallReturnRequirement(
			childConstants,
			childFn,
			requiredCallReturnForSite(
				fn,
				childFn,
				body,
				callee,
				site,
				constants[contextReturnRequirementKey],
			),
		)
		if witness := a.proveEffectFreeSuccessfulExecution(
			id,
			childConstants,
			operationContext,
			"lsm",
			make(map[string]bool),
		); witness.proven {
			childAlternatives := a.annotateSuccessfulCallAlternatives(
				provenNonEnforcingLSMAlternatives(
					witness,
					childFn.DisplayName,
				),
				fn,
				childFn,
				callee,
				site,
				constants[contextReturnRequirementKey],
			)
			targetAlternatives = mergeLSMAlternatives(
				targetAlternatives,
				childAlternatives,
			)
			continue
		}
		child := a.analyzeFunctionLSMCoverage(
			id,
			childConstants,
			operationContext,
			active,
		)
		childAlternatives := a.annotateSuccessfulCallAlternatives(
			child.alternatives,
			fn,
			childFn,
			callee,
			site,
			constants[contextReturnRequirementKey],
		)
		targetAlternatives = mergeLSMAlternatives(
			targetAlternatives,
			childAlternatives,
		)
		switch child.state {
		case "enforcing":
			targetStates |= lsmPathEnforcing
		case "non_enforcing":
			targetStates |= lsmPathNonEnforcing
		default:
			targetStates |= lsmPathUnresolved
		}
		hooks.addAll(child.hooks)
		proofFunctions.addAll(child.proofFunctions)
		for hook, path := range child.hookProofPaths {
			extended := append(append([]string(nil), path...), fn.DisplayName)
			mergeHookProofPaths(hookProofPaths, map[string][]string{hook: extended})
		}
		reasons.addAll(child.reasons)
		unresolved = append(unresolved, child.unresolved...)
	}
	targetAlternatives = composeLSMAlternativesWithEdge(
		targetAlternatives,
		edgeEffect,
		fn.DisplayName,
	)
	targetStates = lsmStatesForAlternatives(targetAlternatives)
	if targetStates&lsmPathUnresolved != 0 {
		reasons.add(fn.DisplayName + ": callee denial propagation is unresolved: " + callee)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain: "lsm",
			Caller: fn.DisplayName,
			Kind:   "callee_denial_propagation_unresolved",
			Symbol: callee,
			Detail: "at least one callee denial-propagation alternative remains unresolved",
		})
	}
	if targetStates&lsmPathEnforcing != 0 {
		proofFunctions.add(fn.DisplayName)
	}
	return lsmCoverageEvent{
		states:         targetStates,
		hooks:          hooks.slice(),
		alternatives:   targetAlternatives,
		proofFunctions: proofFunctions.slice(),
		hookProofPaths: hookProofPaths,
		reasons:        reasons.slice(),
		unresolved:     uniqueProofEdges(unresolved),
	}
}

func lsmStatesForAlternatives(alternatives []lsmPathAlternative) uint8 {
	var states uint8
	for _, alternative := range canonicalLSMAlternatives(alternatives) {
		switch {
		case len(alternative.hooks) > 0:
			states |= lsmPathEnforcing
		case alternative.unresolved:
			states |= lsmPathUnresolved
		default:
			states |= lsmPathNonEnforcing
		}
	}
	return states
}

func projectChildAlternativesForCaller(
	alternatives []lsmPathAlternative,
) []lsmPathAlternative {
	result := cloneLSMAlternatives(alternatives)
	for index := range result {
		projectChildAlternativeForCaller(&result[index])
	}
	return canonicalLSMAlternatives(result)
}

func projectChildAlternativeForCaller(
	alternative *lsmPathAlternative,
) {
	if alternative == nil {
		return
	}
	alternative.bypassConstraints = nil
	alternative.bypassSuccessfulCalls = nil
	alternative.returnOutcome = returnOutcome{}
	alternative.bypassValues = nil
	alternative.bypassCyclic = false
}

func (a *Analyzer) sourceFreeCallAlternatives(
	fn *FunctionInfo,
	body, callee string,
	site *ClangCallSite,
	constants map[string]string,
	resolvedIDs []string,
) []lsmPathAlternative {
	if fn == nil {
		return nonEnforcingLSMAlternatives()
	}
	fallback := nonEnforcingLSMAlternatives(fn.DisplayName)
	if site == nil || !site.Direct ||
		site.ResultUse == "discarded" {
		return fallback
	}
	if site.ResultVariable == "" && site.ResultUse != "returned" &&
		site.ResultUse != "condition" {
		return fallback
	}
	ids := append([]string(nil), resolvedIDs...)
	if len(ids) == 0 {
		var status string
		ids, status = a.resolveCallee(fn, callee)
		typedTargetSetClosed := status == "ambiguous" &&
			len(fn.TypedCallees[callee]) > 0 && len(ids) > 0
		if status != "resolved" && !typedTargetSetClosed ||
			len(ids) == 0 {
			return fallback
		}
	}
	result := make([]lsmPathAlternative, 0, len(ids))
	for _, id := range ids {
		child := a.functions[id]
		if child == nil {
			result = mergeLSMAlternatives(result, fallback)
			continue
		}
		arguments := make([]string, 0, len(site.Arguments))
		for _, argument := range site.Arguments {
			arguments = append(
				arguments,
				substituteIdentifierConstants(argument, constants),
			)
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			child,
			arguments,
			site,
		)
		childConstants = bindCallStructConstants(
			childConstants,
			body,
			callInvocation{
				name:       callee,
				arguments:  arguments,
				callSiteID: site.ID,
			},
			child.Parameters,
		)
		requirement := requiredCallReturnForSite(
			fn,
			child,
			body,
			callee,
			site,
			constants[contextReturnRequirementKey],
		)
		if requirement == "" {
			if site.ResultVariable == "" ||
				!cfgFunctionReturnsIdentifier(
					fn,
					site.ResultVariable,
				) {
				result = mergeLSMAlternatives(result, fallback)
				continue
			}
			requirement = defaultSuccessRequirement(child.ReturnType)
		}
		if requirement == "" {
			result = mergeLSMAlternatives(result, fallback)
			continue
		}
		childConstants = bindCallReturnRequirement(
			childConstants,
			child,
			requirement,
		)
		witness := a.proveFunctionSuccessfulExecution(
			child.ID,
			childConstants,
			make(map[string]bool),
		)
		if !witness.proven {
			result = mergeLSMAlternatives(result, fallback)
			continue
		}
		childAlternatives := provenNonEnforcingLSMAlternatives(
			witness,
			child.DisplayName,
		)
		if outcome := a.provenAtomicSuccessOutcome(
			child,
			childConstants,
		); outcome.mask != 0 {
			childAlternatives[0].returnOutcome = outcome
		}
		result = mergeLSMAlternatives(
			result,
			a.annotateSuccessfulCallAlternatives(
				childAlternatives,
				fn,
				child,
				callee,
				site,
				constants[contextReturnRequirementKey],
			),
		)
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}

func (a *Analyzer) provenAtomicSuccessOutcome(
	fn *FunctionInfo,
	constants map[string]string,
) returnOutcome {
	if a == nil || fn == nil || fn.Frontend != "clang-ast-cfg" ||
		!fn.CFGComplete || fn.FrontendVariantConflict ||
		!fn.CFGHasSuccessExit {
		return returnOutcome{}
	}
	requirement := constants[contextReturnRequirementKey]
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	domain := returnDomainForType(fn.ReturnType)
	requiredMask, ok := requirementMask(domain, requirement)
	if !ok {
		return returnOutcome{}
	}
	var witnessedMask uint16
	for _, state := range successConstraintPathStates(fn, constants) {
		if state.cyclic {
			continue
		}
		block, ok := cfgBlockByID(fn, state.blockID)
		if !ok || !block.PotentialSuccessExit {
			continue
		}
		witness := a.proveSuccessfulReturnBlockAlongPathWithValues(
			fn,
			block,
			constants,
			make(map[string]bool),
			state.constraints,
			false,
			true,
			nil,
			state.values,
		)
		if !witness.proven {
			continue
		}
		expression := resolvedCFGConstantReturnExpression(
			substituteIdentifierConstants(
				strings.TrimSpace(
					clangCFGReturnExpression(block),
				),
				constants,
			),
			state.values,
		)
		outcome := returnOutcomeFromExpression(
			fn,
			expression,
			state.constraints,
			false,
			nil,
			requirement,
		)
		outcome = constrainReturnOutcomeByLLVMFunctionFacts(
			fn,
			outcome,
		)
		if outcome.domain != domain {
			continue
		}
		mask := outcome.mask & requiredMask
		if mask == 0 || mask&(mask-1) != 0 {
			continue
		}
		witnessedMask |= mask
	}
	if witnessedMask == 0 {
		return returnOutcome{}
	}
	if _, representable := requirementForOutcomeMask(
		domain,
		witnessedMask,
	); !representable {
		return returnOutcome{}
	}
	return returnOutcome{
		domain: domain,
		mask:   witnessedMask,
	}
}

func cfgFunctionReturnsIdentifier(
	fn *FunctionInfo,
	identifier string,
) bool {
	if fn == nil || identifier == "" {
		return false
	}
	for _, block := range fn.CFGBlocks {
		if stripSimpleCasts(
			compactExpression(clangCFGReturnExpression(block)),
		) == identifier {
			return true
		}
	}
	return false
}

func (a *Analyzer) annotateSuccessfulCallAlternatives(
	alternatives []lsmPathAlternative,
	fn, child *FunctionInfo,
	callee string,
	site *ClangCallSite,
	callerRequirement string,
) []lsmPathAlternative {
	baseConstraint, hasBaseConstraint :=
		a.successfulCallConstraintForSite(
			fn,
			child,
			callee,
			site,
			callerRequirement,
		)
	childRequirement := requiredCallReturnForSite(
		fn,
		child,
		fn.Body,
		callee,
		site,
		callerRequirement,
	)
	if childRequirement == "" {
		childRequirement = defaultSuccessRequirement(child.ReturnType)
	}
	result := cloneLSMAlternatives(alternatives)
	projected := result[:0]
	for index := range result {
		childOutcome := result[index].returnOutcome
		childSuccessProven := result[index].bypassSuccessProven
		projectChildAlternativeForCaller(&result[index])
		constraint, constrained, feasible :=
			successfulCallConstraintForAlternative(
				fn,
				child,
				callee,
				site,
				childOutcome,
				baseConstraint,
				hasBaseConstraint,
				childSuccessProven,
				childRequirement,
			)
		if !feasible {
			continue
		}
		if constrained {
			result[index].bypassSuccessfulCalls =
				canonicalSuccessfulCallConstraints(append(
					result[index].bypassSuccessfulCalls,
					constraint,
				))
		}
		projected = append(projected, result[index])
	}
	return canonicalLSMAlternatives(projected)
}

func successfulCallConstraintForAlternative(
	fn, child *FunctionInfo,
	callee string,
	site *ClangCallSite,
	childOutcome returnOutcome,
	base successfulCallConstraint,
	hasBase, childSuccessProven bool,
	childRequirement string,
) (successfulCallConstraint, bool, bool) {
	if fn == nil || child == nil || site == nil || !site.Direct ||
		site.ID == "" || site.Name != callee {
		return successfulCallConstraint{}, false, true
	}
	constraint := base
	if !hasBase {
		constraint = successfulCallConstraint{
			functionID:     fn.ID,
			callSiteID:     site.ID,
			callee:         callee,
			resultVariable: site.ResultVariable,
			returnType:     child.ReturnType,
			method:         "child_return_outcome",
		}
	}
	constraint.certifiesCallerSuccess =
		constraint.certifiesCallerSuccess && childSuccessProven
	constraint.provenCalleeSuccess = childSuccessProven

	childDomain := returnDomainForType(child.ReturnType)
	if childOutcome.domain == childDomain && childOutcome.mask != 0 {
		mask := childOutcome.mask
		if hasBase && base.requirement != "" {
			requiredMask, ok := requirementMask(
				childDomain,
				base.requirement,
			)
			if !ok {
				return successfulCallConstraint{}, false, true
			}
			mask &= requiredMask
			if mask == 0 {
				outcomeRequirement, representable :=
					requirementForOutcomeMask(
						childDomain,
						childOutcome.mask,
					)
				if !representable || site.ResultVariable == "" {
					return successfulCallConstraint{}, false, true
				}
				return successfulCallConstraint{
					functionID:          fn.ID,
					callSiteID:          site.ID,
					callee:              callee,
					resultVariable:      site.ResultVariable,
					returnType:          child.ReturnType,
					requirement:         outcomeRequirement,
					provenCalleeSuccess: childSuccessProven,
					method:              "child_return_outcome",
				}, true, true
			}
		}
		requirement, ok := requirementForOutcomeMask(childDomain, mask)
		if !ok {
			return successfulCallConstraint{}, false, true
		}
		constraint.requirement = requirement
	}
	if constraint.requirement == "" {
		if !childSuccessProven || childRequirement == "" {
			return successfulCallConstraint{}, false, true
		}
		if !hasBase {
			domain := returnDomainForType(child.ReturnType)
			mask, ok := requirementMask(
				domain,
				childRequirement,
			)
			if !ok || mask == 0 || mask&(mask-1) != 0 {
				return successfulCallConstraint{}, false, true
			}
		}
		constraint.requirement = childRequirement
	}
	if constraint.resultVariable == "" &&
		!constraint.certifiesCallerSuccess {
		return successfulCallConstraint{}, false, true
	}
	return constraint, true, true
}

func (a *Analyzer) successfulCallConstraintForSite(
	fn, child *FunctionInfo,
	callee string,
	site *ClangCallSite,
	callerRequirement string,
) (successfulCallConstraint, bool) {
	if fn == nil || child == nil || site == nil {
		return successfulCallConstraint{}, false
	}
	requirement := callerRequirement
	if requirement == "" {
		requirement = defaultSuccessRequirement(fn.ReturnType)
	}
	if correlatableSuccessfulReturnCallSite(fn, callee, site) &&
		requirementsCompatibleAcrossFunctions(
			fn,
			child,
			requirement,
		) {
		return successfulCallConstraint{
			functionID:             fn.ID,
			callSiteID:             site.ID,
			callee:                 callee,
			resultVariable:         site.ResultVariable,
			returnType:             child.ReturnType,
			requirement:            requirement,
			callerRequirement:      requirement,
			certifiesCallerSuccess: true,
			method:                 "direct_forwarded_success_return",
		}, true
	}
	if childRequirement, method, ok :=
		a.llvmIntegerSuccessRequirementAtSite(
			fn,
			child,
			callee,
			site,
			requirement,
		); ok {
		return successfulCallConstraint{
			functionID:             fn.ID,
			callSiteID:             site.ID,
			callee:                 callee,
			resultVariable:         site.ResultVariable,
			returnType:             child.ReturnType,
			requirement:            childRequirement,
			callerRequirement:      requirement,
			certifiesCallerSuccess: true,
			method:                 method,
		}, true
	}
	if a.llvmCallPreservesValidPointerSuccessAtSite(
		fn,
		child,
		callee,
		site,
		requirement,
	) {
		return successfulCallConstraint{
			functionID:             fn.ID,
			callSiteID:             site.ID,
			callee:                 callee,
			resultVariable:         site.ResultVariable,
			returnType:             child.ReturnType,
			requirement:            requirement,
			callerRequirement:      requirement,
			certifiesCallerSuccess: true,
			method:                 "llvm_ssa_valid_pointer_success_preservation",
		}, true
	}
	return successfulCallConstraint{}, false
}

func correlatableSuccessfulReturnCallSite(
	fn *FunctionInfo,
	callee string,
	site *ClangCallSite,
) bool {
	if fn == nil || site == nil || !site.Direct || !site.HasBlock ||
		site.ID == "" || site.Name != callee {
		return false
	}
	block, ok := cfgBlockByID(fn, site.BlockID)
	if !ok || !block.PotentialSuccessExit {
		return false
	}
	returnedCallee, _, ok := directReturnedCall(
		clangCFGReturnExpression(block),
	)
	if !ok || returnedCallee != callee {
		return false
	}
	matches := 0
	for _, candidate := range fn.CallSites {
		if !candidate.Direct || !candidate.HasBlock ||
			candidate.BlockID != block.ID || candidate.Name != callee {
			continue
		}
		matches++
		if candidate.ID != site.ID {
			return false
		}
	}
	return matches == 1
}

func composeLSMAlternativesWithEdge(
	alternatives []lsmPathAlternative,
	effect localErrorEffect,
	caller string,
) []lsmPathAlternative {
	effectClass := classifySignalAbortEffect(effect)
	result := make([]lsmPathAlternative, 0, len(alternatives)*2)
	addBypass := func(
		alternative lsmPathAlternative,
		derivedFromEffect bool,
	) {
		result = append(result, lsmPathAlternative{
			bypassPath: uniqueStrings(append(
				append([]string(nil), alternative.bypassPath...),
				caller,
			)),
			bypassConstraints: append(
				[]successPathConstraint(nil),
				alternative.bypassConstraints...,
			),
			bypassValues: cloneCFGPathValues(
				alternative.bypassValues,
			),
			bypassCyclic: alternative.bypassCyclic,
			bypassDerivedEffect: alternative.bypassDerivedEffect ||
				derivedFromEffect,
			bypassSuccessfulCalls: append(
				[]successfulCallConstraint(nil),
				alternative.bypassSuccessfulCalls...,
			),
		})
	}
	for _, alternative := range canonicalLSMAlternatives(alternatives) {
		if len(alternative.hooks) == 0 && !alternative.unresolved {
			addBypass(alternative, false)
			continue
		}
		switch effectClass {
		case "guaranteed":
			result = append(result, alternative)
		case "not_effective":
			addBypass(alternative, true)
		case "conditional":
			result = append(result, alternative)
			addBypass(alternative, true)
		default:
			result = append(result, lsmPathAlternative{unresolved: true})
		}
	}
	return canonicalLSMAlternatives(result)
}

func uniqueProofEdges(edges []UnresolvedProofEdge) []UnresolvedProofEdge {
	seen := make(map[string]struct{}, len(edges))
	result := make([]UnresolvedProofEdge, 0, len(edges))
	for _, edge := range edges {
		edge = classifyUnresolvedProofEdge(edge)
		key := edge.Domain + "\x00" + edge.Caller + "\x00" + edge.Kind + "\x00" + edge.Symbol + "\x00" + edge.Expression
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, edge)
	}
	return result
}

func classifyUnresolvedProofEdge(
	edge UnresolvedProofEdge,
) UnresolvedProofEdge {
	if edge.Category != "" && edge.ResolutionScope != "" {
		return edge
	}
	switch edge.Kind {
	case "successful_execution_unproven":
		edge.Category = "success_value_or_path_feasibility"
		edge.ResolutionScope = "implementation_improvable"
	case "indirect_signal_target_set_unproven",
		"indirect_coverage_edge_unresolved":
		edge.Category = "open_function_pointer_target_set"
		edge.ResolutionScope = "static_analysis_limit"
	case "translation_unit_variant_conflict":
		edge.Category = "configured_translation_unit_variation"
		edge.ResolutionScope = "configured_input_ambiguity"
	case "recursive_signal_cycle", "recursive_coverage_cycle":
		edge.Category = "recursive_fixed_point"
		edge.ResolutionScope = "analysis_precision_limit"
	case "cfg_incomplete", "cfg_event_unplaced",
		"cfg_callsite_missing":
		edge.Category = "frontend_cfg_extraction"
		edge.ResolutionScope = "implementation_improvable"
	case "direct_call_unresolved", "direct_call_ambiguous",
		"function_unresolved":
		edge.Category = "symbol_or_definition_resolution"
		edge.ResolutionScope = "configured_input_ambiguity"
	case "signal_state_unresolved", "signal_subject_unresolved":
		edge.Category = "signal_state_or_subject_alias"
		edge.ResolutionScope = "static_analysis_limit"
	case "signal_abort_effect_unresolved",
		"lsm_denial_effect_unresolved",
		"callee_denial_propagation_unresolved",
		"closed_indirect_denial_propagation_unresolved":
		edge.Category = "termination_or_error_propagation"
		edge.ResolutionScope = "implementation_improvable"
	default:
		edge.Category = "other_unresolved_semantics"
		edge.ResolutionScope = "analysis_precision_limit"
	}
	return edge
}

func mergeHookProofPaths(target, source map[string][]string) {
	for hook, path := range source {
		existing, ok := target[hook]
		if ok && len(existing) <= len(path) {
			continue
		}
		target[hook] = append([]string(nil), path...)
	}
}

type signalPathAlternative = lsmPathAlternative

type signalCoverageResult struct {
	state              string
	checks             []string
	alternatives       []signalPathAlternative
	proofMethods       []string
	proofFunctions     []string
	checkProofPaths    map[string][]string
	bypassProofPath    []string
	bypassProofMethod  string
	unprovenBypassPath []string
	checkPaths         []SignalCheckPath
	reasons            []string
	unresolved         []UnresolvedProofEdge
	coveredUnresolved  []UnresolvedProofEdge
}

type signalCoverageEvent struct {
	states          uint8
	checks          []string
	alternatives    []signalPathAlternative
	proofFunctions  []string
	checkProofPaths map[string][]string
	checkPaths      []SignalCheckPath
	reasons         []string
	unresolved      []UnresolvedProofEdge
}

const maxSIGKILLCoverageAlternatives = 65536

func alternativeProductExceedsLimit(
	left, right, limit int,
) bool {
	if left <= 0 || right <= 0 || limit <= 0 {
		return false
	}
	return left > limit/right
}

func sigkillStateBudgetGap(
	fn *FunctionInfo,
) UnresolvedProofEdge {
	caller := ""
	if fn != nil {
		caller = fn.DisplayName
	}
	return UnresolvedProofEdge{
		Domain:          "sigkill",
		Caller:          caller,
		Kind:            "analysis_state_budget_exceeded",
		Category:        "path_state_explosion",
		ResolutionScope: "implementation_improvable",
		Detail: fmt.Sprintf(
			"SIGKILL path alternatives exceeded the conservative per-function limit of %d",
			maxSIGKILLCoverageAlternatives,
		),
	}
}

func nonEnforcingSignalAlternatives(path ...string) []signalPathAlternative {
	return nonEnforcingLSMAlternatives(path...)
}

func unresolvedSignalAlternatives() []signalPathAlternative {
	return unresolvedLSMAlternatives()
}

func enforcingSignalAlternatives(checks ...string) []signalPathAlternative {
	return enforcingLSMAlternatives(checks...)
}

func signalAlternativeCheckSets(values []signalPathAlternative) [][]string {
	return lsmAlternativeHookSets(values)
}

func (a *Analyzer) analyzeSIGKILLPathCoverage(start string) signalCoverageResult {
	if a.sigkillCoverageMu != nil {
		a.sigkillCoverageMu.Lock()
		defer a.sigkillCoverageMu.Unlock()
	}
	return a.analyzeFunctionSIGKILLCoverage(
		start,
		nil,
		nil,
		make(map[string]bool),
	)
}

func (a *Analyzer) cachedFunctionSIGKILLCoverage(
	fn *FunctionInfo,
	constants map[string]string,
	operationContext map[string][]string,
) (signalCoverageResult, bool) {
	if fn == nil {
		return signalCoverageResult{}, false
	}
	cacheKey := functionContextKey(fn, constants) +
		operationContextKey(operationContext)
	result, ok := a.signalCoverageCache[cacheKey]
	return result, ok
}

func (a *Analyzer) analyzeFunctionSIGKILLCoverage(
	functionID string,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) signalCoverageResult {
	fn := a.functions[functionID]
	if fn == nil {
		return signalCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedSignalAlternatives(),
			reasons:      []string{"function is not indexed: " + functionID},
			unresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Caller: functionID,
				Kind:   "function_unresolved",
				Detail: "the function required by SIGKILL path coverage is not indexed",
			}},
		}
	}
	cacheKey := functionContextKey(fn, constants) +
		operationContextKey(operationContext)
	if cached, ok := a.signalCoverageCache[cacheKey]; ok {
		return cached
	}
	if isSignalTraversalBarrier(fn) ||
		a.signalEffectSourceState(functionID) == effectSourceNone {
		witness := a.proveFunctionSuccessfulExecution(
			functionID,
			constants,
			make(map[string]bool),
		)
		result := signalCoverageResult{
			state:        "uncertain",
			alternatives: nonEnforcingSignalAlternatives(fn.DisplayName),
			proofMethods: []string{"closed_effect_source_absence"},
			reasons: []string{
				"the closed function cone contains no effective current-task SIGKILL checkpoint, but a normal successful operation return is not proven",
			},
			unresolved: []UnresolvedProofEdge{
				successfulExecutionUnprovenEdge("sigkill", fn),
			},
			unprovenBypassPath: []string{fn.DisplayName},
		}
		if witness.proven {
			result.state = "non_enforcing"
			result.alternatives = provenNonEnforcingLSMAlternatives(
				witness,
				fn.DisplayName,
			)
			result.proofMethods = []string{
				"closed_effect_source_absence",
				witness.method,
			}
			result.bypassProofPath = firstLSMBypassPath(result.alternatives)
			result.bypassProofMethod = witness.method
			result.unprovenBypassPath = nil
			result.reasons = []string{
				"a proven normal successful operation path has no effective current-task SIGKILL checkpoint",
			}
			result.unresolved = nil
		}
		a.signalCoverageCache[cacheKey] = result
		return result
	}
	if active[cacheKey] {
		return signalCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedSignalAlternatives(),
			reasons:      []string{"recursive SIGKILL coverage cycle: " + fn.DisplayName},
			unresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "recursive_signal_cycle",
				Detail: "the recursive cycle has no independently established enforcement summary",
			}},
		}
	}
	if fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		len(fn.CFGBlocks) == 0 || !fn.CFGHasSuccessExit {
		reason := "complete Clang CFG with a potential success exit is required"
		result := signalCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedSignalAlternatives(),
			reasons:      []string{fn.DisplayName + ": " + reason},
			unresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "cfg_incomplete",
				Detail: reason,
			}},
		}
		a.signalCoverageCache[cacheKey] = result
		return result
	}
	if fn.FrontendVariantConflict {
		result := signalCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedSignalAlternatives(),
			reasons: []string{
				fn.DisplayName + ": translation-unit variants have different CFG facts",
			},
			unresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "translation_unit_variant_conflict",
				Detail: "coverage is not guessed across differing translation-unit variants",
			}},
		}
		a.signalCoverageCache[cacheKey] = result
		return result
	}
	if witness := a.proveEffectFreeSuccessfulExecution(
		functionID,
		constants,
		operationContext,
		"sigkill",
		make(map[string]bool),
	); witness.proven {
		result := certifiedEffectFreeSIGKILLBypass(fn, witness)
		a.signalCoverageCache[cacheKey] = result
		return result
	}

	active[cacheKey] = true
	defer delete(active, cacheKey)
	body := substituteIdentifierConstants(fn.Body, constants)
	blockByID := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blockByID[block.ID] = block
	}
	if _, ok := blockByID[fn.CFGEntry]; !ok {
		result := signalCoverageResult{
			state:        "uncertain",
			alternatives: unresolvedSignalAlternatives(),
			reasons:      []string{fn.DisplayName + ": CFG entry block is missing"},
		}
		a.signalCoverageCache[cacheKey] = result
		return result
	}

	initialAlternatives := nonEnforcingSignalAlternatives(fn.DisplayName)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	for _, site := range fn.CallSites {
		if !containsString(fn.CFGUnplacedCallSites, site.ID) {
			continue
		}
		event, relevant := a.signalCoverageEventForCallSite(
			fn,
			body,
			site,
			constants,
			operationContext,
			active,
		)
		if !relevant || event.states == lsmPathNonEnforcing {
			continue
		}
		initialAlternatives = unresolvedSignalAlternatives()
		symbol := site.Name
		if !site.Direct {
			symbol = site.Expression
		}
		reasons.add(fn.DisplayName + ": unplaced CFG callsite " + site.ID)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain: "sigkill",
			Caller: fn.DisplayName,
			Kind:   "cfg_event_unplaced",
			Symbol: symbol,
			Detail: "a signal-relevant event cannot be assigned to one CFG block without guessing",
		})
	}

	inAlternatives := map[int][]signalPathAlternative{
		fn.CFGEntry: initialAlternatives,
	}
	outAlternatives := make(map[int][]signalPathAlternative)
	exitAlternativesByBlock := make(map[int][]signalPathAlternative)
	queue := []int{fn.CFGEntry}
	queued := map[int]bool{fn.CFGEntry: true}
	checks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	checkProofPaths := make(map[string][]string)
	checkPaths := make([]SignalCheckPath, 0)

	for len(queue) > 0 {
		nextIndex := a.prioritizedCFGQueueIndex(
			fn,
			blockByID,
			queue,
			"sigkill",
		)
		blockID := queue[nextIndex]
		queue = append(queue[:nextIndex], queue[nextIndex+1:]...)
		delete(queued, blockID)
		block, ok := blockByID[blockID]
		if !ok {
			continue
		}
		alternatives := cloneLSMAlternatives(inAlternatives[blockID])
		if !allPathAlternativesEnforcing(alternatives) {
			a.visitSignalCoverageEventsForBlock(
				fn,
				body,
				block,
				constants,
				operationContext,
				active,
				func(event signalCoverageEvent) bool {
					if alternativeProductExceedsLimit(
						len(alternatives),
						len(event.alternatives),
						maxSIGKILLCoverageAlternatives,
					) {
						alternatives = unresolvedSignalAlternatives()
						reasons.add(
							fn.DisplayName +
								": SIGKILL path-state budget exceeded while composing call effects",
						)
						unresolved = append(
							unresolved,
							sigkillStateBudgetGap(fn),
						)
						return false
					}
					alternatives = sequenceLSMAlternatives(
						alternatives,
						event.alternatives,
					)
					checks.addAll(event.checks)
					proofFunctions.addAll(event.proofFunctions)
					mergeHookProofPaths(checkProofPaths, event.checkProofPaths)
					checkPaths = mergeSignalCheckPaths(
						checkPaths,
						event.checkPaths,
					)
					reasons.addAll(event.reasons)
					unresolved = append(unresolved, event.unresolved...)
					return !allPathAlternativesEnforcing(alternatives)
				},
			)
		}
		alternatives = applyCFGValueWritesToAlternatives(
			fn,
			block,
			alternatives,
		)
		if block.PotentialSuccessExit {
			exitAlternatives := a.finalizeSuccessExitAlternatives(
				fn,
				block,
				constants,
				alternatives,
			)
			exitAlternativesByBlock[block.ID] = exitAlternatives
			if classifySuccessExitLSMAlternatives(exitAlternatives) ==
				"non_enforcing" {
				result := signalCoverageResult{
					state:           "non_enforcing",
					checks:          checks.slice(),
					alternatives:    exitAlternatives,
					proofMethods:    []string{"clang_cfg_bypass_witness", "early_exit_short_circuit"},
					proofFunctions:  proofFunctions.slice(),
					checkProofPaths: checkProofPaths,
					bypassProofPath: firstLSMBypassPath(
						exitAlternatives,
					),
					bypassProofMethod: firstLSMBypassMethod(
						exitAlternatives,
					),
					checkPaths:        checkPaths,
					reasons:           []string{"at least one modeled feasible success path bypasses every effective current-task SIGKILL checkpoint"},
					coveredUnresolved: sortedProofGaps(uniqueProofEdges(unresolved)),
				}
				a.signalCoverageCache[cacheKey] = result
				return result
			}
		}
		if lsmAlternativesEqual(outAlternatives[blockID], alternatives) {
			continue
		}
		outAlternatives[blockID] = alternatives
		for _, edge := range a.prioritizedSuccessSuccessorEdges(
			fn,
			blockByID,
			block,
			constants,
			"sigkill",
		) {
			if edge.blockID == fn.CFGExit {
				continue
			}
			edgeAlternatives := a.constrainAlternativesForCFGEdge(
				alternatives,
				fn,
				block,
				edge,
			)
			next := mergeLSMAlternatives(
				inAlternatives[edge.blockID],
				edgeAlternatives,
			)
			if len(next) > maxSIGKILLCoverageAlternatives {
				next = unresolvedSignalAlternatives()
				reasons.add(
					fn.DisplayName +
						": SIGKILL path-state budget exceeded while merging CFG paths",
				)
				unresolved = append(
					unresolved,
					sigkillStateBudgetGap(fn),
				)
			}
			if lsmAlternativesEqual(next, inAlternatives[edge.blockID]) {
				continue
			}
			inAlternatives[edge.blockID] = next
			if !queued[edge.blockID] {
				queue = append(queue, edge.blockID)
				queued[edge.blockID] = true
			}
		}
	}

	exitAlternatives := make([]signalPathAlternative, 0)
	for _, block := range fn.CFGBlocks {
		if !block.PotentialSuccessExit {
			continue
		}
		exitAlternatives = mergeLSMAlternatives(
			exitAlternatives,
			exitAlternativesByBlock[block.ID],
		)
	}
	unprovenBypassPath := firstUnprovenLSMBypassPath(exitAlternatives)
	if len(unprovenBypassPath) > 0 {
		reasons.add(fn.DisplayName + ": a checkpoint-free potential return is not proven to be a normal successful operation return")
		unresolved = append(
			unresolved,
			successfulExecutionUnprovenEdge("sigkill", fn),
		)
	}
	result := signalCoverageResult{
		state:           classifySuccessExitLSMAlternatives(exitAlternatives),
		checks:          checks.slice(),
		alternatives:    canonicalLSMAlternatives(exitAlternatives),
		proofMethods:    []string{"clang_cfg_coverage"},
		proofFunctions:  proofFunctions.slice(),
		checkProofPaths: checkProofPaths,
		bypassProofPath: firstLSMBypassPath(exitAlternatives),
		bypassProofMethod: firstLSMBypassMethod(
			exitAlternatives,
		),
		unprovenBypassPath: unprovenBypassPath,
		checkPaths:         checkPaths,
		reasons:            reasons.slice(),
		unresolved:         sortedProofGaps(uniqueProofEdges(unresolved)),
	}
	switch result.state {
	case "enforcing":
		result.coveredUnresolved = result.unresolved
		result.reasons = nil
		result.unresolved = nil
	case "non_enforcing":
		result.proofMethods = uniqueStrings([]string{
			"clang_cfg_bypass_witness",
			result.bypassProofMethod,
		})
		result.reasons = []string{
			"at least one modeled feasible success path bypasses every effective current-task SIGKILL checkpoint",
		}
		result.coveredUnresolved = result.unresolved
		result.unresolved = nil
	default:
		if len(exitAlternatives) == 0 {
			result.reasons = uniqueStrings(append(
				result.reasons,
				fn.DisplayName+": no modeled potential-success exit was reachable",
			))
		} else if len(result.reasons) == 0 {
			result.reasons = []string{
				fn.DisplayName + ": success exits contain enforcing and unresolved path states without a certified bypass",
			}
		}
	}
	a.signalCoverageCache[cacheKey] = result
	return result
}

func mergeSignalCheckPaths(
	target, source []SignalCheckPath,
) []SignalCheckPath {
	result := append([]SignalCheckPath(nil), target...)
	byKey := make(map[string]int, len(result))
	for index, path := range result {
		byKey[path.Check+"\x00"+path.CallSiteID+"\x00"+path.Function] = index
	}
	for _, path := range source {
		key := path.Check + "\x00" + path.CallSiteID + "\x00" + path.Function
		if index, ok := byKey[key]; ok {
			if len(path.ProofPath) < len(result[index].ProofPath) {
				result[index] = path
			}
			continue
		}
		byKey[key] = len(result)
		result = append(result, path)
	}
	return result
}

func (a *Analyzer) visitSignalCoverageEventsForBlock(
	fn *FunctionInfo,
	body string,
	block ClangCFGBlock,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
	visit func(signalCoverageEvent) bool,
) {
	byID := make(map[string]ClangCallSite, len(fn.CallSites))
	for _, site := range fn.CallSites {
		byID[site.ID] = site
	}
	representedChecks := make(map[string]bool)
	for _, callSiteID := range block.CallSiteIDs {
		site, ok := byID[callSiteID]
		if !ok {
			if !visit(signalCoverageEvent{
				states:       lsmPathUnresolved,
				alternatives: unresolvedSignalAlternatives(),
				reasons: []string{
					fn.DisplayName + ": CFG callsite record is missing: " + callSiteID,
				},
				unresolved: []UnresolvedProofEdge{{
					Domain: "sigkill",
					Caller: fn.DisplayName,
					Kind:   "cfg_callsite_missing",
					Symbol: callSiteID,
					Detail: "the CFG refers to a callsite absent from the Clang callsite index",
				}},
			}) {
				return
			}
			continue
		}
		if site.Direct && isSignalCheckName(site.Name) {
			representedChecks[site.Name] = true
		}
		event, relevant := a.signalCoverageEventForCallSite(
			fn,
			body,
			site,
			constants,
			operationContext,
			active,
		)
		if relevant && !visit(event) {
			return
		}
	}
	for _, check := range block.SignalChecks {
		if representedChecks[check] {
			continue
		}
		if !visit(a.localSignalCoverageEvent(
			fn,
			body,
			check,
			"",
		)) {
			return
		}
	}
	if len(block.CallSiteIDs) > 0 {
		return
	}
	for _, callee := range filterInternalCallees(block.Calls) {
		if isSignalCheckName(callee) {
			continue
		}
		if !visit(a.directCallSignalCoverageEvent(
			fn,
			body,
			callee,
			nil,
			constants,
			operationContext,
			active,
		)) {
			return
		}
	}
	for _, expression := range block.IndirectCalls {
		if !visit(a.indirectCallSignalCoverageEvent(
			fn,
			body,
			expression,
			nil,
			constants,
			operationContext,
			active,
		)) {
			return
		}
	}
}

func (a *Analyzer) signalCoverageEventForCallSite(
	fn *FunctionInfo,
	body string,
	site ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) (signalCoverageEvent, bool) {
	if site.Direct {
		if isSignalCheckName(site.Name) {
			return a.localSignalCoverageEvent(
				fn,
				body,
				site.Name,
				site.ID,
			), true
		}
		if len(filterInternalCallees([]string{site.Name})) == 0 ||
			strings.HasPrefix(site.Name, "security_") {
			return signalCoverageEvent{}, false
		}
		return a.directCallSignalCoverageEvent(
			fn,
			body,
			site.Name,
			&site,
			constants,
			operationContext,
			active,
		), true
	}
	return a.indirectCallSignalCoverageEvent(
		fn,
		body,
		site.Expression,
		&site,
		constants,
		operationContext,
		active,
	), true
}

func (a *Analyzer) localSignalCoverageEvent(
	fn *FunctionInfo,
	body, check, callSiteID string,
) signalCoverageEvent {
	eligible := []string(nil)
	if callSiteID != "" {
		eligible = []string{callSiteID}
	}
	evidences := a.signalCheckEvidences(
		fn,
		body,
		check,
		false,
		eligible,
	)
	alternatives := make([]signalPathAlternative, 0)
	checks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	checkProofPaths := make(map[string][]string)
	paths := make([]SignalCheckPath, 0)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	for _, evidence := range evidences {
		effect := unknownLocalErrorEffect()
		if evidence.localSite != nil {
			effect = analyzeSignalCheckLocalEffectForFunction(
				fn,
				body,
				check,
				evidence.localSite,
			)
		} else if !evidence.requireSpecificSite {
			effect = analyzeSignalCheckLocalEffectForFunction(
				fn,
				body,
				check,
				nil,
			)
		}
		if classifySignalAbortEffect(effect) == "unknown" &&
			a.llvmCallMustReturnNegativeOnTrue(fn, check) {
			effect = guaranteedEncodedLocalErrorEffect(
				"normalized",
				failureReturnErrno,
				nil,
			)
		}
		effectClass := classifySignalAbortEffect(effect)
		path := SignalCheckPath{
			Check:             check,
			CallSiteID:        evidence.callSiteID,
			Category:          signalCheckCategory(check),
			SIGKILLRelevance:  evidence.relevance,
			Subject:           evidence.subject,
			Traversal:         "cfg-path",
			Function:          fn.DisplayName,
			BlocksOperation:   effect.blocksOperation,
			TerminatesSyscall: effect.terminatesSyscall,
			ErrnoPropagation:  effect.errnoPropagation,
			FailureEncoding:   effect.failureEncoding,
			AbortEffect:       classifyFinalSignalAbortEffect(effect),
			ProofPath:         []string{check, fn.DisplayName},
		}
		paths = append(paths, path)
		switch {
		case effectClass == "not_effective":
			alternatives = mergeLSMAlternatives(
				alternatives,
				nonEnforcingSignalAlternatives(check, fn.DisplayName),
			)
		case evidence.relevance == signalSIGKILLIrrelevant:
			alternatives = mergeLSMAlternatives(
				alternatives,
				nonEnforcingSignalAlternatives(check, fn.DisplayName),
			)
		case evidence.relevance == signalSIGKILLUnknown:
			alternatives = mergeLSMAlternatives(
				alternatives,
				unresolvedSignalAlternatives(),
			)
			reasons.add(fn.DisplayName + ": SIGKILL state relevance is unresolved for " + check)
			unresolved = append(unresolved, UnresolvedProofEdge{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "signal_state_unresolved",
				Symbol: check,
				Detail: "the signal predicate state mask is not proven to observe SIGKILL",
			})
		case evidence.subject != "current-task":
			alternatives = mergeLSMAlternatives(
				alternatives,
				unresolvedSignalAlternatives(),
			)
			reasons.add(fn.DisplayName + ": signal subject is unresolved for " + check)
			unresolved = append(unresolved, UnresolvedProofEdge{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "signal_subject_unresolved",
				Symbol: check,
				Detail: "the predicate subject is not proven to be the current syscall task",
			})
		case effectClass == "guaranteed":
			checks.add(check)
			proofFunctions.add(fn.DisplayName)
			mergeHookProofPaths(checkProofPaths, map[string][]string{
				check: {check, fn.DisplayName},
			})
			alternatives = mergeLSMAlternatives(
				alternatives,
				enforcingSignalAlternatives(check),
			)
		case effectClass == "conditional":
			checks.add(check)
			proofFunctions.add(fn.DisplayName)
			mergeHookProofPaths(checkProofPaths, map[string][]string{
				check: {check, fn.DisplayName},
			})
			alternatives = mergeLSMAlternatives(
				alternatives,
				mergeLSMAlternatives(
					enforcingSignalAlternatives(check),
					[]signalPathAlternative{{
						bypassPath: uniqueStrings(
							[]string{check, fn.DisplayName},
						),
						bypassDerivedEffect: true,
					}},
				),
			)
		default:
			alternatives = mergeLSMAlternatives(
				alternatives,
				unresolvedSignalAlternatives(),
			)
			reasons.add(fn.DisplayName + ": syscall-abort effect is unresolved for " + check)
			unresolved = append(unresolved, UnresolvedProofEdge{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   "signal_abort_effect_unresolved",
				Symbol: check,
				Detail: "the predicate is evaluated but its failure is not proven to terminate the function",
			})
		}
	}
	if len(alternatives) == 0 {
		alternatives = unresolvedSignalAlternatives()
	}
	return signalCoverageEvent{
		states:          lsmStatesForAlternatives(alternatives),
		checks:          checks.slice(),
		alternatives:    alternatives,
		proofFunctions:  proofFunctions.slice(),
		checkProofPaths: checkProofPaths,
		checkPaths:      paths,
		reasons:         reasons.slice(),
		unresolved:      uniqueProofEdges(unresolved),
	}
}

func (a *Analyzer) directCallSignalCoverageEvent(
	fn *FunctionInfo,
	body, callee string,
	site *ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) signalCoverageEvent {
	if site != nil && site.ResultUse == "discarded" {
		return signalCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: nonEnforcingSignalAlternatives(
				fn.DisplayName,
			),
			proofFunctions: []string{fn.DisplayName},
		}
	}
	edgeEffect := a.analyzeNamedCallErrorEffect(fn, body, callee)
	if classifySignalAbortEffect(edgeEffect) == "not_effective" ||
		a.llvmCallCannotContainEffectSource(fn, callee) {
		return signalCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: a.sourceFreeCallAlternatives(
				fn,
				body,
				callee,
				site,
				constants,
				nil,
			),
		}
	}
	ids, status := a.resolveCallee(fn, callee)
	typedTargetSetClosed := status == "ambiguous" &&
		len(fn.TypedCallees[callee]) > 0 && len(ids) > 0
	if (status != "resolved" && !typedTargetSetClosed) || len(ids) == 0 {
		kind := "direct_call_unresolved"
		if status == "ambiguous" {
			kind = "direct_call_ambiguous"
		}
		return signalCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedSignalAlternatives(),
			reasons: []string{
				fn.DisplayName + ": signal-relevant call target is " + status + ": " + callee,
			},
			unresolved: []UnresolvedProofEdge{{
				Domain: "sigkill",
				Caller: fn.DisplayName,
				Kind:   kind,
				Symbol: callee,
				Detail: "the call may contain a current-task checkpoint and cannot be resolved without guessing",
			}},
		}
	}
	sourceFree := true
	for _, id := range ids {
		if a.signalEffectSourceState(id) != effectSourceNone {
			sourceFree = false
			break
		}
	}
	if sourceFree {
		return signalCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: a.sourceFreeCallAlternatives(
				fn,
				body,
				callee,
				site,
				constants,
				ids,
			),
		}
	}

	alternatives := make([]signalPathAlternative, 0)
	checks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	checkProofPaths := make(map[string][]string)
	checkPaths := make([]SignalCheckPath, 0)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	for _, id := range ids {
		childFn := a.functions[id]
		if childFn == nil {
			alternatives = mergeLSMAlternatives(
				alternatives,
				unresolvedSignalAlternatives(),
			)
			continue
		}
		childConstants := map[string]string(nil)
		if site != nil {
			arguments := make([]string, 0, len(site.Arguments))
			for _, argument := range site.Arguments {
				arguments = append(
					arguments,
					substituteIdentifierConstants(argument, constants),
				)
			}
			childConstants = a.bindCallAnalysisContext(
				fn,
				constants,
				childFn,
				arguments,
				site,
			)
			childConstants = bindCallStructConstants(
				childConstants,
				body,
				callInvocation{
					name:       callee,
					arguments:  arguments,
					callSiteID: site.ID,
				},
				childFn.Parameters,
			)
		}
		childConstants = bindCallReturnRequirement(
			childConstants,
			childFn,
			requiredCallReturnForSite(
				fn,
				childFn,
				body,
				callee,
				site,
				constants[contextReturnRequirementKey],
			),
		)
		child, cached := a.cachedFunctionSIGKILLCoverage(
			childFn,
			childConstants,
			operationContext,
		)
		if !cached {
			if witness := a.proveEffectFreeSuccessfulExecution(
				id,
				childConstants,
				operationContext,
				"sigkill",
				make(map[string]bool),
			); witness.proven {
				childAlternatives := a.annotateSuccessfulCallAlternatives(
					provenNonEnforcingLSMAlternatives(
						witness,
						childFn.DisplayName,
					),
					fn,
					childFn,
					callee,
					site,
					constants[contextReturnRequirementKey],
				)
				alternatives = mergeLSMAlternatives(
					alternatives,
					childAlternatives,
				)
				continue
			}
			child = a.analyzeFunctionSIGKILLCoverage(
				id,
				childConstants,
				operationContext,
				active,
			)
		}
		childAlternatives := a.annotateSuccessfulCallAlternatives(
			child.alternatives,
			fn,
			childFn,
			callee,
			site,
			constants[contextReturnRequirementKey],
		)
		alternatives = mergeLSMAlternatives(
			alternatives,
			childAlternatives,
		)
		checks.addAll(child.checks)
		proofFunctions.addAll(child.proofFunctions)
		for check, proofPath := range child.checkProofPaths {
			extended := append(
				append([]string(nil), proofPath...),
				fn.DisplayName,
			)
			mergeHookProofPaths(checkProofPaths, map[string][]string{
				check: extended,
			})
		}
		for _, childPath := range child.checkPaths {
			childPath.ProofPath = append(
				append([]string(nil), childPath.ProofPath...),
				fn.DisplayName,
			)
			checkPaths = mergeSignalCheckPaths(
				checkPaths,
				[]SignalCheckPath{childPath},
			)
		}
		reasons.addAll(child.reasons)
		unresolved = append(unresolved, child.unresolved...)
	}
	alternatives = composeLSMAlternativesWithEdge(
		alternatives,
		edgeEffect,
		fn.DisplayName,
	)
	states := lsmStatesForAlternatives(alternatives)
	if states&lsmPathUnresolved != 0 {
		reasons.add(fn.DisplayName + ": signal-abort propagation is unresolved: " + callee)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain: "sigkill",
			Caller: fn.DisplayName,
			Kind:   "signal_abort_effect_unresolved",
			Symbol: callee,
			Detail: "at least one child checkpoint propagation alternative remains unresolved",
		})
	}
	if states&lsmPathEnforcing != 0 {
		proofFunctions.add(fn.DisplayName)
	}
	return signalCoverageEvent{
		states:          states,
		checks:          checks.slice(),
		alternatives:    alternatives,
		proofFunctions:  proofFunctions.slice(),
		checkProofPaths: checkProofPaths,
		checkPaths:      checkPaths,
		reasons:         reasons.slice(),
		unresolved:      uniqueProofEdges(unresolved),
	}
}

func (a *Analyzer) indirectCallSignalCoverageEvent(
	fn *FunctionInfo,
	body, expression string,
	site *ClangCallSite,
	constants map[string]string,
	operationContext map[string][]string,
	active map[string]bool,
) signalCoverageEvent {
	if site != nil && site.ResultUse == "discarded" {
		return signalCoverageEvent{
			states: lsmPathNonEnforcing,
			alternatives: nonEnforcingSignalAlternatives(
				fn.DisplayName,
			),
			proofFunctions: []string{fn.DisplayName},
		}
	}
	edgeEffect := a.analyzeIndirectCallErrorEffect(fn, body, expression)
	if classifySignalAbortEffect(edgeEffect) == "not_effective" {
		return signalCoverageEvent{
			states:       lsmPathNonEnforcing,
			alternatives: nonEnforcingSignalAlternatives(fn.DisplayName),
		}
	}
	invocation, ok := findIndirectInvocation(body, expression)
	if !ok || !a.indirectTargetSetClosedWithContext(
		fn,
		invocation,
		operationContext,
		constants,
	) {
		return signalCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedSignalAlternatives(),
			reasons: []string{
				fn.DisplayName + ": indirect signal target set is open: " + expression,
			},
			unresolved: []UnresolvedProofEdge{{
				Domain:     "sigkill",
				Caller:     fn.DisplayName,
				Kind:       "indirect_signal_target_set_unproven",
				Expression: expression,
				Detail:     "the runtime function-pointer target set is not statically closed",
			}},
		}
	}
	targets := a.resolveIndirectInvocationWithContext(
		fn,
		invocation,
		operationContext,
		constants,
	)
	if len(targets) == 0 {
		return signalCoverageEvent{
			states:       lsmPathUnresolved,
			alternatives: unresolvedSignalAlternatives(),
			reasons: []string{
				fn.DisplayName + ": closed indirect target set has no modeled target",
			},
		}
	}

	alternatives := make([]signalPathAlternative, 0)
	checks := orderedSet(nil)
	proofFunctions := orderedSet(nil)
	checkProofPaths := make(map[string][]string)
	checkPaths := make([]SignalCheckPath, 0)
	reasons := orderedSet(nil)
	unresolved := make([]UnresolvedProofEdge, 0)
	for _, target := range targets {
		childFn := a.functions[target.functionID]
		if childFn == nil {
			alternatives = mergeLSMAlternatives(
				alternatives,
				unresolvedSignalAlternatives(),
			)
			continue
		}
		childConstants := a.bindCallAnalysisContext(
			fn,
			constants,
			childFn,
			target.arguments,
			site,
		)
		childConstants = bindCallReturnRequirement(
			childConstants,
			childFn,
			requiredIndirectCallReturnForSite(
				fn,
				childFn,
				body,
				site,
				constants[contextReturnRequirementKey],
			),
		)
		nextOperationContext := extendOperationContext(
			operationContext,
			target.evidence,
		)
		child, cached := a.cachedFunctionSIGKILLCoverage(
			childFn,
			childConstants,
			nextOperationContext,
		)
		if !cached {
			if witness := a.proveEffectFreeSuccessfulExecution(
				target.functionID,
				childConstants,
				nextOperationContext,
				"sigkill",
				make(map[string]bool),
			); witness.proven {
				alternatives = mergeLSMAlternatives(
					alternatives,
					provenNonEnforcingLSMAlternatives(
						witness,
						childFn.DisplayName,
					),
				)
				continue
			}
			child = a.analyzeFunctionSIGKILLCoverage(
				target.functionID,
				childConstants,
				nextOperationContext,
				active,
			)
		}
		alternatives = mergeLSMAlternatives(
			alternatives,
			projectChildAlternativesForCaller(child.alternatives),
		)
		checks.addAll(child.checks)
		proofFunctions.addAll(child.proofFunctions)
		for check, proofPath := range child.checkProofPaths {
			extended := append(
				append([]string(nil), proofPath...),
				fn.DisplayName,
			)
			mergeHookProofPaths(checkProofPaths, map[string][]string{
				check: extended,
			})
		}
		for _, childPath := range child.checkPaths {
			edge := target.evidence
			childPath.ProofPath = append(
				append([]string(nil), childPath.ProofPath...),
				fn.DisplayName,
			)
			childPath.IndirectEdges = append(
				cloneIndirectEvidence(childPath.IndirectEdges),
				edge,
			)
			checkPaths = mergeSignalCheckPaths(
				checkPaths,
				[]SignalCheckPath{childPath},
			)
		}
		reasons.addAll(child.reasons)
		unresolved = append(unresolved, child.unresolved...)
	}
	alternatives = composeLSMAlternativesWithEdge(
		alternatives,
		edgeEffect,
		fn.DisplayName,
	)
	states := lsmStatesForAlternatives(alternatives)
	if states&lsmPathUnresolved != 0 {
		reasons.add(fn.DisplayName + ": indirect signal-abort propagation is unresolved: " + expression)
		unresolved = append(unresolved, UnresolvedProofEdge{
			Domain:     "sigkill",
			Caller:     fn.DisplayName,
			Kind:       "signal_abort_effect_unresolved",
			Expression: expression,
			Detail:     "at least one closed-target checkpoint propagation alternative remains unresolved",
		})
	}
	if states&lsmPathEnforcing != 0 {
		proofFunctions.add(fn.DisplayName)
	}
	return signalCoverageEvent{
		states:          states,
		checks:          checks.slice(),
		alternatives:    alternatives,
		proofFunctions:  proofFunctions.slice(),
		checkProofPaths: checkProofPaths,
		checkPaths:      checkPaths,
		reasons:         reasons.slice(),
		unresolved:      uniqueProofEdges(unresolved),
	}
}

type namedCallSite struct {
	start int
	end   int
}

type errorTraceFacts struct {
	nullVariables map[string]struct{}
}

type signalEffectPathNode struct {
	functionID       string
	constants        map[string]string
	incomingIndirect *IndirectCallEvidence
}

type signalCheckEvidence struct {
	callSiteID          string
	relevance           string
	subject             string
	localSite           *namedCallSite
	requireSpecificSite bool
}

func (a *Analyzer) analyzeSignalAbortEffect(
	path []signalEffectPathNode,
	check string,
	localSite *namedCallSite,
	requireSpecificSite bool,
) localErrorEffect {
	if len(path) == 0 {
		return unknownLocalErrorEffect()
	}
	leafNode := path[len(path)-1]
	leaf := a.functions[leafNode.functionID]
	if leaf == nil {
		return unknownLocalErrorEffect()
	}
	leafBody := substituteIdentifierConstants(leaf.Body, leafNode.constants)
	effect := unknownLocalErrorEffect()
	switch {
	case localSite != nil:
		effect = analyzeSignalCheckLocalEffectForFunction(
			leaf,
			leafBody,
			check,
			localSite,
		)
	case !requireSpecificSite:
		effect = analyzeSignalCheckLocalEffectForFunction(
			leaf,
			leafBody,
			check,
			nil,
		)
	}
	if classifySignalAbortEffect(effect) == "unknown" &&
		a.llvmCallMustReturnNegativeOnTrue(leaf, check) {
		effect = guaranteedEncodedLocalErrorEffect(
			"normalized",
			failureReturnErrno,
			nil,
		)
	}
	for index := len(path) - 2; index >= 0; index-- {
		parentNode := path[index]
		childNode := path[index+1]
		parent := a.functions[parentNode.functionID]
		child := a.functions[childNode.functionID]
		if parent == nil || child == nil {
			return unknownLocalErrorEffect()
		}
		parentBody := substituteIdentifierConstants(parent.Body, parentNode.constants)
		var edgeEffect localErrorEffect
		if childNode.incomingIndirect != nil {
			edgeEffect = a.analyzeIndirectCallErrorEffect(parent, parentBody, childNode.incomingIndirect.Expression)
		} else {
			failureRequirement := propagatedFailureRequirement(
				effect,
				childNode.constants[contextReturnRequirementKey],
			)
			edgeEffect = a.analyzeNamedCallErrorEffect(
				parent,
				parentBody,
				child.Name,
				failureRequirement,
				parentNode.constants[contextReturnRequirementKey],
			)
		}
		effect = composeLocalErrorEffects(effect, edgeEffect)
	}
	return effect
}

func analyzeSignalCheckLocalEffectAtSite(
	body, check string,
	site namedCallSite,
) localErrorEffect {
	if check == "SIGNAL_GROUP_EXIT" {
		return analyzeSignalCheckLocalEffect(body, check)
	}
	effect := analyzeNamedCallSite(body, check, site, "", "")
	if effect.errnoPropagation == "exact" {
		effect = unknownLocalErrorEffect()
	}
	if classifySignalAbortEffect(effect) != "unknown" {
		return effect
	}
	if controlEffect := analyzePreassignedSignalErrorEffectAtSite(body, check, site); classifySignalAbortEffect(controlEffect) == "guaranteed" {
		return controlEffect
	}
	if assignedEffect := analyzeAssignedSignalErrorEffectAtSite(body, check, site); classifySignalAbortEffect(assignedEffect) == "guaranteed" {
		return assignedEffect
	}
	if conditionalEffect := analyzeConditionalSignalErrorEffectAtSite(body, check, site); classifySignalAbortEffect(conditionalEffect) == "conditional" {
		return conditionalEffect
	}
	return effect
}

func analyzeSignalCheckLocalEffectForFunction(
	fn *FunctionInfo,
	body, check string,
	site *namedCallSite,
) localErrorEffect {
	var effect localErrorEffect
	if site != nil {
		effect = analyzeSignalCheckLocalEffectAtSite(body, check, *site)
	} else {
		effect = analyzeSignalCheckLocalEffect(body, check)
	}
	if classifySignalAbortEffect(effect) != "unknown" ||
		fn == nil || check == "SIGNAL_GROUP_EXIT" {
		return effect
	}
	if cfgEffect := analyzeCFGSignalCheckFailureEffect(
		fn,
		check,
	); classifySignalAbortEffect(cfgEffect) == "guaranteed" {
		return cfgEffect
	}
	sites := []namedCallSite(nil)
	if site != nil {
		sites = []namedCallSite{*site}
	} else {
		sites = findNamedCallSites(body, check)
	}
	encodedEffects := make([]localErrorEffect, 0, len(sites))
	for _, candidate := range sites {
		detail, ok := enclosingIfCondition(body, candidate.start)
		if !ok {
			continue
		}
		relation := positiveCallConditionRelation(
			detail.condText,
			body[candidate.start:candidate.end],
		)
		if relation == "unknown" {
			continue
		}
		encoding := terminalFunctionFailureEncoding(
			fn,
			detail.bodyText,
		)
		if encoding == failureReturnUnknown {
			continue
		}
		encoded := guaranteedEncodedLocalErrorEffect(
			"exact",
			encoding,
			nil,
		)
		if relation == "conditional" {
			encoded.blocksOperation = "conditional"
			encoded.terminatesSyscall = "conditional"
			encoded.errnoPropagation = "conditional"
		}
		encodedEffects = append(encodedEffects, encoded)
	}
	if len(encodedEffects) == 0 {
		return effect
	}
	return mergeLocalErrorEffects(encodedEffects)
}

type cfgSignalFailureState struct {
	blockID     int
	constraints []successPathConstraint
	values      map[string]cfgPathValue
	visited     map[int]bool
}

func analyzeCFGSignalCheckFailureEffect(
	fn *FunctionInfo,
	check string,
) localErrorEffect {
	if fn == nil || fn.Frontend != "clang-ast-cfg" ||
		!fn.CFGComplete || fn.FrontendVariantConflict ||
		check == "" {
		return unknownLocalErrorEffect()
	}
	sites := make([]ClangCallSite, 0)
	for _, site := range fn.CallSites {
		if site.Direct && site.Name == check &&
			site.Reachable && site.HasBlock {
			sites = append(sites, site)
		}
	}
	if len(sites) != 1 {
		return unknownLocalErrorEffect()
	}
	site := sites[0]
	source, ok := cfgBlockByID(fn, site.BlockID)
	if !ok || source.TerminatorCondition == "" {
		return unknownLocalErrorEffect()
	}
	callExpression := check + "(" +
		strings.Join(site.Arguments, ",") + ")"
	requiredBranch := ""
	switch {
	case positiveCallConditionRelation(
		source.TerminatorCondition,
		callExpression,
	) == "guaranteed":
		requiredBranch = "true"
	case negativeCallConditionRelation(
		source.TerminatorCondition,
		callExpression,
	) == "guaranteed":
		requiredBranch = "false"
	default:
		return unknownLocalErrorEffect()
	}
	start := -1
	for _, edge := range allCFGSuccessorEdges(source) {
		if edge.branch != requiredBranch {
			continue
		}
		if start >= 0 {
			return unknownLocalErrorEffect()
		}
		start = edge.blockID
	}
	if start < 0 || start == fn.CFGExit {
		return unknownLocalErrorEffect()
	}
	blocks := make(map[int]ClangCFGBlock, len(fn.CFGBlocks))
	for _, block := range fn.CFGBlocks {
		blocks[block.ID] = block
	}
	if _, ok := blocks[start]; !ok {
		return unknownLocalErrorEffect()
	}
	queue := []cfgSignalFailureState{{
		blockID: start,
		constraints: []successPathConstraint{{
			functionID: fn.ID,
			blockID:    source.ID,
			expression: strings.TrimSpace(
				source.TerminatorCondition,
			),
			required:   requiredBranch == "true",
			pathStable: true,
		}},
		visited: map[int]bool{
			source.ID: true,
			start:     true,
		},
	}}
	encoding := ""
	sawReturn := false
	processed := 0
	const maxSignalFailureStates = 1024
	for len(queue) > 0 {
		if processed >= maxSignalFailureStates {
			return unknownLocalErrorEffect()
		}
		processed++
		state := queue[0]
		queue = queue[1:]
		block, ok := blocks[state.blockID]
		if !ok {
			return unknownLocalErrorEffect()
		}
		valueState := applyCFGValueWritesToAlternatives(
			fn,
			block,
			[]lsmPathAlternative{{
				bypassConstraints: state.constraints,
				bypassValues:      state.values,
			}},
		)
		if len(valueState) != 1 {
			return unknownLocalErrorEffect()
		}
		state.constraints = valueState[0].bypassConstraints
		state.values = valueState[0].bypassValues
		if block.ReturnExpression != "" ||
			block.ReturnExpressionExpanded != "" {
			expression := resolvedCFGConstantReturnExpression(
				clangCFGReturnExpression(block),
				state.values,
			)
			outcome := returnOutcomeFromExpression(
				fn,
				expression,
				state.constraints,
				false,
				nil,
				"",
			)
			candidateEncoding, guaranteed :=
				failureEncodingForReturnOutcome(outcome)
			if !guaranteed {
				return unknownLocalErrorEffect()
			}
			if encoding == "" {
				encoding = candidateEncoding
			} else if encoding != candidateEncoding {
				encoding = failureReturnUnknown
			}
			sawReturn = true
			continue
		}
		edges := allCFGSuccessorEdges(block)
		if len(edges) == 0 {
			return unknownLocalErrorEffect()
		}
		for _, edge := range edges {
			if edge.blockID == fn.CFGExit {
				return unknownLocalErrorEffect()
			}
			if _, ok := blocks[edge.blockID]; !ok ||
				state.visited[edge.blockID] {
				return unknownLocalErrorEffect()
			}
			next := cfgSignalFailureState{
				blockID: edge.blockID,
				constraints: append(
					[]successPathConstraint(nil),
					state.constraints...,
				),
				values: cloneCFGPathValues(state.values),
				visited: make(
					map[int]bool,
					len(state.visited)+1,
				),
			}
			for blockID := range state.visited {
				next.visited[blockID] = true
			}
			next.visited[edge.blockID] = true
			if block.TerminatorCondition != "" &&
				(edge.branch == "true" ||
					edge.branch == "false") {
				next.constraints =
					canonicalSuccessPathConstraints(append(
						next.constraints,
						successPathConstraint{
							functionID: fn.ID,
							blockID:    block.ID,
							expression: strings.TrimSpace(
								block.TerminatorCondition,
							),
							required:   edge.branch == "true",
							pathStable: true,
						},
					))
			}
			queue = append(queue, next)
		}
	}
	if !sawReturn {
		return unknownLocalErrorEffect()
	}
	if encoding == "" {
		encoding = failureReturnUnknown
	}
	return guaranteedEncodedLocalErrorEffect(
		"normalized",
		encoding,
		nil,
	)
}

func failureEncodingForReturnOutcome(
	outcome returnOutcome,
) (string, bool) {
	switch outcome.domain {
	case returnDomainSigned:
		return failureReturnErrno,
			outcome.mask != 0 &&
				outcome.mask&^outcomeNegative == 0
	case returnDomainPointer:
		switch {
		case outcome.mask != 0 &&
			outcome.mask&^outcomePointerNull == 0:
			return failureReturnNull, true
		case outcome.mask != 0 &&
			outcome.mask&^outcomePointerError == 0:
			return failureReturnErrPtr, true
		case outcome.mask != 0 &&
			outcome.mask&^(outcomePointerNull|
				outcomePointerError) == 0:
			return failureReturnUnknown, true
		}
	case returnDomainBool:
		return failureReturnFalse,
			outcome.mask != 0 &&
				outcome.mask&^outcomeBoolFalse == 0
	}
	return failureReturnUnknown, false
}

func terminalFunctionFailureEncoding(
	fn *FunctionInfo,
	branch string,
) string {
	if fn == nil {
		return failureReturnUnknown
	}
	trimmed := strings.TrimSpace(branch)
	match := regexp.MustCompile(
		`\breturn\s+([^;]+);\s*$`,
	).FindStringSubmatchIndex(trimmed)
	if len(match) != 4 {
		return failureReturnUnknown
	}
	prefix := maskStringAndCharLiterals(trimmed[:match[0]])
	if regexp.MustCompile(
		`\b(?:if|switch|for|while|do|goto|return|break|continue|case|default)\b`,
	).MatchString(prefix) {
		return failureReturnUnknown
	}
	expression := trimmed[match[2]:match[3]]
	expression = stripSimpleCasts(compactExpression(expression))
	switch returnDomainForType(fn.ReturnType) {
	case returnDomainSigned:
		if isExplicitNegativeError(expression) {
			return failureReturnErrno
		}
	case returnDomainPointer:
		switch {
		case expression == "NULL" || expression == "0":
			return failureReturnNull
		case strings.HasPrefix(expression, "ERR_PTR("):
			argument, ok := singleCallArgument(expression, "ERR_PTR")
			if ok && isExplicitNegativeError(argument) {
				return failureReturnErrPtr
			}
		}
	case returnDomainBool:
		if expression == "false" || expression == "0" {
			return failureReturnFalse
		}
	}
	return failureReturnUnknown
}

func analyzeSignalCheckLocalEffect(body, check string) localErrorEffect {
	if check != "SIGNAL_GROUP_EXIT" {
		effect := analyzeNamedCallErrorEffect(body, check)
		if effect.errnoPropagation == "exact" {
			effect = unknownLocalErrorEffect()
		}
		if classifySignalAbortEffect(effect) == "unknown" {
			controlEffect := analyzePreassignedSignalErrorEffect(body, check)
			if classifySignalAbortEffect(controlEffect) == "guaranteed" {
				return controlEffect
			}
			assignedEffect := analyzeAssignedSignalErrorEffect(body, check)
			if classifySignalAbortEffect(assignedEffect) == "guaranteed" {
				return assignedEffect
			}
			conditionalEffect := analyzeConditionalSignalErrorEffect(body, check)
			if classifySignalAbortEffect(conditionalEffect) == "conditional" {
				return conditionalEffect
			}
		}
		return effect
	}
	masked := maskStringAndCharLiterals(body)
	indexes := regexp.MustCompile(`\bSIGNAL_GROUP_EXIT\b`).FindAllStringIndex(masked, -1)
	effects := make([]localErrorEffect, 0, len(indexes))
	for _, index := range indexes {
		effects = append(effects, analyzeNamedCallSite(
			body,
			check,
			namedCallSite{start: index[0], end: index[1]},
			"",
			"",
		))
	}
	effect := mergeLocalErrorEffects(effects)
	if effect.errnoPropagation == "exact" {
		return unknownLocalErrorEffect()
	}
	return effect
}

func analyzePreassignedSignalErrorEffect(body, check string) localErrorEffect {
	effects := make([]localErrorEffect, 0)
	for _, site := range findNamedCallSites(body, check) {
		effect := analyzePreassignedSignalErrorEffectAtSite(body, check, site)
		if classifySignalAbortEffect(effect) == "guaranteed" {
			effects = append(effects, effect)
		}
	}
	if len(effects) == 0 {
		return unknownLocalErrorEffect()
	}
	return mergeLocalErrorEffects(effects)
}

func analyzePreassignedSignalErrorEffectAtSite(
	body, check string,
	site namedCallSite,
) localErrorEffect {
	detail, ok := enclosingIfCondition(body, site.start)
	if !ok || !conditionIsDirectPositiveCall(detail.condText, body[site.start:site.end]) {
		return unknownLocalErrorEffect()
	}
	variable, ok := immediatelyPreassignedNegativeError(body, detail.start)
	if !ok {
		return unknownLocalErrorEffect()
	}
	effect := terminalErrorEffectWithFacts(body, detail.bodyText, variable, 0, errorTraceFacts{})
	if effect.blocksOperation != "guaranteed" || effect.terminatesSyscall != "guaranteed" {
		return unknownLocalErrorEffect()
	}
	effect.errnoPropagation = "normalized"
	return effect
}

func analyzeAssignedSignalErrorEffect(body, check string) localErrorEffect {
	effects := make([]localErrorEffect, 0)
	for _, site := range findNamedCallSites(body, check) {
		effect := analyzeAssignedSignalErrorEffectAtSite(body, check, site)
		if classifySignalAbortEffect(effect) == "guaranteed" {
			effects = append(effects, effect)
		}
	}
	if len(effects) == 0 {
		return unknownLocalErrorEffect()
	}
	return mergeLocalErrorEffects(effects)
}

func analyzeAssignedSignalErrorEffectAtSite(
	body, check string,
	site namedCallSite,
) localErrorEffect {
	detail, ok := enclosingIfCondition(body, site.start)
	if !ok || !conditionIsDirectPositiveCall(
		detail.condText,
		body[site.start:site.end],
	) {
		return unknownLocalErrorEffect()
	}
	variable, assignmentEnd, ok := topLevelNegativeAssignment(detail.bodyText)
	if !ok || assignsVariable(detail.bodyText[assignmentEnd:], variable) {
		return unknownLocalErrorEffect()
	}
	effect := terminalErrorEffectWithFacts(
		body,
		body[detail.nextPos:],
		variable,
		0,
		errorTraceFacts{},
	)
	if classifySignalAbortEffect(effect) != "guaranteed" {
		return unknownLocalErrorEffect()
	}
	effect.errnoPropagation = "normalized"
	effect.failureEncoding = failureReturnErrno
	return effect
}

func topLevelNegativeAssignment(body string) (string, int, bool) {
	masked := maskStringAndCharLiterals(body)
	pattern := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);`)
	depth := 0
	cursor := 0
	for _, match := range pattern.FindAllStringSubmatchIndex(masked, -1) {
		for cursor < match[0] {
			switch masked[cursor] {
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			}
			cursor++
		}
		if depth == 0 && isExplicitNegativeError(strings.TrimSpace(body[match[4]:match[5]])) {
			return body[match[2]:match[3]], match[1], true
		}
		cursor = match[1]
	}
	return "", 0, false
}

func analyzeConditionalSignalErrorEffect(body, check string) localErrorEffect {
	effects := make([]localErrorEffect, 0)
	for _, site := range findNamedCallSites(body, check) {
		effect := analyzeConditionalSignalErrorEffectAtSite(body, check, site)
		if classifySignalAbortEffect(effect) == "conditional" {
			effects = append(effects, effect)
		}
	}
	if len(effects) == 0 {
		return unknownLocalErrorEffect()
	}
	return mergeLocalErrorEffects(effects)
}

func analyzeConditionalSignalErrorEffectAtSite(
	body, check string,
	site namedCallSite,
) localErrorEffect {
	if detail, ok := enclosingIfCondition(body, site.start); ok &&
		conditionHasPositiveConjunct(detail.condText, body[site.start:site.end]) {
		if effect, ok := conditionalSignalBranchEffect(body, detail); ok {
			return effect
		}
	}

	predicate := assignedCallTarget(body, site.start)
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(predicate) ||
		!hasLocalScalarBinding(body, site.start, predicate) {
		return unknownLocalErrorEffect()
	}
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return unknownLocalErrorEffect()
	}
	ifPattern := regexp.MustCompile(`\bif\s*\(`)
	for _, location := range ifPattern.FindAllStringIndex(body[statementEnd+1:], -1) {
		ifStart := statementEnd + 1 + location[0]
		between := body[statementEnd+1 : ifStart]
		if assignsVariable(between, predicate) ||
			hasUnsupportedScalarMutation(between, predicate) ||
			addressEscapesVariable(between, predicate) {
			break
		}
		detail, ok := parseIfDetail(body, ifStart)
		if !ok || !conditionHasPositiveConjunct(detail.condText, predicate) {
			continue
		}
		if effect, ok := conditionalSignalBranchEffect(body, detail); ok {
			return effect
		}
		break
	}
	return unknownLocalErrorEffect()
}

func hasLocalScalarBinding(body string, callStart int, variable string) bool {
	if callStart < 0 || callStart > len(body) {
		return false
	}
	quoted := regexp.QuoteMeta(variable)
	currentStatementStart := callStart
	for currentStatementStart > 0 {
		previous := body[currentStatementStart-1]
		if previous == ';' || previous == '{' || previous == '}' {
			break
		}
		currentStatementStart--
	}
	currentPrefix := strings.TrimSpace(body[currentStatementStart:callStart])
	if regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*\s+)+(?:\*+\s*)?` + quoted + `\s*=\s*$`).MatchString(currentPrefix) {
		return true
	}
	declaration := regexp.MustCompile(
		`(?m)(?:^|[;{}])\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)+(?:\*+\s*)?` +
			quoted + `\s*(?:=[^;]*)?;`,
	)
	return declaration.MatchString(body[:callStart])
}

func hasUnsupportedScalarMutation(body, variable string) bool {
	quoted := regexp.QuoteMeta(variable)
	patterns := []string{
		`\b` + quoted + `\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)`,
		`(?:\+\+|--)\s*\b` + quoted + `\b`,
	}
	return matchesAny(maskStringAndCharLiterals(body), patterns)
}

func conditionalSignalBranchEffect(body string, detail ifDetail) (localErrorEffect, bool) {
	variable, ok := explicitNegativeAssignment(detail.bodyText)
	if !ok {
		return localErrorEffect{}, false
	}
	effect := traceTaintedErrorWithFacts(body, body[detail.nextPos:], variable, 0, errorTraceFacts{})
	if effect.blocksOperation != "guaranteed" || effect.terminatesSyscall != "guaranteed" {
		return localErrorEffect{}, false
	}
	effect.blocksOperation = "conditional"
	effect.terminatesSyscall = "conditional"
	effect.errnoPropagation = "normalized"
	return effect, true
}

func explicitNegativeAssignment(body string) (string, bool) {
	statement := strings.TrimSpace(body)
	match := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);$`).FindStringSubmatch(statement)
	if len(match) != 3 || !isExplicitNegativeError(strings.TrimSpace(match[2])) {
		return "", false
	}
	return match[1], true
}

func conditionHasPositiveConjunct(condition, target string) bool {
	terms, ok := splitTopLevelConjunction(condition)
	if !ok {
		return false
	}
	target = compactExpression(target)
	for _, term := range terms {
		term = compactExpression(term)
		for {
			unwrapped, wrapped := unwrapSingleCallWrapper(term, "likely")
			if !wrapped {
				unwrapped, wrapped = unwrapSingleCallWrapper(term, "unlikely")
			}
			if !wrapped {
				break
			}
			term = compactExpression(unwrapped)
		}
		if term == target {
			return true
		}
	}
	return false
}

func splitTopLevelConjunction(expression string) ([]string, bool) {
	masked := maskStringAndCharLiterals(expression)
	depth := 0
	start := 0
	terms := make([]string, 0, 2)
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 && index+1 < len(masked) && masked[index+1] == '|' {
				return nil, false
			}
		case '&':
			if depth == 0 && index+1 < len(masked) && masked[index+1] == '&' {
				terms = append(terms, strings.TrimSpace(expression[start:index]))
				start = index + 2
				index++
			}
		}
	}
	terms = append(terms, strings.TrimSpace(expression[start:]))
	return terms, len(terms) > 0
}

func conditionIsDirectPositiveCall(condition, call string) bool {
	condition = compactExpression(condition)
	call = compactExpression(call)
	for {
		unwrapped, ok := unwrapSingleCallWrapper(condition, "likely")
		if !ok {
			unwrapped, ok = unwrapSingleCallWrapper(condition, "unlikely")
		}
		if !ok {
			break
		}
		condition = compactExpression(unwrapped)
	}
	return condition == call
}

func compactExpression(expression string) string {
	expression = strings.Join(strings.Fields(strings.TrimSpace(expression)), "")
	for len(expression) >= 2 && expression[0] == '(' {
		closeParen, ok := findMatchingParenForward(expression, 0)
		if !ok || closeParen != len(expression)-1 {
			break
		}
		expression = strings.TrimSpace(expression[1:closeParen])
	}
	return expression
}

func unwrapSingleCallWrapper(expression, wrapper string) (string, bool) {
	prefix := wrapper + "("
	if !strings.HasPrefix(expression, prefix) {
		return "", false
	}
	openParen := len(wrapper)
	closeParen, ok := findMatchingParenForward(expression, openParen)
	if !ok || closeParen != len(expression)-1 {
		return "", false
	}
	return expression[openParen+1 : closeParen], true
}

func immediatelyPreassignedNegativeError(body string, position int) (string, bool) {
	end := position
	for end > 0 && unicode.IsSpace(rune(body[end-1])) {
		end--
	}
	if end == 0 || body[end-1] != ';' {
		return "", false
	}
	start := end - 1
	for start > 0 {
		previous := body[start-1]
		if previous == ';' || previous == '{' || previous == '}' {
			break
		}
		start--
	}
	statement := strings.TrimSpace(body[start:end])
	match := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);$`).FindStringSubmatch(statement)
	if len(match) == 3 && isExplicitNegativeError(strings.TrimSpace(match[2])) {
		return match[1], true
	}
	declaration := regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*\s+)+(?:\*+\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);$`).FindStringSubmatch(statement)
	if len(declaration) == 3 && isExplicitNegativeError(strings.TrimSpace(declaration[2])) {
		return declaration[1], true
	}
	return "", false
}

func classifySignalAbortEffect(effect localErrorEffect) string {
	switch {
	case effect.blocksOperation == "guaranteed" &&
		effect.terminatesSyscall == "guaranteed" &&
		effect.errnoPropagation != "unknown" &&
		effect.errnoPropagation != "ignored":
		return "guaranteed"
	case effect.blocksOperation == "conditional" &&
		effect.terminatesSyscall == "conditional" &&
		effect.errnoPropagation != "unknown" &&
		effect.errnoPropagation != "ignored":
		return "conditional"
	case effect.blocksOperation == "no" ||
		effect.terminatesSyscall == "no" ||
		effect.errnoPropagation == "ignored":
		return "not_effective"
	default:
		return "unknown"
	}
}

func classifyFinalSignalAbortEffect(effect localErrorEffect) string {
	return classifySignalAbortEffect(effect)
}

const reviewedKernelLSMGateProofMethod = "reviewed_kernel_success_gate_contract"

type reviewedKernelLSMGate struct {
	hook   string
	effect localErrorEffect
}

func reviewedKernelFunctionLSMGates(
	fn *FunctionInfo,
) []reviewedKernelLSMGate {
	if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete ||
		fn.FrontendVariantConflict {
		return nil
	}
	file := filepath.ToSlash(fn.File)
	body := strings.Join(strings.Fields(fn.Body), "")
	matches := func(parts ...string) bool {
		for _, part := range parts {
			if !strings.Contains(body, part) {
				return false
			}
		}
		return true
	}
	errnoGate := func(hook string) []reviewedKernelLSMGate {
		return []reviewedKernelLSMGate{{
			hook: hook,
			effect: guaranteedEncodedLocalErrorEffect(
				"normalized",
				failureReturnErrno,
				nil,
			),
		}}
	}

	switch {
	case strings.HasSuffix(file, "/fs/eventpoll.c") &&
		fn.Name == "do_epoll_create" &&
		matches(
			"file=anon_inode_getfile(",
			"if(IS_ERR(file)){",
			"error=PTR_ERR(file);",
			"fd_install(fd,file);",
			"returnfd;",
			"returnerror;",
		):
		return errnoGate("security_file_alloc")
	case strings.HasSuffix(file, "/ipc/mqueue.c") &&
		fn.Name == "do_mq_open" &&
		matches(
			"file=dentry_open(&path,oflag,current_cred());",
			"if(!IS_ERR(file))",
			"error=PTR_ERR(file);",
			"fd=error;",
			"returnfd;",
		):
		return errnoGate("security_file_alloc")
	case strings.HasSuffix(file, "/fs/fhandle.c") &&
		fn.Name == "do_handle_open" &&
		matches(
			"file=file_open_root(&path,\"\",open_flag,0);",
			"if(IS_ERR(file)){",
			"retval=PTR_ERR(file);",
			"fd_install(fd,file);",
			"returnretval;",
		):
		return errnoGate("security_file_alloc")
	case strings.HasSuffix(file, "/mm/memfd.c") &&
		fn.Name == "__do_sys_memfd_create" &&
		matches(
			"file=hugetlb_file_setup(",
			"file=shmem_file_setup(",
			"if(IS_ERR(file)){",
			"error=PTR_ERR(file);",
			"fd_install(fd,file);",
			"returnfd;",
			"returnerror;",
		):
		return errnoGate("security_file_alloc")
	case strings.HasSuffix(file, "/fs/namespace.c") &&
		fn.Name == "__do_sys_open_tree" &&
		matches(
			"file=open_detached_copy(&path,flags&AT_RECURSIVE);",
			"file=dentry_open(&path,O_PATH,current_cred());",
			"if(IS_ERR(file)){",
			"returnPTR_ERR(file);",
			"fd_install(fd,file);",
			"returnfd;",
		):
		return errnoGate("security_file_alloc")
	case strings.HasSuffix(file, "/mm/madvise.c") &&
		fn.Name == "__do_sys_process_madvise" &&
		matches(
			"if(!capable(CAP_SYS_NICE)){",
			"ret=-EPERM;",
			"gotorelease_mm;",
			"release_mm:",
			"returnret;",
		):
		return errnoGate("security_capable")
	default:
		return nil
	}
}

func (a *Analyzer) kernelGateMandatoryLSMHooks(start string) []string {
	hooks := orderedSet(nil)
	visited := make(map[string]bool)
	active := make(map[string]bool)
	var walk func(string, map[string]string)
	walk = func(functionID string, constants map[string]string) {
		fn := a.functions[functionID]
		if fn == nil || fn.Frontend != "clang-ast-cfg" || !fn.CFGComplete || fn.FrontendVariantConflict {
			return
		}
		contextKey := functionContextKey(fn, constants)
		if visited[contextKey] || active[functionID] {
			return
		}
		visited[contextKey] = true
		active[functionID] = true
		defer delete(active, functionID)
		scan := a.cachedContextKernelSuccessScan(fn, constants)
		hooks.addAll(scan.lsmHooks)
		for _, gate := range reviewedKernelFunctionLSMGates(fn) {
			if a.isConfiguredLSMHookActive(gate.hook) {
				hooks.add(gate.hook)
			}
		}
		for _, call := range a.resolveContextCallsInContext(fn, constants, scan) {
			if call.indirect != nil && !call.indirect.TargetSetClosed {
				continue
			}
			walk(call.functionID, call.constants)
		}
	}
	walk(start, nil)
	return hooks.slice()
}

func (a *Analyzer) analyzeLSMErrorEffects(start string, mandatoryHooks []string) ([]LSMErrorEffect, []string) {
	return a.analyzeLSMErrorEffectsWithScan(start, mandatoryHooks, a.cachedContextSuccessScan, false)
}

func (a *Analyzer) analyzeKernelGateLSMErrorEffects(start string, mandatoryHooks []string) ([]LSMErrorEffect, []string) {
	return a.analyzeLSMErrorEffectsWithScan(start, mandatoryHooks, a.cachedContextKernelSuccessScan, false)
}

func (a *Analyzer) analyzeLSMErrorEffectsWithScan(
	start string,
	mandatoryHooks []string,
	scanFunction func(*FunctionInfo, map[string]string) prefixScanResult,
	followIndirect bool,
) ([]LSMErrorEffect, []string) {
	mandatory := make(map[string]struct{}, len(mandatoryHooks))
	for _, hook := range mandatoryHooks {
		mandatory[hook] = struct{}{}
	}

	type errorPathNode struct {
		functionID string
		constants  map[string]string
	}
	visited := make(map[string]bool)
	active := make(map[string]bool)
	byHook := make(map[string]LSMErrorEffect)
	var walk func(string, map[string]string, []errorPathNode)
	walk = func(functionID string, constants map[string]string, path []errorPathNode) {
		fn, ok := a.functions[functionID]
		if !ok {
			return
		}
		contextKey := functionContextKey(fn, constants)
		if visited[contextKey] || active[functionID] {
			return
		}
		visited[contextKey] = true
		active[functionID] = true
		defer delete(active, functionID)
		path = append(append([]errorPathNode(nil), path...), errorPathNode{functionID: functionID, constants: constants})
		body := substituteIdentifierConstants(fn.Body, constants)
		scan := scanFunction(fn, constants)
		recordEffect := func(
			hook string,
			effect localErrorEffect,
			proofMethod string,
		) {
			if _, ok := mandatory[hook]; !ok {
				return
			}
			proofPath := []string{hook, fn.DisplayName}
			for index := len(path) - 2; index >= 0; index-- {
				parentNode := path[index]
				childNode := path[index+1]
				parent := a.functions[parentNode.functionID]
				child := a.functions[childNode.functionID]
				if parent == nil || child == nil {
					effect = unknownLocalErrorEffect()
					break
				}
				parentBody := substituteIdentifierConstants(parent.Body, parentNode.constants)
				failureRequirement := propagatedFailureRequirement(
					effect,
					childNode.constants[contextReturnRequirementKey],
				)
				edgeEffect := a.analyzeNamedCallErrorEffect(parent, parentBody, child.Name,
					failureRequirement, parentNode.constants[contextReturnRequirementKey])
				effect = composeLocalErrorEffects(effect, edgeEffect)
				proofPath = append(proofPath, parent.DisplayName)
			}

			candidate := LSMErrorEffect{
				Hook:              hook,
				BPFHook:           a.canonicalBPFLSMHook(hook),
				HookKind:          a.classifyLSMHookKind(hook, effect),
				CallsiteFunctions: []string{fn.DisplayName},
				BlocksOperation:   effect.blocksOperation,
				TerminatesSyscall: effect.terminatesSyscall,
				ErrnoPropagation:  effect.errnoPropagation,
				FailureEncoding:   effect.failureEncoding,
				OverwriteSites:    uniqueStrings(effect.overwriteSites),
				ProofPath:         proofPath,
				ProofMethod:       proofMethod,
				LLVMEvidence:      a.llvmFactsForHook(fn, hook),
			}
			candidate.LLVMVerification = classifyLLVMVerification(candidate.LLVMEvidence)
			if existing, ok := byHook[hook]; ok {
				switch {
				case isCertifiedReviewedKernelLSMEffect(existing):
					candidate = existing
				case isCertifiedReviewedKernelLSMEffect(candidate):
				default:
					candidate = mergeLSMErrorEffects(existing, candidate)
				}
			}
			byHook[hook] = candidate
		}
		for _, hook := range scan.lsmHooks {
			recordEffect(
				hook,
				a.localLSMErrorEffectForBody(fn, body, hook),
				"",
			)
		}
		for _, gate := range reviewedKernelFunctionLSMGates(fn) {
			recordEffect(
				gate.hook,
				gate.effect,
				reviewedKernelLSMGateProofMethod,
			)
		}

		for _, call := range a.resolveContextCallsInContext(fn, constants, scan) {
			if call.indirect != nil && !followIndirect && !call.indirect.TargetSetClosed {
				continue
			}
			walk(call.functionID, call.constants, path)
		}
	}
	walk(start, nil, nil)

	effects := make([]LSMErrorEffect, 0, len(byHook))
	effectiveHooks := orderedSet(nil)
	for _, hook := range mandatoryHooks {
		effect, ok := byHook[hook]
		if !ok {
			effect = LSMErrorEffect{
				Hook:              hook,
				BPFHook:           a.canonicalBPFLSMHook(hook),
				HookKind:          a.classifyLSMHookKind(hook, unknownLocalErrorEffect()),
				BlocksOperation:   "unknown",
				TerminatesSyscall: "unknown",
				ErrnoPropagation:  "unknown",
				FailureEncoding:   failureReturnUnknown,
				LLVMVerification:  "unknown",
			}
		}
		effects = append(effects, effect)
		if effect.HookKind == "error-return" && effect.BlocksOperation == "guaranteed" && effect.TerminatesSyscall == "guaranteed" &&
			effect.ErrnoPropagation != "ignored" && effect.ErrnoPropagation != "unknown" &&
			effect.FailureEncoding == failureReturnErrno &&
			effect.LLVMVerification != "contradicted_ignored" {
			effectiveHooks.add(hook)
		}
	}
	return effects, effectiveHooks.slice()
}

func (a *Analyzer) llvmFactsForHook(fn *FunctionInfo, hook string) []LLVMHookFact {
	result := make([]LLVMHookFact, 0)
	standalone := make([]LLVMHookFact, 0)
	for _, fact := range fn.LLVMHookFacts {
		if fact.Hook == hook {
			result = append(result, fact)
			if fact.Function == fn.Name && len(fact.InlinedAtFunctions) == 0 {
				standalone = append(standalone, fact)
			}
		}
	}
	if len(standalone) > 0 {
		result = standalone
	}
	return uniqueLLVMHookFacts(result)
}

func classifyLLVMVerification(facts []LLVMHookFact) string {
	corroborated := false
	ignored := false
	actual := false
	for _, fact := range facts {
		switch fact.Verification {
		case "must_return_exact", "must_return_negative", "controls_branch", "controls_branch_and_reaches_return", "reaches_return":
			corroborated = true
			actual = true
		case "ignored":
			ignored = true
			actual = true
		case "ssa_use_unresolved":
			actual = true
		}
	}
	switch {
	case corroborated && ignored:
		return "mixed"
	case corroborated:
		return "corroborated"
	case actual && ignored:
		return "contradicted_ignored"
	default:
		return "unknown"
	}
}

func (a *Analyzer) classifyLSMHookKind(hook string, effect localErrorEffect) string {
	kinds := orderedSet(nil)
	for _, functionID := range a.nameIndex[hook] {
		fn := a.functions[functionID]
		if fn == nil {
			continue
		}
		switch fn.ReturnType {
		case "void":
			kinds.add("notification")
		case "int", "bool", "long", "unsigned", "ssize_t", "size_t",
			"signed_integer", "unsigned_integer":
			kinds.add("error-return")
		}
	}
	if len(kinds.items) == 1 {
		return kinds.items[0]
	}
	if len(kinds.items) == 0 && effect.errnoPropagation != "ignored" && effect.errnoPropagation != "unknown" {
		return "error-return"
	}
	return "unknown"
}

func analyzeNamedCallErrorEffect(body, callee string, requirements ...string) localErrorEffect {
	calleeRequirement := ""
	functionRequirement := ""
	if len(requirements) > 0 {
		calleeRequirement = requirements[0]
	}
	if len(requirements) > 1 {
		functionRequirement = requirements[1]
	}
	sites := findNamedCallSites(body, callee)
	if len(sites) == 0 {
		return unknownLocalErrorEffect()
	}
	effects := make([]localErrorEffect, 0, len(sites))
	for _, site := range sites {
		effects = append(effects, analyzeNamedCallSite(body, callee, site, calleeRequirement, functionRequirement))
	}
	return mergeLocalErrorEffects(effects)
}

func findNamedCallSites(body, callee string) []namedCallSite {
	masked := maskStringAndCharLiterals(body)
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(callee) + `\s*\(`)
	indexes := pattern.FindAllStringIndex(masked, -1)
	result := make([]namedCallSite, 0, len(indexes))
	for _, index := range indexes {
		openOffset := strings.LastIndex(masked[index[0]:index[1]], "(")
		if openOffset < 0 {
			continue
		}
		openParen := index[0] + openOffset
		closeParen, ok := findMatchingParenForward(masked, openParen)
		if !ok {
			continue
		}
		result = append(result, namedCallSite{start: index[0], end: closeParen + 1})
	}
	return result
}

func analyzeCallExpressionErrorEffect(body, expression string) localErrorEffect {
	sites := findExpressionCallSites(body, expression)
	if len(sites) == 0 {
		return unknownLocalErrorEffect()
	}
	effects := make([]localErrorEffect, 0, len(sites))
	for _, site := range sites {
		effects = append(effects, analyzeNamedCallSite(body, expression, site, "", ""))
	}
	return mergeLocalErrorEffects(effects)
}

func findExpressionCallSites(body, expression string) []namedCallSite {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil
	}
	masked := maskStringAndCharLiterals(body)
	result := make([]namedCallSite, 0)
	for offset := 0; offset < len(masked); {
		index := strings.Index(masked[offset:], expression)
		if index < 0 {
			break
		}
		start := offset + index
		after := skipSpace(masked, start+len(expression))
		if after < len(masked) && masked[after] == '(' {
			if closeParen, ok := findMatchingParenForward(masked, after); ok {
				result = append(result, namedCallSite{start: start, end: closeParen + 1})
			}
		}
		offset = start + len(expression)
	}
	return result
}

func analyzeNamedCallSite(body, callee string, site namedCallSite, calleeRequirement, functionRequirement string) localErrorEffect {
	prefixStart := max(0, site.start-256)
	prefix := body[prefixStart:site.start]
	if regexp.MustCompile(`\breturn\s*$`).MatchString(prefix) {
		return guaranteedEncodedLocalErrorEffect(
			"exact",
			failureEncodingForRequirement(calleeRequirement),
			nil,
		)
	}

	if calleeRequirement == "nonnull" {
		target := assignedCallTarget(body, site.start)
		if target != "" && callSiteRequiresNonNull(body, site, target, functionRequirement) {
			return requiredCallFailureEffect(body, site, target, functionRequirement)
		}
	}

	assignment := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$`).FindStringSubmatch(prefix)
	if len(assignment) == 2 {
		statementEnd := findNextTopLevelSemicolon(body, site.end)
		if statementEnd < 0 {
			return unknownLocalErrorEffect()
		}
		if calleeRequirement == "failure_false" {
			return traceFalsyFailure(body, body[statementEnd+1:], assignment[1])
		}
		facts := inferErrorTraceFacts(body[:site.start])
		continuation := body[statementEnd+1:]
		if detail, ok := enclosingIfControlledBody(body, site.start); ok {
			remainingControlledBody := ""
			if statementEnd+1 <= detail.bodyEnd {
				remainingControlledBody = body[statementEnd+1 : detail.bodyEnd]
			}
			if strings.TrimSpace(remainingControlledBody) == "" {
				continuation = body[detail.nextPos:]
			}
		}
		return traceTaintedErrorWithFacts(body, continuation, assignment[1], 0, facts)
	}

	if detail, ok := enclosingIfCondition(body, site.start); ok {
		relation := positiveCallConditionRelation(detail.condText, body[site.start:site.end])
		if calleeRequirement == "failure_false" || calleeRequirement == "nonnull" {
			relation = negativeCallConditionRelation(detail.condText, body[site.start:site.end])
		} else if calleeRequirement == "failure_err_ptr" {
			relation = errorPointerCallConditionRelation(detail.condText, body[site.start:site.end])
		}
		if relation == "unknown" {
			return unknownLocalErrorEffect()
		}
		effect := terminalErrorEffect(body, detail.bodyText, "", 0)
		if effect.blocksOperation == "guaranteed" {
			if effect.errnoPropagation == "exact" {
				effect.errnoPropagation = "normalized"
			}
			if relation == "conditional" {
				effect.blocksOperation = "conditional"
				effect.terminatesSyscall = "conditional"
			}
			return effect
		}
		if functionRequirement == "nonnull" {
			effect = requiredFailureEffect(body, detail.bodyText, "", functionRequirement, 0)
			if effect.blocksOperation == "guaranteed" {
				effect.errnoPropagation = "normalized"
				return effect
			}
		}
		return unknownLocalErrorEffect()
	}

	_ = callee
	if !callSiteResultDefinitelyDiscarded(body, site) {
		return unknownLocalErrorEffect()
	}
	return localErrorEffect{
		blocksOperation:   "no",
		terminatesSyscall: "no",
		errnoPropagation:  "ignored",
		failureEncoding:   failureReturnNone,
	}
}

func failureEncodingForRequirement(requirement string) string {
	switch requirement {
	case "failure_false":
		return failureReturnFalse
	case "nonnull":
		return failureReturnNull
	case "failure_err_ptr":
		return failureReturnErrPtr
	default:
		return failureReturnErrno
	}
}

func positiveCallConditionRelation(condition, call string) string {
	condition = compactExpression(condition)
	call = compactExpression(call)
	if call == "" || strings.Count(condition, call) != 1 {
		return "unknown"
	}
	for {
		unwrapped, ok := unwrapSingleCallWrapper(condition, "likely")
		if !ok {
			unwrapped, ok = unwrapSingleCallWrapper(condition, "unlikely")
		}
		if !ok {
			break
		}
		condition = compactExpression(unwrapped)
	}
	if condition == call || condition == "!!"+call ||
		condition == call+"!=0" || condition == "0!="+call {
		return "guaranteed"
	}
	if terms := splitTopLevelBooleanTerms(condition, "||"); len(terms) > 1 {
		relation := "unknown"
		for _, term := range terms {
			switch positiveCallConditionRelation(term, call) {
			case "guaranteed":
				return "guaranteed"
			case "conditional":
				relation = "conditional"
			}
		}
		return relation
	}
	if terms := splitTopLevelBooleanTerms(condition, "&&"); len(terms) > 1 {
		for _, term := range terms {
			if positiveCallConditionRelation(term, call) != "unknown" {
				return "conditional"
			}
		}
	}
	return "unknown"
}

func negativeCallConditionRelation(condition, call string) string {
	condition = compactExpression(condition)
	call = compactExpression(call)
	if call == "" || strings.Count(condition, call) != 1 {
		return "unknown"
	}
	for {
		unwrapped, ok := unwrapSingleCallWrapper(condition, "likely")
		if !ok {
			unwrapped, ok = unwrapSingleCallWrapper(condition, "unlikely")
		}
		if !ok {
			break
		}
		condition = compactExpression(unwrapped)
	}
	if condition == "!"+call || condition == call+"==0" ||
		condition == "0=="+call || condition == call+"==false" ||
		condition == "false=="+call {
		return "guaranteed"
	}
	if terms := splitTopLevelBooleanTerms(condition, "||"); len(terms) > 1 {
		relation := "unknown"
		for _, term := range terms {
			switch negativeCallConditionRelation(term, call) {
			case "guaranteed":
				return "guaranteed"
			case "conditional":
				relation = "conditional"
			}
		}
		return relation
	}
	if terms := splitTopLevelBooleanTerms(condition, "&&"); len(terms) > 1 {
		for _, term := range terms {
			if negativeCallConditionRelation(term, call) != "unknown" {
				return "conditional"
			}
		}
	}
	return "unknown"
}

func errorPointerCallConditionRelation(condition, call string) string {
	condition = compactExpression(condition)
	call = compactExpression(call)
	if call == "" || strings.Count(condition, call) != 1 {
		return "unknown"
	}
	if condition == "IS_ERR("+call+")" || condition == "IS_ERR_OR_NULL("+call+")" {
		return "guaranteed"
	}
	return "unknown"
}

func traceFalsyFailure(fullBody, continuation, variable string) localErrorEffect {
	position := skipSpace(continuation, 0)
	if position >= len(continuation) || !hasKeywordPrefix(continuation[position:], "if") {
		return unknownLocalErrorEffect()
	}
	detail, ok := parseIfDetail(continuation, position)
	if !ok {
		return unknownLocalErrorEffect()
	}
	condition := normalizeCondition(detail.condText)
	var failureBody string
	switch {
	case conditionIndicatesFalsyExpression(condition, variable):
		failureBody = detail.bodyText
	case conditionIndicatesTruthyExpression(condition, variable):
		if detail.hasElse {
			failureBody = detail.elseText
		} else {
			failureBody = continuation[detail.nextPos:]
		}
	default:
		return unknownLocalErrorEffect()
	}
	effect := terminalErrorEffect(fullBody, failureBody, "", 0)
	if effect.blocksOperation == "guaranteed" && effect.errnoPropagation == "exact" {
		effect.errnoPropagation = "normalized"
	}
	return effect
}

func splitTopLevelBooleanTerms(expression, operator string) []string {
	if operator != "&&" && operator != "||" {
		return []string{expression}
	}
	masked := maskStringAndCharLiterals(expression)
	depth := 0
	start := 0
	terms := make([]string, 0, 2)
	for index := 0; index+1 < len(masked); index++ {
		switch masked[index] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && masked[index:index+2] == operator {
			terms = append(terms, strings.TrimSpace(expression[start:index]))
			start = index + 2
			index++
		}
	}
	terms = append(terms, strings.TrimSpace(expression[start:]))
	return terms
}

func callSiteResultDefinitelyDiscarded(body string, site namedCallSite) bool {
	if site.start < 0 || site.end < site.start || site.end > len(body) {
		return false
	}
	statementEnd := skipSpace(body, site.end)
	if statementEnd >= len(body) || body[statementEnd] != ';' {
		return false
	}
	statementStart := site.start
	for statementStart > 0 {
		previous := body[statementStart-1]
		if previous == ';' || previous == '{' || previous == '}' {
			break
		}
		statementStart--
	}
	prefix := compactExpression(body[statementStart:site.start])
	return prefix == "" || prefix == "void"
}

var ifConditionRE = regexp.MustCompile(`\bif\s*\(`)

func enclosingIfControlledBody(body string, position int) (ifDetail, bool) {
	candidates := ifConditionRE.FindAllStringIndex(body[:position], -1)
	for index := len(candidates) - 1; index >= 0; index-- {
		detail, ok := parseIfDetail(body, candidates[index][0])
		if !ok {
			continue
		}
		if position >= detail.bodyStart && position < detail.bodyEnd {
			return detail, true
		}
	}
	return ifDetail{}, false
}

func requiredCallFailureEffect(body string, site namedCallSite, target, functionRequirement string) localErrorEffect {
	statementEnd := findNextTopLevelSemicolon(body, site.end)
	if statementEnd < 0 {
		return unknownLocalErrorEffect()
	}
	guardStart := skipSpace(body, statementEnd+1)
	detail, ok := parseIfDetail(body, guardStart)
	if !ok {
		return unknownLocalErrorEffect()
	}
	condition := normalizeCondition(detail.condText)
	if conditionIndicatesFalsyExpression(condition, target) {
		return requiredFailureEffect(body, detail.bodyText, target, functionRequirement, 0)
	}
	if conditionIndicatesTruthyExpression(condition, target) {
		return requiredFailureEffect(body, body[detail.nextPos:], target, functionRequirement, 0)
	}
	return unknownLocalErrorEffect()
}

func requiredFailureEffect(fullBody, body, target, functionRequirement string, depth int) localErrorEffect {
	if depth > 12 {
		return unknownLocalErrorEffect()
	}
	trimmed := strings.TrimSpace(body)
	if match := regexp.MustCompile(`\breturn\s+([^;]+);\s*$`).FindStringSubmatch(trimmed); len(match) == 2 {
		expression := normalizeCondition(strings.TrimSpace(match[1]))
		if isExplicitNegativeError(expression) {
			return guaranteedLocalErrorEffect("normalized", nil)
		}
		if functionRequirement == "nonnull" && (expression == "NULL" || expression == "0" || expression == target) {
			return guaranteedLocalErrorEffect("exact", nil)
		}
		return unknownLocalErrorEffect()
	}
	if match := regexp.MustCompile(`\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$`).FindStringSubmatch(trimmed); len(match) == 2 {
		label := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(match[1]) + `\s*:`).FindStringIndex(fullBody)
		if label == nil {
			return unknownLocalErrorEffect()
		}
		return requiredFailureEffect(fullBody, fullBody[label[1]:], target, functionRequirement, depth+1)
	}
	return unknownLocalErrorEffect()
}

func enclosingIfCondition(body string, callStart int) (ifDetail, bool) {
	candidates := ifConditionRE.FindAllStringIndex(body[:callStart], -1)
	for index := len(candidates) - 1; index >= 0; index-- {
		ifStart := candidates[index][0]
		condStart := strings.Index(body[ifStart:], "(") + ifStart
		condEnd, ok := findMatchingParenForward(body, condStart)
		if !ok || callStart > condEnd {
			continue
		}
		detail, ok := parseIfDetail(body, ifStart)
		return detail, ok
	}
	return ifDetail{}, false
}

func traceTaintedErrorWithFacts(fullBody, body, variable string, depth int, facts errorTraceFacts) localErrorEffect {
	if depth > 12 {
		return unknownLocalErrorEffect()
	}
	conditionalOverwrite := false
	overwriteSites := orderedSet(nil)
	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return unknownLocalErrorEffect()
		}
		for pos < len(body) && body[pos] == '}' {
			pos = skipSpace(body, pos+1)
		}
		if pos >= len(body) {
			return unknownLocalErrorEffect()
		}
		if labelEnd := leadingLabelEnd(body[pos:]); labelEnd > 0 {
			pos += labelEnd
			continue
		}
		rest := body[pos:]
		switch {
		case strings.HasPrefix(rest, "if"):
			detail, ok := parseIfDetail(body, pos)
			if !ok {
				return unknownLocalErrorEffect()
			}
			condition := normalizeCondition(detail.condText)
			if truth, known := conditionFromErrorTraceFacts(condition, facts); known {
				if !truth && !detail.hasElse {
					pos = detail.nextPos
					continue
				}
				branch := detail.bodyText
				if !truth {
					branch = detail.elseText
				}
				effect := terminalErrorEffectWithFacts(fullBody, branch, variable, depth+1, cloneErrorTraceFacts(facts))
				if effect.blocksOperation == "guaranteed" {
					effect.overwriteSites = uniqueStrings(append(effect.overwriteSites, overwriteSites.slice()...))
					return effect
				}
				return unknownLocalErrorEffect()
			}
			switch {
			case conditionTrueForError(condition, variable):
				effect := terminalErrorEffectWithFacts(fullBody, detail.bodyText, variable, depth+1, cloneErrorTraceFacts(facts))
				if effect.blocksOperation == "guaranteed" {
					effect.overwriteSites = uniqueStrings(append(effect.overwriteSites, overwriteSites.slice()...))
					if conditionalOverwrite && effect.errnoPropagation == "exact" {
						effect.errnoPropagation = "conditional"
					}
					return effect
				}
				if assignsVariable(detail.bodyText, variable) {
					return unknownLocalErrorEffect()
				}
			case conditionFalseForError(condition, variable):
				if detail.hasElse {
					effect := terminalErrorEffectWithFacts(fullBody, detail.elseText, variable, depth+1, cloneErrorTraceFacts(facts))
					if effect.blocksOperation == "guaranteed" {
						return effect
					}
				}
			default:
				if isBoundedEstaleRetry(detail, condition, variable) {
					conditionalOverwrite = true
					overwriteSites.add("retry_estale")
					pos = detail.nextPos
					continue
				}
				effect := terminalErrorEffectWithFacts(fullBody, detail.bodyText, variable, depth+1, cloneErrorTraceFacts(facts))
				if effect.blocksOperation == "guaranteed" && effect.errnoPropagation != "exact" {
					conditionalOverwrite = true
					overwriteSites.addAll(extractDirectCallees(detail.condText))
					overwriteSites.addAll(effect.overwriteSites)
				} else if branchReturnsSuccess(detail.bodyText) {
					return localErrorEffect{
						blocksOperation:   "conditional",
						terminatesSyscall: "conditional",
						errnoPropagation:  "conditional",
						failureEncoding:   failureReturnErrno,
					}
				} else if assignsVariable(detail.bodyText, variable) || detail.hasElse && assignsVariable(detail.elseText, variable) {
					return unknownLocalErrorEffect()
				}
			}
			pos = detail.nextPos
		case hasKeywordPrefix(rest, "return"):
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				return unknownLocalErrorEffect()
			}
			expression := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(body[pos:next+1]), "return"), ";"))
			effect := returnTaintedErrorEffect(expression, variable)
			effect.overwriteSites = uniqueStrings(append(effect.overwriteSites, overwriteSites.slice()...))
			if conditionalOverwrite && effect.errnoPropagation == "exact" {
				effect.errnoPropagation = "conditional"
			}
			return effect
		case hasKeywordPrefix(rest, "goto"):
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				return unknownLocalErrorEffect()
			}
			label := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(body[pos:next+1]), "goto"), ";"))
			return traceTaintedErrorFromLabelWithFacts(fullBody, label, variable, depth+1, facts)
		case hasKeywordPrefix(rest, "switch"), hasKeywordPrefix(rest, "for"), hasKeywordPrefix(rest, "while"),
			hasKeywordPrefix(rest, "do"), hasKeywordPrefix(rest, "case"), hasKeywordPrefix(rest, "default"):
			return unknownLocalErrorEffect()
		default:
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				return unknownLocalErrorEffect()
			}
			statement := strings.TrimSpace(body[pos : next+1])
			if assignsVariable(statement, variable) {
				if expression, ok := assignedExpression(statement, variable); ok && isExplicitNegativeError(expression) {
					effect := traceTaintedErrorWithFacts(fullBody, body[next+1:], variable, depth+1, facts)
					if effect.blocksOperation != "guaranteed" {
						return unknownLocalErrorEffect()
					}
					effect.errnoPropagation = "overwritten"
					sites := extractDirectCallees(expression)
					if len(sites) == 0 {
						sites = []string{strings.TrimSpace(expression)}
					}
					effect.overwriteSites = uniqueStrings(append(append(effect.overwriteSites, overwriteSites.slice()...), sites...))
					return effect
				}
				return unknownLocalErrorEffect()
			}
			updateErrorTraceFacts(statement, &facts)
			pos = next + 1
		}
	}
}

func leadingLabelEnd(body string) int {
	match := regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*|case\b[^:]*|default)\s*:`).FindStringIndex(body)
	if match == nil {
		return 0
	}
	return match[1]
}

func terminalErrorEffect(fullBody, body, variable string, depth int) localErrorEffect {
	return terminalErrorEffectWithFacts(fullBody, body, variable, depth, errorTraceFacts{})
}

func terminalErrorEffectWithFacts(fullBody, body, variable string, depth int, facts errorTraceFacts) localErrorEffect {
	trimmed := strings.TrimSpace(body)
	if match := regexp.MustCompile(`\breturn\s+([^;]+);\s*$`).FindStringSubmatch(trimmed); len(match) == 2 {
		return returnTaintedErrorEffect(strings.TrimSpace(match[1]), variable)
	}
	if match := regexp.MustCompile(`\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$`).FindStringSubmatch(trimmed); len(match) == 2 {
		return traceTaintedErrorFromLabelWithFacts(fullBody, match[1], variable, depth+1, facts)
	}
	if variable != "" {
		return traceTaintedErrorWithFacts(fullBody, trimmed, variable, depth+1, facts)
	}
	return unknownLocalErrorEffect()
}

func traceTaintedErrorFromLabelWithFacts(fullBody, label, variable string, depth int, facts errorTraceFacts) localErrorEffect {
	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(label) + `\s*:`)
	location := pattern.FindStringIndex(fullBody)
	if location == nil {
		return unknownLocalErrorEffect()
	}
	return traceTaintedErrorWithFacts(fullBody, fullBody[location[1]:], variable, depth+1, facts)
}

func inferErrorTraceFacts(prefix string) errorTraceFacts {
	facts := errorTraceFacts{nullVariables: make(map[string]struct{})}
	pattern := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*NULL\s*;`)
	for _, indexes := range pattern.FindAllStringSubmatchIndex(prefix, -1) {
		variable := prefix[indexes[2]:indexes[3]]
		remainder := prefix[indexes[1]:]
		if assignsVariable(remainder, variable) || addressEscapesVariable(remainder, variable) {
			continue
		}
		facts.nullVariables[variable] = struct{}{}
	}
	return facts
}

func cloneErrorTraceFacts(facts errorTraceFacts) errorTraceFacts {
	clone := errorTraceFacts{nullVariables: make(map[string]struct{}, len(facts.nullVariables))}
	for variable := range facts.nullVariables {
		clone.nullVariables[variable] = struct{}{}
	}
	return clone
}

func conditionFromErrorTraceFacts(condition string, facts errorTraceFacts) (bool, bool) {
	for variable := range facts.nullVariables {
		quoted := regexp.QuoteMeta(variable)
		switch {
		case regexp.MustCompile(`^` + quoted + `$`).MatchString(condition),
			regexp.MustCompile(`^` + quoted + `\s*!=\s*(?:NULL|0)$`).MatchString(condition):
			return false, true
		case regexp.MustCompile(`^!\s*` + quoted + `$`).MatchString(condition),
			regexp.MustCompile(`^` + quoted + `\s*==\s*(?:NULL|0)$`).MatchString(condition):
			return true, true
		}
	}
	return false, false
}

func updateErrorTraceFacts(statement string, facts *errorTraceFacts) {
	if len(facts.nullVariables) == 0 {
		return
	}
	for variable := range facts.nullVariables {
		if assignsVariable(statement, variable) || addressEscapesVariable(statement, variable) {
			delete(facts.nullVariables, variable)
		}
	}
}

func addressEscapesVariable(body, variable string) bool {
	return regexp.MustCompile(`&\s*` + regexp.QuoteMeta(variable) + `\b`).MatchString(body)
}

func returnTaintedErrorEffect(expression, variable string) localErrorEffect {
	expression = strings.TrimSpace(expression)
	if variable != "" {
		quoted := regexp.QuoteMeta(variable)
		if regexp.MustCompile(`^(?:` + quoted + `|ERR_PTR\s*\(\s*` + quoted + `\s*\)|PTR_ERR\s*\(\s*` + quoted + `\s*\))$`).MatchString(expression) {
			return guaranteedLocalErrorEffect("exact", nil)
		}
		if regexp.MustCompile(`^` + quoted + `\s*\?\s*:\s*.+$`).MatchString(expression) {
			return guaranteedLocalErrorEffect("exact", nil)
		}
		ternaryPatterns := []string{
			`^` + quoted + `\s*==\s*0\s*\?\s*.+\s*:\s*` + quoted + `$`,
			`^0\s*==\s*` + quoted + `\s*\?\s*.+\s*:\s*` + quoted + `$`,
			`^` + quoted + `\s*!=\s*0\s*\?\s*` + quoted + `\s*:\s*.+$`,
			`^0\s*!=\s*` + quoted + `\s*\?\s*` + quoted + `\s*:\s*.+$`,
			`^` + quoted + `\s*<\s*0\s*\?\s*` + quoted + `\s*:\s*.+$`,
		}
		if matchesAny(expression, ternaryPatterns) {
			return guaranteedLocalErrorEffect("exact", nil)
		}
	}
	if isExplicitNegativeError(expression) {
		return guaranteedLocalErrorEffect("normalized", nil)
	}
	return unknownLocalErrorEffect()
}

func assignedExpression(statement, variable string) (string, bool) {
	pattern := regexp.MustCompile(`(?s)^\s*` + regexp.QuoteMeta(variable) + `\s*=\s*(.*?)\s*;\s*$`)
	match := pattern.FindStringSubmatch(statement)
	if len(match) != 2 || strings.HasPrefix(strings.TrimSpace(match[1]), "=") {
		return "", false
	}
	return strings.TrimSpace(match[1]), true
}

func isExplicitNegativeError(expression string) bool {
	expression = strings.TrimSpace(expression)
	return regexp.MustCompile(`^-\s*(?:[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|[0-9]+)$`).MatchString(expression) ||
		regexp.MustCompile(`^ERR_PTR\s*\(\s*-`).MatchString(expression)
}

func conditionTrueForError(condition, variable string) bool {
	if variable == "" {
		return false
	}
	quoted := regexp.QuoteMeta(variable)
	patterns := []string{
		`^` + quoted + `$`,
		`^` + quoted + `\s*!=\s*0$`,
		`^0\s*!=\s*` + quoted + `$`,
		`^` + quoted + `\s*<\s*0$`,
		`^0\s*>\s*` + quoted + `$`,
		`^IS_ERR\s*\(\s*` + quoted + `\s*\)$`,
		`^IS_ERR_OR_NULL\s*\(\s*` + quoted + `\s*\)$`,
	}
	return matchesAny(condition, patterns)
}

func conditionFalseForError(condition, variable string) bool {
	if variable == "" {
		return false
	}
	quoted := regexp.QuoteMeta(variable)
	patterns := []string{
		`^!\s*` + quoted + `$`,
		`^` + quoted + `\s*==\s*0$`,
		`^0\s*==\s*` + quoted + `$`,
		`^` + quoted + `\s*>=\s*0(?:\s*&&.*)?$`,
		`^0\s*<=\s*` + quoted + `$`,
		`^` + quoted + `\s*>\s*0(?:\s*&&.*)?$`,
		`^!\s*IS_ERR\s*\(\s*` + quoted + `\s*\)$`,
	}
	return matchesAny(condition, patterns)
}

func branchReturnsSuccess(body string) bool {
	for _, match := range regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1) {
		expression := strings.TrimSpace(match[1])
		if expression == "0" || regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(expression) {
			return true
		}
	}
	return false
}

func isBoundedEstaleRetry(detail ifDetail, condition, variable string) bool {
	if variable == "" || detail.hasElse {
		return false
	}
	match := regexp.MustCompile(`^retry_estale\s*\(\s*` + regexp.QuoteMeta(variable) + `\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$`).FindStringSubmatch(condition)
	if len(match) != 2 {
		return false
	}
	flags := regexp.QuoteMeta(match[1])
	setsRevalidation := regexp.MustCompile(`\b` + flags + `\s*\|=\s*LOOKUP_REVAL\s*;`).MatchString(detail.bodyText)
	retries := regexp.MustCompile(`\bgoto\s+[A-Za-z_][A-Za-z0-9_]*\s*;`).MatchString(detail.bodyText)
	return setsRevalidation && retries
}

func guaranteedLocalErrorEffect(errno string, overwriteSites []string) localErrorEffect {
	return guaranteedEncodedLocalErrorEffect(errno, failureReturnErrno, overwriteSites)
}

func guaranteedEncodedLocalErrorEffect(errno, encoding string, overwriteSites []string) localErrorEffect {
	return localErrorEffect{
		blocksOperation:   "guaranteed",
		terminatesSyscall: "guaranteed",
		errnoPropagation:  errno,
		failureEncoding:   encoding,
		overwriteSites:    uniqueStrings(overwriteSites),
	}
}

func unknownLocalErrorEffect() localErrorEffect {
	return localErrorEffect{
		blocksOperation:   "unknown",
		terminatesSyscall: "unknown",
		errnoPropagation:  "unknown",
		failureEncoding:   failureReturnUnknown,
	}
}

func ignoredLocalErrorEffect() localErrorEffect {
	return localErrorEffect{
		blocksOperation:   "no",
		terminatesSyscall: "no",
		errnoPropagation:  "ignored",
		failureEncoding:   failureReturnNone,
	}
}

func composeLocalErrorEffects(inner, outer localErrorEffect) localErrorEffect {
	if inner.errnoPropagation == "ignored" {
		return inner
	}
	result := localErrorEffect{
		blocksOperation:   combineGuarantee(inner.blocksOperation, outer.blocksOperation),
		terminatesSyscall: combineGuarantee(inner.terminatesSyscall, outer.terminatesSyscall),
		failureEncoding:   failureReturnUnknown,
		overwriteSites:    uniqueStrings(append(append([]string(nil), inner.overwriteSites...), outer.overwriteSites...)),
	}
	switch outer.errnoPropagation {
	case "exact":
		result.errnoPropagation = inner.errnoPropagation
		if outer.failureEncoding != "" && outer.failureEncoding != failureReturnUnknown {
			result.failureEncoding = outer.failureEncoding
		} else {
			result.failureEncoding = inner.failureEncoding
		}
	case "normalized", "overwritten", "conditional", "ignored", "unknown":
		result.errnoPropagation = outer.errnoPropagation
		if outer.errnoPropagation == "ignored" {
			result.failureEncoding = failureReturnNone
		} else if outer.errnoPropagation != "unknown" {
			result.failureEncoding = failureReturnErrno
		}
	default:
		result.errnoPropagation = "unknown"
	}
	return result
}

func combineGuarantee(left, right string) string {
	if left == "guaranteed" && right == "guaranteed" {
		return "guaranteed"
	}
	if left == "no" || right == "no" {
		return "no"
	}
	if left == "conditional" || right == "conditional" {
		return "conditional"
	}
	return "unknown"
}

func mergeLocalErrorEffects(effects []localErrorEffect) localErrorEffect {
	if len(effects) == 0 {
		return unknownLocalErrorEffect()
	}
	result := effects[0]
	for _, effect := range effects[1:] {
		result.blocksOperation = mergeAlternativeGuarantee(result.blocksOperation, effect.blocksOperation)
		result.terminatesSyscall = mergeAlternativeGuarantee(result.terminatesSyscall, effect.terminatesSyscall)
		result.errnoPropagation = mergeAlternativeErrno(result.errnoPropagation, effect.errnoPropagation)
		if result.failureEncoding != effect.failureEncoding {
			result.failureEncoding = failureReturnUnknown
		}
		result.overwriteSites = uniqueStrings(append(result.overwriteSites, effect.overwriteSites...))
	}
	return result
}

func mergeAlternativeGuarantee(left, right string) string {
	if left == right {
		return left
	}
	if left == "unknown" || right == "unknown" {
		return "unknown"
	}
	return "conditional"
}

func mergeAlternativeErrno(left, right string) string {
	if left == right {
		return left
	}
	if left == "ignored" || right == "ignored" || left == "unknown" || right == "unknown" {
		return "unknown"
	}
	return "conditional"
}

func isGuaranteedLSMErrorEffect(effect LSMErrorEffect) bool {
	return effect.HookKind == "error-return" &&
		effect.BlocksOperation == "guaranteed" &&
		effect.TerminatesSyscall == "guaranteed" &&
		effect.ErrnoPropagation != "ignored" &&
		effect.ErrnoPropagation != "unknown" &&
		effect.FailureEncoding == failureReturnErrno &&
		effect.LLVMVerification != "contradicted_ignored"
}

func isCertifiedReviewedKernelLSMEffect(effect LSMErrorEffect) bool {
	return effect.ProofMethod == reviewedKernelLSMGateProofMethod &&
		isGuaranteedLSMErrorEffect(effect)
}

func mergeLSMErrorEffects(left, right LSMErrorEffect) LSMErrorEffect {
	if isCertifiedReviewedKernelLSMEffect(left) {
		return left
	}
	if isCertifiedReviewedKernelLSMEffect(right) {
		return right
	}
	if left.BPFHook != right.BPFHook {
		left.BPFHook = ""
	}
	if left.HookKind != right.HookKind {
		left.HookKind = "unknown"
	}
	left.BlocksOperation = mergeAlternativeGuarantee(left.BlocksOperation, right.BlocksOperation)
	left.TerminatesSyscall = mergeAlternativeGuarantee(left.TerminatesSyscall, right.TerminatesSyscall)
	left.ErrnoPropagation = mergeAlternativeErrno(left.ErrnoPropagation, right.ErrnoPropagation)
	if left.FailureEncoding != right.FailureEncoding {
		left.FailureEncoding = failureReturnUnknown
	}
	if left.ProofMethod != right.ProofMethod {
		left.ProofMethod = "mixed"
	}
	left.CallsiteFunctions = uniqueStrings(append(left.CallsiteFunctions, right.CallsiteFunctions...))
	left.OverwriteSites = uniqueStrings(append(left.OverwriteSites, right.OverwriteSites...))
	left.LLVMEvidence = uniqueLLVMHookFacts(append(left.LLVMEvidence, right.LLVMEvidence...))
	left.LLVMVerification = mergeLLVMVerification(left.LLVMVerification, right.LLVMVerification)
	return left
}

func mergeLSMEffectLists(left, right []LSMErrorEffect) []LSMErrorEffect {
	byHook := make(map[string]LSMErrorEffect, len(left)+len(right))
	order := make([]string, 0, len(left)+len(right))
	for _, effect := range append(append([]LSMErrorEffect(nil), left...), right...) {
		if existing, ok := byHook[effect.Hook]; ok {
			byHook[effect.Hook] = mergeLSMErrorEffects(existing, effect)
			continue
		}
		byHook[effect.Hook] = effect
		order = append(order, effect.Hook)
	}
	result := make([]LSMErrorEffect, 0, len(order))
	for _, hook := range order {
		result = append(result, byHook[hook])
	}
	return result
}

func (a *Analyzer) promoteKernelGateLSMCoverage(
	coverage lsmCoverageResult,
	effects []LSMErrorEffect,
	effectiveHooks []string,
) lsmCoverageResult {
	if len(effectiveHooks) == 0 || coverage.state == "enforcing" {
		return coverage
	}
	effective := make(map[string]struct{}, len(effectiveHooks))
	for _, hook := range effectiveHooks {
		effective[hook] = struct{}{}
	}
	hooks := orderedSet(nil)
	proofMethods := orderedSet([]string{
		"kernel_errno_success_gate",
		"clang_reachable_cross_check",
	})
	proofFunctions := orderedSet(nil)
	hookProofPaths := make(map[string][]string)
	for _, effect := range effects {
		if _, ok := effective[effect.Hook]; !ok {
			continue
		}
		if !a.isCertifiedKernelGateLSMEffect(effect) {
			continue
		}
		path := append([]string(nil), effect.ProofPath...)
		functionPath := path
		if len(functionPath) > 0 && functionPath[0] == effect.Hook {
			functionPath = functionPath[1:]
		}
		if len(functionPath) == 0 || len(a.proofPathReasons(functionPath)) > 0 {
			continue
		}
		hooks.add(effect.Hook)
		if effect.ProofMethod != "" {
			proofMethods.add(effect.ProofMethod)
		}
		proofFunctions.addAll(functionPath)
		hookProofPaths[effect.Hook] = path
	}
	if len(hooks.items) == 0 {
		return coverage
	}
	if coverage.state == "non_enforcing" {
		proofMethods.add("kernel_gate_invalidates_cfg_bypass")
	}
	coverage.state = "enforcing"
	coverage.hooks = hooks.slice()
	coverage.alternatives = enforcingLSMAlternatives(hooks.slice()...)
	coverage.proofMethods = proofMethods.slice()
	coverage.proofFunctions = proofFunctions.slice()
	coverage.hookProofPaths = hookProofPaths
	coverage.bypassProofPath = nil
	coverage.bypassProofMethod = ""
	coverage.unprovenBypassPath = nil
	coverage.reasons = nil
	coverage.coveredUnresolved = append(
		coverage.coveredUnresolved,
		coverage.unresolved...,
	)
	coverage.unresolved = nil
	return coverage
}

func (a *Analyzer) isCertifiedKernelGateLSMEffect(effect LSMErrorEffect) bool {
	if effect.Hook == "" || effect.BPFHook == "" ||
		effect.HookKind != "error-return" ||
		effect.BlocksOperation != "guaranteed" ||
		effect.TerminatesSyscall != "guaranteed" ||
		effect.ErrnoPropagation == "ignored" ||
		effect.ErrnoPropagation == "unknown" ||
		effect.FailureEncoding != failureReturnErrno ||
		effect.LLVMVerification == "contradicted_ignored" {
		return false
	}
	path := append([]string(nil), effect.ProofPath...)
	if len(path) > 0 && path[0] == effect.Hook {
		path = path[1:]
	}
	return len(path) > 0 && len(a.proofPathReasons(path)) == 0
}

func uniqueLLVMHookFacts(facts []LLVMHookFact) []LLVMHookFact {
	seen := make(map[string]struct{}, len(facts))
	result := make([]LLVMHookFact, 0, len(facts))
	for _, fact := range facts {
		key := fmt.Sprintf(
			"%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s",
			fact.Hook,
			fact.Function,
			fact.SourceFunction,
			fact.SourceFile,
			fact.SourceLine,
			fact.SourceColumn,
			fact.Verification,
		)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, fact)
	}
	return result
}

func mergeLLVMVerification(left, right string) string {
	if left == "" {
		left = "unknown"
	}
	if right == "" {
		right = "unknown"
	}
	if left == right {
		return left
	}
	if left == "mixed" || right == "mixed" {
		return "mixed"
	}
	if left == "unknown" {
		return right
	}
	if right == "unknown" {
		return left
	}
	return "mixed"
}

func (a *Analyzer) newReportWorker() *Analyzer {
	worker := *a
	worker.summaryCache = make(map[string]FunctionSummary)
	worker.allScanCache = make(map[string]prefixScanResult)
	worker.validScanCache = make(map[string]prefixScanResult)
	worker.successCache = make(map[string]prefixScanResult)
	worker.contextScanCache = make(map[string]prefixScanResult)
	worker.kernelSuccessCache = make(map[string]prefixScanResult)
	worker.kernelContextCache = make(map[string]prefixScanResult)
	worker.signalScanCache = make(map[string]prefixScanResult)
	worker.signalTransitionCache = make(map[string][]resolvedContextCall)
	worker.lsmCoverageCache = make(map[string]lsmCoverageResult)
	worker.signalCoverageCache = a.signalCoverageCache
	worker.successWitnessCache = make(map[string]functionSuccessWitness)
	worker.effectFreeSuccessCache = make(map[string]functionSuccessWitness)
	worker.cfgCycleEdgeCache = make(map[string]bool)
	worker.lsmFailureKindCache = make(map[string]string)
	worker.sigFailureKindCache = make(map[string]string)
	worker.buildingEffectSources = false
	return &worker
}

func (a *Analyzer) writeReports() error {
	if err := os.RemoveAll(a.cfg.OutDir); err != nil {
		return fmt.Errorf("remove output dir: %w", err)
	}
	dirs := []string{
		a.cfg.OutDir,
		filepath.Join(a.cfg.OutDir, "syscalls"),
		filepath.Join(a.cfg.OutDir, "reports"),
		filepath.Join(a.cfg.OutDir, "checkpoints"),
		filepath.Join(a.cfg.OutDir, "checkpoints", "syscalls"),
	}
	if a.cfg.EmitRaw {
		dirs = append(dirs, filepath.Join(a.cfg.OutDir, "raw_syscalls"))
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	lsmFunctions := orderedSet(nil)
	signalFunctions := orderedSet(nil)
	for _, fn := range a.functions {
		if len(fn.DirectLSMHooks) > 0 {
			lsmFunctions.add(fn.Name)
		}
		if len(fn.DirectSigChecks) > 0 {
			signalFunctions.add(fn.Name)
		}
	}

	reports := make([]SyscallReport, len(a.syscalls))
	lsmSyscalls := make([]string, 0)
	signalSyscalls := make([]string, 0)

	sort.Slice(a.syscalls, func(i, j int) bool { return a.syscalls[i].Number < a.syscalls[j].Number })
	if !a.lsmEffectSourcesBuilt {
		a.buildEffectSourceStates("lsm")
	}
	if !a.sigEffectSourcesBuilt {
		a.buildEffectSourceStates("sigkill")
	}
	reportStarted := time.Now()
	progress := newIncrementalReportProgress(len(a.syscalls), reportStarted)
	progressPath := filepath.Join(a.cfg.OutDir, "checkpoints", "progress.json")
	if err := writeJSONAtomic(progressPath, progress); err != nil {
		return fmt.Errorf("write initial report progress: %w", err)
	}
	reportJobs := min(max(1, a.cfg.ReportJobs), max(1, len(a.syscalls)))
	fmt.Fprintf(
		os.Stderr,
		"report generation: 0/%d syscalls workers=%d classification=clang-cfg-path-value-success-exit raw-may-reach=%t\n",
		len(a.syscalls),
		reportJobs,
		a.cfg.EmitRaw,
	)
	type reportJob struct {
		index int
		entry SyscallEntry
	}
	type reportResult struct {
		index   int
		entry   SyscallEntry
		report  SyscallReport
		elapsed time.Duration
	}
	jobs := make(chan reportJob)
	results := make(chan reportResult)
	var workers sync.WaitGroup
	for workerIndex := 0; workerIndex < reportJobs; workerIndex++ {
		workerAnalyzer := a.newReportWorker()
		workers.Add(1)
		go func(workerID int, analyzer *Analyzer) {
			defer workers.Done()
			for job := range jobs {
				syscallStarted := time.Now()
				fmt.Fprintf(
					os.Stderr,
					"report generation: worker=%d syscall=%s(%d) start\n",
					workerID,
					job.entry.Name,
					job.entry.Number,
				)
				heartbeatDone := make(chan struct{})
				go func(entry SyscallEntry, started time.Time) {
					ticker := time.NewTicker(30 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							fmt.Fprintf(
								os.Stderr,
								"report generation: worker=%d syscall=%s(%d) active elapsed=%s\n",
								workerID,
								entry.Name,
								entry.Number,
								time.Since(started).Round(time.Second),
							)
						case <-heartbeatDone:
							return
						}
					}
				}(job.entry, syscallStarted)
				report := analyzer.buildSyscallReport(job.entry)
				close(heartbeatDone)
				results <- reportResult{
					index:   job.index,
					entry:   job.entry,
					report:  report,
					elapsed: time.Since(syscallStarted),
				}
			}
		}(workerIndex+1, workerAnalyzer)
	}
	go func() {
		for index, entry := range a.syscalls {
			jobs <- reportJob{index: index, entry: entry}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	completed := 0
	for result := range results {
		completed++
		report := result.report
		reports[result.index] = report
		checkpointName := syscallCheckpointFilename(report)
		checkpointPath := filepath.Join(a.cfg.OutDir, "checkpoints", "syscalls", checkpointName)
		if err := writeJSONAtomic(checkpointPath, report); err != nil {
			return fmt.Errorf("write syscall checkpoint %s: %w", report.Name, err)
		}
		updateIncrementalReportProgress(
			&progress,
			report,
			result.elapsed,
			time.Since(reportStarted),
			filepath.ToSlash(filepath.Join("checkpoints", "syscalls", checkpointName)),
		)
		if err := writeJSONAtomic(progressPath, progress); err != nil {
			return fmt.Errorf("write report progress after %s: %w", report.Name, err)
		}
		if report.ContainsLSMHook {
			lsmSyscalls = append(lsmSyscalls, report.Name)
		}
		if report.ContainsSignalChecks {
			signalSyscalls = append(signalSyscalls, report.Name)
		}
		fmt.Fprintf(
			os.Stderr,
			"report generation: %d/%d syscall=%s(%d) done elapsed=%s lsm=%s sigkill=%s lsm-outcomes=%d sigkill-outcomes=%d unresolved=%d legacy-raw-signal-states=%d dominance-skips=%d dominated=%d transition-cache-hits=%d transition-builds=%d total=%s\n",
			completed,
			len(a.syscalls),
			result.entry.Name,
			result.entry.Number,
			result.elapsed.Round(time.Millisecond),
			report.LSMEnforcementState,
			report.SIGKILLEnforcementState,
			len(report.LSMPathCoverage.SuccessPathHookSets),
			len(report.SIGKILLPathCoverage.SuccessPathCheckSets),
			len(report.UnresolvedProofEdges),
			report.AnalysisStats.VisitedStates,
			report.AnalysisStats.DominanceSkips,
			report.AnalysisStats.DominatedStates,
			report.AnalysisStats.TransitionCacheHits,
			report.AnalysisStats.TransitionBuilds,
			time.Since(reportStarted).Round(time.Second),
		)
	}

	sort.Strings(lsmSyscalls)
	sort.Strings(signalSyscalls)

	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "lsm_functions.txt"), strings.Join(lsmFunctions.slice(), "\n")+"\n"); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "signal_functions.txt"), strings.Join(signalFunctions.slice(), "\n")+"\n"); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "lsm_syscalls.txt"), strings.Join(lsmSyscalls, "\n")+"\n"); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "signal_syscalls.txt"), strings.Join(signalSyscalls, "\n")+"\n"); err != nil {
		return err
	}
	if err := writeText(
		filepath.Join(a.cfg.OutDir, "reports", "syscall_availability.txt"),
		buildSyscallAvailabilityReport(reports),
	); err != nil {
		return err
	}
	if err := writeJSON(
		filepath.Join(a.cfg.OutDir, "reports", "input_validation.json"),
		a.inputValidation,
	); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "always_lsm_syscalls.txt"), buildAlwaysReport(reports, true)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "always_signal_syscalls.txt"), buildAlwaysReport(reports, false)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "signal_check_paths.txt"), buildSignalCheckPathReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "indirect_call_resolutions.txt"), buildIndirectResolutionReport(a.functions)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "must_pass_lsm_syscalls.txt"), buildMustPassReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "effective_lsm_syscalls.txt"), buildEffectiveLSMReport(reports)); err != nil {
		return err
	}
	if err := writeText(
		filepath.Join(a.cfg.OutDir, "reports", "certified_bpf_lsm_syscalls.txt"),
		buildCertifiedBPFLSMReport(reports),
	); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "lsm_path_coverage.txt"), buildLSMPathCoverageReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "sigkill_path_coverage.txt"), buildSIGKILLPathCoverageReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "inactive_lsm_syscalls.txt"), buildInactiveLSMReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "unproven_lsm_candidates.txt"), buildUnprovenLSMReport(reports)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "lsm_classification.txt"), buildClassificationReport(reports, true)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "sigkill_classification.txt"), buildClassificationReport(reports, false)); err != nil {
		return err
	}
	if err := writeJSON(
		filepath.Join(a.cfg.OutDir, "reports", "classification_counts.json"),
		buildClassificationCounts(reports),
	); err != nil {
		return err
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "proof_gaps.txt"), buildProofGapReport(reports)); err != nil {
		return err
	}
	if err := writeJSON(
		filepath.Join(
			a.cfg.OutDir,
			"reports",
			"proof_gap_categories.json",
		),
		buildProofGapCategoryCounts(reports),
	); err != nil {
		return err
	}
	if err := writeText(
		filepath.Join(a.cfg.OutDir, "reports", "effect_source_unknown_witnesses.txt"),
		buildEffectSourceWitnessReport(a.functions),
	); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(a.cfg.OutDir, "summary.json"), reports); err != nil {
		return err
	}
	if a.cfg.EmitFunctionIndex {
		if err := writeJSON(filepath.Join(a.cfg.OutDir, "function_index.json"), a.functions); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(a.cfg.OutDir, "analysis_metadata.json"), a.buildAnalysisMetadata()); err != nil {
		return err
	}
	llvmFailures := ""
	if len(a.llvmFailures) > 0 {
		llvmFailures = strings.Join(a.llvmFailures, "\n") + "\n"
	}
	if err := writeText(filepath.Join(a.cfg.OutDir, "reports", "llvm_verification_failures.txt"), llvmFailures); err != nil {
		return err
	}

	readme := buildREADME(a.cfg)
	if err := writeText(filepath.Join(a.cfg.OutDir, "README.txt"), readme); err != nil {
		return err
	}
	progress.Status = "complete"
	progress.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	progress.ElapsedMilliseconds = time.Since(reportStarted).Milliseconds()
	return writeJSONAtomic(progressPath, progress)
}

func buildEffectSourceWitnessReport(functions map[string]*FunctionInfo) string {
	items := make([]*FunctionInfo, 0)
	for _, fn := range functions {
		if fn.LSMEffectUnknownWitness != "" || fn.SIGEffectUnknownWitness != "" {
			items = append(items, fn)
		}
	}
	sort.Slice(items, func(left, right int) bool {
		return items[left].DisplayName < items[right].DisplayName
	})
	var builder strings.Builder
	for _, fn := range items {
		if fn.LSMEffectUnknownWitness != "" {
			fmt.Fprintf(&builder, "lsm\t%s\t%s\n", fn.DisplayName, fn.LSMEffectUnknownWitness)
		}
		if fn.SIGEffectUnknownWitness != "" {
			fmt.Fprintf(&builder, "sigkill\t%s\t%s\n", fn.DisplayName, fn.SIGEffectUnknownWitness)
		}
	}
	return builder.String()
}

type AnalysisMetadata struct {
	Frontend                   string          `json:"frontend"`
	CompileDatabase            string          `json:"compile_database,omitempty"`
	FrontendCache              string          `json:"frontend_cache,omitempty"`
	FrontendCacheStatus        string          `json:"frontend_cache_status"`
	FrontendCacheFingerprint   string          `json:"frontend_cache_fingerprint,omitempty"`
	FrontendCacheBuiltAt       string          `json:"frontend_cache_built_at,omitempty"`
	EnforcementSemantics       string          `json:"enforcement_semantics"`
	ClassificationEngine       string          `json:"classification_engine"`
	RawMayReachTraversal       bool            `json:"raw_may_reach_traversal_enabled"`
	ReportWorkers              int             `json:"report_workers"`
	Functions                  int             `json:"functions"`
	ClangFunctions             int             `json:"clang_functions"`
	LegacyFallbackFunctions    int             `json:"legacy_fallback_functions"`
	CFGCompleteFunctions       int             `json:"cfg_complete_functions"`
	CFGIncompleteFunctions     int             `json:"cfg_incomplete_functions"`
	CFGErrnoGuardFunctions     int             `json:"cfg_kernel_errno_guard_functions"`
	CFGUnplacedFunctions       int             `json:"cfg_unplaced_event_functions"`
	CFGUnplacedEvents          int             `json:"cfg_unplaced_events"`
	FrontendVariantConflicts   int             `json:"frontend_variant_conflicts"`
	LLVMVerificationEnabled    bool            `json:"llvm_verification_enabled"`
	LLVMFunctionsWithEvidence  int             `json:"llvm_functions_with_evidence"`
	LLVMFunctionsWithCalls     int             `json:"llvm_functions_with_call_evidence"`
	LLVMCallFacts              int             `json:"llvm_call_facts"`
	LLVMFunctionReturnFacts    int             `json:"llvm_function_return_facts"`
	LLVMMustSuccessReturnFacts int             `json:"llvm_must_success_return_facts"`
	LLVMMustNonpositiveFacts   int             `json:"llvm_must_nonpositive_return_facts"`
	LLVMPointeePreserveFacts   int             `json:"llvm_pointee_preservation_facts"`
	CFGPreservedEscapes        int             `json:"cfg_llvm_preserved_escaped_variables"`
	LLVMMustReturnExactFacts   int             `json:"llvm_must_return_exact_facts"`
	LLVMMustReturnErrorFacts   int             `json:"llvm_must_return_negative_facts"`
	LLVMSuccessPreserveFacts   int             `json:"llvm_nonnegative_success_preservation_facts"`
	LLVMPointerPreserveFacts   int             `json:"llvm_valid_pointer_success_preservation_facts"`
	LLVMFailures               int             `json:"llvm_failures"`
	ClangExactCallbackArgs     int             `json:"clang_exact_callback_arguments"`
	ClangVerifiedOpsTables     int             `json:"clang_verified_operation_tables"`
	ClosedConstOperationTables int             `json:"closed_const_operation_tables"`
	LSMUnknownWitnessFunctions int             `json:"lsm_unknown_witness_functions"`
	SIGUnknownWitnessFunctions int             `json:"sigkill_unknown_witness_functions"`
	InputValidation            InputValidation `json:"input_validation"`
}

func (a *Analyzer) buildAnalysisMetadata() AnalysisMetadata {
	result := AnalysisMetadata{
		Frontend:                 a.cfg.Frontend,
		CompileDatabase:          a.cfg.CompileDB,
		FrontendCache:            a.cfg.FrontendCache,
		FrontendCacheStatus:      a.frontendCacheStatus,
		FrontendCacheFingerprint: a.frontendCacheHash,
		FrontendCacheBuiltAt:     a.frontendCacheBuiltAt,
		EnforcementSemantics:     "universal_success_path_enforcement_e_n_u_v5",
		ClassificationEngine:     "clang_cfg_path_value_success_exit_coverage",
		RawMayReachTraversal:     a.cfg.EmitRaw,
		ReportWorkers:            max(1, a.cfg.ReportJobs),
		Functions:                len(a.functions),
		LLVMVerificationEnabled:  a.cfg.Frontend == "hybrid" && a.cfg.LLVMVerify,
		LLVMFailures:             len(a.llvmFailures),
		InputValidation:          a.inputValidation,
	}
	for _, fn := range a.functions {
		if fn.Frontend == "clang-ast-cfg" {
			result.ClangFunctions++
			if fn.CFGComplete {
				result.CFGCompleteFunctions++
			} else {
				result.CFGIncompleteFunctions++
			}
			if fn.CFGUsedErrnoGuards {
				result.CFGErrnoGuardFunctions++
			}
			if len(fn.CFGUnplacedEvents) > 0 {
				result.CFGUnplacedFunctions++
				result.CFGUnplacedEvents += len(fn.CFGUnplacedEvents)
			}
			if fn.FrontendVariantConflict {
				result.FrontendVariantConflicts++
			}
			for _, site := range fn.CallSites {
				for _, argument := range site.CallbackArguments {
					if argument.Complete &&
						len(argument.Targets) > 0 {
						result.ClangExactCallbackArgs++
					}
				}
			}
		} else {
			result.LegacyFallbackFunctions++
		}
		if len(fn.LLVMHookFacts) > 0 || len(fn.LLVMCallFacts) > 0 ||
			len(fn.LLVMFunctionFacts) > 0 {
			result.LLVMFunctionsWithEvidence++
		}
		for _, fact := range fn.LLVMFunctionFacts {
			result.LLVMFunctionReturnFacts++
			if fact.FunctionMustReturnNonnegative ||
				fact.FunctionMustReturnNonNull ||
				fact.FunctionMustReturnValidPointer ||
				fact.FunctionMustReturnTrue {
				result.LLVMMustSuccessReturnFacts++
			}
			if fact.FunctionMustReturnNonpositive {
				result.LLVMMustNonpositiveFacts++
			}
			result.LLVMPointeePreserveFacts +=
				len(fact.FunctionPreservedPointeeArguments)
		}
		result.CFGPreservedEscapes += len(fn.CFGPreservedEscapes)
		if len(fn.LLVMCallFacts) > 0 {
			result.LLVMFunctionsWithCalls++
			result.LLVMCallFacts += len(fn.LLVMCallFacts)
			for _, fact := range fn.LLVMCallFacts {
				if fact.MustReturnExact {
					result.LLVMMustReturnExactFacts++
				}
				if fact.MustReturnNegativeOnError || fact.MustReturnNegativeOnFalse {
					result.LLVMMustReturnErrorFacts++
				}
				if fact.MustPreserveNonnegativeSuccess {
					result.LLVMSuccessPreserveFacts++
				}
				if fact.MustPreserveValidPointerSuccess {
					result.LLVMPointerPreserveFacts++
				}
			}
		}
		if fn.LSMEffectUnknownWitness != "" {
			result.LSMUnknownWitnessFunctions++
		}
		if fn.SIGEffectUnknownWitness != "" {
			result.SIGUnknownWitnessFunctions++
		}
	}
	for _, table := range a.operationTables {
		if table.VerifiedByClang {
			result.ClangVerifiedOpsTables++
		}
		if table.Const && table.Complete {
			result.ClosedConstOperationTables++
		}
	}
	return result
}

func (a *Analyzer) buildSyscallReport(entry SyscallEntry) SyscallReport {
	report := SyscallReport{
		Number:                  entry.Number,
		ABI:                     entry.ABI,
		Name:                    entry.Name,
		Entry:                   entry.Entry,
		Start:                   entry.Start,
		LinkedSymbol:            entry.LinkedSymbol,
		LinkedSymbolType:        entry.LinkedSymbolType,
		Availability:            entry.Availability,
		AvailabilityReason:      entry.AvailabilityReason,
		LSMClassification:       "uncertain",
		SIGKILLClassification:   "uncertain",
		LSMEnforcementState:     "U",
		SIGKILLEnforcementState: "U",
		NegativeReasons:         ClassificationNegativeReasons{LSM: []string{}, SIGKILL: []string{}},
		UnresolvedProofEdges:    []UnresolvedProofEdge{},
		CertifiedLSMHooks:       []string{},
		LSMPathCoverage:         LSMPathCoverageProof{Status: "uncertain", Hooks: []string{}, SuccessPathHookSets: [][]string{}, ProofMethods: []string{}, ProofFunctions: []string{}, HookProofPaths: map[string][]string{}, Reasons: []string{}},
		SIGKILLPathCoverage:     SIGKILLPathCoverageProof{Status: "uncertain", Checks: []string{}, SuccessPathCheckSets: [][]string{}, ProofMethods: []string{}, ProofFunctions: []string{}, CheckProofPaths: map[string][]string{}, Reasons: []string{}},
		CurrentReachableSig:     []string{},
		CurrentAlwaysSig:        []string{},
		UnknownSubjectSig:       []string{},
		AlwaysSignalCheckPaths:  []SignalCheckPath{},
	}
	if entry.Availability == syscallAvailabilityUnavailableSlot ||
		entry.Availability == syscallAvailabilityUnavailableConfig {
		reason := entry.AvailabilityReason
		if reason == "" {
			reason = "the configured kernel does not provide an executable implementation for this syscall slot"
		}
		report.LSMClassification = "not_applicable_unavailable"
		report.SIGKILLClassification = "not_applicable_unavailable"
		report.LSMEnforcementState = "NA"
		report.SIGKILLEnforcementState = "NA"
		report.NegativeReasons.LSM = []string{reason}
		report.NegativeReasons.SIGKILL = []string{reason}
		report.ProofEligibility = SyscallProofEligibility{
			LSM: DomainProofEligibility{
				Status:        "not_applicable",
				NegativeProof: true,
				Reasons:       []string{reason},
			},
			SIGKILL: DomainProofEligibility{
				Status:        "not_applicable",
				NegativeProof: true,
				Reasons:       []string{reason},
			},
		}
		report.CallTreeFile = filepath.Join("syscalls", entry.Name+".txt")
		_ = writeText(
			filepath.Join(a.cfg.OutDir, report.CallTreeFile),
			fmt.Sprintf("syscall %s(%d): unavailable in the configured kernel: %s\n", entry.Name, entry.Number, reason),
		)
		return report
	}
	startFn, ok := a.resolveStartFunction(entry)
	if !ok {
		reason := "syscall entry function was not found in the configured function index"
		report.ProofEligibility = SyscallProofEligibility{
			LSM:     DomainProofEligibility{Status: "incomplete", Reasons: []string{reason}},
			SIGKILL: DomainProofEligibility{Status: "incomplete", Reasons: []string{reason}},
		}
		report.NegativeReasons.LSM = []string{reason}
		report.NegativeReasons.SIGKILL = []string{reason}
		report.UnresolvedProofEdges = []UnresolvedProofEdge{
			{Domain: "lsm", Caller: entry.Start, Kind: "start_function_unresolved", Detail: reason},
			{Domain: "sigkill", Caller: entry.Start, Kind: "start_function_unresolved", Detail: reason},
		}
		report.CallTreeFile = filepath.Join("syscalls", entry.Name+".txt")
		_ = writeText(filepath.Join(a.cfg.OutDir, report.CallTreeFile), fmt.Sprintf("syscall %s: start function not found (candidate: %s)\n", entry.Name, entry.Start))
		return report
	}

	report.StartFound = true
	report.Start = startFn
	summary := a.summarizeFunction(startFn, map[string]bool{})
	report.AnalysisStats = summary.SignalStats
	report.ReachableFunctions = summary.NormalPathFuncs
	report.SuccessPathFunctions = summary.NormalPathFuncs
	if a.cfg.EmitRaw {
		report.RawReachableFunctions = summary.ReachableFuncs
	}
	report.AlwaysLSMHooks = summary.MustPassLSMHooks
	report.AlwaysSigChecks = summary.AlwaysSigChecks
	report.AlwaysSigCategories = categorizeSignalChecks(summary.AlwaysSigChecks)
	report.ValidatedLSMHooks = summary.ValidatedLSMHooks
	report.ValidatedSigChecks = summary.ValidatedSigChecks
	report.MustPassLSMHooks = summary.MustPassLSMHooks
	report.InactiveLSMHooks = summary.InactiveLSMHooks
	strictEffects, strictEffective := a.analyzeLSMErrorEffects(startFn, summary.MustPassLSMHooks)
	kernelGateHooks := a.kernelGateMandatoryLSMHooks(startFn)
	kernelGateEffects, kernelGateEffective := a.analyzeKernelGateLSMErrorEffects(startFn, kernelGateHooks)
	report.MustPassLSMHooks = uniqueStrings(append(report.MustPassLSMHooks, kernelGateHooks...))
	report.AlwaysLSMHooks = append([]string(nil), report.MustPassLSMHooks...)
	report.LSMErrorEffects = mergeLSMEffectLists(strictEffects, kernelGateEffects)
	report.EffectiveLSMHooks = uniqueStrings(append(strictEffective, kernelGateEffective...))
	lsmCoverage := a.analyzeLSMPathCoverage(startFn)
	lsmCoverage = a.promoteKernelGateLSMCoverage(lsmCoverage, kernelGateEffects, kernelGateEffective)
	report.LSMPathCoverage = LSMPathCoverageProof{
		Status:              lsmCoverage.state,
		Hooks:               append([]string(nil), lsmCoverage.hooks...),
		SuccessPathHookSets: lsmAlternativeHookSets(lsmCoverage.alternatives),
		ProofMethods:        append([]string(nil), lsmCoverage.proofMethods...),
		ProofFunctions:      append([]string(nil), lsmCoverage.proofFunctions...),
		HookProofPaths:      cloneStringSliceMap(lsmCoverage.hookProofPaths),
		BypassProofPath:     append([]string(nil), lsmCoverage.bypassProofPath...),
		BypassProofMethod:   lsmCoverage.bypassProofMethod,
		UnprovenBypassPath:  append([]string(nil), lsmCoverage.unprovenBypassPath...),
		Reasons:             append([]string(nil), lsmCoverage.reasons...),
		Unresolved:          append([]UnresolvedProofEdge(nil), lsmCoverage.unresolved...),
		CoveredUnresolved:   append([]UnresolvedProofEdge(nil), lsmCoverage.coveredUnresolved...),
	}
	report.EffectiveLSMHooks = uniqueStrings(append(
		report.EffectiveLSMHooks,
		lsmCoverage.hooks...,
	))
	signalCoverage := a.analyzeSIGKILLPathCoverage(startFn)
	report.SIGKILLPathCoverage = SIGKILLPathCoverageProof{
		Status:               signalCoverage.state,
		Checks:               append([]string(nil), signalCoverage.checks...),
		SuccessPathCheckSets: signalAlternativeCheckSets(signalCoverage.alternatives),
		ProofMethods:         append([]string(nil), signalCoverage.proofMethods...),
		ProofFunctions:       append([]string(nil), signalCoverage.proofFunctions...),
		CheckProofPaths:      cloneStringSliceMap(signalCoverage.checkProofPaths),
		BypassProofPath:      append([]string(nil), signalCoverage.bypassProofPath...),
		BypassProofMethod:    signalCoverage.bypassProofMethod,
		UnprovenBypassPath:   append([]string(nil), signalCoverage.unprovenBypassPath...),
		Reasons:              append([]string(nil), signalCoverage.reasons...),
		Unresolved:           append([]UnresolvedProofEdge(nil), signalCoverage.unresolved...),
		CoveredUnresolved:    append([]UnresolvedProofEdge(nil), signalCoverage.coveredUnresolved...),
	}
	report.NormalPathFunctions = uniqueStrings(append(summary.NormalPathFuncs, lsmCoverage.proofFunctions...))
	report.ReachableFunctions = append([]string(nil), report.NormalPathFunctions...)
	report.SuccessPathFunctions = append([]string(nil), report.NormalPathFunctions...)
	report.UnprovenLSMCandidates = a.findUnprovenLSMCandidates(summary.NormalPathFuncs, report.MustPassLSMHooks)
	report.ReachableSigChecks = uniqueStrings(append(
		append([]string(nil), summary.ReachableSigChecks...),
		signalCoverage.checks...,
	))
	report.ReachableSigCategories = categorizeSignalChecks(summary.ReachableSigChecks)
	report.SignalCheckPaths = mergeSignalCheckPaths(
		summary.SignalCheckPaths,
		signalCoverage.checkPaths,
	)
	report.AlwaysSignalCheckPaths = summary.AlwaysSignalCheckPaths
	report.StrongSigChecks = summary.StrongSigChecks
	report.CurrentReachableSig = uniqueStrings(append(
		append([]string(nil), summary.CurrentReachableSignals...),
		signalCoverage.checks...,
	))
	report.CurrentAlwaysSig = summary.CurrentAlwaysSignals
	report.UnknownSubjectSig = summary.UnknownSubjectSignals
	report.ConditionalSigChecks = subtractPreserve(summary.ReachableSigChecks, summary.AlwaysSigChecks)
	if a.cfg.EmitRaw {
		report.ReachableLSMHooks = summary.ReachableLSMHooks
		report.OptionalLSMHooks = subtractPreserve(summary.ReachableLSMHooks, report.MustPassLSMHooks)
		report.ConditionalLSMHooks = subtractPreserve(summary.ReachableLSMHooks, report.MustPassLSMHooks)
	} else {
		report.ReachableLSMHooks = report.MustPassLSMHooks
		report.ValidatedLSMHooks = report.MustPassLSMHooks
	}
	report.ContainsLSMHook = len(report.ReachableLSMHooks) > 0 || len(report.LSMPathCoverage.Hooks) > 0
	report.ContainsSignalChecks = len(report.ReachableSigChecks) > 0 ||
		len(report.SIGKILLPathCoverage.Checks) > 0
	report.LSMReachability = classifyMandatoryReachability(report.ReachableLSMHooks, report.MustPassLSMHooks)
	report.SignalReachability = classifyReachability(report.ReachableSigChecks, summary.AlwaysSigChecks)
	report.ValidatedLSMReach = classifyReachability(report.ReachableLSMHooks, summary.ValidatedLSMHooks)
	report.ValidatedSignalReach = classifyReachability(report.ReachableSigChecks, summary.ValidatedSigChecks)
	report.HasSigkillChecks = len(report.StrongSigChecks) > 0
	report.DirectLSMFunctions = a.findTaggedFunctions(startFn, true)
	report.DirectSignalFuncs = a.findTaggedDisplayFunctions(summary.SignalPathFuncs, false)
	if !a.cfg.EmitRaw {
		report.DirectLSMFunctions = intersectStrings(report.DirectLSMFunctions, report.NormalPathFunctions)
	}
	a.applyFinalClassifications(&report, summary)

	callTreeFile := filepath.Join("syscalls", entry.Name+".txt")
	report.CallTreeFile = callTreeFile
	_ = writeText(filepath.Join(a.cfg.OutDir, callTreeFile), a.renderCallTree(startFn, report.NormalPathFunctions))
	if a.cfg.EmitRaw {
		rawCallTreeFile := filepath.Join("raw_syscalls", entry.Name+".txt")
		report.RawCallTreeFile = rawCallTreeFile
		_ = writeText(filepath.Join(a.cfg.OutDir, rawCallTreeFile), a.renderCallTree(startFn, nil))
	}

	return report
}

func (a *Analyzer) applyFinalClassifications(report *SyscallReport, summary FunctionSummary) {
	report.UnresolvedProofEdges = sortedProofGaps(append(
		append([]UnresolvedProofEdge(nil), report.LSMPathCoverage.Unresolved...),
		report.SIGKILLPathCoverage.Unresolved...,
	))
	prerequisiteReasons := a.proofPrerequisiteReasons()
	bpfEnabled, bpfDefinitelyDisabled, bpfReasons := a.bpfLSMConfiguration()

	lsmBlockers := orderedSet(prerequisiteReasons)
	lsmBlockers.addAll(report.LSMPathCoverage.Reasons)
	coverageEffectsComplete := len(report.LSMPathCoverage.SuccessPathHookSets) > 0
	certifiedHooks := orderedSet(nil)
	for index, hookSet := range report.LSMPathCoverage.SuccessPathHookSets {
		pathCovered := false
		for _, hook := range hookSet {
			if containsString(report.EffectiveLSMHooks, hook) {
				pathCovered = true
				certifiedHooks.add(hook)
			}
		}
		if !pathCovered {
			coverageEffectsComplete = false
			lsmBlockers.add(fmt.Sprintf(
				"success path %d has no hook with certified final syscall-error propagation",
				index+1,
			))
		}
	}
	if report.LSMPathCoverage.Status == "enforcing" && !bpfEnabled && !bpfDefinitelyDisabled {
		lsmBlockers.addAll(bpfReasons)
	}
	switch {
	case bpfDefinitelyDisabled && len(prerequisiteReasons) == 0:
		report.LSMClassification = "certified_bpf_lsm_not_enforceable"
		report.NegativeReasons.LSM = append([]string(nil), bpfReasons...)
		report.ProofEligibility.LSM = DomainProofEligibility{
			Status:        "complete",
			PositiveProof: false,
			NegativeProof: true,
			Reasons:       append([]string(nil), bpfReasons...),
		}
	case report.LSMPathCoverage.Status == "enforcing" && coverageEffectsComplete &&
		len(prerequisiteReasons) == 0 && bpfEnabled:
		report.CertifiedLSMHooks = certifiedHooks.slice()
		certifiedBPFHooks := orderedSet(nil)
		for _, wrapper := range report.CertifiedLSMHooks {
			if hook := a.canonicalBPFLSMHook(wrapper); hook != "" {
				certifiedBPFHooks.add(hook)
			}
		}
		report.CertifiedBPFLSMHooks = certifiedBPFHooks.slice()
		report.LSMClassification = "certified_bpf_lsm_enforceable"
		report.ProofEligibility.LSM = makeDomainProofEligibility(true, false, nil)
	case report.LSMPathCoverage.Status == "non_enforcing" && len(prerequisiteReasons) == 0:
		report.LSMClassification = "certified_bpf_lsm_not_enforceable"
		report.NegativeReasons.LSM = append([]string(nil), report.LSMPathCoverage.Reasons...)
		report.ProofEligibility.LSM = makeDomainProofEligibility(false, true, nil)
	default:
		report.LSMClassification = "uncertain"
		if report.LSMPathCoverage.Status == "enforcing" && !bpfEnabled {
			lsmBlockers.addAll(bpfReasons)
		}
		report.NegativeReasons.LSM = lsmBlockers.slice()
		report.ProofEligibility.LSM = makeDomainProofEligibility(false, false, lsmBlockers.slice())
	}

	signalBlockers := orderedSet(prerequisiteReasons)
	signalBlockers.addAll(report.SIGKILLPathCoverage.Reasons)
	switch {
	case report.SIGKILLPathCoverage.Status == "enforcing" &&
		len(prerequisiteReasons) == 0:
		report.SIGKILLClassification = "certified_sigkill_enforceable"
		report.ProofEligibility.SIGKILL = makeDomainProofEligibility(
			true,
			false,
			nil,
		)
	case report.SIGKILLPathCoverage.Status == "non_enforcing" &&
		len(prerequisiteReasons) == 0:
		report.SIGKILLClassification = "certified_sigkill_not_enforceable"
		report.NegativeReasons.SIGKILL = append(
			[]string(nil),
			report.SIGKILLPathCoverage.Reasons...,
		)
		report.ProofEligibility.SIGKILL = makeDomainProofEligibility(false, true, nil)
	default:
		report.SIGKILLClassification = "uncertain"
		report.NegativeReasons.SIGKILL = signalBlockers.slice()
		report.ProofEligibility.SIGKILL = makeDomainProofEligibility(
			false,
			false,
			signalBlockers.slice(),
		)
	}
	report.LSMEnforcementState = enforcementStateForClassification(
		report.LSMClassification,
	)
	report.SIGKILLEnforcementState = enforcementStateForClassification(
		report.SIGKILLClassification,
	)
}

func enforcementStateForClassification(classification string) string {
	switch classification {
	case "certified_bpf_lsm_enforceable", "certified_sigkill_enforceable":
		return "E"
	case "certified_bpf_lsm_not_enforceable",
		"certified_sigkill_not_enforceable":
		return "N"
	case "not_applicable_unavailable":
		return "NA"
	default:
		return "U"
	}
}

func (a *Analyzer) proofPrerequisiteReasons() []string {
	reasons := orderedSet(nil)
	if a.cfg.Frontend != "hybrid" {
		reasons.add("final certification requires the hybrid Clang AST/CFG frontend")
	}
	if a.cfg.CompileDB == "" {
		reasons.add("final certification requires a configured compile database")
	}
	if !a.hasKernelConfig {
		reasons.add("final certification requires the analyzed kernel .config")
	}
	if a.inputValidation.Performed && a.inputValidation.Status != "complete" {
		reasons.addAll(a.inputValidation.Reasons)
	}
	return reasons.slice()
}

func (a *Analyzer) bpfLSMConfiguration() (bool, bool, []string) {
	if !a.hasKernelConfig {
		return false, false, []string{"BPF LSM configuration is unknown"}
	}
	disabled := orderedSet(nil)
	for _, symbol := range []string{"CONFIG_SECURITY", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_LSM"} {
		if !a.configSymbols[symbol] {
			disabled.add(symbol + " is disabled")
		}
	}
	if len(disabled.items) > 0 {
		return false, true, disabled.slice()
	}
	lsmOrder := a.configValues["CONFIG_LSM"]
	if lsmOrder != "" && !containsString(strings.Split(lsmOrder, ","), "bpf") {
		return false, false, []string{"CONFIG_LSM does not enable bpf by default; runtime lsm= override is not statically known"}
	}
	return true, false, nil
}

func (a *Analyzer) proofPathReasons(path []string) []string {
	reasons := orderedSet(nil)
	for _, displayName := range path {
		functionID, ok := a.displayIndex[displayName]
		if !ok {
			reasons.add("proof path function is not indexed: " + displayName)
			continue
		}
		fn := a.functions[functionID]
		if fn == nil {
			reasons.add("proof path function is not indexed: " + displayName)
			continue
		}
		if fn.Frontend != "clang-ast-cfg" {
			reasons.add("legacy frontend function in proof path: " + displayName)
		} else if !fn.CFGComplete {
			reasons.add("incomplete CFG in proof path: " + displayName)
		}
		if fn.FrontendVariantConflict {
			reasons.add("translation-unit variant conflict in proof path: " + displayName)
		}
	}
	return reasons.slice()
}

func indirectEvidenceClosed(edges []IndirectCallEvidence) bool {
	for _, edge := range edges {
		if !edge.TargetSetClosed {
			return false
		}
	}
	return true
}

func (a *Analyzer) betterSignalCheckPath(candidate, existing SignalCheckPath) bool {
	score := func(path SignalCheckPath) int {
		result := 0
		if path.SIGKILLRelevance == signalSIGKILLRelevant {
			result += 100
		}
		switch path.AbortEffect {
		case "guaranteed":
			result += 40
		case "conditional":
			result += 20
		}
		switch path.Traversal {
		case "mandatory":
			result += 20
		case "locally-mandatory":
			result += 15
		case "locally-conditional":
			result += 10
		}
		if indirectEvidenceClosed(path.IndirectEdges) {
			result += 10
		}
		if len(a.proofPathReasons(path.ProofPath)) == 0 {
			result += 10
		}
		return result
	}
	candidateScore := score(candidate)
	existingScore := score(existing)
	if candidateScore != existingScore {
		return candidateScore > existingScore
	}
	return len(candidate.ProofPath) < len(existing.ProofPath)
}

func makeDomainProofEligibility(positive, negative bool, reasons []string) DomainProofEligibility {
	status := "incomplete"
	if negative {
		status = "complete"
	} else if positive {
		status = "positive_only"
	}
	return DomainProofEligibility{
		Status:        status,
		PositiveProof: positive,
		NegativeProof: negative,
		Reasons:       uniqueStrings(reasons),
	}
}

func (a *Analyzer) findUnprovenLSMCandidates(normalPathFunctions, mandatoryHooks []string) []UnprovenLSMCandidate {
	mandatory := make(map[string]struct{}, len(mandatoryHooks))
	for _, hook := range mandatoryHooks {
		mandatory[hook] = struct{}{}
	}
	byDisplay := make(map[string]*FunctionInfo, len(a.functions))
	for _, function := range a.functions {
		byDisplay[function.DisplayName] = function
	}
	seen := make(map[string]struct{})
	result := make([]UnprovenLSMCandidate, 0)
	for _, displayName := range normalPathFunctions {
		function := byDisplay[displayName]
		if function == nil {
			continue
		}
		for _, hook := range function.DirectLSMHooks {
			if _, ok := mandatory[hook]; ok {
				continue
			}
			key := hook + "\x00" + function.DisplayName
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, UnprovenLSMCandidate{
				Hook:     hook,
				Function: function.DisplayName,
				HookKind: a.classifyLSMHookKind(hook, unknownLocalErrorEffect()),
				Reason:   "normal-path function reached, but mandatory hook traversal was not proven",
			})
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Hook != result[right].Hook {
			return result[left].Hook < result[right].Hook
		}
		return result[left].Function < result[right].Function
	})
	return result
}

func (a *Analyzer) findTaggedDisplayFunctions(displayNames []string, lsm bool) []string {
	byDisplay := make(map[string]*FunctionInfo, len(a.functions))
	for _, fn := range a.functions {
		byDisplay[fn.DisplayName] = fn
	}
	result := orderedSet(nil)
	for _, displayName := range displayNames {
		fn := byDisplay[displayName]
		if fn == nil {
			continue
		}
		if (lsm && len(fn.DirectLSMHooks) > 0) || (!lsm && len(fn.DirectSigChecks) > 0) {
			result.add(fn.DisplayName)
		}
	}
	return result.slice()
}

func (a *Analyzer) resolveStartFunction(entry SyscallEntry) (string, bool) {
	candidates := []string{
		entry.Start,
		"__do_sys_" + entry.Name,
		"__do_compat_sys_" + entry.Name,
		entry.Entry,
	}
	for _, candidate := range candidates {
		if _, ok := a.functions[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

func (a *Analyzer) findTaggedFunctions(start string, lsm bool) []string {
	visited := make(map[string]bool)
	result := orderedSet(nil)
	var walk func(string)
	walk = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		fn, ok := a.functions[name]
		if !ok {
			return
		}
		if lsm && len(fn.DirectLSMHooks) > 0 {
			result.add(fn.DisplayName)
		}
		if !lsm && len(fn.DirectSigChecks) > 0 {
			result.add(fn.DisplayName)
		}
		for _, calleeID := range fn.DirectCallees {
			walk(calleeID)
		}
	}
	walk(start)
	return result.slice()
}

func (a *Analyzer) renderCallTree(start string, allowedFunctions []string) string {
	var b strings.Builder
	visited := make(map[string]bool)
	active := make(map[string]bool)
	var allowed map[string]bool
	if allowedFunctions != nil {
		allowed = make(map[string]bool, len(allowedFunctions))
		for _, displayName := range allowedFunctions {
			allowed[displayName] = true
		}
	}
	var walk func(string, map[string]string, int)
	walk = func(id string, constants map[string]string, depth int) {
		indent := strings.Repeat("  ", depth)
		fn, ok := a.functions[id]
		if !ok {
			fmt.Fprintf(&b, "%s- %s [unresolved]\n", indent, id)
			return
		}
		if allowed != nil && !allowed[fn.DisplayName] {
			return
		}
		contextKey := functionContextKey(fn, constants)

		annotations := make([]string, 0, 8)
		if len(fn.DirectLSMHooks) > 0 {
			annotations = append(annotations, "direct_lsm="+strings.Join(fn.DirectLSMHooks, ","))
		}
		if len(fn.InactiveLSMHooks) > 0 {
			annotations = append(annotations, "inactive_config_lsm="+strings.Join(fn.InactiveLSMHooks, ","))
		}
		if len(fn.DirectSigChecks) > 0 {
			annotations = append(annotations, "direct_signal="+strings.Join(fn.DirectSigChecks, ","))
		}
		successScan := a.cachedContextSuccessScan(fn, constants)
		if allowed != nil {
			kernelScan := a.cachedContextKernelSuccessScan(fn, constants)
			successScan.callees = uniqueStrings(append(successScan.callees, kernelScan.callees...))
			successScan.calls = append(successScan.calls, kernelScan.calls...)
			successScan.indirectCalls = uniqueIndirectInvocations(append(successScan.indirectCalls, kernelScan.indirectCalls...))
			successScan.lsmHooks = uniqueStrings(append(successScan.lsmHooks, kernelScan.lsmHooks...))
			successScan.inactiveLSMHooks = uniqueStrings(append(successScan.inactiveLSMHooks, kernelScan.inactiveLSMHooks...))
		}
		successLSM := successScan.lsmHooks
		if len(successLSM) > 0 {
			annotations = append(annotations, "success_lsm="+strings.Join(successLSM, ","))
		}
		alwaysSig := directAlwaysSignalChecks(fn)
		if len(alwaysSig) > 0 {
			annotations = append(annotations, "always_signal="+strings.Join(alwaysSig, ","))
		}
		validatedLSM := a.cachedValidatedScan(fn).lsmHooks
		if len(validatedLSM) > 0 {
			annotations = append(annotations, "validated_lsm="+strings.Join(validatedLSM, ","))
		}
		validatedSig := directValidatedSignalChecks(fn)
		if len(validatedSig) > 0 {
			annotations = append(annotations, "validated_signal="+strings.Join(validatedSig, ","))
		}
		if len(fn.AmbiguousCalls) > 0 {
			annotations = append(annotations, "ambiguous="+strings.Join(fn.AmbiguousCalls, ","))
		}
		if len(fn.IndirectCalls) > 0 {
			annotations = append(annotations, "indirect="+strings.Join(fn.IndirectCalls, ","))
		}
		if len(fn.ResolvedIndirectCalls) > 0 {
			resolved := make([]string, 0, len(fn.ResolvedIndirectCalls))
			for _, resolution := range fn.ResolvedIndirectCalls {
				resolved = append(resolved, resolution.Expression+"=>"+strings.Join(resolution.Targets, ","))
			}
			annotations = append(annotations, "indirect_resolved="+strings.Join(resolved, ";"))
		}
		if len(fn.UnresolvedCalls) > 0 {
			annotations = append(annotations, "unresolved="+strings.Join(fn.UnresolvedCalls, ","))
		}
		if visited[contextKey] || active[id] {
			annotations = append(annotations, "dp_skip=revisited")
		}
		if len(annotations) > 0 {
			fmt.Fprintf(&b, "%s- %s [%s]\n", indent, fn.DisplayName, strings.Join(annotations, " | "))
		} else {
			fmt.Fprintf(&b, "%s- %s\n", indent, fn.DisplayName)
		}

		if visited[contextKey] || active[id] {
			return
		}
		if a.cfg.MaxDepth > 0 && depth >= a.cfg.MaxDepth {
			fmt.Fprintf(&b, "%s  - ... [max depth reached]\n", indent)
			return
		}
		visited[contextKey] = true
		active[id] = true
		defer delete(active, id)
		if allowed == nil {
			for _, calleeID := range fn.DirectCallees {
				walk(calleeID, nil, depth+1)
			}
			return
		}
		for _, call := range a.resolveContextCalls(fn, successScan) {
			walk(call.functionID, call.constants, depth+1)
		}
	}

	walk(start, nil, 0)
	return b.String()
}

func stripComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))

	inLine := false
	inBlock := false
	inString := byte(0)
	for i := 0; i < len(src); i++ {
		ch := src[i]
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}

		if inLine {
			if ch == '\n' {
				inLine = false
				b.WriteByte('\n')
			}
			continue
		}
		if inBlock {
			if ch == '*' && next == '/' {
				inBlock = false
				i++
			} else if ch == '\n' {
				b.WriteByte('\n')
			}
			continue
		}
		if inString != 0 {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}

		if ch == '"' || ch == '\'' {
			inString = ch
			b.WriteByte(ch)
			continue
		}
		if ch == '/' && next == '/' {
			inLine = true
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlock = true
			i++
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func findMatchingBrace(src string, openBrace int) (int, bool) {
	depth := 0
	inString := byte(0)
	for i := openBrace; i < len(src); i++ {
		ch := src[i]
		if inString != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inString = ch
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func findMatchingParenBackward(src string, closeParen int) (int, bool) {
	depth := 0
	for i := closeParen; i >= 0; i-- {
		switch src[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func extractDirectCallees(body string) []string {
	body = maskStringAndCharLiterals(body)
	re := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	indexes := re.FindAllStringSubmatchIndex(body, -1)
	set := orderedSet(nil)
	for _, idx := range indexes {
		name := body[idx[2]:idx[3]]
		if shouldSkipCallee(name) || isIndirectMatch(body, idx[2]) {
			continue
		}
		set.add(name)
	}
	return set.slice()
}

type callInvocation struct {
	name       string
	arguments  []string
	callSiteID string
}

type indirectCallInvocation struct {
	expression      string
	macro           string
	fallback        string
	arguments       []string
	explicitTargets []string
}

func extractDirectInvocations(body string) []callInvocation {
	masked := maskStringAndCharLiterals(body)
	re := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	indexes := re.FindAllStringSubmatchIndex(masked, -1)
	result := make([]callInvocation, 0, len(indexes))
	for _, index := range indexes {
		name := masked[index[2]:index[3]]
		if shouldSkipCallee(name) || isIndirectMatch(masked, index[2]) {
			continue
		}
		openParen := index[1] - 1
		closeParen, ok := findMatchingParenForward(masked, openParen)
		if !ok {
			continue
		}
		arguments := splitTopLevelCommaList(body[openParen+1 : closeParen])
		if len(arguments) == 1 && arguments[0] == "" {
			arguments = nil
		}
		result = append(result, callInvocation{name: name, arguments: arguments})
	}
	return result
}

func extractIndirectCalls(body string) []string {
	set := orderedSet(nil)
	for _, invocation := range extractIndirectInvocations(body) {
		set.add(invocation.expression)
	}
	masked := maskStringAndCharLiterals(body)
	for _, match := range regexp.MustCompile(`\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(`).FindAllString(masked, -1) {
		set.add(strings.TrimSpace(match))
	}
	return set.slice()
}

func extractIndirectInvocations(body string) []indirectCallInvocation {
	masked := maskStringAndCharLiterals(body)
	result := make([]indirectCallInvocation, 0)
	macroPattern := regexp.MustCompile(`\b(INDIRECT_CALL_(?:[1-4]|INET|INET_1))\s*\(`)
	for _, match := range macroPattern.FindAllStringSubmatchIndex(masked, -1) {
		macro := masked[match[2]:match[3]]
		openParen := match[1] - 1
		closeParen, ok := findMatchingParenForward(masked, openParen)
		if !ok {
			continue
		}
		arguments := splitTopLevelCommaList(body[openParen+1 : closeParen])
		candidateCount := indirectMacroCandidateCount(macro)
		if candidateCount == 0 || len(arguments) < candidateCount+1 {
			continue
		}
		explicitTargets := make([]string, 0, candidateCount)
		for _, candidate := range arguments[1 : candidateCount+1] {
			candidate = strings.TrimSpace(candidate)
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(candidate) {
				explicitTargets = append(explicitTargets, candidate)
			}
		}
		fallback := normalizeMemberExpression(arguments[0])
		result = append(result, indirectCallInvocation{
			expression:      macro + "(" + fallback + ")",
			macro:           macro,
			fallback:        fallback,
			arguments:       append([]string(nil), arguments[candidateCount+1:]...),
			explicitTargets: explicitTargets,
		})
	}

	memberPattern := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*\(`)
	for _, match := range memberPattern.FindAllStringSubmatchIndex(masked, -1) {
		expression := normalizeMemberExpression(body[match[2]:match[3]])
		openParen := match[1] - 1
		closeParen, ok := findMatchingParenForward(masked, openParen)
		if !ok {
			continue
		}
		arguments := splitTopLevelCommaList(body[openParen+1 : closeParen])
		if len(arguments) == 1 && arguments[0] == "" {
			arguments = nil
		}
		result = append(result, indirectCallInvocation{expression: expression, arguments: arguments})
	}
	return uniqueIndirectInvocations(result)
}

func indirectMacroCandidateCount(name string) int {
	switch name {
	case "INDIRECT_CALL_INET":
		return 2
	case "INDIRECT_CALL_INET_1":
		return 1
	}
	value, err := strconv.Atoi(strings.TrimPrefix(name, "INDIRECT_CALL_"))
	if err != nil || value < 1 || value > 4 {
		return 0
	}
	return value
}

func normalizeMemberExpression(expression string) string {
	expression = strings.TrimSpace(expression)
	expression = regexp.MustCompile(`\s*->\s*`).ReplaceAllString(expression, "->")
	return regexp.MustCompile(`\s*\.\s*`).ReplaceAllString(expression, ".")
}

func uniqueIndirectInvocations(invocations []indirectCallInvocation) []indirectCallInvocation {
	seen := make(map[string]struct{}, len(invocations))
	result := make([]indirectCallInvocation, 0, len(invocations))
	for _, invocation := range invocations {
		key := invocation.expression + "\x00" + invocation.fallback + "\x00" + strings.Join(invocation.arguments, "\x00") + "\x00" + strings.Join(invocation.explicitTargets, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, invocation)
	}
	return result
}

func isIndirectMatch(body string, start int) bool {
	prev := start - 1
	for prev >= 0 && unicode.IsSpace(rune(body[prev])) {
		prev--
	}
	if prev >= 1 && body[prev] == '>' && body[prev-1] == '-' {
		return true
	}
	return prev >= 0 && body[prev] == '.'
}

func extractLSMHooks(body string) []string {
	body = maskStringAndCharLiterals(body)
	re := regexp.MustCompile(`\b(security_[A-Za-z0-9_]+)\s*\(`)
	matches := re.FindAllStringSubmatch(body, -1)
	set := orderedSet(nil)
	for _, match := range matches {
		set.add(match[1])
	}
	return set.slice()
}

func extractSignalChecks(body string) []string {
	body = maskStringAndCharLiterals(body)
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"fatal_signal_pending", regexp.MustCompile(`\bfatal_signal_pending\s*\(`)},
		{"signal_pending", regexp.MustCompile(`\bsignal_pending\s*\(`)},
		{"__fatal_signal_pending", regexp.MustCompile(`\b__fatal_signal_pending\s*\(`)},
		{"task_sigpending", regexp.MustCompile(`\btask_sigpending\s*\(`)},
		{"signal_group_exit", regexp.MustCompile(`\bsignal_group_exit\s*\(`)},
		{"signal_pending_state", regexp.MustCompile(`\bsignal_pending_state\s*\(`)},
		{"SIGNAL_GROUP_EXIT", regexp.MustCompile(`\bSIGNAL_GROUP_EXIT\b`)},
	}
	set := orderedSet(nil)
	for _, pattern := range patterns {
		if pattern.re.MatchString(body) {
			set.add(pattern.name)
		}
	}
	return set.slice()
}

func maskStringAndCharLiterals(source string) string {
	masked := []byte(source)
	literal := byte(0)
	for index := 0; index < len(masked); index++ {
		char := masked[index]
		if literal == 0 {
			if char == '"' || char == '\'' {
				literal = char
				masked[index] = ' '
			}
			continue
		}

		if char == '\n' {
			continue
		}
		masked[index] = ' '
		if char == '\\' && index+1 < len(masked) {
			index++
			if masked[index] != '\n' {
				masked[index] = ' '
			}
			continue
		}
		if char == literal {
			literal = 0
		}
	}
	return string(masked)
}

func shouldSkipFunctionName(name string) bool {
	switch name {
	case "if", "for", "while", "switch", "return", "sizeof":
		return true
	}
	if strings.HasPrefix(name, "SYSCALL_DEFINE") || strings.HasPrefix(name, "COMPAT_SYSCALL_DEFINE") {
		return true
	}
	return false
}

func shouldSkipCallee(name string) bool {
	keywords := map[string]struct{}{
		"if": {}, "for": {}, "while": {}, "switch": {}, "return": {}, "sizeof": {}, "typeof": {},
		"__typeof__": {}, "likely": {}, "unlikely": {}, "case": {}, "do": {}, "WARN_ON": {},
		"BUILD_BUG_ON": {}, "ARRAY_SIZE": {}, "min": {}, "max": {}, "min_t": {}, "max_t": {},
	}
	if _, ok := keywords[name]; ok {
		return true
	}
	if len(name) > 0 && strings.ToUpper(name) == name {
		return true
	}
	return false
}

func overlapsAny(target span, spans []span) bool {
	for _, candidate := range spans {
		if target.start <= candidate.end && candidate.start <= target.end {
			return true
		}
	}
	return false
}

func isIdentChar(ch byte) bool {
	return ch == '_' || ch == '$' || unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch))
}

func looksStaticDeclaration(source string, nameStart int) bool {
	declarationStart := strings.LastIndexAny(source[:nameStart], ";{}") + 1
	prefix := source[declarationStart:nameStart]
	return regexp.MustCompile(`\bstatic\b`).MatchString(prefix)
}

func extractFunctionReturnType(source string, nameStart int) string {
	declarationStart := strings.LastIndexAny(source[:nameStart], ";{}") + 1
	declaration := strings.TrimSpace(source[declarationStart:nameStart])
	if regexp.MustCompile(`\*\s*$`).MatchString(declaration) {
		return "pointer"
	}
	match := regexp.MustCompile(`\b(void|int|bool|long|unsigned|ssize_t|size_t)\s*$`).FindStringSubmatch(declaration)
	if len(match) != 2 {
		return "unknown"
	}
	return match[1]
}

func makeFunctionID(path, name string, static bool) string {
	if !static {
		return name
	}
	return path + "::" + name
}

func makeClangFunctionID(
	path, name string,
	static, inline bool,
	semanticHash, _ string,
) string {
	if static || inline {
		if semanticHash == "" {
			semanticHash = "unknown"
		}
		return path + "::" + name + "@@" + semanticHash
	}
	return makeFunctionID(path, name, static)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (a *Analyzer) resolvePrefixCallees(fn *FunctionInfo, raw []string) []string {
	result := orderedSet(nil)
	for _, name := range raw {
		ids, status := a.resolveCallee(fn, name)
		if status == "resolved" {
			result.addAll(ids)
		}
	}
	return result.slice()
}

func buildREADME(cfg Config) string {
	sourceMode := "raw source (configuration-independent over-approximation)"
	compileDatabase := "none"
	if cfg.CompileDB != "" {
		sourceMode = "compile database + configured preprocessor branch filtering"
		compileDatabase = cfg.CompileDB
	}
	if cfg.Frontend == "hybrid" {
		sourceMode = "hybrid Clang AST/CFG + kernel success-gate semantics + selective LLVM IR verification"
	}
	rawFiles := "- raw diagnostic output disabled; pass -emit-raw to generate it"
	rawNotes := "- branch-insensitive debug, panic, warning, and failure-only paths are omitted by default"
	if cfg.EmitRaw {
		rawFiles = "- raw_syscalls/<name>.txt: branch-insensitive raw static call tree"
		rawNotes = "- raw_reachable_functions and raw call trees include error, allocator-debug, warning, panic, and cleanup branches"
	}
	functionIndexFile := "- function_index.json: disabled by default; pass -emit-function-index to emit the complete diagnostic AST/CFG/LLVM index"
	if cfg.EmitFunctionIndex {
		functionIndexFile = "- function_index.json: complete per-function AST call-site use, CFG, typed callee, and LLVM SSA facts"
	}
	return fmt.Sprintf(`systematic_analysis output

kernel_root: %s
compile_database: %s
source_mode: %s
generated_output: %s

files:
- summary.json: syscall-level aggregate report
- checkpoints/progress.json: atomically updated completion, classification, uncertain, and unresolved ratios
- checkpoints/syscalls/<number>-<name>.json: complete syscall report written immediately after that syscall finishes
%s
- analysis_metadata.json: frontend coverage, CFG coverage, translation-unit variants, and LLVM failure counts
- reports/input_validation.json: source/config/build/compile-database completeness checks used by certification
- reports/syscall_availability.txt: every x86-64 table slot classified from the linked System.map
- reports/lsm_syscalls.txt: syscalls that can reach one or more security_* hooks
- reports/signal_syscalls.txt: syscalls that can reach one or more signal-exit-related checks
- reports/always_lsm_syscalls.txt: syscall -> hooks proven mandatory for successful syscall execution
- reports/always_signal_syscalls.txt: compatibility view of locally mandatory signal checks
- reports/signal_check_paths.txt: strict SIGKILL proof-cone checkpoints with category and proof path
- reports/indirect_call_resolutions.txt: evidence-based INDIRECT_CALL_* and audited socket ops-table target expansion
- reports/must_pass_lsm_syscalls.txt: syscall -> hooks that must be traversed on the normal success path
- reports/effective_lsm_syscalls.txt: path-local hooks whose negative result is proven to block the operation and terminate the syscall
- reports/certified_bpf_lsm_syscalls.txt: only syscalls with the final certified BPF LSM classification and canonical BPF hook names
- reports/lsm_path_coverage.txt: per-success-exit E/N/U coverage proof, including branch-specific enforcing hook sets
- reports/inactive_lsm_syscalls.txt: source-level security_* calls compiled as inactive stubs by the selected configuration
- reports/unproven_lsm_candidates.txt: direct hooks inside proven normal-path functions that were not promoted to mandatory
- reports/lsm_classification.txt: final certified_bpf_lsm_enforceable / certified_bpf_lsm_not_enforceable / uncertain classification
- reports/sigkill_classification.txt: final certified_sigkill_enforceable / certified_sigkill_not_enforceable / uncertain classification
- reports/classification_counts.json: paper-ready counts with unavailable syscall slots separated from applicable syscalls
- reports/proof_gaps.txt: per-syscall CFG, alias, function-pointer, variant, and unresolved-call proof gaps
- reports/proof_gap_categories.json: proof gaps grouped by domain, cause, and implementation/static-limit scope
- reports/llvm_verification_failures.txt: translation units whose optional LLVM corroboration could not be produced
- summary.json also includes validated_* fields for hooks/checks proven after top-level guard-return validation
- reports/lsm_functions.txt: functions that directly contain security_* calls
- reports/signal_functions.txt: functions that directly contain signal-exit-related checks
- syscalls/<name>.txt: conservatively proven successful-path call tree
%s

notes:
- frontend: %s
- final certification requires a completed build: vmlinux, System.map, configured module manifests, and every selected compile command object must exist and be newer than its source and build .config
- empty or weak-ENOSYS x86-64 syscall slots are reported as not_applicable_unavailable rather than omitted or counted as uncertain
- hybrid mode obtains typed function definitions, direct callees, exact direct callback arguments, and const ops-table initializers from Clang AST; regex parsing is retained only for kernel-specific errno/success-gate semantics and fallback diagnostics
- a missing Clang-identified direct target is never replaced by an unrelated same-name definition
- Clang CFG supplies executable may-reach calls, success-only edges, and per-block hook/call events
- Clang CFG successor predicates are retained so interprocedural constant arguments can remove infeasible branches before an E/N/U witness is accepted
- ambiguous AST-to-CFG event placement is emitted as cfg_event_unplaced and is never guessed
- kernel errno guards such as if (err) return err and initialized-error success gates are composed with CFG facts
- kernel_errno_success_gate is an LSM-only proof method; SIGKILL enforcement uses per-success-exit Clang CFG coverage
- LLVM verification is proof-cone selective and corroborative: it records hook and ordinary direct-call SSA uses plus negative-error, nonnegative-success, and valid-pointer-success preservation after optimization
- Clang keeps both source and macro-expanded return expressions; LLVM function summaries certify a return class only when every modeled return satisfies it
- assigned call results retain exact CFG callsite lineage across value-preserving wrappers; a wrapper is treated as identity only when every CFG return forwards the same input parameter
- symbolic caller arguments become existential success witnesses only when exact parameter-return structure and current CFG constraints prove compatibility
- LLVM may-use evidence never creates a new positive proof by itself; ignored-call slicing additionally requires complete matching reachable AST call sites
- not_present_after_codegen means optimized/inlined or absent and remains unknown; it is never treated as proof that a hook is ignored
- translation-unit-dependent inline variants are separated with Clang ODR semantic hashes and marked frontend_variant_conflict when their CFG facts differ
- reachable_functions and success_path_functions contain only the conservatively proven success path
%s
- closed_effect_source_absence is a fixed-point summary over the syscall-reachable direct-call graph
- source-free recursive SCCs converge to no effect; an actual source or unresolved effect edge propagates Possible or Unknown backward through the SCC
- unresolved targets and relevant unplaced CFG events are never closed merely because they occur in a cycle
- a final return wrapper propagates an errno only when its unique tainted parameter cannot escape and every assignment/return preserves or explicitly normalizes a negative error
- Clang records each call as returned, assigned, condition, argument, discarded, or unknown together with its return type
- a call result is classified as discarded only for a Clang-proven standalone/void call or complete matching LLVM ignored facts; calls inside if/while/comparison/short-circuit expressions remain effect-relevant
- direct predicate propagation rejects negated conditions and treats additional && requirements as conditional
- audited diagnostic-only barriers such as schedule_debug, debug hrtimer setup, taint tests, and dump_stack are excluded from success paths
- reachable_lsm_hooks uses clean mandatory paths by default; reachable_signal_checks is populated from the strict context-sensitive SIGKILL proof cone unless -emit-raw requests the legacy may-reach diagnostic traversal
- INDIRECT_CALL_1..4/INET candidates plus type-proven proto_ops/proto tables are expanded for may-reach signal paths
- proto_ops/proto candidates are narrowed through configured .ops/.prot registration pairs when that provenance is available
- other operation-table types remain unresolved because type-only global target unions can create cross-subsystem false paths
- unresolved function pointers remain marked indirect instead of being guessed; indirect expansion never promotes a hook/check into always by itself
- each unresolved proof edge records a category and resolution_scope so implementation gaps remain separate from runtime alias/function-pointer limits
- revisited functions are marked with dp_skip=revisited and not expanded again
- signal checks include only group-exit, fatal-pending, and generic-pending predicates; errno constants and PF_EXITING are excluded
- "always_lsm_hooks" means proven mandatory on the successful syscall path
- "validated" means proven after skipping top-level guard returns like if (bad_input) return ...;
- "must_pass_lsm_hooks" is the backward-compatible alias for always_lsm_hooks
- "lsm_error_effects" tracks hook_kind, blocks_operation, terminates_syscall, errno_propagation, overwrite_sites, and proof_path
- hook_kind is error-return, notification, or unknown based on the indexed hook definition's return type
- errno_propagation is exact, normalized, overwritten, conditional, ignored, or unknown; unsupported control flow remains unknown
- "effective_enforcing_lsm_hooks" contains hooks whose denial is proven to block and reach the syscall on the modeled path; collective all-path coverage is recorded separately
- "lsm_path_coverage" composes E/N/U states over every CFG success exit; different branches may use different enforcing hooks
- lsm_path_coverage.proof_methods distinguishes clang_cfg_coverage from kernel_errno_success_gate plus clang_reachable_cross_check
- a bypass is certified as N only when its return is explicitly successful or directly forwards another recursively proven successful return
- a shared variable return such as return err remains U when unrelated negative precondition paths and successful paths merge; unproven_bypass_path records that diagnostic
- unrelated baseline failures such as -EBADF or -EFAULT are excluded from E/N success-path voting
- a negative return caused by a BPF LSM denial or an observed current-task SIGKILL checkpoint remains E evidence when operation blocking and propagation to the syscall are proven
- an unresolved edge is adversarial until a later common enforcing hook covers every remaining successful path
- "certified_enforcing_lsm_hooks" is the collectively covering enforcing hook set after hybrid/CFG and BPF configuration checks
- proof_eligibility status is complete, positive_only, or incomplete; positive_only permits a certified positive witness but never a closed-world negative claim
- lsm_classification is certified_bpf_lsm_enforceable, certified_bpf_lsm_not_enforceable, or uncertain
- universal enforcement uses E+E=E, E+N=N, N+U=N, and E+U=U; one certified complete normal-success bypass therefore makes the syscall N even when other paths contain E or U
- a common E after a branch covers that branch only when every surviving path actually reaches it; an independently certified path that bypasses the common E still takes N precedence
- sigkill_classification is certified_sigkill_enforceable, certified_sigkill_not_enforceable, or uncertain
- sigkill_path_coverage applies the same E/N/U algebra to current-task SIGKILL checkpoints and requires their abort result to reach the syscall
- lsm_enforcement_state and sigkill_enforcement_state expose the paper-facing E, N, U, or NA label directly
- unresolved_edges_in_proof_cone records the exact frontend, CFG, direct-call, function-pointer, and ops-table gaps behind uncertain results
- only signal predicates whose subject is explicitly proven current and whose abort reaches the syscall contribute positive evidence
- repeated signal predicates are analyzed by Clang callsite ID; state mask, task subject, and local abort evidence cannot be borrowed across callsites
- current_task_reachable_signal_checks is diagnostic reachability; signal_check_paths.abort_effect and sigkill_classification carry the enforcement verdict
- abort_effect=conditional is limited to a positive current-task predicate conjunct followed by an explicit negative errno assignment whose return path is proven
- boolean predicate forwarding such as return signal_pending(current) is not treated as errno termination without a proven negative-error normalization
- loop-controlled predicates such as while (!signal_pending(current)) remain uncertain until loop exit and errno flow are modeled together
- ignored signal-return paths, including allocator/reclaim/debug descendants, are sliced out of the SIGKILL proof cone
- indirect signal paths remain uncertified unless the runtime target set can be closed; they are never promoted by a single candidate target
- default report generation prioritizes effect-free, low-complexity CFG blocks and stops a syscall proof immediately after a certified N success-exit witness; this changes exploration order only, not proof semantics; -report-jobs controls independent syscall workers with per-worker DP caches
- "unproven_lsm_candidates" is a review queue, not an always/optional verdict; it prevents unsupported CFG cases from becoming silent false negatives
- inactive_config_lsm_hooks records source-level security_* calls compiled as inactive stubs by the selected kernel configuration
- success-path analysis follows nested errno gates, negative initializers, and result/&errno lookup patterns; unsupported control flow produces conservative false negatives
- pointer-return calls propagate a non-NULL success requirement only when the caller proves it with an immediate failure guard; NULL is never treated as failure globally
- notify_change receives caller-proven iattr.ia_valid bits so ATTR_* masks can prove mandatory setattr hooks without guessing unrelated structure fields
- error-flow analysis preserves proven NULL cleanup guards across goto labels
- bounded retry_estale paths retain enforcement when the mandatory hook is re-entered, while errno propagation is marked conditional
- guaranteed-entry for loops such as for (;;) are analyzed through the first conditional break/continue; other loop forms remain conservative
- compile-database mode indexes only translation units built by that kernel configuration and removes inactive preprocessor branches
`, cfg.KernelRoot, compileDatabase, sourceMode, cfg.OutDir, functionIndexFile, rawFiles, cfg.Frontend, rawNotes)
}

func writeText(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func writeJSON(path string, value any) error {
	data, err := marshalIndentedJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeJSONAtomic(path string, value any) error {
	data, err := marshalIndentedJSON(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func marshalIndentedJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

func newIncrementalReportProgress(total int, started time.Time) IncrementalReportProgress {
	return IncrementalReportProgress{
		SchemaVersion: 1,
		Status:        "running",
		TotalSyscalls: total,
		StartedAt:     started.UTC().Format(time.RFC3339Nano),
		UpdatedAt:     started.UTC().Format(time.RFC3339Nano),
		LSMClassifications: map[string]int{
			"certified_bpf_lsm_enforceable":     0,
			"certified_bpf_lsm_not_enforceable": 0,
			"uncertain":                         0,
			"not_applicable_unavailable":        0,
		},
		SIGKILLClassifications: map[string]int{
			"certified_sigkill_enforceable":     0,
			"certified_sigkill_not_enforceable": 0,
			"uncertain":                         0,
			"not_applicable_unavailable":        0,
		},
	}
}

func updateIncrementalReportProgress(
	progress *IncrementalReportProgress,
	report SyscallReport,
	syscallElapsed, totalElapsed time.Duration,
	checkpoint string,
) {
	if progress == nil {
		return
	}
	progress.CompletedSyscalls++
	progress.CompletedRatio = fraction(progress.CompletedSyscalls, progress.TotalSyscalls)
	progress.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	progress.ElapsedMilliseconds = totalElapsed.Milliseconds()
	progress.LSMClassifications[report.LSMClassification]++
	progress.SIGKILLClassifications[report.SIGKILLClassification]++
	applicable := report.LSMClassification != "not_applicable_unavailable" &&
		report.SIGKILLClassification != "not_applicable_unavailable"
	if applicable {
		progress.CompletedApplicableSyscalls++
	} else {
		progress.UnavailableSyscalls++
	}
	if report.LSMClassification == "uncertain" {
		progress.LSMUncertainSyscalls++
	}
	if report.SIGKILLClassification == "uncertain" {
		progress.SIGKILLUncertainSyscalls++
	}
	if report.LSMClassification == "uncertain" ||
		report.SIGKILLClassification == "uncertain" {
		progress.EitherDomainUncertainSyscalls++
	}
	if len(report.UnresolvedProofEdges) > 0 {
		progress.UnresolvedProofSyscalls++
	}
	progress.UnresolvedProofEdges += len(report.UnresolvedProofEdges)
	for _, edge := range report.UnresolvedProofEdges {
		switch edge.Domain {
		case "lsm":
			progress.UnresolvedLSMProofEdges++
		case "sigkill":
			progress.UnresolvedSIGKILLProofEdges++
		default:
			progress.UnresolvedUnknownDomainEdges++
		}
	}
	progress.LSMUncertainRatio = fraction(
		progress.LSMUncertainSyscalls,
		progress.CompletedApplicableSyscalls,
	)
	progress.SIGKILLUncertainRatio = fraction(
		progress.SIGKILLUncertainSyscalls,
		progress.CompletedApplicableSyscalls,
	)
	progress.EitherDomainUncertainRatio = fraction(
		progress.EitherDomainUncertainSyscalls,
		progress.CompletedApplicableSyscalls,
	)
	progress.UnresolvedProofSyscallRatio = fraction(
		progress.UnresolvedProofSyscalls,
		progress.CompletedApplicableSyscalls,
	)
	progress.LastCompleted = &IncrementalSyscallResult{
		Number:                report.Number,
		ABI:                   report.ABI,
		Name:                  report.Name,
		LSMClassification:     report.LSMClassification,
		SIGKILLClassification: report.SIGKILLClassification,
		UnresolvedProofEdges:  len(report.UnresolvedProofEdges),
		ElapsedMilliseconds:   syscallElapsed.Milliseconds(),
		Checkpoint:            checkpoint,
	}
}

func fraction(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func syscallCheckpointFilename(report SyscallReport) string {
	name := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(report.Name, "_")
	return fmt.Sprintf("%03d-%s.json", report.Number, name)
}

func atoiSafe(raw string) int {
	value := 0
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return value
		}
		value = value*10 + int(ch-'0')
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func directAlwaysSignalChecks(fn *FunctionInfo) []string {
	return uniqueStrings(allInvocationPrefixScan(fn.Body).sigChecks)
}

func directValidatedSignalChecks(fn *FunctionInfo) []string {
	return uniqueStrings(validatedPrefixScan(fn.Body).sigChecks)
}

type prefixScanResult struct {
	callees           []string
	calls             []callInvocation
	unmatchedCalls    []callInvocation
	indirectCalls     []indirectCallInvocation
	lsmHooks          []string
	inactiveLSMHooks  []string
	sigChecks         []string
	returnRequirement string
}

func allInvocationPrefixScan(body string) prefixScanResult {
	var result prefixScanResult
	for _, stmt := range scanTopLevelFlow(body, false) {
		if stmt.kind != "normal" {
			continue
		}
		trimmed := stmt.text
		result.lsmHooks = append(result.lsmHooks, extractLSMHooks(trimmed)...)
		result.sigChecks = append(result.sigChecks, extractSignalChecks(trimmed)...)
		result.callees = append(result.callees, extractDirectCallees(trimmed)...)
	}
	result.callees = filterInternalCallees(result.callees)
	return result
}

func validatedPrefixScan(body string) prefixScanResult {
	var result prefixScanResult
	for _, stmt := range scanTopLevelFlow(body, true) {
		if stmt.kind != "normal" {
			continue
		}
		trimmed := stmt.text
		result.lsmHooks = append(result.lsmHooks, extractLSMHooks(trimmed)...)
		result.sigChecks = append(result.sigChecks, extractSignalChecks(trimmed)...)
		result.callees = append(result.callees, extractDirectCallees(trimmed)...)
	}
	result.callees = filterInternalCallees(result.callees)
	return result
}

func mustPassPrefixScan(body string, returnRequirements ...string) prefixScanResult {
	return mustPassSuccessPathScan(body, returnRequirements...)
}

func feasibleMayReachScan(body string) prefixScanResult {
	result := prefixScanResult{}
	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return finalizeMayReachScan(result)
		}
		if labelEnd := leadingLabelEnd(body[pos:]); labelEnd > 0 {
			pos += labelEnd
			continue
		}
		if strings.HasPrefix(body[pos:], "if") {
			detail, ok := parseIfDetail(body, pos)
			if !ok {
				appendMayReachText(&result, body[pos:])
				return finalizeMayReachScan(result)
			}
			appendMayReachText(&result, detail.condText)
			if conditionValue, known := constantConditionValue(detail.condText); known {
				selected := detail.bodyText
				if !conditionValue {
					selected = detail.elseText
				}
				appendPrefixResult(&result, feasibleMayReachScan(selected))
			} else {
				appendPrefixResult(&result, feasibleMayReachScan(detail.bodyText))
				if detail.hasElse {
					appendPrefixResult(&result, feasibleMayReachScan(detail.elseText))
				}
			}
			pos = detail.nextPos
			continue
		}
		next := findNextTopLevelSemicolon(body, pos)
		if next < 0 {
			appendMayReachText(&result, body[pos:])
			return finalizeMayReachScan(result)
		}
		appendMayReachText(&result, body[pos:next+1])
		pos = next + 1
	}
}

func appendMayReachText(result *prefixScanResult, text string) {
	result.callees = append(result.callees, extractDirectCallees(text)...)
	result.calls = append(result.calls, extractDirectInvocations(text)...)
	result.indirectCalls = append(result.indirectCalls, extractIndirectInvocations(text)...)
	result.sigChecks = append(result.sigChecks, extractSignalChecks(text)...)
}

func finalizeMayReachScan(result prefixScanResult) prefixScanResult {
	result.callees = filterInternalCallees(result.callees)
	result.calls = filterInvocations(result.calls, result.callees)
	result.indirectCalls = uniqueIndirectInvocations(result.indirectCalls)
	result.sigChecks = uniqueStrings(result.sigChecks)
	return result
}

type flowStmt struct {
	kind string
	text string
}

type ifDetail struct {
	start     int
	stmtText  string
	condText  string
	bodyText  string
	elseText  string
	bodyStart int
	bodyEnd   int
	nextPos   int
	guard     bool
	hasElse   bool
	bodyBrace bool
}

type successScanState struct {
	returnVar          string
	returnRequirement  string
	knownError         map[string]bool
	knownValues        map[string]string
	resultErrors       map[string]string
	pointerErrors      map[string]string
	functionBody       string
	activeScans        map[string]bool
	insideRequiredLoop bool
	insideRequiredGate bool
}

type loopDetail struct {
	bodyText                 string
	nextPos                  int
	firstIterationGuaranteed bool
}

type switchDetail struct {
	bodyText string
	nextPos  int
}

func mustPassSuccessPathScan(body string, returnRequirements ...string) prefixScanResult {
	returnRequirement := ""
	if len(returnRequirements) > 0 {
		returnRequirement = returnRequirements[0]
	}
	state := &successScanState{
		returnVar:         topLevelReturnVar(body),
		returnRequirement: returnRequirement,
		knownError:        make(map[string]bool),
		knownValues:       make(map[string]string),
		resultErrors:      make(map[string]string),
		pointerErrors:     make(map[string]string),
		functionBody:      body,
		activeScans:       make(map[string]bool),
	}
	return mustPassSuccessPathScanWithState(body, state)
}

func mustPassSuccessPathScanWithState(body string, state *successScanState) prefixScanResult {
	result := prefixScanResult{}
	if state.activeScans == nil {
		state.activeScans = make(map[string]bool)
	}
	if state.activeScans[body] {
		return result
	}
	state.activeScans[body] = true
	defer delete(state.activeScans, body)

	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return finalizePrefixScan(result)
		}
		if labelEnd := leadingLabelEnd(body[pos:]); labelEnd > 0 {
			pos += labelEnd
			continue
		}

		rest := body[pos:]
		switch {
		case strings.HasPrefix(rest, "if"):
			detail, ok := parseIfDetail(body, pos)
			if !ok {
				return finalizePrefixScan(result)
			}
			mandatoryCondition := mandatoryConditionPrefix(detail.condText)
			result.lsmHooks = append(result.lsmHooks, extractLSMHooks(mandatoryCondition)...)
			result.sigChecks = append(result.sigChecks, extractSignalChecks(mandatoryCondition)...)
			result.callees = append(result.callees, extractDirectCallees(mandatoryCondition)...)
			result.calls = append(result.calls, extractDirectInvocations(mandatoryCondition)...)
			if conditionValue, known := constantConditionValueWithState(detail.condText, state); known {
				selected := detail.bodyText
				if !conditionValue {
					selected = detail.elseText
				}
				if strings.TrimSpace(selected) == "" {
					pos = detail.nextPos
					continue
				}
				if labelBody, branchState, ok := successfulGotoLabelBody(selected, detail.condText, state); ok {
					appendPrefixResult(&result, mustPassSuccessPathScanWithState(labelBody, branchState))
					return finalizePrefixScan(result)
				}
				appendPrefixResult(&result, mustPassSuccessPathScanWithState(selected, state))
				if branchTerminates(selected) {
					return finalizePrefixScan(result)
				}
				pos = detail.nextPos
				continue
			}
			if state.insideRequiredLoop && (branchExitsLoop(detail.bodyText) || detail.hasElse && branchExitsLoop(detail.elseText)) {
				return finalizePrefixScan(result)
			}
			if detail.hasElse {
				branchFailure := branchEndsInKnownFailure(detail.bodyText, detail.condText, state)
				elseFailure := branchEndsInKnownFailure(detail.elseText, "!("+detail.condText+")", state)
				if branchFailure != elseFailure && !assignsVariable(body[detail.nextPos:], state.returnVar) {
					selected := detail.bodyText
					selectedCondition := detail.condText
					if branchFailure {
						selected = detail.elseText
						selectedCondition = "!(" + detail.condText + ")"
					}
					selectedState := cloneSuccessScanState(state)
					applyBranchConditionFacts(selectedCondition, selectedState)
					appendPrefixResult(&result, mustPassSuccessPathScanWithState(selected, selectedState))
					if branchTerminates(selected) {
						return finalizePrefixScan(result)
					}
					copySuccessScanFacts(state, stateAfterFeasiblePrefix(selected, selectedState))
					pos = detail.nextPos
					continue
				}
				if branchCanReturnSuccess(detail.bodyText, detail.condText, state) ||
					branchCanReturnSuccess(detail.elseText, "!("+detail.condText+")", state) {
					return finalizePrefixScan(result)
				}
				mergeConditionalState(state, detail.condText, detail.bodyText, detail.elseText)
				pos = detail.nextPos
				continue
			}
			if labelBody, branchState, ok := successfulGotoLabelBody(detail.bodyText, detail.condText, state); ok {
				branchResult := mustPassSuccessPathScanWithState(labelBody, branchState)
				fallthroughResult := mustPassSuccessPathScanWithState(body[detail.nextPos:], cloneSuccessScanState(state))
				common := intersectPrefixScans(branchResult, fallthroughResult)
				result.callees = append(result.callees, common.callees...)
				result.calls = append(result.calls, common.calls...)
				result.lsmHooks = append(result.lsmHooks, common.lsmHooks...)
				result.sigChecks = append(result.sigChecks, common.sigChecks...)
				return finalizePrefixScan(result)
			}
			if isFailureOnlyIf(detail, state) {
				pos = detail.nextPos
				continue
			}
			if isSuccessGateIf(detail, body[detail.nextPos:], state) {
				previousRequiredGate := state.insideRequiredGate
				state.insideRequiredGate = true
				inner := mustPassSuccessPathScanWithState(detail.bodyText, state)
				state.insideRequiredGate = previousRequiredGate
				result.callees = append(result.callees, inner.callees...)
				result.calls = append(result.calls, inner.calls...)
				result.lsmHooks = append(result.lsmHooks, inner.lsmHooks...)
				result.sigChecks = append(result.sigChecks, inner.sigChecks...)
				pos = detail.nextPos
				continue
			}
			if branchCanReturnSuccess(detail.bodyText, detail.condText, state) {
				branchResult := mustPassSuccessPathScanWithState(detail.bodyText, cloneSuccessScanState(state))
				fallthroughResult := mustPassSuccessPathScanWithState(body[detail.nextPos:], cloneSuccessScanState(state))
				common := intersectPrefixScans(branchResult, fallthroughResult)
				result.callees = append(result.callees, common.callees...)
				result.calls = append(result.calls, common.calls...)
				result.lsmHooks = append(result.lsmHooks, common.lsmHooks...)
				result.sigChecks = append(result.sigChecks, common.sigChecks...)
				return finalizePrefixScan(result)
			}
			mergeConditionalState(state, detail.condText, detail.bodyText, "")
			pos = detail.nextPos
			continue
		case hasKeywordPrefix(rest, "return"):
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				return finalizePrefixScan(result)
			}
			stmt := strings.TrimSpace(body[pos : next+1])
			result.lsmHooks = append(result.lsmHooks, extractLSMHooks(stmt)...)
			result.sigChecks = append(result.sigChecks, extractSignalChecks(stmt)...)
			result.callees = append(result.callees, extractDirectCallees(stmt)...)
			result.calls = append(result.calls, extractDirectInvocations(stmt)...)
			return finalizePrefixScan(result)
		case hasKeywordPrefix(rest, "for"):
			detail, ok := parseLoopDetail(body, pos)
			if !ok {
				return finalizePrefixScan(result)
			}
			if !detail.firstIterationGuaranteed {
				if loopMayBypassFollowingSuccess(detail.bodyText, state) {
					return finalizePrefixScan(result)
				}
				pos = detail.nextPos
				continue
			}
			loopState := cloneSuccessScanState(state)
			loopState.insideRequiredLoop = true
			inner := mustPassSuccessPathScanWithState(detail.bodyText, loopState)
			result.callees = append(result.callees, inner.callees...)
			result.calls = append(result.calls, inner.calls...)
			result.lsmHooks = append(result.lsmHooks, inner.lsmHooks...)
			result.sigChecks = append(result.sigChecks, inner.sigChecks...)
			pos = detail.nextPos
			continue
		case hasKeywordPrefix(rest, "while"), hasKeywordPrefix(rest, "do"):
			detail, ok := parseLoopDetail(body, pos)
			if !ok || loopMayBypassFollowingSuccess(detail.bodyText, state) {
				return finalizePrefixScan(result)
			}
			if detail.firstIterationGuaranteed {
				loopState := cloneSuccessScanState(state)
				loopState.insideRequiredLoop = true
				inner := mustPassSuccessPathScanWithState(detail.bodyText, loopState)
				result.callees = append(result.callees, inner.callees...)
				result.calls = append(result.calls, inner.calls...)
				result.lsmHooks = append(result.lsmHooks, inner.lsmHooks...)
				result.sigChecks = append(result.sigChecks, inner.sigChecks...)
			}
			pos = detail.nextPos
			continue
		case hasKeywordPrefix(rest, "switch"):
			detail, ok := parseSwitchDetail(body, pos)
			if !ok || switchMayBypassFollowingSuccess(detail.bodyText, state) {
				return finalizePrefixScan(result)
			}
			pos = detail.nextPos
			continue
		case isMacroLoopStart(rest):
			detail, ok := parseMacroLoopDetail(body, pos)
			if !ok || loopMayBypassFollowingSuccess(detail.bodyText, state) {
				return finalizePrefixScan(result)
			}
			pos = detail.nextPos
			continue
		case state.insideRequiredLoop && (hasKeywordPrefix(rest, "break") || hasKeywordPrefix(rest, "continue")):
			return finalizePrefixScan(result)
		case hasKeywordPrefix(rest, "goto"),
			hasKeywordPrefix(rest, "case"), hasKeywordPrefix(rest, "default"):
			return finalizePrefixScan(result)
		default:
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				stmt := strings.TrimSpace(body[pos:])
				if stmt != "" {
					result.lsmHooks = append(result.lsmHooks, extractLSMHooks(stmt)...)
					result.sigChecks = append(result.sigChecks, extractSignalChecks(stmt)...)
					result.callees = append(result.callees, extractDirectCallees(stmt)...)
					result.calls = append(result.calls, extractDirectInvocations(stmt)...)
					recordSuccessState(stmt, state)
				}
				return finalizePrefixScan(result)
			}
			stmt := strings.TrimSpace(body[pos : next+1])
			if stmt != "" {
				result.lsmHooks = append(result.lsmHooks, extractLSMHooks(stmt)...)
				result.sigChecks = append(result.sigChecks, extractSignalChecks(stmt)...)
				result.callees = append(result.callees, extractDirectCallees(stmt)...)
				result.calls = append(result.calls, extractDirectInvocations(stmt)...)
				recordSuccessState(stmt, state)
			}
			pos = next + 1
		}
	}
}

func finalizePrefixScan(result prefixScanResult) prefixScanResult {
	result.callees = filterInternalCallees(result.callees)
	result.calls = filterInvocations(result.calls, result.callees)
	result.lsmHooks = uniqueStrings(result.lsmHooks)
	result.sigChecks = uniqueStrings(result.sigChecks)
	return result
}

func appendPrefixResult(target *prefixScanResult, source prefixScanResult) {
	target.callees = append(target.callees, source.callees...)
	target.calls = append(target.calls, source.calls...)
	target.indirectCalls = append(target.indirectCalls, source.indirectCalls...)
	target.lsmHooks = append(target.lsmHooks, source.lsmHooks...)
	target.inactiveLSMHooks = append(target.inactiveLSMHooks, source.inactiveLSMHooks...)
	target.sigChecks = append(target.sigChecks, source.sigChecks...)
}

func constantConditionValue(condition string) (bool, bool) {
	condition = normalizeCondition(condition)
	if parts := splitTopLevelLogical(condition, "||"); len(parts) > 1 {
		allKnown := true
		for _, part := range parts {
			value, known := constantConditionValue(part)
			if known && value {
				return true, true
			}
			if !known {
				allKnown = false
			}
		}
		if allKnown {
			return false, true
		}
		return false, false
	}
	if parts := splitTopLevelLogical(condition, "&&"); len(parts) > 1 {
		allKnown := true
		for _, part := range parts {
			value, known := constantConditionValue(part)
			if known && !value {
				return false, true
			}
			if !known {
				allKnown = false
			}
		}
		if allKnown {
			return true, true
		}
		return false, false
	}
	if strings.HasPrefix(condition, "!") {
		value, known := constantConditionValue(strings.TrimSpace(condition[1:]))
		return !value, known
	}
	if value, known := symbolicBitmaskTruth(condition); known {
		return value, true
	}
	comparison := regexp.MustCompile(
		`^(.+?)(==|!=|<=|>=|<|>)(.+)$`,
	).FindStringSubmatch(compactExpression(condition))
	if len(comparison) == 4 {
		left, leftKnown := signedIntegerConstant(comparison[1])
		right, rightKnown := signedIntegerConstant(comparison[3])
		if leftKnown && rightKnown {
			switch comparison[2] {
			case "==":
				return left == right, true
			case "!=":
				return left != right, true
			case "<=":
				return left <= right, true
			case ">=":
				return left >= right, true
			case "<":
				return left < right, true
			case ">":
				return left > right, true
			}
		}
	}
	switch condition {
	case "true":
		return true, true
	case "false", "NULL":
		return false, true
	}
	value, err := strconv.ParseInt(condition, 0, 64)
	if err != nil {
		return false, false
	}
	return value != 0, true
}

func symbolicBitmaskTruth(expression string) (bool, bool) {
	expression = normalizeCondition(expression)
	operator := topLevelOperatorIndex(expression, '&')
	if operator < 0 {
		return false, false
	}
	leftFlags, leftUnknown, leftOK := symbolicFlagSet(expression[:operator])
	rightExpression := normalizeCondition(expression[operator+1:])
	complement := strings.HasPrefix(rightExpression, "~")
	if complement {
		rightExpression = strings.TrimSpace(rightExpression[1:])
	}
	rightFlags, rightUnknown, rightOK := symbolicFlagSet(rightExpression)
	if !leftOK || !rightOK {
		return false, false
	}
	if complement {
		for flag := range leftFlags {
			if _, excluded := rightFlags[flag]; !excluded {
				return true, true
			}
		}
		if !leftUnknown && !rightUnknown {
			return false, true
		}
		return false, false
	}
	for flag := range leftFlags {
		if _, present := rightFlags[flag]; present {
			return true, true
		}
	}
	if !leftUnknown && !rightUnknown {
		return false, true
	}
	return false, false
}

func topLevelOperatorIndex(expression string, operator byte) int {
	masked := maskStringAndCharLiterals(expression)
	parenDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		default:
			if masked[index] == operator && parenDepth == 0 {
				return index
			}
		}
	}
	return -1
}

func symbolicFlagSet(expression string) (map[string]struct{}, bool, bool) {
	expression = normalizeCondition(expression)
	parts := splitTopLevelOperator(expression, '|')
	flags := make(map[string]struct{})
	unknown := false
	for _, part := range parts {
		part = normalizeCondition(part)
		switch {
		case regexp.MustCompile(`^ATTR_[A-Z0-9_]+$`).MatchString(part):
			flags[part] = struct{}{}
		case regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(part):
			unknown = true
		case regexp.MustCompile(`^(?:0[xX][0-9A-Fa-f]+|[0-9]+)$`).MatchString(part):
			if part != "0" {
				unknown = true
			}
		case regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(part):
			unknown = true
		default:
			return nil, false, false
		}
	}
	return flags, unknown, true
}

func splitTopLevelOperator(expression string, operator byte) []string {
	masked := maskStringAndCharLiterals(expression)
	parts := make([]string, 0, 2)
	start := 0
	parenDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		default:
			if masked[index] == operator && parenDepth == 0 {
				parts = append(parts, strings.TrimSpace(expression[start:index]))
				start = index + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(expression[start:]))
	return parts
}

func constantConditionValueWithState(condition string, state *successScanState) (bool, bool) {
	condition = normalizeCondition(condition)
	if value, known := constantConditionValue(condition); known {
		return value, true
	}
	if substituted := substituteIdentifierConstants(condition, state.knownValues); substituted != condition {
		if value, known := constantConditionValue(substituted); known {
			return value, true
		}
	}
	if strings.HasPrefix(condition, "!") {
		value, known := constantConditionValueWithState(strings.TrimSpace(condition[1:]), state)
		return !value, known
	}
	if value, ok := state.knownValues[condition]; ok {
		return knownScalarTruth(value)
	}
	comparison := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=)\s*(NULL|true|false|0[xX][0-9A-Fa-f]+|[0-9]+)$`).FindStringSubmatch(condition)
	if len(comparison) != 4 {
		comparison = regexp.MustCompile(`^(NULL|true|false|0[xX][0-9A-Fa-f]+|[0-9]+)\s*(==|!=)\s*([A-Za-z_][A-Za-z0-9_]*)$`).FindStringSubmatch(condition)
		if len(comparison) == 4 {
			comparison[1], comparison[3] = comparison[3], comparison[1]
		}
	}
	if len(comparison) != 4 {
		return false, false
	}
	left, ok := state.knownValues[comparison[1]]
	if !ok {
		return false, false
	}
	equal := normalizeKnownScalar(left) == normalizeKnownScalar(comparison[3])
	if comparison[2] == "!=" {
		equal = !equal
	}
	return equal, true
}

func knownScalarTruth(value string) (bool, bool) {
	value = normalizeKnownScalar(value)
	switch value {
	case "NULL", "false", "0":
		return false, true
	case "true", "1":
		return true, true
	}
	numeric, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return false, false
	}
	return numeric != 0, true
}

func normalizeKnownScalar(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "NULL", "false", "true":
		return value
	}
	if numeric, err := strconv.ParseUint(value, 0, 64); err == nil {
		return strconv.FormatUint(numeric, 10)
	}
	return value
}

func cloneSuccessScanState(state *successScanState) *successScanState {
	cloned := &successScanState{
		returnVar:          state.returnVar,
		returnRequirement:  state.returnRequirement,
		knownError:         make(map[string]bool, len(state.knownError)),
		knownValues:        make(map[string]string, len(state.knownValues)),
		resultErrors:       make(map[string]string, len(state.resultErrors)),
		pointerErrors:      make(map[string]string, len(state.pointerErrors)),
		functionBody:       state.functionBody,
		activeScans:        state.activeScans,
		insideRequiredLoop: state.insideRequiredLoop,
		insideRequiredGate: state.insideRequiredGate,
	}
	for variable, known := range state.knownError {
		cloned.knownError[variable] = known
	}
	for variable, value := range state.knownValues {
		cloned.knownValues[variable] = value
	}
	for variable, errorVariable := range state.resultErrors {
		cloned.resultErrors[variable] = errorVariable
	}
	for pointer, errorVariable := range state.pointerErrors {
		cloned.pointerErrors[pointer] = errorVariable
	}
	return cloned
}

func mergeConditionalState(state *successScanState, condition, branchBody, elseBody string) {
	branchState := cloneSuccessScanState(state)
	applyBranchConditionFacts(condition, branchState)
	invalidateAssignedState(branchBody, branchState)
	recordBranchState(branchBody, branchState)

	fallthroughState := cloneSuccessScanState(state)
	applyBranchConditionFacts("!("+condition+")", fallthroughState)
	if elseBody != "" {
		invalidateAssignedState(elseBody, fallthroughState)
		recordBranchState(elseBody, fallthroughState)
	}

	intersectBoolFacts(state.knownError, branchState.knownError, fallthroughState.knownError)
	intersectStringFacts(state.knownValues, branchState.knownValues, fallthroughState.knownValues)
	intersectStringFacts(state.resultErrors, branchState.resultErrors, fallthroughState.resultErrors)
	intersectStringFacts(state.pointerErrors, branchState.pointerErrors, fallthroughState.pointerErrors)
}

func intersectBoolFacts(target, left, right map[string]bool) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range left {
		if value && right[key] {
			target[key] = true
		}
	}
}

func intersectStringFacts(target, left, right map[string]string) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range left {
		if right[key] == value {
			target[key] = value
		}
	}
}

func successfulGotoLabelBody(branch, condition string, state *successScanState) (string, *successScanState, bool) {
	prefix, label, ok := terminalDirectGoto(branch)
	if !ok || state.functionBody == "" {
		return "", nil, false
	}
	branchState := cloneSuccessScanState(state)
	recordBranchState(prefix, branchState)
	applyBranchConditionFacts(condition, branchState)

	labelPattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(label) + `\s*:`)
	location := labelPattern.FindStringIndex(state.functionBody)
	if location == nil {
		return "", nil, false
	}
	body := state.functionBody[location[1]:]
	if !bodyMayReturnSuccess(body, branchState) {
		return "", nil, false
	}
	return body, branchState, true
}

func terminalDirectGoto(branch string) (string, string, bool) {
	trimmed := strings.TrimSpace(branch)
	pattern := regexp.MustCompile(`\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$`)
	indexes := pattern.FindStringSubmatchIndex(trimmed)
	if len(indexes) != 4 {
		return "", "", false
	}

	gotoStart := indexes[0]
	maskedPrefix := maskStringAndCharLiterals(trimmed[:gotoStart])
	statementStart := 0
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	for index := 0; index < len(maskedPrefix); index++ {
		switch maskedPrefix[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				statementStart = index + 1
			}
		case ';':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				statementStart = index + 1
			}
		}
	}
	if strings.TrimSpace(maskedPrefix[statementStart:]) != "" {
		return "", "", false
	}
	return trimmed[:gotoStart], trimmed[indexes[2]:indexes[3]], true
}

func recordBranchState(body string, state *successScanState) {
	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return
		}
		next := findNextTopLevelSemicolon(body, pos)
		if next < 0 {
			return
		}
		recordSuccessState(strings.TrimSpace(body[pos:next+1]), state)
		pos = next + 1
	}
}

func applyBranchConditionFacts(condition string, state *successScanState) {
	condition = normalizeCondition(condition)
	if conditionIndicatesFailure(condition, state.returnVar) {
		state.knownError[state.returnVar] = true
	}
	for resultVariable, errorVariable := range state.resultErrors {
		if conditionIndicatesFalsyValue(condition, resultVariable) {
			state.knownError[errorVariable] = true
		}
	}
	for pointer, errorVariable := range state.pointerErrors {
		if conditionIndicatesPointerError(condition, pointer) {
			state.knownError[errorVariable] = true
		}
	}
	for variable := range state.knownValues {
		if conditionIndicatesFalsyValue(condition, variable) {
			state.knownValues[variable] = "0"
		}
		if conditionIndicatesTruthyValue(condition, variable) {
			state.knownValues[variable] = "1"
		}
	}
}

func conditionIndicatesPointerError(condition, pointer string) bool {
	quoted := regexp.QuoteMeta(pointer)
	patterns := []string{
		`^IS_ERR\s*\(\s*` + quoted + `\s*\)$`,
		`^IS_ERR_OR_NULL\s*\(\s*` + quoted + `\s*\)$`,
		`^IS_ERR_VALUE\s*\(\s*` + quoted + `\s*\)$`,
	}
	return matchesAny(condition, patterns)
}

func conditionIndicatesPointerSuccess(condition, pointer string) bool {
	quoted := regexp.QuoteMeta(pointer)
	patterns := []string{
		`^!\s*IS_ERR\s*\(\s*` + quoted + `\s*\)$`,
		`^!\s*IS_ERR_OR_NULL\s*\(\s*` + quoted + `\s*\)$`,
		`^!\s*IS_ERR_VALUE\s*\(\s*` + quoted + `\s*\)$`,
	}
	return matchesAny(condition, patterns) || conditionIndicatesTruthyValue(condition, pointer)
}

func conditionIndicatesFalsyValue(condition, variable string) bool {
	return conditionIndicatesFalsyExpression(condition, variable)
}

func conditionIndicatesFalsyExpression(condition, expression string) bool {
	condition = normalizeCondition(condition)
	quoted := regexp.QuoteMeta(strings.Join(strings.Fields(expression), ""))
	condition = strings.Join(strings.Fields(condition), "")
	patterns := []string{
		`^!\s*` + quoted + `$`,
		`^` + quoted + `\s*==\s*(?:0|NULL|false)$`,
		`^(?:0|NULL|false)\s*==\s*` + quoted + `$`,
	}
	return matchesAny(condition, patterns)
}

func conditionIndicatesTruthyValue(condition, variable string) bool {
	return conditionIndicatesTruthyExpression(condition, variable)
}

func conditionIndicatesTruthyExpression(condition, expression string) bool {
	condition = normalizeCondition(condition)
	quoted := regexp.QuoteMeta(strings.Join(strings.Fields(expression), ""))
	condition = strings.Join(strings.Fields(condition), "")
	patterns := []string{
		`^` + quoted + `$`,
		`^!!\s*` + quoted + `$`,
		`^` + quoted + `\s*!=\s*(?:0|NULL|false)$`,
		`^(?:0|NULL|false)\s*!=\s*` + quoted + `$`,
	}
	return matchesAny(condition, patterns)
}

func conditionIndicatesFailureForState(condition string, state *successScanState) bool {
	if conditionIndicatesFailure(condition, state.returnVar) {
		return true
	}
	for resultVariable, errorVariable := range state.resultErrors {
		if errorVariable == state.returnVar && conditionIndicatesFalsyValue(condition, resultVariable) {
			return true
		}
	}
	for pointer, errorVariable := range state.pointerErrors {
		if errorVariable == state.returnVar && conditionIndicatesPointerError(condition, pointer) {
			return true
		}
	}
	return false
}

func bodyMayReturnSuccess(body string, state *successScanState) bool {
	returnPattern := regexp.MustCompile(`\breturn\s+([^;]+);`)
	for _, indexes := range returnPattern.FindAllStringSubmatchIndex(body, -1) {
		expression := strings.TrimSpace(body[indexes[2]:indexes[3]])
		if returnExpressionIsFailureForState(expression, "", state) {
			continue
		}
		returnState := stateAfterFeasiblePrefix(body[:indexes[0]], state)
		if expression == returnState.returnVar && returnState.knownError[returnState.returnVar] {
			continue
		}
		return true
	}
	return false
}

func branchEndsInKnownFailure(body, condition string, state *successScanState) bool {
	branchState := cloneSuccessScanState(state)
	applyBranchConditionFacts(condition, branchState)
	branchState = stateAfterFeasiblePrefix(body, branchState)
	return branchState.returnVar != "" && branchState.knownError[branchState.returnVar]
}

func stateAfterFeasiblePrefix(body string, state *successScanState) *successScanState {
	localState := cloneSuccessScanState(state)
	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return localState
		}
		if labelEnd := leadingLabelEnd(body[pos:]); labelEnd > 0 {
			pos += labelEnd
			continue
		}
		rest := body[pos:]
		if strings.HasPrefix(rest, "if") {
			detail, ok := parseIfDetail(body, pos)
			if !ok {
				invalidateAssignedState(body[pos:], localState)
				return localState
			}
			if conditionValue, known := constantConditionValueWithState(detail.condText, localState); known {
				selected := detail.bodyText
				selectedCondition := detail.condText
				if !conditionValue {
					selected = detail.elseText
					selectedCondition = "!(" + detail.condText + ")"
				}
				applyBranchConditionFacts(selectedCondition, localState)
				localState = stateAfterFeasiblePrefix(selected, localState)
			} else {
				mergeConditionalState(localState, detail.condText, detail.bodyText, detail.elseText)
			}
			pos = detail.nextPos
			continue
		}
		next := findNextTopLevelSemicolon(body, pos)
		if next < 0 {
			invalidateAssignedState(body[pos:], localState)
			return localState
		}
		statement := strings.TrimSpace(body[pos : next+1])
		recordSuccessState(statement, localState)
		pos = next + 1
	}
}

func copySuccessScanFacts(target, source *successScanState) {
	copyBoolFacts(target.knownError, source.knownError)
	copyStringFacts(target.knownValues, source.knownValues)
	copyStringFacts(target.resultErrors, source.resultErrors)
	copyStringFacts(target.pointerErrors, source.pointerErrors)
}

func copyBoolFacts(target, source map[string]bool) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range source {
		target[key] = value
	}
}

func copyStringFacts(target, source map[string]string) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range source {
		target[key] = value
	}
}

func intersectPrefixScans(left, right prefixScanResult) prefixScanResult {
	return prefixScanResult{
		callees:       intersectStrings(left.callees, right.callees),
		calls:         intersectCallInvocations(left.calls, right.calls),
		indirectCalls: intersectIndirectInvocations(left.indirectCalls, right.indirectCalls),
		lsmHooks:      intersectStrings(left.lsmHooks, right.lsmHooks),
		sigChecks:     intersectStrings(left.sigChecks, right.sigChecks),
	}
}

func intersectStrings(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	result := make([]string, 0, min(len(left), len(right)))
	for _, value := range left {
		if _, ok := rightSet[value]; ok {
			result = append(result, value)
		}
	}
	return uniqueStrings(result)
}

func filterInvocations(calls []callInvocation, allowedCallees []string) []callInvocation {
	allowed := make(map[string]struct{}, len(allowedCallees))
	for _, callee := range allowedCallees {
		allowed[callee] = struct{}{}
	}
	seen := make(map[string]struct{}, len(calls))
	result := make([]callInvocation, 0, len(calls))
	for _, call := range calls {
		if _, ok := allowed[call.name]; !ok {
			continue
		}
		key := call.callSiteID
		if key == "" {
			key = call.name + "\x00" + strings.Join(call.arguments, "\x00")
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, call)
	}
	return result
}

func intersectCallInvocations(left, right []callInvocation) []callInvocation {
	rightByName := make(map[string][]callInvocation)
	for _, call := range right {
		rightByName[call.name] = append(rightByName[call.name], call)
	}
	seen := make(map[string]struct{})
	result := make([]callInvocation, 0, min(len(left), len(right)))
	for _, call := range left {
		if _, ok := seen[call.name]; ok {
			continue
		}
		matches := rightByName[call.name]
		if len(matches) == 0 {
			continue
		}
		leftSummary := summarizeInvocationArguments(call.name, left)
		rightSummary := summarizeInvocationArguments(call.name, right)
		result = append(result, callInvocation{
			name:      call.name,
			arguments: mergeInvocationArguments(leftSummary, rightSummary),
		})
		seen[call.name] = struct{}{}
	}
	return result
}

func intersectIndirectInvocations(left, right []indirectCallInvocation) []indirectCallInvocation {
	rightKeys := make(map[string]struct{}, len(right))
	for _, invocation := range right {
		rightKeys[indirectInvocationKey(invocation)] = struct{}{}
	}
	result := make([]indirectCallInvocation, 0, min(len(left), len(right)))
	for _, invocation := range left {
		if _, ok := rightKeys[indirectInvocationKey(invocation)]; ok {
			result = append(result, invocation)
		}
	}
	return uniqueIndirectInvocations(result)
}

func indirectInvocationKey(invocation indirectCallInvocation) string {
	return invocation.expression + "\x00" + invocation.fallback + "\x00" + strings.Join(invocation.arguments, "\x00") + "\x00" + strings.Join(invocation.explicitTargets, "\x00")
}

func summarizeInvocationArguments(name string, calls []callInvocation) []string {
	var summary []string
	found := false
	for _, call := range calls {
		if call.name != name {
			continue
		}
		if !found {
			summary = append([]string(nil), call.arguments...)
			found = true
			continue
		}
		summary = mergeInvocationArguments(summary, call.arguments)
	}
	return summary
}

func mergeInvocationArguments(left, right []string) []string {
	if len(left) != len(right) {
		return nil
	}
	result := make([]string, len(left))
	for index := range left {
		if strings.TrimSpace(left[index]) == strings.TrimSpace(right[index]) {
			result[index] = strings.TrimSpace(left[index])
		}
	}
	return result
}

func topLevelReturnVar(body string) string {
	pos := 0
	lastReturn := ""
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return lastReturn
		}
		if labelEnd := leadingLabelEnd(body[pos:]); labelEnd > 0 {
			pos += labelEnd
			continue
		}
		rest := body[pos:]
		if strings.HasPrefix(rest, "if") {
			detail, ok := parseIfDetail(body, pos)
			if !ok {
				return lastReturn
			}
			if candidate := returnedConditionVariable(detail); candidate != "" {
				lastReturn = candidate
			}
			pos = detail.nextPos
			continue
		}
		next := findNextTopLevelSemicolon(body, pos)
		if next < 0 {
			return lastReturn
		}
		stmt := strings.TrimSpace(body[pos : next+1])
		if hasKeywordPrefix(stmt, "return") {
			expr := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(stmt, "return"), ";"))
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(expr) {
				lastReturn = expr
			}
		}
		pos = next + 1
	}
}

func returnedConditionVariable(detail ifDetail) string {
	match := regexp.MustCompile(`\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$`).FindStringSubmatch(strings.TrimSpace(detail.bodyText))
	if len(match) != 2 {
		return ""
	}
	variable := match[1]
	if !regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\b`).MatchString(detail.condText) {
		return ""
	}
	return variable
}

func parseIfDetail(body string, pos int) (ifDetail, bool) {
	condStart := strings.Index(body[pos:], "(")
	if condStart < 0 {
		return ifDetail{}, false
	}
	condStart += pos
	condEnd, ok := findMatchingParenForward(body, condStart)
	if !ok {
		return ifDetail{}, false
	}
	next := skipSpace(body, condEnd+1)
	if next >= len(body) {
		return ifDetail{}, false
	}

	var stmtText, bodyText string
	var bodyStart, bodyEnd int
	var nextPos int
	bodyBrace := false

	if body[next] == '{' {
		end, ok := findMatchingBrace(body, next)
		if !ok {
			return ifDetail{}, false
		}
		stmtText = strings.TrimSpace(body[pos : end+1])
		bodyText = body[next+1 : end]
		bodyStart = next + 1
		bodyEnd = end
		nextPos = end + 1
		bodyBrace = true
	} else {
		semi := findNextTopLevelSemicolon(body, next)
		if semi < 0 {
			return ifDetail{}, false
		}
		stmtText = strings.TrimSpace(body[pos : semi+1])
		bodyText = strings.TrimSpace(body[next : semi+1])
		bodyStart = next
		bodyEnd = semi + 1
		nextPos = semi + 1
	}

	afterCond := strings.TrimSpace(body[next:nextPos])
	guard := strings.HasPrefix(afterCond, "return ") || afterCond == "return;" || strings.HasPrefix(afterCond, "goto ")
	after := skipSpace(body, nextPos)
	hasElse := hasKeywordPrefix(body[after:], "else")
	elseText := ""
	if hasElse {
		elseStart := skipSpace(body, after+len("else"))
		switch {
		case elseStart < len(body) && body[elseStart] == '{':
			end, ok := findMatchingBrace(body, elseStart)
			if !ok {
				return ifDetail{}, false
			}
			elseText = body[elseStart+1 : end]
			nextPos = end + 1
		case strings.HasPrefix(body[elseStart:], "if"):
			nested, ok := parseIfDetail(body, elseStart)
			if !ok {
				return ifDetail{}, false
			}
			elseText = body[elseStart:nested.nextPos]
			nextPos = nested.nextPos
		default:
			semi := findNextTopLevelSemicolon(body, elseStart)
			if semi < 0 {
				return ifDetail{}, false
			}
			elseText = strings.TrimSpace(body[elseStart : semi+1])
			nextPos = semi + 1
		}
		stmtText = strings.TrimSpace(body[pos:nextPos])
	}

	return ifDetail{
		start:     pos,
		stmtText:  stmtText,
		condText:  strings.TrimSpace(body[condStart+1 : condEnd]),
		bodyText:  bodyText,
		elseText:  elseText,
		bodyStart: bodyStart,
		bodyEnd:   bodyEnd,
		nextPos:   nextPos,
		guard:     guard,
		hasElse:   hasElse,
		bodyBrace: bodyBrace,
	}, true
}

func parseLoopDetail(body string, pos int) (loopDetail, bool) {
	keyword := ""
	for _, candidate := range []string{"for", "while", "do"} {
		if hasKeywordPrefix(body[pos:], candidate) {
			keyword = candidate
			break
		}
	}
	if keyword == "" {
		return loopDetail{}, false
	}
	if keyword == "do" {
		next := skipSpace(body, pos+len(keyword))
		bodyText, afterBody, ok := parseControlledBody(body, next)
		if !ok {
			return loopDetail{}, false
		}
		whileStart := skipSpace(body, afterBody)
		if !hasKeywordPrefix(body[whileStart:], "while") {
			return loopDetail{}, false
		}
		openOffset := strings.Index(body[whileStart:], "(")
		if openOffset < 0 {
			return loopDetail{}, false
		}
		closeParen, ok := findMatchingParenForward(body, whileStart+openOffset)
		if !ok {
			return loopDetail{}, false
		}
		nextPos := skipSpace(body, closeParen+1)
		if nextPos >= len(body) || body[nextPos] != ';' {
			return loopDetail{}, false
		}
		return loopDetail{bodyText: bodyText, nextPos: nextPos + 1, firstIterationGuaranteed: true}, true
	}

	openOffset := strings.Index(body[pos:], "(")
	if openOffset < 0 {
		return loopDetail{}, false
	}
	openParen := pos + openOffset
	closeParen, ok := findMatchingParenForward(body, openParen)
	if !ok {
		return loopDetail{}, false
	}
	condition := normalizeCondition(strings.TrimSpace(body[openParen+1 : closeParen]))
	if keyword == "for" {
		headerParts := splitTopLevelForHeader(body[openParen+1 : closeParen])
		if len(headerParts) != 3 {
			return loopDetail{}, false
		}
		condition = normalizeCondition(strings.TrimSpace(headerParts[1]))
	}
	guaranteed := condition == "" || condition == "1" || condition == "true"

	next := skipSpace(body, closeParen+1)
	bodyText, nextPos, ok := parseControlledBody(body, next)
	if !ok {
		return loopDetail{}, false
	}
	return loopDetail{
		bodyText:                 bodyText,
		nextPos:                  nextPos,
		firstIterationGuaranteed: guaranteed,
	}, true
}

func parseControlledBody(body string, start int) (string, int, bool) {
	start = skipSpace(body, start)
	if start >= len(body) {
		return "", 0, false
	}
	if body[start] == '{' {
		end, ok := findMatchingBrace(body, start)
		if !ok {
			return "", 0, false
		}
		return body[start+1 : end], end + 1, true
	}
	end := findNextTopLevelSemicolon(body, start)
	if end < 0 {
		return "", 0, false
	}
	return body[start : end+1], end + 1, true
}

func parseSwitchDetail(body string, pos int) (switchDetail, bool) {
	openOffset := strings.Index(body[pos:], "(")
	if openOffset < 0 {
		return switchDetail{}, false
	}
	closeParen, ok := findMatchingParenForward(body, pos+openOffset)
	if !ok {
		return switchDetail{}, false
	}
	next := skipSpace(body, closeParen+1)
	if next >= len(body) || body[next] != '{' {
		return switchDetail{}, false
	}
	end, ok := findMatchingBrace(body, next)
	if !ok {
		return switchDetail{}, false
	}
	return switchDetail{bodyText: body[next+1 : end], nextPos: end + 1}, true
}

func isMacroLoopStart(body string) bool {
	match := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*\(`).FindStringSubmatch(body)
	if len(match) != 2 {
		return false
	}
	name := strings.ToLower(match[1])
	return strings.Contains(name, "for_each") || strings.HasPrefix(name, "do_each_") || strings.HasPrefix(name, "while_each_")
}

func parseMacroLoopDetail(body string, pos int) (loopDetail, bool) {
	openOffset := strings.Index(body[pos:], "(")
	if openOffset < 0 {
		return loopDetail{}, false
	}
	closeParen, ok := findMatchingParenForward(body, pos+openOffset)
	if !ok {
		return loopDetail{}, false
	}
	bodyText, nextPos, ok := parseControlledBody(body, closeParen+1)
	if !ok {
		return loopDetail{}, false
	}
	return loopDetail{bodyText: bodyText, nextPos: nextPos}, true
}

func loopMayBypassFollowingSuccess(body string, state *successScanState) bool {
	if bodyMayReturnSuccess(body, cloneSuccessScanState(state)) {
		return true
	}
	gotoPattern := regexp.MustCompile(`\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;`)
	for _, match := range gotoPattern.FindAllStringSubmatch(body, -1) {
		labelPattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(match[1]) + `\s*:`)
		location := labelPattern.FindStringIndex(state.functionBody)
		if location == nil || bodyMayReturnSuccess(state.functionBody[location[1]:], cloneSuccessScanState(state)) {
			return true
		}
	}
	return false
}

func switchMayBypassFollowingSuccess(body string, state *successScanState) bool {
	casePattern := regexp.MustCompile(`(?m)^\s*(?:case\b[^:\n]*|default)\s*:`)
	locations := casePattern.FindAllStringIndex(body, -1)
	if len(locations) == 0 {
		return regexp.MustCompile(`\b(?:return|goto)\b`).MatchString(body)
	}
	for index, location := range locations {
		end := len(body)
		if index+1 < len(locations) {
			end = locations[index+1][0]
		}
		caseBody := strings.TrimSpace(body[location[1]:end])
		if switchCaseMayBypassFollowingSuccess(caseBody, state) {
			return true
		}
	}
	return false
}

func switchCaseMayBypassFollowingSuccess(body string, state *successScanState) bool {
	returnPattern := regexp.MustCompile(`\breturn\s+([^;]+);`)
	for _, indexes := range returnPattern.FindAllStringSubmatchIndex(body, -1) {
		branchState := cloneSuccessScanState(state)
		recordBranchState(body[:indexes[0]], branchState)
		expression := strings.TrimSpace(body[indexes[2]:indexes[3]])
		if returnExpressionIsFailureForState(expression, "", branchState) {
			continue
		}
		if expression == branchState.returnVar && branchState.knownError[branchState.returnVar] {
			continue
		}
		return true
	}

	prefix, label, hasGoto := terminalDirectGoto(body)
	if !hasGoto {
		return regexp.MustCompile(`\bgoto\s+[A-Za-z_][A-Za-z0-9_]*\s*;`).MatchString(body)
	}
	branchState := cloneSuccessScanState(state)
	recordBranchState(prefix, branchState)
	labelPattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(label) + `\s*:`)
	location := labelPattern.FindStringIndex(state.functionBody)
	if location == nil {
		return true
	}
	return bodyMayReturnSuccess(state.functionBody[location[1]:], branchState)
}

func splitTopLevelForHeader(header string) []string {
	masked := maskStringAndCharLiterals(header)
	parts := make([]string, 0, 3)
	start := 0
	parenDepth := 0
	bracketDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case ';':
			if parenDepth == 0 && bracketDepth == 0 {
				parts = append(parts, header[start:index])
				start = index + 1
			}
		}
	}
	parts = append(parts, header[start:])
	return parts
}

func branchExitsLoop(body string) bool {
	return regexp.MustCompile(`^(?:break|continue)\s*;$`).MatchString(strings.TrimSpace(body))
}

func recordSuccessState(stmt string, state *successScanState) {
	for variable := range state.knownValues {
		if regexp.MustCompile(`&\s*` + regexp.QuoteMeta(variable) + `\b`).MatchString(stmt) {
			delete(state.knownValues, variable)
		}
	}
	assignment := regexp.MustCompile(`(?s)^\s*(?:(?:struct|union|enum)\s+[A-Za-z_][A-Za-z0-9_]*\s+|(?:[A-Za-z_][A-Za-z0-9_]*\s+)*)(?:\*+\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*;\s*$`)
	match := assignment.FindStringSubmatch(stmt)
	if len(match) != 3 || strings.HasPrefix(strings.TrimSpace(match[2]), "=") {
		return
	}

	lhs := match[1]
	rhs := strings.TrimSpace(match[2])
	delete(state.knownError, lhs)
	delete(state.knownValues, lhs)
	delete(state.resultErrors, lhs)
	deletePointerErrorTarget(state, lhs)
	if regexp.MustCompile(`^-\s*(?:[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|[0-9]+)$`).MatchString(rhs) {
		state.knownError[lhs] = true
	}
	if regexp.MustCompile(`^(?:NULL|true|false|0[xX][0-9A-Fa-f]+|[0-9]+)$`).MatchString(rhs) {
		state.knownValues[lhs] = normalizeKnownScalar(rhs)
	} else if isSymbolicScalarExpression(rhs) {
		state.knownValues[lhs] = normalizeCondition(rhs)
	}
	if pointer := ptrErrArgument(rhs); pointer != "" {
		state.pointerErrors[pointer] = lhs
	}
	if state.returnVar != "" && regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\s*\(`).MatchString(rhs) &&
		regexp.MustCompile(`&\s*`+regexp.QuoteMeta(state.returnVar)+`\b`).MatchString(rhs) {
		state.resultErrors[lhs] = state.returnVar
	}
}

func ptrErrArgument(expression string) string {
	match := regexp.MustCompile(`^PTR_ERR\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$`).FindStringSubmatch(strings.TrimSpace(expression))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func deletePointerErrorTarget(state *successScanState, target string) {
	for pointer, errorVariable := range state.pointerErrors {
		if errorVariable == target {
			delete(state.pointerErrors, pointer)
		}
	}
}

func isSuccessGateIf(detail ifDetail, remainder string, state *successScanState) bool {
	if detail.hasElse || detail.bodyText == "" || state.returnVar == "" {
		return false
	}
	condition := normalizeCondition(detail.condText)
	if conditionIndicatesSuccess(condition, state.returnVar) {
		return true
	}
	for resultVariable, errorVariable := range state.resultErrors {
		if errorVariable == state.returnVar && conditionIndicatesTruthyValue(condition, resultVariable) {
			return true
		}
	}
	for pointer, errorVariable := range state.pointerErrors {
		if errorVariable == state.returnVar && conditionIndicatesPointerSuccess(condition, pointer) {
			return true
		}
	}
	if !state.knownError[state.returnVar] || !assignsVariable(detail.bodyText, state.returnVar) {
		return branchCanReturnSuccess(detail.bodyText, detail.condText, state) &&
			remainderReturnsFailure(remainder, state.returnVar)
	}
	return remainderPreservesReturn(remainder, state.returnVar) ||
		state.insideRequiredGate && !assignsVariable(remainder, state.returnVar)
}

func isFailureOnlyIf(detail ifDetail, state *successScanState) bool {
	body := strings.TrimSpace(detail.bodyText)
	condition := normalizeCondition(detail.condText)
	if strings.HasPrefix(body, "goto ") || strings.HasSuffix(body, ";") && strings.Contains(body, "goto ") {
		return conditionIndicatesFailureForState(condition, state) || state.knownError[state.returnVar]
	}

	returnExprs := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
	if len(returnExprs) == 0 || !branchTerminates(body) {
		return false
	}
	for _, match := range returnExprs {
		expression := strings.TrimSpace(match[1])
		if returnExpressionIsFailureForState(expression, condition, state) {
			continue
		}
		if expression == state.returnVar && conditionIndicatesFailureForState(condition, state) {
			continue
		}
		if !state.knownError[expression] {
			return false
		}
	}
	return true
}

func branchCanReturnSuccess(body, condition string, state *successScanState) bool {
	returnExprs := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatchIndex(body, -1)
	for _, indexes := range returnExprs {
		returnCondition := normalizeCondition(condition)
		if nestedCondition, ok := enclosingIfBodyCondition(body, indexes[0]); ok {
			returnCondition = nestedCondition
		}
		expression := strings.TrimSpace(body[indexes[2]:indexes[3]])
		if !returnExpressionIsFailureForState(expression, returnCondition, state) {
			return true
		}
	}
	return false
}

func enclosingIfBodyCondition(body string, position int) (string, bool) {
	for searchEnd := position; searchEnd > 0; {
		ifStart := strings.LastIndex(body[:searchEnd], "if")
		if ifStart < 0 {
			return "", false
		}
		searchEnd = ifStart
		if ifStart > 0 && isIdentChar(body[ifStart-1]) || !hasKeywordPrefix(body[ifStart:], "if") {
			continue
		}
		detail, ok := parseIfDetail(body, ifStart)
		if ok && position >= detail.bodyStart && position < detail.bodyEnd {
			return normalizeCondition(detail.condText), true
		}
	}
	return "", false
}

func returnExpressionIsFailure(expression, condition, returnVar string) bool {
	if regexp.MustCompile(`^-\s*(?:[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|[0-9]+)$`).MatchString(expression) {
		return true
	}
	if regexp.MustCompile(`^(?:PTR_ERR|ERR_PTR|ERR_CAST)\s*\(`).MatchString(expression) {
		return true
	}
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(expression) && conditionIndicatesFailure(condition, expression) {
		return true
	}
	return expression == returnVar && conditionIndicatesFailure(condition, returnVar)
}

func returnExpressionIsFailureForState(expression, condition string, state *successScanState) bool {
	expression = strings.TrimSpace(expression)
	if returnExpressionIsFailure(expression, condition, state.returnVar) {
		return true
	}
	if state.returnRequirement == "nonnull" {
		normalized := normalizeCondition(expression)
		if normalized == "NULL" || normalized == "0" {
			return true
		}
		if conditionIndicatesFalsyExpression(condition, normalized) {
			return true
		}
	}
	if expression == state.returnVar && state.knownError[state.returnVar] {
		return true
	}
	ternaryCondition, trueExpression, falseExpression, ok := splitTopLevelTernary(expression)
	if !ok {
		return false
	}
	if conditionValue, known := conditionValueWithErrorFacts(ternaryCondition, state); known {
		selected := trueExpression
		if !conditionValue {
			selected = falseExpression
		}
		return returnExpressionIsFailureForState(selected, condition, state)
	}
	return returnExpressionIsFailureForState(trueExpression, condition, state) &&
		returnExpressionIsFailureForState(falseExpression, condition, state)
}

func conditionValueWithErrorFacts(condition string, state *successScanState) (bool, bool) {
	if value, known := constantConditionValueWithState(condition, state); known {
		return value, true
	}
	condition = normalizeCondition(condition)
	if strings.HasPrefix(condition, "!") {
		value, known := conditionValueWithErrorFacts(strings.TrimSpace(condition[1:]), state)
		return !value, known
	}
	for variable, knownError := range state.knownError {
		if !knownError {
			continue
		}
		quoted := regexp.QuoteMeta(variable)
		truthy := []string{
			`^` + quoted + `$`,
			`^` + quoted + `\s*!=\s*0$`,
			`^0\s*!=\s*` + quoted + `$`,
			`^` + quoted + `\s*<\s*0$`,
			`^0\s*>\s*` + quoted + `$`,
		}
		falsy := []string{
			`^!\s*` + quoted + `$`,
			`^` + quoted + `\s*==\s*0$`,
			`^0\s*==\s*` + quoted + `$`,
			`^` + quoted + `\s*>=\s*0$`,
			`^0\s*<=\s*` + quoted + `$`,
		}
		if matchesAny(condition, truthy) {
			return true, true
		}
		if matchesAny(condition, falsy) {
			return false, true
		}
	}
	return false, false
}

func splitTopLevelTernary(expression string) (string, string, string, bool) {
	masked := maskStringAndCharLiterals(expression)
	parenDepth := 0
	bracketDepth := 0
	question := -1
	nestedQuestions := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '?':
			if parenDepth == 0 && bracketDepth == 0 {
				if question < 0 {
					question = index
				} else {
					nestedQuestions++
				}
			}
		case ':':
			if question >= 0 && parenDepth == 0 && bracketDepth == 0 {
				if nestedQuestions > 0 {
					nestedQuestions--
					continue
				}
				return strings.TrimSpace(expression[:question]), strings.TrimSpace(expression[question+1 : index]), strings.TrimSpace(expression[index+1:]), true
			}
		}
	}
	return "", "", "", false
}

func branchTerminates(body string) bool {
	trimmed := strings.TrimSpace(body)
	return regexp.MustCompile(`(?:\breturn\s+[^;]+;|\bgoto\s+[A-Za-z_][A-Za-z0-9_]*;)\s*$`).MatchString(trimmed)
}

func normalizeCondition(condition string) string {
	condition = strings.TrimSpace(condition)
	for {
		changed := false
		for _, wrapper := range []string{"likely", "unlikely"} {
			prefix := wrapper + "("
			if strings.HasPrefix(condition, prefix) {
				if end, ok := findMatchingParenForward(condition, len(wrapper)); ok && end == len(condition)-1 {
					condition = strings.TrimSpace(condition[len(prefix):end])
					changed = true
				}
			}
		}
		if len(condition) >= 2 && condition[0] == '(' {
			if end, ok := findMatchingParenForward(condition, 0); ok && end == len(condition)-1 {
				condition = strings.TrimSpace(condition[1:end])
				changed = true
			}
		}
		if !changed {
			return condition
		}
	}
}

func mandatoryConditionPrefix(condition string) string {
	parenDepth := 0
	for index := 0; index+1 < len(condition); index++ {
		switch condition[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '&', '|':
			if parenDepth == 0 && condition[index+1] == condition[index] {
				return strings.TrimSpace(condition[:index])
			}
		}
	}
	return condition
}

func conditionIndicatesSuccess(condition, returnVar string) bool {
	if returnVar == "" {
		return false
	}
	quoted := regexp.QuoteMeta(returnVar)
	patterns := []string{
		`^!\s*` + quoted + `$`,
		`^` + quoted + `\s*==\s*0$`,
		`^0\s*==\s*` + quoted + `$`,
		`^` + quoted + `\s*>=\s*0$`,
		`^0\s*<=\s*` + quoted + `$`,
	}
	return matchesAny(condition, patterns)
}

func conditionIndicatesFailure(condition, returnVar string) bool {
	if returnVar == "" {
		return false
	}
	quoted := regexp.QuoteMeta(returnVar)
	patterns := []string{
		`^` + quoted + `$`,
		`^` + quoted + `\s*!=\s*0$`,
		`^0\s*!=\s*` + quoted + `$`,
		`^` + quoted + `\s*<\s*0$`,
		`^0\s*>\s*` + quoted + `$`,
		`^IS_ERR\s*\(\s*` + quoted + `\s*\)$`,
		`^IS_ERR_OR_NULL\s*\(\s*` + quoted + `\s*\)$`,
		`^IS_ERR_VALUE\s*\(\s*` + quoted + `\s*\)$`,
	}
	return matchesAny(condition, patterns)
}

func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(value) {
			return true
		}
	}
	return false
}

func assignsVariable(body, variable string) bool {
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\s*=`)
	for _, match := range pattern.FindAllStringIndex(body, -1) {
		if match[1] >= len(body) || body[match[1]] != '=' {
			return true
		}
	}
	return false
}

func remainderPreservesReturn(remainder, returnVar string) bool {
	if returnVar == "" || !regexp.MustCompile(`\breturn\s+`+regexp.QuoteMeta(returnVar)+`\s*;`).MatchString(remainder) {
		return false
	}
	return !assignsVariable(remainder, returnVar)
}

func remainderReturnsFailure(remainder, returnVar string) bool {
	match := regexp.MustCompile(`(?s)\breturn\s+([^;]+);\s*$`).FindStringSubmatch(strings.TrimSpace(remainder))
	if len(match) != 2 {
		return false
	}
	return returnExpressionIsFailure(strings.TrimSpace(match[1]), "", returnVar)
}

func invalidateAssignedState(body string, state *successScanState) {
	assignment := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	for _, indexes := range assignment.FindAllStringSubmatchIndex(body, -1) {
		if indexes[1] < len(body) && body[indexes[1]] == '=' {
			continue
		}
		match := body[indexes[2]:indexes[3]]
		delete(state.knownError, match)
		delete(state.knownValues, match)
		delete(state.resultErrors, match)
		delete(state.pointerErrors, match)
		deletePointerErrorTarget(state, match)
	}
}

func scanTopLevelFlow(body string, allowGuardReturns bool) []flowStmt {
	var out []flowStmt
	pos := 0
	for {
		pos = skipSpace(body, pos)
		if pos >= len(body) {
			return out
		}
		rest := body[pos:]
		switch {
		case strings.HasPrefix(rest, "if"):
			stmt, next, guard, hasElse := parseIfStatement(body, pos)
			if allowGuardReturns && guard {
				out = append(out, flowStmt{kind: "guard", text: stmt})
				pos = next
				continue
			}
			if !hasElse {
				pos = next
				continue
			}
			return out
		case hasKeywordPrefix(rest, "return"):
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				return out
			}
			stmt := strings.TrimSpace(body[pos : next+1])
			if strings.Contains(stmt, "(") {
				out = append(out, flowStmt{kind: "normal", text: stmt})
			}
			return out
		case hasKeywordPrefix(rest, "goto"), hasKeywordPrefix(rest, "switch"),
			hasKeywordPrefix(rest, "for"), hasKeywordPrefix(rest, "while"), hasKeywordPrefix(rest, "do"),
			hasKeywordPrefix(rest, "case"), hasKeywordPrefix(rest, "default"):
			return out
		default:
			next := findNextTopLevelSemicolon(body, pos)
			if next < 0 {
				stmt := strings.TrimSpace(body[pos:])
				if stmt != "" {
					out = append(out, flowStmt{kind: "normal", text: stmt})
				}
				return out
			}
			stmt := strings.TrimSpace(body[pos : next+1])
			if stmt != "" {
				out = append(out, flowStmt{kind: "normal", text: stmt})
			}
			pos = next + 1
		}
	}
}

func parseIfStatement(body string, pos int) (string, int, bool, bool) {
	condStart := strings.Index(body[pos:], "(")
	if condStart < 0 {
		return strings.TrimSpace(body[pos:]), len(body), false, false
	}
	condStart += pos
	condEnd, ok := findMatchingParenForward(body, condStart)
	if !ok {
		return strings.TrimSpace(body[pos:]), len(body), false, false
	}
	next := skipSpace(body, condEnd+1)
	if next >= len(body) {
		return strings.TrimSpace(body[pos:]), len(body), false, false
	}
	if body[next] == '{' {
		end, ok := findMatchingBrace(body, next)
		if !ok {
			return strings.TrimSpace(body[pos:]), len(body), false, false
		}
		stmt := strings.TrimSpace(body[pos : end+1])
		after := skipSpace(body, end+1)
		return stmt, end + 1, false, strings.HasPrefix(body[after:], "else")
	}
	semi := findNextTopLevelSemicolon(body, next)
	if semi < 0 {
		return strings.TrimSpace(body[pos:]), len(body), false, false
	}
	stmt := strings.TrimSpace(body[pos : semi+1])
	afterCond := strings.TrimSpace(body[next : semi+1])
	guard := strings.HasPrefix(afterCond, "return ") || afterCond == "return;" || strings.HasPrefix(afterCond, "goto ")
	after := skipSpace(body, semi+1)
	return stmt, semi + 1, guard, strings.HasPrefix(body[after:], "else")
}

func hasKeywordPrefix(text, keyword string) bool {
	if !strings.HasPrefix(text, keyword) {
		return false
	}
	if len(text) == len(keyword) {
		return true
	}
	next := text[len(keyword)]
	return unicode.IsSpace(rune(next)) || next == '(' || next == ':'
}

func skipSpace(text string, pos int) int {
	for pos < len(text) && unicode.IsSpace(rune(text[pos])) {
		pos++
	}
	return pos
}

func findMatchingParenForward(src string, openParen int) (int, bool) {
	depth := 0
	for i := openParen; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func findNextTopLevelSemicolon(src string, start int) int {
	parenDepth := 0
	braceDepth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ';':
			if parenDepth == 0 && braceDepth == 0 {
				return i
			}
		}
	}
	return -1
}

func filterInternalCallees(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "security_") {
			continue
		}
		out = append(out, value)
	}
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	set := orderedSet(nil)
	set.addAll(values)
	return set.slice()
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func subtractPreserve(base, remove []string) []string {
	rm := make(map[string]struct{}, len(remove))
	for _, item := range remove {
		rm[item] = struct{}{}
	}
	out := make([]string, 0, len(base))
	for _, item := range base {
		if _, ok := rm[item]; ok {
			continue
		}
		out = append(out, item)
	}
	return out
}

func classifyReachability(reachable, always []string) string {
	switch {
	case len(reachable) == 0:
		return "none"
	case len(always) == len(reachable):
		return "always"
	case len(always) > 0:
		return "mixed"
	default:
		return "conditional"
	}
}

func classifyMandatoryReachability(reachable, mandatory []string) string {
	switch {
	case len(mandatory) > 0:
		return "always"
	case len(reachable) > 0:
		return "conditional"
	default:
		return "none"
	}
}

func buildAlwaysReport(reports []SyscallReport, lsm bool) string {
	var b strings.Builder
	for _, report := range reports {
		var hooks []string
		var label string
		if lsm {
			hooks = report.AlwaysLSMHooks
			label = report.LSMReachability
		} else {
			hooks = report.AlwaysSigChecks
			label = report.SignalReachability
		}
		if len(hooks) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s [%s]: %s\n", report.Name, label, strings.Join(hooks, ", "))
	}
	return b.String()
}

func buildSyscallAvailabilityReport(reports []SyscallReport) string {
	groups := make(map[string][]SyscallReport)
	labels := make([]string, 0)
	for _, report := range reports {
		label := report.Availability
		if label == "" {
			label = syscallAvailabilityUnverified
		}
		if _, ok := groups[label]; !ok {
			labels = append(labels, label)
		}
		groups[label] = append(groups[label], report)
	}
	sort.Strings(labels)
	var builder strings.Builder
	for _, label := range labels {
		items := groups[label]
		sort.Slice(items, func(left, right int) bool {
			return items[left].Number < items[right].Number
		})
		fmt.Fprintf(&builder, "[%s] count=%d\n", label, len(items))
		for _, report := range items {
			fmt.Fprintf(
				&builder,
				"%d %s %s entry=%s",
				report.Number,
				report.ABI,
				report.Name,
				report.Entry,
			)
			if report.LinkedSymbol != "" {
				fmt.Fprintf(
					&builder,
					" linked=%s(%s)",
					report.LinkedSymbol,
					report.LinkedSymbolType,
				)
			}
			if report.AvailabilityReason != "" {
				fmt.Fprintf(&builder, " reason=%s", report.AvailabilityReason)
			}
			builder.WriteByte('\n')
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func buildSignalCheckPathReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		for _, path := range report.SignalCheckPaths {
			fmt.Fprintf(&builder, "%s: %s [category=%s,relevance=%s,subject=%s,traversal=%s,abort=%s,blocks=%s,terminates=%s,errno=%s,encoding=%s] path=%s",
				report.Name, path.Check, path.Category, path.SIGKILLRelevance, path.Subject, path.Traversal,
				path.AbortEffect, path.BlocksOperation, path.TerminatesSyscall, path.ErrnoPropagation,
				path.FailureEncoding,
				strings.Join(path.ProofPath, " -> "))
			if path.CallSiteID != "" {
				fmt.Fprintf(&builder, " [callsite=%s]", path.CallSiteID)
			}
			for _, edge := range path.IndirectEdges {
				fmt.Fprintf(&builder, " [indirect=%s:%s=>%s,kind=%s", edge.Caller, edge.Expression, edge.Target, edge.Kind)
				if edge.TableType != "" {
					fmt.Fprintf(&builder, ",table_type=%s,field=%s", edge.TableType, edge.Field)
				}
				if len(edge.Tables) > 0 {
					fmt.Fprintf(&builder, ",tables=%s", strings.Join(edge.Tables, ","))
				}
				builder.WriteByte(']')
			}
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func buildIndirectResolutionReport(functions map[string]*FunctionInfo) string {
	items := make([]*FunctionInfo, 0, len(functions))
	for _, function := range functions {
		if len(function.ResolvedIndirectCalls) > 0 {
			items = append(items, function)
		}
	}
	sort.Slice(items, func(left, right int) bool {
		return items[left].DisplayName < items[right].DisplayName
	})
	var builder strings.Builder
	for _, function := range items {
		for _, resolution := range function.ResolvedIndirectCalls {
			fmt.Fprintf(&builder, "%s: %s [kind=%s", function.DisplayName, resolution.Expression, resolution.Kind)
			if resolution.TableType != "" {
				fmt.Fprintf(&builder, ",table_type=%s,field=%s", resolution.TableType, resolution.Field)
			}
			if len(resolution.Tables) > 0 {
				fmt.Fprintf(&builder, ",tables=%s", strings.Join(resolution.Tables, ","))
			}
			if resolution.TargetSetClosed {
				fmt.Fprintf(&builder, ",target_set=closed")
			}
			fmt.Fprintf(&builder, "] targets=%s\n", strings.Join(resolution.Targets, ","))
		}
	}
	return builder.String()
}

func buildMustPassReport(reports []SyscallReport) string {
	var b strings.Builder
	for _, report := range reports {
		if len(report.MustPassLSMHooks) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", report.Name, strings.Join(report.MustPassLSMHooks, ", "))
	}
	return b.String()
}

func buildEffectiveLSMReport(reports []SyscallReport) string {
	var b strings.Builder
	for _, report := range reports {
		for _, effect := range report.LSMErrorEffects {
			if !containsString(report.EffectiveLSMHooks, effect.Hook) {
				continue
			}
			fmt.Fprintf(&b, "%s: %s [kind=%s, blocks=%s, terminates=%s, errno=%s, encoding=%s",
				report.Name, effect.Hook, effect.HookKind, effect.BlocksOperation, effect.TerminatesSyscall, effect.ErrnoPropagation, effect.FailureEncoding)
			if len(effect.OverwriteSites) > 0 {
				fmt.Fprintf(&b, ", overwrite_sites=%s", strings.Join(effect.OverwriteSites, ","))
			}
			fmt.Fprintf(&b, "] path=%s\n", strings.Join(effect.ProofPath, " -> "))
		}
	}
	return b.String()
}

func buildCertifiedBPFLSMReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		if report.LSMClassification != "certified_bpf_lsm_enforceable" {
			continue
		}
		fmt.Fprintf(
			&builder,
			"%s: bpf_hooks=%s wrappers=%s\n",
			report.Name,
			strings.Join(report.CertifiedBPFLSMHooks, ","),
			strings.Join(report.CertifiedLSMHooks, ","),
		)
	}
	return builder.String()
}

func buildClassificationCounts(reports []SyscallReport) map[string]any {
	lsm := make(map[string]int)
	sigkill := make(map[string]int)
	lsmStates := make(map[string]int)
	sigkillStates := make(map[string]int)
	applicable := 0
	unavailable := 0
	for _, report := range reports {
		lsm[report.LSMClassification]++
		sigkill[report.SIGKILLClassification]++
		lsmStates[report.LSMEnforcementState]++
		sigkillStates[report.SIGKILLEnforcementState]++
		if report.LSMClassification == "not_applicable_unavailable" &&
			report.SIGKILLClassification == "not_applicable_unavailable" {
			unavailable++
		} else {
			applicable++
		}
	}
	return map[string]any{
		"total_syscall_table_entries": len(reports),
		"applicable_syscalls":         applicable,
		"unavailable_syscalls":        unavailable,
		"lsm":                         lsm,
		"sigkill":                     sigkill,
		"lsm_enforcement_states":      lsmStates,
		"sigkill_enforcement_states":  sigkillStates,
	}
}

func buildLSMPathCoverageReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		fmt.Fprintf(
			&builder,
			"%s: state=%s status=%s",
			report.Name,
			report.LSMEnforcementState,
			report.LSMPathCoverage.Status,
		)
		if len(report.LSMPathCoverage.ProofMethods) > 0 {
			fmt.Fprintf(&builder, " methods=%s", strings.Join(report.LSMPathCoverage.ProofMethods, ","))
		}
		if len(report.LSMPathCoverage.Hooks) > 0 {
			fmt.Fprintf(&builder, " hook_set=%s", strings.Join(report.LSMPathCoverage.Hooks, ","))
		}
		for index, hookSet := range report.LSMPathCoverage.SuccessPathHookSets {
			fmt.Fprintf(&builder, " success_path[%d]=%s", index+1, strings.Join(hookSet, "|"))
		}
		if len(report.LSMPathCoverage.ProofFunctions) > 0 {
			fmt.Fprintf(&builder, " proof_functions=%s", strings.Join(report.LSMPathCoverage.ProofFunctions, ","))
		}
		for _, hook := range report.LSMPathCoverage.Hooks {
			if path := report.LSMPathCoverage.HookProofPaths[hook]; len(path) > 0 {
				fmt.Fprintf(&builder, " proof[%s]=%s", hook, strings.Join(path, " -> "))
			}
		}
		if len(report.LSMPathCoverage.BypassProofPath) > 0 {
			fmt.Fprintf(
				&builder,
				" bypass=%s",
				strings.Join(report.LSMPathCoverage.BypassProofPath, " -> "),
			)
			if report.LSMPathCoverage.BypassProofMethod != "" {
				fmt.Fprintf(
					&builder,
					" bypass_method=%s",
					report.LSMPathCoverage.BypassProofMethod,
				)
			}
		}
		if len(report.LSMPathCoverage.UnprovenBypassPath) > 0 {
			fmt.Fprintf(
				&builder,
				" unproven_bypass=%s",
				strings.Join(
					report.LSMPathCoverage.UnprovenBypassPath,
					" -> ",
				),
			)
		}
		if len(report.LSMPathCoverage.Reasons) > 0 {
			fmt.Fprintf(&builder, " reasons=%s", strings.Join(report.LSMPathCoverage.Reasons, "; "))
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func buildSIGKILLPathCoverageReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		fmt.Fprintf(
			&builder,
			"%s: state=%s status=%s",
			report.Name,
			report.SIGKILLEnforcementState,
			report.SIGKILLPathCoverage.Status,
		)
		if len(report.SIGKILLPathCoverage.ProofMethods) > 0 {
			fmt.Fprintf(
				&builder,
				" methods=%s",
				strings.Join(report.SIGKILLPathCoverage.ProofMethods, ","),
			)
		}
		if len(report.SIGKILLPathCoverage.Checks) > 0 {
			fmt.Fprintf(
				&builder,
				" checks=%s",
				strings.Join(report.SIGKILLPathCoverage.Checks, ","),
			)
		}
		for index, checkSet := range report.SIGKILLPathCoverage.SuccessPathCheckSets {
			fmt.Fprintf(
				&builder,
				" success_path[%d]=%s",
				index+1,
				strings.Join(checkSet, "|"),
			)
		}
		for _, check := range report.SIGKILLPathCoverage.Checks {
			if path := report.SIGKILLPathCoverage.CheckProofPaths[check]; len(path) > 0 {
				fmt.Fprintf(
					&builder,
					" proof[%s]=%s",
					check,
					strings.Join(path, " -> "),
				)
			}
		}
		if len(report.SIGKILLPathCoverage.BypassProofPath) > 0 {
			fmt.Fprintf(
				&builder,
				" bypass=%s",
				strings.Join(report.SIGKILLPathCoverage.BypassProofPath, " -> "),
			)
			if report.SIGKILLPathCoverage.BypassProofMethod != "" {
				fmt.Fprintf(
					&builder,
					" bypass_method=%s",
					report.SIGKILLPathCoverage.BypassProofMethod,
				)
			}
		}
		if len(report.SIGKILLPathCoverage.UnprovenBypassPath) > 0 {
			fmt.Fprintf(
				&builder,
				" unproven_bypass=%s",
				strings.Join(
					report.SIGKILLPathCoverage.UnprovenBypassPath,
					" -> ",
				),
			)
		}
		if len(report.SIGKILLPathCoverage.Reasons) > 0 {
			fmt.Fprintf(
				&builder,
				" reasons=%s",
				strings.Join(report.SIGKILLPathCoverage.Reasons, "; "),
			)
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func buildInactiveLSMReport(reports []SyscallReport) string {
	var b strings.Builder
	for _, report := range reports {
		if len(report.InactiveLSMHooks) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", report.Name, strings.Join(report.InactiveLSMHooks, ", "))
	}
	return b.String()
}

func buildUnprovenLSMReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		for _, candidate := range report.UnprovenLSMCandidates {
			fmt.Fprintf(&builder, "%s: %s [function=%s, kind=%s] %s\n",
				report.Name, candidate.Hook, candidate.Function, candidate.HookKind, candidate.Reason)
		}
	}
	return builder.String()
}

func buildClassificationReport(reports []SyscallReport, lsm bool) string {
	groups := make(map[string][]SyscallReport)
	labels := make([]string, 0)
	for _, report := range reports {
		label := report.SIGKILLClassification
		if lsm {
			label = report.LSMClassification
		}
		if _, ok := groups[label]; !ok {
			labels = append(labels, label)
		}
		groups[label] = append(groups[label], report)
	}
	sort.Strings(labels)
	var builder strings.Builder
	for _, label := range labels {
		items := groups[label]
		fmt.Fprintf(&builder, "[%s] count=%d\n", label, len(items))
		for _, report := range items {
			reasons := report.NegativeReasons.SIGKILL
			evidence := effectiveSignalEvidence(report)
			state := report.SIGKILLEnforcementState
			if lsm {
				reasons = report.NegativeReasons.LSM
				evidence = report.LSMPathCoverage.Hooks
				state = report.LSMEnforcementState
			}
			fmt.Fprintf(&builder, "%s state=%s", report.Name, state)
			if len(evidence) > 0 {
				fmt.Fprintf(&builder, " evidence=%s", strings.Join(evidence, ","))
			}
			if len(reasons) > 0 {
				fmt.Fprintf(&builder, " reasons=%s", strings.Join(reasons, "; "))
			}
			builder.WriteByte('\n')
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func effectiveSignalEvidence(report SyscallReport) []string {
	result := orderedSet(report.SIGKILLPathCoverage.Checks)
	for _, path := range report.SignalCheckPaths {
		if path.Subject == "current-task" &&
			path.SIGKILLRelevance == signalSIGKILLRelevant &&
			path.AbortEffect == "guaranteed" &&
			indirectEvidenceClosed(path.IndirectEdges) {
			result.add(path.Check)
		}
	}
	return result.slice()
}

func buildProofGapReport(reports []SyscallReport) string {
	var builder strings.Builder
	for _, report := range reports {
		for _, gap := range report.UnresolvedProofEdges {
			gap = classifyUnresolvedProofEdge(gap)
			fmt.Fprintf(
				&builder,
				"%s [%s] %s category=%s scope=%s caller=%s",
				report.Name,
				gap.Domain,
				gap.Kind,
				gap.Category,
				gap.ResolutionScope,
				gap.Caller,
			)
			if gap.Symbol != "" {
				fmt.Fprintf(&builder, " symbol=%s", gap.Symbol)
			}
			if gap.Expression != "" {
				fmt.Fprintf(&builder, " expression=%s", gap.Expression)
			}
			fmt.Fprintf(&builder, " detail=%s", gap.Detail)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

type ProofGapCategoryCounts struct {
	EdgeCounts    map[string]map[string]int `json:"edge_counts"`
	SyscallCounts map[string]map[string]int `json:"syscall_counts"`
}

func buildProofGapCategoryCounts(
	reports []SyscallReport,
) ProofGapCategoryCounts {
	result := ProofGapCategoryCounts{
		EdgeCounts:    make(map[string]map[string]int),
		SyscallCounts: make(map[string]map[string]int),
	}
	for _, report := range reports {
		seen := make(map[string]map[string]bool)
		for _, gap := range report.UnresolvedProofEdges {
			gap = classifyUnresolvedProofEdge(gap)
			domain := gap.Domain
			if domain == "" {
				domain = "unknown"
			}
			if result.EdgeCounts[domain] == nil {
				result.EdgeCounts[domain] = make(map[string]int)
			}
			if result.SyscallCounts[domain] == nil {
				result.SyscallCounts[domain] = make(map[string]int)
			}
			result.EdgeCounts[domain][gap.Category]++
			if seen[domain] == nil {
				seen[domain] = make(map[string]bool)
			}
			if !seen[domain][gap.Category] {
				result.SyscallCounts[domain][gap.Category]++
				seen[domain][gap.Category] = true
			}
		}
	}
	return result
}

func strongSignalChecks(values []string) []string {
	strong := map[string]struct{}{
		"fatal_signal_pending":   {},
		"signal_pending":         {},
		"__fatal_signal_pending": {},
		"task_sigpending":        {},
		"signal_group_exit":      {},
		"signal_pending_state":   {},
		"SIGNAL_GROUP_EXIT":      {},
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := strong[value]; ok {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func categorizeSignalChecks(values []string) SignalCheckCategories {
	categories := SignalCheckCategories{
		GroupExit:      []string{},
		FatalPending:   []string{},
		GenericPending: []string{},
	}
	for _, value := range uniqueStrings(values) {
		switch value {
		case "signal_group_exit", "SIGNAL_GROUP_EXIT":
			categories.GroupExit = append(categories.GroupExit, value)
		case "fatal_signal_pending", "__fatal_signal_pending":
			categories.FatalPending = append(categories.FatalPending, value)
		case "signal_pending", "task_sigpending", "signal_pending_state":
			categories.GenericPending = append(categories.GenericPending, value)
		}
	}
	return categories
}

func signalCheckCategory(value string) string {
	switch value {
	case "signal_group_exit", "SIGNAL_GROUP_EXIT":
		return "group-exit"
	case "fatal_signal_pending", "__fatal_signal_pending":
		return "fatal-pending"
	case "signal_pending", "task_sigpending", "signal_pending_state":
		return "generic-pending"
	default:
		return "unknown"
	}
}

func cloneIndirectEvidence(values []IndirectCallEvidence) []IndirectCallEvidence {
	cloned := make([]IndirectCallEvidence, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].Tables = append([]string(nil), value.Tables...)
	}
	return cloned
}

func cloneOperationContext(context map[string][]string) map[string][]string {
	if len(context) == 0 {
		return nil
	}
	cloned := make(map[string][]string, len(context))
	for structType, tables := range context {
		cloned[structType] = append([]string(nil), tables...)
	}
	return cloned
}

func extendOperationContext(context map[string][]string, evidence IndirectCallEvidence) map[string][]string {
	extended := cloneOperationContext(context)
	if evidence.TableType == "" || len(evidence.Tables) == 0 {
		return extended
	}
	if extended == nil {
		extended = make(map[string][]string)
	}
	extended[evidence.TableType] = uniqueStrings(evidence.Tables)
	return extended
}

func operationContextKey(context map[string][]string) string {
	if len(context) == 0 {
		return ""
	}
	types := make([]string, 0, len(context))
	for structType := range context {
		types = append(types, structType)
	}
	sort.Strings(types)
	var builder strings.Builder
	for _, structType := range types {
		tables := append([]string(nil), context[structType]...)
		sort.Strings(tables)
		builder.WriteString("\x01")
		builder.WriteString(structType)
		builder.WriteString("=")
		builder.WriteString(strings.Join(tables, ","))
	}
	return builder.String()
}

func (a *Analyzer) effectiveOperationConstraints(context map[string][]string) map[string][]string {
	if len(context) == 0 {
		return nil
	}
	constraints := make(map[string][]string)
	for sourceType, tables := range context {
		linkedSet := make(map[string]struct{})
		for _, table := range tables {
			for _, linked := range a.operationLinks[table] {
				linkedSet[linked] = struct{}{}
			}
		}
		if len(linkedSet) == 0 {
			continue
		}
		linked := make([]string, 0, len(linkedSet))
		for table := range linkedSet {
			linked = append(linked, table)
		}
		sort.Strings(linked)
		constraints[sourceType] = linked
	}
	if len(constraints) == 0 {
		return nil
	}
	return constraints
}

func operationConstraintsKey(constraints map[string][]string) string {
	if len(constraints) == 0 {
		return ""
	}
	types := make([]string, 0, len(constraints))
	for structType := range constraints {
		types = append(types, structType)
	}
	sort.Strings(types)
	var builder strings.Builder
	for _, structType := range types {
		builder.WriteByte('\x01')
		builder.WriteString(structType)
		builder.WriteByte('=')
		builder.WriteString(strings.Join(constraints[structType], ","))
	}
	return builder.String()
}

func (a *Analyzer) admitSignalState(
	index map[string][]signalDominanceState,
	functionID string,
	constants map[string]string,
	operationContext map[string][]string,
	stats *SignalTraversalStats,
) bool {
	candidate := signalDominanceState{
		constants:            cloneStringMap(constants),
		operationConstraints: a.effectiveOperationConstraints(operationContext),
	}
	states := index[functionID]
	for _, existing := range states {
		if signalStateDominates(existing, candidate) {
			stats.DominanceSkips++
			return false
		}
	}
	kept := states[:0]
	for _, existing := range states {
		if signalStateDominates(candidate, existing) {
			stats.DominatedStates++
			continue
		}
		kept = append(kept, existing)
	}
	index[functionID] = append(kept, candidate)
	stats.VisitedStates++
	return true
}

func signalStateDominates(broad, narrow signalDominanceState) bool {
	return constantsDominate(broad.constants, narrow.constants) &&
		operationConstraintsDominate(broad.operationConstraints, narrow.operationConstraints)
}

func constantsDominate(broad, narrow map[string]string) bool {
	if len(broad) > len(narrow) {
		return false
	}
	for key, value := range broad {
		if narrow[key] != value {
			return false
		}
	}
	return true
}

func operationConstraintsDominate(broad, narrow map[string][]string) bool {
	for structType, broadTables := range broad {
		narrowTables, ok := narrow[structType]
		if !ok || !stringSetContainsAll(broadTables, narrowTables) {
			return false
		}
	}
	return true
}

func stringSetContainsAll(superset, subset []string) bool {
	if len(superset) < len(subset) {
		return false
	}
	values := make(map[string]struct{}, len(superset))
	for _, value := range superset {
		values[value] = struct{}{}
	}
	for _, value := range subset {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}

func (a *Analyzer) linkedOperationTables(context map[string][]string, targetType string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for sourceType, tables := range context {
		if sourceType == targetType {
			continue
		}
		for _, table := range tables {
			for _, linked := range a.operationLinks[table] {
				allowed[linked] = struct{}{}
			}
		}
	}
	return allowed
}

type orderedStringSet struct {
	index map[string]struct{}
	items []string
}

func orderedSet(initial []string) *orderedStringSet {
	set := &orderedStringSet{
		index: make(map[string]struct{}),
		items: make([]string, 0),
	}
	set.addAll(initial)
	return set
}

func (s *orderedStringSet) add(value string) {
	if value == "" {
		return
	}
	if _, exists := s.index[value]; exists {
		return
	}
	s.index[value] = struct{}{}
	s.items = append(s.items, value)
}

func (s *orderedStringSet) addAll(values []string) {
	for _, value := range values {
		s.add(value)
	}
}

func (s *orderedStringSet) slice() []string {
	out := make([]string, len(s.items))
	copy(out, s.items)
	return out
}
