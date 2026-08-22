//go:build amd64

package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestProcessStateMapMigrationDecision(t *testing.T) {
	for _, test := range []struct {
		valueSize uint32
		want      bool
	}{
		{valueSize: 28, want: false},
		{valueSize: 32, want: true},
		{valueSize: 0, want: true},
	} {
		if got := processStateMapNeedsMigration(test.valueSize); got != test.want {
			t.Errorf("value size %d: got migration=%v, want %v", test.valueSize, got, test.want)
		}
	}
}

func TestCollectionGraphMapMigrationDecision(t *testing.T) {
	if !collectionGraphMapNeedsMigration(0) {
		t.Fatal("preallocated collection graph map was not selected for migration")
	}
	if collectionGraphMapNeedsMigration(uint32(unix.BPF_F_NO_PREALLOC)) {
		t.Fatal("NO_PREALLOC collection graph map was selected for migration")
	}
}

func TestLegacyPinMigrationListIsBounded(t *testing.T) {
	wantRemoved := []string{
		"app_tids",
		"container_info_map",
		"huffman_context_map",
		"main_process_map",
		"ns_image_map",
		"policy_decision_map",
		"policy_location_transition_map",
		"syscall_stats",
		"trigger_counter_map",
	}
	for _, name := range wantRemoved {
		if !slices.Contains(legacyPinnedMapNames, name) {
			t.Errorf("legacy pin %s is not included in migration", name)
		}
	}

	wantPreserved := []string{
		"blocked_history",
		"collection_graph_map",
		"collection_mode_map",
		"execution_time_map",
		"observation_state_map",
		"observed_transition_map",
		"pid_mount_ns_map",
		"policy_config_map",
		"policy_state_rule_map",
		"policy_state_transition_map",
		"syscall_graph_map",
		"transition_check_count",
	}
	for _, name := range wantPreserved {
		if slices.Contains(legacyPinnedMapNames, name) {
			t.Errorf("current pin %s must not be removed by legacy migration", name)
		}
	}

	seen := make(map[string]struct{}, len(legacyPinnedMapNames))
	for _, name := range legacyPinnedMapNames {
		if _, exists := seen[name]; exists {
			t.Errorf("duplicate legacy pin %s", name)
		}
		seen[name] = struct{}{}
	}
}

func TestEvaluationBuildIsObservationOnly(t *testing.T) {
	if !observationMode {
		t.Fatal("observation mode must remain enabled even without an environment override")
	}
}

func TestEmbeddedBPFHasNoBlockingHelpers(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	forbidden := map[asm.BuiltinFunc]string{
		asm.FnOverrideReturn:   "bpf_override_return",
		asm.FnSendSignal:       "bpf_send_signal",
		asm.FnSendSignalThread: "bpf_send_signal_thread",
	}
	for programName, program := range spec.Programs {
		for instructionIndex := range program.Instructions {
			instruction := &program.Instructions[instructionIndex]
			if !instruction.IsBuiltinCall() {
				continue
			}
			helper := asm.BuiltinFunc(instruction.Constant)
			if helperName, blocked := forbidden[helper]; blocked {
				t.Fatalf(
					"embedded program %s instruction %d calls %s",
					programName, instructionIndex, helperName,
				)
			}
		}
	}
}

func TestEmbeddedBPFHasNoLSMPrograms(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	for programName, program := range spec.Programs {
		if program.Type == ebpf.LSM {
			t.Fatalf(
				"observation-only object must not contain BPF LSM program %s (%s)",
				programName, program.SectionName,
			)
		}
	}
}

func TestPerfEventOpenUsesPtraceObservationRoute(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	if _, exists := spec.Programs["kprobe_sys_perf_event_open"]; exists {
		t.Fatal("perf_event_open must not use its kernel-blacklisted kprobe entry")
	}
}

func TestEmbeddedBPFContainsOnlyStateMachinePolicyMaps(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	for _, required := range []string{
		"policy_config_map",
		"policy_state_rule_map",
		"policy_state_transition_map",
	} {
		if _, exists := spec.Maps[required]; !exists {
			t.Errorf("required state-machine map %s is missing", required)
		}
	}
	if got := spec.Maps["process_state_map"].ValueSize; got != 28 {
		t.Errorf("process_state_map value size is %d bytes, want 28", got)
	}

	for _, removed := range []string{
		"container_info_map",
		"events",
		"huffman_context_map",
		"huffman_stats_map",
		"main_process_map",
		"ns_image_map",
		"policy_location_transition_map",
		"policy_decision_map",
		"syscall_stats",
		"observed_misses",
	} {
		if _, exists := spec.Maps[removed]; exists {
			t.Errorf("removed evaluation-overhead map %s is still embedded", removed)
		}
	}
}

func TestEmbeddedBPFIncludesAvailabilityStabilityMaps(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	want := map[string]struct {
		keySize, valueSize, maxEntries uint32
	}{
		"observed_transition_map": {20, 4, 150000},
		"blocked_history":         {20, 4, 100000},
		"transition_check_count":  {12, 8, 128},
		"observation_state_map":   {4, 8, 10000},
	}
	for name, expected := range want {
		m, exists := spec.Maps[name]
		if !exists {
			t.Errorf("required stability map %s is missing", name)
			continue
		}
		if m.KeySize != expected.keySize || m.ValueSize != expected.valueSize ||
			m.MaxEntries != expected.maxEntries {
			t.Errorf(
				"%s ABI is key=%d value=%d max=%d, want %d/%d/%d",
				name, m.KeySize, m.ValueSize, m.MaxEntries,
				expected.keySize, expected.valueSize, expected.maxEntries,
			)
		}
	}
}

func TestEmbeddedBPFHasNoAuditCompressionPrograms(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	for name := range spec.Programs {
		if strings.HasPrefix(name, "trace_") || strings.Contains(name, "huffman") {
			t.Errorf("removed audit/compression program %s is still embedded", name)
		}
	}
}

func TestEmbeddedBPFHasOnlyThreePerCPURouteCounters(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	counters, exists := spec.Maps["route_counter_map"]
	if !exists {
		t.Fatal("route_counter_map is missing")
	}
	if counters.Type != ebpf.PerCPUArray {
		t.Fatalf("route_counter_map type is %s, want PerCPUArray", counters.Type)
	}
	if counters.KeySize != 4 || counters.ValueSize != 8 || counters.MaxEntries != 3 {
		t.Fatalf(
			"route_counter_map ABI is key=%d value=%d max=%d, want 4/8/3",
			counters.KeySize, counters.ValueSize, counters.MaxEntries,
		)
	}
}

func TestEmbeddedBPFIncludesProcessExitCleanup(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	program, exists := spec.Programs["handle_process_exit"]
	if !exists {
		t.Fatal("process-exit cleanup program is missing")
	}
	if program.SectionName != "tp/sched/sched_process_exit" {
		t.Fatalf("unexpected process-exit cleanup section %q", program.SectionName)
	}
}

func TestCollectionGraphDoesNotPreallocatePerCPUCapacity(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	collection, exists := spec.Maps["collection_graph_map"]
	if !exists {
		t.Fatal("collection_graph_map is missing")
	}
	if collection.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		t.Fatalf("collection_graph_map flags %#x do not include BPF_F_NO_PREALLOC", collection.Flags)
	}
}

func TestSeccompStopsHaveAnExplicitEntryRoute(t *testing.T) {
	source, err := os.ReadFile("monitoring.c")
	if err != nil {
		t.Fatalf("read monitoring source: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"SYGMA_PTRACE_EVENT_SECCOMP 7",
		"if (!seccomp_event && !is_syscall_entry(user_regs))",
		"if (seccomp_event && phase == PHASE_INIT)",
		"is_async_bypass_syscall(ps->current_syscall)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("explicit seccomp-entry route is missing %q", required)
		}
	}
}
