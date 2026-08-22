package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestTimelinePrestartRecordsOnlyLifecycleBoundaries(t *testing.T) {
	timelinePath := filepath.Join(t.TempDir(), "timeline.jsonl")
	t.Setenv("SYGMA_TIMELINE_PATH", timelinePath)
	t.Setenv("SYGMA_TIMELINE_MODE", "tetragon-measurement")
	t.Setenv("SYGMA_HOOK_ROLE", "timestamp-only")
	t.Setenv("SYGMA_EXPERIMENT_BACKEND", "tetragon")
	t.Setenv("SYGMA_EXPERIMENT_TRIAL_ID", "m001-tetragon")
	t.Setenv("SYGMA_EXPERIMENT_APPLICATION", "nginx")

	state := `{"ociVersion":"1.0.2","id":"container-1234567890",` +
		`"pid":4242,"annotations":{` +
		`"io.kubernetes.cri.sandbox-namespace":"sygma-gap-eval",` +
		`"io.kubernetes.cri.sandbox-name":"gap-m001-tetragon",` +
		`"io.kubernetes.cri.container-name":"probe",` +
		`"io.kubernetes.cri.sandbox-uid":"pod-uid"}}`
	if err := handleTimelinePrestart(strings.NewReader(state)); err != nil {
		t.Fatalf("timing-only prestart failed: %v", err)
	}

	data, err := os.ReadFile(timelinePath)
	if err != nil {
		t.Fatalf("read timeline: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d timeline records, want 2: %s", len(lines), data)
	}
	wantEvents := []string{"oci_prestart_enter", "oci_prestart_complete"}
	var previousBoot int64
	for index, line := range lines {
		var event HookTimelineEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode event %d: %v", index, err)
		}
		if event.SchemaVersion != hookTimelineSchemaVersion ||
			event.Event != wantEvents[index] ||
			event.Mode != "tetragon-measurement" ||
			event.HookRole != "timestamp-only" ||
			event.Backend != "tetragon" ||
			event.TrialID != "m001-tetragon" ||
			event.Application != "nginx" ||
			event.ContainerID != "container-1234567890" ||
			event.ContainerName != "probe" ||
			event.PodUID != "pod-uid" {
			t.Fatalf("unexpected event %d: %+v", index, event)
		}
		if event.BoottimeNS <= 0 || event.RealtimeNS <= 0 {
			t.Fatalf("event %d lacks clocks: %+v", index, event)
		}
		if index > 0 && event.BoottimeNS < previousBoot {
			t.Fatalf("timeline regressed: %d then %d", previousBoot, event.BoottimeNS)
		}
		previousBoot = event.BoottimeNS
	}
}

func TestPrestartFailureTimelinePreservesCause(t *testing.T) {
	timelinePath := filepath.Join(t.TempDir(), "timeline.jsonl")
	t.Setenv("SYGMA_TIMELINE_PATH", timelinePath)
	t.Setenv("SYGMA_HOOK_ROLE", "policy-and-release")
	t.Setenv("SYGMA_EXPERIMENT_BACKEND", "sygma")
	t.Setenv("SYGMA_EXPERIMENT_TRIAL_ID", "m071-sygma-a01")
	t.Setenv("SYGMA_EXPERIMENT_APPLICATION", "nginx")
	state := OCIState{ID: "container-id", Pid: 4242}

	recordHookTimelineFailure(
		"oci_prestart_abort", &state, "enforcement", "nginx", "gap-launch",
		0, 0, 0, 5, errors.New("tracer attach timeout: deadline exceeded"),
	)

	data, err := os.ReadFile(timelinePath)
	if err != nil {
		t.Fatalf("read failure timeline: %v", err)
	}
	var event HookTimelineEvent
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("decode failure timeline: %v", err)
	}
	if event.SchemaVersion != hookTimelineSchemaVersion ||
		event.Event != "oci_prestart_abort" ||
		event.Failure != "tracer attach timeout: deadline exceeded" {
		t.Fatalf("unexpected failure event: %+v", event)
	}
}

func TestTimelinePrestartRequiresExplicitMeasurementIdentity(t *testing.T) {
	t.Setenv("SYGMA_TIMELINE_PATH", filepath.Join(t.TempDir(), "timeline.jsonl"))
	t.Setenv("SYGMA_TIMELINE_MODE", "tetragon-measurement")
	t.Setenv("SYGMA_HOOK_ROLE", "")
	t.Setenv("SYGMA_EXPERIMENT_BACKEND", "tetragon")
	t.Setenv("SYGMA_EXPERIMENT_TRIAL_ID", "m001-tetragon")
	t.Setenv("SYGMA_EXPERIMENT_APPLICATION", "nginx")
	if err := handleTimelinePrestart(strings.NewReader(`{"id":"container","pid":1}`)); err == nil {
		t.Fatal("marker without explicit timestamp-only role unexpectedly succeeded")
	}
}

func TestProcessStateABIFromValueSize(t *testing.T) {
	tests := []struct {
		name      string
		valueSize uint32
		wantErr   bool
	}{
		{name: "state-machine", valueSize: 28},
		{name: "legacy", valueSize: 20, wantErr: true},
		{name: "below", valueSize: 27, wantErr: true},
		{name: "above", valueSize: 29, wantErr: true},
		{name: "old typed", valueSize: 32, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := processStateABIFromValueSize(test.valueSize)
			if test.wantErr {
				if err == nil {
					t.Fatalf("value size %d unexpectedly selected ABI %s", test.valueSize, got)
				}
				if got != processStateABIUnknown {
					t.Fatalf("unknown value size selected ABI %s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("select ABI for value size %d: %v", test.valueSize, err)
			}
			if got != processStateABIStateMachine {
				t.Fatalf("value size %d selected ABI %s", test.valueSize, got)
			}
		})
	}
}

func TestProcessStateABIFieldOffsets(t *testing.T) {
	state := ProcessState{}
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "prev_syscall", got: unsafe.Offsetof(state.PrevSyscall), want: 0},
		{name: "current_syscall", got: unsafe.Offsetof(state.CurrentSyscall), want: 4},
		{name: "image_id", got: unsafe.Offsetof(state.ImageID), want: 8},
		{name: "saved_prev_syscall", got: unsafe.Offsetof(state.SavedPrevSyscall), want: 12},
		{name: "in_signal_handler", got: unsafe.Offsetof(state.InSignalHandler), want: 16},
		{name: "policy_state", got: unsafe.Offsetof(state.PolicyState), want: 20},
		{name: "policy_initialized", got: unsafe.Offsetof(state.PolicyInitialized), want: 24},
	}
	for _, field := range offsets {
		if field.got != field.want {
			t.Errorf("%s offset is %d, want %d", field.name, field.got, field.want)
		}
	}
	if got := binary.Size(state); got != int(stateMachineProcessStateValueSize) {
		t.Fatalf("state-machine Go layout is %d bytes, want %d", got, stateMachineProcessStateValueSize)
	}
}

func TestProcessStateABIValueLayout(t *testing.T) {
	const imageID uint32 = 73
	value, err := initialProcessStateForABI(processStateABIStateMachine, imageID)
	if err != nil {
		t.Fatalf("create state-machine initial state: %v", err)
	}
	state, ok := value.(*ProcessState)
	if !ok {
		t.Fatalf("state-machine ABI returned %T", value)
	}
	if state.PrevSyscall != 500 || state.CurrentSyscall != 500 ||
		state.SavedPrevSyscall != 500 || state.ImageID != imageID ||
		state.PolicyState != 0 || state.PolicyInitialized != 0 {
		t.Fatalf("unexpected state-machine initial state: %+v", state)
	}

	decodeTarget, err := processStateDecodeTargetForABI(processStateABIStateMachine)
	if err != nil {
		t.Fatalf("create state-machine iteration target: %v", err)
	}
	if got := binary.Size(decodeTarget); got != int(stateMachineProcessStateValueSize) {
		t.Fatalf("iteration target is %d bytes, want %d", got, stateMachineProcessStateValueSize)
	}
}

func TestStateMachinePolicyJSONContract(t *testing.T) {
	const raw = `{
		"type":"state-machine",
		"stateMachine":{
			"initialState":0,
			"states":{"0":{"allowedSyscalls":[0,334,424,448]}},
			"transitions":{"0":{"0":0}}
		}
	}`

	var policy MainPolicySpec
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatalf("decode state-machine policy: %v", err)
	}
	if policy.Type != "state-machine" || policy.StateMachine == nil {
		t.Fatalf("unexpected policy: %+v", policy)
	}
	if policyTypeStateMachine != 2 {
		t.Fatalf("kernel policy ABI changed to %d, want 2", policyTypeStateMachine)
	}
	if got := policy.StateMachine.States["0"].AllowedSyscalls; len(got) != 4 {
		t.Fatalf("decoded allow-list length is %d, want 4", len(got))
	}
}

func TestParseImageMetadata(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantImage  string
		wantBinary string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "JSON record",
			raw:        `{"imageName":"nginx:1.27","binaryName":"nginx","binaryPath":"/usr/sbin/nginx"}`,
			wantImage:  "nginx:1.27",
			wantBinary: "nginx",
			wantPath:   "/usr/sbin/nginx",
		},
		{
			name:       "JSON optional path",
			raw:        `{"imageName":"redis:7","binaryName":"redis-server","binaryPath":""}`,
			wantImage:  "redis:7",
			wantBinary: "redis-server",
		},
		{
			name:       "legacy binary and absolute path",
			raw:        "nginx:/usr/sbin/nginx",
			wantBinary: "nginx",
			wantPath:   "/usr/sbin/nginx",
		},
		{
			name:       "legacy tagged image and binary",
			raw:        "registry.example:5000/library/nginx:1.27:nginx",
			wantImage:  "registry.example:5000/library/nginx:1.27",
			wantBinary: "nginx",
		},
		{name: "missing JSON binary", raw: `{"imageName":"nginx:1.27"}`, wantErr: true},
		{name: "missing JSON image", raw: `{"binaryName":"nginx"}`, wantErr: true},
		{name: "relative JSON path", raw: `{"imageName":"nginx:1.27","binaryName":"nginx","binaryPath":"usr/sbin/nginx"}`, wantErr: true},
		{name: "malformed JSON", raw: `{"imageName":`, wantErr: true},
		{name: "empty", raw: "  ", wantErr: true},
		{name: "bare binary", raw: "nginx", wantErr: true},
		{name: "missing legacy binary", raw: "nginx:", wantErr: true},
		{name: "missing legacy image", raw: ":nginx", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata, err := parseImageMetadata(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseImageMetadata(%q) = %+v, want error", test.raw, metadata)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseImageMetadata(%q): %v", test.raw, err)
			}
			if metadata.ImageName != test.wantImage ||
				metadata.BinaryName != test.wantBinary ||
				metadata.BinaryPath != test.wantPath {
				t.Fatalf(
					"parseImageMetadata(%q) = %+v, want image=%q binary=%q path=%q",
					test.raw, metadata, test.wantImage, test.wantBinary, test.wantPath,
				)
			}
		})
	}
}

func TestStablePolicyRevision(t *testing.T) {
	if err := validateStablePolicyRevision("revision-1", "revision-1"); err != nil {
		t.Fatalf("stable revision rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		before string
		after  string
	}{
		{name: "missing before", before: "", after: "revision-1"},
		{name: "missing after", before: "revision-1", after: ""},
		{name: "changed", before: "revision-1", after: "revision-2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStablePolicyRevision(test.before, test.after); err == nil {
				t.Fatal("unstable policy revision unexpectedly accepted")
			}
		})
	}
}

func TestProcessStateABIUnknownFailsClosed(t *testing.T) {
	if _, err := initialProcessStateForABI(processStateABIUnknown, 1); err == nil {
		t.Fatal("unknown ABI unexpectedly produced an initial map value")
	}
	if _, err := processStateDecodeTargetForABI(processStateABIUnknown); err == nil {
		t.Fatal("unknown ABI unexpectedly produced an iteration target")
	}
}

func writeExecutableForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func TestVerifyBinaryReplacementUsesContainerRoot(t *testing.T) {
	containerRoot := t.TempDir()
	binDir := filepath.Join(containerRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin directory: %v", err)
	}

	writeExecutableForTest(t, filepath.Join(binDir, "sh"))
	writeExecutableForTest(t, filepath.Join(binDir, "busybox.real"))
	if err := os.Symlink("busybox.real", filepath.Join(binDir, "sh.real")); err != nil {
		t.Fatalf("create .real symlink: %v", err)
	}

	if err := verifyBinaryReplacement(containerRoot, "/bin/sh"); err != nil {
		t.Fatalf("verify replacement rooted at container rootfs: %v", err)
	}
}

func TestHostPathIsConfinedToContainerRoot(t *testing.T) {
	containerRoot := t.TempDir()

	path, err := hostPathWithinContainerRoot(containerRoot, "/bin/probe")
	if err != nil {
		t.Fatalf("resolve normal container path: %v", err)
	}
	want := filepath.Join(containerRoot, "bin", "probe")
	if path != want {
		t.Fatalf("resolved %s, want %s", path, want)
	}

	path, err = hostPathWithinContainerRoot(containerRoot, "/../../etc/passwd")
	if err != nil {
		t.Fatalf("rooted traversal path should be normalized inside rootfs: %v", err)
	}
	want = filepath.Join(containerRoot, "etc", "passwd")
	if path != want {
		t.Fatalf("rooted traversal resolved %s, want %s", path, want)
	}

	outside := filepath.Join(filepath.Dir(containerRoot), "outside")
	if err := validateHostPathWithinRoot(containerRoot, outside); err == nil {
		t.Fatal("host path outside container root unexpectedly accepted")
	}
}

func TestWrapperReplacementSelectionFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name          string
		shouldReplace bool
		path          string
		wantErr       bool
	}{
		{name: "verified replacement path", shouldReplace: true, path: "/bin/probe"},
		{name: "path hijack is not installed", shouldReplace: false, path: "/bin/probe", wantErr: true},
		{name: "empty replacement path", shouldReplace: true, path: "  ", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateWrapperReplacementSelection(test.shouldReplace, test.path)
			if test.wantErr && err == nil {
				t.Fatal("unsafe wrapper selection unexpectedly succeeded")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("valid wrapper selection failed: %v", err)
			}
		})
	}
}

func TestTracerPIDFromStatus(t *testing.T) {
	pid, err := tracerPIDFromStatus([]byte("Name:\tprobe\nTracerPid:\t4321\nState:\tT\n"))
	if err != nil {
		t.Fatalf("parse tracer PID: %v", err)
	}
	if pid != 4321 {
		t.Fatalf("parsed tracer PID %d, want 4321", pid)
	}

	for _, status := range []string{
		"Name:\tprobe\n",
		"TracerPid:\tnot-a-pid\n",
		"TracerPid:\t-1\n",
		"TracerPid:\t1 extra\n",
	} {
		if _, err := tracerPIDFromStatus([]byte(status)); err == nil {
			t.Fatalf("malformed status %q unexpectedly succeeded", status)
		}
	}
}

func TestPolicyTransitionSyscallValidation(t *testing.T) {
	for _, syscallNumber := range []int{0, 204, 334, 424, 448} {
		if err := validatePolicyTransitionSyscall(syscallNumber); err != nil {
			t.Errorf("supported syscall %d rejected: %v", syscallNumber, err)
		}
	}
	for _, syscallNumber := range []int{-1, 335, 423, 449, 500} {
		if err := validatePolicyTransitionSyscall(syscallNumber); err == nil {
			t.Errorf("unsupported syscall %d accepted", syscallNumber)
		}
	}
}

func TestPolicyMaskHighSyscallRangeABI(t *testing.T) {
	mask, err := policyMask([]int{424, 448})
	if err != nil {
		t.Fatalf("encode high syscall range: %v", err)
	}

	// 424 maps to logical bit 335 and 448 maps to logical bit 359. The
	// 45-byte wire format stores logical bytes in reverse byte order.
	if got := mask.AllowedMask[3]; got != 0x80 {
		t.Errorf("syscall 424 byte is %#02x, want 0x80", got)
	}
	if got := mask.AllowedMask[0]; got != 0x80 {
		t.Errorf("syscall 448 byte is %#02x, want 0x80", got)
	}
	for index, value := range mask.AllowedMask {
		if index != 0 && index != 3 && value != 0 {
			t.Errorf("unexpected bit in mask byte %d: %#02x", index, value)
		}
	}
}

func TestPolicyMaskRejectsUnsupportedSyscalls(t *testing.T) {
	for _, syscallNumber := range []int{-1, 335, 423, 449, 500} {
		if _, err := policyMask([]int{syscallNumber}); err == nil {
			t.Errorf("unsupported syscall %d encoded successfully", syscallNumber)
		}
	}
}

func TestProcessStateABIMustMatchPolicyGeneration(t *testing.T) {
	if err := validateProcessStateABIForPolicy(
		processStateABIStateMachine, processStateABIStateMachine,
	); err != nil {
		t.Fatalf("matching state-machine ABI rejected: %v", err)
	}
	if err := validateProcessStateABIForPolicy(processStateABIUnknown, processStateABIUnknown); err == nil {
		t.Fatal("unknown state ABI unexpectedly accepted")
	}
}

func TestKillTargetForFailedPrestartUsesSIGKILL(t *testing.T) {
	originalSignalProcess := signalProcess
	t.Cleanup(func() { signalProcess = originalSignalProcess })

	var gotPID int
	var gotSignal syscall.Signal
	signalProcess = func(pid int, signal syscall.Signal) error {
		gotPID = pid
		gotSignal = signal
		return nil
	}
	if err := killTargetForFailedPrestart(1234); err != nil {
		t.Fatalf("kill failed target: %v", err)
	}
	if gotPID != 1234 || gotSignal != syscall.SIGKILL {
		t.Fatalf("signal call was pid=%d signal=%v, want pid=1234 SIGKILL", gotPID, gotSignal)
	}

	signalProcess = func(int, syscall.Signal) error { return syscall.ESRCH }
	if err := killTargetForFailedPrestart(1234); err != nil {
		t.Fatalf("already-exited target should be accepted: %v", err)
	}

	sentinel := errors.New("permission denied")
	signalProcess = func(int, syscall.Signal) error { return sentinel }
	if err := killTargetForFailedPrestart(1234); !errors.Is(err, sentinel) {
		t.Fatalf("kill error %v does not wrap sentinel", err)
	}
}

type fakePolicyDeleter struct {
	namespace   string
	podName     string
	containerID string
	closed      bool
}

func (f *fakePolicyDeleter) DeleteSYGMAPolicy(
	_ context.Context, namespace, podName, containerID string,
) error {
	f.namespace = namespace
	f.podName = podName
	f.containerID = containerID
	return nil
}

func (f *fakePolicyDeleter) Close() error {
	f.closed = true
	return nil
}

func TestPolicyDeletionCreatesClientInFreshPoststopProcess(t *testing.T) {
	originalFactory := newSYGMAPolicyDeleter
	originalCreator := policyCreator
	t.Cleanup(func() {
		newSYGMAPolicyDeleter = originalFactory
		policyCreator = originalCreator
	})
	policyCreator = nil

	bundle := t.TempDir()
	config := []byte(`{"annotations":{"io.kubernetes.pod.namespace":"eval","io.kubernetes.pod.name":"probe-pod"}}`)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), config, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fake := &fakePolicyDeleter{}
	newSYGMAPolicyDeleter = func(string) (sygmaPolicyDeleter, error) {
		return fake, nil
	}
	state := OCIState{Bundle: bundle, ID: "0123456789abcdef"}
	if err := deleteSYGMAPolicyForContainer(state); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if fake.namespace != "eval" || fake.podName != "probe-pod" {
		t.Fatalf("deleted %s/%s, want eval/probe-pod", fake.namespace, fake.podName)
	}
	if fake.containerID != "0123456789abcdef" {
		t.Fatalf("deleted container %q, want full OCI container ID", fake.containerID)
	}
	if !fake.closed {
		t.Fatal("fresh poststop policy client was not closed")
	}
}

func TestPodInfoForStateFallsBackToPoststopAnnotations(t *testing.T) {
	state := OCIState{
		Bundle: "",
		Annotations: map[string]string{
			"io.kubernetes.cri.sandbox-namespace": "eval",
			"io.kubernetes.cri.sandbox-name":      "probe-pod",
		},
	}
	namespace, podName, err := getPodInfoForState(state)
	if err != nil {
		t.Fatalf("recover pod identity from OCI state: %v", err)
	}
	if namespace != "eval" || podName != "probe-pod" {
		t.Fatalf("got %s/%s, want eval/probe-pod", namespace, podName)
	}
}

func TestPoststopPolicyDeletionMode(t *testing.T) {
	t.Setenv("SYGMA_POLICY_CR_ENABLED", "true")
	for _, test := range []struct {
		mode string
		want bool
	}{
		{mode: "enforcement", want: true},
		{mode: "", want: true},
		{mode: "  ", want: true},
		{mode: "collection", want: false},
		{mode: "tetragon-measurement", want: false},
		{mode: "future-explicit-mode", want: false},
	} {
		if got := shouldDeleteSYGMAPolicyOnPoststop(test.mode); got != test.want {
			t.Errorf("mode %q deletion=%t, want %t", test.mode, got, test.want)
		}
	}
}

func TestPolicyCRCompatibilityIsDisabledByDefault(t *testing.T) {
	t.Setenv("SYGMA_POLICY_CR_ENABLED", "")
	originalDefault := SYGMAPolicyEnabled
	SYGMAPolicyEnabled = "false"
	t.Cleanup(func() { SYGMAPolicyEnabled = originalDefault })

	if policyCRIntegrationEnabled() {
		t.Fatal("host-side SYGMAPolicy compatibility path is enabled by default")
	}
	if shouldDeleteSYGMAPolicyOnPoststop("enforcement") {
		t.Fatal("poststop would contact the Kubernetes API while compatibility is disabled")
	}
}

func TestContainerScopedPolicyName(t *testing.T) {
	first, err := policyNameForContainer(
		"API_Pod.With Invalid Characters And A Very Very Very Very Long Name",
		"containerd://0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("create policy name: %v", err)
	}
	repeated, err := policyNameForContainer(
		"API_Pod.With Invalid Characters And A Very Very Very Very Long Name",
		"containerd://0123456789abcdef",
	)
	if err != nil || repeated != first {
		t.Fatalf("policy name is not deterministic: first=%q repeated=%q err=%v", first, repeated, err)
	}
	second, err := policyNameForContainer(
		"API_Pod.With Invalid Characters And A Very Very Very Very Long Name",
		"containerd://fedcba9876543210",
	)
	if err != nil {
		t.Fatalf("create second policy name: %v", err)
	}
	if second == first {
		t.Fatalf("different containers collided on policy name %q", first)
	}
	if len(first) > 63 || first == "" || first[0] == '-' || first[len(first)-1] == '-' {
		t.Fatalf("policy name is not a bounded DNS label: %q", first)
	}
	for _, character := range first {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			t.Fatalf("policy name contains invalid character %q: %q", character, first)
		}
	}
	if _, err := policyNameForContainer("pod", " "); err == nil {
		t.Fatal("empty container ID unexpectedly produced a policy name")
	}
}

func TestEmptyMetadataPathFallsBackToConfig(t *testing.T) {
	originalLookup := lookupBinaryByImage
	t.Cleanup(func() { lookupBinaryByImage = originalLookup })
	t.Setenv("SYGMA_TARGET_BINARY", "")
	t.Setenv("SYGMA_BINARY_PATH", "")
	lookupBinaryByImage = func(string) (string, string, error) {
		return "redis-server", "", nil
	}

	bundle := t.TempDir()
	config := []byte(`{"process":{"args":["docker-entrypoint.sh","/usr/local/bin/redis-server"]}}`)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), config, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	binary, path := extractBinaryNameAndPath(OCIState{Bundle: bundle}, "redis:7")
	if binary != "redis-server" || path != "/usr/local/bin/redis-server" {
		t.Fatalf("resolved binary=%q path=%q, want redis-server config path", binary, path)
	}
}

func TestEmptyMetadataPathFallsBackToBinaryNameForPATH(t *testing.T) {
	originalLookup := lookupBinaryByImage
	t.Cleanup(func() { lookupBinaryByImage = originalLookup })
	t.Setenv("SYGMA_TARGET_BINARY", "")
	t.Setenv("SYGMA_BINARY_PATH", "")
	lookupBinaryByImage = func(string) (string, string, error) {
		return "redis-server", "", nil
	}

	binary, path := extractBinaryNameAndPath(
		OCIState{Bundle: t.TempDir()}, "redis:7",
	)
	if binary != "redis-server" || path != "redis-server" {
		t.Fatalf("resolved binary=%q path=%q, want relative PATH lookup", binary, path)
	}
}

func TestRedisPolicyKeysAreCollectedWithScan(t *testing.T) {
	var cursors []uint64
	keys, err := collectRedisKeysByScan(
		context.Background(),
		"syscall_graph:7:0:*",
		func(_ context.Context, cursor uint64, pattern string, count int64) ([]string, uint64, error) {
			cursors = append(cursors, cursor)
			if pattern != "syscall_graph:7:0:*" || count != 256 {
				t.Fatalf("unexpected SCAN args pattern=%q count=%d", pattern, count)
			}
			switch cursor {
			case 0:
				return []string{"syscall_graph:7:0:500", "syscall_graph:7:0:1"}, 19, nil
			case 19:
				return []string{"syscall_graph:7:0:1", "syscall_graph:7:0:2"}, 0, nil
			default:
				return nil, 0, fmt.Errorf("unexpected cursor %d", cursor)
			}
		},
	)
	if err != nil {
		t.Fatalf("collect SCAN pages: %v", err)
	}
	if got, want := fmt.Sprint(cursors), "[0 19]"; got != want {
		t.Fatalf("SCAN cursors=%s, want %s", got, want)
	}
	if got, want := fmt.Sprint(keys), "[syscall_graph:7:0:1 syscall_graph:7:0:2 syscall_graph:7:0:500]"; got != want {
		t.Fatalf("SCAN keys=%s, want %s", got, want)
	}
}

func TestImageNameCandidatesMatchOperatorAliases(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{image: "nginx", want: "nginx:latest"},
		{image: "docker.io/nginx", want: "nginx:latest"},
		{image: "docker.io/library/nginx:1.27", want: "nginx:1.27"},
		{image: "registry.example:5000/team/httpd", want: "registry.example:5000/team/httpd:latest"},
		{image: "registry.example:5000/team/redis:7", want: "registry.example:5000/team/redis:7"},
		{image: "registry.example/team/mysql@sha256:abc", want: "registry.example/team/mysql@sha256:abc"},
	}
	for _, test := range tests {
		if got := normalizeImageName(test.image); got != test.want {
			t.Errorf("normalizeImageName(%q) = %q, want %q", test.image, got, test.want)
		}
		candidates := generateImageNameCandidates(test.image)
		if !slices.Contains(candidates, test.want) {
			t.Errorf("generateImageNameCandidates(%q) = %#v, missing %q", test.image, candidates, test.want)
		}
		seen := make(map[string]struct{}, len(candidates))
		for _, candidate := range candidates {
			if _, duplicate := seen[candidate]; duplicate {
				t.Errorf("generateImageNameCandidates(%q) contains duplicate %q", test.image, candidate)
			}
			seen[candidate] = struct{}{}
		}
	}
}

func TestNamespacePolicyCleanupMatchingIsExact(t *testing.T) {
	const wantedPidNs uint32 = 101
	const wantedMntNs uint32 = 202
	for _, test := range []struct {
		pidNs uint32
		mntNs uint32
		want  bool
	}{
		{pidNs: wantedPidNs, mntNs: wantedMntNs, want: true},
		{pidNs: 999, mntNs: wantedMntNs, want: false},
		{pidNs: wantedPidNs, mntNs: 999, want: false},
		{pidNs: 999, mntNs: 999, want: false},
	} {
		if got := namespaceMatches(test.pidNs, test.mntNs, wantedPidNs, wantedMntNs); got != test.want {
			t.Errorf("namespace (%d,%d) match=%t, want %t", test.pidNs, test.mntNs, got, test.want)
		}
	}
}

func TestPolicyDeletionMustPrecedeDirectMapCleanup(t *testing.T) {
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "security.security.io", Resource: "sygmapolicies"},
		"probe-policy",
		errors.New("kubelet identity cannot delete custom resources"),
	)
	if policyDeletionAllowsDataPlaneCleanup(fmt.Errorf("wrapped: %w", forbidden)) {
		t.Fatal("wrapped Forbidden error must suppress direct-map cleanup")
	}
	if policyDeletionAllowsDataPlaneCleanup(errors.New("API timeout")) {
		t.Fatal("transient API failure must suppress direct-map cleanup")
	}
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: "security.security.io", Resource: "sygmapolicies"},
		"probe-policy",
	)
	if !policyDeletionAllowsDataPlaneCleanup(fmt.Errorf("wrapped: %w", notFound)) {
		t.Fatal("NotFound proves the controller cannot repopulate this CR")
	}
	if !policyDeletionAllowsDataPlaneCleanup(nil) {
		t.Fatal("successful policy deletion must permit direct-map cleanup")
	}
}
