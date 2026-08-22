package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sys/unix"
)

var DefaultRedisAddr = "localhost:6379"

var SYGMAPolicyEnabled = "false"

const tracerReadyFilePrefix = "/tmp/sygma-tracer-ready"

var signalProcess = syscall.Kill

var lookupBinaryByImage = getBinaryNameByImage

type sygmaPolicyDeleter interface {
	DeleteSYGMAPolicy(context.Context, string, string, string) error
	Close() error
}

var newSYGMAPolicyDeleter = func(redisAddr string) (sygmaPolicyDeleter, error) {
	return NewSYGMAPolicyCreator(redisAddr)
}

var policyCreator *SYGMAPolicyCreator

type SyscallGraphKey struct {
	MntNs       uint32
	PidNs       uint32
	FromSyscall uint32
	Phase       uint32
}

type SyscallGraphValue struct {
	AllowedMask [45]byte
}

type CollectionGraphKey struct {
	MntNs       uint32
	PidNs       uint32
	PrevSyscall uint32
	Phase       uint32
}

type ObservedTransitionKey struct {
	MntNs       uint32
	PidNs       uint32
	FromSyscall uint32
	ToSyscall   uint32
	Phase       uint32
}

type TransitionCheckKey struct {
	MntNs uint32
	PidNs uint32
	Phase uint32
}

type PidMountNs struct {
	MntNs uint32
	PidNs uint32
}

type ExecutionValue struct {
	Comm          [16]byte
	ExecutionTime uint32
}

type ProcessState struct {
	PrevSyscall    uint32
	CurrentSyscall uint32
	ImageID        uint32

	SavedPrevSyscall uint32
	InSignalHandler  uint32

	PolicyState       uint32
	PolicyInitialized uint32
}

type processStateMapABI uint8

const (
	processStateABIUnknown processStateMapABI = iota
	processStateABIStateMachine

	stateMachineProcessStateValueSize uint32 = 28
)

func (abi processStateMapABI) String() string {
	switch abi {
	case processStateABIStateMachine:
		return "state-machine"
	default:
		return "unknown"
	}
}

func processStateABIFromValueSize(valueSize uint32) (processStateMapABI, error) {
	switch valueSize {
	case stateMachineProcessStateValueSize:
		return processStateABIStateMachine, nil
	default:
		return processStateABIUnknown, fmt.Errorf(
			"unsupported process_state_map value size %d (expected state-machine=%d)",
			valueSize, stateMachineProcessStateValueSize,
		)
	}
}

func inspectProcessStateMapABI(stateMap *ebpf.Map) (processStateMapABI, uint32, error) {
	info, err := stateMap.Info()
	if err != nil {
		return processStateABIUnknown, 0, fmt.Errorf("inspect process_state_map: %w", err)
	}

	abi, err := processStateABIFromValueSize(info.ValueSize)
	if err != nil {
		return processStateABIUnknown, info.ValueSize, err
	}
	log.Printf("process_state_map ABI=%s value_size=%d", abi, info.ValueSize)
	return abi, info.ValueSize, nil
}

func initialProcessStateForABI(abi processStateMapABI, imageID uint32) (any, error) {
	switch abi {
	case processStateABIStateMachine:
		return &ProcessState{
			PrevSyscall:      500,
			CurrentSyscall:   500,
			ImageID:          imageID,
			SavedPrevSyscall: 500,
			InSignalHandler:  0,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported process_state_map ABI %d", abi)
	}
}

func processStateDecodeTargetForABI(abi processStateMapABI) (any, error) {
	switch abi {
	case processStateABIStateMachine:
		return &ProcessState{}, nil
	default:
		return nil, fmt.Errorf("unsupported process_state_map ABI %d", abi)
	}
}

const policyTypeStateMachine uint32 = 2

type MainPolicySpec struct {
	Type         string                  `json:"type"`
	StateMachine *StateMachinePolicySpec `json:"stateMachine,omitempty"`
}

type ImageMetadata struct {
	ImageName  string `json:"imageName"`
	BinaryName string `json:"binaryName"`
	BinaryPath string `json:"binaryPath"`
}

type StateMachineStateSpec struct {
	AllowedSyscalls []int `json:"allowedSyscalls"`
}

type StateMachinePolicySpec struct {
	InitialState uint32                           `json:"initialState"`
	States       map[string]StateMachineStateSpec `json:"states"`
	Transitions  map[string]map[string]uint32     `json:"transitions,omitempty"`
}

type PolicyConfigValue struct {
	Type         uint32
	InitialState uint32
}

type PolicyStateRuleKey struct {
	MntNs uint32
	PidNs uint32
	State uint32
}

type PolicyStateTransitionKey struct {
	MntNs   uint32
	PidNs   uint32
	State   uint32
	Syscall uint32
}

type NamespaceInfo struct {
	PidNs   uint32 `json:"pidNs"`
	MntNs   uint32 `json:"mntNs"`
	RootPID uint32 `json:"rootPid,omitempty"`
}

type OCIState struct {
	Version     string                 `json:"ociVersion"`
	ID          string                 `json:"id"`
	Status      string                 `json:"status"`
	Pid         int                    `json:"pid"`
	Bundle      string                 `json:"bundle"`
	Annotations map[string]string      `json:"annotations"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

const hookTimelineSchemaVersion = 3

type HookTimelineEvent struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	Event         string `json:"event"`
	RealtimeNS    int64  `json:"realtime_ns"`
	BoottimeNS    int64  `json:"boottime_ns"`
	ElapsedNS     int64  `json:"elapsed_ns,omitempty"`

	ContainerID      string `json:"container_id,omitempty"`
	ContainerShortID string `json:"container_short_id,omitempty"`
	HostPID          int    `json:"host_pid,omitempty"`
	Mode             string `json:"mode,omitempty"`
	HookRole         string `json:"hook_role,omitempty"`
	Backend          string `json:"backend,omitempty"`
	TrialID          string `json:"trial_id,omitempty"`
	Application      string `json:"application,omitempty"`
	Image            string `json:"image,omitempty"`
	Binary           string `json:"binary,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	PodName          string `json:"pod_name,omitempty"`
	ContainerName    string `json:"container_name,omitempty"`
	PodUID           string `json:"pod_uid,omitempty"`
	PIDNS            uint32 `json:"pid_ns,omitempty"`
	MNTNS            uint32 `json:"mnt_ns,omitempty"`
	ImageID          uint32 `json:"image_id,omitempty"`
	Failure          string `json:"failure,omitempty"`
}

type hookTimelineTimestamp struct {
	realtimeNS int64
	boottimeNS int64
}

func sampleHookTimelineTimestamp() (hookTimelineTimestamp, error) {
	timestamp := hookTimelineTimestamp{realtimeNS: time.Now().UnixNano()}
	var bootTS unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTS); err != nil {
		return hookTimelineTimestamp{}, err
	}
	timestamp.boottimeNS = bootTS.Sec*int64(time.Second) + bootTS.Nsec
	return timestamp, nil
}

func recordHookTimeline(
	event string,
	state *OCIState,
	mode, image, binary string,
	pidNs, mntNs, imageID uint32,
	elapsed time.Duration,
) {
	timestamp, err := sampleHookTimelineTimestamp()
	if err != nil {
		log.Printf("EVAL timeline clock read failed for %s: %v", event, err)
		return
	}
	recordHookTimelineAt(
		timestamp, event, state, mode, image, binary,
		pidNs, mntNs, imageID, elapsed,
	)
}

func recordHookTimelineAt(
	timestamp hookTimelineTimestamp,
	event string,
	state *OCIState,
	mode, image, binary string,
	pidNs, mntNs, imageID uint32,
	elapsed time.Duration,
) {
	recordHookTimelineAtWithFailure(
		timestamp, event, state, mode, image, binary,
		pidNs, mntNs, imageID, elapsed, "",
	)
}

func recordHookTimelineFailure(
	event string,
	state *OCIState,
	mode, image, binary string,
	pidNs, mntNs, imageID uint32,
	elapsed time.Duration,
	cause error,
) {
	timestamp, err := sampleHookTimelineTimestamp()
	if err != nil {
		log.Printf("EVAL timeline clock read failed for %s: %v", event, err)
		return
	}
	failure := "unknown prestart failure"
	if cause != nil {
		failure = cause.Error()
	}
	recordHookTimelineAtWithFailure(
		timestamp, event, state, mode, image, binary,
		pidNs, mntNs, imageID, elapsed, failure,
	)
}

func recordHookTimelineAtWithFailure(
	timestamp hookTimelineTimestamp,
	event string,
	state *OCIState,
	mode, image, binary string,
	pidNs, mntNs, imageID uint32,
	elapsed time.Duration,
	failure string,
) {
	timeline := HookTimelineEvent{
		SchemaVersion: hookTimelineSchemaVersion,
		Component:     "sygma-oci-hook",
		Event:         event,
		RealtimeNS:    timestamp.realtimeNS,
		BoottimeNS:    timestamp.boottimeNS,
		ElapsedNS:     elapsed.Nanoseconds(),
		Mode:          mode,
		HookRole:      os.Getenv("SYGMA_HOOK_ROLE"),
		Backend:       os.Getenv("SYGMA_EXPERIMENT_BACKEND"),
		TrialID:       os.Getenv("SYGMA_EXPERIMENT_TRIAL_ID"),
		Application:   os.Getenv("SYGMA_EXPERIMENT_APPLICATION"),
		Image:         image,
		Binary:        binary,
		PIDNS:         pidNs,
		MNTNS:         mntNs,
		ImageID:       imageID,
		Failure:       failure,
	}

	if state != nil {
		timeline.ContainerID = state.ID
		timeline.ContainerShortID = state.ID
		if len(timeline.ContainerShortID) > 12 {
			timeline.ContainerShortID = timeline.ContainerShortID[:12]
		}
		timeline.HostPID = state.Pid
		if state.Annotations != nil {
			timeline.Namespace = state.Annotations["io.kubernetes.cri.sandbox-namespace"]
			timeline.PodName = state.Annotations["io.kubernetes.cri.sandbox-name"]
			timeline.ContainerName = state.Annotations["io.kubernetes.cri.container-name"]
			timeline.PodUID = state.Annotations["io.kubernetes.cri.sandbox-uid"]
			if timeline.PodUID == "" {
				timeline.PodUID = state.Annotations["io.kubernetes.pod.uid"]
			}
		}
	}

	data, err := json.Marshal(timeline)
	if err != nil {
		log.Printf("EVAL timeline encode failed for %s: %v", event, err)
		return
	}
	data = append(data, '\n')

	path := os.Getenv("SYGMA_TIMELINE_PATH")
	if path == "" {
		path = "/var/log/sygma-timeline.jsonl"
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("EVAL timeline open failed for %s: %v", event, err)
		return
	}
	if _, err := file.Write(data); err != nil {
		log.Printf("EVAL timeline write failed for %s: %v", event, err)
	}
	if err := file.Close(); err != nil {
		log.Printf("EVAL timeline close failed for %s: %v", event, err)
	}
}

func main() {
	processStart := time.Now()
	entryTimestamp, entryTimestampErr := sampleHookTimelineTimestamp()
	logFile, err := os.OpenFile("/var/log/sygma-hook.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}
	log.SetPrefix("[sygma-hook] ")

	args := os.Args
	log.Printf("========================================")
	log.Printf("========== HOOK INVOKED ==========")
	log.Printf("Args: %v", args)

	if len(args) < 2 {
		log.Printf("ERROR: No hook type specified")
		os.Exit(1)
	}

	hookType := args[1]
	log.Printf("Hook type: %s", hookType)

	switch hookType {
	case "prestart":
		if err := handlePrestartAt(processStart, entryTimestamp, entryTimestampErr); err != nil {
			log.Printf("ERROR: Prestart failed: %v", err)
			os.Exit(1)
		}
	case "timeline-prestart":
		if err := handleTimelinePrestartAt(
			os.Stdin, processStart, entryTimestamp, entryTimestampErr,
		); err != nil {
			log.Printf("ERROR: Timeline prestart failed: %v", err)
			os.Exit(1)
		}
	case "poststop":
		if err := handlePoststop(); err != nil {
			log.Printf("ERROR: Poststop failed: %v", err)
			os.Exit(1)
		}
	default:
		log.Printf("Unsupported hook type: %s", hookType)
	}
}

func handleTimelinePrestart(input io.Reader) error {
	start := time.Now()
	entryTimestamp, err := sampleHookTimelineTimestamp()
	return handleTimelinePrestartAt(input, start, entryTimestamp, err)
}

func handleTimelinePrestartAt(
	input io.Reader,
	start time.Time,
	entryTimestamp hookTimelineTimestamp,
	entryTimestampErr error,
) error {
	if entryTimestampErr != nil {
		return fmt.Errorf("failed to sample entry timestamp: %w", entryTimestampErr)
	}
	var state OCIState
	if err := json.NewDecoder(input).Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %w", err)
	}

	mode := os.Getenv("SYGMA_TIMELINE_MODE")
	if mode == "" {
		return fmt.Errorf("SYGMA_TIMELINE_MODE is required")
	}
	if mode != "tetragon-measurement" {
		return fmt.Errorf("unsupported SYGMA_TIMELINE_MODE %q", mode)
	}
	if os.Getenv("SYGMA_HOOK_ROLE") != "timestamp-only" {
		return fmt.Errorf("SYGMA_HOOK_ROLE must be timestamp-only")
	}
	if os.Getenv("SYGMA_EXPERIMENT_BACKEND") != "tetragon" {
		return fmt.Errorf("SYGMA_EXPERIMENT_BACKEND must be tetragon")
	}
	if os.Getenv("SYGMA_EXPERIMENT_TRIAL_ID") == "" {
		return fmt.Errorf("SYGMA_EXPERIMENT_TRIAL_ID is required")
	}
	if os.Getenv("SYGMA_EXPERIMENT_APPLICATION") == "" {
		return fmt.Errorf("SYGMA_EXPERIMENT_APPLICATION is required")
	}
	recordHookTimelineAt(
		entryTimestamp,
		"oci_prestart_enter", &state, mode, "", "",
		0, 0, 0, time.Since(start),
	)
	recordHookTimeline(
		"oci_prestart_complete", &state, mode, "", "",
		0, 0, 0, time.Since(start),
	)
	return nil
}

func resolveRelativePath(containerID string, containerPid int, relativePath string) (string, error) {
	if relativePath == "" {
		return "", fmt.Errorf("empty path")
	}

	if strings.HasPrefix(relativePath, "/") {
		return relativePath, nil
	}

	output, err := exec.Command("/usr/bin/crictl", "inspect", containerID).Output()
	if err != nil {
		return "", fmt.Errorf("crictl inspect failed: %w", err)
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return "", fmt.Errorf("failed to parse crictl output: %w", err)
	}

	info := inspectData["info"].(map[string]interface{})
	runtimeSpec := info["runtimeSpec"].(map[string]interface{})
	root := runtimeSpec["root"].(map[string]interface{})
	rootfsPath := root["path"].(string)

	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join("/run/containerd/io.containerd.runtime.v2.task/k8s.io", containerID, rootfsPath)
	}

	log.Printf("🔍 Actual rootfs path: %s", rootfsPath)

	environPath := fmt.Sprintf("/proc/%d/environ", containerPid)
	data, err := os.ReadFile(environPath)
	if err != nil {
		log.Printf("⚠️ Failed to read environ: %v", err)
		data = []byte("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00")
	}

	envVars := strings.Split(string(data), "\x00")
	envPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "PATH=") {
			envPath = strings.TrimPrefix(envVar, "PATH=")
			log.Printf("📂 Container PATH: %s", envPath)
			break
		}
	}

	log.Printf("🔍 Searching for '%s' in PATH: %s", relativePath, envPath)

	for _, dir := range strings.Split(envPath, ":") {
		if dir == "" {
			continue
		}

		candidate := filepath.Join(dir, relativePath)
		hostPath, err := hostPathWithinContainerRoot(rootfsPath, candidate)
		if err != nil {
			log.Printf("   ❌ Unsafe candidate path: %v", err)
			continue
		}

		log.Printf("🔍 Checking hostPath: %s", hostPath)

		stat, err := os.Stat(hostPath)
		if err != nil {
			log.Printf("   ❌ Stat failed: %v", err)
			continue
		}

		log.Printf("   📊 Found file - Mode: %s, IsRegular: %v, Executable: %v",
			stat.Mode(), stat.Mode().IsRegular(), stat.Mode()&0111 != 0)

		if stat.Mode().IsRegular() && (stat.Mode()&0111 != 0) {
			log.Printf("✅ Resolved: %s → %s (found at %s)", relativePath, candidate, hostPath)
			return candidate, nil
		}
	}

	return "", fmt.Errorf("binary not found in PATH: %s", relativePath)
}

func handlePrestart() error {
	start := time.Now()
	entryTimestamp, entryTimestampErr := sampleHookTimelineTimestamp()
	return handlePrestartAt(start, entryTimestamp, entryTimestampErr)
}

func handlePrestartAt(
	start time.Time,
	entryTimestamp hookTimelineTimestamp,
	entryTimestampErr error,
) (retErr error) {
	log.Printf("========== PRESTART START ==========")

	var state OCIState
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %w", err)
	}

	mode := os.Getenv("SYGMA_MODE")
	if mode == "" {
		log.Printf("No SYGMA_MODE set, skipping")
		return nil
	}

	log.Printf("Container: %s, PID: %d, Mode: %s", state.ID, state.Pid, mode)
	imageName := ""
	binaryName := ""
	defer func() {
		if retErr != nil {
			recordHookTimelineFailure(
				"oci_prestart_abort", &state, mode, imageName, binaryName,
				0, 0, 0, time.Since(start), retErr,
			)
		}
	}()
	if entryTimestampErr != nil {
		log.Printf("EVAL timeline clock read failed for oci_prestart_enter: %v", entryTimestampErr)
	} else {
		recordHookTimelineAt(
			entryTimestamp,
			"oci_prestart_enter", &state, mode, "", "",
			0, 0, 0, time.Since(start),
		)
	}

	imageName = os.Getenv("SYGMA_IMAGE_NAME")
	if imageName == "" {
		var err error
		imageName, err = getImageFromConfig(state.Bundle)
		if err != nil {
			log.Printf("Warning: failed to get image name: %v", err)
			imageName = ""
		}
	}
	log.Printf("Image: %s", imageName)

	binaryName, binaryPath := extractBinaryNameAndPath(state, imageName)
	if binaryName == "" || binaryName == "unknown" {
		return fmt.Errorf("target binary name could not be determined")
	}
	log.Printf("Binary: %s (path: %s)", binaryName, binaryPath)

	shouldReplace := false
	replacementPath := ""
	replacementMethod := os.Getenv("SYGMA_REPLACEMENT_METHOD")
	bootstrapPath := os.Getenv("SYGMA_BOOTSTRAP_PATH")
	pathToReplace := binaryPath
	if replacementMethod == "bootstrap-replacement" && bootstrapPath != "" {
		pathToReplace = bootstrapPath
		log.Printf("✅ Bootstrap replacement: initial executable=%s, target binary=%s",
			bootstrapPath, binaryName)
	}

	if pathToReplace != "" && pathToReplace != "unknown" {
		if strings.HasPrefix(pathToReplace, "/") {
			log.Printf("🔄 Absolute path detected: %s", pathToReplace)
			log.Printf("   Method: Binary Replacement")
			shouldReplace = true
			replacementPath = pathToReplace
		} else {
			log.Printf("📍 Relative path detected: %s", pathToReplace)
			log.Printf("   Attempting to resolve...")

			absolutePath, err := resolveRelativePath(state.ID, state.Pid, pathToReplace)
			if err != nil {
				log.Printf("⚠️ Path resolution failed: %v", err)
				log.Printf("   No verifiable wrapper injection path is available")
				shouldReplace = false
			} else {
				log.Printf("✅ Resolved to: %s", absolutePath)
				log.Printf("   Method: Binary Replacement (resolved)")
				shouldReplace = true
				replacementPath = absolutePath
			}
		}
	} else {
		log.Printf("📍 No valid path available")
		log.Printf("   Wrapper injection cannot be verified")
		shouldReplace = false
	}

	if err := validateWrapperReplacementSelection(shouldReplace, replacementPath); err != nil {
		return err
	}
	containerRoot, err := replaceBinaryInContainerHostBased(state.ID, state.Pid, replacementPath)
	if err != nil {
		return fmt.Errorf("binary replacement failed: %w", err)
	}
	log.Printf("✅ Binary replacement complete")
	if err := verifyBinaryReplacement(containerRoot, replacementPath); err != nil {
		return fmt.Errorf("binary replacement verification failed: %w", err)
	}
	log.Printf("✅ Binary replacement verification complete")

	pidNs, mntNs, err := getNamespaces(state.Pid)
	if err != nil {
		return fmt.Errorf("failed to get container namespaces: %w", err)
	}
	log.Printf("✅ Namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)

	if err := saveNamespaceInfo(state.ID, state.Pid, pidNs, mntNs); err != nil {
		return fmt.Errorf("failed to save namespace to Redis: %w", err)
	}
	log.Printf("✅ Saved namespaces to Redis (container:ns:%s)", shortContainerID(state.ID))

	cmd := exec.Command(
		"/usr/local/bin/sygma-tracer",
		strconv.Itoa(state.Pid),
		mode,
		binaryName,
	)
	logFile, err := os.OpenFile(
		fmt.Sprintf("/var/log/sygma-tracer-%d.log", state.Pid),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: failed to create tracer log file: %v", err)
	} else {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	readyFile := tracerReadyFilePath(state.Pid)
	if err := os.Remove(readyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return abortPrestart(state, pidNs, mntNs, nil,
			fmt.Errorf("remove stale tracer ready file %s: %w", readyFile, err))
	}

	if err := cmd.Start(); err != nil {
		return abortPrestart(state, pidNs, mntNs, nil,
			fmt.Errorf("tracer start failed: %w", err))
	}

	log.Printf("✅ Tracer started (PID: %d, mode: %s) (%v)",
		cmd.Process.Pid, mode, time.Since(start))

	if err := waitForTracerReady(state.Pid, cmd.Process.Pid, 5*time.Second); err != nil {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("tracer attach timeout: %w", err))
	} else {
		log.Printf("✅ Tracer attached (%v)", time.Since(start))
	}

	if err := waitForTracerReadyFile(state.Pid, 5*time.Second); err != nil {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("tracer ready-file timeout: %w", err))
	} else {
		log.Printf("✅ Tracer ready file detected (%v)", time.Since(start))
	}

	var directPolicyImageID uint32
	if mode == "enforcement" {

		directPolicyImageID, err = setupEnforceMode(
			state, binaryName, imageName, pidNs, mntNs, start,
		)
		if err != nil {
			return abortPrestart(state, pidNs, mntNs, cmd.Process,
				fmt.Errorf("enforcement instrumentation setup failed: %w", err))
		}
	} else if mode == "collection" {
		if err := setupCollectionMode(state.Pid, pidNs, mntNs, binaryName, imageName); err != nil {
			return abortPrestart(state, pidNs, mntNs, cmd.Process,
				fmt.Errorf("collection instrumentation setup failed: %w", err))
		}
		recordHookTimeline(
			"sygma_collection_ready", &state, mode, imageName, binaryName,
			pidNs, mntNs, 0, time.Since(start),
		)
	} else {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("unsupported SYGMA_MODE %q", mode))
	}

	if mode == "enforcement" && policyCRIntegrationEnabled() {
		crErr := createSYGMAPolicyForContainer(state, binaryName, imageName, pidNs, mntNs)
		if crErr != nil {
			log.Printf("⚠️ Warning: SYGMAPolicy CR creation failed: %v", crErr)
		} else {
			log.Printf("✅ SYGMAPolicy CR created")
		}
	}

	recordHookTimeline(
		"target_release_begin", &state, mode, imageName, binaryName,
		pidNs, mntNs, directPolicyImageID, time.Since(start),
	)

	if err := signalProcess(state.Pid, syscall.SIGUSR1); err != nil {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("failed to send SIGUSR1 to target: %w", err))
	} else {
		log.Printf("✅ Sent SIGUSR1 to PID %d (%v)", state.Pid, time.Since(start))
		recordHookTimeline(
			"target_release_signal_sent", &state, mode, imageName, binaryName,
			pidNs, mntNs, directPolicyImageID, time.Since(start),
		)
	}

	if err := cmd.Process.Release(); err != nil {
		log.Printf("Warning: failed to release tracer process: %v", err)
	}

	recordHookTimeline(
		"oci_prestart_complete", &state, mode, imageName, binaryName,
		pidNs, mntNs, directPolicyImageID, time.Since(start),
	)
	log.Printf("✅ Prestart completed (Total: %v)", time.Since(start))
	log.Printf("   Wrapper will execve when ready")
	log.Printf("   Tracer will catch EXEC event")

	return nil
}

func validateWrapperReplacementSelection(shouldReplace bool, replacementPath string) error {
	if !shouldReplace || strings.TrimSpace(replacementPath) == "" {
		return fmt.Errorf(
			"wrapper injection cannot be verified: binary replacement path is unavailable",
		)
	}
	return nil
}

func createSYGMAPolicyForContainer(
	state OCIState,
	binaryName, imageName string,
	pidNs, mntNs uint32,
) error {
	log.Printf("🔧 Creating SYGMAPolicy CR...")

	namespace, podName, err := getPodInfoForState(state)
	if err != nil {
		namespace = "default"
		podName = shortContainerID(state.ID)
		log.Printf("⚠️ Using fallback: %s/%s", namespace, podName)
	}

	if policyCreator == nil {
		redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
		creator, err := NewSYGMAPolicyCreator(redisAddr)
		if err != nil {
			return fmt.Errorf("failed to create policy creator: %w", err)
		}
		policyCreator = creator
		log.Printf("✅ Policy creator initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	imageID, err := policyCreator.getImageIDFromRedis(ctx, imageName)
	if err != nil {
		log.Printf("⚠️ Warning: imageID lookup failed: %v", err)
		imageID = 0
	}

	if err := policyCreator.CreateSYGMAPolicy(
		ctx,
		namespace, podName, state.ID,
		imageName, binaryName,
		imageID,
		pidNs, mntNs,
	); err != nil {
		return fmt.Errorf("failed to create SYGMAPolicy: %w", err)
	}

	log.Printf("✅ SYGMAPolicy created: %s/%s", namespace, podName)
	return nil
}

func deleteSYGMAPolicyForContainer(state OCIState) error {
	namespace, podName, _ := getPodInfoForState(state)
	if namespace == "" {
		namespace = "default"
	}
	if podName == "" {
		podName = shortContainerID(state.ID)
	}
	if podName == "" {
		return fmt.Errorf("cannot determine SYGMAPolicy name for container")
	}

	var creator sygmaPolicyDeleter
	if policyCreator != nil {
		creator = policyCreator
	}
	ownedCreator := false
	if creator == nil {
		redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
		var err error
		creator, err = newSYGMAPolicyDeleter(redisAddr)
		if err != nil {
			return fmt.Errorf("create policy client for deletion: %w", err)
		}
		ownedCreator = true
	}
	if ownedCreator {
		defer creator.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := creator.DeleteSYGMAPolicy(ctx, namespace, podName, state.ID); err != nil {
		return fmt.Errorf("delete SYGMAPolicy %s/%s: %w", namespace, podName, err)
	}
	return nil
}

func shortContainerID(containerID string) string {
	if len(containerID) > 12 {
		return containerID[:12]
	}
	return containerID
}

func replaceBinaryInContainerHostBased(containerID string, containerPid int, binaryPath string) (string, error) {
	log.Printf("🔍 Binary Replacement (Host-based)")
	log.Printf("   Container ID: %s", shortContainerID(containerID))
	log.Printf("   Container PID: %d", containerPid)
	log.Printf("   Target binary: %s", binaryPath)

	output, err := exec.Command("/usr/bin/crictl", "inspect", containerID).Output()
	if err != nil {
		log.Printf("❌ crictl inspect failed: %v", err)
		return "", fmt.Errorf("crictl inspect failed: %w", err)
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return "", fmt.Errorf("failed to parse crictl output: %w", err)
	}

	info := inspectData["info"].(map[string]interface{})
	runtimeSpec := info["runtimeSpec"].(map[string]interface{})
	root := runtimeSpec["root"].(map[string]interface{})
	rootfsPath := root["path"].(string)

	if !filepath.IsAbs(rootfsPath) {
		absRootfs := filepath.Join("/run/containerd/io.containerd.runtime.v2.task/k8s.io", containerID, rootfsPath)
		log.Printf("🔄 Converting relative to absolute rootfs:")
		log.Printf("   Relative: %s", rootfsPath)
		log.Printf("   Absolute: %s", absRootfs)
		rootfsPath = absRootfs
	}

	log.Printf("   Rootfs path: %s", rootfsPath)

	originalBinary, err := hostPathWithinContainerRoot(rootfsPath, binaryPath)
	if err != nil {
		return "", fmt.Errorf("resolve target inside container rootfs: %w", err)
	}
	realBinary := originalBinary + ".real"

	log.Printf("   Original: %s", originalBinary)
	log.Printf("   Real: %s", realBinary)

	stat, err := os.Lstat(originalBinary)
	if err != nil {
		log.Printf("❌ Original binary not found: %v", err)
		return "", fmt.Errorf("original binary not found: %w", err)
	}

	if stat.Mode()&os.ModeSymlink != 0 {
		log.Printf("🔗 Detected symlink: %s", binaryPath)

		target, err := os.Readlink(originalBinary)
		if err != nil {
			return "", fmt.Errorf("failed to read symlink: %w", err)
		}
		log.Printf("   Symlink target: %s", target)

		var actualBinary string
		if filepath.IsAbs(target) {
			actualBinary, err = hostPathWithinContainerRoot(rootfsPath, target)
			if err != nil {
				return "", fmt.Errorf("resolve absolute symlink target: %w", err)
			}
		} else {
			actualBinary = filepath.Join(filepath.Dir(originalBinary), target)
			if err := validateHostPathWithinRoot(rootfsPath, actualBinary); err != nil {
				return "", fmt.Errorf("resolve relative symlink target: %w", err)
			}
		}

		log.Printf("   Actual binary: %s", actualBinary)

		actualRealBinary := actualBinary + ".real"

		if err := os.Rename(actualBinary, actualRealBinary); err != nil {
			log.Printf("❌ Rename actual binary failed: %v", err)
			return "", fmt.Errorf("failed to rename actual binary: %w", err)
		}
		log.Printf("✅ Renamed actual binary: %s → %s.real", target, target)

		wrapperSource := "/opt/sygma/wrapper"
		if err := copyFileWithPermissions(wrapperSource, actualBinary); err != nil {
			log.Printf("❌ Copy to actual binary failed: %v", err)
			os.Rename(actualRealBinary, actualBinary)
			return "", fmt.Errorf("failed to copy wrapper to actual binary: %w", err)
		}
		log.Printf("✅ Wrapper copied to actual binary: %s", actualBinary)

		if err := os.Remove(originalBinary); err != nil {
			log.Printf("❌ Remove symlink failed: %v", err)
			return "", fmt.Errorf("failed to remove symlink: %w", err)
		}
		log.Printf("✅ Removed symlink: %s", binaryPath)

		if err := copyFileWithPermissions(wrapperSource, originalBinary); err != nil {
			log.Printf("❌ Copy wrapper failed: %v", err)
			return "", fmt.Errorf("failed to copy wrapper: %w", err)
		}
		log.Printf("✅ Wrapper copied: %s", binaryPath)

		relativeRealPath := filepath.Base(actualRealBinary)

		if err := os.Symlink(relativeRealPath, realBinary); err != nil {
			log.Printf("⚠️ Warning: failed to create .real symlink: %v", err)

			if err := copyFileWithPermissions(actualRealBinary, realBinary); err != nil {
				log.Printf("❌ Failed to copy .real: %v", err)
			} else {
				log.Printf("✅ Copied .real as fallback: %s", realBinary)
			}
		} else {
			log.Printf("✅ Created .real symlink: %s → %s", realBinary, relativeRealPath)
		}
	} else {
		log.Printf("📄 Regular file detected")
		log.Printf("✅ Original binary exists (size: %d bytes)", stat.Size())

		if err := os.Rename(originalBinary, realBinary); err != nil {
			log.Printf("❌ Rename failed: %v", err)
			return "", fmt.Errorf("failed to rename binary: %w", err)
		}
		log.Printf("✅ Renamed: %s → %s.real", binaryPath, binaryPath)

		wrapperSource := "/opt/sygma/wrapper"
		if err := copyFileWithPermissions(wrapperSource, originalBinary); err != nil {
			log.Printf("❌ Copy failed: %v", err)
			os.Rename(realBinary, originalBinary)
			return "", fmt.Errorf("failed to copy wrapper: %w", err)
		}
		log.Printf("✅ Wrapper copied: %s → %s", wrapperSource, binaryPath)
	}

	log.Printf("✅ Binary replacement complete")
	return rootfsPath, nil
}

func copyFileWithPermissions(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	if err := dstFile.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	if err := os.Chmod(dst, srcInfo.Mode()|0111); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	return nil
}

func hostPathWithinContainerRoot(containerRoot, containerPath string) (string, error) {
	if strings.TrimSpace(containerRoot) == "" || strings.TrimSpace(containerPath) == "" {
		return "", fmt.Errorf("container root and path must be non-empty")
	}
	root, err := filepath.Abs(containerRoot)
	if err != nil {
		return "", fmt.Errorf("resolve container root: %w", err)
	}

	cleanContainerPath := filepath.Clean("/" + strings.TrimPrefix(containerPath, "/"))
	hostPath := filepath.Join(root, strings.TrimPrefix(cleanContainerPath, "/"))
	if err := validateHostPathWithinRoot(root, hostPath); err != nil {
		return "", err
	}
	return hostPath, nil
}

func validateHostPathWithinRoot(containerRoot, hostPath string) error {
	root, err := filepath.Abs(containerRoot)
	if err != nil {
		return fmt.Errorf("resolve container root: %w", err)
	}
	candidate, err := filepath.Abs(hostPath)
	if err != nil {
		return fmt.Errorf("resolve host path: %w", err)
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return fmt.Errorf("compare host path to container root: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %s escapes container root %s", candidate, root)
	}
	return nil
}

func verifyBinaryReplacement(containerRoot, binaryPath string) error {
	wrapperPath, err := hostPathWithinContainerRoot(containerRoot, binaryPath)
	if err != nil {
		return err
	}
	wrapperInfo, err := os.Stat(wrapperPath)
	if err != nil {
		return fmt.Errorf("wrapper not found: %w", err)
	}

	realPath := wrapperPath + ".real"
	realInfo, err := os.Stat(realPath)
	if err != nil {
		return fmt.Errorf(".real not found: %w", err)
	}

	if wrapperInfo.Mode()&0111 == 0 {
		return fmt.Errorf("wrapper not executable")
	}

	if realInfo.Mode()&0111 == 0 {
		return fmt.Errorf(".real not executable")
	}

	log.Printf("✅ Binary replacement verified:")
	log.Printf("   Wrapper: %s (%s, %d bytes)",
		binaryPath, wrapperInfo.Mode(), wrapperInfo.Size())
	log.Printf("   Real:    %s.real (%s, %d bytes)",
		binaryPath, realInfo.Mode(), realInfo.Size())

	return nil
}

func setupEnforceMode(state OCIState, binaryName, imageName string, pidNs, mntNs uint32, hookStart time.Time) (uint32, error) {
	start := time.Now()
	log.Printf("⏱️ Enforce setup starting")

	namespace, podName, _ := getPodInfoFromConfig(state.Bundle)
	if podName == "" {
		namespace = "default"
		podName = shortContainerID(state.ID)
	}

	if pidNs == 0 || mntNs == 0 {
		return 0, fmt.Errorf("invalid namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)
	}

	log.Printf("Pod: %s/%s, Image: %s", namespace, podName, imageName)
	log.Printf("Namespaces: pidns=%d, mntns=%d", pidNs, mntNs)

	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return 0, fmt.Errorf("redis ping failed: %w", err)
	}

	imageID, binaryName, err := loadImagePolicyToEBPF(
		ctx, rdb, imageName, pidNs, mntNs, binaryName,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to load policy: %w", err)
	}

	if err := initializeProcessStateForPolicy(
		state.Pid, imageID, pidNs, mntNs, processStateABIStateMachine,
	); err != nil {
		return 0, fmt.Errorf("process state init failed: %w", err)
	}

	mappingKey := fmt.Sprintf("container:mapping:%s", state.ID)
	podKey := fmt.Sprintf("%s/%s", namespace, podName)
	if err := rdb.Set(ctx, mappingKey, podKey, 0).Err(); err != nil {
		return 0, fmt.Errorf("save container mapping: %w", err)
	}

	if err := updateNamespaceMaps(imageID, binaryName, pidNs, mntNs); err != nil {
		return 0, fmt.Errorf("install namespace policy gates: %w", err)
	}

	recordHookTimeline(
		"sygma_direct_policy_ready", &state, "enforcement", imageName, binaryName,
		pidNs, mntNs, imageID, time.Since(hookStart),
	)
	log.Printf("✅ Enforce setup completed (%v)", time.Since(start))
	return imageID, nil
}

func saveNamespaceInfo(containerID string, rootPID int, pidNs, mntNs uint32) error {
	if pidNs == 0 || mntNs == 0 {
		return fmt.Errorf("invalid namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)
	}
	if rootPID <= 0 {
		return fmt.Errorf("invalid root PID: %d", rootPID)
	}

	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	nsInfo := NamespaceInfo{
		PidNs:   pidNs,
		MntNs:   mntNs,
		RootPID: uint32(rootPID),
	}

	data, err := json.Marshal(nsInfo)
	if err != nil {
		return fmt.Errorf("json marshal failed: %w", err)
	}

	key := fmt.Sprintf("container:ns:%s", containerID)

	if err := rdb.Set(ctx, key, data, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	log.Printf("📝 Saved to Redis: %s → {pidNs:%d, mntNs:%d}", key, pidNs, mntNs)

	savedData, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		log.Printf("⚠️ Warning: Failed to verify saved data: %v", err)
	} else {
		var verifyInfo NamespaceInfo
		if err := json.Unmarshal(savedData, &verifyInfo); err == nil {
			log.Printf("✅ Verified: Redis data is correct (pidNs=%d, mntNs=%d)",
				verifyInfo.PidNs, verifyInfo.MntNs)
		}
	}

	return nil
}

func getNamespaces(pid int) (uint32, uint32, error) {
	pidNsPath := fmt.Sprintf("/proc/%d/ns/pid", pid)
	pidNsStat, err := os.Stat(pidNsPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to stat %s: %w", pidNsPath, err)
	}
	pidNs := uint32(pidNsStat.Sys().(*syscall.Stat_t).Ino)

	mntNsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	mntNsStat, err := os.Stat(mntNsPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to stat %s: %w", mntNsPath, err)
	}
	mntNs := uint32(mntNsStat.Sys().(*syscall.Stat_t).Ino)

	log.Printf("📊 Extracted namespaces from /proc/%d/ns: pidNs=%d, mntNs=%d",
		pid, pidNs, mntNs)

	return pidNs, mntNs, nil
}

func waitForTracerReady(containerPid, expectedTracerPid int, timeout time.Duration) error {
	if expectedTracerPid <= 0 {
		return fmt.Errorf("invalid expected tracer PID: %d", expectedTracerPid)
	}
	deadline := time.Now().Add(timeout)

	log.Printf("⏳ Waiting for tracer PID %d to attach to PID %d...",
		expectedTracerPid, containerPid)

	for time.Now().Before(deadline) {
		statusPath := fmt.Sprintf("/proc/%d/status", containerPid)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		tracerPid, err := tracerPIDFromStatus(data)
		if err == nil && tracerPid == expectedTracerPid {
			log.Printf("✅ Expected tracer attached (TracerPid=%d)", tracerPid)
			return nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("timeout: tracer PID %d did not attach within %v",
		expectedTracerPid, timeout)
}

func tracerPIDFromStatus(data []byte) (int, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, fmt.Errorf("malformed TracerPid status line %q", line)
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || pid < 0 {
			return 0, fmt.Errorf("invalid TracerPid value %q", fields[1])
		}
		return pid, nil
	}
	return 0, fmt.Errorf("TracerPid field is missing")
}

func extractBinaryNameAndPath(state OCIState, imageName string) (string, string) {
	preferredBinary := strings.TrimSpace(os.Getenv("SYGMA_TARGET_BINARY"))
	preferredPath := strings.TrimSpace(os.Getenv("SYGMA_BINARY_PATH"))
	if preferredBinary == "unknown" {
		preferredBinary = ""
	}
	if preferredPath == "unknown" {
		preferredPath = ""
	}

	if preferredBinary != "" {
		log.Printf("✅ Binary from env (NRI): %s", preferredBinary)
		if preferredPath != "" {
			log.Printf("✅ Binary path from env (NRI): %s", preferredPath)
			return preferredBinary, preferredPath
		}
	}

	if preferredBinary == "" && imageName != "" {
		binaryName, binaryPath, err := lookupBinaryByImage(imageName)
		if err != nil {
			log.Printf("⚠️ Redis lookup failed: %v", err)
		} else if binaryName == "" || binaryName == "unknown" {
			log.Printf("⚠️ Redis returned 'unknown' binary, falling back to config.json")
		} else {
			preferredBinary = binaryName
			preferredPath = strings.TrimSpace(binaryPath)
			if preferredPath != "" {
				return preferredBinary, preferredPath
			}
			log.Printf(
				"⚠️ Redis metadata for %s has no binary path; checking config.json and PATH",
				preferredBinary,
			)
		}
	}

	configBinary, configPath := extractBinaryFromConfig(state.Bundle)
	if preferredBinary != "" {
		if configBinary == preferredBinary ||
			(configPath != "" && filepath.Base(configPath) == preferredBinary) {
			log.Printf("✅ Resolved metadata binary from config.json: %s", configPath)
			return preferredBinary, configPath
		}

		log.Printf("✅ Resolving metadata binary through container PATH: %s", preferredBinary)
		return preferredBinary, preferredBinary
	}
	return configBinary, configPath
}

func extractBinaryFromConfig(bundlePath string) (string, string) {
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("❌ Failed to read config.json: %v", err)
		return "", ""
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("❌ Failed to parse config.json: %v", err)
		return "", ""
	}

	process, ok := config["process"].(map[string]interface{})
	if !ok {
		log.Printf("❌ No process field in config.json")
		return "", ""
	}

	args, ok := process["args"].([]interface{})
	if !ok || len(args) == 0 {
		log.Printf("❌ No args in config.json")
		return "", ""
	}

	log.Printf("📋 config.json args: %v", args)

	startIdx := 0

	if len(args) > 0 {
		if arg0, ok := args[0].(string); ok {
			if strings.Contains(arg0, "wrapper") {
				log.Printf("   Skipping wrapper at args[0]: %s", arg0)
				startIdx = 1
			}
		}
	}

	if startIdx < len(args) {
		if arg, ok := args[startIdx].(string); ok {
			if strings.Contains(arg, "entrypoint") ||
				strings.HasSuffix(arg, ".sh") ||
				strings.Contains(arg, "foreground") {
				log.Printf("   Skipping script at args[%d]: %s", startIdx, arg)
				startIdx++
			}
		}
	}

	if startIdx < len(args) {
		if binaryArg, ok := args[startIdx].(string); ok {
			if strings.HasPrefix(binaryArg, "-") {
				log.Printf("❌ First non-wrapper arg is a flag: %s", binaryArg)
				return "", ""
			}

			if strings.HasPrefix(binaryArg, "/") {
				binaryName := filepath.Base(binaryArg)
				log.Printf("✅ Binary from config.json (absolute): name=%s, path=%s",
					binaryName, binaryArg)
				return binaryName, binaryArg
			}

			log.Printf("✅ Binary from config.json (relative): %s", binaryArg)
			return binaryArg, binaryArg
		}
	}

	log.Printf("❌ Failed to extract binary from args: %v", args)
	return "", ""
}

func getBinaryNameByImage(imageName string) (string, string, error) {
	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")

	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	normalizedImage := normalizeImageName(imageName)

	imageIDKey := fmt.Sprintf("image_name_map:%s", normalizedImage)
	imageIDStr, err := rdb.Get(ctx, imageIDKey).Result()
	if err != nil {
		return "", "", fmt.Errorf("image_name_map lookup failed for %s: %w", normalizedImage, err)
	}

	imageMapKey := fmt.Sprintf("image_id_map:%s", imageIDStr)
	imageInfo, err := rdb.Get(ctx, imageMapKey).Result()
	if err != nil {
		return "", "", fmt.Errorf("image_id_map lookup failed for ID %s: %w", imageIDStr, err)
	}

	metadata, err := parseImageMetadata(imageInfo)
	if err != nil {
		return "", "", fmt.Errorf("decode image_id_map metadata for ID %s: %w", imageIDStr, err)
	}

	log.Printf("✅ Parsed from image_id_map:")
	log.Printf("   Raw: %s", imageInfo)
	log.Printf("   Binary: '%s'", metadata.BinaryName)
	log.Printf("   Path: '%s'", metadata.BinaryPath)

	return metadata.BinaryName, metadata.BinaryPath, nil
}

func parseImageMetadata(raw string) (ImageMetadata, error) {
	var metadata ImageMetadata
	value := strings.TrimSpace(raw)
	if value == "" {
		return metadata, errors.New("image metadata is empty")
	}

	if strings.HasPrefix(value, "{") {
		if err := json.Unmarshal([]byte(value), &metadata); err != nil {
			return ImageMetadata{}, fmt.Errorf("decode JSON image metadata: %w", err)
		}
		metadata.ImageName = strings.TrimSpace(metadata.ImageName)
		metadata.BinaryName = strings.TrimSpace(metadata.BinaryName)
		metadata.BinaryPath = strings.TrimSpace(metadata.BinaryPath)
		if metadata.ImageName == "" {
			return ImageMetadata{}, errors.New("JSON image metadata has no imageName")
		}
		if err := validateMetadataBinaryName(metadata.BinaryName); err != nil {
			return ImageMetadata{}, err
		}
		if metadata.BinaryPath != "" && !filepath.IsAbs(metadata.BinaryPath) {
			return ImageMetadata{}, fmt.Errorf(
				"JSON binaryPath %q is not absolute", metadata.BinaryPath,
			)
		}
		return metadata, nil
	}

	firstColon := strings.IndexByte(value, ':')
	if firstColon <= 0 || firstColon == len(value)-1 {
		return metadata, fmt.Errorf("malformed legacy image metadata %q", value)
	}
	firstField := strings.TrimSpace(value[:firstColon])
	remainder := strings.TrimSpace(value[firstColon+1:])
	if firstField == "" || remainder == "" {
		return metadata, fmt.Errorf("malformed legacy image metadata %q", value)
	}

	if filepath.IsAbs(remainder) {
		if err := validateMetadataBinaryName(firstField); err != nil {
			return metadata, err
		}
		return ImageMetadata{BinaryName: firstField, BinaryPath: remainder}, nil
	}

	lastColon := strings.LastIndexByte(value, ':')
	imageName := strings.TrimSpace(value[:lastColon])
	binaryName := strings.TrimSpace(value[lastColon+1:])
	if imageName == "" {
		return metadata, fmt.Errorf("legacy image metadata %q has no image name", value)
	}
	if err := validateMetadataBinaryName(binaryName); err != nil {
		return metadata, err
	}
	return ImageMetadata{ImageName: imageName, BinaryName: binaryName}, nil
}

func validateMetadataBinaryName(binaryName string) error {
	if binaryName == "" || binaryName == "unknown" {
		return fmt.Errorf("invalid binary name %q", binaryName)
	}
	if strings.ContainsAny(binaryName, "/\\") {
		return fmt.Errorf("binary name %q must not contain a path separator", binaryName)
	}
	return nil
}

func policyMask(syscalls []int) (SyscallGraphValue, error) {
	var value SyscallGraphValue
	for _, syscall := range syscalls {
		if syscall < 0 {
			return value, fmt.Errorf("negative syscall %d", syscall)
		}
		bitIndex := uint32(0xFFFFFFFF)
		switch {
		case syscall <= 334:
			bitIndex = uint32(syscall)
		case syscall >= 424 && syscall <= 448:
			bitIndex = 335 + uint32(syscall-424)
		}
		if bitIndex == 0xFFFFFFFF || bitIndex >= 360 {
			return value, fmt.Errorf("unsupported syscall %d", syscall)
		}
		byteIndex := 44 - (bitIndex >> 3)
		value.AllowedMask[byteIndex] |= byte(1 << (bitIndex & 7))
	}
	return value, nil
}

func namespaceMatches(
	keyPidNs, keyMntNs, wantedPidNs, wantedMntNs uint32,
) bool {
	return keyPidNs == wantedPidNs && keyMntNs == wantedMntNs
}

func deleteNamespaceSyscallGraphRows(
	graphMap *ebpf.Map, pidNs, mntNs uint32,
) error {
	var key SyscallGraphKey
	var value SyscallGraphValue
	var keys []SyscallGraphKey
	iter := graphMap.Iterate()
	for iter.Next(&key, &value) {
		if namespaceMatches(key.PidNs, key.MntNs, pidNs, mntNs) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate syscall_graph_map: %w", err)
	}
	for index := range keys {
		if err := deleteMapKey(graphMap, &keys[index]); err != nil {
			return fmt.Errorf("delete syscall graph key %+v: %w", keys[index], err)
		}
	}
	return nil
}

func deleteNamespaceStateRuleRows(
	ruleMap *ebpf.Map, pidNs, mntNs uint32,
) error {
	var key PolicyStateRuleKey
	var value SyscallGraphValue
	var keys []PolicyStateRuleKey
	iter := ruleMap.Iterate()
	for iter.Next(&key, &value) {
		if namespaceMatches(key.PidNs, key.MntNs, pidNs, mntNs) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate policy_state_rule_map: %w", err)
	}
	for index := range keys {
		if err := deleteMapKey(ruleMap, &keys[index]); err != nil {
			return fmt.Errorf("delete policy state rule %+v: %w", keys[index], err)
		}
	}
	return nil
}

func deleteNamespaceStateTransitionRows(
	transitionMap *ebpf.Map, pidNs, mntNs uint32,
) error {
	var key PolicyStateTransitionKey
	var value uint32
	var keys []PolicyStateTransitionKey
	iter := transitionMap.Iterate()
	for iter.Next(&key, &value) {
		if namespaceMatches(key.PidNs, key.MntNs, pidNs, mntNs) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate policy_state_transition_map: %w", err)
	}
	for index := range keys {
		if err := deleteMapKey(transitionMap, &keys[index]); err != nil {
			return fmt.Errorf(
				"delete policy state transition %+v: %w", keys[index], err,
			)
		}
	}
	return nil
}

func clearPinnedNamespacePolicyRows(pidNs, mntNs uint32) error {
	nsKey := PidMountNs{MntNs: mntNs, PidNs: pidNs}
	configMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_config_map", nil)
	if err != nil {
		return fmt.Errorf("open policy_config_map for replacement: %w", err)
	}
	if err := deleteMapKey(configMap, &nsKey); err != nil {
		configMap.Close()
		return fmt.Errorf("clear policy config before replacement: %w", err)
	}
	configMap.Close()

	type namespacePolicyMap struct {
		path  string
		name  string
		clear func(*ebpf.Map, uint32, uint32) error
	}
	maps := []namespacePolicyMap{
		{
			path:  "/sys/fs/bpf/sygma/syscall_graph_map",
			name:  "syscall_graph_map",
			clear: deleteNamespaceSyscallGraphRows,
		},
		{
			path:  "/sys/fs/bpf/sygma/policy_state_rule_map",
			name:  "policy_state_rule_map",
			clear: deleteNamespaceStateRuleRows,
		},
		{
			path:  "/sys/fs/bpf/sygma/policy_state_transition_map",
			name:  "policy_state_transition_map",
			clear: deleteNamespaceStateTransitionRows,
		},
	}

	for _, mapSpec := range maps {
		pinnedMap, err := ebpf.LoadPinnedMap(mapSpec.path, nil)
		if err != nil {
			return fmt.Errorf("open %s for replacement: %w", mapSpec.name, err)
		}
		clearErr := mapSpec.clear(pinnedMap, pidNs, mntNs)
		pinnedMap.Close()
		if clearErr != nil {
			return fmt.Errorf("clear %s before replacement: %w", mapSpec.name, clearErr)
		}
	}

	log.Printf("Cleared stale policy rows for pidns=%d mntns=%d", pidNs, mntNs)
	return nil
}

func installStateMachinePolicy(
	ctx context.Context,
	rdb *redis.Client,
	imageID, pidNs, mntNs uint32,
) error {
	policyData, err := rdb.Get(ctx, fmt.Sprintf("main_policy:%d", imageID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("state-machine policy is missing for image %d", imageID)
		}
		return fmt.Errorf("read state-machine policy: %w", err)
	}

	var policy MainPolicySpec
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return fmt.Errorf("decode state-machine policy: %w", err)
	}
	if !strings.EqualFold(policy.Type, "state-machine") {
		return fmt.Errorf("unsupported main policy type %q; expected state-machine", policy.Type)
	}
	if policy.StateMachine == nil {
		return errors.New("state-machine policy body is missing")
	}
	if _, ok := policy.StateMachine.States[strconv.FormatUint(uint64(policy.StateMachine.InitialState), 10)]; !ok {
		return fmt.Errorf(
			"state-machine initial state %d has no allow-list",
			policy.StateMachine.InitialState,
		)
	}

	configMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_config_map", nil)
	if err != nil {
		return fmt.Errorf("open policy_config_map: %w", err)
	}
	defer configMap.Close()

	ruleMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_state_rule_map", nil)
	if err != nil {
		return fmt.Errorf("open policy_state_rule_map: %w", err)
	}
	defer ruleMap.Close()

	transitionMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_state_transition_map", nil)
	if err != nil {
		return fmt.Errorf("open policy_state_transition_map: %w", err)
	}
	defer transitionMap.Close()

	for stateRaw, state := range policy.StateMachine.States {
		stateID, err := strconv.ParseUint(stateRaw, 10, 32)
		if err != nil {
			return fmt.Errorf("parse state-machine state %q: %w", stateRaw, err)
		}
		value, err := policyMask(state.AllowedSyscalls)
		if err != nil {
			return fmt.Errorf("state %d allow-list: %w", stateID, err)
		}
		key := PolicyStateRuleKey{
			MntNs: mntNs,
			PidNs: pidNs,
			State: uint32(stateID),
		}
		if err := ruleMap.Put(&key, &value); err != nil {
			return fmt.Errorf("install state %d allow-list: %w", stateID, err)
		}
	}

	for stateRaw, transitions := range policy.StateMachine.Transitions {
		stateID, err := strconv.ParseUint(stateRaw, 10, 32)
		if err != nil {
			return fmt.Errorf("parse state-machine transition state %q: %w", stateRaw, err)
		}
		for syscallRaw, nextState := range transitions {
			syscallNumber, err := strconv.Atoi(syscallRaw)
			if err != nil {
				return fmt.Errorf("parse state-machine syscall %q: %w", syscallRaw, err)
			}
			if err := validatePolicyTransitionSyscall(syscallNumber); err != nil {
				return err
			}
			key := PolicyStateTransitionKey{
				MntNs:   mntNs,
				PidNs:   pidNs,
				State:   uint32(stateID),
				Syscall: uint32(syscallNumber),
			}
			if err := transitionMap.Put(&key, &nextState); err != nil {
				return fmt.Errorf(
					"install state %d syscall %d transition: %w",
					stateID, syscallNumber, err,
				)
			}
		}
	}

	nsKey := PidMountNs{MntNs: mntNs, PidNs: pidNs}
	config := PolicyConfigValue{
		Type:         policyTypeStateMachine,
		InitialState: policy.StateMachine.InitialState,
	}
	if err := configMap.Put(&nsKey, &config); err != nil {
		return fmt.Errorf("install state-machine policy config: %w", err)
	}

	log.Printf(
		"Installed state-machine policy to eBPF (imageID=%d, pidns=%d, mntns=%d)",
		imageID, pidNs, mntNs,
	)
	return nil
}

type redisScanPageFunc func(
	context.Context, uint64, string, int64,
) ([]string, uint64, error)

func scanRedisKeys(ctx context.Context, rdb *redis.Client, pattern string) ([]string, error) {
	return collectRedisKeysByScan(
		ctx,
		pattern,
		func(ctx context.Context, cursor uint64, pattern string, count int64) ([]string, uint64, error) {
			return rdb.Scan(ctx, cursor, pattern, count).Result()
		},
	)
}

func collectRedisKeysByScan(
	ctx context.Context,
	pattern string,
	scanPage redisScanPageFunc,
) ([]string, error) {
	const scanCount int64 = 256
	seen := make(map[string]struct{})
	var keys []string
	var cursor uint64
	for {
		page, nextCursor, err := scanPage(ctx, cursor, pattern, scanCount)
		if err != nil {
			return nil, err
		}
		for _, key := range page {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func loadImagePolicyToEBPF(ctx context.Context, rdb *redis.Client, imageName string, pidNs, mntNs uint32, binaryName string) (uint32, string, error) {
	start := time.Now()
	log.Printf("Loading image policy to eBPF: %s", imageName)

	imageID, foundImageName, err := getImageIDFromRedis(ctx, rdb, imageName)
	if err != nil {
		return 0, "", err
	}
	log.Printf("Found image: %s (ID=%d) (%v)", foundImageName, imageID, time.Since(start))

	policyRevisionKey := fmt.Sprintf("policy_ready:%d", imageID)
	policyRevision, err := rdb.Get(ctx, policyRevisionKey).Result()
	if err != nil {
		return 0, "", fmt.Errorf("read policy publication marker %s: %w", policyRevisionKey, err)
	}
	if strings.TrimSpace(policyRevision) == "" {
		return 0, "", fmt.Errorf("policy publication marker %s is empty", policyRevisionKey)
	}

	if binaryName == "" {
		binaryInfo, err := rdb.Get(ctx, fmt.Sprintf("image_id_map:%d", imageID)).Result()
		if err != nil {
			return 0, "", fmt.Errorf("read image metadata for image %d: %w", imageID, err)
		}
		metadata, err := parseImageMetadata(binaryInfo)
		if err != nil {
			return 0, "", fmt.Errorf("decode image metadata for image %d: %w", imageID, err)
		}
		binaryName = metadata.BinaryName
	}
	log.Printf("Binary: %s", binaryName)

	if err := clearPinnedNamespacePolicyRows(pidNs, mntNs); err != nil {
		return 0, "", err
	}

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		return 0, "", fmt.Errorf("open syscall_graph_map: %w", err)
	}
	defer graphMap.Close()

	totalLoaded := 0
	phaseLoaded := map[uint32]int{}
	phaseZeroStartLoaded := false
	for _, phase := range []uint32{0} {
		pattern := fmt.Sprintf("syscall_graph:%d:%d:*", imageID, phase)
		keys, err := scanRedisKeys(ctx, rdb, pattern)
		if err != nil {
			return 0, "", fmt.Errorf("list phase %d policy keys: %w", phase, err)
		}

		if len(keys) == 0 {
			log.Printf("Phase %d: no transitions", phase)
			continue
		}

		pipe := rdb.Pipeline()
		cmds := make(map[string]*redis.StringCmd, len(keys))

		for _, key := range keys {
			cmds[key] = pipe.Get(ctx, key)
		}

		_, err = pipe.Exec(ctx)
		if err != nil {
			return 0, "", fmt.Errorf("read phase %d policy: %w", phase, err)
		}

		for key, cmd := range cmds {
			var keyImageID, keyPhase, fromSyscall uint32
			if _, err := fmt.Sscanf(key, "syscall_graph:%d:%d:%d",
				&keyImageID, &keyPhase, &fromSyscall); err != nil {
				return 0, "", fmt.Errorf("parse policy key %q: %w", key, err)
			}
			if keyImageID != imageID || keyPhase != phase {
				return 0, "", fmt.Errorf(
					"policy key %q does not match requested image=%d phase=%d",
					key, imageID, phase)
			}

			if !isSyscallInValidRange(fromSyscall) {
				return 0, "", fmt.Errorf(
					"policy key %q contains unsupported from syscall %d",
					key, fromSyscall)
			}

			data, err := cmd.Bytes()
			if err != nil {
				return 0, "", fmt.Errorf("read policy value %q: %w", key, err)
			}
			if len(data) != 45 {
				return 0, "", fmt.Errorf(
					"policy value %q has length %d, want 45", key, len(data))
			}
			hasAllowedTransition := false
			for _, maskByte := range data {
				if maskByte != 0 {
					hasAllowedTransition = true
					break
				}
			}
			if !hasAllowedTransition && phase == 0 {
				return 0, "", fmt.Errorf("policy value %q has no allowed transitions", key)
			}

			mapKey := SyscallGraphKey{
				MntNs:       mntNs,
				PidNs:       pidNs,
				FromSyscall: fromSyscall,
				Phase:       phase,
			}

			var mapValue SyscallGraphValue
			copy(mapValue.AllowedMask[:], data)

			if err := graphMap.Put(&mapKey, &mapValue); err != nil {
				return 0, "", fmt.Errorf("install policy key %q: %w", key, err)
			}

			totalLoaded++
			phaseLoaded[phase]++
			if phase == 0 && fromSyscall == 500 {
				phaseZeroStartLoaded = true
			}
		}
	}

	if phaseLoaded[0] == 0 {
		return 0, "", fmt.Errorf(
			"phase 0 policy is empty for image %s (imageID=%d)", imageName, imageID)
	}
	if !phaseZeroStartLoaded {
		return 0, "", fmt.Errorf(
			"phase 0 policy for image %s (imageID=%d) has no START transition (from=500)",
			imageName, imageID)
	}

	log.Printf("✅ Loaded %d bootstrap transitions to eBPF (pidns=%d, mntns=%d) (%v)",
		totalLoaded, pidNs, mntNs, time.Since(start))

	if err := installStateMachinePolicy(ctx, rdb, imageID, pidNs, mntNs); err != nil {
		return 0, "", fmt.Errorf("install state-machine policy: %w", err)
	}
	currentRevision, err := rdb.Get(ctx, policyRevisionKey).Result()
	if err != nil {
		return 0, "", fmt.Errorf("re-read policy publication marker %s: %w", policyRevisionKey, err)
	}
	if err := validateStablePolicyRevision(policyRevision, currentRevision); err != nil {
		return 0, "", fmt.Errorf("policy publication changed during installation: %w", err)
	}

	return imageID, binaryName, nil
}

func validateStablePolicyRevision(before, after string) error {
	if strings.TrimSpace(before) == "" {
		return errors.New("initial policy revision is empty")
	}
	if strings.TrimSpace(after) == "" {
		return errors.New("final policy revision is empty")
	}
	if before != after {
		return fmt.Errorf("revision changed from %q to %q", before, after)
	}
	return nil
}

func isSyscallInValidRange(syscall uint32) bool {
	if syscall == 500 {
		return true
	}
	if syscall <= 334 {
		return true
	}
	if syscall >= 424 && syscall <= 448 {
		return true
	}
	return false
}

func validatePolicyTransitionSyscall(syscall int) error {
	if syscall < 0 || syscall == 500 || !isSyscallInValidRange(uint32(syscall)) {
		return fmt.Errorf("unsupported policy transition syscall %d", syscall)
	}
	return nil
}

func getImageIDFromRedis(ctx context.Context, rdb *redis.Client, fullImageName string) (uint32, string, error) {
	candidates := generateImageNameCandidates(fullImageName)
	log.Printf("Searching for image with candidates: %v", candidates)

	for _, imageName := range candidates {
		key := fmt.Sprintf("image_name_map:%s", imageName)
		imageIDStr, err := rdb.Get(ctx, key).Result()

		if err == nil {
			imageIDInt, err := strconv.ParseUint(imageIDStr, 10, 32)
			if err != nil {
				return 0, "", fmt.Errorf("invalid image id for %s: %w", imageName, err)
			}
			imageID := uint32(imageIDInt)
			log.Printf("Found image '%s' with ID=%d", imageName, imageID)
			return imageID, imageName, nil
		}
	}

	return 0, "", fmt.Errorf("image not found in Redis (tried: %v)", candidates)
}

func generateImageNameCandidates(fullImageName string) []string {
	var candidates []string
	seen := make(map[string]struct{})
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	add(fullImageName)
	add(normalizeImageName(fullImageName))

	parts := strings.Split(strings.TrimSpace(fullImageName), "/")
	if len(parts) >= 3 {
		withoutRegistry := strings.Join(parts[1:], "/")
		add(withoutRegistry)
		add(normalizeImageName(withoutRegistry))
	}
	if len(parts) >= 2 {
		lastSegment := parts[len(parts)-1]
		add(lastSegment)
		add(normalizeImageName(lastSegment))
	}
	return candidates
}

func updateNamespaceMaps(imageID uint32, binaryName string, pidNs, mntNs uint32) error {
	nsKey := PidMountNs{PidNs: pidNs, MntNs: mntNs}

	execTimeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/execution_time_map", nil)
	if err != nil {
		return fmt.Errorf("open execution_time_map: %w", err)
	}
	defer execTimeMap.Close()

	var execValue ExecutionValue
	commBytes := []byte(binaryName)
	if len(commBytes) > 15 {
		commBytes = commBytes[:15]
	}
	copy(execValue.Comm[:], commBytes)
	execValue.ExecutionTime = 0

	if err := execTimeMap.Put(&nsKey, &execValue); err != nil {
		return fmt.Errorf("update execution_time_map: %w", err)
	}

	pidMountNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/pid_mount_ns_map", nil)
	if err != nil {
		rollbackErr := deleteMapKey(execTimeMap, &nsKey)
		return errors.Join(
			fmt.Errorf("open pid_mount_ns_map: %w", err),
			wrapMapRollbackError("execution_time_map", rollbackErr),
		)
	}
	defer pidMountNsMap.Close()

	enableValue := uint64(1)
	if err := pidMountNsMap.Put(&nsKey, &enableValue); err != nil {
		rollbackErr := deleteMapKey(execTimeMap, &nsKey)
		return errors.Join(
			fmt.Errorf("update pid_mount_ns_map: %w", err),
			wrapMapRollbackError("execution_time_map", rollbackErr),
		)
	}

	log.Printf("✅ Namespace policy gates initialized (imageID=%d, pidns=%d, mntns=%d)",
		imageID, pidNs, mntNs)
	return nil
}

func initializeProcessState(pid int, imageID, pidNs, mntNs uint32) error {
	return initializeProcessStateForPolicy(
		pid, imageID, pidNs, mntNs, processStateABIUnknown,
	)
}

func initializeProcessStateForPolicy(
	pid int,
	imageID, pidNs, mntNs uint32,
	expectedABI processStateMapABI,
) error {
	if pid <= 0 {
		return fmt.Errorf("invalid root PID: %d", pid)
	}

	stateMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
	if err != nil {
		return fmt.Errorf("open process_state_map: %w", err)
	}
	defer stateMap.Close()

	stateABI, _, err := inspectProcessStateMapABI(stateMap)
	if err != nil {
		return err
	}
	if err := validateProcessStateABIForPolicy(stateABI, expectedABI); err != nil {
		return err
	}

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	if err != nil {
		return fmt.Errorf("open tid_to_namespace: %w", err)
	}
	defer tidNsMap.Close()

	state, err := initialProcessStateForABI(stateABI, imageID)
	if err != nil {
		return err
	}

	tid := uint32(pid)
	if err := stateMap.Put(&tid, state); err != nil {

		pruned, pruneErr := pruneDeadProcessStates(stateMap, tidNsMap, stateABI)
		if pruneErr != nil {
			return fmt.Errorf(
				"failed to update process_state_map: %w (dead-state pruning also failed: %v)",
				err, pruneErr)
		}
		if pruned == 0 {
			return fmt.Errorf("failed to update process_state_map: %w", err)
		}
		log.Printf("⚠️ Reclaimed %d stale process-state entries after map update failure", pruned)
		if retryErr := stateMap.Put(&tid, state); retryErr != nil {
			return fmt.Errorf(
				"failed to update process_state_map after reclaiming %d stale entries: %w",
				pruned, retryErr)
		}
	}

	nsKey := PidMountNs{MntNs: mntNs, PidNs: pidNs}
	if err := tidNsMap.Put(&tid, &nsKey); err != nil {
		rollbackErr := deleteMapKey(stateMap, &tid)
		return errors.Join(
			fmt.Errorf("failed to link root TID to namespace: %w", err),
			wrapMapRollbackError("process_state_map", rollbackErr),
		)
	}

	log.Printf("Initialized process_state and TID namespace for PID %d (imageID=%d, pidns=%d, mntns=%d)",
		pid, imageID, pidNs, mntNs)
	return nil
}

func validateProcessStateABIForPolicy(
	actual, expected processStateMapABI,
) error {
	if actual == processStateABIUnknown {
		return fmt.Errorf("process_state_map ABI is unknown")
	}
	if expected != processStateABIUnknown && actual != expected {
		return fmt.Errorf(
			"process_state_map ABI %s is incompatible with installed policy maps (expected %s)",
			actual, expected,
		)
	}
	return nil
}

func pruneDeadProcessStates(
	stateMap, tidNsMap *ebpf.Map,
	stateABI processStateMapABI,
) (int, error) {
	var tid uint32
	state, err := processStateDecodeTargetForABI(stateABI)
	if err != nil {
		return 0, err
	}
	var deadTIDs []uint32
	iter := stateMap.Iterate()
	for iter.Next(&tid, state) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", tid)); errors.Is(err, os.ErrNotExist) {
			deadTIDs = append(deadTIDs, tid)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterate process_state_map: %w", err)
	}

	for _, deadTID := range deadTIDs {
		if err := deleteMapKey(stateMap, &deadTID); err != nil {
			return 0, fmt.Errorf("delete stale process state TID %d: %w", deadTID, err)
		}
		if err := deleteMapKey(tidNsMap, &deadTID); err != nil {
			return 0, fmt.Errorf("delete stale namespace link TID %d: %w", deadTID, err)
		}
	}
	return len(deadTIDs), nil
}

func setupCollectionMode(pid int, pidNs, mntNs uint32, binaryName string, imageName string) error {
	collectionModeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_mode_map", nil)
	if err != nil {
		return fmt.Errorf("open collection_mode_map: %w", err)
	}
	defer collectionModeMap.Close()

	nsKey := PidMountNs{MntNs: mntNs, PidNs: pidNs}
	collectValue := uint32(1)

	if err := collectionModeMap.Put(&nsKey, &collectValue); err != nil {
		return fmt.Errorf("collection_mode_map update failed: %w", err)
	}

	log.Printf("✅ Collection mode enabled (mntns=%d, pidns=%d)", mntNs, pidNs)

	if err := initializeProcessState(pid, 0, pidNs, mntNs); err != nil {
		return fmt.Errorf("process state init failed: %w", err)
	}

	execTimeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/execution_time_map", nil)
	if err != nil {
		return fmt.Errorf("open execution_time_map: %w", err)
	} else {
		defer execTimeMap.Close()

		var execValue ExecutionValue

		if binaryName != "" {
			commBytes := []byte(binaryName)
			if len(commBytes) > 15 {
				commBytes = commBytes[:15]
			}
			copy(execValue.Comm[:], commBytes)
		}

		execValue.ExecutionTime = 0

		if err := execTimeMap.Put(&nsKey, &execValue); err != nil {
			return fmt.Errorf("execution_time_map update failed: %w", err)
		} else {
			log.Printf("✅ Init execution_time_map[%d:%d] = 0 (INIT phase, comm='%s')",
				pidNs, mntNs, binaryName)
		}
	}

	return nil
}

func normalizeImageName(imageName string) string {
	normalized := strings.TrimSpace(imageName)
	normalized = strings.TrimPrefix(normalized, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")
	lastSlash := strings.LastIndexByte(normalized, '/')
	lastSegment := normalized[lastSlash+1:]
	if !strings.Contains(lastSegment, ":") && !strings.Contains(lastSegment, "@") {
		normalized += ":latest"
	}
	return normalized
}

func shouldDeleteSYGMAPolicyOnPoststop(mode string) bool {
	if !policyCRIntegrationEnabled() {
		return false
	}
	switch strings.TrimSpace(mode) {
	case "", "enforcement":

		return true
	default:

		return false
	}
}

func policyCRIntegrationEnabled() bool {
	value := strings.TrimSpace(os.Getenv("SYGMA_POLICY_CR_ENABLED"))
	if value == "" {
		value = strings.TrimSpace(SYGMAPolicyEnabled)
	}
	return strings.EqualFold(value, "true")
}

func handlePoststop() error {
	start := time.Now()
	log.Printf("========== POSTSTOP (Cleanup) ==========")

	var state OCIState
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %w", err)
	}

	mode := os.Getenv("SYGMA_MODE")
	if mode == "" {

		log.Printf("⚠️ No SYGMA_MODE set; continuing namespace cleanup")
	}
	recordHookTimeline(
		"oci_poststop_enter", &state, mode, "", "",
		0, 0, 0, time.Since(start),
	)

	log.Printf("Cleaning up container: %s, PID: %d", state.ID, state.Pid)

	var cleanupErrs []error
	controlPlaneCleanupSucceeded := true

	if shouldDeleteSYGMAPolicyOnPoststop(mode) {
		if err := deleteSYGMAPolicyForContainer(state); !policyDeletionAllowsDataPlaneCleanup(err) {
			cleanupErrs = append(cleanupErrs, err)
			controlPlaneCleanupSucceeded = false
		} else {
			log.Printf("✅ Deleted per-container SYGMAPolicy")
		}
	}
	namespaceCleanupSucceeded := false
	nsInfo, nsErr := getNamespacesFromRedis(state.ID)
	if nsErr != nil && state.Pid > 0 {
		pidNs, mntNs, procErr := getNamespaces(state.Pid)
		if procErr == nil {
			nsInfo = NamespaceInfo{
				PidNs:   pidNs,
				MntNs:   mntNs,
				RootPID: uint32(state.Pid),
			}
			nsErr = nil
			log.Printf("⚠️ Redis namespace lookup failed; recovered namespaces from /proc/%d", state.Pid)
		}
	}

	rootPID := state.Pid
	if rootPID <= 0 && nsInfo.RootPID != 0 {
		rootPID = int(nsInfo.RootPID)
	}
	if rootPID > 0 {
		if err := killTracerForPid(rootPID); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("kill tracer for PID %d: %w", rootPID, err))
		} else {
			log.Printf("✅ Tracer cleanup checked for root PID %d", rootPID)
		}
	}

	if nsErr != nil {
		cleanupErrs = append(cleanupErrs,
			fmt.Errorf("get namespace for container %s: %w", state.ID, nsErr))
		log.Printf("❌ Cannot resolve namespace for cleanup: %v", nsErr)
	} else {
		log.Printf("Resolved cleanup identity from Redis: pidns=%d, mntns=%d, rootPID=%d",
			nsInfo.PidNs, nsInfo.MntNs, nsInfo.RootPID)

		if !controlPlaneCleanupSucceeded {
			log.Printf(
				"⚠️ Skipping eBPF cleanup because the per-container SYGMAPolicy may still exist",
			)
		} else {
			ebpfCleanupErr := cleanupEBPFMaps(nsInfo.PidNs, nsInfo.MntNs, uint32(rootPID))
			if ebpfCleanupErr != nil {
				cleanupErrs = append(cleanupErrs, ebpfCleanupErr)
			} else {
				log.Printf("✅ eBPF maps cleaned")
				namespaceCleanupSucceeded = true
			}
		}
	}

	if err := cleanupContainerMapping(state.ID); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("delete container mapping: %w", err))
	}
	if namespaceCleanupSucceeded {
		if err := deleteNamespaceInfo(state.ID); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete namespace record: %w", err))
		}
	} else {
		log.Printf("⚠️ Preserving container:ns:%s for cleanup retry/forensics (TTL remains)",
			state.ID)
	}

	if err := errors.Join(cleanupErrs...); err != nil {
		return fmt.Errorf("poststop cleanup incomplete: %w", err)
	}

	recordHookTimeline(
		"sygma_cleanup_complete", &state, mode, "", "",
		nsInfo.PidNs, nsInfo.MntNs, 0, time.Since(start),
	)
	log.Printf("✅ Cleanup completed without errors")
	return nil
}

func killTracerForPid(pid int) error {
	cmd := exec.Command("pgrep", "-f", fmt.Sprintf("sygma-tracer.* %d ", pid))
	output, err := cmd.Output()
	if err != nil {
		log.Printf("No tracer found for PID %d", pid)
		return nil
	}

	tracerPids := strings.TrimSpace(string(output))
	if tracerPids == "" {
		return nil
	}

	for _, tracerPid := range strings.Split(tracerPids, "\n") {
		tracerPid = strings.TrimSpace(tracerPid)
		if tracerPid == "" {
			continue
		}

		killCmd := exec.Command("kill", "-9", tracerPid)
		if err := killCmd.Run(); err != nil {
			log.Printf("Warning: failed to kill tracer PID %s: %v", tracerPid, err)
		} else {
			log.Printf("Killed tracer PID %s", tracerPid)
		}
	}

	return nil
}

func cleanupEBPFMaps(pidNs, mntNs, rootPID uint32) error {
	nsKey := PidMountNs{MntNs: mntNs, PidNs: pidNs}
	var cleanupErrs []error

	namespaceMaps := []struct {
		path string
		name string
	}{
		{"/sys/fs/bpf/sygma/execution_time_map", "execution_time_map"},
		{"/sys/fs/bpf/sygma/collection_mode_map", "collection_mode_map"},
		{"/sys/fs/bpf/sygma/pid_mount_ns_map", "pid_mount_ns_map"},
		{"/sys/fs/bpf/sygma/policy_config_map", "policy_config_map"},
	}
	for _, mapSpec := range namespaceMaps {
		pinnedMap, err := ebpf.LoadPinnedMap(mapSpec.path, nil)
		if err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("open %s: %w", mapSpec.name, err))
			continue
		}
		if err := deleteMapKey(pinnedMap, &nsKey); err != nil {
			cleanupErrs = append(
				cleanupErrs,
				fmt.Errorf("delete %s namespace key: %w", mapSpec.name, err),
			)
		}
		pinnedMap.Close()
	}

	transitionMaps := []struct {
		path string
		name string
	}{
		{"/sys/fs/bpf/sygma/observed_transition_map", "observed_transition_map"},
		{"/sys/fs/bpf/sygma/blocked_history", "blocked_history"},
	}
	for _, mapSpec := range transitionMaps {
		transitionMap, err := ebpf.LoadPinnedMap(mapSpec.path, nil)
		if err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("open %s: %w", mapSpec.name, err))
			continue
		}
		var key ObservedTransitionKey
		var value uint32
		var keys []ObservedTransitionKey
		iter := transitionMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				keys = append(keys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate %s: %w", mapSpec.name, err))
		}
		for index := range keys {
			if err := deleteMapKey(transitionMap, &keys[index]); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf(
					"delete %s key %+v: %w", mapSpec.name, keys[index], err,
				))
			}
		}
		transitionMap.Close()
	}

	heartbeatMap, err := ebpf.LoadPinnedMap(
		"/sys/fs/bpf/sygma/transition_check_count", nil,
	)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open transition_check_count: %w", err))
	} else {
		for phase := uint32(0); phase <= 1; phase++ {
			key := TransitionCheckKey{MntNs: mntNs, PidNs: pidNs, Phase: phase}
			if err := deleteMapKey(heartbeatMap, &key); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf(
					"delete transition_check_count key %+v: %w", key, err,
				))
			}
		}
		heartbeatMap.Close()
	}

	ruleMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_state_rule_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open policy_state_rule_map: %w", err))
	} else {
		var key PolicyStateRuleKey
		var value SyscallGraphValue
		var keys []PolicyStateRuleKey
		iter := ruleMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				keys = append(keys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate policy_state_rule_map: %w", err))
		}
		for index := range keys {
			if err := deleteMapKey(ruleMap, &keys[index]); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("delete policy state rule %+v: %w", keys[index], err))
			}
		}
		ruleMap.Close()
	}

	transitionMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/policy_state_transition_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open policy_state_transition_map: %w", err))
	} else {
		var key PolicyStateTransitionKey
		var value uint32
		var keys []PolicyStateTransitionKey
		iter := transitionMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				keys = append(keys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate policy_state_transition_map: %w", err))
		}
		for index := range keys {
			if err := deleteMapKey(transitionMap, &keys[index]); err != nil {
				cleanupErrs = append(
					cleanupErrs,
					fmt.Errorf("delete policy state transition %+v: %w", keys[index], err),
				)
			}
		}
		transitionMap.Close()
	}

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open syscall_graph_map: %w", err))
	} else {
		var key SyscallGraphKey
		var value SyscallGraphValue
		var keys []SyscallGraphKey
		iter := graphMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				keys = append(keys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate syscall_graph_map: %w", err))
		}
		for index := range keys {
			if err := deleteMapKey(graphMap, &keys[index]); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("delete syscall graph key %+v: %w", keys[index], err))
			}
		}
		graphMap.Close()
	}

	collectionGraphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_graph_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open collection_graph_map: %w", err))
	} else {
		deleteCollectionKey := func(phase, previous uint32) {
			key := CollectionGraphKey{
				MntNs:       mntNs,
				PidNs:       pidNs,
				PrevSyscall: previous,
				Phase:       phase,
			}
			if err := deleteMapKey(collectionGraphMap, &key); err != nil {
				cleanupErrs = append(
					cleanupErrs,
					fmt.Errorf("delete collection graph key %+v: %w", key, err),
				)
			}
		}
		for phase := uint32(0); phase <= 1; phase++ {
			for previous := uint32(0); previous <= 334; previous++ {
				deleteCollectionKey(phase, previous)
			}
			for previous := uint32(424); previous <= 448; previous++ {
				deleteCollectionKey(phase, previous)
			}
			deleteCollectionKey(phase, 500)
		}
		collectionGraphMap.Close()
	}

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	var tidsToDelete []uint32
	seen := make(map[uint32]struct{})
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open tid_to_namespace: %w", err))
	} else {
		var tid uint32
		var tidNamespace PidMountNs
		iter := tidNsMap.Iterate()
		for iter.Next(&tid, &tidNamespace) {
			if tidNamespace.PidNs == pidNs && tidNamespace.MntNs == mntNs {
				tidsToDelete = append(tidsToDelete, tid)
				seen[tid] = struct{}{}
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate tid_to_namespace: %w", err))
		}
	}
	if rootPID != 0 {
		if _, exists := seen[rootPID]; !exists {
			tidsToDelete = append(tidsToDelete, rootPID)
		}
	}

	processStateMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
	stateABI := processStateABIUnknown
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open process_state_map: %w", err))
	} else {
		var inspectErr error
		stateABI, _, inspectErr = inspectProcessStateMapABI(processStateMap)
		if inspectErr != nil {
			cleanupErrs = append(cleanupErrs, inspectErr)
		}
	}
	observationStateMap, observationStateErr := ebpf.LoadPinnedMap(
		"/sys/fs/bpf/sygma/observation_state_map", nil,
	)
	if observationStateErr != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf(
			"open observation_state_map: %w", observationStateErr,
		))
	}

	for _, tid := range tidsToDelete {
		stateDeleted := processStateMap != nil
		if processStateMap != nil {
			if err := deleteMapKey(processStateMap, &tid); err != nil {
				stateDeleted = false
				cleanupErrs = append(
					cleanupErrs,
					fmt.Errorf("delete process_state_map TID %d: %w", tid, err),
				)
			}
		}
		if tidNsMap != nil && stateDeleted {
			if err := deleteMapKey(tidNsMap, &tid); err != nil {
				cleanupErrs = append(
					cleanupErrs,
					fmt.Errorf("delete tid_to_namespace TID %d: %w", tid, err),
				)
			}
		}
		if observationStateMap != nil {
			if err := deleteMapKey(observationStateMap, &tid); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf(
					"delete observation_state_map TID %d: %w", tid, err,
				))
			}
		}
	}

	if processStateMap != nil && tidNsMap != nil && stateABI == processStateABIStateMachine {
		pruned, err := pruneDeadProcessStates(processStateMap, tidNsMap, stateABI)
		if err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("prune dead process states: %w", err))
		} else if pruned > 0 {
			log.Printf("Reclaimed %d dead process-state rows", pruned)
		}
	}
	if processStateMap != nil {
		processStateMap.Close()
	}
	if tidNsMap != nil {
		tidNsMap.Close()
	}
	if observationStateMap != nil {
		observationStateMap.Close()
	}

	if err := errors.Join(cleanupErrs...); err != nil {
		return fmt.Errorf("cleanup namespace pidns=%d mntns=%d: %w", pidNs, mntNs, err)
	}
	return nil
}
func deleteMapKey(ebpfMap *ebpf.Map, key interface{}) error {
	err := ebpfMap.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func isPinnedMapMissing(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT)
}

func wrapMapRollbackError(mapName string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("rollback %s: %w", mapName, err)
}

func abortPrestart(
	state OCIState,
	pidNs, mntNs uint32,
	tracer *os.Process,
	cause error,
) error {
	log.Printf("❌ SYGMA instrumentation is not ready; aborting container start: %v", cause)

	var abortErrs []error
	abortErrs = append(abortErrs, cause)
	controlPlaneCleanupSucceeded := true
	if err := killTargetForFailedPrestart(state.Pid); err != nil {
		abortErrs = append(abortErrs, err)
	}
	if tracer != nil {
		if err := tracer.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			abortErrs = append(abortErrs, fmt.Errorf("kill tracer: %w", err))
		}
	}
	if err := os.Remove(tracerReadyFilePath(state.Pid)); err != nil && !errors.Is(err, os.ErrNotExist) {
		abortErrs = append(abortErrs, fmt.Errorf("remove tracer ready file: %w", err))
	}
	if os.Getenv("SYGMA_MODE") == "enforcement" && policyCRIntegrationEnabled() {
		if err := deleteSYGMAPolicyForContainer(state); !policyDeletionAllowsDataPlaneCleanup(err) {
			abortErrs = append(abortErrs, err)
			controlPlaneCleanupSucceeded = false
		}
	}
	namespaceCleanupSucceeded := false
	if pidNs != 0 && mntNs != 0 && controlPlaneCleanupSucceeded {
		ebpfCleanupErr := cleanupEBPFMaps(pidNs, mntNs, uint32(state.Pid))
		if ebpfCleanupErr != nil {
			abortErrs = append(abortErrs, ebpfCleanupErr)
		}
		namespaceCleanupSucceeded = ebpfCleanupErr == nil
	} else if pidNs != 0 && mntNs != 0 {
		log.Printf(
			"⚠️ Skipping failed-prestart eBPF rollback because the per-container SYGMAPolicy may still exist",
		)
	}
	if err := cleanupContainerMapping(state.ID); err != nil {
		abortErrs = append(abortErrs, fmt.Errorf("delete container mapping: %w", err))
	}
	if namespaceCleanupSucceeded {
		if err := deleteNamespaceInfo(state.ID); err != nil {
			abortErrs = append(abortErrs, fmt.Errorf("delete namespace record: %w", err))
		}
	} else {
		log.Printf("⚠️ Preserving container:ns:%s after failed prestart cleanup (TTL remains)",
			state.ID)
	}
	return errors.Join(abortErrs...)
}

func killTargetForFailedPrestart(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("cannot terminate invalid target PID %d", pid)
	}
	if err := signalProcess(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill target PID %d after failed prestart: %w", pid, err)
	}
	return nil
}

func getImageFromConfig(bundlePath string) (string, error) {
	configPath := filepath.Join(bundlePath, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read config.json: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("parse config.json: %w", err)
	}

	if annotations, ok := config["annotations"].(map[string]interface{}); ok {
		imageKeys := []string{
			"io.kubernetes.cri.image-name",
			"io.cri-containerd.image",
			"io.kubernetes.container.image",
		}

		for _, key := range imageKeys {
			if image, ok := annotations[key].(string); ok && image != "" {
				return image, nil
			}
		}
	}

	return "", fmt.Errorf("image not found in config.json annotations")
}

func getPodInfoFromConfig(bundlePath string) (namespace, podName string, err error) {
	configPath := filepath.Join(bundlePath, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", "", err
	}

	if annotations, ok := config["annotations"].(map[string]interface{}); ok {
		if ns, ok := annotations["io.kubernetes.pod.namespace"].(string); ok {
			namespace = ns
		}
		if pn, ok := annotations["io.kubernetes.pod.name"].(string); ok {
			podName = pn
		}
	}

	if namespace == "" || podName == "" {
		return "", "", fmt.Errorf("pod info not found")
	}

	return namespace, podName, nil
}

func getPodInfoForState(state OCIState) (namespace, podName string, err error) {
	if strings.TrimSpace(state.Bundle) != "" {
		if namespace, podName, err = getPodInfoFromConfig(state.Bundle); err == nil {
			return namespace, podName, nil
		}
	}

	if state.Annotations != nil {
		for _, key := range []string{
			"io.kubernetes.pod.namespace",
			"io.kubernetes.cri.sandbox-namespace",
		} {
			if value := strings.TrimSpace(state.Annotations[key]); value != "" {
				namespace = value
				break
			}
		}
		for _, key := range []string{
			"io.kubernetes.pod.name",
			"io.kubernetes.cri.sandbox-name",
		} {
			if value := strings.TrimSpace(state.Annotations[key]); value != "" {
				podName = value
				break
			}
		}
	}
	if namespace == "" || podName == "" {
		return namespace, podName, fmt.Errorf("pod info not found in bundle or OCI state")
	}
	return namespace, podName, nil
}

func getNamespacesFromRedis(containerID string) (NamespaceInfo, error) {
	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("container:ns:%s", containerID)
	data, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		return NamespaceInfo{}, err
	}

	var nsInfo NamespaceInfo
	if err := json.Unmarshal(data, &nsInfo); err != nil {
		return NamespaceInfo{}, err
	}
	if nsInfo.PidNs == 0 || nsInfo.MntNs == 0 {
		return NamespaceInfo{}, fmt.Errorf(
			"invalid namespace record: pidNs=%d mntNs=%d",
			nsInfo.PidNs, nsInfo.MntNs)
	}

	return nsInfo, nil
}

func deleteNamespaceInfo(containerID string) error {
	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("container:ns:%s", containerID)
	return rdb.Del(ctx, key).Err()
}

func cleanupContainerMapping(containerID string) error {
	redisAddr := getEnv("REDIS_ADDR", "redis-service.default.svc.cluster.local:6379")
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mappingKey := fmt.Sprintf("container:mapping:%s", containerID)
	return rdb.Del(ctx, mappingKey).Err()
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	if key == "REDIS_ADDR" && DefaultRedisAddr != "" {
		return DefaultRedisAddr
	}

	return defaultValue
}

func tracerReadyFilePath(containerPid int) string {
	return fmt.Sprintf("%s.%d", tracerReadyFilePrefix, containerPid)
}

func waitForTracerReadyFile(containerPid int, timeout time.Duration) error {
	readyFile := tracerReadyFilePath(containerPid)
	deadline := time.Now().Add(timeout)

	log.Printf("⏳ Waiting for tracer ready file: %s", readyFile)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyFile); err == nil {
			log.Printf("✅ Tracer ready file found")
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("timeout: tracer ready file not created within %v", timeout)
}
