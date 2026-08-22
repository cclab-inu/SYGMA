//go:build amd64

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const bpfFSPath = "/sys/fs/bpf"

const (
	expectedProcessStateValueSize = 28
	expectedCollectionGraphFlags  = uint32(unix.BPF_F_NO_PREALLOC)
	defaultLoaderLockPath         = "/run/sygma-ebpf-loader.lock"
)

// These pins belonged to policy engines, diagnostics, or audit-compression
// paths that are not part of the current evaluation build. Keep the list exact:
// migration must never sweep arbitrary objects from bpffs.
var legacyPinnedMapNames = []string{
	"app_cgroups",
	"app_sc_bins",
	"app_sc_counts",
	"app_sc_first_seen",
	"app_sc_meta",
	"app_tids",
	"container_info_map",
	"events",
	"huffman_context_map",
	"huffman_enabled",
	"huffman_rules_1",
	"huffman_rules_2",
	"huffman_rules_3",
	"huffman_rules_str_1",
	"huffman_rules_str_2",
	"huffman_rules_str_3",
	"huffman_stats_map",
	"main_process_map",
	"ns_image_map",
	"observed_misses",
	"per_cpu_buffers",
	"policy_decision_map",
	"policy_location_transition_map",
	"prog_map",
	"syscall_stats",
	"syscall_stats_ns_map",
	"syscall_transition_map",
	"thread_last_syscall",
	"tid_syscall_queue",
	"trigger_counter_map",
}

// Availability evaluation observes policy misses without changing the
// tracee's syscall result.
const observationMode = true

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf monitoring.c -- -I../headers

func setupTailCalls(objs *bpfObjects) error {
	if objs.ProgArray == nil {
		return errors.New("ProgArray map is nil")
	}

	programs := map[uint32]*ebpf.Program{
		0: objs.Stage2Verify,
		1: objs.CollectSyscalls,
	}
	for index, program := range programs {
		if program == nil {
			return fmt.Errorf("required tail-call program at index %d is nil", index)
		}
		if err := objs.ProgArray.Put(index, program); err != nil {
			return fmt.Errorf("install tail-call program at index %d: %w", index, err)
		}
	}
	return nil
}

type namedBPFProgram struct {
	name string
	prog *ebpf.Program
}

func programsWithPrefix(programs *bpfPrograms, prefix string) ([]namedBPFProgram, error) {
	value := reflect.ValueOf(programs)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, errors.New("invalid BPF program collection")
	}
	value = value.Elem()
	programType := value.Type()

	var matches []namedBPFProgram
	for index := 0; index < value.NumField(); index++ {
		name := programType.Field(index).Tag.Get("ebpf")
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		field := value.Field(index)
		if field.IsNil() {
			return nil, fmt.Errorf("required BPF program %s is nil", name)
		}
		program, ok := field.Interface().(*ebpf.Program)
		if !ok {
			return nil, fmt.Errorf("field for %s is not an eBPF program", name)
		}
		matches = append(matches, namedBPFProgram{name: name, prog: program})
	}

	sort.Slice(matches, func(left, right int) bool {
		return matches[left].name < matches[right].name
	})
	return matches, nil
}

func closeLinks(links []link.Link) {
	for _, attachedLink := range links {
		attachedLink.Close()
	}
}

func acquireLoaderLock() (*os.File, error) {
	lockPath := strings.TrimSpace(os.Getenv("SYGMA_LOADER_LOCK_FILE"))
	if lockPath == "" {
		lockPath = defaultLoaderLockPath
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open loader lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf(
			"acquire loader lock %s (is another SYGMA core running?): %w",
			lockPath, err,
		)
	}
	return lockFile, nil
}

func closeLoaderLock(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

func isMissingPin(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT)
}

func unpinMapIfPresent(pinPath string) error {
	pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil)
	if isMissingPin(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pinned map %s: %w", pinPath, err)
	}
	defer pinnedMap.Close()

	if err := pinnedMap.Unpin(); err != nil {
		return fmt.Errorf("unpin map %s: %w", pinPath, err)
	}
	return nil
}

func processStateMapNeedsMigration(valueSize uint32) bool {
	return valueSize != expectedProcessStateValueSize
}

func collectionGraphMapNeedsMigration(flags uint32) bool {
	return flags&expectedCollectionGraphFlags != expectedCollectionGraphFlags
}

func migrateCollectionGraphMap(pinpath string) error {
	mapPath := path.Join(pinpath, "collection_graph_map")
	pinnedMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if isMissingPin(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pinned collection graph map %s: %w", mapPath, err)
	}

	info, err := pinnedMap.Info()
	if err != nil {
		pinnedMap.Close()
		return fmt.Errorf("read pinned collection graph map metadata %s: %w", mapPath, err)
	}
	if !collectionGraphMapNeedsMigration(info.Flags) {
		return pinnedMap.Close()
	}

	if err := pinnedMap.Unpin(); err != nil {
		pinnedMap.Close()
		return fmt.Errorf("replace preallocated collection graph map: %w", err)
	}
	if err := pinnedMap.Close(); err != nil {
		return fmt.Errorf("close migrated collection graph map: %w", err)
	}
	log.Printf(
		"Migrated collection_graph_map flags from %#x to %#x",
		info.Flags, expectedCollectionGraphFlags,
	)
	return nil
}

func migrateProcessStateMap(pinpath string) error {
	processStatePath := path.Join(pinpath, "process_state_map")
	pinnedMap, err := ebpf.LoadPinnedMap(processStatePath, nil)
	if isMissingPin(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pinned process-state map %s: %w", processStatePath, err)
	}

	valueSize := pinnedMap.ValueSize()
	if !processStateMapNeedsMigration(valueSize) {
		return pinnedMap.Close()
	}

	if err := pinnedMap.Unpin(); err != nil {
		pinnedMap.Close()
		return fmt.Errorf(
			"replace process-state map with value size %d (expected %d): %w",
			valueSize, expectedProcessStateValueSize, err,
		)
	}
	if err := pinnedMap.Close(); err != nil {
		return fmt.Errorf("close migrated process-state map: %w", err)
	}

	// TID ownership rows are ephemeral and coupled to process-state entries.
	// Keeping them across an ABI replacement can associate a recycled TID with
	// a namespace even though its corresponding process state was discarded.
	if err := unpinMapIfPresent(path.Join(pinpath, "tid_to_namespace")); err != nil {
		return err
	}
	log.Printf(
		"Migrated pinned process_state_map ABI from %d to %d bytes",
		valueSize, expectedProcessStateValueSize,
	)
	return nil
}

func removeLegacyPhasePins(pinpath string) error {
	linkDir := path.Join(pinpath, "phase_links")
	entries, err := os.ReadDir(linkDir)
	if err != nil && !isMissingPin(err) {
		return fmt.Errorf("inspect legacy phase-link directory %s: %w", linkDir, err)
	}
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				return fmt.Errorf("unexpected directory in legacy phase-link path: %s", entry.Name())
			}
			linkPath := path.Join(linkDir, entry.Name())
			pinnedLink, loadErr := link.LoadPinnedLink(linkPath, nil)
			if loadErr != nil {
				return fmt.Errorf("inspect legacy pinned link %s: %w", linkPath, loadErr)
			}
			if unpinErr := pinnedLink.Unpin(); unpinErr != nil {
				pinnedLink.Close()
				return fmt.Errorf("unpin legacy phase link %s: %w", linkPath, unpinErr)
			}
			if closeErr := pinnedLink.Close(); closeErr != nil {
				return fmt.Errorf("close legacy phase link %s: %w", linkPath, closeErr)
			}
		}
		if err := os.Remove(linkDir); err != nil && !isMissingPin(err) {
			return fmt.Errorf("remove empty legacy phase-link directory %s: %w", linkDir, err)
		}
	}

	programPath := path.Join(pinpath, "phase_transition_uprobe")
	pinnedProgram, err := ebpf.LoadPinnedProgram(programPath, nil)
	if isMissingPin(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy pinned program %s: %w", programPath, err)
	}
	defer pinnedProgram.Close()
	if err := pinnedProgram.Unpin(); err != nil {
		return fmt.Errorf("unpin legacy phase-transition program %s: %w", programPath, err)
	}
	return nil
}

func migratePinnedState(pinpath string) error {
	if err := removeLegacyPhasePins(pinpath); err != nil {
		return err
	}
	for _, mapName := range legacyPinnedMapNames {
		if err := unpinMapIfPresent(path.Join(pinpath, mapName)); err != nil {
			return err
		}
	}
	if err := migrateCollectionGraphMap(pinpath); err != nil {
		return err
	}
	return migrateProcessStateMap(pinpath)
}

func policyEntryKprobeTarget(programName string) (string, string, error) {
	route := "LSM-routed observation"
	syscallName := ""

	switch {
	case strings.HasPrefix(programName, "kprobe_sys_"):
		syscallName = strings.TrimPrefix(programName, "kprobe_sys_")
	case strings.HasPrefix(programName, "kprobe_sigkill_"):
		syscallName = strings.TrimPrefix(programName, "kprobe_sigkill_")
		route = "direct observation"
	default:
		return "", "", fmt.Errorf("unsupported policy-entry kprobe %s", programName)
	}

	switch syscallName {
	case "stat":
		return "__x64_sys_newstat", route, nil
	case "fstat":
		return "__x64_sys_newfstat", route, nil
	case "lstat":
		return "__x64_sys_newlstat", route, nil
	case "sendfile":
		return "__x64_sys_sendfile64", route, nil
	case "umount2":
		return "__x64_sys_umount", route, nil
	default:
		return "__x64_sys_" + syscallName, route, nil
	}
}

func attachPolicyEntryKprobes(objs *bpfObjects) ([]link.Link, error) {
	lsmKprobes, err := programsWithPrefix(&objs.bpfPrograms, "kprobe_sys_")
	if err != nil {
		return nil, err
	}
	sigkillKprobes, err := programsWithPrefix(&objs.bpfPrograms, "kprobe_sigkill_")
	if err != nil {
		return nil, err
	}
	if len(lsmKprobes) != 141 || len(sigkillKprobes) != 4 {
		return nil, fmt.Errorf(
			"expected 141 dedicated and 4 direct observation kprobes, found %d and %d",
			len(lsmKprobes), len(sigkillKprobes),
		)
	}

	kprobes := append(lsmKprobes, sigkillKprobes...)
	sort.Slice(kprobes, func(left, right int) bool {
		return kprobes[left].name < kprobes[right].name
	})

	links := make([]link.Link, 0, len(kprobes))
	for _, kprobe := range kprobes {
		kernelFunc, route, err := policyEntryKprobeTarget(kprobe.name)
		if err != nil {
			closeLinks(links)
			return nil, err
		}

		attached, err := link.Kprobe(kernelFunc, kprobe.prog, nil)
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf(
				"attach %s kprobe %s to %s: %w",
				route, kprobe.name, kernelFunc, err,
			)
		}
		links = append(links, attached)
	}
	return links, nil
}

func cleanupPinnedMaps(pinpath string) {
	mapNames := []string{
		"execution_time_map",
		"syscall_graph_map",
		"collection_mode_map",
		"process_state_map",
		"pid_mount_ns_map",
		"collection_graph_map",
		"tid_to_namespace",
		"policy_config_map",
		"policy_state_rule_map",
		"policy_state_transition_map",
		"route_counter_map",
	}

	for _, mapName := range mapNames {
		pinnedMap, err := ebpf.LoadPinnedMap(path.Join(pinpath, mapName), nil)
		if err != nil {
			continue
		}
		_ = pinnedMap.Unpin()
		pinnedMap.Close()
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	pinpath := path.Join(bpfFSPath, "sygma")
	if err := os.MkdirAll(pinpath, os.ModePerm); err != nil {
		log.Fatalf("create BPF pin directory: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock limit: %v", err)
	}

	loaderLock, err := acquireLoaderLock()
	if err != nil {
		log.Fatalf("establish exclusive loader ownership: %v", err)
	}
	defer closeLoaderLock(loaderLock)

	if err := migratePinnedState(pinpath); err != nil {
		log.Fatalf(
			"migrate pinned state before loading eBPF objects (stop the old core and quiesce traced containers first): %v",
			err,
		)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinpath},
	}); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	if err := setupTailCalls(&objs); err != nil {
		log.Fatalf("set up tail calls: %v", err)
	}

	execveReturn, err := link.Kretprobe("__x64_sys_execve", objs.KretprobeExecve, nil)
	if err != nil {
		log.Fatalf("attach execve return probe: %v", err)
	}
	defer execveReturn.Close()

	ptraceNotify, err := link.Kprobe("ptrace_notify", objs.Stage1Filter, nil)
	if err != nil {
		log.Fatalf("attach ptrace_notify probe: %v", err)
	}
	defer ptraceNotify.Close()

	processFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		log.Fatalf("attach process-fork tracepoint: %v", err)
	}
	defer processFork.Close()

	processExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleProcessExit, nil)
	if err != nil {
		log.Fatalf("attach process-exit tracepoint: %v", err)
	}
	defer processExit.Close()

	signalDeliver, err := link.Tracepoint("signal", "signal_deliver", objs.HandleSignalDeliver, nil)
	if err != nil {
		log.Fatalf("attach signal-deliver tracepoint: %v", err)
	}
	defer signalDeliver.Close()

	// Neutral application-syscall observer: fires for every syscall on the
	// host, but only ever writes to app_sc_bins/app_sc_counts/app_sc_meta for
	// tids registered by kretprobe_execve/handle_fork (see monitoring.c).
	appSyscallEnter, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleAppSyscallEnter,
	})
	if err != nil {
		log.Fatalf("attach sys_enter raw tracepoint: %v", err)
	}
	defer appSyscallEnter.Close()

	policyEntryLinks, err := attachPolicyEntryKprobes(&objs)
	if err != nil {
		log.Fatalf("attach dedicated policy-entry probes: %v", err)
	}
	defer closeLinks(policyEntryLinks)

	readyKey := uint32(0)
	readyValue := uint32(1)
	if err := objs.EnforcementReadyMap.Put(&readyKey, &readyValue); err != nil {
		log.Fatalf("enable dedicated policy routing: %v", err)
	}
	defer func() {
		disabled := uint32(0)
		if err := objs.EnforcementReadyMap.Put(&readyKey, &disabled); err != nil {
			log.Printf("warning: disable dedicated policy routing: %v", err)
		}
	}()

	log.Printf(
		"SYGMA observation mode ready (%d dedicated policy-entry probes)",
		len(policyEntryLinks),
	)
	<-stopper

	log.Println("Shutting down SYGMA eBPF monitor")
	cleanupPinnedMaps(pinpath)
}
