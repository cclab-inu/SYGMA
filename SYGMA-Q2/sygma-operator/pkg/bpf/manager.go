package bpf

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cilium/ebpf"
)

type Manager struct {
	syscallGraphMap *ebpf.Map
}

// CollectionGraphKey collection_graph_map
type CollectionGraphKey struct {
	MntNs       uint32
	PidNs       uint32
	PrevSyscall uint32
	Phase       uint32
}

type ExecvePathKey struct {
	MntNs uint32
	PidNs uint32
	Phase uint32
}

type ExecvePathValue struct {
	Count uint32
	Paths [16][16]byte
}

// CollectionGraphValue collection_graph_map
type CollectionGraphValue struct {
	AllowedMask [45]byte
}

// ExecutionValue execution_time_map
type ExecutionValue struct {
	Comm          [16]byte
	ExecutionTime uint32
}

// PidMountNs execution_time_map
type PidMountNs struct {
	MntNs uint32
	PidNs uint32
}

// ⭐ Sentinel
const (
	SyscallSentinel = 500
)

// ⭐ CollectFromGraphMap -  namespace
func (m *Manager) CollectFromGraphMap(pidNs, mntNs uint32) (map[string][]int, error) {
	logger := ctrl.Log.WithName("bpf-manager")

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_graph_map", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection_graph_map: %w", err)
	}
	defer graphMap.Close()

	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("failed to determine possible CPU count for per-CPU graph map: %w", err)
	}
	logger.Info("Collecting syscall graph with namespace filter",
		"pidNs", pidNs,
		"mntNs", mntNs,
		"numCPUs", numCPUs)

	result := make(map[string][]int)
	phaseCount := map[uint32]int{0: 0, 1: 0}

	// ⭐  syscall  (500 !)
	syscallsToCollect := []uint32{SyscallSentinel} // 500

	// 0-334
	for i := uint32(0); i <= 334; i++ {
		syscallsToCollect = append(syscallsToCollect, i)
	}

	// 424-448
	for i := uint32(424); i <= 448; i++ {
		syscallsToCollect = append(syscallsToCollect, i)
	}

	for phase := uint32(0); phase <= 1; phase++ {
		for _, prevSyscall := range syscallsToCollect {
			// ⭐  namespace
			key := CollectionGraphKey{
				MntNs:       mntNs,
				PidNs:       pidNs,
				PrevSyscall: prevSyscall,
				Phase:       phase,
			}

			perCPUValues := make([]CollectionGraphValue, numCPUs)

			if err := graphMap.Lookup(&key, perCPUValues); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					continue
				}
				return nil, fmt.Errorf(
					"failed to look up collection_graph_map key (pidNs=%d, mntNs=%d, prevSyscall=%d, phase=%d): %w",
					pidNs, mntNs, prevSyscall, phase, err,
				)
			}

			mergedMask := [45]uint8{}
			hasData := false

			for _, cpuValue := range perCPUValues {
				for i := 0; i < 45; i++ {
					if cpuValue.AllowedMask[i] != 0 {
						hasData = true
					}
					mergedMask[i] |= cpuValue.AllowedMask[i]
				}
			}

			if !hasData {
				continue
			}

			allowedSyscalls := m.bitmaskToSyscalls(mergedMask)

			// ⭐  : "prevSyscall:phase"
			transKey := fmt.Sprintf("%d:%d", prevSyscall, phase)
			result[transKey] = allowedSyscalls
			phaseCount[phase]++

			// 500
			if prevSyscall == SyscallSentinel {
				logger.Info("✅ Collected START transition",
					"phase", phase,
					"to_syscalls", len(allowedSyscalls),
					"first_few", allowedSyscalls[:min(5, len(allowedSyscalls))])
			}
		}
	}

	logger.Info("Collection complete (namespace-filtered)",
		"pidNs", pidNs,
		"mntNs", mntNs,
		"phase0_transitions", phaseCount[0],
		"phase1_transitions", phaseCount[1])

	return result, nil
}

// ⭐ CleanupAllStaleData -     (   )
func (m *Manager) CleanupAllStaleData() error {
	log.Println("🧹 Starting cleanup of all stale collection data")

	var cleanupErrors []error
	deletedGraphEntries := 0
	deletedModeEntries := 0
	deletedTIDs := 0

	collectionModeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_mode_map", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open collection_mode_map: %w", err))
	} else {
		defer collectionModeMap.Close()

		type CollectionModeKey struct {
			MntNs uint32
			PidNs uint32
		}

		var modeKey CollectionModeKey
		var modeValue uint32
		var modeKeysToDelete []CollectionModeKey

		modeIter := collectionModeMap.Iterate()
		for modeIter.Next(&modeKey, &modeValue) {
			modeKeysToDelete = append(modeKeysToDelete, modeKey)
		}
		if err := modeIter.Err(); err != nil {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("failed to iterate collection_mode_map: %w", err))
		}

		for _, key := range modeKeysToDelete {
			if err := collectionModeMap.Delete(&key); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf(
						"failed to delete collection_mode_map key (mntNs=%d, pidNs=%d): %w",
						key.MntNs, key.PidNs, err,
					))
				}
			} else {
				deletedModeEntries++
			}
		}
	}

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_graph_map", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open collection_graph_map: %w", err))
	} else {
		defer graphMap.Close()

		numCPUs, cpuErr := ebpf.PossibleCPU()
		if cpuErr != nil {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("failed to determine possible CPU count for collection_graph_map cleanup: %w", cpuErr))
		} else {
			var graphKey CollectionGraphKey
			graphValues := make([]CollectionGraphValue, numCPUs)
			var graphKeysToDelete []CollectionGraphKey

			graphIter := graphMap.Iterate()
			for graphIter.Next(&graphKey, graphValues) {
				graphKeysToDelete = append(graphKeysToDelete, graphKey)
			}
			if err := graphIter.Err(); err != nil {
				cleanupErrors = append(cleanupErrors,
					fmt.Errorf("failed to iterate per-CPU collection_graph_map: %w", err))
			}

			for _, key := range graphKeysToDelete {
				if err := graphMap.Delete(&key); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						cleanupErrors = append(cleanupErrors, fmt.Errorf(
							"failed to delete collection_graph_map key (mntNs=%d, pidNs=%d, prevSyscall=%d, phase=%d): %w",
							key.MntNs, key.PidNs, key.PrevSyscall, key.Phase, err,
						))
					}
				} else {
					deletedGraphEntries++
				}
			}
		}
	}

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open tid_to_namespace: %w", err))
	} else {
		defer tidNsMap.Close()

		processStateMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open process_state_map: %w", err))
		} else {
			defer processStateMap.Close()

			var tid uint32
			var nsKey struct {
				MntNs uint32
				PidNs uint32
			}

			var tidsToDelete []uint32
			tidIter := tidNsMap.Iterate()

			for tidIter.Next(&tid, &nsKey) {
				tidsToDelete = append(tidsToDelete, tid)
			}
			if err := tidIter.Err(); err != nil {
				cleanupErrors = append(cleanupErrors,
					fmt.Errorf("failed to iterate tid_to_namespace: %w", err))
			}

			for _, tid := range tidsToDelete {
				processStateRemoved := true
				if err := processStateMap.Delete(&tid); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						processStateRemoved = false
						cleanupErrors = append(cleanupErrors,
							fmt.Errorf("failed to delete process_state_map TID %d: %w", tid, err))
					}
				} else {
					deletedTIDs++
				}

				if processStateRemoved {
					if err := tidNsMap.Delete(&tid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						cleanupErrors = append(cleanupErrors,
							fmt.Errorf("failed to delete tid_to_namespace TID %d: %w", tid, err))
					}
				}
			}
		}
	}

	log.Printf("✅ Cleanup complete: deleted %d graph entries, %d mode entries, %d process states",
		deletedGraphEntries, deletedModeEntries, deletedTIDs)

	return errors.Join(cleanupErrors...)
}

func (m *Manager) UpdateBlockedPaths(pidNs, mntNs uint32, blockedPaths map[string][]string) error {
	pathMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/execve_path_map", nil)
	if err != nil {
		return fmt.Errorf("failed to open execve_path_map: %w", err)
	}
	defer pathMap.Close()

	for phaseName, paths := range blockedPaths {
		var phase uint32
		if phaseName == "initPhase" {
			phase = 0
		} else if phaseName == "mainPhase" {
			phase = 1
		} else {
			continue
		}

		key := ExecvePathKey{
			MntNs: mntNs,
			PidNs: pidNs,
			Phase: phase,
		}

		value := ExecvePathValue{
			Count: uint32(len(paths)),
		}

		for i, path := range paths {
			if i >= 16 {
				break
			}

			pathBytes := []byte(path)
			if len(pathBytes) > 16 {
				pathBytes = pathBytes[:16]
			}

			copy(value.Paths[i][:], pathBytes)
		}

		if err := pathMap.Put(&key, &value); err != nil {
			return fmt.Errorf("failed to update blocked paths for phase %d: %w", phase, err)
		}

		log.Printf("✅ Updated %d blocked paths for phase %d (pidns=%d, mntns=%d)",
			len(paths), phase, pidNs, mntNs)
	}

	return nil
}

// CheckMainPhaseStarted checks if the container has transitioned to MAIN phase
// by reading execution_time_map. Returns true if execution_time == 1 (MAIN phase started)
func (m *Manager) CheckMainPhaseStarted(pidNs, mntNs uint32) (bool, error) {
	execTimeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/execution_time_map", nil)
	if err != nil {
		return false, fmt.Errorf("failed to open execution_time_map: %w", err)
	}
	defer execTimeMap.Close()

	key := PidMountNs{
		MntNs: mntNs,
		PidNs: pidNs,
	}

	var value ExecutionValue
	if err := execTimeMap.Lookup(&key, &value); err != nil {
		// Key not found means container hasn't started yet or already cleaned up
		return false, fmt.Errorf("namespace not found in execution_time_map: %w", err)
	}

	// execution_time == 0: INIT phase
	// execution_time == 1: MAIN phase (main binary execve detected)
	mainPhaseStarted := value.ExecutionTime == 1

	log.Printf("⭐ Phase check: pidns=%d, mntns=%d, comm=%s, execution_time=%d, main_phase=%v",
		pidNs, mntNs, string(value.Comm[:]), value.ExecutionTime, mainPhaseStarted)

	return mainPhaseStarted, nil
}

func (m *Manager) bitmaskToSyscalls(mask [45]byte) []int {
	syscalls := make([]int, 0)

	// Big-endian   (44 → 0)
	for byteIdx := 0; byteIdx < 45; byteIdx++ {
		actualByteIdx := 44 - byteIdx
		byteValue := mask[actualByteIdx]

		if byteValue == 0 {
			continue
		}

		for bitOffset := 0; bitOffset < 8; bitOffset++ {
			if byteValue&(1<<bitOffset) != 0 {
				bitIndex := byteIdx*8 + bitOffset
				syscallNum := m.bitIndexToSyscall(uint32(bitIndex))
				if syscallNum != 0xFFFFFFFF {
					syscalls = append(syscalls, int(syscallNum))
				}
			}
		}
	}

	return syscalls
}

func (m *Manager) bitIndexToSyscall(bitIndex uint32) uint32 {
	if bitIndex <= 334 {
		return bitIndex
	}
	if bitIndex >= 335 && bitIndex < 360 {
		return 424 + (bitIndex - 335)
	}
	return 0xFFFFFFFF
}

func (m *Manager) CollectInitPhaseData() (map[string][]int, error) {
	log.Println("CollectInitPhaseData is deprecated, use CollectFromGraphMap instead")
	return make(map[string][]int), nil
}

func NewManager() (*Manager, error) {
	syscallGraphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load syscall_graph_map: %w", err)
	}

	return &Manager{
		syscallGraphMap: syscallGraphMap,
	}, nil
}

func (m *Manager) Close() {
	if m.syscallGraphMap != nil {
		m.syscallGraphMap.Close()
	}
}

type SyscallGraphKey struct {
	MntNs       uint32
	PidNs       uint32
	FromSyscall uint32
	Phase       uint32
}

type SyscallGraphValue struct {
	AllowedMask [45]byte
}

type SyscallQueue struct {
	Syscalls [64]uint32
	Head     uint32
	Count    uint32
}

func syscallToBitIndex(syscallNum uint32) uint32 {
	if syscallNum <= 334 {
		return syscallNum
	}
	if syscallNum >= 424 && syscallNum <= 448 {
		return 335 + (syscallNum - 424)
	}
	return 0xFFFFFFFF
}

// ⭐
func isSyscallInValidRange(syscall uint32) bool {
	// Sentinel
	if syscall == SyscallSentinel {
		return true
	}

	//  syscall
	if syscall <= 334 {
		return true
	}

	if syscall >= 424 && syscall <= 448 {
		return true
	}

	return false
}

func (m *Manager) UpdateSyscallGraphMapByNamespace(pidNs, mntNs, phase uint32, transitions map[string][]int) error {
	log.Printf("🔧 UpdateSyscallGraphMapByNamespace: pidNs=%d, mntNs=%d, phase=%d, transitions=%d",
		pidNs, mntNs, phase, len(transitions))

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		return fmt.Errorf("failed to open syscall_graph_map: %w", err)
	}
	defer graphMap.Close()

	updatedCount := 0

	for prevSyscallStr, allowedSyscalls := range transitions {
		prevSyscall, err := strconv.ParseUint(prevSyscallStr, 10, 32)
		if err != nil {
			log.Printf("⚠️ Invalid syscall string: %s", prevSyscallStr)
			continue
		}

		// ⭐ 500
		if !isSyscallInValidRange(uint32(prevSyscall)) {
			log.Printf("⚠️ Invalid from_syscall: %d (not in valid range)", prevSyscall)
			continue
		}

		key := SyscallGraphKey{
			MntNs:       mntNs,
			PidNs:       pidNs,
			FromSyscall: uint32(prevSyscall),
			Phase:       phase,
		}

		// Bitmask
		value := SyscallGraphValue{}

		for _, toSyscall := range allowedSyscalls {
			// ⭐ to_syscall 0-359  (500 to_syscall   )
			if toSyscall < 0 || toSyscall >= 360 {
				log.Printf("⚠️ Invalid to_syscall: %d (out of 0-359 range)", toSyscall)
				continue
			}

			bitIndex := syscallToBitIndex(uint32(toSyscall))
			if bitIndex >= 360 {
				log.Printf("⚠️ Syscall %d converts to invalid bit index", toSyscall)
				continue
			}

			bytePos := bitIndex >> 3
			bitOffset := bitIndex & 7
			byteIndex := 44 - bytePos

			value.AllowedMask[byteIndex] |= (1 << bitOffset)
		}

		if err := graphMap.Put(&key, &value); err != nil {
			log.Printf("❌ Failed to update: %v", err)
			return fmt.Errorf("failed to update syscall %d: %w", prevSyscall, err)
		}

		updatedCount++

		// 500
		if uint32(prevSyscall) == SyscallSentinel {
			log.Printf("✅ Updated START (500)→%v (phase=%d)", allowedSyscalls, phase)
		}
	}

	log.Printf("✅ Updated %d transitions for phase %d", updatedCount, phase)
	return nil
}

// ⭐ CleanupCollectionMode -  namespace
func (m *Manager) CleanupCollectionMode(pidNs, mntNs uint32) error {
	log.Printf("🧹 Cleaning up collection mode for namespace: pidNs=%d, mntNs=%d", pidNs, mntNs)

	var cleanupErrors []error
	deletedGraphEntries := 0
	deletedTIDs := 0

	collectionModeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_mode_map", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open collection_mode_map: %w", err))
	} else {
		defer collectionModeMap.Close()

		key := struct {
			MntNs uint32
			PidNs uint32
		}{
			MntNs: mntNs,
			PidNs: pidNs,
		}

		if err := collectionModeMap.Delete(&key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf(
					"failed to delete collection_mode_map key (mntNs=%d, pidNs=%d): %w",
					mntNs, pidNs, err,
				))
			}
		} else {
			log.Printf("✅ Cleaned collection_mode_map for pidns=%d, mntns=%d", pidNs, mntNs)
		}
	}

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_graph_map", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open collection_graph_map: %w", err))
	} else {
		defer graphMap.Close()

		syscallsToDelete := []uint32{SyscallSentinel}
		for i := uint32(0); i <= 334; i++ {
			syscallsToDelete = append(syscallsToDelete, i)
		}
		for i := uint32(424); i <= 448; i++ {
			syscallsToDelete = append(syscallsToDelete, i)
		}

		for phase := uint32(0); phase <= 1; phase++ {
			for _, prevSyscall := range syscallsToDelete {
				key := CollectionGraphKey{
					MntNs:       mntNs,
					PidNs:       pidNs,
					PrevSyscall: prevSyscall,
					Phase:       phase,
				}

				if err := graphMap.Delete(&key); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						cleanupErrors = append(cleanupErrors, fmt.Errorf(
							"failed to delete collection_graph_map key (mntNs=%d, pidNs=%d, prevSyscall=%d, phase=%d): %w",
							mntNs, pidNs, prevSyscall, phase, err,
						))
					}
				} else {
					deletedGraphEntries++
				}
			}
		}
	}

	log.Printf("✅ Cleaned %d entries from collection_graph_map", deletedGraphEntries)

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to open tid_to_namespace: %w", err))
	} else {
		defer tidNsMap.Close()

		processStateMap, processStateErr := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
		if processStateErr != nil {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("failed to open process_state_map: %w", processStateErr))
		} else {
			defer processStateMap.Close()

			var tid uint32
			var nsKey struct {
				MntNs uint32
				PidNs uint32
			}

			var tidsToDelete []uint32
			tidIter := tidNsMap.Iterate()
			for tidIter.Next(&tid, &nsKey) {
				if nsKey.PidNs == pidNs && nsKey.MntNs == mntNs {
					tidsToDelete = append(tidsToDelete, tid)
				}
			}
			if err := tidIter.Err(); err != nil {
				cleanupErrors = append(cleanupErrors,
					fmt.Errorf("failed to iterate tid_to_namespace: %w", err))
			}

			for _, tid := range tidsToDelete {
				processStateRemoved := true
				if err := processStateMap.Delete(&tid); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						processStateRemoved = false
						cleanupErrors = append(cleanupErrors,
							fmt.Errorf("failed to delete process_state_map TID %d: %w", tid, err))
					}
				} else {
					deletedTIDs++
				}

				if processStateRemoved {
					if err := tidNsMap.Delete(&tid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						cleanupErrors = append(cleanupErrors,
							fmt.Errorf("failed to delete tid_to_namespace TID %d: %w", tid, err))
					}
				}
			}
		}
	}

	log.Printf("✅ Cleaned %d TIDs from process_state_map for pidns=%d, mntns=%d",
		deletedTIDs, pidNs, mntNs)

	return errors.Join(cleanupErrors...)
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
