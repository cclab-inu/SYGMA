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

type CollectionGraphKey struct {
	MntNs       uint32
	PidNs       uint32
	PrevSyscall uint32
	Phase       uint32
}

type CollectionGraphValue struct {
	AllowedMask [45]byte
}

type ExecutionValue struct {
	Comm          [16]byte
	ExecutionTime uint32
}

type PidMountNs struct {
	MntNs uint32
	PidNs uint32
}

const (
	SyscallSentinel = 500
)

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
	initTransitionCount := 0
	const phase uint32 = 0

	syscallsToCollect := []uint32{SyscallSentinel}

	for i := uint32(0); i <= 334; i++ {
		syscallsToCollect = append(syscallsToCollect, i)
	}

	for i := uint32(424); i <= 448; i++ {
		syscallsToCollect = append(syscallsToCollect, i)
	}

	for _, prevSyscall := range syscallsToCollect {

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

		transKey := fmt.Sprintf("%d:%d", prevSyscall, phase)
		result[transKey] = allowedSyscalls
		initTransitionCount++

		if prevSyscall == SyscallSentinel {
			logger.Info("✅ Collected START transition",
				"phase", phase,
				"to_syscalls", len(allowedSyscalls),
				"first_few", allowedSyscalls[:min(5, len(allowedSyscalls))])
		}
	}

	logger.Info("Collection complete (namespace-filtered)",
		"pidNs", pidNs,
		"mntNs", mntNs,
		"init_transitions", initTransitionCount)

	return result, nil
}

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

		return false, fmt.Errorf("namespace not found in execution_time_map: %w", err)
	}

	mainPhaseStarted := value.ExecutionTime == 1

	log.Printf("⭐ Phase check: pidns=%d, mntns=%d, comm=%s, execution_time=%d, main_phase=%v",
		pidNs, mntNs, string(value.Comm[:]), value.ExecutionTime, mainPhaseStarted)

	return mainPhaseStarted, nil
}

func (m *Manager) bitmaskToSyscalls(mask [45]byte) []int {
	syscalls := make([]int, 0)

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

func isSyscallInValidRange(syscall uint32) bool {

	if syscall == SyscallSentinel {
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

func (m *Manager) UpdateSyscallGraphMapByNamespace(pidNs, mntNs, phase uint32, transitions map[string][]int) error {
	if phase != 0 {
		return fmt.Errorf("only init bootstrap phase 0 is supported")
	}
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

		value := SyscallGraphValue{}

		for _, toSyscall := range allowedSyscalls {

			if toSyscall < 0 || toSyscall == int(SyscallSentinel) ||
				!isSyscallInValidRange(uint32(toSyscall)) {
				log.Printf("⚠️ Invalid to_syscall: %d (unsupported syscall number)", toSyscall)
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

		if uint32(prevSyscall) == SyscallSentinel {
			log.Printf("✅ Updated START (500)→%v (phase=%d)", allowedSyscalls, phase)
		}
	}

	log.Printf("✅ Updated %d transitions for phase %d", updatedCount, phase)
	return nil
}

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
