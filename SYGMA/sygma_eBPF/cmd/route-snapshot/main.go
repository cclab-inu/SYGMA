//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"

	"github.com/cilium/ebpf"
)

const schemaVersion = 1

var routeNames = []string{
	"conventional_sigkill",
	"lsm_bpf",
	"ptrace_notify",
}

type snapshot struct {
	SchemaVersion int               `json:"schema_version"`
	Node          string            `json:"node,omitempty"`
	MapPath       string            `json:"map_path"`
	Counters      map[string]uint64 `json:"counters"`
}

func sumPerCPU(values []uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, fmt.Errorf("per-CPU counter sum overflow")
		}
		total += value
	}
	return total, nil
}

func readSnapshot(mapPath string) (*snapshot, error) {
	counters, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("open route counter map %q: %w", mapPath, err)
	}
	defer counters.Close()

	info, err := counters.Info()
	if err != nil {
		return nil, fmt.Errorf("inspect route counter map: %w", err)
	}
	if info.Type != ebpf.PerCPUArray || info.KeySize != 4 ||
		info.ValueSize != 8 || info.MaxEntries != uint32(len(routeNames)) {
		return nil, fmt.Errorf(
			"route counter ABI mismatch: type=%s key=%d value=%d max=%d",
			info.Type, info.KeySize, info.ValueSize, info.MaxEntries,
		)
	}

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("determine possible CPUs: %w", err)
	}
	result := &snapshot{
		SchemaVersion: schemaVersion,
		Node:          os.Getenv("NODE_NAME"),
		MapPath:       mapPath,
		Counters:      make(map[string]uint64, len(routeNames)),
	}
	for key, name := range routeNames {
		perCPU := make([]uint64, possibleCPUs)
		mapKey := uint32(key)
		if err := counters.Lookup(&mapKey, &perCPU); err != nil {
			return nil, fmt.Errorf("lookup route %s: %w", name, err)
		}
		total, err := sumPerCPU(perCPU)
		if err != nil {
			return nil, fmt.Errorf("sum route %s: %w", name, err)
		}
		result.Counters[name] = total
	}
	return result, nil
}

func main() {
	mapPath := flag.String(
		"map",
		"/sys/fs/bpf/sygma/route_counter_map",
		"pinned route counter map",
	)
	flag.Parse()

	result, err := readSnapshot(*mapPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode snapshot: %v\n", err)
		os.Exit(1)
	}
}
