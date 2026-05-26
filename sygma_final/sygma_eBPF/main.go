//go:build amd64

package main

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bpfFSPath = "/sys/fs/bpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf monitoring.c -- -I../headers

// =============================================================================
// Header  (8 bits)
// =============================================================================

const (
	PID_SIZE_BIT    = 1 << 0
	HUFFMAN_FLAG    = 1 << 1
	ARG1_SIZE_SHIFT = 2
	ARG2_SIZE_SHIFT = 4
	ARG3_SIZE_SHIFT = 6
	BUFSIZE         = 256
)

// Timestamp
const TS_RECORD_MARKER = uint64(1 << 63)

func isTS_RECORD(x uint64) bool {
	return (x & TS_RECORD_MARKER) != 0
}

func MS_BITS(ts uint64) uint64 {
	return ts >> 24
}

func LS_BITS(ts uint64) uint32 {
	return uint32(ts & 0xFFFFFF)
}

// =============================================================================
// ⭐ Namespace-based
// =============================================================================

type SyscallStatsKey struct {
	PidNS uint32
	MntNS uint32
}

type SyscallStatsValue struct {
	EnterCount         uint64
	EnqueuedCount      uint64
	DroppedCount       uint64
	BatchSuccess       uint64
	BatchFailed        uint64
	RingbufSubmitCount uint64
}

type HuffmanStatsKey struct {
	PidNS uint32
	MntNS uint32
}

type HuffmanStatsValue struct {
	CompressedCount   uint64
	TotalSavedBytes   uint64
	OriginalTotalSize uint64
	EauditTotalSize   uint64
	HuffmanTotalSize  uint64
}

// ⭐ Container  (eBPF  )
type ContainerInfoKey struct {
	PidNS uint32
	MntNS uint32
}

type ContainerInfoValue struct {
	Name [64]byte
}

// =============================================================================
// Syscall
// =============================================================================

type SyscallMetadata struct {
	Nr        uint16
	Name      string
	ArgCount  uint8
	HasString bool
}

var syscallMetadataMap = map[uint16]SyscallMetadata{
	56:  {Nr: 56, Name: "clone", ArgCount: 3, HasString: false},
	57:  {Nr: 57, Name: "fork", ArgCount: 0, HasString: false},
	59:  {Nr: 59, Name: "execve", ArgCount: 3, HasString: true},
	322: {Nr: 322, Name: "execveat", ArgCount: 3, HasString: true},
	90:  {Nr: 90, Name: "chmod", ArgCount: 2, HasString: true},
	105: {Nr: 105, Name: "setuid", ArgCount: 1, HasString: false},
	106: {Nr: 106, Name: "setgid", ArgCount: 1, HasString: false},
	113: {Nr: 113, Name: "setreuid", ArgCount: 2, HasString: false},
	10:  {Nr: 10, Name: "mprotect", ArgCount: 3, HasString: false},
	101: {Nr: 101, Name: "ptrace", ArgCount: 3, HasString: false},
	41:  {Nr: 41, Name: "socket", ArgCount: 3, HasString: false},
	43:  {Nr: 43, Name: "accept", ArgCount: 3, HasString: false},
	49:  {Nr: 49, Name: "bind", ArgCount: 3, HasString: false},
	42:  {Nr: 42, Name: "connect", ArgCount: 3, HasString: false},
	50:  {Nr: 50, Name: "listen", ArgCount: 2, HasString: false},
	45:  {Nr: 45, Name: "recvfrom", ArgCount: 3, HasString: false},
	288: {Nr: 288, Name: "accept4", ArgCount: 3, HasString: false},
}

var syscallNameToNr = map[byte]uint16{
	'C': 56,  // clone
	'F': 57,  // fork
	'E': 59,  // execve
	'T': 322, // execveat
	'M': 90,  // chmod
	'U': 105, // setuid
	'G': 106, // setgid
	'D': 113, // setreuid
	'P': 10,  // mprotect
	'Y': 101, // ptrace
	'S': 41,  // socket
	'H': 43,  // accept
	'B': 49,  // bind
	'N': 42,  // connect
	'L': 50,  // listen
	'R': 45,  // recvfrom
	'A': 288, // accept4
}

// =============================================================================
// eBPF
// =============================================================================

type ArgKey1 struct {
	Arg1 uint64
}

type ArgKey2 struct {
	Arg1 uint64
	Arg2 uint64
}

type ArgKey3 struct {
	Arg1 uint64
	Arg2 uint64
	Arg3 uint64
}

type ArgKeyString1 struct {
	Arg1      uint64
	StringArg [64]byte
}

type ArgKeyString2 struct {
	Arg1      uint64
	Arg2      uint64
	StringArg [64]byte
}

type ArgKeyString3 struct {
	Arg1      uint64
	Arg2      uint64
	Arg3      uint64
	StringArg [64]byte
}

type CompressedData struct {
	Valid  uint8
	Length uint8
	_      [6]byte
	Data   [64]byte
}

// =============================================================================
//
// =============================================================================

type EAuditLog struct {
	SyscallName byte
	SyscallNr   uint16
	PID         uint64
	Args        []uint64
	StringArg   string
	Timestamp   time.Time
	IsHuffman   bool
}

// =============================================================================
// Header
// =============================================================================

type HeaderInfo struct {
	PIDSize   int
	IsHuffman bool
	Arg1Size  int
	Arg2Size  int
	Arg3Size  int
}

func decodeHeader(header byte) HeaderInfo {
	info := HeaderInfo{}

	if (header & PID_SIZE_BIT) != 0 {
		info.PIDSize = 3
	} else {
		info.PIDSize = 2
	}

	info.IsHuffman = (header & HUFFMAN_FLAG) != 0

	arg1Bits := (header >> ARG1_SIZE_SHIFT) & 0x03
	info.Arg1Size = 1 << arg1Bits

	arg2Bits := (header >> ARG2_SIZE_SHIFT) & 0x03
	info.Arg2Size = 1 << arg2Bits

	arg3Bits := (header >> ARG3_SIZE_SHIFT) & 0x03
	info.Arg3Size = 1 << arg3Bits

	return info
}

// =============================================================================
// Huffman
// =============================================================================

type HuffmanDecoder struct {
	Trees map[uint16]map[uint64]*HuffmanNode
	mu    sync.RWMutex
}

var globalDecoder = &HuffmanDecoder{
	Trees: make(map[uint16]map[uint64]*HuffmanNode),
}

func (d *HuffmanDecoder) RegisterTree(syscallNr uint16, tree *HuffmanNode) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Trees[syscallNr] == nil {
		d.Trees[syscallNr] = make(map[uint64]*HuffmanNode)
	}

	d.Trees[syscallNr][0] = tree
}

func (d *HuffmanDecoder) Decode(syscallNr uint16, codeBytes []byte, codeLen uint8) ([]uint64, string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	treeMap, exists := d.Trees[syscallNr]
	if !exists {
		return nil, "", fmt.Errorf("no tree for syscall %d", syscallNr)
	}

	tree, exists := treeMap[0]
	if !exists {
		return nil, "", fmt.Errorf("no tree for syscall %d", syscallNr)
	}

	var bits []int
	for i := uint8(0); i < codeLen; i++ {
		b := codeBytes[i]
		for j := 7; j >= 0; j-- {
			bits = append(bits, int((b>>uint(j))&1))
		}
	}

	current := tree

	for _, bit := range bits {
		if current == nil {
			return nil, "", fmt.Errorf("null node during traversal")
		}

		if bit == 0 {
			current = current.Left
		} else {
			current = current.Right
		}

		if current == nil {
			return nil, "", fmt.Errorf("invalid huffman code")
		}

		if current.Left == nil && current.Right == nil {
			args := make([]uint64, len(current.Args))
			copy(args, current.Args)
			return args, "", nil
		}
	}

	return nil, "", fmt.Errorf("incomplete huffman code")
}

// =============================================================================
// Huffman
// =============================================================================

type ArgFrequency struct {
	SyscallNr       uint16
	Args            []uint64
	StringArg       string
	Count           uint64
	OriginalSize    int
	ExpectedSavings int64
}

type HuffmanNode struct {
	Freq      uint64
	Args      []uint64
	StringArg string
	Left      *HuffmanNode
	Right     *HuffmanNode
	Code      []byte
}

type PriorityQueue []*HuffmanNode

func (pq PriorityQueue) Len() int           { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool { return pq[i].Freq < pq[j].Freq }
func (pq PriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }

func (pq *PriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*HuffmanNode))
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

type FrequencyAnalyzer struct {
	mu          sync.RWMutex
	Frequencies map[string]*ArgFrequency
	TotalLogs   uint64
}

func NewFrequencyAnalyzer() *FrequencyAnalyzer {
	return &FrequencyAnalyzer{
		Frequencies: make(map[string]*ArgFrequency),
	}
}

func calculateEAuditSize(pid uint64, args []uint64) int {
	size := 6

	if pid > 0xFFFF {
		size += 3
	} else {
		size += 2
	}

	for _, arg := range args {
		if arg <= 0xFF {
			size += 1
		} else if arg <= 0xFFFF {
			size += 2
		} else if arg <= 0xFFFFFFFF {
			size += 4
		} else {
			size += 8
		}
	}

	return size
}

func estimateHuffmanSize(codeLength int, pid uint64) int {
	codeBytes := (codeLength + 7) / 8
	size := 6 + codeBytes

	if pid > 0xFFFF {
		size += 3
	} else {
		size += 2
	}

	return size
}

func (fa *FrequencyAnalyzer) AddLog(syscallNr uint16, args []uint64, stringArg string) {
	key := makeFrequencyKey(syscallNr, args, stringArg)

	fa.mu.Lock()
	defer fa.mu.Unlock()

	if freq, exists := fa.Frequencies[key]; exists {
		freq.Count++
	} else {
		avgPID := uint64(10000)
		originalSize := calculateEAuditSize(avgPID, args)

		fa.Frequencies[key] = &ArgFrequency{
			SyscallNr:    syscallNr,
			Args:         args,
			StringArg:    stringArg,
			Count:        1,
			OriginalSize: originalSize,
		}
	}
	fa.TotalLogs++
}

func makeFrequencyKey(syscallNr uint16, args []uint64, stringArg string) string {
	key := fmt.Sprintf("%d", syscallNr)
	for _, arg := range args {
		key += fmt.Sprintf(":%d", arg)
	}
	if stringArg != "" {
		key += ":" + stringArg
	}
	return key
}

func assignCodes(node *HuffmanNode, code []byte) {
	if node == nil {
		return
	}

	if node.Left == nil && node.Right == nil {
		node.Code = make([]byte, len(code))
		copy(node.Code, code)
		return
	}

	if node.Left != nil {
		leftCode := append(code, 0)
		assignCodes(node.Left, leftCode)
	}

	if node.Right != nil {
		rightCode := append(code, 1)
		assignCodes(node.Right, rightCode)
	}
}

func (fa *FrequencyAnalyzer) BuildHuffmanTreeBySyscall(syscallNr uint16, minSavings int64) *HuffmanNode {
	candidates := make([]*ArgFrequency, 0)

	fa.mu.RLock()
	for _, freq := range fa.Frequencies {
		if freq.SyscallNr != syscallNr {
			continue
		}

		avgCodeLength := 4
		avgPID := uint64(10000)
		huffmanSize := estimateHuffmanSize(avgCodeLength, avgPID)

		savings := int64(freq.Count) * int64(freq.OriginalSize-huffmanSize)

		freqCopy := &ArgFrequency{
			SyscallNr:       freq.SyscallNr,
			Args:            make([]uint64, len(freq.Args)),
			StringArg:       freq.StringArg,
			Count:           freq.Count,
			OriginalSize:    freq.OriginalSize,
			ExpectedSavings: savings,
		}
		copy(freqCopy.Args, freq.Args)

		if savings >= minSavings {
			candidates = append(candidates, freqCopy)
		}
	}
	fa.mu.RUnlock()

	if len(candidates) == 0 {
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ExpectedSavings > candidates[j].ExpectedSavings
	})

	maxPatterns := 128
	if len(candidates) > maxPatterns {
		candidates = candidates[:maxPatterns]
	}

	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	for _, freq := range candidates {
		node := &HuffmanNode{
			Freq:      freq.Count,
			Args:      freq.Args,
			StringArg: freq.StringArg,
		}
		heap.Push(&pq, node)
	}

	if pq.Len() == 0 {
		return nil
	}

	if pq.Len() == 1 {
		node := heap.Pop(&pq).(*HuffmanNode)
		node.Code = []byte{0}
		return node
	}

	for pq.Len() > 1 {
		left := heap.Pop(&pq).(*HuffmanNode)
		right := heap.Pop(&pq).(*HuffmanNode)

		parent := &HuffmanNode{
			Freq:  left.Freq + right.Freq,
			Left:  left,
			Right: right,
		}
		heap.Push(&pq, parent)
	}

	root := heap.Pop(&pq).(*HuffmanNode)
	assignCodes(root, []byte{})

	return root
}

func collectHuffmanCodes(node *HuffmanNode, codes map[string]*HuffmanNode, syscallNr uint16) {
	if node == nil {
		return
	}

	if node.Left == nil && node.Right == nil {
		key := makeFrequencyKey(syscallNr, node.Args, node.StringArg)
		codes[key] = node
		return
	}

	collectHuffmanCodes(node.Left, codes, syscallNr)
	collectHuffmanCodes(node.Right, codes, syscallNr)
}

func huffmanCodeToBytes(code []byte) []byte {
	if len(code) == 0 {
		return nil
	}

	numBytes := (len(code) + 7) / 8
	result := make([]byte, numBytes)

	for i, bit := range code {
		if bit == 1 {
			byteIdx := i / 8
			bitIdx := uint(i % 8)
			result[byteIdx] |= (1 << (7 - bitIdx))
		}
	}

	return result
}

func (fa *FrequencyAnalyzer) UpdateEBPFMaps(objs *bpfObjects) error {
	log.Printf("\n========== Updating Huffman Rules ==========")

	if objs == nil {
		return fmt.Errorf("bpfObjects is nil")
	}

	hasStringMaps := true
	if objs.HuffmanRulesStr1 == nil || objs.HuffmanRulesStr2 == nil || objs.HuffmanRulesStr3 == nil {
		log.Printf("⚠️  Warning: String-based Huffman maps are nil, skipping string syscalls")
		hasStringMaps = false
	}

	log.Printf("Updating Huffman rules (cumulative mode)...")

	totalUpdated := 0
	totalExpectedSavings := int64(0)

	for syscallNr, metadata := range syscallMetadataMap {
		fa.mu.RLock()
		syscallCount := 0
		for _, freq := range fa.Frequencies {
			if freq.SyscallNr == syscallNr {
				syscallCount++
			}
		}
		fa.mu.RUnlock()

		if syscallCount == 0 {
			continue
		}

		log.Printf("\n[%s] Processing %d unique patterns...", metadata.Name, syscallCount)

		tree := fa.BuildHuffmanTreeBySyscall(syscallNr, 0)
		if tree == nil {
			log.Printf("  → No patterns found")
			continue
		}

		globalDecoder.RegisterTree(syscallNr, tree)
		log.Printf("  → Registered decoder tree")

		codes := make(map[string]*HuffmanNode)
		collectHuffmanCodes(tree, codes, syscallNr)

		log.Printf("  → Generated %d Huffman codes", len(codes))

		updated := 0
		syscallSavings := int64(0)

		for freqKey, node := range codes {
			freq := fa.Frequencies[freqKey]
			if freq == nil {
				continue
			}

			codeBytes := huffmanCodeToBytes(node.Code)
			if len(codeBytes) > 64 {
				if updated < 3 {
					log.Printf("    ⚠️  Code too long (%d bytes): skipped", len(codeBytes))
				}
				continue
			}

			if len(freq.Args) < int(metadata.ArgCount) {
				if updated < 3 {
					log.Printf("    ⚠️  Args mismatch: need %d, got %d", metadata.ArgCount, len(freq.Args))
				}
				continue
			}

			compData := CompressedData{
				Valid:  1,
				Length: uint8(len(codeBytes)),
			}
			copy(compData.Data[:], codeBytes)

			var err error

			if metadata.HasString {
				if !hasStringMaps {
					if updated < 3 {
						log.Printf("    ⚠️  Skipping string rule (maps unavailable): %s", metadata.Name)
					}
					continue
				}

				switch metadata.ArgCount {
				case 1:
					if len(freq.Args) >= 1 {
						argKey := ArgKeyString1{
							Arg1: freq.Args[0],
						}
						copy(argKey.StringArg[:], []byte(freq.StringArg))
						err = objs.HuffmanRulesStr1.Put(&argKey, &compData)
					}
				case 2:
					if len(freq.Args) >= 2 {
						argKey := ArgKeyString2{
							Arg1: freq.Args[0],
							Arg2: freq.Args[1],
						}
						copy(argKey.StringArg[:], []byte(freq.StringArg))
						err = objs.HuffmanRulesStr2.Put(&argKey, &compData)
					}
				case 3:
					if len(freq.Args) >= 3 {
						argKey := ArgKeyString3{
							Arg1: freq.Args[0],
							Arg2: freq.Args[1],
							Arg3: freq.Args[2],
						}
						copy(argKey.StringArg[:], []byte(freq.StringArg))
						err = objs.HuffmanRulesStr3.Put(&argKey, &compData)
					}
				}
			} else {
				switch metadata.ArgCount {
				case 1:
					if len(freq.Args) >= 1 {
						argKey := ArgKey1{
							Arg1: freq.Args[0],
						}
						err = objs.HuffmanRules1.Put(&argKey, &compData)
					}
				case 2:
					if len(freq.Args) >= 2 {
						argKey := ArgKey2{
							Arg1: freq.Args[0],
							Arg2: freq.Args[1],
						}
						err = objs.HuffmanRules2.Put(&argKey, &compData)
					}
				case 3:
					if len(freq.Args) >= 3 {
						argKey := ArgKey3{
							Arg1: freq.Args[0],
							Arg2: freq.Args[1],
							Arg3: freq.Args[2],
						}
						err = objs.HuffmanRules3.Put(&argKey, &compData)
					}
				}
			}

			if err == nil {
				updated++
				syscallSavings += freq.ExpectedSavings

				if updated <= 5 {
					avgPID := uint64(10000)
					huffmanSize := estimateHuffmanSize(len(node.Code), avgPID)
					savingsKB := freq.ExpectedSavings / 1000

					log.Printf("    ✓ Pattern (freq=%d, orig=%dB, huff=%dB, savings=%dKB): args=%v",
						freq.Count, freq.OriginalSize, huffmanSize, savingsKB,
						freq.Args[:min(len(freq.Args), int(metadata.ArgCount))])
				}
			} else {
				if updated < 3 {
					log.Printf("    ✗ FAILED to store rule: syscall=%s, args=%v, err=%v",
						metadata.Name,
						freq.Args[:min(len(freq.Args), int(metadata.ArgCount))], err)
				}
			}
		}

		if updated > 0 {
			log.Printf("  → Updated %d rules for %s (expected savings: %.2f KB)",
				updated, metadata.Name, float64(syscallSavings)/1000.0)
		}

		totalUpdated += updated
		totalExpectedSavings += syscallSavings
	}

	log.Printf("\n✅ Total: Updated %d Huffman rules", totalUpdated)
	log.Printf("📊 Expected total savings: %.2f MB", float64(totalExpectedSavings)/(1000.0*1000.0))

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// ⭐ eAudit
// =============================================================================

func decodeEAuditLogAtOffset(data []byte, startOffset int, kernelTsMsb uint64, bootTime time.Time) (*EAuditLog, int, error) {
	if startOffset+5 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data")
	}

	log := &EAuditLog{}

	offset := startOffset

	log.SyscallName = data[offset]
	offset++

	if nr, ok := syscallNameToNr[log.SyscallName]; ok {
		log.SyscallNr = nr
	} else {
		return nil, 0, fmt.Errorf("unknown syscall name: %c", log.SyscallName)
	}

	if offset+3 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for timestamp")
	}
	tsLsb := uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
	offset += 3

	// MSB LSB  monotonic time ( )
	monotonicTimeNs := (kernelTsMsb << 24) | uint64(tsLsb)

	// absolute_time = boot_time + bpf_ktime_get_ns()
	log.Timestamp = bootTime.Add(time.Duration(monotonicTimeNs))

	header := data[offset]
	offset++

	hdrInfo := decodeHeader(header)
	log.IsHuffman = hdrInfo.IsHuffman

	if offset+hdrInfo.PIDSize > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for PID")
	}

	var pid uint64
	if hdrInfo.PIDSize == 2 {
		pid = uint64(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
	} else {
		pid = uint64(data[offset])<<16 | uint64(data[offset+1])<<8 | uint64(data[offset+2])
		offset += 3
	}
	log.PID = pid

	if hdrInfo.IsHuffman {
		endIdx := bytes.IndexByte(data[offset:], '\n')
		if endIdx == -1 {
			return nil, 0, fmt.Errorf("no newline found")
		}

		huffmanCode := data[offset : offset+endIdx]
		codeLen := uint8(len(huffmanCode))

		args, stringArg, err := globalDecoder.Decode(log.SyscallNr, huffmanCode, codeLen)
		if err != nil {
			log.Args = []uint64{}
			log.StringArg = ""
		} else {
			log.Args = args
			log.StringArg = stringArg
		}

		offset += endIdx + 1
	} else {
		metadata, ok := syscallMetadataMap[log.SyscallNr]
		if !ok {
			return nil, 0, fmt.Errorf("unknown syscall nr: %d", log.SyscallNr)
		}

		argCount := metadata.ArgCount

		if argCount >= 1 {
			if offset+hdrInfo.Arg1Size > len(data) {
				return nil, 0, fmt.Errorf("insufficient data for arg1")
			}
			arg1 := readVariableInt(data[offset:], hdrInfo.Arg1Size)
			log.Args = append(log.Args, arg1)
			offset += hdrInfo.Arg1Size
		}

		if argCount >= 2 {
			if offset+hdrInfo.Arg2Size > len(data) {
				return nil, 0, fmt.Errorf("insufficient data for arg2")
			}
			arg2 := readVariableInt(data[offset:], hdrInfo.Arg2Size)
			log.Args = append(log.Args, arg2)
			offset += hdrInfo.Arg2Size
		}

		if argCount >= 3 {
			if offset+hdrInfo.Arg3Size > len(data) {
				return nil, 0, fmt.Errorf("insufficient data for arg3")
			}
			arg3 := readVariableInt(data[offset:], hdrInfo.Arg3Size)
			log.Args = append(log.Args, arg3)
			offset += hdrInfo.Arg3Size
		}

		if metadata.HasString && offset < len(data) && data[offset] != '\n' {
			strLen := data[offset]
			offset++
			if int(offset)+int(strLen) <= len(data) {
				log.StringArg = string(data[offset : offset+int(strLen)])
				offset += int(strLen)
			}
		}

		if offset < len(data) && data[offset] == '\n' {
			offset++
		}
	}

	consumed := offset - startOffset
	return log, consumed, nil
}

func readVariableInt(data []byte, size int) uint64 {
	switch size {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		return binary.BigEndian.Uint64(data)
	default:
		return 0
	}
}

// =============================================================================
// ⭐ Namespace
// =============================================================================

func printStatistics(objs *bpfObjects) {
	log.Printf("\n========== Per-Container Statistics ==========")

	// ⭐ 1. Per-CPU
	residualEvents, err := countResidualEvents(objs)
	if err != nil {
		log.Printf("⚠️  Warning: failed to count residual events: %v", err)
		residualEvents = 0
	}

	// ⭐ 2.
	receivedLogs := getReceivedLogs()

	// 3. Namespace
	var syscallKey SyscallStatsKey
	var syscallVal SyscallStatsValue

	iter := objs.SyscallStatsNsMap.Iterate()

	containerStats := make(map[string]struct {
		Syscall SyscallStatsValue
		Huffman HuffmanStatsValue
	})

	// 4. Syscall stats
	for iter.Next(&syscallKey, &syscallVal) {
		nsKey := fmt.Sprintf("%d:%d", syscallKey.PidNS, syscallKey.MntNS)

		stats := containerStats[nsKey]
		stats.Syscall = syscallVal
		containerStats[nsKey] = stats
	}

	// 5. Huffman stats
	var huffmanKey HuffmanStatsKey
	var huffmanVal HuffmanStatsValue

	huffIter := objs.HuffmanStatsMap.Iterate()
	for huffIter.Next(&huffmanKey, &huffmanVal) {
		nsKey := fmt.Sprintf("%d:%d", huffmanKey.PidNS, huffmanKey.MntNS)

		stats := containerStats[nsKey]
		stats.Huffman = huffmanVal
		containerStats[nsKey] = stats
	}

	// 6. Container
	for nsKey, stats := range containerStats {
		log.Printf("\n--- Container %s ---", nsKey)

		baselineSyscalls := stats.Syscall.EnterCount
		compressedEvents := stats.Huffman.CompressedCount
		ringbufCalls := stats.Syscall.RingbufSubmitCount // ⭐ NEW

		log.Printf("Baseline Syscalls:   %d (from sys_enter)", baselineSyscalls)
		log.Printf("Compressed Events:   %d (%.2f%%)",
			compressedEvents,
			float64(compressedEvents)/float64(baselineSyscalls)*100)

		log.Printf("\n--- Event Flow ---")
		log.Printf("Kernel Generated:    %d (finish_event calls)", baselineSyscalls)
		log.Printf("Ringbuf Submits:     %d (bpf_ringbuf_output calls)", ringbufCalls) // ⭐ NEW
		log.Printf("User Received:       %d (decoded successfully)", receivedLogs)
		log.Printf("Pending (Residual):  %d (in per-CPU buffers)", residualEvents)

		// ⭐ : Received + Residual = Baseline
		totalAccounted := receivedLogs + residualEvents
		log.Printf("Total Accounted:     %d (Received + Residual)", totalAccounted)

		if totalAccounted == baselineSyscalls {
			log.Printf("✅ Perfect match: Baseline = Received + Residual")
		} else {
			discrepancy := int64(baselineSyscalls) - int64(totalAccounted)
			log.Printf("⚠️  Discrepancy: %+d events (%.2f%%)",
				discrepancy,
				float64(discrepancy)/float64(baselineSyscalls)*100)
		}

		// ⭐ Ringbuf efficiency
		if ringbufCalls > 0 {
			avgEventsPerRingbuf := float64(baselineSyscalls) / float64(ringbufCalls)
			log.Printf("\n--- Ringbuf Efficiency ---")
			log.Printf("Avg events/submit:   %.2f (higher is better)", avgEventsPerRingbuf)
			log.Printf("Batching ratio:      %.2f%% (%.0f events per %d ringbuf calls)",
				avgEventsPerRingbuf/float64(BUFSIZE)*100*BUFSIZE, // BUFSIZE = 8192
				avgEventsPerRingbuf,
				ringbufCalls)
		}

		log.Printf("\n--- Sizes ---")
		log.Printf("Original Size:       %d bytes (%.2f MB)",
			stats.Huffman.OriginalTotalSize,
			float64(stats.Huffman.OriginalTotalSize)/(1024*1024))

		log.Printf("eAudit Size:         %d bytes (%.2f MB)",
			stats.Huffman.EauditTotalSize,
			float64(stats.Huffman.EauditTotalSize)/(1024*1024))

		log.Printf("Huffman Size:        %d bytes (%.2f MB)",
			stats.Huffman.HuffmanTotalSize,
			float64(stats.Huffman.HuffmanTotalSize)/(1024*1024))

		// 7.
		if stats.Huffman.OriginalTotalSize > 0 {
			eauditRatio := float64(stats.Huffman.EauditTotalSize) /
				float64(stats.Huffman.OriginalTotalSize) * 100
			huffmanRatio := float64(stats.Huffman.HuffmanTotalSize) /
				float64(stats.Huffman.OriginalTotalSize) * 100

			log.Printf("\n--- Compression Ratios ---")
			log.Printf("eAudit:              %.2f%% of original (%.2f%% reduction)",
				eauditRatio, 100-eauditRatio)
			log.Printf("Huffman:             %.2f%% of original (%.2f%% reduction)",
				huffmanRatio, 100-huffmanRatio)
		}

		// ⭐ 8.   (Received )
		lossRate := 0.0
		if baselineSyscalls > 0 {
			lossRate = float64(baselineSyscalls-receivedLogs) / float64(baselineSyscalls) * 100
		}

		log.Printf("\n--- Log Loss Rate ---")
		log.Printf("Baseline:            %d", baselineSyscalls)
		log.Printf("Received:            %d", receivedLogs)
		log.Printf("Loss Rate:           %.2f%%", lossRate)
	}

	log.Printf("\n================================================\n")
}

// =============================================================================
// ⭐ CSV   (Container)
// =============================================================================

func printStatisticsCSV(objs *bpfObjects, outputFile string) error {
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// ⭐ 1. Per-CPU
	residualEvents, err := countResidualEvents(objs)
	if err != nil {
		log.Printf("⚠️  Warning: failed to count residual events: %v", err)
		residualEvents = 0
	}

	// ⭐ 2.
	receivedLogs := getReceivedLogs()

	// CSV
	if stat, _ := f.Stat(); stat.Size() == 0 {
		header := "timestamp,container_name,pidns,mntns," +
			"baseline_syscalls,ringbuf_submit_count,received_logs,residual_logs,total_accounted," + // ⭐ ringbuf_submit_count
			"loss_rate_pct,discrepancy,avg_events_per_ringbuf," + // ⭐ avg_events_per_ringbuf
			"compressed_events,compression_rate_pct," +
			"original_bytes,eaudit_bytes,huffman_bytes," +
			"original_mb,eaudit_mb,huffman_mb," +
			"eaudit_reduction_pct,huffman_reduction_pct\n"

		if _, err := f.WriteString(header); err != nil {
			return err
		}
	}

	// Namespace
	var syscallKey SyscallStatsKey
	var syscallVal SyscallStatsValue

	iter := objs.SyscallStatsNsMap.Iterate()

	type ContainerStat struct {
		Syscall SyscallStatsValue
		Huffman HuffmanStatsValue
	}

	containerStats := make(map[string]ContainerStat)

	for iter.Next(&syscallKey, &syscallVal) {
		nsKey := fmt.Sprintf("%d:%d", syscallKey.PidNS, syscallKey.MntNS)

		stats := containerStats[nsKey]
		stats.Syscall = syscallVal
		containerStats[nsKey] = stats
	}

	var huffmanKey HuffmanStatsKey
	var huffmanVal HuffmanStatsValue

	huffIter := objs.HuffmanStatsMap.Iterate()
	for huffIter.Next(&huffmanKey, &huffmanVal) {
		nsKey := fmt.Sprintf("%d:%d", huffmanKey.PidNS, huffmanKey.MntNS)

		stats := containerStats[nsKey]
		stats.Huffman = huffmanVal
		containerStats[nsKey] = stats
	}

	// CSV
	timestamp := time.Now().Format(time.RFC3339)

	// Container Info
	containerInfoMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/container_info_map", nil)
	var containerInfoAvailable bool
	if err != nil {
		log.Printf("⚠️  Warning: Failed to load container_info_map: %v", err)
		containerInfoAvailable = false
	} else {
		defer containerInfoMap.Close()
		containerInfoAvailable = true
	}

	for nsKey, stats := range containerStats {
		// Container
		containerName := "unknown"

		if containerInfoAvailable {
			var pidns, mntns uint32
			if _, err := fmt.Sscanf(nsKey, "%d:%d", &pidns, &mntns); err == nil {
				infoKey := ContainerInfoKey{
					PidNS: pidns,
					MntNS: mntns,
				}

				var infoVal ContainerInfoValue
				if err := containerInfoMap.Lookup(&infoKey, &infoVal); err == nil {
					nameBytes := infoVal.Name[:]
					if nullIdx := bytes.IndexByte(nameBytes, 0); nullIdx >= 0 {
						containerName = string(nameBytes[:nullIdx])
					} else {
						containerName = string(nameBytes)
					}
					containerName = strings.TrimSpace(containerName)
				}
			}
		}

		// ⭐
		baselineSyscalls := stats.Syscall.EnterCount
		ringbufSubmits := stats.Syscall.RingbufSubmitCount // ⭐ NEW
		compressedEvents := stats.Huffman.CompressedCount

		// ⭐ Average events per ringbuf submit
		avgEventsPerRingbuf := 0.0
		if ringbufSubmits > 0 {
			avgEventsPerRingbuf = float64(baselineSyscalls) / float64(ringbufSubmits)
		}

		// ⭐ Total Accounted = Received + Residual
		totalAccounted := receivedLogs + residualEvents

		// ⭐ Discrepancy = Baseline - Total Accounted
		discrepancy := int64(baselineSyscalls) - int64(totalAccounted)

		// Loss Rate (Received )
		lossRate := 0.0
		if baselineSyscalls > 0 {
			lossRate = float64(baselineSyscalls-receivedLogs) / float64(baselineSyscalls) * 100.0
		}

		// Compression Rate
		compressionRate := 0.0
		if baselineSyscalls > 0 {
			compressionRate = float64(compressedEvents) / float64(baselineSyscalls) * 100.0
		}

		// Sizes
		originalBytes := stats.Huffman.OriginalTotalSize
		eauditBytes := stats.Huffman.EauditTotalSize
		huffmanBytes := stats.Huffman.HuffmanTotalSize

		originalMB := float64(originalBytes) / (1024 * 1024)
		eauditMB := float64(eauditBytes) / (1024 * 1024)
		huffmanMB := float64(huffmanBytes) / (1024 * 1024)

		eauditReductionPct := 0.0
		huffmanReductionPct := 0.0

		if originalBytes > 0 {
			eauditReductionPct = float64(originalBytes-eauditBytes) / float64(originalBytes) * 100.0
			huffmanReductionPct = float64(originalBytes-huffmanBytes) / float64(originalBytes) * 100.0
		}

		// CSV
		parts := bytes.Split([]byte(nsKey), []byte(":"))
		pidns := string(parts[0])
		mntns := string(parts[1])

		line := fmt.Sprintf("%s,%s,%s,%s,"+
			"%d,%d,%d,%d,%d,"+ // ⭐ ringbuf_submit_count
			"%.2f,%d,%.2f,"+ // ⭐ avg_events_per_ringbuf
			"%d,%.2f,"+
			"%d,%d,%d,"+
			"%.4f,%.4f,%.4f,"+
			"%.2f,%.2f\n",
			timestamp, containerName, pidns, mntns,
			baselineSyscalls, ringbufSubmits, receivedLogs, residualEvents, totalAccounted, // ⭐
			lossRate, discrepancy, avgEventsPerRingbuf, // ⭐
			compressedEvents, compressionRate,
			originalBytes, eauditBytes, huffmanBytes,
			originalMB, eauditMB, huffmanMB,
			eauditReductionPct, huffmanReductionPct,
		)

		if _, err := f.WriteString(line); err != nil {
			return err
		}
	}

	// ⭐ TOTAL
	totalBaseline := uint64(0)
	totalRingbufSubmits := uint64(0) // ⭐ NEW
	totalOriginalBytes := uint64(0)
	totalEauditBytes := uint64(0)
	totalHuffmanBytes := uint64(0)
	totalCompressed := uint64(0)

	//
	iter2 := objs.SyscallStatsNsMap.Iterate()
	for iter2.Next(&syscallKey, &syscallVal) {
		totalBaseline += syscallVal.EnterCount
		totalRingbufSubmits += syscallVal.RingbufSubmitCount // ⭐ NEW
	}

	huffIter2 := objs.HuffmanStatsMap.Iterate()
	for huffIter2.Next(&huffmanKey, &huffmanVal) {
		totalOriginalBytes += huffmanVal.OriginalTotalSize
		totalEauditBytes += huffmanVal.EauditTotalSize
		totalHuffmanBytes += huffmanVal.HuffmanTotalSize
		totalCompressed += huffmanVal.CompressedCount
	}

	totalAccounted := receivedLogs + residualEvents
	totalDiscrepancy := int64(totalBaseline) - int64(totalAccounted)
	totalLossRate := 0.0
	if totalBaseline > 0 {
		totalLossRate = float64(totalBaseline-receivedLogs) / float64(totalBaseline) * 100.0
	}

	totalAvgEventsPerRingbuf := 0.0
	if totalRingbufSubmits > 0 {
		totalAvgEventsPerRingbuf = float64(totalBaseline) / float64(totalRingbufSubmits)
	}

	totalCompressionRate := 0.0
	if totalBaseline > 0 {
		totalCompressionRate = float64(totalCompressed) / float64(totalBaseline) * 100.0
	}

	totalOriginalMB := float64(totalOriginalBytes) / (1024 * 1024)
	totalEauditMB := float64(totalEauditBytes) / (1024 * 1024)
	totalHuffmanMB := float64(totalHuffmanBytes) / (1024 * 1024)

	totalEauditReduction := 0.0
	totalHuffmanReduction := 0.0
	if totalOriginalBytes > 0 {
		totalEauditReduction = float64(totalOriginalBytes-totalEauditBytes) / float64(totalOriginalBytes) * 100.0
		totalHuffmanReduction = float64(totalOriginalBytes-totalHuffmanBytes) / float64(totalOriginalBytes) * 100.0
	}

	totalLine := fmt.Sprintf("%s,TOTAL,ALL,ALL,"+
		"%d,%d,%d,%d,%d,"+ // ⭐ ringbuf_submit_count
		"%.2f,%d,%.2f,"+ // ⭐ avg_events_per_ringbuf
		"%d,%.2f,"+
		"%d,%d,%d,"+
		"%.4f,%.4f,%.4f,"+
		"%.2f,%.2f\n",
		timestamp,
		totalBaseline, totalRingbufSubmits, receivedLogs, residualEvents, totalAccounted, // ⭐
		totalLossRate, totalDiscrepancy, totalAvgEventsPerRingbuf, // ⭐
		totalCompressed, totalCompressionRate,
		totalOriginalBytes, totalEauditBytes, totalHuffmanBytes,
		totalOriginalMB, totalEauditMB, totalHuffmanMB,
		totalEauditReduction, totalHuffmanReduction,
	)

	if _, err := f.WriteString(totalLine); err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Setup & Attach ( )
// =============================================================================

func setupTailCalls(objs *bpfObjects) error {
	log.Println("Setting up tail call programs...")

	if objs.ProgArray == nil {
		return fmt.Errorf("ProgArray map is nil")
	}

	progMap := map[uint32]*ebpf.Program{
		0: objs.Stage2Verify,
		1: objs.CollectSyscalls,
	}

	for idx, prog := range progMap {
		if prog == nil {
			log.Printf("Warning: Stage program at index %d is nil", idx)
			continue
		}
		if err := objs.ProgArray.Put(uint32(idx), prog); err != nil {
			return fmt.Errorf("failed to put stage prog at index %d: %w", idx, err)
		}
		log.Printf("✓ Registered stage program at index %d", idx)
	}

	if objs.ProgMap == nil {
		return fmt.Errorf("ProgMap is nil")
	}

	// huffmanProgs := map[uint32]*ebpf.Program{
	// 	26: objs.HuffmanCloneHandler,
	// 	28: objs.HuffmanExecveHandler,
	// 	29: objs.HuffmanExecveatHandler,
	// 	30: objs.HuffmanChmodHandler,
	// 	31: objs.HuffmanSetuidHandler,
	// 	32: objs.HuffmanSetgidHandler,
	// 	33: objs.HuffmanSetreuidHandler,
	// 	34: objs.HuffmanMprotectHandler,
	// 	35: objs.HuffmanPtraceHandler,
	// 	36: objs.HuffmanSocketHandler,
	// 	37: objs.HuffmanAcceptHandler,
	// 	38: objs.HuffmanBindHandler,
	// 	39: objs.HuffmanConnectHandler,
	// 	40: objs.HuffmanListenHandler,
	// 	41: objs.HuffmanRecvfromHandler,
	// 	42: objs.HuffmanAccept4Handler,
	// }

	// for idx, prog := range huffmanProgs {
	// 	if prog == nil {
	// 		log.Printf("Warning: Huffman program at index %d is nil", idx)
	// 		continue
	// 	}
	// 	if err := objs.ProgMap.Put(uint32(idx), prog); err != nil {
	// 		return fmt.Errorf("failed to put huffman prog at index %d: %w", idx, err)
	// 	}
	// 	log.Printf("✓ Registered huffman handler at index %d", idx)
	// }

	log.Println("All tail call programs registered successfully")
	return nil
}

func attachTracepoints(objs *bpfObjects) ([]link.Link, error) {
	var links []link.Link

	tracepoints := map[string]*ebpf.Program{
		"clone":    objs.TraceCloneEnter,
		"fork":     objs.TraceForkEnter,
		"execve":   objs.TraceExecveEnter,
		"execveat": objs.TraceExecveatEnter,
		"chmod":    objs.TraceChmodEnter,
		"ptrace":   objs.TracePtraceEnter,
		"mprotect": objs.TraceMprotectEnter,
		"setuid":   objs.TraceSetuidEnter,
		"setgid":   objs.TraceSetgidEnter,
		"setreuid": objs.TraceSetreuidEnter,
		"socket":   objs.TraceSocketEnter,
		"accept":   objs.TraceAcceptEnter,
		"bind":     objs.TraceBindEnter,
		"connect":  objs.TraceConnectEnter,
		"listen":   objs.TraceListenEnter,
		"recvfrom": objs.TraceRecvfromEnter,
		"accept4":  objs.TraceAccept4Enter,
	}

	log.Println("Attaching tracepoint handlers...")
	for name, prog := range tracepoints {
		if prog == nil {
			log.Printf("Warning: Tracepoint program for %s is nil, skipping", name)
			continue
		}

		tp, err := link.Tracepoint("syscalls", fmt.Sprintf("sys_enter_%s", name), prog, nil)
		if err != nil {
			log.Printf("Warning: Failed to attach tracepoint for %s: %v", name, err)
			continue
		}
		links = append(links, tp)
		log.Printf("✓ Attached tracepoint: sys_enter_%s", name)
	}

	otherTracepoints := map[string]struct {
		category string
		name     string
		prog     *ebpf.Program
	}{
		"sched_process_fork": {
			category: "sched",
			name:     "sched_process_fork",
			prog:     objs.HandleFork,
		},
		"signal_deliver": {
			category: "signal",
			name:     "signal_deliver",
			prog:     objs.HandleSignalDeliver,
		},
	}

	log.Println("Attaching other tracepoint handlers...")
	for desc, tp := range otherTracepoints {
		if tp.prog == nil {
			log.Printf("Warning: Tracepoint program for %s is nil, skipping", desc)
			continue
		}

		link, err := link.Tracepoint(tp.category, tp.name, tp.prog, nil)
		if err != nil {
			log.Printf("Warning: Failed to attach tracepoint %s/%s: %v", tp.category, tp.name, err)
			continue
		}
		links = append(links, link)
		log.Printf("✓ Attached tracepoint: %s/%s", tp.category, tp.name)
	}

	return links, nil
}

func attachLSMHooks(objs *bpfObjects) ([]link.Link, error) {
	var links []link.Link

	lsmHooks := map[string]*ebpf.Program{
		"file_permission":     objs.LsmFilePermission,
		"inode_getattr":       objs.LsmInodeGetattr,
		"socket_sendmsg":      objs.LsmSocketSendmsg,
		"socket_recvmsg":      objs.LsmSocketRecvmsg,
		"file_alloc_security": objs.LsmFileAllocSecurity,
		"mmap_file":           objs.LsmMmapFile,
		"socket_setsockopt":   objs.LsmSocketSetsockopt,
		"socket_accept":       objs.LsmSocketAccept,
	}

	log.Println("Attaching LSM hooks...")
	for hookName, prog := range lsmHooks {
		if prog == nil {
			log.Printf("Warning: LSM hook program for %s is nil, skipping", hookName)
			continue
		}

		lsmLink, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach LSM hook %s: %v", hookName, err)
			continue
		}
		links = append(links, lsmLink)
		log.Printf("✓ Attached LSM hook: %s", hookName)
	}

	if len(links) == 0 {
		log.Println("⚠️  No LSM hooks attached - LSM enforcement disabled")
		log.Println("   Check: CONFIG_BPF_LSM=y and lsm=...,bpf in kernel boot params")
	}

	return links, nil
}

func attachLSMKprobes(objs *bpfObjects) ([]link.Link, error) {
	var links []link.Link

	kprobes := map[string]struct {
		kernelFunc string
		prog       *ebpf.Program
	}{
		"read": {
			kernelFunc: "__x64_sys_read",
			prog:       objs.KprobeSysRead,
		},
		"write": {
			kernelFunc: "__x64_sys_write",
			prog:       objs.KprobeSysWrite,
		},
		"fstat": {
			kernelFunc: "__x64_sys_newfstat",
			prog:       objs.KprobeSysNewfstat,
		},
		"writev": {
			kernelFunc: "__x64_sys_writev",
			prog:       objs.KprobeSysWritev,
		},
		"sendfile": {
			kernelFunc: "__x64_sys_sendfile64",
			prog:       objs.KprobeSysSendfile,
		},
		"sendto": {
			kernelFunc: "__x64_sys_sendto",
			prog:       objs.KprobeSysSendto,
		},
		"recvfrom_lsm": {
			kernelFunc: "__x64_sys_recvfrom",
			prog:       objs.KprobeSysRecvfrom,
		},
		"sendmsg": {
			kernelFunc: "__x64_sys_sendmsg",
			prog:       objs.KprobeSysSendmsg,
		},
		"recvmsg": {
			kernelFunc: "__x64_sys_recvmsg",
			prog:       objs.KprobeSysRecvmsg,
		},
		"openat": {
			kernelFunc: "__x64_sys_openat",
			prog:       objs.KprobeSysOpenat,
		},
		"newfstatat": {
			kernelFunc: "__x64_sys_newfstatat",
			prog:       objs.KprobeSysNewfstatat,
		},
		"mmap": {
			kernelFunc: "__x64_sys_mmap",
			prog:       objs.KprobeSysMmap,
		},
		"pread64": {
			kernelFunc: "__x64_sys_pread64",
			prog:       objs.KprobeSysPread64,
		},
		"pwrite64": {
			kernelFunc: "__x64_sys_pwrite64",
			prog:       objs.KprobeSysPwrite64,
		},
		"setsockopt": {
			kernelFunc: "__x64_sys_setsockopt",
			prog:       objs.KprobeSysSetsockopt,
		},
		"accept4": {
			kernelFunc: "__x64_sys_accept4",
			prog:       objs.KprobeSysAccept4,
		},
	}

	log.Println("Attaching LSM enforcement kprobes...")
	for name, kp := range kprobes {
		if kp.prog == nil {
			log.Printf("Warning: LSM kprobe program for %s is nil, skipping", name)
			continue
		}

		kpLink, err := link.Kprobe(kp.kernelFunc, kp.prog, nil)
		if err != nil {
			log.Printf("Warning: Failed to attach kprobe for %s (%s): %v",
				name, kp.kernelFunc, err)
			continue
		}
		links = append(links, kpLink)
		log.Printf("✓ Attached LSM kprobe: %s (%s)", name, kp.kernelFunc)
	}

	return links, nil
}

func cleanupPinnedMaps(pinpath string) {
	maps := []string{
		"execution_time_map",
		"syscall_graph_map",
		"collection_mode_map",
		"ns_image_map",
		"main_process_map",
		"blocked_syscalls_map",
		"process_state_map",
		"tid_syscall_queue",
		"pid_mount_ns_map",
		"blocked_history",
		"blocked_history_execve",
		"syscall_stats",
		"collection_graph_map",
		"execve_path_map",
		"tid_to_namespace",
		"syscall_transition_map",
		"thread_last_syscall",
		"lsm_block_map",
		"trigger_counter_map",
	}

	for _, mapName := range maps {
		mapPath := path.Join(pinpath, mapName)
		m, err := ebpf.LoadPinnedMap(mapPath, nil)
		if err == nil && m != nil {
			m.Unpin()
			m.Close()
		}
	}
}

func printEAuditLog(log *EAuditLog) {
	syscallName := "unknown"
	if meta, exists := syscallMetadataMap[log.SyscallNr]; exists {
		syscallName = meta.Name
	}

	// ⭐ UTC
	tsFormatted := log.Timestamp.UTC().Format("2006-01-02 15:04:05.000000000 UTC")

	if log.IsHuffman {
		if len(log.Args) > 0 {
			fmt.Printf("[Huffman] ts=%s syscall=%s(%c) pid=%d args=%v",
				tsFormatted, syscallName, log.SyscallName, log.PID, log.Args)
			if log.StringArg != "" {
				fmt.Printf(" str=%s", log.StringArg)
			}
			fmt.Println()
		} else {
			fmt.Printf("[Huffman] ts=%s syscall=%s(%c) pid=%d (decode failed)\n",
				tsFormatted, syscallName, log.SyscallName, log.PID)
		}
	} else {
		fmt.Printf("[eAudit] ts=%s syscall=%s(%c) pid=%d args=%v",
			tsFormatted, syscallName, log.SyscallName, log.PID, log.Args)
		if log.StringArg != "" {
			fmt.Printf(" str=%s", log.StringArg)
		}
		fmt.Println()
	}
}

// =============================================================================
// ⭐ Per-CPU   (C audit_b )
// =============================================================================

type AuditBuffer struct {
	Idx        uint32        // offset 0,  size 4
	_          [4]byte       // offset 4,  size 4 (padding to 8)
	TsMsbs     uint64        // offset 8,  size 8
	EventCount uint32        // offset 16, size 4
	Data       [BUFSIZE]byte // offset 20, size BUFSIZE
	_          [4]byte
}

// =============================================================================
// ⭐ Per-CPU
// =============================================================================

// countResidualEvents per-CPU
func countResidualEvents(objs *bpfObjects) (uint64, error) {
	if objs.PerCpuBuffers == nil {
		return 0, fmt.Errorf("PerCpuBuffers map is nil")
	}

	key := uint32(0)

	// Per-CPU array CPU
	var perCPUBuffers []AuditBuffer
	if err := objs.PerCpuBuffers.Lookup(&key, &perCPUBuffers); err != nil {
		return 0, fmt.Errorf("failed to read per-CPU buffers: %v", err)
	}

	totalResidual := uint64(0)
	cpuCount := len(perCPUBuffers)

	log.Printf("Checking residual events across %d CPUs...", cpuCount)

	for cpuID, buf := range perCPUBuffers {
		// Sanity check:
		if buf.EventCount > 100000 {
			log.Printf("  ⚠️  CPU %d: abnormal event_count=%d, skipping", cpuID, buf.EventCount)
			continue
		}

		if buf.EventCount > 0 {
			log.Printf("  CPU %d: %d events pending in buffer (idx=%d)",
				cpuID, buf.EventCount, buf.Idx)
			totalResidual += uint64(buf.EventCount)
		}
	}

	if totalResidual > 0 {
		log.Printf("📊 Total residual events: %d", totalResidual)
	} else {
		log.Printf("✓ No residual events (all buffers flushed)")
	}

	return totalResidual, nil
}

// =============================================================================
// ⭐
// =============================================================================

var (
	totalReceivedLogs uint64
	receivedLogsMu    sync.Mutex
	bootTime          time.Time
)

func incrementReceivedLogs() {
	receivedLogsMu.Lock()
	totalReceivedLogs++
	receivedLogsMu.Unlock()
}

func getReceivedLogs() uint64 {
	receivedLogsMu.Lock()
	defer receivedLogsMu.Unlock()
	return totalReceivedLogs
}

func resetReceivedLogs() {
	receivedLogsMu.Lock()
	totalReceivedLogs = 0
	receivedLogsMu.Unlock()
}

func getBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				bootTimeSec, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return time.Time{}, err
				}
				return time.Unix(bootTimeSec, 0), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}

// =============================================================================
// Main
// =============================================================================
func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime)

	var err error
	bootTime, err = getBootTime()
	if err != nil {
		log.Fatalf("Failed to get boot time: %v", err)
	}
	log.Printf("System boot time: %v", bootTime)

	currentTime := time.Now().UTC()
	uptime := currentTime.Sub(bootTime)

	log.Printf("============ TIME DEBUG INFO ============")
	log.Printf("Boot time (from /proc/stat):  %v", bootTime)
	log.Printf("Current time (time.Now):      %v", currentTime)
	log.Printf("Calculated uptime:            %v", uptime)
	log.Printf("=========================================")

	eAuditOnly := os.Getenv("eAudit_Only") == "true"
	log.Printf("eAudit Only: %v (set ENABLE_HUFFMAN=true to enable)", eAuditOnly)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	fn := "sygma"
	pinpath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinpath, os.ModePerm); err != nil {
		log.Fatalf("Failed to create bpf fs subpath: %+v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	log.Println("Loading eBPF objects...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		log.Fatalf("Loading objects: %s", err)
	}
	defer objs.Close()

	if err := setupTailCalls(&objs); err != nil {
		log.Fatalf("Setting up tail calls: %v", err)
	}

	log.Println("Attaching Kretprobe...")

	kpExecve, err := link.Kretprobe("__x64_sys_execve", objs.KretprobeExecve, nil)
	if err != nil {
		log.Fatalf("Opening Kretprobe sys_execve: %s", err)
	}
	defer kpExecve.Close()
	log.Println("✓ Attached Kretprobe: __x64_sys_execve")

	kpNotify, err := link.Kprobe("ptrace_notify", objs.Stage1Filter, nil)
	if err != nil {
		log.Fatalf("Opening kprobe ptrace_notify: %s", err)
	}
	defer kpNotify.Close()
	log.Println("✓ Attached kprobe: ptrace_notify")

	processFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint process_fork: %s", err)
	}
	defer processFork.Close()
	log.Println("✓ Attached tracepoint: sched_process_fork")

	tpLinks, err := attachTracepoints(&objs)
	if err != nil {
		log.Printf("Warning: Some tracepoints failed to attach: %v", err)
	}
	defer func() {
		for _, l := range tpLinks {
			l.Close()
		}
	}()

	lsmLinks, err := attachLSMHooks(&objs)
	if err != nil {
		log.Printf("Warning: Some LSM hooks failed to attach: %v", err)
	}
	defer func() {
		for _, l := range lsmLinks {
			l.Close()
		}
	}()

	lsmKprobeLinks, err := attachLSMKprobes(&objs)
	if err != nil {
		log.Printf("Warning: Some LSM kprobes failed to attach: %v", err)
	}
	defer func() {
		for _, l := range lsmKprobeLinks {
			l.Close()
		}
	}()

	if len(lsmLinks) > 0 && len(lsmKprobeLinks) > 0 {
		log.Printf("✅ LSM-BPF enforcement enabled (%d hooks, %d kprobes)\n",
			len(lsmLinks), len(lsmKprobeLinks))
		log.Println("   Fast-path syscalls: 0,1,5,20,40,44,45,46,47,257,262")
	} else {
		log.Println("⚠️  LSM-BPF enforcement disabled - falling back to ptrace only")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	analyzer := NewFrequencyAnalyzer()

	statsTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()

	huffmanTicker := time.NewTicker(1 * time.Minute)
	defer huffmanTicker.Stop()

	go func() {
		for {
			select {
			case <-statsTicker.C:
				printStatistics(&objs)

				csvFile := os.Getenv("STATS_CSV_FILE")
				if csvFile != "" {
					if err := printStatisticsCSV(&objs, csvFile); err != nil {
						log.Printf("Failed to write CSV: %v", err)
					}
				}

				log.Printf("Analyzer: %d patterns, %d logs\n",
					len(analyzer.Frequencies), analyzer.TotalLogs)
			case <-huffmanTicker.C:
				if eAuditOnly {
					continue
				}

				if analyzer.TotalLogs < 1000 {
					log.Printf("Collecting logs... (%d/1000)\n", analyzer.TotalLogs)
					continue
				}

				log.Println("Generating Huffman codes...")
				if err := analyzer.UpdateEBPFMaps(&objs); err != nil {
					log.Printf("ERROR: %v\n", err)
				}

				key := uint32(0)
				enabled := uint32(1)
				if err := objs.HuffmanEnabled.Put(&key, &enabled); err != nil {
					log.Printf("Failed to enable Huffman: %v\n", err)
				} else {
					log.Println("✅ Huffman encoding enabled")
				}
			case <-stopper:
				return
			}
		}
	}()

	go func() {
		<-stopper
		log.Println("\nShutting down...")
		printStatistics(&objs)

		type FreqPair struct {
			Key  string
			Freq uint64
		}
		freqs := make([]FreqPair, 0)
		for k, v := range analyzer.Frequencies {
			freqs = append(freqs, FreqPair{k, v.Count})
		}
		sort.Slice(freqs, func(i, j int) bool {
			return freqs[i].Freq > freqs[j].Freq
		})

		log.Println("\nTop 10 patterns:")
		for i := 0; i < 10 && i < len(freqs); i++ {
			log.Printf("%d. %s: %d", i+1, freqs[i].Key, freqs[i].Freq)
		}

		cleanupPinnedMaps(pinpath)
		os.Exit(0)
	}()

	log.Println("\n=== Monitoring Started ===")
	log.Println("Building Huffman codes from logs...")

	eventCount := 0
	eauditCount := 0
	huffmanCount := 0
	lastPrint := time.Now()

	var kernelTsMsb uint64

	// ⭐
	tsRecordCount := 0
	ringbufReadCount := 0
	decodedCount := 0
	parseErrorCount := 0

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("⚠️  Ringbuf read error: %v", err)
			continue
		}

		ringbufReadCount++
		rawData := record.RawSample

		// ⭐ TS_RECORD  (8 )
		if len(rawData) == 8 {
			timestamp := binary.LittleEndian.Uint64(rawData[0:8])
			if isTS_RECORD(timestamp) {
				kernelTsMsb = MS_BITS(timestamp &^ TS_RECORD_MARKER)
				tsRecordCount++

				// ⭐ TS_RECORD
				if tsRecordCount <= 3 {
					log.Printf("✓ TS_RECORD #%d: kernelTsMsb=%d (%.3f sec)",
						tsRecordCount, kernelTsMsb, float64(timestamp&^TS_RECORD_MARKER)/1e9)
				}
				continue
			}
		}

		// ⭐    ( 20 )
		if len(rawData) < 20 {
			log.Printf("⚠️  Ringbuf data too short: %d bytes", len(rawData))
			continue
		}

		// ⭐ kernelTsMsb 0
		if kernelTsMsb == 0 {
			log.Printf("⚠️  Parsing data without TS_RECORD (kernelTsMsb=0)")
		}

		// ⭐  : idx(4) + padding(4) + ts_msbs(8) + event_count(4) = 20 bytes
		//  eAudit  offset 20
		data := rawData[20:]

		// ⭐
		if ringbufReadCount <= 3 {
			log.Printf("📦 Ringbuf #%d: total=%d, data length=%d, first bytes=%v",
				ringbufReadCount, len(rawData), len(data), data[:min(16, len(data))])
		}

		offset := 0
		eventsInBatch := 0

		for offset < len(data) {
			if offset >= len(data) {
				break
			}

			firstByte := data[offset]
			_, isValidSyscall := syscallNameToNr[firstByte]

			if !isValidSyscall {
				if eventsInBatch == 0 && offset == 0 {
					log.Printf("⚠️  First byte not valid syscall: 0x%02X ('%c')", firstByte, firstByte)
				}

				nextPos := -1
				for i := offset + 1; i < len(data); i++ {
					if _, ok := syscallNameToNr[data[i]]; ok {
						nextPos = i
						break
					}
				}
				if nextPos == -1 {
					break
				}
				offset = nextPos
				continue
			}

			eauditLog, consumed, err := decodeEAuditLogAtOffset(data, offset, kernelTsMsb, bootTime)
			if err != nil {
				parseErrorCount++

				// ⭐
				if parseErrorCount <= 5 {
					log.Printf("⚠️  Parse error #%d at offset %d: %v (syscall='%c')",
						parseErrorCount, offset, err, firstByte)
				}

				newlineIdx := bytes.IndexByte(data[offset:], '\n')
				if newlineIdx == -1 {
					break
				}
				offset += newlineIdx + 1
				continue
			}

			//
			incrementReceivedLogs()
			decodedCount++
			eventsInBatch++

			eventCount++
			if eauditLog.IsHuffman {
				huffmanCount++
			} else {
				eauditCount++
				analyzer.AddLog(eauditLog.SyscallNr, eauditLog.Args, eauditLog.StringArg)
			}

			printEAuditLog(eauditLog)

			offset += consumed
		}

		// ⭐
		if ringbufReadCount <= 3 {
			log.Printf("  → Decoded %d events from this batch", eventsInBatch)
		}

		if time.Since(lastPrint) >= 5*time.Second {
			received := getReceivedLogs()
			log.Printf("[Progress] Ringbuf reads: %d, TS_RECORDs: %d, Decoded: %d, Parse errors: %d",
				ringbufReadCount, tsRecordCount, decodedCount, parseErrorCount)
			log.Printf("[Progress] Total: %d (eAudit: %d, Huffman: %d) | Received: %d\n",
				eventCount, eauditCount, huffmanCount, received)
			lastPrint = time.Now()
		}
	}
}
