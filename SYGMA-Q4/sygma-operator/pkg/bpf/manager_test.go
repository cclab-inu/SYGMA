package bpf

import "testing"

func TestSyscallToBitIndexIncludesHighRange(t *testing.T) {
	tests := []struct {
		syscall uint32
		want    uint32
	}{
		{syscall: 0, want: 0},
		{syscall: 334, want: 334},
		{syscall: 424, want: 335},
		{syscall: 448, want: 359},
	}
	for _, test := range tests {
		if got := syscallToBitIndex(test.syscall); got != test.want {
			t.Fatalf("syscallToBitIndex(%d) = %d, want %d", test.syscall, got, test.want)
		}
	}
	for _, syscall := range []uint32{335, 423, 449, SyscallSentinel} {
		if got := syscallToBitIndex(syscall); got < 360 {
			t.Fatalf("unsupported syscall %d mapped to bitmap index %d", syscall, got)
		}
	}
}

func TestNamespaceGraphUpdateRejectsLegacyMainPhase(t *testing.T) {
	manager := &Manager{}
	err := manager.UpdateSyscallGraphMapByNamespace(1, 2, 1, map[string][]int{"500": {0}})
	if err == nil {
		t.Fatal("UpdateSyscallGraphMapByNamespace(phase=1) returned nil error")
	}
}
