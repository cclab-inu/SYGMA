//go:build linux

package main

import (
	"math"
	"testing"
)

func TestSumPerCPU(t *testing.T) {
	got, err := sumPerCPU([]uint64{1, 2, 3, 5})
	if err != nil {
		t.Fatal(err)
	}
	if got != 11 {
		t.Fatalf("sum is %d, want 11", got)
	}
}

func TestSumPerCPURejectsOverflow(t *testing.T) {
	if _, err := sumPerCPU([]uint64{math.MaxUint64, 1}); err == nil {
		t.Fatal("overflow was accepted")
	}
}
