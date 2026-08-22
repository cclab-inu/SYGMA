package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTracerBuildIsObservationOnly(t *testing.T) {
	if !observationOnly {
		t.Fatal("tracer must remain observation-only for the startup-gap evaluation")
	}
}

func TestMainSeccompStopResumesWithPtraceCont(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate tracer test source")
	}
	mainSource, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "main.go"))
	if err != nil {
		t.Fatalf("read tracer main.go: %v", err)
	}

	source := string(mainSource)
	mainLoopStart := strings.Index(source, "func mainLoop(")
	if mainLoopStart < 0 {
		t.Fatal("mainLoop not found")
	}
	mainLoop := source[mainLoopStart:]
	mainLoopEnd := strings.Index(mainLoop, "\nvar commBuf")
	if mainLoopEnd < 0 {
		t.Fatal("mainLoop end marker not found")
	}
	mainLoop = mainLoop[:mainLoopEnd]
	seccompBranch := "if event == unix.PTRACE_EVENT_SECCOMP {\n\t\t\tunix.PtraceCont(pid, 0)"
	if !strings.Contains(mainLoop, seccompBranch) {
		t.Fatal("MAIN seccomp branch must resume unchanged with PtraceCont")
	}
	if strings.Contains(mainLoop, "unix.PtraceSyscall(") {
		t.Fatal("MAIN loop must not request syscall entry/exit stops")
	}
}
