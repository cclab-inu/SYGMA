// cmd/sygma-tracer/main.go (Updated)
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	blockedSyscallsMapPath = "/sys/fs/bpf/sygma/blocked_syscalls_map"
	tracerReadyFile        = "/tmp/sygma-tracer-ready"
)

func main() {
	logPath := fmt.Sprintf("/var/log/sygma-tracer-%d.log", os.Getpid())
	logFile, err := os.OpenFile(logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		os.Stdout = logFile
		os.Stderr = logFile
		defer logFile.Close()
	}

	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "=== TRACER START (PID: %d) ===\n", os.Getpid())
	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "Target PID: %s, Mode: %s, Binary: %s\n",
		os.Args[1], os.Args[2], os.Args[3])

	runtime.LockOSThread()
	runtime.GOMAXPROCS(1)

	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: sygma-tracer <pid> <mode> <binary-name>\n")
		os.Exit(1)
	}

	targetPid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PID: %v\n", err)
		os.Exit(1)
	}

	mode := os.Args[2]             // "enforcement" or "collection"
	targetBinaryName := os.Args[3] // Binary name to detect in /proc/PID/comm

	isEnforceMode := (mode == "enforcement")

	fmt.Fprintf(os.Stderr, "Configuration:\n")
	fmt.Fprintf(os.Stderr, "  - Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "  - Target Binary: %s\n", targetBinaryName)
	fmt.Fprintf(os.Stderr, "  - Enforcement: %v\n", isEnforceMode)
	fmt.Fprintf(os.Stderr, "========================================\n")

	// ⭐ Enforcement : blocked_syscalls_map 
	var blockedSyscallsMap *ebpf.Map
	if isEnforceMode {
		blockedSyscallsMap, err = ebpf.LoadPinnedMap(blockedSyscallsMapPath, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Warning: blocked_syscalls_map not found: %v\n", err)
			fmt.Fprintf(os.Stderr, "   Enforcement will be disabled (eBPF only)\n")
			isEnforceMode = false
		} else {
			fmt.Fprintf(os.Stderr, "✅ Loaded blocked_syscalls_map\n")
		}
	}
	defer func() {
		if blockedSyscallsMap != nil {
			blockedSyscallsMap.Close()
		}
	}()

	// ========== Attach ==========
	fmt.Fprintf(os.Stderr, "🔗 Attaching to PID %d...\n", targetPid)
	if err := unix.PtraceAttach(targetPid); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to attach to PID %d: %v\n", targetPid, err)
		os.Exit(1)
	}

	var ws unix.WaitStatus
	if _, err := unix.Wait4(targetPid, &ws, 0, nil); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Wait4 failed after attach: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✅ Attached to PID %d\n", targetPid)

	// ⭐ INIT phase options (TRACESYSGOOD)
	baseOpts := unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEEXEC

	initOpts := baseOpts | unix.PTRACE_O_TRACESYSGOOD

	if err := unix.PtraceSetOptions(targetPid, initOpts); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: PtraceSetOptions failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "✅ Set INIT phase options (TRACESYSGOOD)\n")
	}

	// ⭐ Continue (wrapper seccomp   - pause()  )
	unix.PtraceCont(targetPid, 0)
	fmt.Fprintf(os.Stderr, "🔄 Continued target process\n")

	// ⭐⭐⭐ CRITICAL:  Wait4  (SIGUSR1 )
	// OCI Hook    SIGUSR1  !

	//   
	readyFile := fmt.Sprintf("%s.%d", tracerReadyFile, targetPid)
	if err := os.WriteFile(readyFile, []byte("ready"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: Failed to create ready file: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "✅ Created ready file: %s\n", readyFile)
	}
	defer os.Remove(readyFile)

	fmt.Fprintf(os.Stderr, "⏳ Waiting for SIGUSR1 from OCI Hook...\n")

	// SIGUSR1  (OCI Hook  )
	unix.Wait4(targetPid, &ws, 0, nil)

	//  
	if ws.Stopped() {
		sig := ws.StopSignal()
		if sig == syscall.SIGUSR1 {
			fmt.Fprintf(os.Stderr, "✅ Received SIGUSR1 from OCI Hook\n")
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ Unexpected signal: %v (expected SIGUSR1)\n", sig)
		}
	}

	// ⭐ SIGUSR1  syscall  
	unix.PtraceSyscall(targetPid, int(syscall.SIGUSR1))
	fmt.Fprintf(os.Stderr, "🔄 Forwarded SIGUSR1 and entered INIT loop\n")
	fmt.Fprintf(os.Stderr, "========================================\n")

	// ⭐⭐⭐ INIT LOOP (PTRACE_SYSCALL) ⭐⭐⭐
	fmt.Fprintf(os.Stderr, "🔍 INIT phase: Detecting main binary (%s)...\n", targetBinaryName)
	mainPids := initLoop(targetPid, targetBinaryName, isEnforceMode, blockedSyscallsMap)

	if len(mainPids) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No main binary detected, exiting\n")
		return
	}

	fmt.Fprintf(os.Stderr, "✅ Main binary detected, transitioning to MAIN phase\n")
	fmt.Fprintf(os.Stderr, "   Main PIDs: %v\n", getKeysFromMap(mainPids))

	// ⭐ MAIN phase  (TRACESECCOMP )
	mainOpts := baseOpts | unix.PTRACE_O_TRACESECCOMP

	for pid := range mainPids {
		if err := unix.PtraceSetOptions(pid, mainOpts); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Warning: Failed to set MAIN opts for PID %d: %v\n", pid, err)
		}
		unix.PtraceCont(pid, 0) // ⭐ CONT !
	}

	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "🔍 MAIN phase: Monitoring syscalls via SECCOMP...\n")
	fmt.Fprintf(os.Stderr, "========================================\n")

	// ⭐⭐⭐ MAIN LOOP (PTRACE_EVENT_SECCOMP) ⭐⭐⭐
	mainLoop(targetPid, mainPids, mainOpts, isEnforceMode, blockedSyscallsMap)

	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "=== TRACER EXIT ===\n")
	fmt.Fprintf(os.Stderr, "========================================\n")
}

// ⭐ INIT LOOP: execve  (PTRACE_SYSCALL)
func initLoop(targetPid int, targetBinaryName string, isEnforceMode bool, blockedMap *ebpf.Map) map[int]bool {
	syscallEntry := make(map[int]bool)
	mainPids := make(map[int]bool)

	var (
		regs           unix.PtraceRegs
		blockedSyscall uint32
		ws             unix.WaitStatus
		pid            int
		err            error
		event          int
		signal         syscall.Signal
		tid            uint32
		comm           string
	)

	const invalidSyscall = ^uint64(0)
	errno := int64(unix.EPERM)
	eperm := uint64(-errno)

	for {
		pid, err = unix.Wait4(-1, &ws, unix.WALL, nil)
		if err != nil {
			if err == syscall.ECHILD {
				break
			}
			continue
		}

		if ws.Exited() || ws.Signaled() {
			if pid == targetPid {
				break
			}
			delete(syscallEntry, pid)
			continue
		}

		if !ws.Stopped() {
			continue
		}

		event = int(ws >> 16)
		signal = ws.StopSignal()

		// ⭐ EXEC  (  )
		if event == unix.PTRACE_EVENT_EXEC {
			delete(syscallEntry, pid)
			comm = getProcessCommFast(pid)

			// ⭐ Wrapper  
			if comm == "sygma-wrapper" {
				unix.PtraceSyscall(pid, 0)
				continue
			}

			// ⭐   !
			if comm == targetBinaryName {
				mainPids[pid] = true
				fmt.Fprintf(os.Stderr, "✅ Main binary detected: %s (PID: %d)\n", comm, pid)

				// ⭐     INIT 
				if pid == targetPid {
					fmt.Fprintf(os.Stderr, "✅ Target PID matched main binary, ending INIT phase\n")
					return mainPids
				}
			}
			unix.PtraceSyscall(pid, 0)
			continue
		}

		// Fork/Clone/Vfork
		if event == unix.PTRACE_EVENT_FORK ||
			event == unix.PTRACE_EVENT_VFORK ||
			event == unix.PTRACE_EVENT_CLONE {
			unix.PtraceSyscall(pid, 0)
			continue
		}

		// ⭐ Syscall-stop (TRACESYSGOOD )
		if (signal & 0x80) != 0 {
			isEntry := !syscallEntry[pid]
			syscallEntry[pid] = isEntry

			// ⭐ Enforcement : INIT  
			if isEnforceMode && isEntry && pid == targetPid && blockedMap != nil {
				tid = uint32(pid)
				if blockedMap.Lookup(&tid, &blockedSyscall) == nil {
					if unix.PtraceGetRegs(pid, &regs) == nil &&
						uint32(regs.Orig_rax) == blockedSyscall {
						blockedMap.Delete(&tid)
						regs.Orig_rax = invalidSyscall
						regs.Rax = eperm
						unix.PtraceSetRegs(pid, &regs)
						// fmt.Fprintf(os.Stderr, "🚫 INIT: Blocked syscall %d for PID %d\n", blockedSyscall, pid)
					}
				}
			}

			unix.PtraceSyscall(pid, 0)
			continue
		}

		// Signals
		signum := 0
		if signal != unix.SIGSTOP && signal != unix.SIGTRAP {
			signum = int(signal)
		}
		unix.PtraceSyscall(pid, signum)
	}

	return mainPids
}

// ⭐ MAIN LOOP: SECCOMP 
func mainLoop(targetPid int, mainPids map[int]bool, mainOpts int, isEnforceMode bool, blockedMap *ebpf.Map) {
	optionsSet := make(map[int]bool)
	for pid := range mainPids {
		optionsSet[pid] = true
	}

	// ⭐ Collection  
	if !isEnforceMode {
		mainLoopCollectOnly(targetPid, mainPids, mainOpts)
		return
	}

	// ⭐ Enforcement 
	var (
		regs           unix.PtraceRegs
		blockedSyscall uint32
		ws             unix.WaitStatus
		pid            int
		err            error
		event          int
		sig            syscall.Signal
		tid            uint32
		msg            uint
		newPid         int
	)

	const invalidSyscall = ^uint64(0)
	errno := int64(unix.EPERM)
	eperm := uint64(-errno)

	for {
		pid, err = unix.Wait4(-1, &ws, unix.WALL, nil)
		if err != nil {
			if err == syscall.ECHILD {
				return
			}
			continue
		}

		if ws&0xFF == 0 { // Exited
			if pid == targetPid {
				fmt.Fprintf(os.Stderr, "✅ Target PID %d exited, tracer stopping\n", targetPid)
				return
			}
			delete(optionsSet, pid)
			delete(mainPids, pid)
			continue
		}

		if !ws.Stopped() {
			continue
		}

		event = int(ws >> 16)

		// ⭐ SECCOMP  ( )
		if event == unix.PTRACE_EVENT_SECCOMP {
			if mainPids[pid] {
				tid = uint32(pid)
				if blockedMap.Lookup(&tid, &blockedSyscall) == nil {
					if unix.PtraceGetRegs(pid, &regs) == nil &&
						uint32(regs.Orig_rax) == blockedSyscall {
						blockedMap.Delete(&tid)
						regs.Orig_rax = invalidSyscall
						regs.Rax = eperm
						unix.PtraceSetRegs(pid, &regs)
						// fmt.Fprintf(os.Stderr, "🚫 MAIN: Blocked syscall %d for PID %d\n", blockedSyscall, pid)
					}
				}
			}
			unix.PtraceCont(pid, 0)
			continue
		}

		//  
		switch event {
		case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK, unix.PTRACE_EVENT_CLONE:
			msg, _ = unix.PtraceGetEventMsg(pid)
			newPid = int(msg)
			optionsSet[newPid] = false
			if mainPids[pid] {
				mainPids[newPid] = true
			}
			unix.PtraceCont(pid, 0)

		case unix.PTRACE_EVENT_EXEC:
			if !optionsSet[pid] {
				unix.PtraceSetOptions(pid, mainOpts)
				optionsSet[pid] = true
			}
			unix.PtraceCont(pid, 0)

		default:
			sig = ws.StopSignal()
			if sig == unix.SIGTRAP || sig == unix.SIGSTOP {
				if !optionsSet[pid] {
					unix.PtraceSetOptions(pid, mainOpts)
					optionsSet[pid] = true
				}
				unix.PtraceCont(pid, 0)
			} else {
				unix.PtraceCont(pid, int(sig))
			}
		}
	}
}

// ⭐ Collection   (map lookup )
func mainLoopCollectOnly(targetPid int, mainPids map[int]bool, mainOpts int) {
	optionsSet := make(map[int]bool)
	for pid := range mainPids {
		optionsSet[pid] = true
	}

	var (
		ws     unix.WaitStatus
		pid    int
		err    error
		event  int
		msg    uint
		newPid int
	)

	for {
		pid, err = unix.Wait4(-1, &ws, unix.WALL, nil)
		if err != nil {
			if err == syscall.ECHILD {
				return
			}
			continue
		}

		if ws&0xFF == 0 {
			if pid == targetPid {
				fmt.Fprintf(os.Stderr, "✅ Target PID %d exited, tracer stopping\n", targetPid)
				return
			}
			delete(optionsSet, pid)
			delete(mainPids, pid)
			continue
		}

		if !ws.Stopped() {
			continue
		}

		event = int(ws >> 16)

		// SECCOMP:  continue (eBPF )
		if event == unix.PTRACE_EVENT_SECCOMP {
			unix.PtraceCont(pid, 0)
			continue
		}

		switch event {
		case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK, unix.PTRACE_EVENT_CLONE:
			msg, _ = unix.PtraceGetEventMsg(pid)
			newPid = int(msg)
			optionsSet[newPid] = false
			if mainPids[pid] {
				mainPids[newPid] = true
			}
			unix.PtraceCont(pid, 0)

		case unix.PTRACE_EVENT_EXEC:
			if !optionsSet[pid] {
				unix.PtraceSetOptions(pid, mainOpts)
				optionsSet[pid] = true
			}
			unix.PtraceCont(pid, 0)

		default:
			sig := ws.StopSignal()
			if sig == unix.SIGTRAP || sig == unix.SIGSTOP {
				if !optionsSet[pid] {
					unix.PtraceSetOptions(pid, mainOpts)
					optionsSet[pid] = true
				}
				unix.PtraceCont(pid, 0)
			} else {
				unix.PtraceCont(pid, int(sig))
			}
		}
	}
}

var commBuf [16]byte

func getProcessCommFast(pid int) string {
	path := fmt.Sprintf("/proc/%d/comm", pid)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	n, err := f.Read(commBuf[:])
	if err != nil || n == 0 {
		return ""
	}

	end := n - 1
	for end >= 0 && (commBuf[end] == '\n' || commBuf[end] == ' ' || commBuf[end] == '\t') {
		end--
	}

	return string(commBuf[:end+1])
}

func getKeysFromMap(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
