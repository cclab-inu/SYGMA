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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/redis/go-redis/v9"
	// ⭐ : K8s client
)

var DefaultRedisAddr = "localhost:6379"

// ⭐ : Global policy creator
var policyCreator *SYGMAPolicyCreator

// ========== eBPF ==========
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

type BlockedSyscallKey struct {
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

type SyscallStatsKey struct {
	PidNs      uint32
	MntNs      uint32
	SyscallNum uint32
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

	saved_prev_syscall uint32
	in_signal_handler  uint32
}

// ⭐ Container Info
type ContainerInfoKey struct {
	PidNS uint32
	MntNS uint32
}

type ContainerInfoValue struct {
	Name [64]byte
}

type NamespaceInfo struct {
	PidNs   uint32 `json:"pidNs"`
	MntNs   uint32 `json:"mntNs"`
	RootPID uint32 `json:"rootPid,omitempty"`
}

// ========== OCI Runtime State ==========
type OCIState struct {
	Version     string                 `json:"ociVersion"`
	ID          string                 `json:"id"`
	Status      string                 `json:"status"`
	Pid         int                    `json:"pid"`
	Bundle      string                 `json:"bundle"`
	Annotations map[string]string      `json:"annotations"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

func main() {
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
		if err := handlePrestart(); err != nil {
			log.Printf("ERROR: Prestart failed: %v", err)
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

func resolveRelativePath(containerID string, containerPid int, relativePath string) (string, error) {
	if relativePath == "" {
		return "", fmt.Errorf("empty path")
	}

	if strings.HasPrefix(relativePath, "/") {
		return relativePath, nil
	}

	// ⭐ crictl inspect  rootfs
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

	//
	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join("/run/containerd/io.containerd.runtime.v2.task/k8s.io", containerID, rootfsPath)
	}

	log.Printf("🔍 Actual rootfs path: %s", rootfsPath)

	// PATH
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

	// ⭐  rootfs
	for _, dir := range strings.Split(envPath, ":") {
		if dir == "" {
			continue
		}

		candidate := filepath.Join(dir, relativePath)
		hostPath := filepath.Join(rootfsPath, candidate)

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

// ========== PRESTART: Tracer , eBPF  ==========
func handlePrestart() error {
	start := time.Now()
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

	imageName := os.Getenv("SYGMA_IMAGE_NAME")
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

			absolutePath, err := resolveRelativePath(state.ID, state.Pid, pathToReplace) // ⭐ containerID
			if err != nil {
				log.Printf("⚠️ Path resolution failed: %v", err)
				log.Printf("   Falling back to PATH Hijacking")
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
		log.Printf("   Method: PATH Hijacking")
		shouldReplace = false
	}

	if shouldReplace && replacementPath != "" {
		if err := replaceBinaryInContainerHostBased(state.ID, state.Pid, replacementPath); err != nil {
			log.Printf("⚠️ Binary replacement failed: %v", err)
			log.Printf("   Falling back to PATH Hijacking")
		} else {
			log.Printf("✅ Binary replacement complete")

			if err := verifyBinaryReplacement(state.Pid, replacementPath); err != nil {
				log.Printf("⚠️ Verification failed: %v", err)
			}
		}
	}

	pidNs, mntNs, err := getNamespaces(state.Pid)
	if err != nil {
		return fmt.Errorf("failed to get container namespaces: %w", err)
	}
	log.Printf("✅ Namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)

	// Container identity is part of the measurement contract. Both records are
	// required for exact per-container validation and poststop cleanup.
	containerName := getContainerName(&state)
	if err := saveContainerInfo(pidNs, mntNs, containerName); err != nil {
		return fmt.Errorf("failed to save container info to eBPF: %w", err)
	}
	log.Printf("✅ Saved container info to eBPF map: %s", containerName)

	if err := saveNamespaceInfo(state.ID, state.Pid, pidNs, mntNs); err != nil {
		cleanupErr := deleteContainerInfo(pidNs, mntNs)
		return errors.Join(
			fmt.Errorf("failed to save namespace to Redis: %w", err),
			cleanupErr,
		)
	}
	log.Printf("✅ Saved namespaces to Redis (container:ns:%s)", state.ID[:12])

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

	if err := cmd.Start(); err != nil {
		return abortPrestart(state, pidNs, mntNs, nil,
			fmt.Errorf("tracer start failed: %w", err))
	}

	log.Printf("✅ Tracer started (PID: %d, mode: %s) (%v)",
		cmd.Process.Pid, mode, time.Since(start))

	if err := waitForTracerReady(state.Pid, 5*time.Second); err != nil {
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

	// ⭐ eBPF   SIGUSR1
	// wrapper pause()
	if mode == "enforcement" {
		// A SYGMAPolicy CR is asynchronous, so it cannot be used as the
		// prestart readiness signal. Always perform the direct setup and only
		// resume the wrapper after every required eBPF entry is installed.
		if err := setupEnforceMode(state, binaryName, imageName, pidNs, mntNs, start); err != nil {
			return abortPrestart(state, pidNs, mntNs, cmd.Process,
				fmt.Errorf("enforcement instrumentation setup failed: %w", err))
		}
	} else if mode == "collection" {
		if err := setupCollectionMode(state.Pid, pidNs, mntNs, binaryName, imageName); err != nil {
			return abortPrestart(state, pidNs, mntNs, cmd.Process,
				fmt.Errorf("collection instrumentation setup failed: %w", err))
		}
	} else {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("unsupported SYGMA_MODE %q", mode))
	}

	// ⭐  eBPF    SIGUSR1
	if err := syscall.Kill(state.Pid, syscall.SIGUSR1); err != nil {
		return abortPrestart(state, pidNs, mntNs, cmd.Process,
			fmt.Errorf("failed to send SIGUSR1 to target: %w", err))
	} else {
		log.Printf("✅ Sent SIGUSR1 to PID %d (%v)", state.Pid, time.Since(start))
	}

	// Only publish asynchronous control-plane metadata after the synchronous
	// setup barrier and target resume both succeeded. A failed prestart can
	// therefore never leave an agent that repopulates the cleaned namespace.
	if mode == "enforcement" {
		crErr := createSYGMAPolicyForContainer(state, binaryName, imageName, pidNs, mntNs)
		if crErr != nil {
			log.Printf("⚠️ Warning: SYGMAPolicy CR creation failed: %v", crErr)
		} else {
			log.Printf("✅ SYGMAPolicy CR created")
		}
	}

	if err := cmd.Process.Release(); err != nil {
		log.Printf("Warning: failed to release tracer process: %v", err)
	}

	log.Printf("✅ Prestart completed (Total: %v)", time.Since(start))
	log.Printf("   Wrapper will execve when ready")
	log.Printf("   Tracer will catch EXEC event")

	return nil
}

func createSYGMAPolicyForContainer(
	state OCIState,
	binaryName, imageName string,
	pidNs, mntNs uint32,
) error {
	log.Printf("🔧 Creating SYGMAPolicy CR...")

	// Get pod info
	namespace, podName, err := getPodInfoFromConfig(state.Bundle)
	if err != nil {
		namespace = "default"
		podName = state.ID[:12]
		log.Printf("⚠️ Using fallback: %s/%s", namespace, podName)
	}

	// Initialize policy creator (lazy init)
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

	// Get imageID from Redis
	imageID, err := policyCreator.getImageIDFromRedis(ctx, imageName)
	if err != nil {
		log.Printf("⚠️ Warning: imageID lookup failed: %v", err)
		imageID = 0 // Continue with 0
	}

	// Create SYGMAPolicy CR
	if err := policyCreator.CreateSYGMAPolicy(
		ctx,
		namespace, podName, state.ID[:12],
		imageName, binaryName,
		imageID,
		pidNs, mntNs,
	); err != nil {
		return fmt.Errorf("failed to create SYGMAPolicy: %w", err)
	}

	log.Printf("✅ SYGMAPolicy created: %s/%s", namespace, podName)
	return nil
}

// ⭐⭐⭐ Container
func getContainerName(state *OCIState) string {
	log.Printf("🔍 Extracting container name...")
	log.Printf("   Container ID: %s", state.ID)

	// 1: Kubernetes CRI Annotations
	if state.Annotations != nil {
		log.Printf("   📋 Annotations count: %d", len(state.Annotations))

		// ⭐ CRI annotations
		sandboxName := state.Annotations["io.kubernetes.cri.sandbox-name"]
		sandboxNamespace := state.Annotations["io.kubernetes.cri.sandbox-namespace"]
		containerName := state.Annotations["io.kubernetes.cri.container-name"]

		log.Printf("   🔎 CRI Annotations:")
		log.Printf("      sandbox-name: %s", sandboxName)
		log.Printf("      sandbox-namespace: %s", sandboxNamespace)
		log.Printf("      container-name: %s", containerName)

		// sandbox-name = Pod  (e.g., "redis-cart-f879c99-mh5ln")
		if sandboxName != "" {
			if containerName != "" {
				if sandboxNamespace != "" {
					// "namespace/pod/container"
					result := fmt.Sprintf("%s/%s/%s", sandboxNamespace, sandboxName, containerName)
					log.Printf("   ✅ Using CRI name: %s", result)
					return result
				}
				// "pod/container"
				result := fmt.Sprintf("%s/%s", sandboxName, containerName)
				log.Printf("   ✅ Using CRI name (no namespace): %s", result)
				return result
			}

			// Container   Pod
			if sandboxNamespace != "" {
				result := fmt.Sprintf("%s/%s", sandboxNamespace, sandboxName)
				log.Printf("   ✅ Using CRI pod name: %s", result)
				return result
			}

			log.Printf("   ✅ Using CRI pod name (no namespace): %s", sandboxName)
			return sandboxName
		}

		log.Printf("   ⚠️ No CRI sandbox-name found in annotations")
	} else {
		log.Printf("   ⚠️ state.Annotations is nil")
	}

	// 2: Container ID ( )
	if len(state.ID) >= 12 {
		shortID := state.ID[:12]
		log.Printf("   📝 Fallback to container ID: %s", shortID)
		return shortID
	}

	log.Printf("   📝 Fallback to full ID: %s", state.ID)
	return state.ID
}

// ⭐⭐⭐ Container  eBPF
func saveContainerInfo(pidNs, mntNs uint32, containerName string) error {
	if pidNs == 0 || mntNs == 0 {
		return fmt.Errorf("invalid namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)
	}

	containerInfoMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/container_info_map", nil)
	if err != nil {
		return fmt.Errorf("failed to load container_info_map: %w", err)
	}
	defer containerInfoMap.Close()

	key := ContainerInfoKey{
		PidNS: pidNs,
		MntNS: mntNs,
	}

	var value ContainerInfoValue
	// Container  64   (null-terminated)
	nameBytes := []byte(containerName)
	if len(nameBytes) > 63 {
		nameBytes = nameBytes[:63]
	}
	copy(value.Name[:], nameBytes)

	if err := containerInfoMap.Put(&key, &value); err != nil {
		return fmt.Errorf("failed to update container_info_map: %w", err)
	}

	log.Printf("📝 Saved to eBPF map: container_info_map[%d:%d] = '%s'",
		pidNs, mntNs, containerName)

	return nil
}

// ⭐⭐⭐ Host  Binary Replacement ( rootfs  )
func replaceBinaryInContainerHostBased(containerID string, containerPid int, binaryPath string) error {
	log.Printf("🔍 Binary Replacement (Host-based)")
	log.Printf("   Container ID: %s", containerID[:12])
	log.Printf("   Container PID: %d", containerPid)
	log.Printf("   Target binary: %s", binaryPath)

	output, err := exec.Command("/usr/bin/crictl", "inspect", containerID).Output()
	if err != nil {
		log.Printf("❌ crictl inspect failed: %v", err)
		return fmt.Errorf("crictl inspect failed: %w", err)
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return fmt.Errorf("failed to parse crictl output: %w", err)
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

	originalBinary := filepath.Join(rootfsPath, binaryPath)
	realBinary := originalBinary + ".real"

	log.Printf("   Original: %s", originalBinary)
	log.Printf("   Real: %s", realBinary)

	stat, err := os.Lstat(originalBinary)
	if err != nil {
		log.Printf("❌ Original binary not found: %v", err)
		return fmt.Errorf("original binary not found: %w", err)
	}

	if stat.Mode()&os.ModeSymlink != 0 {
		log.Printf("🔗 Detected symlink: %s", binaryPath)

		target, err := os.Readlink(originalBinary)
		if err != nil {
			return fmt.Errorf("failed to read symlink: %w", err)
		}
		log.Printf("   Symlink target: %s", target)

		var actualBinary string
		if filepath.IsAbs(target) {
			actualBinary = filepath.Join(rootfsPath, target)
		} else {
			actualBinary = filepath.Join(filepath.Dir(originalBinary), target)
		}

		log.Printf("   Actual binary: %s", actualBinary)

		actualRealBinary := actualBinary + ".real"

		// 1. Actual binary
		if err := os.Rename(actualBinary, actualRealBinary); err != nil {
			log.Printf("❌ Rename actual binary failed: %v", err)
			return fmt.Errorf("failed to rename actual binary: %w", err)
		}
		log.Printf("✅ Renamed actual binary: %s → %s.real", target, target)

		// 2. Actual binary  wrapper
		wrapperSource := "/opt/sygma/wrapper"
		if err := copyFileWithPermissions(wrapperSource, actualBinary); err != nil {
			log.Printf("❌ Copy to actual binary failed: %v", err)
			os.Rename(actualRealBinary, actualBinary)
			return fmt.Errorf("failed to copy wrapper to actual binary: %w", err)
		}
		log.Printf("✅ Wrapper copied to actual binary: %s", actualBinary)

		// 3.  symlink
		if err := os.Remove(originalBinary); err != nil {
			log.Printf("❌ Remove symlink failed: %v", err)
			return fmt.Errorf("failed to remove symlink: %w", err)
		}
		log.Printf("✅ Removed symlink: %s", binaryPath)

		// 4.   wrapper
		if err := copyFileWithPermissions(wrapperSource, originalBinary); err != nil {
			log.Printf("❌ Copy wrapper failed: %v", err)
			return fmt.Errorf("failed to copy wrapper: %w", err)
		}
		log.Printf("✅ Wrapper copied: %s", binaryPath)

		// ⭐⭐⭐ 5. .real symlink  ( !)
		// actualRealBinary realBinary
		//    basename
		relativeRealPath := filepath.Base(actualRealBinary)

		if err := os.Symlink(relativeRealPath, realBinary); err != nil {
			log.Printf("⚠️ Warning: failed to create .real symlink: %v", err)
			// Fallback:
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
			return fmt.Errorf("failed to rename binary: %w", err)
		}
		log.Printf("✅ Renamed: %s → %s.real", binaryPath, binaryPath)

		wrapperSource := "/opt/sygma/wrapper"
		if err := copyFileWithPermissions(wrapperSource, originalBinary); err != nil {
			log.Printf("❌ Copy failed: %v", err)
			os.Rename(realBinary, originalBinary)
			return fmt.Errorf("failed to copy wrapper: %w", err)
		}
		log.Printf("✅ Wrapper copied: %s → %s", wrapperSource, binaryPath)
	}

	log.Printf("✅ Binary replacement complete")
	return nil
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

func verifyBinaryReplacement(containerPid int, binaryPath string) error {
	containerRoot := fmt.Sprintf("/proc/%d/root", containerPid)

	wrapperPath := filepath.Join(containerRoot, binaryPath)
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

func setupEnforceMode(state OCIState, binaryName string, imageName string, pidNs, mntNs uint32, hookStart time.Time) error {
	start := time.Now()
	log.Printf("⏱️ Enforce setup starting")

	namespace, podName, _ := getPodInfoFromConfig(state.Bundle)
	if podName == "" {
		namespace = "default"
		podName = state.ID[:12]
	}

	if pidNs == 0 || mntNs == 0 {
		return fmt.Errorf("invalid namespaces: pidNs=%d, mntNs=%d", pidNs, mntNs)
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
		return fmt.Errorf("redis ping failed: %w", err)
	}

	imageID, binaryName, err := loadImagePolicyToEBPF(ctx, rdb, imageName, pidNs, mntNs, binaryName)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	if err := initializeProcessState(state.Pid, imageID, pidNs, mntNs); err != nil {
		return fmt.Errorf("process state init failed: %w", err)
	}

	mappingKey := fmt.Sprintf("container:mapping:%s", state.ID)
	podKey := fmt.Sprintf("%s/%s", namespace, podName)
	if err := rdb.Set(ctx, mappingKey, podKey, 0).Err(); err != nil {
		return fmt.Errorf("save container mapping: %w", err)
	}

	log.Printf("✅ Enforce setup completed (%v)", time.Since(start))
	return nil
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

func waitForTracerReady(containerPid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	log.Printf("⏳ Waiting for tracer to attach to PID %d...", containerPid)

	for time.Now().Before(deadline) {
		statusPath := fmt.Sprintf("/proc/%d/status", containerPid)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "TracerPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					tracerPid := fields[1]
					if tracerPid != "0" {
						log.Printf("✅ Tracer attached (TracerPid=%s)", tracerPid)
						return nil
					}
				}
				break
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("timeout: tracer did not attach within %v", timeout)
}

func extractBinaryNameAndPath(state OCIState, imageName string) (string, string) {
	envBinary := os.Getenv("SYGMA_TARGET_BINARY")
	envPath := os.Getenv("SYGMA_BINARY_PATH")

	if envBinary != "" && envBinary != "unknown" {
		log.Printf("✅ Binary from env (NRI): %s", envBinary)
		if envPath != "" && envPath != "unknown" {
			log.Printf("✅ Binary path from env (NRI): %s", envPath)
			return envBinary, envPath
		}
		return envBinary, ""
	}

	if imageName != "" {
		if binaryName, binaryPath, err := getBinaryNameByImage(imageName); err == nil {
			if binaryName != "" && binaryName != "unknown" {
				return binaryName, binaryPath
			}
			log.Printf("⚠️ Redis returned 'unknown' binary, falling back to config.json")
		} else {
			log.Printf("⚠️ Redis lookup failed: %v", err)
		}
	}

	configPath := filepath.Join(state.Bundle, "config.json")
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

	lastColonIdx := strings.LastIndex(imageInfo, ":")
	if lastColonIdx == -1 {
		return "", "", fmt.Errorf("invalid format (no colon): %s", imageInfo)
	}

	afterLastColon := imageInfo[lastColonIdx+1:]

	binaryParts := strings.SplitN(afterLastColon, ":", 2)

	binaryName := binaryParts[0]
	binaryPath := ""

	if len(binaryParts) == 2 {
		binaryPath = binaryParts[1]
	}

	log.Printf("✅ Parsed from image_id_map:")
	log.Printf("   Raw: %s", imageInfo)
	log.Printf("   Binary: '%s'", binaryName)
	log.Printf("   Path: '%s'", binaryPath)

	return binaryName, binaryPath, nil
}

func loadImagePolicyToEBPF(ctx context.Context, rdb *redis.Client, imageName string, pidNs, mntNs uint32, binaryName string) (uint32, string, error) {
	start := time.Now()
	log.Printf("Loading image policy to eBPF: %s", imageName)

	imageID, foundImageName, err := getImageIDFromRedis(ctx, rdb, imageName)
	if err != nil {
		return 0, "", err
	}
	log.Printf("Found image: %s (ID=%d) (%v)", foundImageName, imageID, time.Since(start))

	if binaryName == "" {
		binaryInfo, _ := rdb.Get(ctx, fmt.Sprintf("image_id_map:%d", imageID)).Result()
		if lastColonIndex := strings.LastIndex(binaryInfo, ":"); lastColonIndex != -1 && lastColonIndex < len(binaryInfo)-1 {
			binaryName = binaryInfo[lastColonIndex+1:]
		}
	}
	log.Printf("Binary: %s", binaryName)

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		return 0, "", fmt.Errorf("open syscall_graph_map: %w", err)
	}
	defer graphMap.Close()

	totalLoaded := 0
	phaseLoaded := map[uint32]int{}
	phaseZeroStartLoaded := false
	for _, phase := range []uint32{0, 1} {
		pattern := fmt.Sprintf("syscall_graph:%d:%d:*", imageID, phase)
		keys, err := rdb.Keys(ctx, pattern).Result()
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
			if !hasAllowedTransition {
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

	// This evaluation measures INIT completeness. An empty phase-0 policy
	// disables the very check being measured and must never be reported as a
	// successfully instrumented deployment.
	if phaseLoaded[0] == 0 {
		return 0, "", fmt.Errorf(
			"phase 0 policy is empty for image %s (imageID=%d)", imageName, imageID)
	}
	if !phaseZeroStartLoaded {
		return 0, "", fmt.Errorf(
			"phase 0 policy for image %s (imageID=%d) has no START transition (from=500)",
			imageName, imageID)
	}

	log.Printf("✅ Loaded %d transitions to eBPF (pidns=%d, mntns=%d) (%v)",
		totalLoaded, pidNs, mntNs, time.Since(start))

	if err := updateNamespaceMaps(imageID, binaryName, pidNs, mntNs); err != nil {
		return 0, "", fmt.Errorf("install namespace policy gates: %w", err)
	}

	return imageID, binaryName, nil
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
	candidates := []string{fullImageName}
	parts := strings.Split(fullImageName, "/")

	if len(parts) >= 3 {
		candidates = append(candidates, strings.Join(parts[1:], "/"))
		candidates = append(candidates, parts[len(parts)-1])
	} else if len(parts) == 2 {
		candidates = append(candidates, parts[1])
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
	if pid <= 0 {
		return fmt.Errorf("invalid root PID: %d", pid)
	}

	stateMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
	if err != nil {
		return fmt.Errorf("open process_state_map: %w", err)
	}
	defer stateMap.Close()

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	if err != nil {
		return fmt.Errorf("open tid_to_namespace: %w", err)
	}
	defer tidNsMap.Close()

	state := ProcessState{
		PrevSyscall:        500,
		CurrentSyscall:     500,
		ImageID:            imageID,
		saved_prev_syscall: 500,
		in_signal_handler:  0,
	}

	tid := uint32(pid)
	if err := stateMap.Put(&tid, &state); err != nil {
		// Older hook versions created process states without a namespace link,
		// so poststop could not remove them. Reclaim only entries whose TID no
		// longer exists, then retry once. Live processes are never pruned.
		pruned, pruneErr := pruneDeadProcessStates(stateMap, tidNsMap)
		if pruneErr != nil {
			return fmt.Errorf(
				"failed to update process_state_map: %w (dead-state pruning also failed: %v)",
				err, pruneErr)
		}
		if pruned == 0 {
			return fmt.Errorf("failed to update process_state_map: %w", err)
		}
		log.Printf("⚠️ Reclaimed %d stale process-state entries after map update failure", pruned)
		if retryErr := stateMap.Put(&tid, &state); retryErr != nil {
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

func pruneDeadProcessStates(stateMap, tidNsMap *ebpf.Map) (int, error) {
	var tid uint32
	var state ProcessState
	var deadTIDs []uint32
	iter := stateMap.Iterate()
	for iter.Next(&tid, &state) {
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

	// ⭐⭐⭐  :  execution_time_map  ⭐⭐⭐
	execTimeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/execution_time_map", nil)
	if err != nil {
		return fmt.Errorf("open execution_time_map: %w", err)
	} else {
		defer execTimeMap.Close()

		var execValue ExecutionValue

		// Binary name  ,
		if binaryName != "" {
			commBytes := []byte(binaryName)
			if len(commBytes) > 15 {
				commBytes = commBytes[:15]
			}
			copy(execValue.Comm[:], commBytes)
		}

		execValue.ExecutionTime = 0 // INIT phase

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
	normalized := strings.TrimPrefix(imageName, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")

	if !strings.Contains(normalized, ":") {
		normalized += ":latest"
	}

	return normalized
}

// ========== POSTSTOP:  ==========
func handlePoststop() error {
	log.Printf("========== POSTSTOP (Cleanup) ==========")

	var state OCIState
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %w", err)
	}

	mode := os.Getenv("SYGMA_MODE")
	if mode == "" {
		// Cleanup is keyed by the Redis container record, not by mode. Skipping
		// here would leak state if a runtime omitted the hook environment.
		log.Printf("⚠️ No SYGMA_MODE set; continuing namespace cleanup")
	}

	log.Printf("Cleaning up container: %s, PID: %d", state.ID, state.Pid)

	var cleanupErrs []error
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

		containerInfoErr := deleteContainerInfo(nsInfo.PidNs, nsInfo.MntNs)
		if containerInfoErr != nil {
			cleanupErrs = append(cleanupErrs, containerInfoErr)
		}
		ebpfCleanupErr := cleanupEBPFMaps(nsInfo.PidNs, nsInfo.MntNs, uint32(rootPID))
		if ebpfCleanupErr != nil {
			cleanupErrs = append(cleanupErrs, ebpfCleanupErr)
		} else {
			log.Printf("✅ eBPF maps cleaned")
		}
		namespaceCleanupSucceeded = containerInfoErr == nil && ebpfCleanupErr == nil
	}

	// ⭐⭐⭐ : SYGMAPolicy CR
	if mode == "enforcement" {
		namespace, podName, _ := getPodInfoFromConfig(state.Bundle)
		if podName == "" {
			podName = state.ID[:12]
		}
		if namespace == "" {
			namespace = "default"
		}

		if policyCreator != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := policyCreator.DeleteSYGMAPolicy(ctx, namespace, podName); err != nil {
				log.Printf("⚠️ Warning: SYGMAPolicy deletion failed: %v", err)
			} else {
				log.Printf("✅ Deleted SYGMAPolicy: %s/%s", namespace, podName)
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

	log.Printf("✅ Cleanup completed without errors")
	return nil
}

// ⭐ Container Info
func deleteContainerInfo(pidNs, mntNs uint32) error {
	containerInfoMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/container_info_map", nil)
	if err != nil {
		log.Printf("Warning: failed to load container_info_map: %v", err)
		return err
	}
	defer containerInfoMap.Close()

	key := ContainerInfoKey{
		PidNS: pidNs,
		MntNS: mntNs,
	}

	if err := deleteMapKey(containerInfoMap, &key); err != nil {
		return fmt.Errorf("delete container info (pidns=%d, mntns=%d): %w",
			pidNs, mntNs, err)
	}

	log.Printf("✅ Deleted container info from eBPF map (pidns=%d, mntns=%d)", pidNs, mntNs)
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

	maps := []struct {
		path string
		name string
	}{
		{"/sys/fs/bpf/sygma/execution_time_map", "execution_time_map"},
		{"/sys/fs/bpf/sygma/collection_mode_map", "collection_mode_map"},
		{"/sys/fs/bpf/sygma/pid_mount_ns_map", "pid_mount_ns_map"},
		{"/sys/fs/bpf/sygma/main_process_map", "main_process_map"},
		{"/sys/fs/bpf/sygma/ns_image_map", "ns_image_map"},
	}

	for _, m := range maps {
		ebpfMap, err := ebpf.LoadPinnedMap(m.path, nil)
		if err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("open %s: %w", m.name, err))
			continue
		}
		if err := deleteMapKey(ebpfMap, &nsKey); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete %s namespace key: %w", m.name, err))
		}
		ebpfMap.Close()
	}

	graphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_graph_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open syscall_graph_map: %w", err))
	} else {
		var key SyscallGraphKey
		var value SyscallGraphValue
		var graphKeys []SyscallGraphKey
		iter := graphMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				graphKeys = append(graphKeys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate syscall_graph_map: %w", err))
		}
		for i := range graphKeys {
			if err := deleteMapKey(graphMap, &graphKeys[i]); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete syscall_graph_map key %+v: %w", graphKeys[i], err))
			}
		}
		log.Printf("Deleted %d syscall graph rows (including from=500 sentinel)", len(graphKeys))
		graphMap.Close()
	}

	// The operator removes collection rows on the normal training path. Keep a
	// poststop fallback so an interrupted reconcile cannot contaminate a later
	// container that reuses the same namespace inode. collection_graph_map is
	// per-CPU, but deleting a key does not require decoding its per-CPU value.
	collectionGraphMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/collection_graph_map", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open collection_graph_map: %w", err))
	} else {
		deletedCollectionKeys := 0
		for phase := uint32(0); phase <= 1; phase++ {
			for fromSyscall := uint32(0); fromSyscall <= 334; fromSyscall++ {
				key := CollectionGraphKey{
					MntNs:       mntNs,
					PidNs:       pidNs,
					PrevSyscall: fromSyscall,
					Phase:       phase,
				}
				if err := deleteMapKey(collectionGraphMap, &key); err != nil {
					cleanupErrs = append(cleanupErrs,
						fmt.Errorf("delete collection_graph_map key %+v: %w", key, err))
				} else {
					deletedCollectionKeys++
				}
			}
			for fromSyscall := uint32(424); fromSyscall <= 448; fromSyscall++ {
				key := CollectionGraphKey{
					MntNs:       mntNs,
					PidNs:       pidNs,
					PrevSyscall: fromSyscall,
					Phase:       phase,
				}
				if err := deleteMapKey(collectionGraphMap, &key); err != nil {
					cleanupErrs = append(cleanupErrs,
						fmt.Errorf("delete collection_graph_map key %+v: %w", key, err))
				} else {
					deletedCollectionKeys++
				}
			}
			startKey := CollectionGraphKey{
				MntNs:       mntNs,
				PidNs:       pidNs,
				PrevSyscall: 500,
				Phase:       phase,
			}
			if err := deleteMapKey(collectionGraphMap, &startKey); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete collection_graph_map START key %+v: %w", startKey, err))
			} else {
				deletedCollectionKeys++
			}
		}
		log.Printf("Checked/deleted %d collection graph keys (including from=500 sentinel)",
			deletedCollectionKeys)
		collectionGraphMap.Close()
	}

	syscallStatsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/syscall_stats", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open syscall_stats: %w", err))
	} else {
		var key SyscallStatsKey
		var value uint64
		var statsKeys []SyscallStatsKey
		iter := syscallStatsMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				statsKeys = append(statsKeys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate syscall_stats: %w", err))
		}
		for i := range statsKeys {
			if err := deleteMapKey(syscallStatsMap, &statsKeys[i]); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete syscall_stats key %+v: %w", statsKeys[i], err))
			}
		}
		log.Printf("Deleted %d syscall-stat rows for namespace", len(statsKeys))
		syscallStatsMap.Close()
	}

	transitionMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/transition_check_count", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open transition_check_count: %w", err))
	} else {
		for phase := uint32(0); phase <= 1; phase++ {
			key := TransitionCheckKey{MntNs: mntNs, PidNs: pidNs, Phase: phase}
			if err := deleteMapKey(transitionMap, &key); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete transition_check_count phase %d: %w", phase, err))
			}
		}
		transitionMap.Close()
	}

	blockedMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/blocked_history", nil)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open blocked_history: %w", err))
	} else {
		var key BlockedSyscallKey
		var value uint32
		var blockedKeys []BlockedSyscallKey
		iter := blockedMap.Iterate()
		for iter.Next(&key, &value) {
			if key.PidNs == pidNs && key.MntNs == mntNs {
				blockedKeys = append(blockedKeys, key)
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate blocked_history: %w", err))
		}
		for i := range blockedKeys {
			if err := deleteMapKey(blockedMap, &blockedKeys[i]); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete blocked_history key %+v: %w", blockedKeys[i], err))
			}
		}
		log.Printf("Deleted %d blocked-history rows for namespace", len(blockedKeys))
		blockedMap.Close()
	}

	tidNsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/tid_to_namespace", nil)
	var tidsToDelete []uint32
	seen := make(map[uint32]struct{})
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open tid_to_namespace: %w", err))
	} else {
		var tid uint32
		var tidNs PidMountNs
		iter := tidNsMap.Iterate()
		for iter.Next(&tid, &tidNs) {
			if tidNs.PidNs == pidNs && tidNs.MntNs == mntNs {
				tidsToDelete = append(tidsToDelete, tid)
				seen[tid] = struct{}{}
			}
		}
		if err := iter.Err(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("iterate tid_to_namespace: %w", err))
		}
	}
	if rootPID != 0 {
		if _, ok := seen[rootPID]; !ok {
			tidsToDelete = append(tidsToDelete, rootPID)
		}
	}

	processStateMap, stateErr := ebpf.LoadPinnedMap("/sys/fs/bpf/sygma/process_state_map", nil)
	if stateErr != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("open process_state_map: %w", stateErr))
	}

	for _, tid := range tidsToDelete {
		stateDeleted := processStateMap != nil
		if processStateMap != nil {
			if err := deleteMapKey(processStateMap, &tid); err != nil {
				stateDeleted = false
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete process_state_map TID %d: %w", tid, err))
			}
		}
		if tidNsMap != nil && stateDeleted {
			if err := deleteMapKey(tidNsMap, &tid); err != nil {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("delete tid_to_namespace TID %d: %w", tid, err))
			}
		} else if tidNsMap != nil {
			log.Printf("Preserving tid_to_namespace[%d] because process-state deletion did not succeed", tid)
		}
	}
	if processStateMap != nil && tidNsMap != nil {
		pruned, err := pruneDeadProcessStates(processStateMap, tidNsMap)
		if err != nil {
			cleanupErrs = append(cleanupErrs,
				fmt.Errorf("prune unlinked dead process states: %w", err))
		} else if pruned > 0 {
			log.Printf("Reclaimed %d additional dead/unlinked process-state rows", pruned)
		}
	}
	if processStateMap != nil {
		processStateMap.Close()
	}
	if tidNsMap != nil {
		tidNsMap.Close()
	}
	log.Printf("Deleted process state for %d namespace-linked/root TIDs", len(tidsToDelete))

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
	if tracer != nil {
		if err := tracer.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			abortErrs = append(abortErrs, fmt.Errorf("kill tracer: %w", err))
		}
	}
	namespaceCleanupSucceeded := false
	if pidNs != 0 && mntNs != 0 {
		ebpfCleanupErr := cleanupEBPFMaps(pidNs, mntNs, uint32(state.Pid))
		if ebpfCleanupErr != nil {
			abortErrs = append(abortErrs, ebpfCleanupErr)
		}
		containerInfoErr := deleteContainerInfo(pidNs, mntNs)
		if containerInfoErr != nil {
			abortErrs = append(abortErrs, containerInfoErr)
		}
		namespaceCleanupSucceeded = ebpfCleanupErr == nil && containerInfoErr == nil
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

	// 2. Redis :
	if key == "REDIS_ADDR" && DefaultRedisAddr != "" {
		return DefaultRedisAddr
	}

	return defaultValue
}

func waitForTracerReadyFile(containerPid int, timeout time.Duration) error {
	readyFile := fmt.Sprintf("/tmp/sygma-tracer-ready.%d", containerPid)
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
