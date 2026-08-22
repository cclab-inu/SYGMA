// NRI Plugin - Universal Binary Replacement Support
// Supports both PATH Hijacking (relative path) and Binary Replacement (absolute path)

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var DefaultRedisAddr = "localhost:6379"
var RedisAddrFile = "/etc/nri/sygma-redis-addr"

const (
	timelinePrestartAnnotation = "gap.sygma.io/prestart-timeline"
	timelinePrestartValue      = "v1"
	timelineMeasurementMode    = "tetragon-measurement"

	seccompRoutingAnnotation = "sygma.io/seccomp-routing"
	seccompRoutingSelective  = "selective"
	seccompRoutingAllTrace   = "all-trace"
)

type plugin struct {
	stub stub.Stub
}

// imageMetadataRecord is the durable image_id_map wire format shared with the
// operator and OCI hook. Keep the legacy parser below until existing Redis
// databases have been refreshed by a SYGMAConfig reconciliation.
type imageMetadataRecord struct {
	ImageName  string `json:"imageName,omitempty"`
	BinaryName string `json:"binaryName"`
	BinaryPath string `json:"binaryPath,omitempty"`
}

var log *logrus.Logger

func (p *plugin) Configure(_ context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Infof("Connected to %s/%s", runtime, version)
	return api.MustParseEventMask("CreateContainer"), nil
}

func (p *plugin) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("Synchronized: %d pods, %d containers", len(pods), len(containers))
	return nil, nil
}

func (p *plugin) Shutdown(_ context.Context) {
	log.Info("Shutting down...")
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if pod == nil || container == nil {
		return nil, nil, fmt.Errorf("CreateContainer requires pod and container metadata")
	}
	if pod.Annotations == nil {
		return nil, nil, nil
	}

	mode, exists := pod.Annotations["sygma.io/mode"]
	markerValue, markerRequested := pod.Annotations[timelinePrestartAnnotation]
	if markerRequested && markerValue != timelinePrestartValue {
		return nil, nil, fmt.Errorf(
			"unsupported %s value %q", timelinePrestartAnnotation, markerValue,
		)
	}
	if markerRequested && exists {
		return nil, nil, fmt.Errorf(
			"%s cannot be combined with sygma.io/mode", timelinePrestartAnnotation,
		)
	}
	if !exists || mode == "" {
		if markerRequested {
			if err := validateTimelineOnlyTarget(pod, container); err != nil {
				return nil, nil, err
			}
			log.Infof(
				"CreateContainer: pod=%s/%s, container=%s, installing timing-only prestart marker",
				pod.Namespace, pod.Name, container.Name,
			)
			return timelineOnlyAdjustment(pod), nil, nil
		}
		return nil, nil, nil
	}

	seccompRouting, err := resolveSeccompRouting(pod.Annotations)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("========================================")
	log.Infof("CreateContainer: pod=%s/%s, container=%s, mode=%s, seccomp-routing=%s",
		pod.Namespace, pod.Name, container.Name, mode, seccompRouting)

	// 1.
	imageName := ""

	if img, ok := pod.Annotations["sygma.io/image"]; ok && img != "" {
		imageName = img
		log.Infof("📷 Image from SYGMA annotation: %s", imageName)
	}

	if imageName == "" && container != nil && container.Annotations != nil {
		imageKeys := []string{
			"io.kubernetes.cri.image-name",
			"io.cri-containerd.image",
			"io.kubernetes.container.image",
		}
		for _, key := range imageKeys {
			if img, ok := container.Annotations[key]; ok && img != "" {
				imageName = img
				log.Infof("📷 Image from container annotation '%s': %s", key, imageName)
				break
			}
		}
	}

	if imageName == "" {
		imageName = p.getImageFromCRIAnnotations(pod)
		if imageName != "" {
			log.Infof("📷 Image from Pod CRI annotations: %s", imageName)
		}
	}

	if imageName == "" {
		log.Warnf("⚠️ Failed to determine image name")
	}

	log.Infof("Container Args: %v", container.Args)

	// ⭐⭐⭐ 2.    ( )
	var binaryName string
	var binaryPath string
	var useArgsBasedDetection bool

	// 2-1. Container Args
	var argsBinaryName string
	var argsBinaryPath string

	if len(container.Args) > 0 {
		extractedPath := p.extractBinaryPath(container.Args)
		if extractedPath != "" {
			argsBinaryName = filepath.Base(extractedPath)
			argsBinaryPath = extractedPath
			log.Infof("📋 Binary from container.Args: name=%s, path=%s", argsBinaryName, argsBinaryPath)
		}
	}

	// 2-2. Redis
	var redisBinaryName string
	var redisBinaryPath string

	if imageName != "" {
		if redisName, redisPath, err := p.getBinaryFromTempKey(imageName); err == nil && redisName != "" && redisName != "unknown" {
			redisBinaryName = redisName
			redisBinaryPath = redisPath
			log.Infof("📦 Binary from Redis (temp_key): name=%s, path=%s", redisBinaryName, redisBinaryPath)
		} else if redisName, redisPath, err := p.getBinaryNameByImage(imageName); err == nil && redisName != "" && redisName != "unknown" {
			redisBinaryName = redisName
			redisBinaryPath = redisPath
			log.Infof("📦 Binary from Redis (image_id_map): name=%s, path=%s", redisBinaryName, redisBinaryPath)
		}
	}

	// ⭐⭐⭐ 2-3.
	if argsBinaryName != "" && redisBinaryName != "" {
		//    :
		if argsBinaryName != redisBinaryName {
			//   → Args
			log.Infof("⚠️ Binary name mismatch: Args='%s' vs Redis='%s'", argsBinaryName, redisBinaryName)
			log.Infof("→ Using Args-based detection")
			binaryName = argsBinaryName
			binaryPath = argsBinaryPath
			useArgsBasedDetection = true
		} else {
			//   → Redis  (  )
			log.Infof("✅ Binary names match: '%s'", argsBinaryName)
			log.Infof("→ Using Redis path")
			binaryName = redisBinaryName
			binaryPath = redisBinaryPath
			useArgsBasedDetection = false
		}
	} else if argsBinaryName != "" {
		// Args
		log.Infof("→ Using Args only (Redis empty)")
		binaryName = argsBinaryName
		binaryPath = argsBinaryPath
		useArgsBasedDetection = true
	} else if redisBinaryName != "" {
		// Redis
		log.Infof("→ Using Redis only (Args empty)")
		binaryName = redisBinaryName
		binaryPath = redisBinaryPath
		useArgsBasedDetection = false
	} else {
		//    → Annotation fallback
		if bin, ok := pod.Annotations["sygma.io/binary"]; ok && bin != "" && bin != "unknown" {
			binaryName = bin
			log.Infof("🎯 Binary from SYGMA annotation: %s", binaryName)
		}
		if path, ok := pod.Annotations["sygma.io/binary-path"]; ok && path != "" && path != "unknown" {
			binaryPath = path
			log.Infof("📂 Binary path from SYGMA annotation: %s", binaryPath)
		}
	}

	if binaryName == "" {
		log.Warnf("⚠️ Failed to determine binary name")
		binaryName = "unknown"
	}

	log.Infof("🎯 Final binary: name=%s, path=%s (source: %s)",
		binaryName, binaryPath,
		map[bool]string{true: "Args", false: "Redis/Annotation"}[useArgsBasedDetection])

	// Bootstrap the original container command instead of replacing a binary
	// in the rootfs. The seccomp filter is installed once by PID 1 and is then
	// inherited across the entrypoint's forks and execs.
	replacementMethod := "bootstrap-replacement"
	bootstrapPath := ""
	if len(container.Args) > 0 {
		bootstrapPath = container.Args[0]
	}
	adjust := p.setupWrapperInjection(
		binaryName, binaryPath, bootstrapPath, replacementMethod, mode, imageName,
		seccompRouting,
	)

	// 5. OCI Hooks
	hookEnv := buildHookEnv(
		mode, binaryName, binaryPath, bootstrapPath, imageName, replacementMethod,
	)
	hookEnv = append(hookEnv, experimentHookEnv(pod, "policy-and-release")...)
	adjust.AddHooks(&api.Hooks{
		Prestart: []*api.Hook{
			{
				Path: "/usr/local/bin/sygma-hook",
				Args: []string{"sygma-hook", "prestart"},
				Env:  hookEnv,
			},
		},
		Poststop: []*api.Hook{
			{
				Path: "/usr/local/bin/sygma-hook",
				Args: []string{"sygma-hook", "poststop"},
				Env: []string{
					fmt.Sprintf("SYGMA_MODE=%s", mode),
					fmt.Sprintf("REDIS_ADDR=%s", getEnv("REDIS_ADDR", DefaultRedisAddr)),
					fmt.Sprintf("SYGMA_POLICY_CR_ENABLED=%s", getEnv("SYGMA_POLICY_CR_ENABLED", "false")),
				},
			},
		},
	})

	log.Infof("🚀 SYGMA configured successfully (method: %s)", replacementMethod)
	log.Infof("========================================")

	return adjust, nil, nil
}

// resolveSeccompRouting validates the routing selector before any container
// mutation is returned. An omitted annotation preserves the selective hybrid
// route used by existing deployments.
func resolveSeccompRouting(annotations map[string]string) (string, error) {
	routing, exists := annotations[seccompRoutingAnnotation]
	if !exists || routing == "" {
		return seccompRoutingSelective, nil
	}

	switch routing {
	case seccompRoutingSelective, seccompRoutingAllTrace:
		return routing, nil
	default:
		return "", fmt.Errorf(
			"unsupported %s value %q (expected %q or %q)",
			seccompRoutingAnnotation,
			routing,
			seccompRoutingSelective,
			seccompRoutingAllTrace,
		)
	}
}

// timelineOnlyAdjustment adds a lifecycle timestamp marker to the Tetragon
// experiment arm. Keep this adjustment intentionally minimal: it must never
// add SYGMA environment variables, mounts, wrapper replacement, policy setup,
// process signals, or a poststop hook.
func validateTimelineOnlyTarget(pod *api.PodSandbox, container *api.Container) error {
	if container.Name != "probe" {
		return fmt.Errorf(
			"timing-only prestart marker is restricted to target container probe, got %q",
			container.Name,
		)
	}
	labels := pod.Labels
	if labels["app.kubernetes.io/part-of"] != "sygma-startup-gap-eval" {
		return fmt.Errorf("timing-only prestart marker requires experiment part-of label")
	}
	if labels["gap.sygma.io/backend"] != "tetragon" {
		return fmt.Errorf("timing-only prestart marker requires tetragon backend label")
	}
	if labels["gap.sygma.io/trial"] == "" {
		return fmt.Errorf("timing-only prestart marker requires trial label")
	}
	if labels["gap.sygma.io/application"] == "" {
		return fmt.Errorf("timing-only prestart marker requires application label")
	}
	switch labels["gap.sygma.io/application"] {
	case "synthetic", "nginx", "redis", "httpd", "mysql",
		// DeathStarBench Hotel Reservation core application microservices.
		"hotel-frontend", "hotel-geo", "hotel-profile", "hotel-rate",
		"hotel-recommendation", "hotel-reservation", "hotel-search", "hotel-user",
		// Google Online Boutique (microservices-demo) services.
		"boutique-ad", "boutique-cart", "boutique-checkout", "boutique-currency",
		"boutique-email", "boutique-frontend", "boutique-payment",
		"boutique-productcatalog", "boutique-recommendation", "boutique-shipping",
		// Hotel Reservation supporting infrastructure and Boutique's redis-cart.
		"hotel-consul", "hotel-jaeger",
		"hotel-mongo-geo", "hotel-mongo-profile", "hotel-mongo-rate",
		"hotel-mongo-recommendation", "hotel-mongo-reservation", "hotel-mongo-user",
		"hotel-memcached-profile", "hotel-memcached-rate", "hotel-memcached-reserve",
		"boutique-redis-cart":
	default:
		return fmt.Errorf(
			"unsupported timing-only application %q",
			labels["gap.sygma.io/application"],
		)
	}
	return nil
}

func experimentHookEnv(pod *api.PodSandbox, role string) []string {
	if pod == nil || pod.Labels == nil ||
		pod.Labels["app.kubernetes.io/part-of"] != "sygma-startup-gap-eval" {
		return nil
	}
	return []string{
		fmt.Sprintf("SYGMA_HOOK_ROLE=%s", role),
		fmt.Sprintf("SYGMA_EXPERIMENT_BACKEND=%s", pod.Labels["gap.sygma.io/backend"]),
		fmt.Sprintf("SYGMA_EXPERIMENT_TRIAL_ID=%s", pod.Labels["gap.sygma.io/trial"]),
		fmt.Sprintf("SYGMA_EXPERIMENT_APPLICATION=%s", pod.Labels["gap.sygma.io/application"]),
	}
}

func timelineOnlyAdjustment(pod *api.PodSandbox) *api.ContainerAdjustment {
	adjust := &api.ContainerAdjustment{}
	hookEnv := []string{fmt.Sprintf("SYGMA_TIMELINE_MODE=%s", timelineMeasurementMode)}
	hookEnv = append(hookEnv, experimentHookEnv(pod, "timestamp-only")...)
	adjust.AddHooks(&api.Hooks{
		Prestart: []*api.Hook{
			{
				Path: "/usr/local/bin/sygma-hook",
				Args: []string{"sygma-hook", "timeline-prestart"},
				Env:  hookEnv,
			},
		},
	})
	return adjust
}

func buildHookEnv(mode, binaryName, binaryPath, bootstrapPath, imageName, replacementMethod string) []string {
	env := []string{
		fmt.Sprintf("SYGMA_MODE=%s", mode),
		fmt.Sprintf("SYGMA_IMAGE_NAME=%s", imageName),
		fmt.Sprintf("SYGMA_REPLACEMENT_METHOD=%s", replacementMethod),
		fmt.Sprintf("REDIS_ADDR=%s", getEnv("REDIS_ADDR", DefaultRedisAddr)),
		fmt.Sprintf("SYGMA_POLICY_CR_ENABLED=%s", getEnv("SYGMA_POLICY_CR_ENABLED", "false")),
	}

	// ⭐ "unknown"
	if binaryName != "" && binaryName != "unknown" {
		env = append(env, fmt.Sprintf("SYGMA_TARGET_BINARY=%s", binaryName))
	}

	if binaryPath != "" && binaryPath != "unknown" {
		env = append(env, fmt.Sprintf("SYGMA_BINARY_PATH=%s", binaryPath))
	}
	if bootstrapPath != "" {
		env = append(env, fmt.Sprintf("SYGMA_BOOTSTRAP_PATH=%s", bootstrapPath))
	}

	return env
}

func (p *plugin) getImageFromCRIAnnotations(pod *api.PodSandbox) string {
	if pod.Annotations == nil {
		return ""
	}

	imageKeys := []string{
		"io.kubernetes.cri.image-name",
		"io.cri-containerd.image",
		"io.kubernetes.container.image",
	}

	for _, key := range imageKeys {
		if image, ok := pod.Annotations[key]; ok && image != "" {
			log.Debugf("Found image from CRI annotation '%s': %s", key, image)
			return image
		}
	}

	return ""
}

// ========================================
// Wrapper Injection Setup (Universal)
// ========================================

func (p *plugin) setupWrapperInjection(
	targetBinary, binaryPath, bootstrapPath, replacementMethod, mode, imageName,
	seccompRouting string,
) *api.ContainerAdjustment {
	adjust := &api.ContainerAdjustment{}

	// 1. /opt/sygma  mount
	adjust.AddMount(&api.Mount{
		Source:      "/opt/sygma",
		Destination: "/opt/sygma",
		Type:        "bind",
		Options:     []string{"ro", "rbind"},
	})
	log.Infof("✅ Mount: /opt/sygma → /opt/sygma")

	log.Infof("✅ Bootstrap executable: %s", bootstrapPath)

	// 3. SYGMA
	adjust.AddEnv("SYGMA_INJECTED", "true")
	adjust.AddEnv("SYGMA_MODE", mode)
	adjust.AddEnv("SYGMA_IMAGE_NAME", imageName)
	adjust.AddEnv("SYGMA_REPLACEMENT_METHOD", replacementMethod)
	adjust.AddEnv("SYGMA_SECCOMP_ROUTING", seccompRouting)

	// ⭐ "unknown"
	if targetBinary != "" && targetBinary != "unknown" {
		adjust.AddEnv("SYGMA_TARGET_BINARY", targetBinary)
	}

	if binaryPath != "" && binaryPath != "unknown" {
		adjust.AddEnv("SYGMA_BINARY_PATH", binaryPath)
	}
	if bootstrapPath != "" {
		adjust.AddEnv("SYGMA_BOOTSTRAP_PATH", bootstrapPath)
	}

	return adjust
}

// ========================================
// Binary Path Extraction
// ========================================

// extractBinaryPath - Args
func (p *plugin) extractBinaryPath(args []string) string {
	if len(args) == 0 {
		return ""
	}
	log.Infof("Extracting binary from args: %v", args)

	wrapperScripts := map[string]bool{
		"sh": true, "bash": true, "dash": true, "ash": true,
		"docker-entrypoint": true, "entrypoint": true,
		"docker-init": true, "tini": true,
	}

	for i, arg := range args {
		if arg == "" {
			continue
		}

		if strings.HasPrefix(arg, "-") {
			continue
		}

		if i > 0 && args[i-1] == "-c" {
			log.Infof("   [%d] Parsing shell script: %s", i, arg)
			if binary := p.parseShellScript(arg); binary != "" {
				return binary
			}
			continue
		}

		// ⭐   wrapper  (   )
		baseName := filepath.Base(arg)
		baseNameLower := strings.ToLower(baseName)

		// .sh
		if strings.HasSuffix(baseNameLower, ".sh") {
			log.Debugf("   [%d] Skipping shell script: %s", i, arg)
			continue
		}

		// wrapper script   (substring   )
		if wrapperScripts[baseNameLower] {
			log.Debugf("   [%d] Skipping wrapper: %s", i, arg)
			continue
		}

		// ⭐   !
		log.Infof("   [%d] Found binary: %s", i, arg)
		return arg
	}

	return ""
}

func (p *plugin) parseShellScript(script string) string {
	// "set -e; exec node server.js" → "node"

	// ⭐ exec  (  )
	if strings.Contains(script, "exec ") {
		parts := strings.Fields(script)
		for i, part := range parts {
			if part == "exec" && i+1 < len(parts) {
				binary := parts[i+1]
				log.Infof("   Found exec in script: %s", binary)
				return binary
			}
		}
	}

	// ⭐ exec
	// "set -e; node server.js" → "node"
	commands := strings.Split(script, ";")
	if len(commands) > 0 {
		lastCmd := strings.TrimSpace(commands[len(commands)-1])
		parts := strings.Fields(lastCmd)
		if len(parts) > 0 {
			binary := parts[0]
			log.Infof("   Found last command in script: %s", binary)
			return binary
		}
	}

	return ""
}

// ========================================
// Binary Name Detection
// ========================================

func (p *plugin) extractBinaryNameFromArgs(args []string) string {
	wrapperScripts := []string{
		"sh", "bash", "dash",
		"docker-entrypoint", "entrypoint",
		"docker-init", "tini",
		"foreground", // httpd-foreground, nginx-foreground
	}

	startIdx := 0

	if startIdx < len(args) && strings.Contains(args[startIdx], "wrapper") {
		startIdx++
	}

	for startIdx < len(args) {
		arg := args[startIdx]

		isWrapperScript := false
		for _, wrapper := range wrapperScripts {
			if strings.Contains(strings.ToLower(arg), wrapper) ||
				strings.HasSuffix(arg, ".sh") {
				isWrapperScript = true
				break
			}
		}

		if !isWrapperScript {
			break
		}

		startIdx++
	}

	if startIdx < len(args) {
		binaryPath := args[startIdx]
		binaryName := filepath.Base(binaryPath)
		if !strings.HasPrefix(binaryName, "-") {
			return binaryName
		}
	}

	return ""
}

func (p *plugin) getBinaryFromTempKey(imageName string) (string, string, error) {
	redisAddr := getEnv("REDIS_ADDR", DefaultRedisAddr)
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	result, err := rdb.Get(ctx, tempKey).Result()
	if err != nil {
		return "", "", err
	}

	// ⭐ JSON
	var binaryInfo map[string]string
	if err := json.Unmarshal([]byte(result), &binaryInfo); err != nil {
		// Backward compatibility:
		return strings.TrimSpace(result), "", nil
	}

	return binaryInfo["name"], binaryInfo["path"], nil
}

func (p *plugin) getBinaryNameByImage(imageName string) (string, string, error) {
	redisAddr := getEnv("REDIS_ADDR", DefaultRedisAddr)
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	normalized := normalizeImageName(imageName)
	imageIDKey := fmt.Sprintf("image_name_map:%s", normalized)
	imageIDStr, err := rdb.Get(ctx, imageIDKey).Result()
	if err != nil {
		return "", "", err
	}

	imageMapKey := fmt.Sprintf("image_id_map:%s", imageIDStr)
	imageInfo, err := rdb.Get(ctx, imageMapKey).Result()
	if err != nil {
		return "", "", err
	}

	binaryName, binaryPath, err := parseImageMetadata(imageInfo)
	if err != nil {
		return "", "", fmt.Errorf("parse %s: %w", imageMapKey, err)
	}

	log.Infof("✅ Parsed from image_id_map: binary='%s', path='%s' (raw: %s)",
		binaryName, binaryPath, imageInfo)

	return binaryName, binaryPath, nil
}

func parseImageMetadata(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty image metadata")
	}

	var record imageMetadataRecord
	if err := json.Unmarshal([]byte(raw), &record); err == nil {
		record.ImageName = strings.TrimSpace(record.ImageName)
		record.BinaryName = strings.TrimSpace(record.BinaryName)
		record.BinaryPath = strings.TrimSpace(record.BinaryPath)
		if record.ImageName == "" {
			return "", "", fmt.Errorf("JSON image metadata requires imageName and binaryName")
		}
		if err := validateImageMetadataBinaryName(record.BinaryName); err != nil {
			return "", "", err
		}
		if record.BinaryPath != "" && !filepath.IsAbs(record.BinaryPath) {
			return "", "", fmt.Errorf("JSON binaryPath must be absolute: %q", record.BinaryPath)
		}
		return record.BinaryName, record.BinaryPath, nil
	} else if strings.HasPrefix(raw, "{") {
		return "", "", fmt.Errorf("decode JSON image metadata: %w", err)
	}

	// Legacy completion records used "binary:/absolute/path". Split at the
	// first colon only when the suffix is visibly an absolute path.
	if colon := strings.IndexByte(raw, ':'); colon > 0 &&
		colon+1 < len(raw) && raw[colon+1] == '/' {
		binaryName := strings.TrimSpace(raw[:colon])
		binaryPath := strings.TrimSpace(raw[colon+1:])
		if binaryPath == "" {
			return "", "", fmt.Errorf("invalid legacy binary/path metadata %q", raw)
		}
		if err := validateImageMetadataBinaryName(binaryName); err != nil {
			return "", "", err
		}
		return binaryName, binaryPath, nil
	}

	// Older storage records used "<image-reference>:<binary>". Image
	// references may themselves contain registry ports and tags, so the final
	// colon is the only unambiguous delimiter.
	if colon := strings.LastIndexByte(raw, ':'); colon >= 0 && colon+1 < len(raw) {
		binaryName := strings.TrimSpace(raw[colon+1:])
		if err := validateImageMetadataBinaryName(binaryName); err == nil {
			return binaryName, "", nil
		}
	}

	return "", "", fmt.Errorf("unrecognized image metadata %q", raw)
}

func validateImageMetadataBinaryName(binaryName string) error {
	if binaryName == "" || binaryName == "unknown" {
		return fmt.Errorf("invalid binary name %q", binaryName)
	}
	if strings.ContainsAny(binaryName, "/\\") {
		return fmt.Errorf("binary name %q must not contain a path separator", binaryName)
	}
	return nil
}

func (p *plugin) saveBinaryInfoToTempKey(imageName, binaryName, binaryPath string) error {
	redisAddr := getEnv("REDIS_ADDR", DefaultRedisAddr)
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	// ⭐ JSON
	binaryInfo := map[string]string{
		"name": binaryName,
		"path": binaryPath,
	}

	jsonData, err := json.Marshal(binaryInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	err = rdb.Set(ctx, tempKey, jsonData, 1*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to save to Redis: %w", err)
	}

	log.Infof("✅ Saved temp binary: %s → {name: %s, path: %s}", tempKey, binaryName, binaryPath)
	return nil
}

func (p *plugin) saveBinaryToTempKey(imageName, binaryName string) error {
	redisAddr := getEnv("REDIS_ADDR", DefaultRedisAddr)
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	err := rdb.Set(ctx, tempKey, binaryName, 1*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to save to Redis: %w", err)
	}

	log.Infof("✅ Saved temp binary: %s → %s", tempKey, binaryName)
	return nil
}

func (p *plugin) guessFromImage(image string) string {
	parts := strings.Split(image, "/")
	name := strings.Split(parts[len(parts)-1], ":")[0]

	knownImages := map[string]string{
		"nginx":     "nginx",
		"redis":     "redis-server",
		"postgres":  "postgres",
		"mysql":     "mysqld",
		"memcached": "memcached",
		"mongodb":   "mongod",
		"apache":    "apache2",
		"httpd":     "httpd",
	}

	if binary, ok := knownImages[name]; ok {
		return binary
	}

	return name
}

// ========================================
// Utilities
// ========================================

func normalizeImageName(imageName string) string {
	normalized := strings.TrimPrefix(imageName, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")
	lastSlash := strings.LastIndexByte(normalized, '/')
	lastColon := strings.LastIndexByte(normalized, ':')
	namePart := normalized[lastSlash+1:]
	if lastColon <= lastSlash && !strings.Contains(namePart, "@") {
		normalized += ":latest"
	}
	return normalized
}

func getEnv(key, defaultValue string) string {
	// Explicit process configuration wins.
	if v := os.Getenv(key); v != "" {
		return v
	}

	// The NRI plugin runs as a host process, not in the installer Pod. The
	// installer writes the deployment-selected Redis endpoint to this
	// node-local file before restarting containerd.
	if key == "REDIS_ADDR" && RedisAddrFile != "" {
		if raw, err := os.ReadFile(RedisAddrFile); err == nil {
			if endpoint := strings.TrimSpace(string(raw)); validRedisEndpoint(endpoint) {
				return endpoint
			}
		}
	}

	// Retain the link-time value as a standalone-development fallback.
	if key == "REDIS_ADDR" && DefaultRedisAddr != "" {
		return DefaultRedisAddr
	}

	return defaultValue
}

func validRedisEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	return err == nil && portNumber != 0
}

func (p *plugin) onClose() {
	log.Info("Connection lost, exiting...")
	os.Exit(1)
}

// ========================================
// Main
// ========================================

func main() {
	var (
		pluginName string
		pluginIdx  string
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText:    true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	logFile, err := os.OpenFile("/var/log/sygma-nri.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.Parse()

	p := &plugin{}
	opts := []stub.Option{stub.WithOnClose(p.onClose)}

	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Fatalf("failed to create stub: %v", err)
	}

	log.Info("========================================")
	log.Info("SYGMA NRI Plugin Starting...")
	log.Info("Method: Universal (PATH Hijacking + Binary Replacement)")
	log.Info("========================================")

	if err = p.stub.Run(context.Background()); err != nil {
		log.Errorf("plugin exited: %v", err)
		os.Exit(1)
	}
}
