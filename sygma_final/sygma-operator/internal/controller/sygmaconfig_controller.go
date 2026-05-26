package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "git.cclab.info/cclab-research/sygma/sygma-operator/api/v1"
	"git.cclab.info/cclab-research/sygma/sygma-operator/pkg/bpf"
	"git.cclab.info/cclab-research/sygma/sygma-operator/pkg/storage"
)

const (
	MinCollectionTime = 60 * time.Second  //  60
	MaxCollectionTime = 180 * time.Second //  3
	InitCheckInterval = 5 * time.Second   // Init
)

type SYGMAConfigReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Config         *rest.Config
	Clientset      *kubernetes.Clientset
	RedisClient    *storage.RedisClient
	SyscallManager *storage.SyscallGraphManager
	BPFManager     *bpf.Manager
}

//+kubebuilder:rbac:groups=security.security.io,resources=sygmaconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.security.io,resources=sygmaconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.security.io,resources=sygmaconfigs/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create

func (r *SYGMAConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	config := &securityv1.SYGMAConfig{}
	if err := r.Get(ctx, req.NamespacedName, config); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// ⭐ Collection
	if config.Status.CollectionComplete {
		logger.Info("Collection already completed, skipping reconciliation",
			"imageID", config.Status.ImageID,
			"phase", config.Status.Phase)
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling SYGMAConfig",
		"phase", config.Status.Phase,
		"collectionComplete", config.Status.CollectionComplete)

	switch config.Status.Phase {
	case "":
		return r.deployInitialPod(ctx, config)

	case "PodDeployed":
		return r.extractBinaryName(ctx, config)

	case "BinaryExtracted":
		// ⭐
		if r.hasWildcardPolicy(config) {
			logger.Info("🌟 Wildcard policy detected, skipping dynamic analysis")
			return r.storeWildcardPolicyDirectly(ctx, config)
		}
		return r.redeployPodWithAnnotations(ctx, config)

	case "CollectionStarted":
		return r.waitForCollectionData(ctx, config)

	case "Completed":
		if !config.Status.CollectionComplete {
			logger.Info("Phase is Completed but CollectionComplete is false, fixing status")
			config.Status.CollectionComplete = true
			if err := r.Status().Update(ctx, config); err != nil {
				return ctrl.Result{Requeue: true}, nil
			}
		}
		return ctrl.Result{}, nil

	default:
		logger.Info("Unknown phase", "phase", config.Status.Phase)
		return ctrl.Result{}, nil
	}
}

// ⭐
func (r *SYGMAConfigReconciler) hasWildcardPolicy(config *securityv1.SYGMAConfig) bool {
	if config.Spec.Collection.ThirdParty == nil {
		return false
	}

	var thirdPartyJSON []byte
	if config.Spec.Collection.ThirdParty.OutputContent != "" {
		thirdPartyJSON = []byte(config.Spec.Collection.ThirdParty.OutputContent)
	} else if config.Spec.Collection.ThirdParty.OutputPath != "" {
		data, err := os.ReadFile(config.Spec.Collection.ThirdParty.OutputPath)
		if err != nil {
			return false
		}
		thirdPartyJSON = data
	}

	if len(thirdPartyJSON) == 0 {
		return false
	}

	var thirdPartyData map[string]interface{}
	if err := json.Unmarshal(thirdPartyJSON, &thirdPartyData); err != nil {
		return false
	}

	phases, ok := thirdPartyData["phases"].(map[string]interface{})
	if !ok {
		return false
	}

	// Init Phase
	if initPhase, ok := phases["initPhase"].(map[string]interface{}); ok {
		if transitions, ok := initPhase["transitions"].(map[string]interface{}); ok {
			if hasWildcardInTransitions(transitions) {
				return true
			}
		}
	}

	// Main Phase
	if mainPhase, ok := phases["mainPhase"].(map[string]interface{}); ok {
		if transitions, ok := mainPhase["transitions"].(map[string]interface{}); ok {
			if hasWildcardInTransitions(transitions) {
				return true
			}
		}
	}

	return false
}

// ⭐ Transition (-1)
func hasWildcardInTransitions(transitions map[string]interface{}) bool {
	for _, value := range transitions {
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				switch num := item.(type) {
				case float64:
					if int(num) == -1 {
						return true
					}
				case int:
					if num == -1 {
						return true
					}
				}
			}
		}
	}
	return false
}

// ⭐     (  )
func (r *SYGMAConfigReconciler) storeWildcardPolicyDirectly(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("🚀 Storing wildcard policy directly (no dynamic analysis needed)")

	// ⭐     CollectionComplete  (  )
	latestConfig := &securityv1.SYGMAConfig{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get latest config: %w", err)
	}

	if latestConfig.Status.CollectionComplete {
		logger.Info("⚠️ Collection already completed by another reconcile, skipping")
		return ctrl.Result{}, nil
	}

	// ⭐ BinaryName BinaryPath  Status   (BinaryExtracted )
	binaryName := config.Status.BinaryName
	binaryPath := config.Status.BinaryPath
	imageName := config.Status.ImageName

	if binaryName == "" || binaryName == "unknown" {
		// ⭐ Redis
		logger.Info("🔍 Binary name not in status, attempting Redis lookup")
		var err error
		binaryName, err = r.getBinaryFromRedis(imageName)
		if err != nil || binaryName == "" {
			logger.Info("⚠️ Could not retrieve binary name, using 'unknown'")
			binaryName = "unknown"
		} else {
			logger.Info("✅ Retrieved binary name from Redis", "binary", binaryName)
		}
	}

	logger.Info("Using binary information from extraction phase",
		"imageName", imageName,
		"binaryName", binaryName,
		"binaryPath", binaryPath)

	// Third-party
	var thirdPartyJSON []byte
	var err error

	if config.Spec.Collection.ThirdParty.OutputContent != "" {
		thirdPartyJSON = []byte(config.Spec.Collection.ThirdParty.OutputContent)
	} else if config.Spec.Collection.ThirdParty.OutputPath != "" {
		thirdPartyJSON, err = os.ReadFile(config.Spec.Collection.ThirdParty.OutputPath)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to read third-party output: %w", err)
		}
	} else {
		return ctrl.Result{}, fmt.Errorf("no third-party policy provided")
	}

	var thirdPartyData map[string]interface{}
	if err := json.Unmarshal(thirdPartyJSON, &thirdPartyData); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to parse third-party JSON: %w", err)
	}

	// Phase
	initPhaseData := make(map[string][]int)
	mainPhaseData := make(map[string][]int)

	if phases, ok := thirdPartyData["phases"].(map[string]interface{}); ok {
		if initPhase, ok := phases["initPhase"].(map[string]interface{}); ok {
			if transitions, ok := initPhase["transitions"].(map[string]interface{}); ok {
				initPhaseData = convertTransitions(transitions)
				initPhaseData = expandWildcardTransitions(initPhaseData)
				logger.Info("✅ Loaded init phase from third-party", "transitions", len(initPhaseData))
			}
		}

		if mainPhase, ok := phases["mainPhase"].(map[string]interface{}); ok {
			if transitions, ok := mainPhase["transitions"].(map[string]interface{}); ok {
				mainPhaseData = convertTransitions(transitions)
				mainPhaseData = expandWildcardTransitions(mainPhaseData)
				logger.Info("✅ Loaded main phase from third-party", "transitions", len(mainPhaseData))
			}
		}
	}

	// Redis
	imageID, err := r.storeImageTemplate(imageName, binaryName, initPhaseData, mainPhaseData)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to store image template: %w", err)
	}

	logger.Info("✅ Wildcard policy stored in Redis", "imageID", imageID)

	// ⭐ BinaryPath   Redis
	if binaryPath != "" {
		imageInfoKey := fmt.Sprintf("image_id_map:%d", imageID)
		imageInfo := fmt.Sprintf("%s:%s", binaryName, binaryPath)

		if r.RedisClient != nil {
			err := r.RedisClient.Client.Set(r.RedisClient.Ctx, imageInfoKey, imageInfo, 0).Err()
			if err != nil {
				logger.Error(err, "Failed to save binary path to image_id_map (non-fatal)")
			} else {
				logger.Info("✅ Saved binary path to image_id_map",
					"imageID", imageID,
					"binaryName", binaryName,
					"binaryPath", binaryPath)
			}
		}
	}

	// ⭐  Pod  (  )
	pod, err := r.findCollectionPod(ctx, config)
	if err == nil && pod != nil {
		logger.Info("Deleting initial collection pod (no longer needed)",
			"podName", pod.Name)
		if err := r.Delete(ctx, pod); err != nil {
			if !errors.IsNotFound(err) {
				logger.Error(err, "Failed to delete pod (non-fatal)")
			}
		}
	}

	// ⭐ Status  (  )
	for attempt := 1; attempt <= 10; attempt++ { // 3 → 10
		latestConfig := &securityv1.SYGMAConfig{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err != nil {
			if attempt == 10 {
				logger.Error(err, "Failed to get config after 10 attempts")
				return ctrl.Result{RequeueAfter: 5 * time.Second}, err
			}
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
			continue
		}

		if latestConfig.Status.CollectionComplete {
			logger.Info("Already completed")
			return ctrl.Result{}, nil
		}

		latestConfig.Status.Phase = "Completed"
		latestConfig.Status.ImageID = imageID
		latestConfig.Status.ImageName = imageName
		latestConfig.Status.BinaryName = binaryName
		latestConfig.Status.BinaryPath = binaryPath
		latestConfig.Status.CollectionComplete = true
		latestConfig.Status.Message = fmt.Sprintf("Wildcard policy stored (imageID=%d)", imageID)

		if err := r.Status().Update(ctx, latestConfig); err != nil {
			if attempt == 10 {
				logger.Error(err, "Status update failed after 10 attempts")
				// ⭐
				return ctrl.Result{RequeueAfter: 5 * time.Second}, err
			}
			logger.V(1).Info("Conflict, retrying", "attempt", attempt)
			// ⭐
			time.Sleep(time.Duration(attempt*attempt*50) * time.Millisecond)
			continue
		}

		logger.Info("✅ Status updated", "attempt", attempt)
		break
	}

	logger.Info("✅ Workflow completed", "imageID", imageID)
	return ctrl.Result{}, nil
}

func expandWildcardTransitions(transitions map[string][]int) map[string][]int {
	//   syscall
	allSyscalls := make([]int, 0)

	// 500 (INIT sentinel)
	allSyscalls = append(allSyscalls, 500)

	// 0-334
	for i := 0; i <= 334; i++ {
		allSyscalls = append(allSyscalls, i)
	}

	// 424-448
	for i := 424; i <= 448; i++ {
		allSyscalls = append(allSyscalls, i)
	}

	expanded := make(map[string][]int)

	// ⭐ "-1": [-1]  (   shorthand)
	if toList, exists := transitions["-1"]; exists && len(toList) == 1 && toList[0] == -1 {
		// "-1": [-1] !  syscall
		for _, from := range allSyscalls {
			fromKey := fmt.Sprintf("%d", from)
			expanded[fromKey] = make([]int, len(allSyscalls))
			copy(expanded[fromKey], allSyscalls)
		}
		return expanded
	}

	//
	for fromStr, toList := range transitions {
		// to [-1]  syscall
		if len(toList) == 1 && toList[0] == -1 {
			expanded[fromStr] = make([]int, len(allSyscalls))
			copy(expanded[fromStr], allSyscalls)
		} else {
			expanded[fromStr] = toList
		}
	}

	return expanded
}

// ⭐ YAML
func (r *SYGMAConfigReconciler) extractImageFromYAML(yamlData []byte) (string, string, error) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	codecFactory := serializer.NewCodecFactory(scheme)
	deserializer := codecFactory.UniversalDeserializer()

	obj, _, err := deserializer.Decode(yamlData, nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode YAML: %w", err)
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return "", "", fmt.Errorf("decoded object is not a Pod")
	}

	if len(pod.Spec.Containers) == 0 {
		return "", "", fmt.Errorf("pod has no containers")
	}

	imageName := pod.Spec.Containers[0].Image

	// Binary name  (image name)
	binaryName := imageName
	if colonIndex := strings.LastIndex(imageName, ":"); colonIndex >= 0 {
		binaryName = imageName[:colonIndex]
	}
	if slashIndex := strings.LastIndex(binaryName, "/"); slashIndex >= 0 {
		binaryName = binaryName[slashIndex+1:]
	}

	return imageName, binaryName, nil
}

func (r *SYGMAConfigReconciler) getBinaryFromRedis(imageName string) (string, error) {
	if r.RedisClient == nil {
		return "", fmt.Errorf("RedisClient not initialized")
	}

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	result, err := r.RedisClient.Client.Get(r.RedisClient.Ctx, tempKey).Result()
	if err != nil {
		return "", fmt.Errorf("binary not found in Redis: %w", err)
	}

	// ⭐ JSON
	var binaryInfo map[string]string
	if err := json.Unmarshal([]byte(result), &binaryInfo); err != nil {
		// Backward compatibility:
		return strings.TrimSpace(result), nil
	}

	// JSON  name  (  )
	return binaryInfo["name"], nil
}

func (r *SYGMAConfigReconciler) waitForCollectionData(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if config.Status.CollectionComplete {
		logger.Info("Collection already complete (early check)")
		return ctrl.Result{}, nil
	}

	// ⭐ BinaryName "unknown" Redis
	if config.Status.BinaryName == "unknown" {
		logger.Info("🔍 Binary name is 'unknown', attempting Redis lookup")

		// NRI      10 polling
		for attempt := 0; attempt < 10; attempt++ {
			binaryName, err := r.getBinaryFromRedis(config.Status.ImageName)
			if err == nil && binaryName != "" {
				logger.Info("✅ Found binary name from Redis (NRI provided)",
					"binary", binaryName,
					"attempt", attempt+1)

				// Status
				config.Status.BinaryName = binaryName
				config.Status.Message = fmt.Sprintf("Binary name from NRI: %s", binaryName)
				if err := r.Status().Update(ctx, config); err != nil {
					logger.Error(err, "Failed to update binary name from Redis")
				}
				break
			}

			if attempt < 9 {
				logger.V(1).Info("Binary not yet in Redis, waiting...", "attempt", attempt+1)
				time.Sleep(1 * time.Second)
			} else {
				logger.Info("⚠️ Could not retrieve binary from Redis, continuing with 'unknown'")
			}
		}
	}

	initialPod, err := r.findCollectionPod(ctx, config)
	if err != nil {
		logger.Error(err, "Failed to find collection pod at start")

		latestConfig := &securityv1.SYGMAConfig{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err == nil {
			if latestConfig.Status.CollectionComplete {
				logger.Info("Collection already completed (verified)")
				return ctrl.Result{}, nil
			}
		}

		return ctrl.Result{}, fmt.Errorf("failed to find collection pod: %w", err)
	}

	logger.Info("✅ Found collection pod for monitoring",
		"podName", initialPod.Name,
		"namespace", initialPod.Namespace,
		"phase", initialPod.Status.Phase,
		"binaryName", config.Status.BinaryName)

	// ...     ...
	const (
		MinCollectionTime = 1 * time.Second
		MaxCollectionTime = 180 * time.Second
		InitCheckInterval = 5 * time.Second
	)

	startTime := time.Now()

	for {
		elapsed := time.Since(startTime)

		if elapsed < MinCollectionTime {
			logger.Info("Waiting for minimum collection time",
				"elapsed", elapsed.Round(time.Second),
				"remaining", (MinCollectionTime - elapsed).Round(time.Second))
			time.Sleep(InitCheckInterval)
			continue
		}

		currentPod, err := r.findCollectionPod(ctx, config)
		if err != nil {
			logger.Error(err, "⚠️ Collection pod disappeared during wait period")
			logger.Info("Proceeding with available data (pod not found)")
			return r.collectAndStoreTemplate(ctx, config)
		}

		switch currentPod.Status.Phase {
		case corev1.PodPending:
			logger.Info("Pod pending, waiting for container creation")
			time.Sleep(InitCheckInterval)
			continue

		case corev1.PodRunning:
			// init/main

		case corev1.PodSucceeded, corev1.PodFailed:
			return r.collectAndStoreTemplate(ctx, config)
		}

		initComplete, err := r.checkInitProcessesComplete(ctx, config, currentPod)
		if err != nil {
			logger.Error(err, "Failed to check init processes (non-fatal)",
				"podName", currentPod.Name)
		} else if initComplete {
			logger.Info("✅ Collection complete (init processes done)",
				"duration", elapsed.Round(time.Second),
				"podName", currentPod.Name)
			return r.collectAndStoreTemplate(ctx, config)
		}

		if elapsed >= MaxCollectionTime {
			logger.Info("⚠️ Maximum wait time reached, proceeding with available data",
				"podName", currentPod.Name)
			return r.collectAndStoreTemplate(ctx, config)
		}

		logger.Info("Init processes still running, waiting",
			"elapsed", elapsed.Round(time.Second),
			"maxRemaining", (MaxCollectionTime - elapsed).Round(time.Second),
			"podName", currentPod.Name,
			"podPhase", currentPod.Status.Phase)

		time.Sleep(InitCheckInterval)
	}
}

func (r *SYGMAConfigReconciler) checkInitProcessesComplete(ctx context.Context, config *securityv1.SYGMAConfig, pod *corev1.Pod) (bool, error) {
	logger := log.FromContext(ctx)

	pidNs, mntNs, err := r.getPodNamespaces(ctx, pod)
	if err != nil {
		logger.Info("⚠️ Failed to get namespaces, using /proc/1/comm fallback only",
			"error", err.Error())
		return r.checkMainBinaryRunning(ctx, pod, config.Status.BinaryName)
	}

	// ⭐ Namespace 0, 0 eBPF
	if pidNs == 0 && mntNs == 0 {
		logger.Info("⚠️ Namespace unavailable, using /proc/1/comm fallback")
		return r.checkMainBinaryRunning(ctx, pod, config.Status.BinaryName)
	}

	// eBPF
	if r.BPFManager != nil {
		mainPhaseStarted, err := r.BPFManager.CheckMainPhaseStarted(pidNs, mntNs)
		if err != nil {
			if strings.Contains(err.Error(), "key does not exist") ||
				strings.Contains(err.Error(), "not found") {
				logger.Info("⚠️ execution_time_map entry not found",
					"pidNs", pidNs,
					"mntNs", mntNs)
				return r.checkMainBinaryRunning(ctx, pod, config.Status.BinaryName)
			}
			return false, fmt.Errorf("failed to check execution_time_map: %w", err)
		}

		if mainPhaseStarted {
			logger.Info("✅ Main phase started (execution_time == 1)",
				"pidNs", pidNs,
				"mntNs", mntNs)
			return true, nil
		}

		logger.Info("Still in INIT phase (execution_time == 0)",
			"pidNs", pidNs,
			"mntNs", mntNs)
		return false, nil
	}

	return r.checkMainBinaryRunning(ctx, pod, config.Status.BinaryName)
}

func (r *SYGMAConfigReconciler) checkMainBinaryRunning(ctx context.Context, pod *corev1.Pod, expectedBinary string) (bool, error) {
	logger := log.FromContext(ctx)

	currentComm, err := r.execInPod(ctx, pod, "cat", "/proc/1/comm")
	if err != nil {
		logger.Error(err, "Failed to read /proc/1/comm")
		return false, err
	}

	currentComm = strings.TrimSpace(currentComm)

	if len(expectedBinary) > 15 {
		expectedBinary = expectedBinary[:15]
	}

	matched := strings.HasPrefix(currentComm, expectedBinary)

	logger.Info("Checking main binary via /proc/1/comm",
		"expectedBinary", expectedBinary,
		"currentComm", currentComm,
		"matched", matched)

	return matched, nil
}

func (r *SYGMAConfigReconciler) collectAndStoreTemplate(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Collecting syscall data and storing image template")

	// ⭐     CollectionComplete  (  )
	latestConfig := &securityv1.SYGMAConfig{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get latest config: %w", err)
	}

	if latestConfig.Status.CollectionComplete {
		logger.Info("⚠️ Collection already completed by another reconcile, skipping")
		return ctrl.Result{}, nil
	}

	pod, err := r.findCollectionPod(ctx, config)
	var pidNs, mntNs uint32

	if err != nil {
		logger.Info("⚠️ Collection pod not found, will use third-party data only",
			"error", err.Error())
		pidNs = 0
		mntNs = 0
	} else {
		pidNs, mntNs, err = r.getPodNamespaces(ctx, pod)
		if err != nil {
			logger.Error(err, "Failed to get pod namespaces, cleanup will be skipped")
			pidNs = 0
			mntNs = 0
		} else {
			logger.Info("✅ Extracted namespaces from pod",
				"pidNs", pidNs,
				"mntNs", mntNs,
				"podName", pod.Name)
		}
	}

	initPhaseData := make(map[string][]int)
	mainPhaseData := make(map[string][]int)

	hasThirdPartyInit := false
	hasThirdPartyMain := false

	if config.Spec.Collection.ThirdParty != nil {
		var thirdPartyJSON []byte
		var err error

		if config.Spec.Collection.ThirdParty.OutputContent != "" {
			thirdPartyJSON = []byte(config.Spec.Collection.ThirdParty.OutputContent)
			logger.Info("Using inline third-party output content")
		} else if config.Spec.Collection.ThirdParty.OutputPath != "" {
			thirdPartyJSON, err = os.ReadFile(config.Spec.Collection.ThirdParty.OutputPath)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to read third-party output: %w", err)
			}
			logger.Info("Using third-party output from file")
		}

		if len(thirdPartyJSON) > 0 {
			var thirdPartyData map[string]interface{}
			if err := json.Unmarshal(thirdPartyJSON, &thirdPartyData); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to parse third-party JSON: %w", err)
			}

			if phases, ok := thirdPartyData["phases"].(map[string]interface{}); ok {
				if initPhase, ok := phases["initPhase"].(map[string]interface{}); ok {
					if transitions, ok := initPhase["transitions"].(map[string]interface{}); ok {
						initPhaseData = convertTransitions(transitions)
						initPhaseData = expandWildcardTransitions(initPhaseData)
						hasThirdPartyInit = true
						logger.Info("✅ Loaded third-party init phase", "transitions", len(initPhaseData))
					}
				}

				if mainPhase, ok := phases["mainPhase"].(map[string]interface{}); ok {
					if transitions, ok := mainPhase["transitions"].(map[string]interface{}); ok {
						mainPhaseData = convertTransitions(transitions)
						mainPhaseData = expandWildcardTransitions(mainPhaseData)
						hasThirdPartyMain = true
						logger.Info("✅ Loaded third-party main phase", "transitions", len(mainPhaseData))

						if startTransitions, hasStart := mainPhaseData["500"]; hasStart {
							logger.Info("✅ Found START (500) transition in third-party data",
								"to_syscalls", len(startTransitions),
								"destinations", startTransitions)
						}
					}
				}
			}
		}
	}

	needEBPFCollection := !hasThirdPartyInit || !hasThirdPartyMain

	if needEBPFCollection && pidNs != 0 && mntNs != 0 {
		logger.Info("Collecting missing phases from eBPF with namespace filter",
			"needInit", !hasThirdPartyInit,
			"needMain", !hasThirdPartyMain,
			"pidNs", pidNs,
			"mntNs", mntNs)

		if r.BPFManager != nil {
			collectedData, err := r.BPFManager.CollectFromGraphMap(pidNs, mntNs)
			if err != nil {
				logger.Error(err, "Failed to collect from graph map")
			} else {
				logger.Info("✅ Collected data from graph map (namespace-filtered)",
					"transitions", len(collectedData),
					"pidNs", pidNs,
					"mntNs", mntNs)

				for key, syscalls := range collectedData {
					keyParts := strings.Split(key, ":")
					if len(keyParts) != 2 {
						continue
					}

					prevSyscallStr := keyParts[0]
					phase := keyParts[1]

					if phase == "0" && !hasThirdPartyInit {
						initPhaseData[prevSyscallStr] = syscalls

						if prevSyscallStr == "500" {
							logger.Info("✅ Collected START (500) transition for init phase",
								"to_syscalls", len(syscalls),
								"first_few", syscalls[:min(5, len(syscalls))])
						}
					}

					if phase == "1" && !hasThirdPartyMain {
						mainPhaseData[prevSyscallStr] = syscalls

						if prevSyscallStr == "500" {
							logger.Info("✅ Collected START (500) transition for main phase",
								"to_syscalls", len(syscalls),
								"first_few", syscalls[:min(5, len(syscalls))])
						}
					}
				}
			}
		} else {
			logger.Info("BPF Manager not available, using third-party data only")
		}
	}

	logger.Info("Final phase data",
		"initTransitions", len(initPhaseData),
		"mainTransitions", len(mainPhaseData),
		"initSource", map[bool]string{true: "third-party", false: "eBPF"}[hasThirdPartyInit],
		"mainSource", map[bool]string{true: "third-party", false: "eBPF"}[hasThirdPartyMain])

	if startInit, hasStartInit := initPhaseData["500"]; hasStartInit {
		logger.Info("✅ Final init phase includes START (500) transition", "to_syscalls", len(startInit))
	}
	if startMain, hasStartMain := mainPhaseData["500"]; hasStartMain {
		logger.Info("✅ Final main phase includes START (500) transition", "to_syscalls", len(startMain))
	}

	imageID, err := r.storeImageTemplate(config.Status.ImageName, config.Status.BinaryName, initPhaseData, mainPhaseData)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to store image template: %w", err)
	}

	// ⭐ BinaryPath   Redis  (image_id_map  )
	if config.Status.BinaryPath != "" {
		imageInfoKey := fmt.Sprintf("image_id_map:%d", imageID)
		imageInfo := fmt.Sprintf("%s:%s", config.Status.BinaryName, config.Status.BinaryPath)

		if r.RedisClient != nil {
			err := r.RedisClient.Client.Set(r.RedisClient.Ctx, imageInfoKey, imageInfo, 0).Err()
			if err != nil {
				logger.Error(err, "Failed to save binary path to image_id_map (non-fatal)")
			} else {
				logger.Info("✅ Saved binary path to image_id_map",
					"imageID", imageID,
					"binaryName", config.Status.BinaryName,
					"binaryPath", config.Status.BinaryPath)
			}
		}
	}

	logger.Info("✅ Image template stored in Redis", "imageID", imageID)

	if pidNs != 0 && mntNs != 0 && r.BPFManager != nil {
		logger.Info("Cleaning up eBPF collection maps for specific namespace",
			"pidNs", pidNs,
			"mntNs", mntNs)
		if err := r.BPFManager.CleanupCollectionMode(pidNs, mntNs); err != nil {
			logger.Error(err, "Failed to cleanup eBPF maps (non-fatal)")
		} else {
			logger.Info("✅ eBPF collection maps cleaned up")
		}
	}

	if pod != nil {
		if err := r.Delete(ctx, pod); err != nil {
			if !errors.IsNotFound(err) {
				logger.Error(err, "Failed to delete collection pod (non-fatal)")
			}
		} else {
			logger.Info("Collection pod deleted successfully", "podName", pod.Name)
		}
	} else {
		logger.Info("No collection pod to delete (already gone)")
	}

	// ⭐ Status
	for attempt := 1; attempt <= 3; attempt++ {
		latestConfig := &securityv1.SYGMAConfig{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err != nil {
			if attempt == 3 {
				return ctrl.Result{}, fmt.Errorf("failed to get config (attempt %d): %w", attempt, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if latestConfig.Status.CollectionComplete {
			logger.Info("Collection completed by concurrent reconcile")
			return ctrl.Result{}, nil
		}

		latestConfig.Status.Phase = "Completed"
		latestConfig.Status.ImageID = imageID
		latestConfig.Status.CollectionComplete = true
		latestConfig.Status.Message = fmt.Sprintf("Collection completed (imageID=%d)", imageID)

		if err := r.Status().Update(ctx, latestConfig); err != nil {
			logger.Info("Status update conflict, retrying",
				"attempt", attempt,
				"error", err.Error())

			if attempt == 3 {
				logger.Error(err, "⚠️ Status update failed after 3 attempts, but collection is complete")
				return ctrl.Result{}, nil
			}

			time.Sleep(200 * time.Millisecond * time.Duration(attempt))
			continue
		}

		logger.Info("✅ Status updated successfully", "attempt", attempt)
		break
	}

	logger.Info("✅ Collection workflow completed", "imageID", imageID)
	return ctrl.Result{}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *SYGMAConfigReconciler) handleWrapperScript(ctx context.Context, pod *corev1.Pod, binaryName string, logger logr.Logger) string {
	wrapperScripts := []string{
		"sh", "bash", "dash",
		"docker-entrypoint", "entrypoint",
		"docker-init", "tini",
		"foreground", // httpd-foreground, nginx-foreground
	}

	isWrapper := false
	for _, wrapper := range wrapperScripts {
		if strings.Contains(strings.ToLower(binaryName), wrapper) {
			isWrapper = true
			logger.Info("🔄 Wrapper script detected", "wrapper", binaryName)
			break
		}
	}

	if !isWrapper {
		return binaryName
	}

	// Wrapper →
	logger.Info("⏳ Waiting for execve to real binary...")
	maxRetries := 6 // 30 (5 * 6)

	for i := 0; i < maxRetries; i++ {
		time.Sleep(5 * time.Second)

		currentBinary, err := r.execInPod(ctx, pod, "cat", "/proc/1/comm")
		if err != nil {
			logger.V(1).Info("Failed to read comm during wrapper wait", "retry", i+1)
			continue
		}

		currentBinary = strings.TrimSpace(currentBinary)

		// Wrapper
		stillWrapper := false
		for _, wrapper := range wrapperScripts {
			if strings.Contains(strings.ToLower(currentBinary), wrapper) {
				stillWrapper = true
				break
			}
		}

		if !stillWrapper {
			logger.Info("✅ Detected execve transition",
				"from", binaryName,
				"to", currentBinary,
				"waitTime", fmt.Sprintf("%ds", (i+1)*5))
			return currentBinary
		}

		logger.V(1).Info("Still wrapper, retrying...",
			"binary", currentBinary,
			"retry", i+1)
	}

	// Timeout  wrapper
	logger.Info("⚠️ Wrapper timeout, using original binary name", "binary", binaryName)
	return binaryName
}

func MergePolicies(policies ...map[string][]int) map[string][]int {
	merged := make(map[string][]int)

	for _, policy := range policies {
		for prev, nexts := range policy {
			if _, exists := merged[prev]; !exists {
				merged[prev] = make([]int, 0)
			}

			syscallSet := make(map[int]bool)
			for _, s := range merged[prev] {
				syscallSet[s] = true
			}
			for _, s := range nexts {
				syscallSet[s] = true
			}

			result := make([]int, 0, len(syscallSet))
			for s := range syscallSet {
				result = append(result, s)
			}
			sort.Ints(result)
			merged[prev] = result
		}
	}

	return merged
}

func (r *SYGMAConfigReconciler) getPodNamespaces(ctx context.Context, pod *corev1.Pod) (pidNs, mntNs uint32, err error) {
	logger := log.FromContext(ctx)

	// ⭐  1: Redis  (OCI Hook  )
	if r.RedisClient != nil {
		// Container ID
		if len(pod.Status.ContainerStatuses) > 0 {
			containerID := pod.Status.ContainerStatuses[0].ContainerID
			// : "containerd://7541836bf9ec5b88d5bbb0285edb4544ef2cc13eb29ecdb96ee985238a039b51"
			if strings.Contains(containerID, "://") {
				parts := strings.Split(containerID, "://")
				if len(parts) == 2 {
					containerID = parts[1]
				}
			}

			if containerID != "" {
				pidNs, mntNs, err := r.getNamespacesFromRedis(containerID)
				if err == nil {
					logger.Info("✅ Got namespaces from Redis (OCI Hook)",
						"containerID", containerID[:12],
						"pidNs", pidNs,
						"mntNs", mntNs)
					return pidNs, mntNs, nil
				}
				logger.V(1).Info("Redis namespace lookup failed", "error", err)
			}
		}
	}

	// ⭐  2: readlink (  )
	pidNsPath, err := r.execInPod(ctx, pod, "readlink", "/proc/self/ns/pid")
	if err == nil {
		mntNsPath, err := r.execInPod(ctx, pod, "readlink", "/proc/self/ns/mnt")
		if err == nil {
			pidNsPath = strings.TrimSpace(pidNsPath)
			mntNsPath = strings.TrimSpace(mntNsPath)

			var pidNsUint, mntNsUint uint64
			fmt.Sscanf(pidNsPath, "pid:[%d]", &pidNsUint)
			fmt.Sscanf(mntNsPath, "mnt:[%d]", &mntNsUint)

			logger.Info("✅ Got namespaces via readlink",
				"pidNs", pidNsUint,
				"mntNs", mntNsUint)

			return uint32(pidNsUint), uint32(mntNsUint), nil
		}
	}

	logger.V(1).Info("readlink failed", "error", err)

	// ⭐  3: cat /proc/self/status (namespace     )
	//   eBPF   /proc/1/comm
	logger.Info("⚠️ Could not extract namespaces, using fallback mode (no eBPF)")
	return 0, 0, nil //   0, 0
}

func (r *SYGMAConfigReconciler) getNamespacesFromRedis(containerID string) (uint32, uint32, error) {
	if r.RedisClient == nil {
		return 0, 0, fmt.Errorf("RedisClient not initialized")
	}

	key := fmt.Sprintf("container:ns:%s", containerID)

	data, err := r.RedisClient.Client.Get(r.RedisClient.Ctx, key).Bytes()
	if err != nil {
		return 0, 0, fmt.Errorf("namespace not found in Redis: %w", err)
	}

	var nsInfo map[string]uint32
	if err := json.Unmarshal(data, &nsInfo); err != nil {
		return 0, 0, fmt.Errorf("failed to parse namespace info: %w", err)
	}

	pidNs, hasPid := nsInfo["pidNs"]
	mntNs, hasMnt := nsInfo["mntNs"]

	if !hasPid || !hasMnt {
		return 0, 0, fmt.Errorf("incomplete namespace info")
	}

	return pidNs, mntNs, nil
}

func (r *SYGMAConfigReconciler) checkCollectionDataFromGraphMap(ctx context.Context, config *securityv1.SYGMAConfig, pod *corev1.Pod) (bool, error) {
	logger := log.FromContext(ctx)

	if r.BPFManager == nil {
		logger.Info("BPF Manager not available, skipping data check")
		return true, nil
	}

	pidNs, mntNs, err := r.getPodNamespaces(ctx, pod)
	if err != nil {
		logger.Error(err, "Failed to get pod namespaces")
		return false, err
	}

	data, err := r.BPFManager.CollectFromGraphMap(pidNs, mntNs)
	if err != nil {
		return false, err
	}

	minTransitions := 5
	if len(data) >= minTransitions {
		logger.Info("Sufficient data collected", "transitions", len(data))
		return true, nil
	}

	logger.Info("Insufficient data collected yet",
		"transitions", len(data),
		"minimum", minTransitions)
	return false, nil
}

// ⭐⭐⭐  : findCollectionPod ⭐⭐⭐
func (r *SYGMAConfigReconciler) findCollectionPod(ctx context.Context, config *securityv1.SYGMAConfig) (*corev1.Pod, error) {
	logger := log.FromContext(ctx)

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(config.Namespace)); err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	logger.V(1).Info("Searching for collection pod",
		"namespace", config.Namespace,
		"totalPods", len(podList.Items),
		"statusPodName", config.Status.PodName,
		"statusImageName", config.Status.ImageName)

	// ⭐ 1: Status.PodName ( )
	if config.Status.PodName != "" {
		for i := range podList.Items {
			pod := &podList.Items[i]
			if pod.Name == config.Status.PodName {
				logger.V(1).Info("✅ Found collection pod by status.podName",
					"podName", pod.Name,
					"phase", pod.Status.Phase)
				return pod, nil
			}
		}
		logger.Info("⚠️ Status.PodName set but pod not found",
			"expectedPodName", config.Status.PodName)
	}

	// ⭐ 2: sygma.io/mode=collection annotation
	// (redeployPodWithAnnotations  )
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Annotations["sygma.io/mode"] == "collection" {
			logger.Info("✅ Found collection pod by sygma.io/mode annotation",
				"podName", pod.Name,
				"phase", pod.Status.Phase)
			return pod, nil
		}
	}

	// ⭐ 3: Image name
	// (  annotation  )
	if config.Status.ImageName != "" {
		for i := range podList.Items {
			pod := &podList.Items[i]
			if len(pod.Spec.Containers) > 0 {
				if pod.Spec.Containers[0].Image == config.Status.ImageName {
					// ⭐ Pod  "collection"
					if strings.Contains(pod.Name, "collection") {
						logger.Info("✅ Found collection pod by image name",
							"podName", pod.Name,
							"phase", pod.Status.Phase,
							"image", config.Status.ImageName)
						return pod, nil
					}
				}
			}
		}
	}

	logger.Info("❌ Collection pod not found, listing available pods")
	for i := range podList.Items {
		pod := &podList.Items[i]
		logger.Info("Available pod",
			"name", pod.Name,
			"phase", pod.Status.Phase,
			"sygmaMode", pod.Annotations["sygma.io/mode"],
			"hasCollection", strings.Contains(pod.Name, "collection"),
			"image", func() string {
				if len(pod.Spec.Containers) > 0 {
					return pod.Spec.Containers[0].Image
				}
				return ""
			}())
	}

	return nil, fmt.Errorf("collection pod not found (searched %d pods in namespace %s)",
		len(podList.Items), config.Namespace)
}

func (r *SYGMAConfigReconciler) checkCollectionData(ctx context.Context, pod *corev1.Pod) (bool, error) {
	logger := log.FromContext(ctx)

	if r.BPFManager == nil {
		logger.Info("BPF Manager not available, skipping data check")
		return true, nil
	}

	data, err := r.BPFManager.CollectInitPhaseData()
	if err != nil {
		return false, err
	}

	minTransitions := 5
	if len(data) >= minTransitions {
		logger.Info("Sufficient data collected", "transitions", len(data))
		return true, nil
	}

	logger.Info("Insufficient data collected yet",
		"transitions", len(data),
		"minimum", minTransitions)
	return false, nil
}

func (r *SYGMAConfigReconciler) deployInitialPod(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Deploying initial pod for collection")

	var podYAML []byte
	var err error

	if config.Spec.Collection.YAMLContent != "" {
		podYAML = []byte(config.Spec.Collection.YAMLContent)
		logger.Info("Using inline YAML content")
	} else if config.Spec.Collection.YAMLPath != "" {
		podYAML, err = os.ReadFile(config.Spec.Collection.YAMLPath)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to read YAML: %w", err)
		}
		logger.Info("Using YAML from file", "path", config.Spec.Collection.YAMLPath)
	} else {
		return ctrl.Result{}, fmt.Errorf("either yamlContent or yamlPath must be specified")
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	codecFactory := serializer.NewCodecFactory(scheme)
	deserializer := codecFactory.UniversalDeserializer()

	obj, _, err := deserializer.Decode(podYAML, nil, nil)
	if err != nil {
		logger.Error(err, "Failed to decode YAML", "yaml", string(podYAML))
		return ctrl.Result{}, fmt.Errorf("failed to decode pod YAML: %w", err)
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return ctrl.Result{}, fmt.Errorf("decoded object is not a Pod")
	}

	logger.Info("Parsed pod", "name", pod.Name, "namespace", pod.Namespace, "image", pod.Spec.Containers[0].Image)

	if pod.Namespace == "" {
		pod.Namespace = config.Namespace
		logger.Info("Set pod namespace from SYGMAConfig", "namespace", pod.Namespace)
	}

	if pod.Name == "" {
		return ctrl.Result{}, fmt.Errorf("pod name is empty in YAML")
	}

	if len(pod.Spec.Containers) == 0 {
		return ctrl.Result{}, fmt.Errorf("pod has no containers")
	}

	// ⭐⭐⭐ Config Operator    (eBPF   ) ⭐⭐⭐
	operatorNode := os.Getenv("NODE_NAME")
	if operatorNode != "" {
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		pod.Spec.NodeSelector["kubernetes.io/hostname"] = operatorNode
		logger.Info("✅ Added nodeSelector to deploy on same node as Config Operator",
			"node", operatorNode,
			"reason", "eBPF map access required")
	} else {
		logger.Info("⚠️ NODE_NAME not set, pod may be scheduled on different node (eBPF access may fail)")
	}

	if pod.Spec.Containers[0].SecurityContext == nil {
		pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
	}

	pod.Spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
		Add: []corev1.Capability{"SYS_PTRACE"},
	}

	logger.Info("Added SYS_PTRACE capability for /proc/1/exe access")

	imageName := pod.Spec.Containers[0].Image

	if err := r.Create(ctx, pod); err != nil {
		if !errors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create pod: %w", err)
		}
		logger.Info("Pod already exists, continuing")
	}

	config.Status.Phase = "PodDeployed"
	config.Status.ImageName = imageName
	config.Status.PodName = pod.Name
	config.Status.Message = fmt.Sprintf("Pod %s deployed on node %s", pod.Name, operatorNode)
	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("✅ Initial pod deployed on same node",
		"podName", pod.Name,
		"imageName", imageName,
		"namespace", pod.Namespace,
		"targetNode", operatorNode)

	return ctrl.Result{Requeue: true}, nil
}

func (r *SYGMAConfigReconciler) extractBinaryName(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Extracting binary name and path from pod spec and runtime")

	// ⭐ 1. Container Spec
	executedBinary, err := r.getExecutedBinaryFromSpec(config)
	if err != nil {
		logger.Error(err, "Failed to get executed binary from spec")
		// Fallback to old method
		return r.extractBinaryNameLegacy(ctx, config)
	}
	logger.Info("✅ Executed binary from container spec", "binary", executedBinary)

	// ⭐ 2. Running pod
	targetPod, err := r.waitForPodRunning(ctx, config)
	if err != nil {
		logger.Info("⏳ Pod not yet running")
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// ⭐ 3. which
	binaryPath, err := r.execInPod(ctx, targetPod, "which", executedBinary)
	if err != nil {
		logger.Info("which failed, trying command -v", "error", err)
		// Fallback: command -v
		binaryPath, err = r.execInPod(ctx, targetPod, "sh", "-c", fmt.Sprintf("command -v %s", executedBinary))
		if err != nil {
			logger.Error(err, "Failed to find binary path, using readlink fallback")
			// Final fallback: readlink
			return r.extractBinaryNameLegacy(ctx, config)
		}
	}

	binaryPath = strings.TrimSpace(binaryPath)
	logger.Info("✅ Found binary path",
		"binary", executedBinary,
		"path", binaryPath)

	// ⭐ 4. Symlink
	isSymlink, finalTarget := r.checkIfSymlink(ctx, targetPod, binaryPath)
	if isSymlink {
		logger.Info("🔗 Binary is symlink",
			"symlink", binaryPath,
			"target", finalTarget)
	}

	// ⭐ 5. Redis
	if err := r.saveBinaryInfoToRedis(config.Status.ImageName, executedBinary, binaryPath); err != nil {
		logger.Error(err, "Failed to save to Redis (non-fatal)")
	}

	// ⭐ 6. Status
	config.Status.Phase = "BinaryExtracted"
	config.Status.BinaryName = executedBinary // "python"
	config.Status.BinaryPath = binaryPath     // "/usr/local/bin/python"
	config.Status.Message = fmt.Sprintf("Binary: %s at %s", executedBinary, binaryPath)
	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("✅ Binary extraction complete",
		"binary", executedBinary,
		"path", binaryPath,
		"isSymlink", isSymlink)

	return ctrl.Result{Requeue: true}, nil
}

// Legacy method (  )
func (r *SYGMAConfigReconciler) extractBinaryNameLegacy(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Using legacy binary extraction method (readlink /proc/1/exe)")

	targetPod, err := r.waitForPodRunning(ctx, config)
	if err != nil {
		logger.Info("⏳ Pod not yet running")
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	logger.Info("Found running pod", "podName", targetPod.Name)

	var binaryName string
	var binaryPath string

	// ⭐ 1 : readlink /proc/1/exe
	exePath, err := r.execInPod(ctx, targetPod, "readlink", "/proc/1/exe")
	if err == nil {
		exePath = strings.TrimSpace(exePath)
		if exePath != "" && !strings.Contains(exePath, "(deleted)") {
			// ✅ :
			binaryPath = exePath
			parts := strings.Split(exePath, "/")
			binaryName = parts[len(parts)-1]

			logger.Info("✅ Binary from /proc/1/exe",
				"name", binaryName,
				"path", binaryPath)

			binaryName = r.handleWrapperScript(ctx, targetPod, binaryName, logger)

			if err := r.saveBinaryInfoToRedis(config.Status.ImageName, binaryName, binaryPath); err != nil {
				logger.Error(err, "Failed to save to Redis (non-fatal)")
			}

			config.Status.Phase = "BinaryExtracted"
			config.Status.BinaryName = binaryName
			config.Status.BinaryPath = binaryPath
			config.Status.Message = fmt.Sprintf("Binary: %s at %s", binaryName, binaryPath)
			if err := r.Status().Update(ctx, config); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{Requeue: true}, nil
		}
	}

	// ⭐ readlink  → OCI Hook
	logger.Info("⚠️ readlink failed or returned deleted path",
		"error", err,
		"path", exePath)
	logger.Info("📍 Binary path will be extracted by OCI Hook during deployment")

	// ⭐
	if r.hasWildcardPolicy(config) {
		logger.Info("🌟 Wildcard policy detected, no binary path needed")

		config.Status.Phase = "BinaryExtracted"
		config.Status.BinaryName = "unknown"
		config.Status.BinaryPath = ""
		config.Status.Message = "Wildcard policy (binary will be detected by OCI Hook)"
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	// ⭐   /proc/1/comm
	logger.Info("📍 Attempting /proc/1/comm for binary name")
	binaryName, err = r.execInPod(ctx, targetPod, "cat", "/proc/1/comm")
	if err != nil {
		logger.Error(err, "Failed to read /proc/1/comm, marking as unknown")

		config.Status.Phase = "BinaryExtracted"
		config.Status.BinaryName = "unknown"
		config.Status.BinaryPath = ""
		config.Status.Message = "Binary name extraction failed (will use OCI Hook fallback)"
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	binaryName = strings.TrimSpace(binaryName)
	logger.Info("✅ Binary name from /proc/1/comm (path unknown)", "binary", binaryName)

	// ⭐   ( OCI Hook )
	if err := r.saveBinaryInfoToRedis(config.Status.ImageName, binaryName, ""); err != nil {
		logger.Error(err, "Failed to save to Redis (non-fatal)")
	}

	config.Status.Phase = "BinaryExtracted"
	config.Status.BinaryName = binaryName
	config.Status.BinaryPath = ""
	config.Status.Message = fmt.Sprintf("Binary name: %s (path will be detected by OCI Hook)", binaryName)
	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: true}, nil
}

func (r *SYGMAConfigReconciler) waitForPodRunning(ctx context.Context, config *securityv1.SYGMAConfig) (*corev1.Pod, error) {
	logger := log.FromContext(ctx)

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(config.Namespace)); err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Status.PodName
	if config.Status.PodName != "" {
		for i := range podList.Items {
			pod := &podList.Items[i]
			if pod.Name == config.Status.PodName && pod.Status.Phase == corev1.PodRunning {
				logger.Info("Found running pod by name", "podName", pod.Name)
				return pod, nil
			}
		}
	}

	// ImageName
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Status.Phase == corev1.PodRunning {
			if len(pod.Spec.Containers) > 0 && pod.Spec.Containers[0].Image == config.Status.ImageName {
				logger.Info("Found running pod by image", "podName", pod.Name)
				return pod, nil
			}
		}
	}

	logger.Info("⏳ Pod not yet running")
	return nil, fmt.Errorf("no running pod found")
}

func (r *SYGMAConfigReconciler) getExecutedBinaryFromSpec(config *securityv1.SYGMAConfig) (string, error) {
	var podYAML []byte
	var err error

	if config.Spec.Collection.YAMLContent != "" {
		podYAML = []byte(config.Spec.Collection.YAMLContent)
	} else if config.Spec.Collection.YAMLPath != "" {
		podYAML, err = os.ReadFile(config.Spec.Collection.YAMLPath)
		if err != nil {
			return "", fmt.Errorf("failed to read YAML: %w", err)
		}
	} else {
		return "", fmt.Errorf("no YAML content or path specified")
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	codecFactory := serializer.NewCodecFactory(scheme)
	deserializer := codecFactory.UniversalDeserializer()

	obj, _, err := deserializer.Decode(podYAML, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decode YAML: %w", err)
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return "", fmt.Errorf("decoded object is not a Pod")
	}

	if len(pod.Spec.Containers) == 0 {
		return "", fmt.Errorf("no containers in pod")
	}

	container := pod.Spec.Containers[0]

	// Args
	if len(container.Args) > 0 {
		return filepath.Base(container.Args[0]), nil
	}

	// Command fallback
	if len(container.Command) > 0 {
		return filepath.Base(container.Command[0]), nil
	}

	return "", fmt.Errorf("no args or command in container")
}

func (r *SYGMAConfigReconciler) checkIfSymlink(ctx context.Context, pod *corev1.Pod, path string) (bool, string) {
	// readlink -f
	output, err := r.execInPod(ctx, pod, "readlink", "-f", path)
	if err != nil {
		return false, ""
	}

	finalPath := strings.TrimSpace(output)
	return path != finalPath, finalPath
}

// resolveBinaryPathFromPATH -  PATH
// httpd-foreground   PATH   httpd
func (r *SYGMAConfigReconciler) resolveBinaryPathFromPATH(ctx context.Context, pod *corev1.Pod, binaryName string, logger logr.Logger) string {
	if binaryName == "" || binaryName == "unknown" {
		return ""
	}

	logger.Info("🔍 Attempting to resolve binary path from PATH environment variable",
		"binary", binaryName)

	// 1.  PATH
	envOutput, err := r.execInPod(ctx, pod, "sh", "-c", "echo $PATH")
	if err != nil {
		logger.Info("⚠️ Failed to read PATH from container", "error", err.Error())
		// Fallback:  PATH
		envOutput = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	pathEnv := strings.TrimSpace(envOutput)
	logger.Info("📂 Container PATH", "PATH", pathEnv)

	// 2. PATH
	pathDirs := strings.Split(pathEnv, ":")
	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}

		candidatePath := fmt.Sprintf("%s/%s", dir, binaryName)

		// test -x
		testCmd := fmt.Sprintf("test -x '%s' && echo 'found'", candidatePath)
		result, err := r.execInPod(ctx, pod, "sh", "-c", testCmd)
		if err == nil && strings.TrimSpace(result) == "found" {
			logger.Info("✅ Resolved binary path from PATH",
				"binary", binaryName,
				"path", candidatePath,
				"searchedDir", dir)
			return candidatePath
		}
	}

	logger.Info("⚠️ Binary not found in PATH directories",
		"binary", binaryName,
		"searchedPaths", pathDirs)
	return ""
}

func (r *SYGMAConfigReconciler) saveBinaryInfoToRedis(imageName, binaryName, binaryPath string) error {
	if r.RedisClient == nil {
		return fmt.Errorf("RedisClient not initialized")
	}

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	// ⭐ JSON
	binaryInfo := map[string]string{
		"name": binaryName,
		"path": binaryPath,
	}

	jsonData, err := json.Marshal(binaryInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal binary info: %w", err)
	}

	// 1 TTL
	err = r.RedisClient.Client.Set(r.RedisClient.Ctx, tempKey, jsonData, 1*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to save binary info to Redis: %w", err)
	}

	fmt.Printf("✅ Saved binary info to Redis: %s → {name: %s, path: %s}\n",
		tempKey, binaryName, binaryPath)
	return nil
}

func (r *SYGMAConfigReconciler) saveBinaryToRedis(imageName, binaryName string) error {
	if r.RedisClient == nil {
		return fmt.Errorf("RedisClient not initialized")
	}

	normalized := normalizeImageName(imageName)
	tempKey := fmt.Sprintf("temp_binary:%s", normalized)

	// 1 TTL
	err := r.RedisClient.Client.Set(r.RedisClient.Ctx, tempKey, binaryName, 1*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to save binary to Redis: %w", err)
	}

	fmt.Printf("✅ Saved temp binary to Redis: %s → %s", tempKey, binaryName)
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

// ⭐⭐⭐  : redeployPodWithAnnotations ⭐⭐⭐
func (r *SYGMAConfigReconciler) redeployPodWithAnnotations(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Redeploying pod with collection annotations")

	if r.BPFManager != nil {
		logger.Info("🧹 Cleaning up all stale collection data before new collection")
		if err := r.BPFManager.CleanupAllStaleData(); err != nil {
			logger.Error(err, "Failed to cleanup stale data (non-fatal, continuing)")
		} else {
			logger.Info("✅ Stale data cleanup complete")
		}
	}

	var podYAML []byte
	var err error

	if config.Spec.Collection.YAMLContent != "" {
		podYAML = []byte(config.Spec.Collection.YAMLContent)
		logger.Info("Using inline YAML content for redeployment")
	} else if config.Spec.Collection.YAMLPath != "" {
		podYAML, err = os.ReadFile(config.Spec.Collection.YAMLPath)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to read YAML: %w", err)
		}
		logger.Info("Using YAML from file for redeployment", "path", config.Spec.Collection.YAMLPath)
	} else {
		return ctrl.Result{}, fmt.Errorf("either yamlContent or yamlPath must be specified")
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	codecFactory := serializer.NewCodecFactory(scheme)
	deserializer := codecFactory.UniversalDeserializer()

	obj, _, err := deserializer.Decode(podYAML, nil, nil)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to decode pod YAML: %w", err)
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return ctrl.Result{}, fmt.Errorf("decoded object is not a Pod")
	}

	// if len(pod.Spec.Containers) > 0 {
	// 	if pod.Spec.Containers[0].SecurityContext == nil {
	// 		pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
	// 	}

	// 	pod.Spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
	// 		Add: []corev1.Capability{"SYS_PTRACE"},
	// 	}
	// }

	if pod.Namespace == "" {
		pod.Namespace = config.Namespace
	}

	operatorNode := os.Getenv("NODE_NAME")
	if operatorNode != "" {
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		pod.Spec.NodeSelector["kubernetes.io/hostname"] = operatorNode
		logger.Info("✅ Added nodeSelector for collection pod",
			"node", operatorNode,
			"reason", "Must match Config Operator node for eBPF map access")
	} else {
		logger.Info("⚠️ NODE_NAME not set, collection may fail if pod scheduled on different node")
	}

	oldPod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, oldPod); err == nil {
		logger.Info("Found existing pod, initiating deletion",
			"podName", oldPod.Name,
			"currentPhase", oldPod.Status.Phase)

		if err := r.Delete(ctx, oldPod); err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("failed to delete old pod: %w", err)
		}
		logger.Info("Deletion initiated", "podName", pod.Name)

		const maxWaitTime = 60 * time.Second
		const checkInterval = 1 * time.Second
		deadline := time.Now().Add(maxWaitTime)

		for time.Now().Before(deadline) {
			checkPod := &corev1.Pod{}
			err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, checkPod)

			if err != nil {
				if errors.IsNotFound(err) {
					elapsed := time.Since(time.Now().Add(-maxWaitTime))
					logger.Info("✅ Pod fully deleted",
						"podName", pod.Name,
						"elapsed", elapsed.Round(time.Second))
					break
				}
				logger.V(1).Info("Transient error checking pod deletion", "error", err)
			} else {
				logger.Info("⏳ Waiting for pod termination",
					"podName", checkPod.Name,
					"phase", checkPod.Status.Phase,
					"deletionTimestamp", checkPod.DeletionTimestamp)

				if checkPod.DeletionTimestamp != nil {
					elapsed := time.Since(checkPod.DeletionTimestamp.Time)
					if elapsed > 45*time.Second {
						logger.Info("⚠️ Pod deletion taking longer than expected",
							"podName", checkPod.Name,
							"elapsed", elapsed.Round(time.Second),
							"status", checkPod.Status.Phase,
							"reason", checkPod.Status.Reason)
					}
				}
			}

			time.Sleep(checkInterval)
		}

		checkPod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, checkPod); err == nil {
			logger.Info("⚠️ Pod deletion timeout reached, but pod still exists",
				"podName", checkPod.Name,
				"phase", checkPod.Status.Phase,
				"waitTime", maxWaitTime)

			gracePeriod := int64(0)
			deleteOptions := client.DeleteOptions{
				GracePeriodSeconds: &gracePeriod,
			}
			if err := r.Delete(ctx, checkPod, &deleteOptions); err != nil && !errors.IsNotFound(err) {
				logger.Error(err, "Failed to force delete pod")
			} else {
				logger.Info("Initiated force deletion (grace period 0)")
				time.Sleep(5 * time.Second)
			}
		}

		logger.Info("Waiting for API server stabilization")
		time.Sleep(3 * time.Second)
	} else if !errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to check existing pod: %w", err)
	} else {
		logger.Info("No existing pod found, proceeding with creation")
	}

	// ⭐ SYGMA Annotations
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations["sygma.io/mode"] = "collection"

	// ⭐ ImageName  (NRI )
	if config.Status.ImageName != "" {
		pod.Annotations["sygma.io/image"] = config.Status.ImageName
		logger.Info("✅ Added image annotation for NRI", "image", config.Status.ImageName)
	}

	// ⭐ BinaryName  (, NRI fallback  )
	if config.Status.BinaryName != "" && config.Status.BinaryName != "unknown" {
		pod.Annotations["sygma.io/binary"] = config.Status.BinaryName
		logger.Info("✅ Added binary annotation for NRI", "binary", config.Status.BinaryName)
	}

	logger.Info("✅ Adding SYGMA collection annotations",
		"mode", "collection",
		"image", config.Status.ImageName,
		"binary", config.Status.BinaryName)

	pod.ResourceVersion = ""
	pod.UID = ""

	if err := r.Create(ctx, pod); err != nil {
		if !errors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create pod: %w", err)
		}
		logger.Info("Pod already exists")
	}

	config.Status.Phase = "CollectionStarted"
	config.Status.PodName = pod.Name
	config.Status.Message = "Pod redeployed with collection mode"
	if err := r.Status().Update(ctx, config); err != nil {
		logger.Info("Status update conflict, will retry")
		return ctrl.Result{Requeue: true}, nil
	}

	logger.Info("✅ Pod redeployed with SYGMA collection mode", "podName", pod.Name)

	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
}

func (r *SYGMAConfigReconciler) deleteCollectionPod(ctx context.Context, config *securityv1.SYGMAConfig) error {
	logger := log.FromContext(ctx)

	pod, err := r.findCollectionPod(ctx, config)
	if err != nil {
		return fmt.Errorf("pod not found for deletion: %w", err)
	}

	logger.Info("Deleting collection pod", "podName", pod.Name)

	if err := r.Delete(ctx, pod); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete pod: %w", err)
		}
	}

	return nil
}

func convertTransitions(input map[string]interface{}) map[string][]int {
	result := make(map[string][]int)

	for key, value := range input {
		switch v := value.(type) {
		case []interface{}:
			intSlice := make([]int, 0, len(v))
			for _, item := range v {
				switch num := item.(type) {
				case float64:
					intSlice = append(intSlice, int(num))
				case int:
					intSlice = append(intSlice, num)
				}
			}
			result[key] = intSlice
		case []int:
			result[key] = v
		}
	}

	return result
}

func (r *SYGMAConfigReconciler) storeImageTemplate(imageName, binaryName string, initPhase, mainPhase map[string][]int) (uint32, error) {
	var imageID uint32

	// ⭐ BinaryPath    ,
	// Status

	if len(initPhase) > 0 {
		storagePolicy := &storage.SyscallGraphPolicy{
			Metadata: storage.PolicyMetadata{
				Name:      "template",
				Namespace: "system",
			},
			Spec: storage.PolicySpec{
				ImageName:   imageName,
				BinaryName:  binaryName,
				Phase:       0,
				Transitions: initPhase,
			},
		}

		result, err := r.SyscallManager.ProcessSyscallGraphPolicy(storagePolicy)
		if err != nil {
			return 0, fmt.Errorf("failed to store init phase: %w", err)
		}
		imageID = result.ImageID
		fmt.Printf("Stored init phase for imageID %d\n", imageID)
	}

	if len(mainPhase) > 0 {
		storagePolicy := &storage.SyscallGraphPolicy{
			Metadata: storage.PolicyMetadata{
				Name:      "template",
				Namespace: "system",
			},
			Spec: storage.PolicySpec{
				ImageName:   imageName,
				BinaryName:  binaryName,
				Phase:       1,
				Transitions: mainPhase,
			},
		}

		result, err := r.SyscallManager.ProcessSyscallGraphPolicy(storagePolicy)
		if err != nil {
			return 0, fmt.Errorf("failed to store main phase: %w", err)
		}

		if imageID == 0 {
			imageID = result.ImageID
		}
		fmt.Printf("Stored main phase for imageID %d\n", imageID)
	}

	return imageID, nil
}

func (r *SYGMAConfigReconciler) execInPod(ctx context.Context, pod *corev1.Pod, command ...string) (string, error) {
	logger := log.FromContext(ctx)

	if r.Clientset == nil {
		return "", fmt.Errorf("Clientset is nil")
	}
	if r.Config == nil {
		return "", fmt.Errorf("Config is nil")
	}

	containerName := pod.Spec.Containers[0].Name

	// ⭐ Context
	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req := r.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	logger.V(1).Info("Executing command in pod",
		"pod", pod.Name,
		"command", strings.Join(command, " "))

	exec, err := remotecommand.NewSPDYExecutor(r.Config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer

	err = exec.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	if err != nil {
		// ⭐
		if execCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("exec timeout after 15s: %w", err)
		}

		logger.V(1).Info("Command failed",
			"stdout", stdout.String(),
			"stderr", stderr.String())
		return "", fmt.Errorf("command failed: %w", err)
	}

	return stdout.String(), nil
}

func (r *SYGMAConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.SYGMAConfig{}).
		Complete(r)
}
