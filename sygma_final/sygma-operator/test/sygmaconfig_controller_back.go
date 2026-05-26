package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

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
	AnnotationEnforce   = "phalanx.io/enforce"
	AnnotationCollect   = "phalanx.io/collect"
	AnnotationImageName = "phalanx.io/image-name"
	AnnotationBinary    = "phalanx.io/binary"
	MinCollectionTime   = 60 * time.Second  //  60
	MaxCollectionTime   = 180 * time.Second //  3
	InitCheckInterval   = 5 * time.Second   // Init
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

	// ⭐ Collection   ( )
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
		return r.redeployPodWithAnnotations(ctx, config)

	case "CollectionStarted":
		return r.waitForCollectionData(ctx, config)

	case "Completed":
		// ⭐ Completed CollectionComplete false  (status  )
		logger.Info("Phase is Completed but CollectionComplete is false, fixing status")
		config.Status.CollectionComplete = true
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, nil

	default:
		logger.Info("Unknown phase", "phase", config.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *SYGMAConfigReconciler) waitForCollectionData(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// ⭐ Collection complete
	if config.Status.CollectionComplete {
		logger.Info("Collection already complete (early check)")
		return ctrl.Result{}, nil
	}

	// ⭐  Pod  ( )
	initialPod, err := r.findCollectionPod(ctx, config)
	if err != nil {
		logger.Error(err, "Failed to find collection pod at start")

		//
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
		"phase", initialPod.Status.Phase)

	const (
		MinCollectionTime = 1 * time.Second
		MaxCollectionTime = 180 * time.Second
		InitCheckInterval = 5 * time.Second
	)

	startTime := time.Now()

	for {
		elapsed := time.Since(startTime)

		// Minimum time check
		if elapsed < MinCollectionTime {
			logger.Info("Waiting for minimum collection time",
				"elapsed", elapsed.Round(time.Second),
				"remaining", (MinCollectionTime - elapsed).Round(time.Second))
			time.Sleep(InitCheckInterval)
			continue
		}

		// ⭐ Loop Pod  ( !)
		currentPod, err := r.findCollectionPod(ctx, config)
		if err != nil {
			logger.Error(err, "⚠️ Collection pod disappeared during wait period")
			// ⭐ Pod
			logger.Info("Proceeding with available data (pod not found)")
			return r.collectAndStoreTemplate(ctx, config)
		}

		// ⭐ Pod
		// if currentPod.Status.Phase != corev1.PodRunning {
		// 	logger.Info("⚠️ Collection pod is not running",
		// 		"podName", currentPod.Name,
		// 		"phase", currentPod.Status.Phase,
		// 		"reason", currentPod.Status.Reason)
		// 	// Pod
		// 	return r.collectAndStoreTemplate(ctx, config)
		// }
		switch currentPod.Status.Phase {
		case corev1.PodPending:
			//
			logger.Info("Pod pending, waiting for container creation")
			time.Sleep(InitCheckInterval)
			continue

		case corev1.PodRunning:
			//  init/main

		case corev1.PodSucceeded, corev1.PodFailed:
			//
			return r.collectAndStoreTemplate(ctx, config)
		}

		// ⭐  Pod init process
		initComplete, err := r.checkInitProcessesComplete(ctx, config, currentPod)
		if err != nil {
			logger.Error(err, "Failed to check init processes (non-fatal)",
				"podName", currentPod.Name)
			// ⭐    ( )
		} else if initComplete {
			logger.Info("✅ Collection complete (init processes done)",
				"duration", elapsed.Round(time.Second),
				"podName", currentPod.Name)
			return r.collectAndStoreTemplate(ctx, config)
		}

		// Maximum time check
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

	// ⭐ Namespace
	pidNs, mntNs, err := r.getPodNamespaces(ctx, pod)
	if err != nil {
		return false, fmt.Errorf("failed to get pod namespaces: %w", err)
	}

	// ⭐ execution_time_map
	mainPhaseStarted, err := r.BPFManager.CheckMainPhaseStarted(pidNs, mntNs)
	if err != nil {
		return false, fmt.Errorf("failed to check execution_time_map: %w", err)
	}

	if mainPhaseStarted {
		logger.Info("✅ Main phase started (execution_time == 1)",
			"pidNs", pidNs,
			"mntNs", mntNs,
			"binaryName", config.Status.BinaryName)
		return true, nil
	}

	logger.Info("Still in INIT phase (execution_time == 0)",
		"pidNs", pidNs,
		"mntNs", mntNs,
		"binaryName", config.Status.BinaryName)
	return false, nil
}

func (r *SYGMAConfigReconciler) collectAndStoreTemplate(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Collecting syscall data and storing image template")

	// ⭐ Pod   (  )
	pod, err := r.findCollectionPod(ctx, config)
	var pidNs, mntNs uint32

	if err != nil {
		logger.Info("⚠️ Collection pod not found, will use third-party data only",
			"error", err.Error())
		pidNs = 0
		mntNs = 0
	} else {
		// Namespace
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

	// Phase
	initPhaseData := make(map[string][]int)
	mainPhaseData := make(map[string][]int)

	// Phase third-party
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
				// Init Phase
				if initPhase, ok := phases["initPhase"].(map[string]interface{}); ok {
					if transitions, ok := initPhase["transitions"].(map[string]interface{}); ok {
						initPhaseData = convertTransitions(transitions)
						hasThirdPartyInit = true
						logger.Info("✅ Loaded third-party init phase", "transitions", len(initPhaseData))
					}
				}

				// Main Phase
				if mainPhase, ok := phases["mainPhase"].(map[string]interface{}); ok {
					if transitions, ok := mainPhase["transitions"].(map[string]interface{}); ok {
						mainPhaseData = convertTransitions(transitions)
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

	// ⭐ eBPF  (namespace )
	needEBPFCollection := !hasThirdPartyInit || !hasThirdPartyMain

	if needEBPFCollection && pidNs != 0 && mntNs != 0 {
		logger.Info("Collecting missing phases from eBPF with namespace filter",
			"needInit", !hasThirdPartyInit,
			"needMain", !hasThirdPartyMain,
			"pidNs", pidNs,
			"mntNs", mntNs)

		if r.BPFManager != nil {
			// ⭐ namespace
			collectedData, err := r.BPFManager.CollectFromGraphMap(pidNs, mntNs)
			if err != nil {
				logger.Error(err, "Failed to collect from graph map")
			} else {
				logger.Info("✅ Collected data from graph map (namespace-filtered)",
					"transitions", len(collectedData),
					"pidNs", pidNs,
					"mntNs", mntNs)

				// ⭐ Phase  (500 !)
				for key, syscalls := range collectedData {
					keyParts := strings.Split(key, ":")
					if len(keyParts) != 2 {
						continue
					}

					prevSyscallStr := keyParts[0]
					phase := keyParts[1]

					// ⭐ 500   from_syscall
					if phase == "0" && !hasThirdPartyInit {
						initPhaseData[prevSyscallStr] = syscalls

						// 500
						if prevSyscallStr == "500" {
							logger.Info("✅ Collected START (500) transition for init phase",
								"to_syscalls", len(syscalls),
								"first_few", syscalls[:min(5, len(syscalls))])
						}
					}

					if phase == "1" && !hasThirdPartyMain {
						mainPhaseData[prevSyscallStr] = syscalls

						// 500
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

	// Redis
	imageID, err := r.storeImageTemplate(config.Status.ImageName, config.Status.BinaryName, initPhaseData, mainPhaseData)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to store image template: %w", err)
	}

	logger.Info("✅ Image template stored in Redis", "imageID", imageID)

	// ⭐ eBPF   ( namespace)
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

	// Collection Pod  (pod  )
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

	// Status
	latestConfig := &securityv1.SYGMAConfig{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), latestConfig); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get latest config: %w", err)
	}

	latestConfig.Status.Phase = "Completed"
	latestConfig.Status.ImageID = imageID
	latestConfig.Status.CollectionComplete = true
	latestConfig.Status.Message = fmt.Sprintf("Collection completed (imageID=%d)", imageID)

	if err := r.Status().Update(ctx, latestConfig); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{Requeue: true}, nil
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

func MergePolicies(policies ...map[string][]int) map[string][]int {
	merged := make(map[string][]int)

	for _, policy := range policies {
		for prev, nexts := range policy {
			if _, exists := merged[prev]; !exists {
				merged[prev] = make([]int, 0)
			}

			// Union ( )
			syscallSet := make(map[int]bool)
			for _, s := range merged[prev] {
				syscallSet[s] = true
			}
			for _, s := range nexts {
				syscallSet[s] = true
			}

			//
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

	// /proc/self/ns/pid
	pidNsPath, err := r.execInPod(ctx, pod, "readlink", "/proc/self/ns/pid")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read pid namespace: %w", err)
	}

	// /proc/self/ns/mnt
	mntNsPath, err := r.execInPod(ctx, pod, "readlink", "/proc/self/ns/mnt")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read mnt namespace: %w", err)
	}

	// : "pid:[4026533429]" -> 4026533429
	pidNsPath = strings.TrimSpace(pidNsPath)
	mntNsPath = strings.TrimSpace(mntNsPath)

	var pidNsUint, mntNsUint uint64
	fmt.Sscanf(pidNsPath, "pid:[%d]", &pidNsUint)
	fmt.Sscanf(mntNsPath, "mnt:[%d]", &mntNsUint)

	logger.Info("Extracted namespaces from pod",
		"pidNs", pidNsUint,
		"mntNs", mntNsUint)

	return uint32(pidNsUint), uint32(mntNsUint), nil
}

func (r *SYGMAConfigReconciler) checkCollectionDataFromGraphMap(ctx context.Context, config *securityv1.SYGMAConfig, pod *corev1.Pod) (bool, error) {
	logger := log.FromContext(ctx)

	if r.BPFManager == nil {
		logger.Info("BPF Manager not available, skipping data check")
		return true, nil
	}

	// ⭐ Pod  namespace
	pidNs, mntNs, err := r.getPodNamespaces(ctx, pod)
	if err != nil {
		logger.Error(err, "Failed to get pod namespaces")
		return false, err
	}

	// collection_graph_map
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
		"statusBinaryName", config.Status.BinaryName)

	// ⭐ 1: Status.PodName
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

	// ⭐ 2: Annotation + Binary
	if config.Status.BinaryName != "" {
		for i := range podList.Items {
			pod := &podList.Items[i]
			if pod.Annotations["phalanx.io/collect"] == "true" &&
				pod.Annotations["phalanx.io/binary"] == config.Status.BinaryName {
				logger.V(1).Info("✅ Found collection pod by annotation+binary",
					"podName", pod.Name,
					"binary", config.Status.BinaryName)
				return pod, nil
			}
		}
	}

	// ⭐ 3: Collect annotation
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Annotations["phalanx.io/collect"] == "true" {
			logger.Info("✅ Found collection pod by collect annotation only",
				"podName", pod.Name)
			return pod, nil
		}
	}

	// ⭐ :  Pod
	logger.Info("❌ Collection pod not found, listing available pods")
	for i := range podList.Items {
		pod := &podList.Items[i]
		logger.Info("Available pod",
			"name", pod.Name,
			"phase", pod.Status.Phase,
			"collectAnnotation", pod.Annotations["phalanx.io/collect"],
			"binaryAnnotation", pod.Annotations["phalanx.io/binary"])
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

	// ⭐ CAP_SYS_PTRACE  (binary extraction)
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
	config.Status.Message = fmt.Sprintf("Pod %s deployed", pod.Name)
	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Initial pod deployed", "podName", pod.Name, "imageName", imageName, "namespace", pod.Namespace)
	return ctrl.Result{Requeue: true}, nil
}

func (r *SYGMAConfigReconciler) extractBinaryName(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Extracting binary name from running pod")

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(config.Namespace)); err != nil {
		return ctrl.Result{}, err
	}

	var targetPod *corev1.Pod
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Status.Phase == corev1.PodRunning {
			for _, container := range pod.Spec.Containers {
				if container.Image == config.Status.ImageName {
					targetPod = pod
					break
				}
			}
		}
		if targetPod != nil {
			break
		}
	}

	if targetPod == nil {
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	logger.Info("Found running pod", "podName", targetPod.Name)

	binaryPath, err := r.execInPod(ctx, targetPod, "readlink", "/proc/1/exe")
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to execute command in pod: %w", err)
	}

	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return ctrl.Result{}, fmt.Errorf("empty binary path from pod")
	}

	parts := strings.Split(binaryPath, "/")
	binaryName := parts[len(parts)-1]

	logger.Info("Extracted binary name", "path", binaryPath, "name", binaryName)

	config.Status.Phase = "BinaryExtracted"
	config.Status.BinaryName = binaryName
	config.Status.Message = fmt.Sprintf("Binary extracted: %s", binaryName)
	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: true}, nil
}

func (r *SYGMAConfigReconciler) redeployPodWithAnnotations(ctx context.Context, config *securityv1.SYGMAConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Redeploying pod with collection annotations")

	// ⭐
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

	if len(pod.Spec.Containers) > 0 {
		if pod.Spec.Containers[0].SecurityContext == nil {
			pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
		}

		pod.Spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
			Add: []corev1.Capability{"SYS_PTRACE"},
		}
	}

	if pod.Namespace == "" {
		pod.Namespace = config.Namespace
	}

	// ⭐  Pod
	oldPod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, oldPod); err == nil {
		if err := r.Delete(ctx, oldPod); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to delete old pod: %w", err)
		}
		logger.Info("Deleted old pod", "podName", pod.Name)

		// ⭐ Pod
		for i := 0; i < 30; i++ {
			checkPod := &corev1.Pod{}
			if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, checkPod); err != nil {
				if errors.IsNotFound(err) {
					logger.Info("Pod fully deleted", "attempts", i+1)
					break
				}
			}
			time.Sleep(500 * time.Millisecond)
		}

		// ⭐   (API server )
		time.Sleep(2 * time.Second)
	}

	// Annotation
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations["phalanx.io/collect"] = "true"
	pod.Annotations["phalanx.io/image-name"] = config.Status.ImageName
	pod.Annotations["phalanx.io/binary"] = config.Status.BinaryName

	logger.Info("Adding collection annotations",
		"image", config.Status.ImageName,
		"binary", config.Status.BinaryName)

	pod.ResourceVersion = ""
	pod.UID = ""

	// ⭐  Pod
	if err := r.Create(ctx, pod); err != nil {
		if !errors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create pod: %w", err)
		}
		logger.Info("Pod already exists")
	}

	// ⭐ Status
	config.Status.Phase = "CollectionStarted"
	config.Status.PodName = pod.Name
	config.Status.Message = "Pod redeployed with collection mode"
	if err := r.Status().Update(ctx, config); err != nil {
		logger.Info("Status update conflict, will retry")
		return ctrl.Result{Requeue: true}, nil
	}

	logger.Info("Pod redeployed with collection annotations", "podName", pod.Name)

	// ⭐ Pod
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

	// Init phase
	if len(initPhase) > 0 {
		storagePolicy := &storage.SyscallGraphPolicy{
			Metadata: storage.PolicyMetadata{
				Name:      "template",
				Namespace: "system",
			},
			Spec: storage.PolicySpec{
				ImageName:   imageName,
				BinaryName:  binaryName,
				Phase:       0, // INIT
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

	// Main phase
	if len(mainPhase) > 0 {
		storagePolicy := &storage.SyscallGraphPolicy{
			Metadata: storage.PolicyMetadata{
				Name:      "template",
				Namespace: "system",
			},
			Spec: storage.PolicySpec{
				ImageName:   imageName,
				BinaryName:  binaryName,
				Phase:       1, // MAIN
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
		return "", fmt.Errorf("Clientset is nil - check main.go initialization")
	}
	if r.Config == nil {
		return "", fmt.Errorf("Config is nil - check main.go initialization")
	}

	containerName := pod.Spec.Containers[0].Name

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

	logger.Info("Executing command in pod",
		"pod", pod.Name,
		"namespace", pod.Namespace,
		"container", containerName,
		"command", strings.Join(command, " "))

	exec, err := remotecommand.NewSPDYExecutor(r.Config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	if err != nil {
		logger.Error(err, "Command execution failed",
			"stdout", stdout.String(),
			"stderr", stderr.String())
		return "", fmt.Errorf("command execution failed: %w, stderr: %s", err, stderr.String())
	}

	output := stdout.String()
	logger.Info("Command output", "stdout", output)

	return output, nil
}

func (r *SYGMAConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.SYGMAConfig{}).
		Complete(r)
}
