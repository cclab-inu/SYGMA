package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1 "example.org/sygma/operator/api/v1"
	"example.org/sygma/operator/pkg/bpf"
	"example.org/sygma/operator/pkg/storage"
)

type SYGMAPolicyReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	RedisClient    *storage.RedisClient
	SyscallManager *storage.SyscallGraphManager
	BPFManager     *bpf.Manager
	NodeName       string
}

type PodMetadata struct {
	Namespace  string `json:"namespace"`
	PodName    string `json:"podName"`
	ImageName  string `json:"imageName"`
	ImageID    uint32 `json:"imageID"`
	BinaryName string `json:"binaryName"`
	PolicyName string `json:"policyName"`
	PidNs      uint32 `json:"pidNs"`
	MntNs      uint32 `json:"mntNs"`
}

func (r *SYGMAPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy := &securityv1.SYGMAPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err := validateInitOnlyPhases(policy.Spec.Phases); err != nil {
		return r.updateStatusWithError(ctx, policy, err.Error())
	}

	if r.NodeName != "" && policy.Spec.NodeName != "" {
		if policy.Spec.NodeName != r.NodeName {

			logger.V(1).Info("Policy not for this node, skipping",
				"policyNode", policy.Spec.NodeName,
				"thisNode", r.NodeName)
			return ctrl.Result{}, nil
		}
	}

	logger.Info("Reconciling SYGMAPolicy",
		"name", policy.Name,
		"namespace", policy.Namespace,
		"node", policy.Spec.NodeName)

	pidNs := policy.Spec.PidNs
	mntNs := policy.Spec.MntNs

	if pidNs == 0 || mntNs == 0 {
		metadata, err := r.loadPodMetadata(ctx, policy.Namespace, extractPodName(policy.Name))
		if err != nil {
			logger.Info("Metadata not found yet, will retry", "error", err.Error())
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		pidNs = metadata.PidNs
		mntNs = metadata.MntNs
	}

	if len(policy.Spec.Phases) == 0 {
		logger.Info("Empty policy detected, loading from Redis")

		imageID := policy.Spec.ImageID
		if imageID == 0 {

			metadata, err := r.loadPodMetadata(ctx, policy.Namespace, extractPodName(policy.Name))
			if err != nil {
				logger.Info("Metadata not found yet, will retry", "error", err.Error())
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
			imageID = metadata.ImageID
		}

		phases, err := r.loadPolicyFromRedis(ctx, imageID)
		if err != nil {
			logger.Error(err, "Failed to load policy from Redis")
			return r.updateStatusWithError(ctx, policy, "Failed to load: "+err.Error())
		}

		policy.Spec.Phases = phases
		if err := r.Update(ctx, policy); err != nil {
			logger.Error(err, "Failed to update policy spec")
			return ctrl.Result{}, err
		}

		logger.Info("✅ Policy loaded from Redis", "transitions", countTransitions(phases))

		if err := r.updatePodPolicyInEBPF(policy, pidNs, mntNs); err != nil {
			logger.Error(err, "Failed to update eBPF")
			return r.updateStatusWithError(ctx, policy, "eBPF update failed: "+err.Error())
		}

		return r.updateStatusSuccess(ctx, policy, pidNs, mntNs, imageID)
	}

	if policy.Status.ObservedGeneration == policy.Generation {
		logger.Info("Policy already applied to this generation", "generation", policy.Generation)
		return ctrl.Result{}, nil
	}

	logger.Info("Policy update detected, applying changes",
		"generation", policy.Generation,
		"observedGeneration", policy.Status.ObservedGeneration)

	if err := r.updatePodPolicyInEBPF(policy, pidNs, mntNs); err != nil {
		logger.Error(err, "Failed to update eBPF")
		return r.updateStatusWithError(ctx, policy, "eBPF update failed: "+err.Error())
	}

	logger.Info("✅ Policy updated")
	return r.updateStatusSuccess(ctx, policy, pidNs, mntNs, policy.Status.ImageID)
}

func (r *SYGMAPolicyReconciler) updateStatusSuccess(ctx context.Context, policy *securityv1.SYGMAPolicy, pidNs, mntNs, imageID uint32) (ctrl.Result, error) {
	if err := r.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		return ctrl.Result{}, err
	}

	policy.Status.Phase = "active"
	policy.Status.ImageID = imageID
	policy.Status.LastUpdated = metav1.Now()
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.Message = fmt.Sprintf("Policy active (pidns=%d, mntns=%d)", pidNs, mntNs)
	policy.Status.LoadedTransitions = countTransitions(policy.Spec.Phases)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{RequeueAfter: time.Second},
			fmt.Errorf("update SYGMAPolicy success status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *SYGMAPolicyReconciler) updateStatusWithError(ctx context.Context, policy *securityv1.SYGMAPolicy, message string) (ctrl.Result, error) {
	if err := r.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		return ctrl.Result{}, err
	}

	policy.Status.Phase = "error"
	policy.Status.Message = message
	policy.Status.LastUpdated = metav1.Now()
	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{RequeueAfter: time.Second},
			fmt.Errorf("update SYGMAPolicy error status: %w", err)
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func extractPodName(policyName string) string {
	if len(policyName) > 7 && policyName[len(policyName)-7:] == "-policy" {
		return policyName[:len(policyName)-7]
	}
	return policyName
}

func countTransitions(phases map[string]securityv1.PhaseRuleSet) int {
	initPhase, exists := phases["initPhase"]
	if !exists {
		return 0
	}
	return len(initPhase.RuleSet)
}

func validateInitOnlyPhases(phases map[string]securityv1.PhaseRuleSet) error {
	for name, phase := range phases {
		if name != "initPhase" {
			return fmt.Errorf(
				"phase %q is unsupported: main state-machine policy is installed by the OCI hook",
				name,
			)
		}
		if len(phase.RuleSet) == 0 {
			return fmt.Errorf("initPhase contains no bootstrap graph rows")
		}
	}
	return nil
}

func (r *SYGMAPolicyReconciler) loadPodMetadata(ctx context.Context, namespace, podName string) (*PodMetadata, error) {
	metadataKey := fmt.Sprintf("pod:metadata:%s:%s", namespace, podName)

	metadataJSON, err := r.RedisClient.Client.Get(ctx, metadataKey).Result()
	if err != nil {
		return nil, fmt.Errorf("metadata not found: %w", err)
	}

	var metadata PodMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

func (r *SYGMAPolicyReconciler) loadPolicyFromRedis(ctx context.Context, imageID uint32) (map[string]securityv1.PhaseRuleSet, error) {
	readyKey := storage.PolicyReadyKey(imageID)
	revisionBefore, err := r.RedisClient.Client.Get(ctx, readyKey).Result()
	if err != nil {
		return nil, fmt.Errorf("policy publication is not ready for image %d: %w", imageID, err)
	}
	if revisionBefore == "" {
		return nil, fmt.Errorf("policy publication has an empty revision for image %d", imageID)
	}

	pattern := fmt.Sprintf("syscall_graph:%d:0:*", imageID)
	keys, err := r.RedisClient.Client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get init graph keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("init bootstrap graph is empty for image %d", imageID)
	}

	transitions := make(map[string][]int)
	for _, key := range keys {
		var keyImageID, keyPhase, fromSyscall uint32
		if _, err := fmt.Sscanf(key, "syscall_graph:%d:%d:%d", &keyImageID, &keyPhase, &fromSyscall); err != nil || keyPhase != 0 {
			continue
		}

		data, err := r.RedisClient.Client.Get(ctx, key).Bytes()
		if err != nil || len(data) != 45 {
			continue
		}

		allowedSyscalls := []int{}
		for bitIndex := uint32(0); bitIndex < 360; bitIndex++ {
			bytePos := bitIndex >> 3
			bitOffset := bitIndex & 7
			byteIndex := 44 - bytePos
			if data[byteIndex]&(1<<bitOffset) != 0 {
				allowedSyscalls = append(allowedSyscalls, int(bitIndexToSyscall(bitIndex)))
			}
		}
		transitions[strconv.Itoa(int(fromSyscall))] = allowedSyscalls
	}
	if len(transitions) == 0 {
		return nil, fmt.Errorf("init bootstrap graph has no readable rows for image %d", imageID)
	}

	revisionAfter, err := r.RedisClient.Client.Get(ctx, readyKey).Result()
	if err != nil || revisionAfter != revisionBefore {
		return nil, fmt.Errorf("policy publication changed while loading image %d", imageID)
	}

	return map[string]securityv1.PhaseRuleSet{
		"initPhase": {RuleSet: transitions},
	}, nil
}

func (r *SYGMAPolicyReconciler) updatePodPolicyInEBPF(policy *securityv1.SYGMAPolicy, pidNs, mntNs uint32) error {
	logger := log.Log.WithName("sygmapolicy")

	if r.BPFManager == nil {
		return fmt.Errorf("BPF Manager not available")
	}

	logger.Info("Updating eBPF maps", "pidNs", pidNs, "mntNs", mntNs)

	if err := validateInitOnlyPhases(policy.Spec.Phases); err != nil {
		return err
	}
	initPhase, exists := policy.Spec.Phases["initPhase"]
	if !exists {
		return fmt.Errorf("initPhase bootstrap graph is missing")
	}
	logger.Info("Updating init bootstrap phase", "transitions", len(initPhase.RuleSet))
	if err := r.BPFManager.UpdateSyscallGraphMapByNamespace(
		pidNs, mntNs, 0, initPhase.RuleSet,
	); err != nil {
		logger.Error(err, "Failed to update init bootstrap phase")
		return fmt.Errorf("failed to update init bootstrap phase: %w", err)
	}
	logger.Info("✅ Init bootstrap phase updated")

	return nil
}

func syscallToBitIndex(syscall uint32) uint32 {
	if syscall <= 334 {
		return syscall
	}
	if syscall >= 424 && syscall <= 448 {
		return 335 + (syscall - 424)
	}
	return 0xFFFFFFFF
}

func bitIndexToSyscall(bitIndex uint32) uint32 {
	if bitIndex <= 334 {
		return bitIndex
	}
	if bitIndex < 360 {
		return 424 + (bitIndex - 335)
	}
	return 0xFFFFFFFF
}

func (r *SYGMAPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {

	if r.NodeName == "" {
		r.NodeName = os.Getenv("NODE_NAME")
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.SYGMAPolicy{})

	if r.NodeName != "" {
		nodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
			policy, ok := obj.(*securityv1.SYGMAPolicy)
			if !ok {
				return false
			}

			return policy.Spec.NodeName == "" || policy.Spec.NodeName == r.NodeName
		})
		builder = builder.WithEventFilter(nodeFilter)
	}

	return builder.Complete(r)
}
