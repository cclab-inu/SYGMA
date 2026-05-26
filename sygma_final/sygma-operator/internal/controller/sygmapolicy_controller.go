// internal/controller/sygmapolicy_controller.go
//  SYGMAPolicy Controller - NodeName

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

	securityv1 "git.cclab.info/cclab-research/sygma/sygma-operator/api/v1"
	"git.cclab.info/cclab-research/sygma/sygma-operator/pkg/bpf"
	"git.cclab.info/cclab-research/sygma/sygma-operator/pkg/storage"
)

type SYGMAPolicyReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	RedisClient    *storage.RedisClient
	SyscallManager *storage.SyscallGraphManager
	BPFManager     *bpf.Manager
	NodeName       string // ⭐ NEW: Agent
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

//+kubebuilder:rbac:groups=security.security.io,resources=sygmapolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.security.io,resources=sygmapolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.security.io,resources=sygmapolicies/finalizers,verbs=update

func (r *SYGMAPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy := &securityv1.SYGMAPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// ⭐ NEW: NodeName  (Agent )
	if r.NodeName != "" && policy.Spec.NodeName != "" {
		if policy.Spec.NodeName != r.NodeName {
			//     -
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

	// ⭐ NEW: Spec  PidNs, MntNs  (OCI Hook )
	pidNs := policy.Spec.PidNs
	mntNs := policy.Spec.MntNs

	// Backward compatibility: Spec  Redis
	if pidNs == 0 || mntNs == 0 {
		metadata, err := r.loadPodMetadata(ctx, policy.Namespace, extractPodName(policy.Name))
		if err != nil {
			logger.Info("Metadata not found yet, will retry", "error", err.Error())
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		pidNs = metadata.PidNs
		mntNs = metadata.MntNs
	}

	// ========== Case 1:   (phases ) ==========
	if len(policy.Spec.Phases) == 0 {
		logger.Info("Empty policy detected, loading from Redis")

		// ImageID
		imageID := policy.Spec.ImageID
		if imageID == 0 {
			// Redis
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

		// Spec  (   )
		policy.Spec.Phases = phases
		if err := r.Update(ctx, policy); err != nil {
			logger.Error(err, "Failed to update policy spec")
			return ctrl.Result{}, err
		}

		logger.Info("✅ Policy loaded from Redis", "transitions", countTransitions(phases))

		// eBPF
		if err := r.updatePodPolicyInEBPF(policy, pidNs, mntNs); err != nil {
			logger.Error(err, "Failed to update eBPF")
			return r.updateStatusWithError(ctx, policy, "eBPF update failed: "+err.Error())
		}

		// Status
		return r.updateStatusSuccess(ctx, policy, pidNs, mntNs, imageID)
	}

	// ========== Case 2:   ==========
	if policy.Status.ObservedGeneration == policy.Generation {
		logger.Info("Policy already applied to this generation", "generation", policy.Generation)
		return ctrl.Result{}, nil
	}

	logger.Info("Policy update detected, applying changes",
		"generation", policy.Generation,
		"observedGeneration", policy.Status.ObservedGeneration)

	// eBPF
	if err := r.updatePodPolicyInEBPF(policy, pidNs, mntNs); err != nil {
		logger.Error(err, "Failed to update eBPF")
		return r.updateStatusWithError(ctx, policy, "eBPF update failed: "+err.Error())
	}

	logger.Info("✅ Policy updated")
	return r.updateStatusSuccess(ctx, policy, pidNs, mntNs, policy.Status.ImageID)
}

// ⭐ NEW: Status
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
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
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
	r.Status().Update(ctx, policy)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func extractPodName(policyName string) string {
	if len(policyName) > 7 && policyName[len(policyName)-7:] == "-policy" {
		return policyName[:len(policyName)-7]
	}
	return policyName
}

func countTransitions(phases map[string]securityv1.PhaseRuleSet) int {
	total := 0
	for _, phase := range phases {
		total += len(phase.RuleSet)
	}
	return total
}

// Redis Pod metadata
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

// Redis
func (r *SYGMAPolicyReconciler) loadPolicyFromRedis(ctx context.Context, imageID uint32) (map[string]securityv1.PhaseRuleSet, error) {
	result := make(map[string]securityv1.PhaseRuleSet)

	for _, phaseName := range []string{"initPhase", "mainPhase"} {
		var phase uint32
		if phaseName == "initPhase" {
			phase = 0
		} else {
			phase = 1
		}

		pattern := fmt.Sprintf("syscall_graph:%d:%d:*", imageID, phase)
		keys, err := r.RedisClient.Client.Keys(ctx, pattern).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get keys: %w", err)
		}

		if len(keys) == 0 {
			continue
		}

		transitions := make(map[string][]int)

		for _, key := range keys {
			var keyImageID, keyPhase, fromSyscall uint32
			if _, err := fmt.Sscanf(key, "syscall_graph:%d:%d:%d", &keyImageID, &keyPhase, &fromSyscall); err != nil {
				continue
			}

			data, err := r.RedisClient.Client.Get(ctx, key).Bytes()
			if err != nil || len(data) != 45 {
				continue
			}

			// Bitmask → syscall list
			allowedSyscalls := []int{}
			for toSyscall := uint32(0); toSyscall < 360; toSyscall++ {
				bitIndex := syscallToBitIndex(toSyscall)
				if bitIndex >= 360 {
					continue
				}

				bytePos := bitIndex >> 3
				bitOffset := bitIndex & 7
				byteIndex := 44 - bytePos

				if data[byteIndex]&(1<<bitOffset) != 0 {
					allowedSyscalls = append(allowedSyscalls, int(toSyscall))
				}
			}

			transitions[strconv.Itoa(int(fromSyscall))] = allowedSyscalls
		}

		result[phaseName] = securityv1.PhaseRuleSet{
			RuleSet: transitions,
		}
	}

	return result, nil
}

// eBPF   (namespace )
func (r *SYGMAPolicyReconciler) updatePodPolicyInEBPF(policy *securityv1.SYGMAPolicy, pidNs, mntNs uint32) error {
	logger := log.Log.WithName("sygmapolicy")

	if r.BPFManager == nil {
		return fmt.Errorf("BPF Manager not available")
	}

	logger.Info("Updating eBPF maps", "pidNs", pidNs, "mntNs", mntNs)

	// 1. Syscall graph
	for phaseName, phaseRuleSet := range policy.Spec.Phases {
		var phase uint32
		if phaseName == "initPhase" {
			phase = 0
		} else if phaseName == "mainPhase" {
			phase = 1
		} else {
			continue
		}

		logger.Info("Updating phase",
			"phase", phase,
			"transitions", len(phaseRuleSet.RuleSet))

		if err := r.BPFManager.UpdateSyscallGraphMapByNamespace(
			pidNs, mntNs, phase, phaseRuleSet.RuleSet,
		); err != nil {
			logger.Error(err, "Failed to update phase", "phase", phase)
			return fmt.Errorf("failed to update phase %d: %w", phase, err)
		}

		logger.Info("✅ Phase updated", "phase", phase)
	}

	// 2. Blocked paths
	if len(policy.Spec.BlockedPaths) > 0 {
		logger.Info("Updating blocked paths", "count", len(policy.Spec.BlockedPaths))

		if err := r.BPFManager.UpdateBlockedPaths(pidNs, mntNs, policy.Spec.BlockedPaths); err != nil {
			logger.Error(err, "Failed to update blocked paths")
			return fmt.Errorf("failed to update blocked paths: %w", err)
		}

		logger.Info("✅ Blocked paths updated")
	}

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

func (r *SYGMAPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// ⭐ NEW: NodeName
	if r.NodeName == "" {
		r.NodeName = os.Getenv("NODE_NAME")
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.SYGMAPolicy{})

	// Node  predicate
	if r.NodeName != "" {
		nodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
			policy, ok := obj.(*securityv1.SYGMAPolicy)
			if !ok {
				return false
			}
			// NodeName
			return policy.Spec.NodeName == "" || policy.Spec.NodeName == r.NodeName
		})
		builder = builder.WithEventFilter(nodeFilter)
	}

	return builder.Complete(r)
}
