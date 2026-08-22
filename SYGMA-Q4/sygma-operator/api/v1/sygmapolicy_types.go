// api/v1/sygmapolicy_types.go
//  SYGMAPolicy API  - NodeName, PidNs, MntNs

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SYGMAPolicySpec defines the desired state of SYGMAPolicy
type SYGMAPolicySpec struct {
	// ImageName is the container image name
	ImageName string `json:"imageName"`

	// BinaryName is the main binary name
	BinaryName string `json:"binaryName,omitempty"`

	// ⭐ NEW: NodeName specifies which node this policy applies to
	// Used by the DaemonSet agent to filter policies for its node
	// +optional
	NodeName string `json:"nodeName,omitempty"`

	// ⭐ NEW: PodName is the name of the target pod
	// +optional
	PodName string `json:"podName,omitempty"`

	// ⭐ NEW: ContainerID is the container ID (short form, first 12 chars)
	// +optional
	ContainerID string `json:"containerID,omitempty"`

	// ⭐ NEW: PidNs is the PID namespace inode number of the container
	// Set by OCI Hook during container creation
	// +optional
	PidNs uint32 `json:"pidNs,omitempty"`

	// ⭐ NEW: MntNs is the Mount namespace inode number of the container
	// Set by OCI Hook during container creation
	// +optional
	MntNs uint32 `json:"mntNs,omitempty"`

	// ⭐ NEW: ImageID is the image ID from Redis (for faster policy lookup)
	// +optional
	ImageID uint32 `json:"imageID,omitempty"`

	// Phases contains the init bootstrap graph. The only accepted key is
	// "initPhase". Main enforcement is installed directly by the OCI hook from
	// the typed state-machine policy in Redis.
	// If empty, the agent loads initPhase from Redis using ImageID.
	// +kubebuilder:validation:XValidation:rule="self.all(k, k == 'initPhase')",message="only initPhase is supported; mainPhase is installed by the OCI hook"
	Phases map[string]PhaseRuleSet `json:"phases,omitempty"`
}

type PhaseRuleSet struct {
	// RuleSet defines syscall transitions for this phase
	// Key: from_syscall (string), Value: allowed to_syscalls (int array)
	RuleSet map[string][]int `json:"ruleSet"`
}

// SYGMAPolicyStatus defines the observed state of SYGMAPolicy
type SYGMAPolicyStatus struct {
	// Phase represents the current phase: pending, loading, active, error
	// +optional
	Phase string `json:"phase,omitempty"`

	// LastUpdated is the timestamp of last update
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// AppliedToNodes lists nodes where policy is applied
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ImageID is the assigned image ID from Redis
	// +optional
	ImageID uint32 `json:"imageID,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`

	// ObservedGeneration tracks which generation of spec has been applied
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ⭐ NEW: LoadedTransitions is the number of syscall transitions loaded
	// +optional
	LoadedTransitions int `json:"loadedTransitions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced,shortName=sygmap
//+kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
//+kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
//+kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.imageName`
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="Transitions",type=integer,JSONPath=`.status.loadedTransitions`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SYGMAPolicy is the Schema for the sygmapolicies API
type SYGMAPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SYGMAPolicySpec   `json:"spec,omitempty"`
	Status SYGMAPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SYGMAPolicyList contains a list of SYGMAPolicy
type SYGMAPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SYGMAPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SYGMAPolicy{}, &SYGMAPolicyList{})
}
