package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SYGMAPolicySpec struct {
	ImageName string `json:"imageName"`

	BinaryName string `json:"binaryName,omitempty"`

	NodeName string `json:"nodeName,omitempty"`

	PodName string `json:"podName,omitempty"`

	ContainerID string `json:"containerID,omitempty"`

	PidNs uint32 `json:"pidNs,omitempty"`

	MntNs uint32 `json:"mntNs,omitempty"`

	ImageID uint32 `json:"imageID,omitempty"`

	Phases map[string]PhaseRuleSet `json:"phases,omitempty"`
}

type PhaseRuleSet struct {
	RuleSet map[string][]int `json:"ruleSet"`
}

type SYGMAPolicyStatus struct {
	Phase string `json:"phase,omitempty"`

	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	ImageID uint32 `json:"imageID,omitempty"`

	Message string `json:"message,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	LoadedTransitions int `json:"loadedTransitions,omitempty"`
}

type SYGMAPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SYGMAPolicySpec   `json:"spec,omitempty"`
	Status SYGMAPolicyStatus `json:"status,omitempty"`
}

type SYGMAPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SYGMAPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SYGMAPolicy{}, &SYGMAPolicyList{})
}
