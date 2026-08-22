package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SYGMAConfigSpec struct {
	Collection CollectionSpec `json:"collection"`

	Policy ConfigPolicySpec `json:"policy"`
}

type CollectionSpec struct {
	YAMLPath string `json:"yamlPath,omitempty"`

	YAMLContent string `json:"yamlContent,omitempty"`
}

type ConfigPolicySpec struct {
	StateMachine *StateMachinePolicySpec `json:"stateMachine,omitempty"`

	AllowAll *bool `json:"allowAll,omitempty"`
}

type StateMachinePolicySpec struct {
	InitialState uint32 `json:"initialState"`

	States map[string]StateMachineStateSpec `json:"states"`

	Transitions map[string]map[string]uint32 `json:"transitions,omitempty"`
}

type StateMachineStateSpec struct {
	AllowedSyscalls []int `json:"allowedSyscalls"`
}

type SYGMAConfigStatus struct {
	Phase string `json:"phase,omitempty"`

	ImageName string `json:"imageName,omitempty"`

	ImageID uint32 `json:"imageID,omitempty"`

	BinaryName string `json:"binaryName,omitempty"`

	BinaryPath string `json:"binaryPath,omitempty"`

	CollectionComplete bool `json:"collectionComplete,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	Message string `json:"message,omitempty"`

	PodName string `json:"podName,omitempty"`

	CollectionStartTime metav1.Time `json:"collectionStartTime,omitempty"`
}

type SYGMAConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SYGMAConfigSpec   `json:"spec,omitempty"`
	Status SYGMAConfigStatus `json:"status,omitempty"`
}

type SYGMAConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SYGMAConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SYGMAConfig{}, &SYGMAConfigList{})
}
