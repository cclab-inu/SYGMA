/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SYGMAConfigSpec defines the desired state of SYGMAConfig.
type SYGMAConfigSpec struct {
	// Collection defines how to launch the workload used to collect the init policy.
	Collection CollectionSpec `json:"collection"`

	// Policy defines the main-phase state-machine policy. Exactly one of
	// stateMachine or allowAll must be selected.
	Policy ConfigPolicySpec `json:"policy"`
}

type CollectionSpec struct {
	// Path to YAML file (deprecated, for backward compatibility)
	// +optional
	YAMLPath string `json:"yamlPath,omitempty"`

	// Direct YAML content (recommended)
	// +optional
	YAMLContent string `json:"yamlContent,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.stateMachine) && !has(self.allowAll)) || (!has(self.stateMachine) && has(self.allowAll) && self.allowAll)",message="exactly one of stateMachine or allowAll=true must be specified"
type ConfigPolicySpec struct {
	// StateMachine is the main-phase syscall policy.
	// +optional
	StateMachine *StateMachinePolicySpec `json:"stateMachine,omitempty"`

	// AllowAll enables the evaluation-only wildcard policy. The controller
	// materializes it as a one-state state machine so policy lookup overhead is
	// still present during an evaluation.
	// +optional
	AllowAll *bool `json:"allowAll,omitempty"`
}

type StateMachinePolicySpec struct {
	// InitialState identifies the state used for a newly observed process.
	InitialState uint32 `json:"initialState"`

	// States maps decimal state IDs to their syscall allow-lists.
	// +kubebuilder:validation:MinProperties=1
	States map[string]StateMachineStateSpec `json:"states"`

	// Transitions maps state ID -> syscall number -> next state ID. A missing
	// transition keeps the process in its current state.
	// +optional
	Transitions map[string]map[string]uint32 `json:"transitions,omitempty"`
}

type StateMachineStateSpec struct {
	// AllowedSyscalls contains Linux x86-64 syscall numbers supported by SYGMA.
	// +kubebuilder:validation:MinItems=1
	// Duplicate values are rejected in O(n) by validateAllowedSyscalls in the
	// controller. Do not emit OpenAPI uniqueItems here: Kubernetes rejects it
	// below a map-valued schema because admission cost can become quadratic.
	// The same controller validation enforces the disjoint supported syscall
	// ranges. A CEL self.all rule nested below the map-valued states schema is
	// also rejected by Kubernetes' static admission-cost budget.
	AllowedSyscalls []int `json:"allowedSyscalls"`
}

// SYGMAConfigStatus defines the observed state of SYGMAConfig
type SYGMAConfigStatus struct {
	// Phase represents the current phase of collection
	// +optional
	Phase string `json:"phase,omitempty"`

	// ImageName extracted from the YAML
	// +optional
	ImageName string `json:"imageName,omitempty"`

	ImageID uint32 `json:"imageID,omitempty"`

	// BinaryName extracted from the pod
	// +optional
	BinaryName string `json:"binaryName,omitempty"`

	BinaryPath string `json:"binaryPath,omitempty"`

	// CollectionComplete indicates if collection is done
	// +optional
	CollectionComplete bool `json:"collectionComplete,omitempty"`

	// ObservedGeneration is the spec generation currently being processed or
	// already published by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`

	// +optional
	PodName string `json:"podName,omitempty"`

	CollectionStartTime metav1.Time `json:"collectionStartTime,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced,shortName=sygmacfg

// SYGMAConfig is the Schema for the sygmaconfigs API
type SYGMAConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SYGMAConfigSpec   `json:"spec,omitempty"`
	Status SYGMAConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SYGMAConfigList contains a list of SYGMAConfig
type SYGMAConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SYGMAConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SYGMAConfig{}, &SYGMAConfigList{})
}
