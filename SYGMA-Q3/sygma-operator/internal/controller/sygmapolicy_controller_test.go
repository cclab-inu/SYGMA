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

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "example.org/sygma/operator/api/v1"
)

var _ = Describe("SYGMAPolicy API", func() {
	It("accepts the node-agent policy shape", func() {
		ctx := context.Background()
		resource := &securityv1.SYGMAPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-valid", Namespace: "default"},
			Spec: securityv1.SYGMAPolicySpec{
				ImageName: "nginx:1.27",
			},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, resource)).To(Succeed()) })
	})

	It("rejects a legacy mainPhase graph", func() {
		ctx := context.Background()
		resource := &securityv1.SYGMAPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "main-phase-invalid", Namespace: "default"},
			Spec: securityv1.SYGMAPolicySpec{
				ImageName: "nginx:1.27",
				Phases: map[string]securityv1.PhaseRuleSet{
					"mainPhase": {RuleSet: map[string][]int{"500": {0}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, resource)).NotTo(Succeed())
	})
})
