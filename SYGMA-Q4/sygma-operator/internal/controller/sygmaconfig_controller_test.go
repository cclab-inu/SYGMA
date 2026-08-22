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

var _ = Describe("SYGMAConfig API", func() {
	ctx := context.Background()

	It("accepts the evaluation allowAll mode", func() {
		resource := &securityv1.SYGMAConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-all-valid", Namespace: "default"},
			Spec: securityv1.SYGMAConfigSpec{
				Collection: securityv1.CollectionSpec{},
				Policy: securityv1.ConfigPolicySpec{
					AllowAll: boolPointer(true),
				},
			},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, resource)).To(Succeed()) })
	})

	It("rejects a policy with both modes selected", func() {
		resource := &securityv1.SYGMAConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-modes-invalid", Namespace: "default"},
			Spec: securityv1.SYGMAConfigSpec{
				Collection: securityv1.CollectionSpec{},
				Policy: securityv1.ConfigPolicySpec{
					StateMachine: validStateMachine(),
					AllowAll:     boolPointer(true),
				},
			},
		}
		Expect(k8sClient.Create(ctx, resource)).NotTo(Succeed())
	})
})
