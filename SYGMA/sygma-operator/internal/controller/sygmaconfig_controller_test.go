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
