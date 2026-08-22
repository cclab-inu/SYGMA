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
