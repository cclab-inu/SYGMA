package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1 "example.org/sygma/operator/api/v1"
	"example.org/sygma/operator/pkg/storage"
)

type controllerRedisRecorder struct {
	commands     [][]interface{}
	stringValues map[string]string
	getErrors    map[string]error
	deleteErrors map[string]error
}

func (recorder *controllerRedisRecorder) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (recorder *controllerRedisRecorder) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, command redis.Cmder) error {
		recorder.commands = append(recorder.commands, append([]interface{}(nil), command.Args()...))
		if strings.EqualFold(command.Name(), "mget") {
			values := make([]interface{}, 0, len(command.Args())-1)
			for _, rawKey := range command.Args()[1:] {
				key := fmt.Sprint(rawKey)
				if injectedErr, exists := recorder.getErrors[key]; exists {
					command.SetErr(injectedErr)
					return injectedErr
				}
				if value, exists := recorder.stringValues[key]; exists {
					values = append(values, value)
				} else {
					values = append(values, nil)
				}
			}
			sliceCommand, ok := command.(*redis.SliceCmd)
			if !ok {
				return fmt.Errorf("MGET command has type %T", command)
			}
			sliceCommand.SetVal(values)
		}
		if strings.EqualFold(command.Name(), "del") {
			for _, rawKey := range command.Args()[1:] {
				if injectedErr, exists := recorder.deleteErrors[fmt.Sprint(rawKey)]; exists {
					command.SetErr(injectedErr)
					return injectedErr
				}
			}
		}
		command.SetErr(nil)
		return nil
	}
}

func (recorder *controllerRedisRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestValidateInitPhasePolicy(t *testing.T) {
	tests := []struct {
		name      string
		policy    map[string][]int
		wantError string
	}{
		{
			name:      "nil policy",
			policy:    nil,
			wantError: "no syscall transitions",
		},
		{
			name:      "empty policy",
			policy:    map[string][]int{},
			wantError: "no syscall transitions",
		},
		{
			name:      "missing start transition",
			policy:    map[string][]int{"0": {1}},
			wantError: "missing the START",
		},
		{
			name:      "empty start transition",
			policy:    map[string][]int{"500": {}},
			wantError: "has no destination syscalls",
		},
		{
			name:   "valid start transition",
			policy: map[string][]int{"500": {158}, "158": {0}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInitPhasePolicy(tt.policy)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateInitPhasePolicy() returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("validateInitPhasePolicy() returned nil, want error containing %q", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateInitPhasePolicy() error = %q, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestConfigGenerationStatusLifecycle(t *testing.T) {
	config := &securityv1.SYGMAConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "generation-test",
			Namespace:  "default",
			UID:        types.UID("config-uid"),
			Generation: 7,
		},
		Status: securityv1.SYGMAConfigStatus{
			Phase:              "Completed",
			ImageID:            42,
			CollectionComplete: true,
			ObservedGeneration: 6,
		},
	}
	resetConfigStatusForGeneration(config)
	if config.Status.Phase != "" || config.Status.ImageID != 0 || config.Status.CollectionComplete {
		t.Fatalf("reset status = %#v", config.Status)
	}
	if config.Status.ObservedGeneration != 7 {
		t.Fatalf("reset observedGeneration = %d, want 7", config.Status.ObservedGeneration)
	}

	retryConfigStatus(config, "missing START row")
	if config.Status.Phase != "BinaryExtracted" {
		t.Fatalf("retry phase = %q, want BinaryExtracted", config.Status.Phase)
	}

	completeConfigStatus(config, 77, "done")
	if !config.Status.CollectionComplete || config.Status.ImageID != 77 ||
		config.Status.ObservedGeneration != config.Generation {
		t.Fatalf("completed status = %#v", config.Status)
	}
	revision := newPolicyPublicationRevision(config)
	prefix := fmt.Sprintf("%s/%d/", config.UID, config.Generation)
	if !strings.HasPrefix(revision, prefix) || revision == prefix {
		t.Fatalf("publication revision = %q, want prefix %q and unique suffix", revision, prefix)
	}
}

func TestCollectionPodOwnershipAndLookupIsolation(t *testing.T) {
	testScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	config := &securityv1.SYGMAConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "config-a", Namespace: "default", UID: types.UID("uid-a"),
		},
	}
	owned := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owned-collection", Namespace: "default",
			Annotations: map[string]string{"sygma.io/mode": "collection"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "workload", Image: "nginx:1.27"}}},
	}
	if err := setCollectionPodOwner(config, owned, testScheme); err != nil {
		t.Fatalf("setCollectionPodOwner() error = %v", err)
	}
	foreignConfig := config.DeepCopy()
	foreignConfig.Name = "config-b"
	foreignConfig.UID = types.UID("uid-b")
	foreign := owned.DeepCopy()
	foreign.Name = "foreign-collection"
	foreign.OwnerReferences = nil
	if err := setCollectionPodOwner(foreignConfig, foreign, testScheme); err != nil {
		t.Fatalf("set foreign owner error = %v", err)
	}
	if !isCollectionPodOwnedByConfig(owned, config) || isCollectionPodOwnedByConfig(foreign, config) {
		t.Fatal("collection ownership predicate did not isolate owner UID/name")
	}

	config.Status.PodName = foreign.Name
	reconciler := &SYGMAConfigReconciler{
		Client: fake.NewClientBuilder().WithScheme(testScheme).WithObjects(owned, foreign).Build(),
		Scheme: testScheme,
	}
	got, err := reconciler.findCollectionPod(context.Background(), config)
	if err != nil {
		t.Fatalf("findCollectionPod() error = %v", err)
	}
	if got.Name != owned.Name {
		t.Fatalf("findCollectionPod() = %s, want owned pod %s", got.Name, owned.Name)
	}
}

func TestReconcileResetsChangedGenerationAndDeletesOnlyOwnedPod(t *testing.T) {
	testScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	config := &securityv1.SYGMAConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "generation-reset", Namespace: "default", UID: types.UID("reset-uid"), Generation: 2,
		},
		Spec: securityv1.SYGMAConfigSpec{
			Collection: securityv1.CollectionSpec{},
			Policy:     securityv1.ConfigPolicySpec{AllowAll: boolPointer(true)},
		},
		Status: securityv1.SYGMAConfigStatus{
			Phase: "Completed", ImageID: 8, CollectionComplete: true, ObservedGeneration: 1,
		},
	}
	owned := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "owned-old", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "workload", Image: "nginx:1.27"}}},
	}
	if err := setCollectionPodOwner(config, owned, testScheme); err != nil {
		t.Fatal(err)
	}
	foreign := owned.DeepCopy()
	foreign.Name = "foreign"
	foreign.OwnerReferences = nil

	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(&securityv1.SYGMAConfig{}).
		WithObjects(config, owned, foreign).
		Build()
	redisRecorder := &controllerRedisRecorder{}
	goRedisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
	t.Cleanup(func() { _ = goRedisClient.Close() })
	goRedisClient.AddHook(redisRecorder)
	reconciler := &SYGMAConfigReconciler{
		Client: fakeClient,
		Scheme: testScheme,
		SyscallManager: storage.NewSyscallGraphManager(&storage.RedisClient{
			Client: goRedisClient,
			Ctx:    context.Background(),
		}),
	}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: config.Name, Namespace: config.Namespace},
	})
	if err != nil || !result.Requeue {
		t.Fatalf("Reconcile() result = %#v, error = %v", result, err)
	}

	updated := &securityv1.SYGMAConfig{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: config.Name, Namespace: config.Namespace}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ObservedGeneration != 2 || updated.Status.Phase != "" || updated.Status.CollectionComplete {
		t.Fatalf("reset status = %#v", updated.Status)
	}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: owned.Name, Namespace: owned.Namespace}, &corev1.Pod{}); err == nil {
		t.Fatal("owned pod was not deleted during generation reset")
	}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: foreign.Name, Namespace: foreign.Namespace}, &corev1.Pod{}); err != nil {
		t.Fatalf("foreign pod was deleted: %v", err)
	}
	if len(redisRecorder.commands) != 1 || fmt.Sprint(redisRecorder.commands[0]) != "[del policy_ready:8]" {
		t.Fatalf("previous generation publication was not invalidated: %#v", redisRecorder.commands)
	}
}

func TestReconcileCompletedValidatesPolicyPublication(t *testing.T) {
	redisFailure := errors.New("injected Redis read failure")
	redisDeleteFailure := errors.New("injected Redis invalidation failure")
	tests := []struct {
		name              string
		policy            securityv1.ConfigPolicySpec
		redisValues       map[string]string
		redisErrors       map[string]error
		redisDeleteErrors map[string]error
		wantRequeue       bool
		wantRequeueAfter  time.Duration
		wantError         error
		wantPhase         string
		wantComplete      bool
		wantImageID       uint32
		wantRedisCommands int
		wantInvalidation  bool
	}{
		{
			name:   "present marker remains completed and schedules validation",
			policy: securityv1.ConfigPolicySpec{AllowAll: boolPointer(true)},
			redisValues: map[string]string{
				"policy_ready:23":        "ready-revision",
				"main_policy:23":         `{"type":"state-machine"}`,
				"image_id_map:23":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:23:0:500": "bootstrap-bitmap",
			},
			wantRequeueAfter:  CompletedPublicationCheckInterval,
			wantPhase:         "Completed",
			wantComplete:      true,
			wantImageID:       23,
			wantRedisCommands: 1,
		},
		{
			name:   "missing marker schedules allow-all republish",
			policy: securityv1.ConfigPolicySpec{AllowAll: boolPointer(true)},
			redisValues: map[string]string{
				"main_policy:23":         `{"type":"state-machine"}`,
				"image_id_map:23":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:23:0:500": "bootstrap-bitmap",
			},
			wantRequeue:       true,
			wantPhase:         "BinaryExtracted",
			wantRedisCommands: 3,
			wantInvalidation:  true,
		},
		{
			name:   "missing marker schedules state-machine recollection",
			policy: securityv1.ConfigPolicySpec{StateMachine: validStateMachine()},
			redisValues: map[string]string{
				"main_policy:23":         `{"type":"state-machine"}`,
				"image_id_map:23":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:23:0:500": "bootstrap-bitmap",
			},
			wantRequeue:       true,
			wantPhase:         "BinaryExtracted",
			wantRedisCommands: 3,
			wantInvalidation:  true,
		},
		{
			name:              "Redis error preserves completed status",
			policy:            securityv1.ConfigPolicySpec{AllowAll: boolPointer(true)},
			redisValues:       map[string]string{},
			redisErrors:       map[string]error{"policy_ready:23": redisFailure},
			wantRequeueAfter:  CompletedPublicationErrorRetryInterval,
			wantError:         redisFailure,
			wantPhase:         "Completed",
			wantComplete:      true,
			wantImageID:       23,
			wantRedisCommands: 1,
		},
		{
			name:   "invalidation error preserves completed status",
			policy: securityv1.ConfigPolicySpec{StateMachine: validStateMachine()},
			redisValues: map[string]string{
				"policy_ready:23":        "ready-revision",
				"image_id_map:23":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:23:0:500": "bootstrap-bitmap",
			},
			redisDeleteErrors: map[string]error{"policy_ready:23": redisDeleteFailure},
			wantRequeueAfter:  CompletedPublicationErrorRetryInterval,
			wantError:         redisDeleteFailure,
			wantPhase:         "Completed",
			wantComplete:      true,
			wantImageID:       23,
			wantRedisCommands: 3,
			wantInvalidation:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testScheme := runtime.NewScheme()
			if err := securityv1.AddToScheme(testScheme); err != nil {
				t.Fatal(err)
			}
			config := &securityv1.SYGMAConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "completed", Namespace: "default", UID: types.UID("completed-uid"), Generation: 4,
				},
				Spec: securityv1.SYGMAConfigSpec{Policy: test.policy},
				Status: securityv1.SYGMAConfigStatus{
					Phase:              "Completed",
					ImageName:          "nginx:1.27",
					ImageID:            23,
					BinaryName:         "nginx",
					BinaryPath:         "/usr/sbin/nginx",
					CollectionComplete: true,
					ObservedGeneration: 4,
				},
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithStatusSubresource(&securityv1.SYGMAConfig{}).
				WithObjects(config).
				Build()
			redisRecorder := &controllerRedisRecorder{
				stringValues: test.redisValues,
				getErrors:    test.redisErrors,
				deleteErrors: test.redisDeleteErrors,
			}
			goRedisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
			t.Cleanup(func() { _ = goRedisClient.Close() })
			goRedisClient.AddHook(redisRecorder)
			reconciler := &SYGMAConfigReconciler{
				Client: fakeClient,
				SyscallManager: storage.NewSyscallGraphManager(&storage.RedisClient{
					Client: goRedisClient,
					Ctx:    context.Background(),
				}),
			}

			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{Name: config.Name, Namespace: config.Namespace},
			})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Reconcile() error = %v, want %v", err, test.wantError)
			}
			if result.Requeue != test.wantRequeue || result.RequeueAfter != test.wantRequeueAfter {
				t.Fatalf("Reconcile() result = %#v, want Requeue=%t RequeueAfter=%s",
					result, test.wantRequeue, test.wantRequeueAfter)
			}

			updated := &securityv1.SYGMAConfig{}
			if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(config), updated); err != nil {
				t.Fatal(err)
			}
			if updated.Status.Phase != test.wantPhase ||
				updated.Status.CollectionComplete != test.wantComplete ||
				updated.Status.ImageID != test.wantImageID {
				t.Fatalf("updated completed status = %#v", updated.Status)
			}
			if updated.Status.ObservedGeneration != config.Generation {
				t.Fatalf("observed generation = %d, want %d",
					updated.Status.ObservedGeneration, config.Generation)
			}
			if len(redisRecorder.commands) != test.wantRedisCommands {
				t.Fatalf("Redis commands = %#v, want %d GETs",
					redisRecorder.commands, test.wantRedisCommands)
			}
			for index, command := range redisRecorder.commands {
				want := "[mget policy_ready:23 main_policy:23 image_id_map:23 syscall_graph:23:0:500]"
				if test.wantInvalidation && index == len(redisRecorder.commands)-1 {
					want = "[del policy_ready:23]"
				}
				if fmt.Sprint(command) != want {
					t.Fatalf("Redis command %d = %#v, want %s", index, command, want)
				}
			}
		})
	}
}

func TestMissingPublicationRecoveryDoesNotOverwriteConcurrentTransition(t *testing.T) {
	testScheme := runtime.NewScheme()
	if err := securityv1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	latest := &securityv1.SYGMAConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "concurrent-recovery", Namespace: "default", Generation: 6,
		},
		Status: securityv1.SYGMAConfigStatus{
			Phase:              "BinaryExtracted",
			ObservedGeneration: 6,
			Message:            "recovery already started",
		},
	}
	stale := latest.DeepCopy()
	stale.Status.Phase = "Completed"
	stale.Status.ImageID = 29
	stale.Status.CollectionComplete = true
	stale.Status.Message = "stale completion"

	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(&securityv1.SYGMAConfig{}).
		WithObjects(latest).
		Build()
	reconciler := &SYGMAConfigReconciler{Client: fakeClient}
	result, err := reconciler.resetCompletedPublicationForRetry(context.Background(), stale)
	if err != nil || !result.Requeue {
		t.Fatalf("resetCompletedPublicationForRetry() result = %#v, error = %v", result, err)
	}

	updated := &securityv1.SYGMAConfig{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(latest), updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Phase != "BinaryExtracted" || updated.Status.CollectionComplete ||
		updated.Status.ImageID != 0 || updated.Status.Message != "recovery already started" {
		t.Fatalf("concurrent recovery status was overwritten: %#v", updated.Status)
	}
}

func TestGenerationChangePublicationInvalidationMustSucceed(t *testing.T) {
	redisFailure := errors.New("injected Redis delete failure")
	tests := []struct {
		name             string
		deleteErrors     map[string]error
		wantRequeue      bool
		wantRequeueAfter time.Duration
		wantError        error
	}{
		{name: "successful invalidation requeues generation", wantRequeue: true},
		{
			name:             "failed invalidation blocks generation transition",
			deleteErrors:     map[string]error{"policy_ready:31": redisFailure},
			wantRequeueAfter: CompletedPublicationErrorRetryInterval,
			wantError:        redisFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &controllerRedisRecorder{deleteErrors: test.deleteErrors}
			goRedisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
			t.Cleanup(func() { _ = goRedisClient.Close() })
			goRedisClient.AddHook(recorder)
			reconciler := &SYGMAConfigReconciler{
				SyscallManager: storage.NewSyscallGraphManager(&storage.RedisClient{
					Client: goRedisClient,
					Ctx:    context.Background(),
				}),
			}

			result, err := reconciler.invalidatePublicationAfterGenerationChange(31)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("invalidatePublicationAfterGenerationChange() error = %v, want %v", err, test.wantError)
			}
			if result.Requeue != test.wantRequeue || result.RequeueAfter != test.wantRequeueAfter {
				t.Fatalf("invalidatePublicationAfterGenerationChange() result = %#v", result)
			}
			if len(recorder.commands) != 1 || fmt.Sprint(recorder.commands[0]) != "[del policy_ready:31]" {
				t.Fatalf("invalidation commands = %#v", recorder.commands)
			}
		})
	}
}

func TestSYGMAPolicyRejectsNonInitGraph(t *testing.T) {
	valid := map[string]securityv1.PhaseRuleSet{
		"initPhase": {RuleSet: map[string][]int{"500": {0}}},
	}
	if err := validateInitOnlyPhases(valid); err != nil {
		t.Fatalf("validateInitOnlyPhases(valid) error = %v", err)
	}
	invalid := map[string]securityv1.PhaseRuleSet{
		"mainPhase": {RuleSet: map[string][]int{"500": {0}}},
	}
	if err := validateInitOnlyPhases(invalid); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("validateInitOnlyPhases(mainPhase) error = %v", err)
	}
}

func TestExtractImageRejectsPodWithoutContainers(t *testing.T) {
	reconciler := &SYGMAConfigReconciler{}
	_, _, err := reconciler.extractImageFromYAML([]byte(`
apiVersion: v1
kind: Pod
metadata:
  name: empty
spec:
  containers: []
`))
	if err == nil || !strings.Contains(err.Error(), "no containers") {
		t.Fatalf("extractImageFromYAML() error = %v", err)
	}
}

func TestResolveCollectionImageMetadataRepairsImageFromSpec(t *testing.T) {
	reconciler := &SYGMAConfigReconciler{}
	config := &securityv1.SYGMAConfig{
		Spec: securityv1.SYGMAConfigSpec{
			Collection: securityv1.CollectionSpec{YAMLContent: `
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.24.0
`},
		},
		Status: securityv1.SYGMAConfigStatus{
			BinaryName: "nginx",
			BinaryPath: "/usr/sbin/nginx",
		},
	}

	metadata, err := reconciler.resolveCollectionImageMetadata(
		context.Background(), config, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ImageName != "nginx:1.24.0" ||
		metadata.BinaryName != "nginx" || metadata.BinaryPath != "/usr/sbin/nginx" {
		t.Fatalf("resolved metadata = %#v", metadata)
	}
}

func TestPinCollectionPodToOperatorNode(t *testing.T) {
	t.Run("uses exact downward API node name", func(t *testing.T) {
		t.Setenv("NODE_NAME", "worker-a")
		pod := &corev1.Pod{Spec: corev1.PodSpec{
			NodeName:     "stale-node",
			NodeSelector: map[string]string{"disk": "ssd"},
		}}

		if got := pinCollectionPodToOperatorNode(pod); got != "worker-a" {
			t.Fatalf("pinCollectionPodToOperatorNode() = %q, want worker-a", got)
		}
		if pod.Spec.NodeName != "worker-a" {
			t.Fatalf("pod spec.nodeName = %q, want worker-a", pod.Spec.NodeName)
		}
		if pod.Spec.NodeSelector["disk"] != "ssd" {
			t.Fatal("pinning unexpectedly changed the workload node selector")
		}
	})

	t.Run("leaves pod unpinned without operator node", func(t *testing.T) {
		t.Setenv("NODE_NAME", "  ")
		pod := &corev1.Pod{}
		if got := pinCollectionPodToOperatorNode(pod); got != "" {
			t.Fatalf("pinCollectionPodToOperatorNode() = %q, want empty", got)
		}
		if pod.Spec.NodeName != "" {
			t.Fatalf("pod spec.nodeName = %q, want empty", pod.Spec.NodeName)
		}
	})
}

func TestManifestSYGMAConfigExamplesUseCurrentPolicyAPI(t *testing.T) {
	tests := []struct {
		path         string
		wantAllowAll bool
	}{
		{path: "nginx-sygmaconfig.yaml", wantAllowAll: true},
		{path: "redis-sygmaconfig.yaml", wantAllowAll: true},
		{path: filepath.Join("availability-eval", "nginx-sygmaconfig.yaml"), wantAllowAll: false},
		{path: filepath.Join("availability-eval", "redis-sygmaconfig.yaml"), wantAllowAll: false},
		{path: filepath.Join("availability-eval", "httpd-sygmaconfig.yaml"), wantAllowAll: false},
		{path: filepath.Join("availability-eval", "mysql-sygmaconfig.yaml"), wantAllowAll: false},
	}
	manifestDir := filepath.Join("..", "..", "..", "manifest")

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(manifestDir, tt.path))
			if err != nil {
				t.Fatal(err)
			}
			config := &securityv1.SYGMAConfig{}
			if err := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096).Decode(config); err != nil {
				t.Fatalf("decode example: %v", err)
			}
			policy, allowAll, err := resolveConfigPolicy(config)
			if err != nil {
				t.Fatalf("resolve example policy: %v", err)
			}
			if policy.Type != storage.PolicyTypeStateMachine || policy.StateMachine == nil {
				t.Fatalf("resolved policy = %#v, want state machine", policy)
			}
			if allowAll != tt.wantAllowAll {
				t.Fatalf("allowAll = %t, want %t", allowAll, tt.wantAllowAll)
			}
		})
	}
}

func TestSyscallBitmapCodecIncludesHighRange(t *testing.T) {
	for _, syscall := range supportedSyscalls() {
		bitIndex := syscallToBitIndex(uint32(syscall))
		if bitIndex >= 360 {
			t.Fatalf("syscall %d has invalid bitmap index %d", syscall, bitIndex)
		}
		if got := bitIndexToSyscall(bitIndex); got != uint32(syscall) {
			t.Fatalf("syscall %d round-tripped as %d", syscall, got)
		}
	}
	if got := bitIndexToSyscall(335); got != 424 {
		t.Fatalf("bitmap index 335 decoded as %d, want 424", got)
	}
	if got := bitIndexToSyscall(359); got != 448 {
		t.Fatalf("bitmap index 359 decoded as %d, want 448", got)
	}
}
