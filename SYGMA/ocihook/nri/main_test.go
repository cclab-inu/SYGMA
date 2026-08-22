package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/sirupsen/logrus"
)

func hasAdjustmentEnv(values []*api.KeyValue, wantKey, wantValue string) bool {
	for _, value := range values {
		if value.GetKey() == wantKey && value.GetValue() == wantValue {
			return true
		}
	}
	return false
}

func TestResolveSeccompRouting(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        string
		wantErr     bool
	}{
		{name: "missing defaults to selective", annotations: nil, want: seccompRoutingSelective},
		{name: "empty defaults to selective", annotations: map[string]string{seccompRoutingAnnotation: ""}, want: seccompRoutingSelective},
		{name: "explicit selective", annotations: map[string]string{seccompRoutingAnnotation: seccompRoutingSelective}, want: seccompRoutingSelective},
		{name: "all trace", annotations: map[string]string{seccompRoutingAnnotation: seccompRoutingAllTrace}, want: seccompRoutingAllTrace},
		{name: "unknown", annotations: map[string]string{seccompRoutingAnnotation: "trace"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSeccompRouting(test.annotations)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), seccompRoutingAnnotation) {
					t.Fatalf("invalid routing returned value=%q err=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve routing: %v", err)
			}
			if got != test.want {
				t.Fatalf("routing=%q, want %q", got, test.want)
			}
		})
	}
}

func TestParseImageMetadata(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantName string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "JSON record",
			raw:      `{"imageName":"nginx:1.27","binaryName":"nginx","binaryPath":"/usr/sbin/nginx"}`,
			wantName: "nginx",
			wantPath: "/usr/sbin/nginx",
		},
		{
			name:     "legacy binary and absolute path",
			raw:      "nginx:/usr/sbin/nginx",
			wantName: "nginx",
			wantPath: "/usr/sbin/nginx",
		},
		{
			name:     "legacy image reference and binary",
			raw:      "registry.example:5000/library/nginx:1.27:nginx",
			wantName: "nginx",
		},
		{name: "bare binary", raw: "nginx", wantErr: true},
		{name: "missing JSON binary", raw: `{"imageName":"nginx:1.27"}`, wantErr: true},
		{name: "missing JSON image", raw: `{"binaryName":"nginx"}`, wantErr: true},
		{name: "relative JSON path", raw: `{"imageName":"nginx:1.27","binaryName":"nginx","binaryPath":"usr/sbin/nginx"}`, wantErr: true},
		{name: "binary name is a path", raw: `{"imageName":"nginx:1.27","binaryName":"/usr/sbin/nginx"}`, wantErr: true},
		{name: "malformed JSON", raw: `{"imageName":`, wantErr: true},
		{name: "empty", raw: "  ", wantErr: true},
		{name: "malformed legacy", raw: "nginx:", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, path, err := parseImageMetadata(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseImageMetadata(%q) = %q, %q; want error", test.raw, name, path)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseImageMetadata(%q): %v", test.raw, err)
			}
			if name != test.wantName || path != test.wantPath {
				t.Fatalf("parseImageMetadata(%q) = %q, %q; want %q, %q", test.raw, name, path, test.wantName, test.wantPath)
			}
		})
	}
}

func TestNormalizeImageNameHandlesRegistryPorts(t *testing.T) {
	tests := map[string]string{
		"nginx":                                       "nginx:latest",
		"docker.io/library/nginx":                     "nginx:latest",
		"docker.io/library/nginx:1.27":                "nginx:1.27",
		"localhost:5000/team/service":                 "localhost:5000/team/service:latest",
		"localhost:5000/team/service:v1":              "localhost:5000/team/service:v1",
		"registry.example/team/service@sha256:abcdef": "registry.example/team/service@sha256:abcdef",
	}
	for raw, want := range tests {
		if got := normalizeImageName(raw); got != want {
			t.Errorf("normalizeImageName(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestBuildHookEnvPropagatesRedisAddress(t *testing.T) {
	t.Setenv("REDIS_ADDR", "10.0.0.42:6380")
	t.Setenv("SYGMA_POLICY_CR_ENABLED", "true")

	env := buildHookEnv("enforcement", "nginx", "/usr/sbin/nginx", "", "nginx:latest", "replace")
	if !slices.Contains(env, "REDIS_ADDR=10.0.0.42:6380") {
		t.Fatalf("hook environment does not contain configured Redis endpoint: %v", env)
	}
	if !slices.Contains(env, "SYGMA_POLICY_CR_ENABLED=true") {
		t.Fatalf("hook environment does not contain policy CR selector: %v", env)
	}
}

func TestRedisAddressUsesNodeConfigBeforeBuildDefault(t *testing.T) {
	t.Setenv("REDIS_ADDR", "")
	originalFile := RedisAddrFile
	originalDefault := DefaultRedisAddr
	t.Cleanup(func() {
		RedisAddrFile = originalFile
		DefaultRedisAddr = originalDefault
	})

	RedisAddrFile = filepath.Join(t.TempDir(), "redis-addr")
	DefaultRedisAddr = "localhost:6379"
	if err := os.WriteFile(RedisAddrFile, []byte("192.0.2.44:6379\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := getEnv("REDIS_ADDR", "fallback:6379"); got != "192.0.2.44:6379" {
		t.Fatalf("Redis endpoint = %q, want node config", got)
	}

	if err := os.WriteFile(RedisAddrFile, []byte("not-an-endpoint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := getEnv("REDIS_ADDR", "fallback:6379"); got != "localhost:6379" {
		t.Fatalf("invalid node config fallback = %q, want build default", got)
	}
}

func TestValidRedisEndpoint(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"redis.example:6379":  true,
		"192.0.2.1:1":         true,
		"[2001:db8::1]:6379":  true,
		"redis.example":       false,
		":6379":               false,
		"redis.example:0":     false,
		"redis.example:70000": false,
	} {
		if got := validRedisEndpoint(endpoint); got != want {
			t.Errorf("validRedisEndpoint(%q) = %t, want %t", endpoint, got, want)
		}
	}
}

func TestCreateContainerPassesSeccompRoutingToWrapper(t *testing.T) {
	originalLog := log
	log = logrus.New()
	t.Cleanup(func() { log = originalLog })

	tests := []struct {
		name        string
		routing     string
		wantRouting string
	}{
		{name: "default selective", wantRouting: seccompRoutingSelective},
		{name: "explicit selective", routing: seccompRoutingSelective, wantRouting: seccompRoutingSelective},
		{name: "all trace", routing: seccompRoutingAllTrace, wantRouting: seccompRoutingAllTrace},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			annotations := map[string]string{"sygma.io/mode": "enforcement"}
			if test.routing != "" {
				annotations[seccompRoutingAnnotation] = test.routing
			}
			pod := &api.PodSandbox{
				Name:        "routing-test",
				Namespace:   "default",
				Annotations: annotations,
			}
			container := &api.Container{Name: "probe", Args: []string{"/bin/echo"}}

			adjust, updates, err := (&plugin{}).CreateContainer(
				context.Background(), pod, container,
			)
			if err != nil {
				t.Fatalf("CreateContainer failed: %v", err)
			}
			if adjust == nil || updates != nil {
				t.Fatalf("unexpected adjustment=%v updates=%v", adjust, updates)
			}
			if !hasAdjustmentEnv(
				adjust.GetEnv(), "SYGMA_SECCOMP_ROUTING", test.wantRouting,
			) {
				t.Fatalf(
					"container env %v does not contain SYGMA_SECCOMP_ROUTING=%q",
					adjust.GetEnv(), test.wantRouting,
				)
			}
		})
	}
}

func TestCreateContainerRejectsUnknownSeccompRouting(t *testing.T) {
	originalLog := log
	log = logrus.New()
	t.Cleanup(func() { log = originalLog })

	pod := &api.PodSandbox{
		Name:      "routing-test",
		Namespace: "default",
		Annotations: map[string]string{
			"sygma.io/mode":          "enforcement",
			seccompRoutingAnnotation: "everything",
		},
	}
	adjust, updates, err := (&plugin{}).CreateContainer(
		context.Background(), pod, &api.Container{Name: "probe", Args: []string{"/bin/echo"}},
	)
	if err == nil || !strings.Contains(err.Error(), seccompRoutingAnnotation) {
		t.Fatalf("unknown routing accepted: adjustment=%v updates=%v err=%v", adjust, updates, err)
	}
	if adjust != nil || updates != nil {
		t.Fatalf("unknown routing returned mutations: adjustment=%v updates=%v", adjust, updates)
	}
}

func markerPod() *api.PodSandbox {
	return &api.PodSandbox{
		Name:      "gap-m001-tetragon",
		Namespace: "sygma-gap-eval",
		Annotations: map[string]string{
			timelinePrestartAnnotation: timelinePrestartValue,
		},
		Labels: map[string]string{
			"app.kubernetes.io/part-of": "sygma-startup-gap-eval",
			"gap.sygma.io/backend":      "tetragon",
			"gap.sygma.io/trial":        "m001-tetragon",
			"gap.sygma.io/application":  "nginx",
		},
	}
}

func TestTimelineOnlyAdjustmentHasNoPolicySideEffects(t *testing.T) {
	originalLog := log
	log = logrus.New()
	t.Cleanup(func() { log = originalLog })

	adjust, updates, err := (&plugin{}).CreateContainer(
		context.Background(), markerPod(), &api.Container{Name: "probe"},
	)
	if err != nil {
		t.Fatalf("CreateContainer failed: %v", err)
	}
	if adjust == nil || updates != nil {
		t.Fatalf("unexpected adjustment=%v updates=%v", adjust, updates)
	}
	if len(adjust.GetMounts()) != 0 || len(adjust.GetEnv()) != 0 ||
		len(adjust.GetAnnotations()) != 0 || adjust.GetLinux() != nil {
		t.Fatalf("timing marker mutated container policy state: %+v", adjust)
	}
	hooks := adjust.GetHooks()
	if hooks == nil || len(hooks.GetPrestart()) != 1 || len(hooks.GetPoststop()) != 0 ||
		len(hooks.GetPoststart()) != 0 || len(hooks.GetCreateRuntime()) != 0 ||
		len(hooks.GetCreateContainer()) != 0 || len(hooks.GetStartContainer()) != 0 {
		t.Fatalf("unexpected timing-only hooks: %+v", hooks)
	}
	hook := hooks.GetPrestart()[0]
	if hook.GetPath() != "/usr/local/bin/sygma-hook" ||
		len(hook.GetArgs()) != 2 || hook.GetArgs()[1] != "timeline-prestart" {
		t.Fatalf("unexpected prestart hook: %+v", hook)
	}
	wantEnv := map[string]bool{
		"SYGMA_TIMELINE_MODE=tetragon-measurement": true,
		"SYGMA_HOOK_ROLE=timestamp-only":           true,
		"SYGMA_EXPERIMENT_BACKEND=tetragon":        true,
		"SYGMA_EXPERIMENT_TRIAL_ID=m001-tetragon":  true,
		"SYGMA_EXPERIMENT_APPLICATION=nginx":       true,
	}
	if len(hook.GetEnv()) != len(wantEnv) {
		t.Fatalf("unexpected hook env: %v", hook.GetEnv())
	}
	for _, value := range hook.GetEnv() {
		if !wantEnv[value] {
			t.Errorf("unexpected hook env entry %q", value)
		}
	}
}

func TestTimelineOnlyTargetValidationFailsClosed(t *testing.T) {
	originalLog := log
	log = logrus.New()
	t.Cleanup(func() { log = originalLog })

	tests := []struct {
		name      string
		mutatePod func(*api.PodSandbox)
		container string
	}{
		{name: "wrong container", container: "sidecar"},
		{name: "wrong backend", container: "probe", mutatePod: func(pod *api.PodSandbox) {
			pod.Labels["gap.sygma.io/backend"] = "sygma"
		}},
		{name: "missing trial", container: "probe", mutatePod: func(pod *api.PodSandbox) {
			delete(pod.Labels, "gap.sygma.io/trial")
		}},
		{name: "unknown application", container: "probe", mutatePod: func(pod *api.PodSandbox) {
			pod.Labels["gap.sygma.io/application"] = "unknown"
		}},
		{name: "mode collision", container: "probe", mutatePod: func(pod *api.PodSandbox) {
			pod.Annotations["sygma.io/mode"] = "enforcement"
		}},
		{name: "unknown marker version", container: "probe", mutatePod: func(pod *api.PodSandbox) {
			pod.Annotations[timelinePrestartAnnotation] = "v2"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := markerPod()
			if test.mutatePod != nil {
				test.mutatePod(pod)
			}
			adjust, _, err := (&plugin{}).CreateContainer(
				context.Background(), pod, &api.Container{Name: test.container},
			)
			if err == nil || adjust != nil {
				t.Fatalf("unsafe marker target accepted: adjustment=%v err=%v", adjust, err)
			}
		})
	}
}
