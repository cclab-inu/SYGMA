package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"

	securityv1 "example.org/sygma/operator/api/v1"
)

type recordedRedisHook struct {
	commands             [][]interface{}
	stringValues         map[string]string
	getErrors            map[string]error
	pipelineErrorOnReady bool
}

func (hook *recordedRedisHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (hook *recordedRedisHook) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, command redis.Cmder) error {
		hook.commands = append(hook.commands, append([]interface{}(nil), command.Args()...))
		switch strings.ToLower(command.Name()) {
		case "get":
			key := fmt.Sprint(command.Args()[1])
			if injectedErr, exists := hook.getErrors[key]; exists {
				command.SetErr(injectedErr)
				return injectedErr
			}
			value, exists := hook.stringValues[key]
			if !exists {
				command.SetErr(redis.Nil)
				return redis.Nil
			}
			stringCommand, ok := command.(*redis.StringCmd)
			if !ok {
				return fmt.Errorf("GET command has type %T", command)
			}
			stringCommand.SetVal(value)
		case "mget":
			values := make([]interface{}, 0, len(command.Args())-1)
			for _, rawKey := range command.Args()[1:] {
				key := fmt.Sprint(rawKey)
				if injectedErr, exists := hook.getErrors[key]; exists {
					command.SetErr(injectedErr)
					return injectedErr
				}
				if value, exists := hook.stringValues[key]; exists {
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
		case "del":
			for _, key := range command.Args()[1:] {
				delete(hook.stringValues, fmt.Sprint(key))
			}
		}
		command.SetErr(nil)
		return nil
	}
}

func TestGetOrCreateImageIDUsesNormalizedAlias(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
	metadataJSON, err := MarshalImageMetadata(ImageMetadata{
		ImageName: "nginx:1.27", BinaryName: "nginx",
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordedRedisHook{stringValues: map[string]string{
		"image_name_map:nginx:1.27": "12",
		"image_id_map:12":           string(metadataJSON),
	}}
	redisClient.AddHook(recorder)
	manager := &SyscallGraphManager{
		RedisClient: &RedisClient{Client: redisClient, Ctx: context.Background()},
	}
	imageID, err := manager.getOrCreateImageID("docker.io/library/nginx:1.27")
	if err != nil {
		t.Fatalf("getOrCreateImageID() error = %v", err)
	}
	if imageID != 12 {
		t.Fatalf("getOrCreateImageID() = %d, want normalized alias ID 12", imageID)
	}
	for _, command := range recorder.commands {
		if len(command) > 0 && strings.ToLower(fmt.Sprint(command[0])) == "incr" {
			t.Fatalf("getOrCreateImageID() allocated a duplicate ID: %#v", recorder.commands)
		}
	}
}

func (hook *recordedRedisHook) ProcessPipelineHook(_ redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(_ context.Context, commands []redis.Cmder) error {
		fail := false
		for _, command := range commands {
			hook.commands = append(hook.commands, append([]interface{}(nil), command.Args()...))
			if hook.pipelineErrorOnReady && strings.ToLower(command.Name()) == "set" &&
				len(command.Args()) >= 2 && strings.HasPrefix(fmt.Sprint(command.Args()[1]), "policy_ready:") {
				fail = true
			}
		}
		if fail {
			err := fmt.Errorf("injected ready transaction failure")
			for _, command := range commands {
				command.SetErr(err)
			}
			return err
		}
		if hook.stringValues == nil {
			hook.stringValues = make(map[string]string)
		}
		for _, command := range commands {
			if strings.ToLower(command.Name()) == "set" && len(command.Args()) >= 3 {
				hook.stringValues[fmt.Sprint(command.Args()[1])] = fmt.Sprint(command.Args()[2])
			}
			command.SetErr(nil)
		}
		return nil
	}
}

func TestStorageBitmapEncodingIncludesHighSyscalls(t *testing.T) {
	manager := &SyscallGraphManager{}
	mask := big.NewInt(0)
	for _, syscall := range []int{0, 334, 424, 448} {
		manager.setBitInBigInt(mask, syscall)
	}
	for _, bitIndex := range []int{0, 334, 335, 359} {
		if mask.Bit(bitIndex) != 1 {
			t.Fatalf("bitmap bit %d was not set", bitIndex)
		}
	}
	if got := manager.bigIntTo45Bytes(mask); len(got) != 45 {
		t.Fatalf("encoded bitmap length = %d, want 45", len(got))
	}
}

func TestMarshalMainPolicyRejectsNonStateMachineShape(t *testing.T) {
	for _, policy := range []*MainPolicySpec{
		nil,
		{Type: "sequence"},
		{Type: PolicyTypeStateMachine},
	} {
		_, err := marshalMainPolicy(policy, "test-revision")
		if err == nil {
			t.Fatalf("marshalMainPolicy(%#v) returned nil", policy)
		}
		if policy != nil && !strings.Contains(err.Error(), PolicyTypeStateMachine) {
			t.Fatalf("marshalMainPolicy(%#v) error = %q", policy, err)
		}
	}
}

func TestMarshalMainPolicyRejectsEmptyRevision(t *testing.T) {
	policy := &MainPolicySpec{
		Type: PolicyTypeStateMachine,
		StateMachine: &securityv1.StateMachinePolicySpec{
			States: map[string]securityv1.StateMachineStateSpec{
				"0": {AllowedSyscalls: []int{0}},
			},
		},
	}
	if _, err := marshalMainPolicy(policy, ""); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("marshalMainPolicy() error = %v, want revision error", err)
	}
}

func TestImageMetadataJSONWireAndValidation(t *testing.T) {
	metadata := ImageMetadata{
		ImageName:  "docker.io/library/nginx:1.27",
		BinaryName: "nginx",
		BinaryPath: "/usr/sbin/nginx",
	}
	data, err := MarshalImageMetadata(metadata)
	if err != nil {
		t.Fatalf("MarshalImageMetadata() error = %v", err)
	}
	const want = `{"imageName":"docker.io/library/nginx:1.27","binaryName":"nginx","binaryPath":"/usr/sbin/nginx"}`
	if string(data) != want {
		t.Fatalf("metadata wire = %s, want %s", data, want)
	}
	decoded, err := UnmarshalImageMetadata(data)
	if err != nil || decoded != metadata {
		t.Fatalf("UnmarshalImageMetadata() = %#v, %v", decoded, err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil || len(document) != 3 {
		t.Fatalf("metadata JSON shape = %#v, error = %v", document, err)
	}

	invalid := []ImageMetadata{
		{BinaryName: "nginx"},
		{ImageName: "nginx:latest"},
		{ImageName: "nginx:latest", BinaryName: "unknown"},
		{ImageName: "nginx:latest", BinaryName: "usr/bin/nginx"},
		{ImageName: "nginx:latest", BinaryName: `usr\nginx`},
		{ImageName: "nginx:latest", BinaryName: "nginx", BinaryPath: "usr/sbin/nginx"},
	}
	for _, candidate := range invalid {
		if _, err := MarshalImageMetadata(candidate); err == nil {
			t.Fatalf("MarshalImageMetadata(%#v) returned nil error", candidate)
		}
	}
}

func TestImageNameNormalizationAndBinaryFallback(t *testing.T) {
	tests := []struct {
		image      string
		normalized string
		binary     string
	}{
		{image: "nginx", normalized: "nginx:latest", binary: "nginx"},
		{image: "docker.io/library/nginx:1.27", normalized: "nginx:1.27", binary: "nginx"},
		{image: "docker.io/nginx", normalized: "nginx:latest", binary: "nginx"},
		{image: "registry.example:5000/team/httpd", normalized: "registry.example:5000/team/httpd:latest", binary: "httpd"},
		{image: "registry.example:5000/team/redis:7", normalized: "registry.example:5000/team/redis:7", binary: "redis"},
		{image: "registry.example/team/mysql@sha256:abc", normalized: "registry.example/team/mysql@sha256:abc", binary: "mysql"},
	}
	for _, test := range tests {
		if got := NormalizeImageName(test.image); got != test.normalized {
			t.Errorf("NormalizeImageName(%q) = %q, want %q", test.image, got, test.normalized)
		}
		if got := BinaryNameFromImage(test.image); got != test.binary {
			t.Errorf("BinaryNameFromImage(%q) = %q, want %q", test.image, got, test.binary)
		}
	}
	keys := imageNameMappingKeys("docker.io/library/nginx:1.27")
	if len(keys) != 2 || keys[0] != "image_name_map:docker.io/library/nginx:1.27" ||
		keys[1] != "image_name_map:nginx:1.27" {
		t.Fatalf("image mapping keys = %#v", keys)
	}
}

func TestPolicyStorageIsPersistent(t *testing.T) {
	if redisPersistentTTL != 0 {
		t.Fatalf("redisPersistentTTL = %s, want zero", redisPersistentTTL)
	}
	if got := PolicyReadyKey(17); got != "policy_ready:17" {
		t.Fatalf("PolicyReadyKey(17) = %q", got)
	}
}

func TestIsPolicyPublicationReady(t *testing.T) {
	redisFailure := errors.New("injected Redis read failure")
	tests := []struct {
		name      string
		values    map[string]string
		getErrors map[string]error
		wantReady bool
		wantErr   error
	}{
		{
			name: "present nonempty marker",
			values: map[string]string{
				"policy_ready:17":        "config-uid/4/revision",
				"main_policy:17":         `{"type":"state-machine"}`,
				"image_id_map:17":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:17:0:500": "bootstrap-bitmap",
			},
			wantReady: true,
		},
		{
			name: "missing marker",
			values: map[string]string{
				"main_policy:17":         `{"type":"state-machine"}`,
				"image_id_map:17":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:17:0:500": "bootstrap-bitmap",
			},
		},
		{
			name: "blank marker",
			values: map[string]string{
				"policy_ready:17":        "  \t",
				"main_policy:17":         `{"type":"state-machine"}`,
				"image_id_map:17":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:17:0:500": "bootstrap-bitmap",
			},
		},
		{
			name: "missing main policy",
			values: map[string]string{
				"policy_ready:17":        "config-uid/4/revision",
				"image_id_map:17":        `{"imageName":"nginx:1.27"}`,
				"syscall_graph:17:0:500": "bootstrap-bitmap",
			},
		},
		{
			name: "missing image metadata",
			values: map[string]string{
				"policy_ready:17":        "config-uid/4/revision",
				"main_policy:17":         `{"type":"state-machine"}`,
				"syscall_graph:17:0:500": "bootstrap-bitmap",
			},
		},
		{
			name: "missing init START row",
			values: map[string]string{
				"policy_ready:17": "config-uid/4/revision",
				"main_policy:17":  `{"type":"state-machine"}`,
				"image_id_map:17": `{"imageName":"nginx:1.27"}`,
			},
		},
		{
			name:      "Redis error",
			values:    map[string]string{},
			getErrors: map[string]error{"policy_ready:17": redisFailure},
			wantErr:   redisFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			redisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
			t.Cleanup(func() { _ = redisClient.Close() })
			recorder := &recordedRedisHook{
				stringValues: test.values,
				getErrors:    test.getErrors,
			}
			redisClient.AddHook(recorder)
			manager := NewSyscallGraphManager(&RedisClient{
				Client: redisClient,
				Ctx:    context.Background(),
			})

			ready, err := manager.IsPolicyPublicationReady(17)
			if ready != test.wantReady {
				t.Fatalf("IsPolicyPublicationReady() ready = %t, want %t", ready, test.wantReady)
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("IsPolicyPublicationReady() error = %v, want %v", err, test.wantErr)
			}
			if len(recorder.commands) != 1 ||
				fmt.Sprint(recorder.commands[0]) != "[mget policy_ready:17 main_policy:17 image_id_map:17 syscall_graph:17:0:500]" {
				t.Fatalf("ready check commands = %#v", recorder.commands)
			}
		})
	}
}

func TestRedisPublicationValueNonempty(t *testing.T) {
	tests := []struct {
		value interface{}
		want  bool
	}{
		{value: nil},
		{value: "  "},
		{value: []byte("\n\t")},
		{value: "revision", want: true},
		{value: []byte(`{"type":"state-machine"}`), want: true},
	}
	for _, test := range tests {
		if got := redisPublicationValueNonempty(test.value); got != test.want {
			t.Errorf("redisPublicationValueNonempty(%#v) = %t, want %t", test.value, got, test.want)
		}
	}
}

func TestMetadataAndReadyPublicationCommandsArePersistent(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
	recorder := &recordedRedisHook{stringValues: map[string]string{
		"image_name_map:nginx:1.27": "9",
		"policy_ready:9":            "old-revision",
	}}
	redisClient.AddHook(recorder)
	manager := &SyscallGraphManager{
		RedisClient: &RedisClient{Client: redisClient, Ctx: context.Background()},
	}
	metadata := ImageMetadata{
		ImageName:  "docker.io/library/nginx:1.27",
		BinaryName: "nginx",
		BinaryPath: "/usr/sbin/nginx",
	}
	policy := &MainPolicySpec{
		Type: PolicyTypeStateMachine,
		StateMachine: &securityv1.StateMachinePolicySpec{
			States: map[string]securityv1.StateMachineStateSpec{
				"0": {AllowedSyscalls: []int{0}},
			},
		},
	}
	result, err := manager.PublishImageTemplate(
		metadata,
		map[string][]int{"500": {0}, "0": {0}},
		policy,
		"revision-9",
	)
	if err != nil {
		t.Fatalf("PublishImageTemplate() error = %v", err)
	}
	if result.ImageID != 9 {
		t.Fatalf("PublishImageTemplate() image ID = %d, want 9", result.ImageID)
	}

	firstMutation, mainIndex, readyIndex, metadataIndex := -1, -1, -1, -1
	seenKeys := make(map[string]bool)
	for index, command := range recorder.commands {
		if len(command) == 0 {
			continue
		}
		commandName := strings.ToLower(fmt.Sprint(command[0]))
		if firstMutation < 0 && (commandName == "set" || commandName == "del") {
			firstMutation = index
		}
		if commandName != "set" {
			continue
		}
		if len(command) != 3 {
			t.Fatalf("persistent SET includes expiry arguments: %#v", command)
		}
		key := fmt.Sprint(command[1])
		seenKeys[key] = true
		switch key {
		case "image_id_map:9":
			metadataIndex = index
			data, ok := command[2].([]byte)
			if !ok {
				t.Fatalf("metadata SET payload has type %T", command[2])
			}
			stored, err := UnmarshalImageMetadata(data)
			if err != nil || stored != metadata {
				t.Fatalf("published metadata = %#v, %v; want %#v", stored, err, metadata)
			}
		case "main_policy:9":
			mainIndex = index
		case "policy_ready:9":
			readyIndex = index
			if fmt.Sprint(command[2]) != "revision-9" {
				t.Fatalf("ready revision command = %#v", command)
			}
		}
	}
	if firstMutation < 0 || fmt.Sprint(recorder.commands[firstMutation][0]) != "del" ||
		fmt.Sprint(recorder.commands[firstMutation][1]) != "policy_ready:9" {
		t.Fatalf("first payload mutation did not invalidate ready marker: %#v", recorder.commands)
	}
	if metadataIndex < 0 || mainIndex <= metadataIndex || readyIndex <= mainIndex {
		t.Fatalf("publication command order is invalid: %#v", recorder.commands)
	}
	for _, key := range []string{
		"image_name_map:docker.io/library/nginx:1.27",
		"image_name_map:nginx:1.27",
		"image_id_map:9",
	} {
		if !seenKeys[key] {
			t.Fatalf("persistent mapping command for %q is missing: %#v", key, recorder.commands)
		}
	}
}

func TestPublishImageTemplateFailureLeavesReadyMarkerAbsent(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "unused.invalid:0"})
	recorder := &recordedRedisHook{
		stringValues: map[string]string{
			"image_name_map:nginx:1.27": "9",
			"policy_ready:9":            "old-revision",
		},
		pipelineErrorOnReady: true,
	}
	redisClient.AddHook(recorder)
	manager := &SyscallGraphManager{
		RedisClient: &RedisClient{Client: redisClient, Ctx: context.Background()},
	}
	policy := &MainPolicySpec{
		Type: PolicyTypeStateMachine,
		StateMachine: &securityv1.StateMachinePolicySpec{
			States: map[string]securityv1.StateMachineStateSpec{
				"0": {AllowedSyscalls: []int{0}},
			},
		},
	}
	_, err := manager.PublishImageTemplate(
		ImageMetadata{ImageName: "nginx:1.27", BinaryName: "nginx"},
		map[string][]int{"500": {0}},
		policy,
		"revision-9",
	)
	if err == nil || !strings.Contains(err.Error(), "injected ready transaction failure") {
		t.Fatalf("PublishImageTemplate() error = %v, want injected failure", err)
	}
	if _, exists := recorder.stringValues["policy_ready:9"]; exists {
		t.Fatalf("ready marker remains after failed publication: %#v", recorder.stringValues)
	}
	last := recorder.commands[len(recorder.commands)-1]
	if len(last) < 2 || fmt.Sprint(last[0]) != "del" || fmt.Sprint(last[1]) != "policy_ready:9" {
		t.Fatalf("failed publication did not finish by invalidating marker: %#v", recorder.commands)
	}
}

func TestStorageRejectsUnsupportedBitmapDestinations(t *testing.T) {
	manager := &SyscallGraphManager{}
	for _, syscall := range []int{-1, 335, 423, 449, 500} {
		if got := manager.syscallToBitIndex(syscall); got >= 0 {
			t.Fatalf("unsupported syscall %d mapped to bitmap index %d", syscall, got)
		}
	}
}
