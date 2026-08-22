package storage

import (
	"context"

	"github.com/redis/go-redis/v9"

	securityv1 "example.org/sygma/operator/api/v1"
)

type RedisClient struct {
	Client *redis.Client
	Ctx    context.Context
}

type SyscallGraphManager struct {
	RedisClient    *RedisClient
	ImageIDCounter uint32
}

type ProcessResult struct {
	ImageID        uint32
	StoredEntries  int
	SkippedEntries int
}

type ImageMetadata struct {
	ImageName  string `json:"imageName"`
	BinaryName string `json:"binaryName"`
	BinaryPath string `json:"binaryPath"`
}

const PolicyTypeStateMachine = "state-machine"

type MainPolicySpec struct {
	Type         string                             `json:"type"`
	StateMachine *securityv1.StateMachinePolicySpec `json:"stateMachine"`
}
