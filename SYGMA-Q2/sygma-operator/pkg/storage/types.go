package storage

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	Client *redis.Client
	Ctx    context.Context
}

type SyscallGraphManager struct {
	RedisClient    *RedisClient
	ImageIDCounter uint32
}

type PolicyMetadata struct {
	Name      string
	Namespace string
}

type PolicySpec struct {
	ImageName   string
	BinaryName  string
	Phase       uint32 // ⭐ 0: init, 1: main
	Transitions map[string][]int
}

type SyscallGraphPolicy struct {
	Metadata PolicyMetadata
	Spec     PolicySpec
}

type ProcessResult struct {
	ImageID        uint32
	StoredEntries  int
	SkippedEntries int
}

const ALLOW_ALL_TRANSITIONS = -1
