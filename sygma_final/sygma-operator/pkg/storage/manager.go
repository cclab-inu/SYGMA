package storage

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ============================================================================
// Redis Client
// ============================================================================

func NewRedisClient(addr, password string, db int) *RedisClient {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     20,
		MaxRetries:   3,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})

	ctx := context.Background()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis  : %v", err)
	}

	log.Printf("Redis  : %s", addr)
	return &RedisClient{
		Client: rdb,
		Ctx:    ctx,
	}
}

// ============================================================================
// SyscallGraphManager
// ============================================================================

func NewSyscallGraphManager(redisClient *RedisClient) *SyscallGraphManager {
	return &SyscallGraphManager{
		RedisClient:    redisClient,
		ImageIDCounter: 0,
	}
}

func (sgm *SyscallGraphManager) getOrCreateImageID(imageName, binaryName string) (uint32, error) {
	imageIDKey := fmt.Sprintf("image_name_map:%s", imageName)
	result, err := sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, imageIDKey).Result()

	if err == nil {
		id, parseErr := strconv.ParseUint(result, 10, 32)
		if parseErr != nil {
			return 0, fmt.Errorf(" ID  : %v", parseErr)
		}
		log.Printf("  ID : %s → %d", imageName, uint32(id))

		if binaryName != "" {
			imageValueKey := fmt.Sprintf("image_id_map:%d", uint32(id))
			imageValue := fmt.Sprintf("%s:%s", imageName, binaryName)
			err := sgm.RedisClient.Client.Set(sgm.RedisClient.Ctx, imageValueKey, imageValue, 24*time.Hour).Err()
			if err != nil {
				log.Printf("⚠️      : %v", err)
			} else {
				log.Printf("✅    : %s", imageValue)
			}
		}

		return uint32(id), nil
	}

	counterKey := "image_id_counter"
	newID, err := sgm.RedisClient.Client.Incr(sgm.RedisClient.Ctx, counterKey).Result()
	if err != nil {
		return 0, fmt.Errorf(" ID   : %v", err)
	}

	imageID := uint32(newID)

	if binaryName == "" {
		imageNamePart := imageName

		colonIndex := -1
		for i, char := range imageName {
			if char == ':' {
				colonIndex = i
				break
			}
		}
		if colonIndex >= 0 {
			imageNamePart = imageName[:colonIndex]
		}

		slashIndex := -1
		for i := len(imageNamePart) - 1; i >= 0; i-- {
			if imageNamePart[i] == '/' {
				slashIndex = i
				break
			}
		}
		if slashIndex >= 0 {
			binaryName = imageNamePart[slashIndex+1:]
		} else {
			binaryName = imageNamePart
		}

		log.Printf("  : %s → %s", imageName, binaryName)
	}

	pipe := sgm.RedisClient.Client.Pipeline()
	pipe.Set(sgm.RedisClient.Ctx, imageIDKey, imageID, 24*time.Hour)

	imageValue := fmt.Sprintf("%s:%s", imageName, binaryName)
	pipe.Set(sgm.RedisClient.Ctx, fmt.Sprintf("image_id_map:%d", imageID), imageValue, 24*time.Hour)

	_, err = pipe.Exec(sgm.RedisClient.Ctx)
	if err != nil {
		return 0, fmt.Errorf(" ID   : %v", err)
	}

	log.Printf("  ID : %s → %d", imageName, imageID)
	log.Printf("  : image_id_map:%d → %s", imageID, imageValue)
	return imageID, nil
}

// ⭐ ProcessSyscallGraphPolicy - Phase
func (sgm *SyscallGraphManager) ProcessSyscallGraphPolicy(policy *SyscallGraphPolicy) (*ProcessResult, error) {
	log.Printf("     : %s/%s (: %s, : %s, phase: %d)",
		policy.Metadata.Namespace, policy.Metadata.Name,
		policy.Spec.ImageName, policy.Spec.BinaryName, policy.Spec.Phase)

	imageID, err := sgm.getOrCreateImageID(policy.Spec.ImageName, policy.Spec.BinaryName)
	if err != nil {
		return nil, fmt.Errorf(" ID  : %v", err)
	}

	// ⭐ Phase
	storedEntries, skippedEntries, err := sgm.storeSyscallGraph(
		imageID,
		policy.Spec.Phase, // Phase
		policy.Spec.Transitions,
	)
	if err != nil {
		return nil, fmt.Errorf("Redis  : %v", err)
	}

	result := &ProcessResult{
		ImageID:        imageID,
		StoredEntries:  storedEntries,
		SkippedEntries: skippedEntries,
	}

	log.Printf("     : %s (ID: %d, Phase: %d)",
		policy.Spec.ImageName, imageID, policy.Spec.Phase)
	return result, nil
}

func isValidSyscall(syscall int) bool {
	if syscall == 500 {
		return true // Initial syscall
	}
	if syscall >= 0 && syscall <= 334 {
		return true
	}
	if syscall >= 424 && syscall <= 448 {
		return true
	}
	return false
}

// ⭐   syscall
func getAllValidSyscalls() []int {
	syscalls := []int{500} // Initial syscall

	// 0-334
	for i := 0; i <= 334; i++ {
		syscalls = append(syscalls, i)
	}

	// 424-448
	for i := 424; i <= 448; i++ {
		syscalls = append(syscalls, i)
	}

	return syscalls
}

// ⭐ storeSyscallGraph - Phase
func (sgm *SyscallGraphManager) storeSyscallGraph(imageID uint32, phase uint32, transitions map[string][]int) (int, int, error) {
	log.Printf("     - ID: %d, Phase: %d", imageID, phase)

	pipe := sgm.RedisClient.Client.Pipeline()
	storedCount := 0
	skippedCount := 0

	for fromStr, toList := range transitions {
		from, err := strconv.Atoi(fromStr)
		if err != nil {
			log.Printf("   : %s", fromStr)
			skippedCount++
			continue
		}

		// ⭐
		if !isValidSyscall(from) {
			log.Printf("    : %d", from)
			skippedCount++
			continue
		}

		if len(toList) == 0 {
			skippedCount++
			continue
		}

		bigInt := big.NewInt(0)

		hasWildcard := false
		for _, to := range toList {
			if to == ALLOW_ALL_TRANSITIONS {
				hasWildcard = true
				break
			}
		}

		if hasWildcard {
			log.Printf("🌟   : Phase %d,  %d →   ", phase, from)
			sgm.setAllBitsInBigInt(bigInt)
		} else {
			for _, to := range toList {
				// ⭐
				if isValidSyscall(to) {
					sgm.setBitInBigInt(bigInt, to)
				} else {
					log.Printf("     : %d", to)
				}
			}
		}

		bytes := sgm.bigIntTo45Bytes(bigInt)

		//  : syscall_graph:{imageID}:{phase}:{fromSyscall}
		key := fmt.Sprintf("syscall_graph:%d:%d:%d", imageID, phase, from)
		pipe.Set(sgm.RedisClient.Ctx, key, bytes, 24*time.Hour)
		storedCount++
	}

	//  Phase
	metaKey := fmt.Sprintf("syscall_meta:%d:%d", imageID, phase)
	metaValue := fmt.Sprintf("%d:%d", storedCount, skippedCount)
	pipe.Set(sgm.RedisClient.Ctx, metaKey, metaValue, 24*time.Hour)

	_, err := pipe.Exec(sgm.RedisClient.Ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("Redis   : %v", err)
	}

	log.Printf("     - ID: %d, Phase: %d, : %d, : %d",
		imageID, phase, storedCount, skippedCount)
	return storedCount, skippedCount, nil
}

func (sgm *SyscallGraphManager) setAllBitsInBigInt(bigInt *big.Int) {
	for i := 0; i < 360; i++ {
		bit := big.NewInt(1)
		bit.Lsh(bit, uint(i))
		bigInt.Or(bigInt, bit)
	}
}

func (sgm *SyscallGraphManager) setBitInBigInt(bigInt *big.Int, syscall int) {
	bitIndex := sgm.syscallToBitIndex(syscall)
	if bitIndex < 0 || bitIndex >= 360 {
		return
	}

	bit := big.NewInt(1)
	bit.Lsh(bit, uint(bitIndex))
	bigInt.Or(bigInt, bit)
}

func (sgm *SyscallGraphManager) syscallToBitIndex(syscall int) int {
	if syscall == 500 {
		return -1 // Invalid - 500 to_syscall
	}
	if syscall >= 0 && syscall <= 334 {
		return syscall
	}
	if syscall >= 424 && syscall <= 448 {
		return 335 + (syscall - 424)
	}
	return -1
}

func (sgm *SyscallGraphManager) bigIntTo45Bytes(bigInt *big.Int) []byte {
	bytes := bigInt.Bytes()
	result := make([]byte, 45)

	if len(bytes) <= 45 {
		copy(result[45-len(bytes):], bytes)
	} else {
		copy(result, bytes[len(bytes)-45:])
	}

	return result
}

// ⭐ GetSyscallGraph - Phase
func (sgm *SyscallGraphManager) GetSyscallGraph(imageID uint32, phase uint32) (map[int]*big.Int, error) {
	result := make(map[int]*big.Int)

	validSyscalls := getAllValidSyscalls()

	pipe := sgm.RedisClient.Client.Pipeline()
	cmds := make(map[int]*redis.StringCmd)

	for _, syscall := range validSyscalls {
		key := fmt.Sprintf("syscall_graph:%d:%d:%d", imageID, phase, syscall)
		cmds[syscall] = pipe.Get(sgm.RedisClient.Ctx, key)
	}

	_, err := pipe.Exec(sgm.RedisClient.Ctx)
	if err != nil && err != redis.Nil {
		return result, fmt.Errorf("Redis  : %v", err)
	}

	for syscall, cmd := range cmds {
		val, err := cmd.Bytes()
		if err != nil {
			if err == redis.Nil {
				result[syscall] = big.NewInt(0)
				continue
			}
			return result, fmt.Errorf("syscall %d  : %v", syscall, err)
		}

		result[syscall] = sgm.bytesTo360BitInt(val)
	}

	return result, nil
}

func (sgm *SyscallGraphManager) bytesTo360BitInt(bytes []byte) *big.Int {
	bigInt := new(big.Int)
	bigInt.SetBytes(bytes)
	return bigInt
}

func (sgm *SyscallGraphManager) GetImageName(imageID uint32) (string, error) {
	key := fmt.Sprintf("image_id_map:%d", imageID)
	result, err := sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("   : %v", err)
	}

	parts := parseMetaValue(result)
	if len(parts) > 0 {
		return parts[0], nil
	}

	return result, nil
}

func (sgm *SyscallGraphManager) GetImageID(imageName string) (uint32, error) {
	key := fmt.Sprintf("image_name_map:%s", imageName)
	result, err := sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf(" ID  : %v", err)
	}

	id, parseErr := strconv.ParseUint(result, 10, 32)
	if parseErr != nil {
		return 0, fmt.Errorf(" ID  : %v", parseErr)
	}

	return uint32(id), nil
}

func (sgm *SyscallGraphManager) GetBinaryName(imageID uint32) (string, error) {
	key := fmt.Sprintf("image_id_map:%d", imageID)
	result, err := sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("   : %v", err)
	}

	parts := parseMetaValue(result)
	if len(parts) >= 2 {
		return parts[1], nil
	}

	if len(parts) > 0 {
		imageName := parts[0]
		imageNamePart := imageName

		colonIndex := -1
		for i, char := range imageName {
			if char == ':' {
				colonIndex = i
				break
			}
		}
		if colonIndex >= 0 {
			imageNamePart = imageName[:colonIndex]
		}

		slashIndex := -1
		for i := len(imageNamePart) - 1; i >= 0; i-- {
			if imageNamePart[i] == '/' {
				slashIndex = i
				break
			}
		}
		if slashIndex >= 0 {
			return imageNamePart[slashIndex+1:], nil
		}
		return imageNamePart, nil
	}

	return "", fmt.Errorf("   ")
}

// ⭐ DeleteSyscallGraph - Phase
func (sgm *SyscallGraphManager) DeleteSyscallGraph(imageID uint32) error {
	log.Printf("=== Redis    - ID: %d ===", imageID)

	var keys []string
	validSyscalls := getAllValidSyscalls()

	// Phase 0 (Init)
	for _, syscall := range validSyscalls {
		keys = append(keys, fmt.Sprintf("syscall_graph:%d:0:%d", imageID, syscall))
	}
	keys = append(keys, fmt.Sprintf("syscall_meta:%d:0", imageID))

	// Phase 1 (Main)
	for _, syscall := range validSyscalls {
		keys = append(keys, fmt.Sprintf("syscall_graph:%d:1:%d", imageID, syscall))
	}
	keys = append(keys, fmt.Sprintf("syscall_meta:%d:1", imageID))

	deleted, _ := sgm.RedisClient.Client.Del(sgm.RedisClient.Ctx, keys...).Result()
	log.Printf("✅ Syscall graph   : %d  ", deleted)

	return nil
}

func (sgm *SyscallGraphManager) ListStoredImages() ([]string, error) {
	keys, err := sgm.RedisClient.Client.Keys(sgm.RedisClient.Ctx, "image_name_map:*").Result()
	if err != nil {
		return nil, fmt.Errorf("   : %v", err)
	}

	var imageNames []string
	for _, key := range keys {
		if len(key) > 16 {
			imageName := key[16:]
			imageNames = append(imageNames, imageName)
		}
	}

	return imageNames, nil
}

func (sgm *SyscallGraphManager) Close() error {
	return sgm.RedisClient.Client.Close()
}

// ============================================================================
// Utility Functions
// ============================================================================

func parseMetaValue(value string) []string {
	var parts []string
	current := ""

	for _, char := range value {
		if char == ':' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	parts = append(parts, current)

	return parts
}

func (sgm *SyscallGraphManager) cleanupImageMapping(imageID uint32) error {
	imageName, err := sgm.GetImageName(imageID)
	if err != nil {
		return fmt.Errorf("   : %w", err)
	}

	var mappingKeys []string
	mappingKeys = append(mappingKeys, fmt.Sprintf("image_id_map:%d", imageID))
	mappingKeys = append(mappingKeys, fmt.Sprintf("image_name_map:%s", imageName))

	deleted, err := sgm.RedisClient.Client.Del(sgm.RedisClient.Ctx, mappingKeys...).Result()
	if err != nil {
		return fmt.Errorf("   : %w", err)
	}

	log.Printf("✅    : %d   (: %s)", deleted, imageName)
	return nil
}

func (sgm *SyscallGraphManager) DeleteSyscallGraphComplete(imageID uint32) error {
	log.Printf("===    - ID: %d ===", imageID)

	if err := sgm.DeleteSyscallGraph(imageID); err != nil {
		return fmt.Errorf("syscall graph  : %w", err)
	}

	if err := sgm.cleanupImageMapping(imageID); err != nil {
		log.Printf("⚠️     : %v", err)
	}

	log.Printf("===    - ID: %d ===", imageID)
	return nil
}

func (sgm *SyscallGraphManager) DeleteSyscallGraphByImageName(imageName string) error {
	log.Printf("===    : %s ===", imageName)

	imageID, err := sgm.GetImageID(imageName)
	if err != nil {
		return fmt.Errorf(" ID  : %w", err)
	}

	return sgm.DeleteSyscallGraphComplete(imageID)
}
