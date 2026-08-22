package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisPersistentTTL time.Duration = 0

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

func (sgm *SyscallGraphManager) getOrCreateImageID(imageName string) (uint32, error) {
	var result string
	var err error
	for _, key := range imageNameMappingKeys(imageName) {
		result, err = sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
		if err == nil {
			break
		}
		if err != redis.Nil {
			return 0, fmt.Errorf("read image ID mapping: %w", err)
		}
	}

	if err == nil {
		id, parseErr := strconv.ParseUint(result, 10, 32)
		if parseErr != nil {
			return 0, fmt.Errorf(" ID  : %v", parseErr)
		}
		imageID := uint32(id)
		log.Printf("  ID : %s → %d", imageName, imageID)
		return imageID, nil
	}
	counterKey := "image_id_counter"
	newID, err := sgm.RedisClient.Client.Incr(sgm.RedisClient.Ctx, counterKey).Result()
	if err != nil {
		return 0, fmt.Errorf(" ID   : %v", err)
	}

	imageID := uint32(newID)

	log.Printf("  ID : %s → %d", imageName, imageID)
	return imageID, nil
}

func MarshalImageMetadata(metadata ImageMetadata) ([]byte, error) {
	if err := ValidateImageMetadata(metadata); err != nil {
		return nil, err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal image metadata: %w", err)
	}
	return data, nil
}

func UnmarshalImageMetadata(data []byte) (ImageMetadata, error) {
	var metadata ImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return ImageMetadata{}, fmt.Errorf("unmarshal image metadata: %w", err)
	}
	if err := ValidateImageMetadata(metadata); err != nil {
		return ImageMetadata{}, err
	}
	return metadata, nil
}

func ValidateImageMetadata(metadata ImageMetadata) error {
	if strings.TrimSpace(metadata.ImageName) == "" || metadata.ImageName != strings.TrimSpace(metadata.ImageName) {
		return fmt.Errorf("image metadata imageName %q is invalid", metadata.ImageName)
	}
	trimmedBinary := strings.TrimSpace(metadata.BinaryName)
	if trimmedBinary == "" || metadata.BinaryName != trimmedBinary || strings.EqualFold(trimmedBinary, "unknown") {
		return fmt.Errorf("image metadata binaryName %q is invalid", metadata.BinaryName)
	}
	if strings.ContainsAny(metadata.BinaryName, `/\`) {
		return fmt.Errorf("image metadata binaryName %q must be a basename", metadata.BinaryName)
	}
	if metadata.BinaryPath != "" && !filepath.IsAbs(metadata.BinaryPath) {
		return fmt.Errorf("image metadata binaryPath %q is not absolute", metadata.BinaryPath)
	}
	return nil
}

func BinaryNameFromImage(imageName string) string {
	segment := imageName
	if slash := strings.LastIndex(segment, "/"); slash >= 0 {
		segment = segment[slash+1:]
	}
	if delimiter := strings.IndexAny(segment, ":@"); delimiter >= 0 {
		segment = segment[:delimiter]
	}
	return segment
}

func NormalizeImageName(imageName string) string {
	normalized := strings.TrimPrefix(imageName, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")
	lastSlash := strings.LastIndex(normalized, "/")
	lastSegment := normalized[lastSlash+1:]
	if !strings.Contains(lastSegment, ":") && !strings.Contains(lastSegment, "@") {
		normalized += ":latest"
	}
	return normalized
}

func imageNameMappingKeys(imageName string) []string {
	exact := fmt.Sprintf("image_name_map:%s", imageName)
	normalized := fmt.Sprintf("image_name_map:%s", NormalizeImageName(imageName))
	if normalized == exact {
		return []string{exact}
	}
	return []string{exact, normalized}
}

func (sgm *SyscallGraphManager) storeImageMappings(imageID uint32, metadata ImageMetadata) error {
	data, err := MarshalImageMetadata(metadata)
	if err != nil {
		return err
	}
	pipe := sgm.RedisClient.Client.TxPipeline()
	for _, key := range imageNameMappingKeys(metadata.ImageName) {
		pipe.Set(sgm.RedisClient.Ctx, key, imageID, redisPersistentTTL)
	}
	pipe.Set(
		sgm.RedisClient.Ctx,
		fmt.Sprintf("image_id_map:%d", imageID),
		data,
		redisPersistentTTL,
	)
	if _, err := pipe.Exec(sgm.RedisClient.Ctx); err != nil {
		return fmt.Errorf("store image mappings: %w", err)
	}
	return nil
}

func (sgm *SyscallGraphManager) GetImageMetadata(imageID uint32) (ImageMetadata, error) {
	data, err := sgm.RedisClient.Client.Get(
		sgm.RedisClient.Ctx, fmt.Sprintf("image_id_map:%d", imageID),
	).Bytes()
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("read image metadata: %w", err)
	}
	return UnmarshalImageMetadata(data)
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
		// Bootstrap/init policies require at least one destination syscall.
		if len(toList) == 0 {
			skippedCount++
			continue
		}

		bigInt := big.NewInt(0)

		for _, to := range toList {
			// ⭐
			if isValidSyscall(to) && to != 500 {
				sgm.setBitInBigInt(bigInt, to)
			} else {
				log.Printf("     : %d", to)
			}
		}

		bytes := sgm.bigIntTo45Bytes(bigInt)

		//  : syscall_graph:{imageID}:{phase}:{fromSyscall}
		key := fmt.Sprintf("syscall_graph:%d:%d:%d", imageID, phase, from)
		pipe.Set(sgm.RedisClient.Ctx, key, bytes, redisPersistentTTL)
		storedCount++
	}

	//  Phase
	metaKey := fmt.Sprintf("syscall_meta:%d:%d", imageID, phase)
	metaValue := fmt.Sprintf("%d:%d", storedCount, skippedCount)
	pipe.Set(sgm.RedisClient.Ctx, metaKey, metaValue, redisPersistentTTL)

	_, err := pipe.Exec(sgm.RedisClient.Ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("Redis   : %v", err)
	}

	log.Printf("     - ID: %d, Phase: %d, : %d, : %d",
		imageID, phase, storedCount, skippedCount)
	return storedCount, skippedCount, nil
}

func validateInitTransitions(transitions map[string][]int) error {
	if len(transitions) == 0 {
		return fmt.Errorf("init bootstrap policy contains no transitions")
	}
	start, ok := transitions[strconv.Itoa(500)]
	if !ok || len(start) == 0 {
		return fmt.Errorf("init bootstrap policy requires a non-empty START (500) transition")
	}
	for fromString, destinations := range transitions {
		from, err := strconv.Atoi(fromString)
		if err != nil || !isValidSyscall(from) {
			return fmt.Errorf("init bootstrap policy contains invalid source syscall %q", fromString)
		}
		if len(destinations) == 0 {
			return fmt.Errorf("init bootstrap source syscall %d has no destinations", from)
		}
		for _, destination := range destinations {
			if destination == 500 || !isValidSyscall(destination) {
				return fmt.Errorf("init bootstrap source syscall %d contains invalid destination %d", from, destination)
			}
		}
	}
	return nil
}

func marshalMainPolicy(policy *MainPolicySpec, revision string) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("main policy is nil")
	}
	if policy.Type != PolicyTypeStateMachine || policy.StateMachine == nil {
		return nil, fmt.Errorf("main policy must contain a %q state machine", PolicyTypeStateMachine)
	}
	if revision == "" {
		return nil, fmt.Errorf("policy publication revision is empty")
	}

	data, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("marshal main policy: %w", err)
	}
	return data, nil
}

// PublishImageTemplate is the sole complete-publication path. It invalidates
// the previous revision before mutating metadata or policy payloads, then sets
// the ready marker in the same Redis transaction as the main policy. Readers
// must ignore all payload keys while policy_ready:<imageID> is absent.
func (sgm *SyscallGraphManager) PublishImageTemplate(
	metadata ImageMetadata,
	initTransitions map[string][]int,
	mainPolicy *MainPolicySpec,
	revision string,
) (*ProcessResult, error) {
	if err := ValidateImageMetadata(metadata); err != nil {
		return nil, fmt.Errorf("invalid image metadata: %w", err)
	}
	if err := validateInitTransitions(initTransitions); err != nil {
		return nil, err
	}
	mainData, err := marshalMainPolicy(mainPolicy, revision)
	if err != nil {
		return nil, err
	}

	imageID, err := sgm.getOrCreateImageID(metadata.ImageName)
	if err != nil {
		return nil, fmt.Errorf("resolve image ID: %w", err)
	}
	if err := sgm.clearPolicyReady(imageID); err != nil {
		return nil, fmt.Errorf("begin policy publication: %w", err)
	}
	if err := sgm.storeImageMappings(imageID, metadata); err != nil {
		return nil, sgm.failPolicyPublication(imageID, fmt.Errorf("store image metadata and aliases: %w", err))
	}
	if err := sgm.clearSyscallGraphPhase(imageID, 0); err != nil {
		return nil, sgm.failPolicyPublication(imageID, fmt.Errorf("clear existing init graph: %w", err))
	}
	storedEntries, skippedEntries, err := sgm.storeSyscallGraph(imageID, 0, initTransitions)
	if err != nil {
		return nil, sgm.failPolicyPublication(imageID, fmt.Errorf("store init graph: %w", err))
	}

	// A state-machine main policy replaces the old graph-based main phase.
	// Remove those keys so a node agent cannot replay stale graph rows for an
	// image ID that is being reused.
	if err := sgm.clearSyscallGraphPhase(imageID, 1); err != nil {
		return nil, sgm.failPolicyPublication(imageID,
			fmt.Errorf("clear legacy main graph for image %d: %w", imageID, err))
	}

	pipe := sgm.RedisClient.Client.TxPipeline()
	pipe.Set(
		sgm.RedisClient.Ctx,
		fmt.Sprintf("main_policy:%d", imageID),
		mainData,
		redisPersistentTTL,
	)
	pipe.Set(
		sgm.RedisClient.Ctx,
		PolicyReadyKey(imageID),
		revision,
		redisPersistentTTL,
	)
	if _, err := pipe.Exec(sgm.RedisClient.Ctx); err != nil {
		return nil, sgm.failPolicyPublication(imageID,
			fmt.Errorf("publish main policy for image %d: %w", imageID, err))
	}

	log.Printf("Published %s image template for image ID %d (revision %s)", mainPolicy.Type, imageID, revision)
	return &ProcessResult{
		ImageID:        imageID,
		StoredEntries:  storedEntries,
		SkippedEntries: skippedEntries,
	}, nil
}

func PolicyReadyKey(imageID uint32) string {
	return fmt.Sprintf("policy_ready:%d", imageID)
}

// IsPolicyPublicationReady reports whether imageID has a nonempty publication
// marker and the minimum payload needed by every reader. MGET observes the
// marker, main policy, image metadata, and init START row in one Redis command,
// preventing a mixed result across commands. Redis transport/server failures
// are returned so callers do not mistake an unavailable store for a lost
// publication.
func (sgm *SyscallGraphManager) IsPolicyPublicationReady(imageID uint32) (bool, error) {
	if imageID == 0 {
		return false, fmt.Errorf("policy publication image ID is zero")
	}
	keys := []string{
		PolicyReadyKey(imageID),
		fmt.Sprintf("main_policy:%d", imageID),
		fmt.Sprintf("image_id_map:%d", imageID),
		fmt.Sprintf("syscall_graph:%d:0:500", imageID),
	}
	values, err := sgm.RedisClient.Client.MGet(sgm.RedisClient.Ctx, keys...).Result()
	if err != nil {
		return false, fmt.Errorf("read required policy publication keys for image %d: %w", imageID, err)
	}
	if len(values) != len(keys) {
		return false, fmt.Errorf("read required policy publication keys for image %d: got %d values, want %d",
			imageID, len(values), len(keys))
	}
	for _, value := range values {
		if !redisPublicationValueNonempty(value) {
			return false, nil
		}
	}
	return true, nil
}

func redisPublicationValueNonempty(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []byte:
		return strings.TrimSpace(string(typed)) != ""
	default:
		return strings.TrimSpace(fmt.Sprint(typed)) != ""
	}
}

func (sgm *SyscallGraphManager) clearPolicyReady(imageID uint32) error {
	if err := sgm.RedisClient.Client.Del(sgm.RedisClient.Ctx, PolicyReadyKey(imageID)).Err(); err != nil {
		return fmt.Errorf("delete policy ready marker: %w", err)
	}
	return nil
}

func (sgm *SyscallGraphManager) InvalidatePolicyPublication(imageID uint32) error {
	return sgm.clearPolicyReady(imageID)
}

func (sgm *SyscallGraphManager) failPolicyPublication(imageID uint32, cause error) error {
	if cleanupErr := sgm.clearPolicyReady(imageID); cleanupErr != nil {
		return fmt.Errorf("%w (additionally failed to keep publication invalid: %v)", cause, cleanupErr)
	}
	return cause
}

func (sgm *SyscallGraphManager) clearSyscallGraphPhase(imageID, phase uint32) error {
	keys := make([]string, 0, len(getAllValidSyscalls())+1)
	for _, syscall := range getAllValidSyscalls() {
		keys = append(keys, fmt.Sprintf("syscall_graph:%d:%d:%d", imageID, phase, syscall))
	}
	keys = append(keys, fmt.Sprintf("syscall_meta:%d:%d", imageID, phase))
	if err := sgm.RedisClient.Client.Del(sgm.RedisClient.Ctx, keys...).Err(); err != nil {
		return fmt.Errorf("delete syscall graph keys: %w", err)
	}
	return nil
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
	metadata, err := sgm.GetImageMetadata(imageID)
	if err != nil {
		return "", fmt.Errorf("   : %v", err)
	}
	return metadata.ImageName, nil
}

func (sgm *SyscallGraphManager) GetImageID(imageName string) (uint32, error) {
	var result string
	var err error
	for _, key := range imageNameMappingKeys(imageName) {
		result, err = sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
		if err == nil {
			break
		}
		if err != redis.Nil {
			return 0, fmt.Errorf(" ID  : %v", err)
		}
	}
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
	metadata, err := sgm.GetImageMetadata(imageID)
	if err != nil {
		return "", fmt.Errorf("   : %v", err)
	}
	if metadata.BinaryName == "" {
		return "", fmt.Errorf("binary name is empty for image ID %d", imageID)
	}
	return metadata.BinaryName, nil
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
	keys = append(keys, fmt.Sprintf("main_policy:%d", imageID))
	keys = append(keys, PolicyReadyKey(imageID))

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
	seen := make(map[string]struct{})
	for _, key := range keys {
		idText, getErr := sgm.RedisClient.Client.Get(sgm.RedisClient.Ctx, key).Result()
		if getErr != nil {
			continue
		}
		id, parseErr := strconv.ParseUint(idText, 10, 32)
		if parseErr != nil {
			continue
		}
		metadata, metadataErr := sgm.GetImageMetadata(uint32(id))
		if metadataErr != nil {
			continue
		}
		if _, exists := seen[metadata.ImageName]; !exists {
			seen[metadata.ImageName] = struct{}{}
			imageNames = append(imageNames, metadata.ImageName)
		}
	}

	return imageNames, nil
}

func (sgm *SyscallGraphManager) Close() error {
	return sgm.RedisClient.Client.Close()
}

func (sgm *SyscallGraphManager) cleanupImageMapping(imageID uint32) error {
	imageName, err := sgm.GetImageName(imageID)
	if err != nil {
		return fmt.Errorf("   : %w", err)
	}

	mappingKeys := []string{fmt.Sprintf("image_id_map:%d", imageID)}
	mappingKeys = append(mappingKeys, imageNameMappingKeys(imageName)...)

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
