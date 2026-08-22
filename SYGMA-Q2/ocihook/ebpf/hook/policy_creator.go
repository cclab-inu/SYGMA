// ocihook/ebpf/hook/policy_creator.go
// SYGMAPolicy CR creation from OCI Hook

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	// "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	sygmaPolicyGVR = schema.GroupVersionResource{
		Group:    "security.security.io",
		Version:  "v1",
		Resource: "sygmapolicies",
	}
)

// SYGMAPolicyCreator handles SYGMAPolicy CR creation
type SYGMAPolicyCreator struct {
	dynamicClient dynamic.Interface
	redisClient   *redis.Client
}

// NewSYGMAPolicyCreator creates a new policy creator
func NewSYGMAPolicyCreator(redisAddr string) (*SYGMAPolicyCreator, error) {
	// OCI Hook    
	// → kubelet.conf  (   )
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		// ⭐   kubelet.conf 
		kubeconfig = "/etc/kubernetes/kubelet.conf"
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Printf("⚠️ Failed to load kubeconfig from %s: %v", kubeconfig, err)
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	log.Printf("✅ Using kubeconfig: %s", kubeconfig)

	// Create dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	return &SYGMAPolicyCreator{
		dynamicClient: dynamicClient,
		redisClient:   redisClient,
	}, nil
}

// CreateSYGMAPolicy creates a SYGMAPolicy CR
func (c *SYGMAPolicyCreator) CreateSYGMAPolicy(
	ctx context.Context,
	namespace, podName, containerID string,
	imageName, binaryName string,
	imageID uint32,
	pidNs, mntNs uint32,
) error {
	log.Printf("📝 Creating SYGMAPolicy CR for %s/%s", namespace, podName)

	// Get node name
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	policyName := fmt.Sprintf("%s-policy", podName)

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.security.io/v1",
			"kind":       "SYGMAPolicy",
			"metadata": map[string]interface{}{
				"name":      policyName,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"sygma.io/pod":      podName,
					"sygma.io/node":     nodeName,
					"sygma.io/image-id": strconv.FormatUint(uint64(imageID), 10),
					"sygma.io/managed":  "true",
				},
				"annotations": map[string]interface{}{
					"sygma.io/created-at":   time.Now().Format(time.RFC3339),
					"sygma.io/container-id": containerID,
				},
			},
			"spec": map[string]interface{}{
				"imageName":   imageName,
				"binaryName":  binaryName,
				"nodeName":    nodeName,
				"podName":     podName,
				"containerID": containerID,
				"pidNs":       int64(pidNs),
				"mntNs":       int64(mntNs),
				"imageID":     int64(imageID),
				"phases":      map[string]interface{}{}, // Agent loads from Redis
			},
		},
	}

	_, err := c.dynamicClient.Resource(sygmaPolicyGVR).Namespace(namespace).Create(
		ctx, policy, metav1.CreateOptions{},
	)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Printf("⚠️ SYGMAPolicy %s exists, updating...", policyName)
			return c.updateSYGMAPolicy(ctx, namespace, policyName, policy)
		}
		return fmt.Errorf("failed to create SYGMAPolicy: %w", err)
	}

	log.Printf("✅ Created SYGMAPolicy: %s/%s", namespace, policyName)

	// Save metadata to Redis
	if err := c.savePodMetadataToRedis(ctx, namespace, podName, imageName,
		binaryName, policyName, imageID, pidNs, mntNs); err != nil {
		log.Printf("⚠️ Failed to save pod metadata: %v", err)
	}

	return nil
}

// updateSYGMAPolicy updates existing policy
func (c *SYGMAPolicyCreator) updateSYGMAPolicy(
	ctx context.Context,
	namespace, policyName string,
	policy *unstructured.Unstructured,
) error {
	existing, err := c.dynamicClient.Resource(sygmaPolicyGVR).Namespace(namespace).Get(
		ctx, policyName, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to get existing policy: %w", err)
	}

	policy.SetResourceVersion(existing.GetResourceVersion())
	_, err = c.dynamicClient.Resource(sygmaPolicyGVR).Namespace(namespace).Update(
		ctx, policy, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	log.Printf("✅ Updated SYGMAPolicy: %s/%s", namespace, policyName)
	return nil
}

// DeleteSYGMAPolicy deletes SYGMAPolicy CR
func (c *SYGMAPolicyCreator) DeleteSYGMAPolicy(ctx context.Context, namespace, podName string) error {
	policyName := fmt.Sprintf("%s-policy", podName)

	err := c.dynamicClient.Resource(sygmaPolicyGVR).Namespace(namespace).Delete(
		ctx, policyName, metav1.DeleteOptions{},
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.Printf("SYGMAPolicy %s not found", policyName)
			return nil
		}
		return fmt.Errorf("failed to delete SYGMAPolicy: %w", err)
	}

	log.Printf("✅ Deleted SYGMAPolicy: %s/%s", namespace, policyName)
	return nil
}

// savePodMetadataToRedis saves metadata for agent
func (c *SYGMAPolicyCreator) savePodMetadataToRedis(
	ctx context.Context,
	namespace, podName, imageName, binaryName, policyName string,
	imageID uint32,
	pidNs, mntNs uint32,
) error {
	metadata := map[string]interface{}{
		"namespace":  namespace,
		"podName":    podName,
		"imageName":  imageName,
		"imageID":    imageID,
		"binaryName": binaryName,
		"policyName": policyName,
		"pidNs":      pidNs,
		"mntNs":      mntNs,
		"timestamp":  time.Now().Unix(),
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	key := fmt.Sprintf("pod:metadata:%s:%s", namespace, podName)
	return c.redisClient.Set(ctx, key, data, 24*time.Hour).Err()
}

// getImageIDFromRedis gets image ID
func (c *SYGMAPolicyCreator) getImageIDFromRedis(ctx context.Context, imageName string) (uint32, error) {
	candidates := []string{imageName}

	// Normalize
	normalized := strings.TrimPrefix(imageName, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")
	if !strings.Contains(normalized, ":") {
		normalized += ":latest"
	}
	if normalized != imageName {
		candidates = append(candidates, normalized)
	}

	// Without tag
	if idx := strings.LastIndex(normalized, ":"); idx != -1 {
		withoutTag := normalized[:idx]
		candidates = append(candidates, withoutTag, withoutTag+":latest")
	}

	for _, candidate := range candidates {
		key := fmt.Sprintf("image_name_map:%s", candidate)
		imageIDStr, err := c.redisClient.Get(ctx, key).Result()
		if err == nil {
			if imageID, err := strconv.ParseUint(imageIDStr, 10, 32); err == nil {
				return uint32(imageID), nil
			}
		}
	}

	return 0, fmt.Errorf("image not found: %s", imageName)
}

// Close cleanup
func (c *SYGMAPolicyCreator) Close() error {
	if c.redisClient != nil {
		return c.redisClient.Close()
	}
	return nil
}
