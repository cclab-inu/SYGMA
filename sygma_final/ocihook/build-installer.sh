#!/bin/bash
# build-installer.sh
# SYGMA installer    (with SYGMAPolicy support)
# : sygma_final/ocihook/build-installer.sh

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo -e "${BLUE}Building SYGMA Installer Image${NC}"
echo -e "${BLUE}(with SYGMAPolicy support check)${NC}"
echo "=========================================="
echo ""

#   
if [ ! -d "build" ]; then
    echo -e "${RED}❌ Error: build/ directory not found!${NC}"
    echo "   Please run this script from sygma_final/ocihook/ directory"
    exit 1
fi

#   
REQUIRED_BINARIES=("sygma-hook" "sygma-tracer" "sygma-wrapper" "00-sygma")
MISSING=0

echo -e "${BLUE}🔍 Checking required binaries in build/ directory...${NC}"
for binary in "${REQUIRED_BINARIES[@]}"; do
    if [ ! -f "build/$binary" ]; then
        echo -e "${RED}❌ Missing: build/$binary${NC}"
        MISSING=1
    else
        echo -e "${GREEN}✅ Found: build/$binary${NC}"
        
        # ⭐ Special check for sygma-hook (SYGMAPolicy support)
        if [ "$binary" == "sygma-hook" ]; then
            if strings "build/$binary" | grep -q "CreateSYGMAPolicy\|policy_creator" 2>/dev/null; then
                echo -e "${GREEN}   ✅ SYGMAPolicy support: ENABLED${NC}"
            else
                echo -e "${YELLOW}   ⚠️  SYGMAPolicy support: DISABLED (fallback only)${NC}"
            fi
        fi
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}⚠️  Some binaries are missing. Please build them first:${NC}"
    echo ""
    echo "   ./build.sh    # ocihook   "
    echo ""
    exit 1
fi

echo ""

# ⭐ policy_creator.go 
echo -e "${BLUE}🔍 Checking source files for installer...${NC}"

HAS_POLICY_CREATOR=0
if [ -f "ebpf/hook/policy_creator.go" ]; then
    echo -e "${GREEN}✅ policy_creator.go found${NC}"
    echo -e "${GREEN}   → SYGMAPolicy CR creation will be available${NC}"
    HAS_POLICY_CREATOR=1
else
    echo -e "${YELLOW}⚠️  policy_creator.go not found${NC}"
    echo -e "${YELLOW}   → Hook will use direct eBPF only (fallback mode)${NC}"
fi

# go.mod K8s dependencies 
if [ -f "go.mod" ] && grep -q "k8s.io/client-go" go.mod; then
    echo -e "${GREEN}✅ K8s client dependencies in go.mod${NC}"
else
    if [ $HAS_POLICY_CREATOR -eq 1 ]; then
        echo -e "${YELLOW}⚠️  K8s client dependencies missing in go.mod${NC}"
        echo -e "${YELLOW}   → SYGMAPolicy features may not work${NC}"
    fi
fi

echo ""

# Dockerfile.installer 
if [ ! -f "Dockerfile.installer" ]; then
    echo -e "${RED}❌ Dockerfile.installer not found!${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Dockerfile.installer found${NC}"
echo ""

# ⭐ Dockerfile   ( )
echo -e "${BLUE}📋 Dockerfile configuration:${NC}"
if grep -q "policy_creator.go" Dockerfile.installer 2>/dev/null; then
    echo -e "${GREEN}   → Includes policy_creator.go${NC}"
else
    if [ $HAS_POLICY_CREATOR -eq 1 ]; then
        echo -e "${YELLOW}   → Warning: policy_creator.go exists but not in Dockerfile${NC}"
        echo -e "${YELLOW}   → Consider adding COPY for policy_creator.go${NC}"
    fi
fi

echo ""

# Docker 
echo -e "${BLUE}🔨 Building docker image...${NC}"
echo ""

if docker build -t sygma-installer:latest -f Dockerfile.installer . ; then
    echo ""
    echo -e "${GREEN}✅ Docker image built successfully!${NC}"
    echo ""
    
    docker save sygma-installer:latest | sudo ctr -n k8s.io images import -
    # Docker  
    echo -e "${BLUE}📦 Image information:${NC}"
    docker images sygma-installer:latest --format "   Size: {{.Size}}"
    docker images sygma-installer:latest --format "   Created: {{.CreatedSince}}"
    echo ""
    
    #    
    echo -e "${BLUE}🔍 Verifying binaries in image:${NC}"
    docker run --rm sygma-installer:latest ls -lh /binaries/ | while IFS= read -r line; do
        echo "   $line"
    done
    echo ""
    
    # ⭐ SYGMAPolicy  
    echo -e "${BLUE}🔍 Checking SYGMAPolicy support in image:${NC}"
    if docker run --rm sygma-installer:latest strings /binaries/sygma-hook | grep -q "CreateSYGMAPolicy" 2>/dev/null; then
        echo -e "${GREEN}   ✅ SYGMAPolicy CR creation: ENABLED${NC}"
    else
        echo -e "${YELLOW}   ⚠️  SYGMAPolicy CR creation: DISABLED${NC}"
    fi
    echo ""
    
    # containerd  import
    echo -e "${BLUE}📥 Importing image to containerd...${NC}"
    if docker save sygma-installer:latest | sudo ctr -n k8s.io images import - ; then
        echo ""
        echo -e "${GREEN}✅ Image imported to containerd successfully!${NC}"
        echo ""
        
        # containerd  
        echo -e "${BLUE}📋 Containerd images:${NC}"
        sudo ctr -n k8s.io images ls | grep sygma-installer || echo "   (sygma-installer image)"
        echo ""
    else
        echo ""
        echo -e "${RED}❌ Failed to import image to containerd${NC}"
        exit 1
    fi
    
else
    echo ""
    echo -e "${RED}❌ Docker build failed!${NC}"
    exit 1
fi

echo "=========================================="
echo -e "${GREEN}✅ Build Complete!${NC}"
echo "=========================================="
echo ""
echo -e "${BLUE}📌 Next steps:${NC}"
echo ""
echo "1. Verify the installer image:"
echo "   docker run --rm sygma-installer:latest ls -lh /binaries"
echo ""
echo "2. Deploy as DaemonSet:"
echo "   kubectl apply -f deploy/sygma-installer.yaml"
echo ""
echo "3. Check installation logs:"
echo "   kubectl logs -n kube-system -l app=sygma-installer"
echo ""
echo "4. Verify installed binaries on nodes:"
echo "   kubectl exec -it <pod-name> -- ls -lh /usr/local/bin/sygma-*"
echo ""

# ⭐ SYGMAPolicy    
if [ $HAS_POLICY_CREATOR -eq 1 ]; then
    echo -e "${BLUE}📌 SYGMAPolicy Configuration:${NC}"
    echo ""
    echo "Since SYGMAPolicy support is enabled, you may need:"
    echo ""
    echo "1. Set environment variables in DaemonSet:"
    echo "   env:"
    echo "     - name: KUBECONFIG"
    echo "       value: /root/.kube/config"
    echo "     - name: NODE_NAME"
    echo "       valueFrom:"
    echo "         fieldRef:"
    echo "           fieldPath: spec.nodeName"
    echo ""
    echo "2. Or use in-cluster config (recommended):"
    echo "   - serviceAccountName: sygma-hook"
    echo "   - Mount /var/run/secrets/kubernetes.io/serviceaccount"
    echo ""
    echo "3. Deploy Policy Agent to handle SYGMAPolicy CRs:"
    echo "   kubectl apply -f ../sygma-operator/deploy/sygma-policy-agent.yaml"
    echo ""
fi

echo "=========================================="