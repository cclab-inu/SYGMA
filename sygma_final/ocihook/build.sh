#!/bin/bash
# SYGMA Complete Build Script (Unified)
# OCI Hook + Installer Image Builder with Auto Redis Detection + Docker Hub Push
# Location: /home/cclab/sygma_final/ocihook/build.sh

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.2.0"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ⭐ Docker Hub configuration
DOCKER_USERNAME="acsac2026"
DOCKER_IMAGE="sygma-installer"
DOCKER_TAG="latest"
DOCKER_FULL_IMAGE="${DOCKER_USERNAME}/${DOCKER_IMAGE}:${DOCKER_TAG}"

# ⭐ Auto-detect Master IP for Redis
MASTER_IP=$(hostname -I | awk '{print $1}')
REDIS_ADDR="${MASTER_IP}:6379"

# Installation paths
HOOK_INSTALL_PATH="/usr/local/bin/sygma-hook"
TRACER_INSTALL_PATH="/usr/local/bin/sygma-tracer"
WRAPPER_INSTALL_PATH="/opt/sygma/wrapper"
NRI_PLUGIN_DIR="/opt/nri/plugins"
NRI_PLUGIN_PATH="${NRI_PLUGIN_DIR}/00-sygma"

# Build directories
HOOK_DIR="${SCRIPT_DIR}/ebpf/hook"
TRACER_DIR="${SCRIPT_DIR}/ebpf/tracer"
WRAPPER_DIR="${SCRIPT_DIR}/ebpf/wrapper"
NRI_DIR="${SCRIPT_DIR}/nri"

# Build output directory
BUILD_OUTPUT_DIR="${SCRIPT_DIR}/build"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "================================================"
    echo "  SYGMA Complete Build Script (Unified)"
    echo "  Version: ${VERSION}"
    echo "  Build Date: ${BUILD_DATE}"
    echo "================================================"
    echo -e "${NC}"
    echo -e "${GREEN}📍 Auto-detected Master IP: ${MASTER_IP}${NC}"
    echo -e "${GREEN}📍 Redis Address: ${REDIS_ADDR}${NC}"
    echo -e "${BLUE}🐳 Docker Hub: ${DOCKER_FULL_IMAGE}${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check Go
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    else
        log_success "Go: $(go version)"
    fi
    
    # Check gcc
    if ! command -v gcc &> /dev/null; then
        missing_tools+=("gcc")
    else
        log_success "GCC: $(gcc --version | head -n1)"
    fi
    
    # Check docker (for installer image)
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found (required for installer image build)"
    else
        log_success "Docker: $(docker --version)"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install missing tools:"
        echo "  sudo apt-get install -y golang-go gcc"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Check SYGMAPolicy support
check_sygmapolicy_support() {
    log_info "Checking SYGMAPolicy support..."
    
    if [ -f "${HOOK_DIR}/policy_creator.go" ]; then
        log_success "policy_creator.go found - SYGMAPolicy support enabled"
        
        cd "${HOOK_DIR}/../.."
        if grep -q "k8s.io/client-go" go.mod; then
            log_success "K8s client dependencies found in go.mod"
        else
            log_warn "K8s client dependencies missing in go.mod"
            log_info "Adding K8s client dependencies..."
            
            go get k8s.io/client-go@v0.28.0 2>&1 | grep -v "go: downloading" || true
            go get k8s.io/apimachinery@v0.28.0 2>&1 | grep -v "go: downloading" || true
            go mod tidy
            
            log_success "K8s client dependencies added"
        fi
        
        cd "${HOOK_DIR}"
        return 0
    else
        log_warn "policy_creator.go not found - SYGMAPolicy support disabled"
        log_info "Hook will use direct eBPF update only (fallback mode)"
        return 1
    fi
}

# Create build directory
prepare_build_dir() {
    log_info "Preparing build directory..."
    
    rm -rf "${BUILD_OUTPUT_DIR}"
    mkdir -p "${BUILD_OUTPUT_DIR}"
    
    log_success "Build directory ready: ${BUILD_OUTPUT_DIR}"
}

# ⭐ Build OCI Hook (with Redis address embedded)
build_hook() {
    log_info "Building OCI Hook..."
    log_info "  Embedding Redis address: ${REDIS_ADDR}"
    
    if [ ! -f "${HOOK_DIR}/main.go" ]; then
        log_error "OCI Hook source not found: ${HOOK_DIR}/main.go"
        exit 1
    fi
    
    cd "${HOOK_DIR}"
    
    # ⭐ Build flags with embedded Redis address
    local build_flags="-s -w"
    build_flags="${build_flags} -X main.Version=${VERSION}"
    build_flags="${build_flags} -X main.BuildDate=${BUILD_DATE}"
    build_flags="${build_flags} -X main.DefaultRedisAddr=${REDIS_ADDR}"  # ⭐ Redis  
    
    if [ -f "policy_creator.go" ]; then
        log_info "  Including SYGMAPolicy support"
        build_flags="${build_flags} -X main.SYGMAPolicyEnabled=true"
    else
        log_warn "  SYGMAPolicy support disabled (fallback mode only)"
        build_flags="${build_flags} -X main.SYGMAPolicyEnabled=false"
    fi
    
    # Build
    if go build -ldflags "${build_flags}" -o "${BUILD_OUTPUT_DIR}/sygma-hook" . ; then
        log_success "OCI Hook built: ${BUILD_OUTPUT_DIR}/sygma-hook"
        
        # Verify embedded Redis address
        if strings "${BUILD_OUTPUT_DIR}/sygma-hook" | grep -q "${REDIS_ADDR}"; then
            log_success "  ✅ Redis address embedded: ${REDIS_ADDR}"
        else
            log_warn "  ⚠️  Redis address not found in binary"
        fi
        
        # Verify SYGMAPolicy support
        if [ -f "policy_creator.go" ]; then
            if strings "${BUILD_OUTPUT_DIR}/sygma-hook" | grep -q "SYGMAPolicy"; then
                log_success "  ✅ SYGMAPolicy support verified"
            else
                log_warn "  ⚠️  SYGMAPolicy strings not found"
            fi
        fi
        
        ls -lh "${BUILD_OUTPUT_DIR}/sygma-hook"
    else
        log_error "OCI Hook build failed"
        exit 1
    fi
    cd "${SCRIPT_DIR}"
}

# Build Tracer
build_tracer() {
    log_info "Building SYGMA Tracer..."
    
    if [ ! -f "${TRACER_DIR}/main.go" ]; then
        log_error "Tracer source not found: ${TRACER_DIR}/main.go"
        exit 1
    fi
    
    cd "${TRACER_DIR}"
    
    go build \
        -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
        -o "${BUILD_OUTPUT_DIR}/sygma-tracer" \
        main.go
    
    log_success "SYGMA Tracer built: ${BUILD_OUTPUT_DIR}/sygma-tracer"
}

# Build Wrapper
build_wrapper() {
    log_info "Building SYGMA Wrapper..."
    
    if [ ! -f "${WRAPPER_DIR}/wrapper.c" ]; then
        log_error "Wrapper source not found: ${WRAPPER_DIR}/wrapper.c"
        exit 1
    fi
    
    cd "${WRAPPER_DIR}"
    
    gcc -static -O2 -o "${BUILD_OUTPUT_DIR}/sygma-wrapper" wrapper.c
    
    if file "${BUILD_OUTPUT_DIR}/sygma-wrapper" | grep -q "statically linked"; then
        log_success "SYGMA Wrapper built (static): ${BUILD_OUTPUT_DIR}/sygma-wrapper"
    else
        log_warn "SYGMA Wrapper may not be statically linked"
        file "${BUILD_OUTPUT_DIR}/sygma-wrapper"
    fi
    cd "${SCRIPT_DIR}"
}

# Build NRI Plugin
build_nri() {
    log_info "Building NRI Plugin..."
    
    if [ ! -f "${NRI_DIR}/main.go" ]; then
        log_warn "NRI Plugin source not found: ${NRI_DIR}/main.go"
        log_warn "Skipping NRI Plugin build"
        return 0
    fi
    
    cd "${NRI_DIR}"
    
    if go build \
        -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
        -o "${BUILD_OUTPUT_DIR}/00-sygma" \
        main.go; then
        log_success "NRI Plugin built: ${BUILD_OUTPUT_DIR}/00-sygma"
    else
        log_warn "NRI Plugin build failed, continuing without it"
    fi
    cd "${SCRIPT_DIR}"
}

# ⭐ Build installer Docker image
build_installer_image() {
    log_info "Building Installer Docker Image..."
    
    cd "${SCRIPT_DIR}"
    
    # Check binaries
    log_info "Checking available binaries..."
    
    if [ ! -f "${BUILD_OUTPUT_DIR}/sygma-hook" ]; then
        log_error "sygma-hook not found in ${BUILD_OUTPUT_DIR}"
        exit 1
    fi
    
    if [ ! -f "${BUILD_OUTPUT_DIR}/sygma-tracer" ]; then
        log_error "sygma-tracer not found in ${BUILD_OUTPUT_DIR}"
        exit 1
    fi
    
    if [ ! -f "${BUILD_OUTPUT_DIR}/sygma-wrapper" ]; then
        log_error "sygma-wrapper not found in ${BUILD_OUTPUT_DIR}"
        exit 1
    fi
    
    if [ ! -f "${BUILD_OUTPUT_DIR}/00-sygma" ]; then
        log_error "00-sygma not found in ${BUILD_OUTPUT_DIR}"
        exit 1
    fi
    
    log_success "All binaries found"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        exit 1
    fi
    
    # ⭐  Dockerfile  ,  
    if [ ! -f "Dockerfile.installer" ]; then
        log_warn "Dockerfile.installer not found - creating default..."
        cat > Dockerfile.installer <<'EOF'
FROM alpine:3.18

RUN apk add --no-cache bash

COPY build/sygma-hook /binaries/sygma-hook
COPY build/sygma-tracer /binaries/sygma-tracer
COPY build/sygma-wrapper /binaries/sygma-wrapper
COPY build/00-sygma /binaries/00-sygma

RUN chmod +x /binaries/*

CMD ["ls", "-lh", "/binaries/"]
EOF
        log_success "Default Dockerfile.installer created"
    else
        log_success "Using existing Dockerfile.installer"
    fi
    
    log_info "Building Docker image..."
    if docker build -t "${DOCKER_FULL_IMAGE}" -f "${SCRIPT_DIR}/Dockerfile.installer" "${SCRIPT_DIR}" ; then
        log_success "Docker image built: ${DOCKER_FULL_IMAGE}"
        
        docker tag "${DOCKER_FULL_IMAGE}" "sygma-installer:latest"
        log_success "Tagged as: sygma-installer:latest"
        
        docker images "${DOCKER_FULL_IMAGE}" --format "  Size: {{.Size}}, Created: {{.CreatedSince}}"
        
        log_info "Verifying binaries in image..."
        docker run --rm "${DOCKER_FULL_IMAGE}" ls -lh /binaries/
        
        log_info "Importing to containerd..."
        if docker save "${DOCKER_FULL_IMAGE}" | sudo ctr -n k8s.io images import - ; then
            log_success "Image imported to containerd"
            sudo ctr -n k8s.io images ls | grep sygma-installer
        else
            log_error "Failed to import to containerd"
            exit 1
        fi
    else
        log_error "Docker build failed"
        exit 1
    fi
}

# ⭐ Push image to Docker Hub
push_image() {
    log_info "Pushing image to Docker Hub..."
    
    # Check if image exists
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${DOCKER_FULL_IMAGE}$"; then
        log_error "Image not found: ${DOCKER_FULL_IMAGE}"
        log_info "Build the image first: ./build.sh build-image"
        exit 1
    fi
    
    # Check if logged in
    log_info "Checking Docker Hub login..."
    if ! docker info 2>/dev/null | grep -q "Username: ${DOCKER_USERNAME}"; then
        log_warn "Not logged in to Docker Hub"
        log_info "Attempting to login as ${DOCKER_USERNAME}..."
        
        if ! docker login -u "${DOCKER_USERNAME}"; then
            log_error "Docker login failed"
            log_info "Login manually: docker login -u ${DOCKER_USERNAME}"
            exit 1
        fi
    else
        log_success "Already logged in as ${DOCKER_USERNAME}"
    fi
    
    # Push image
    log_info "Pushing ${DOCKER_FULL_IMAGE}..."
    if docker push "${DOCKER_FULL_IMAGE}"; then
        log_success "Image pushed successfully!"
        echo ""
        echo -e "${GREEN}🐳 Image available at:${NC}"
        echo -e "${BLUE}   docker pull ${DOCKER_FULL_IMAGE}${NC}"
        echo ""
        
        # Show manifest
        log_info "Image manifest:"
        docker manifest inspect "${DOCKER_FULL_IMAGE}" 2>/dev/null | grep -E "(architecture|os|size)" || true
    else
        log_error "Push failed"
        exit 1
    fi
}

install_binaries() {
    log_info "Installing binaries..."
    
    # Install OCI Hook
    log_info "Installing OCI Hook to ${HOOK_INSTALL_PATH}..."
    sudo install -m 755 "${BUILD_OUTPUT_DIR}/sygma-hook" "${HOOK_INSTALL_PATH}"
    log_success "OCI Hook installed"
    
    # Install Tracer
    log_info "Installing SYGMA Tracer to ${TRACER_INSTALL_PATH}..."
    sudo install -m 755 "${BUILD_OUTPUT_DIR}/sygma-tracer" "${TRACER_INSTALL_PATH}"
    log_success "SYGMA Tracer installed"
    
    # Install Wrapper
    log_info "Installing SYGMA Wrapper to ${WRAPPER_INSTALL_PATH}..."
    sudo mkdir -p "$(dirname ${WRAPPER_INSTALL_PATH})"
    sudo install -m 755 "${BUILD_OUTPUT_DIR}/sygma-wrapper" "${WRAPPER_INSTALL_PATH}"
    log_success "SYGMA Wrapper installed"
    
    # Install NRI Plugin (if built)
    if [ -f "${BUILD_OUTPUT_DIR}/00-sygma" ]; then
        log_info "Installing NRI Plugin to ${NRI_PLUGIN_PATH}..."
        sudo mkdir -p "${NRI_PLUGIN_DIR}"
        sudo install -m 755 "${BUILD_OUTPUT_DIR}/00-sygma" "${NRI_PLUGIN_PATH}"
        log_success "NRI Plugin installed"
        
        # ⭐⭐⭐ Containerd 재시작 (NRI 플러그인 로딩) ⭐⭐⭐
        if sudo systemctl is-active --quiet containerd 2>/dev/null; then
            log_info "🔄 Restarting containerd to load NRI plugin..."
            
            # Containerd 재시작 전 확인
            read -p "$(echo -e ${YELLOW}WARNING:${NC} This will restart containerd and may temporarily disrupt running containers. Continue? [y/N]: )" -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo systemctl restart containerd
                
                # Containerd 시작 대기
                log_info "Waiting for containerd to be ready..."
                sleep 3
                
                if sudo systemctl is-active --quiet containerd; then
                    log_success "✅ Containerd restarted successfully"
                    
                    # NRI 소켓 확인
                    if [ -S /var/run/nri/nri.sock ]; then
                        log_success "✅ NRI socket available: /var/run/nri/nri.sock"
                    else
                        log_warn "⚠️ NRI socket not found (may need manual containerd restart)"
                    fi
                    
                    # NRI 플러그인 로그 확인
                    log_info "Checking NRI plugin logs..."
                    sleep 2
                    sudo journalctl -u containerd --since "30 seconds ago" | grep -i "nri\|sygma" | tail -n 10 || log_warn "No NRI logs found"
                else
                    log_error "❌ Containerd failed to restart"
                    sudo systemctl status containerd --no-pager
                    exit 1
                fi
            else
                log_warn "Containerd restart skipped by user"
                log_info "To manually restart: sudo systemctl restart containerd"
            fi
        else
            log_warn "Containerd is not running"
            log_info "Start with: sudo systemctl start containerd"
        fi
    else
        log_warn "NRI Plugin not built, skipping installation"
    fi
    
    log_success "All binaries installed successfully"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    
    rm -rf "${BUILD_OUTPUT_DIR}"
    
    # Clean intermediate files in source dirs
    rm -f "${HOOK_DIR}/sygma-hook"
    rm -f "${TRACER_DIR}/sygma-tracer"
    rm -f "${WRAPPER_DIR}/sygma-wrapper"
    rm -f "${NRI_DIR}/00-sygma"
    
    log_success "Build artifacts cleaned"
}

uninstall() {
    log_info "Uninstalling binaries..."
    
    # Remove OCI Hook
    if [ -f "${HOOK_INSTALL_PATH}" ]; then
        sudo rm -f "${HOOK_INSTALL_PATH}"
        log_success "OCI Hook removed"
    fi
    
    # Remove Tracer
    if [ -f "${TRACER_INSTALL_PATH}" ]; then
        sudo rm -f "${TRACER_INSTALL_PATH}"
        log_success "SYGMA Tracer removed"
    fi
    
    # Remove Wrapper
    if [ -f "${WRAPPER_INSTALL_PATH}" ]; then
        sudo rm -f "${WRAPPER_INSTALL_PATH}"
        log_success "SYGMA Wrapper removed"
    fi
    
    # Remove NRI Plugin
    if [ -f "${NRI_PLUGIN_PATH}" ]; then
        sudo rm -f "${NRI_PLUGIN_PATH}"
        log_success "NRI Plugin removed"
        
        # Containerd 재시작 권장
        log_warn "⚠️ NRI Plugin removed"
        log_info "Restart containerd to unload the plugin:"
        log_info "  sudo systemctl restart containerd"
    fi
    
    # Clean empty directories
    sudo rmdir --ignore-fail-on-non-empty "$(dirname ${WRAPPER_INSTALL_PATH})" 2>/dev/null || true
    
    log_success "Uninstallation complete"
}

# Show installation status
status() {
    log_info "Installation status:"
    echo ""
    
    # Check Hook
    if [ -f "${HOOK_INSTALL_PATH}" ]; then
        echo -e "${GREEN}✓${NC} OCI Hook: ${HOOK_INSTALL_PATH}"
        ls -lh "${HOOK_INSTALL_PATH}"
    else
        echo -e "${RED}✗${NC} OCI Hook: Not installed"
    fi
    
    echo ""
    
    # Check Tracer
    if [ -f "${TRACER_INSTALL_PATH}" ]; then
        echo -e "${GREEN}✓${NC} SYGMA Tracer: ${TRACER_INSTALL_PATH}"
        ls -lh "${TRACER_INSTALL_PATH}"
    else
        echo -e "${RED}✗${NC} SYGMA Tracer: Not installed"
    fi
    
    echo ""
    
    # Check Wrapper
    if [ -f "${WRAPPER_INSTALL_PATH}" ]; then
        echo -e "${GREEN}✓${NC} SYGMA Wrapper: ${WRAPPER_INSTALL_PATH}"
        ls -lh "${WRAPPER_INSTALL_PATH}"
        file "${WRAPPER_INSTALL_PATH}"
    else
        echo -e "${RED}✗${NC} SYGMA Wrapper: Not installed"
    fi
    
    echo ""
    
    # Check NRI Plugin
    if [ -f "${NRI_PLUGIN_PATH}" ]; then
        echo -e "${GREEN}✓${NC} NRI Plugin: ${NRI_PLUGIN_PATH}"
        ls -lh "${NRI_PLUGIN_PATH}"
    else
        echo -e "${RED}✗${NC} NRI Plugin: Not installed"
    fi
    
    echo ""
    
    # Check Containerd
    if sudo systemctl is-active --quiet containerd 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Containerd: Running"
        
        # Check NRI socket
        if [ -S /var/run/nri/nri.sock ]; then
            echo -e "${GREEN}✓${NC} NRI Socket: Available (/var/run/nri/nri.sock)"
        else
            echo -e "${YELLOW}○${NC} NRI Socket: Not found (NRI may not be enabled)"
        fi
        
        # Check NRI plugin process
        if pgrep -f "00-sygma" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} NRI Plugin Process: Running"
            pgrep -fa "00-sygma"
        else
            echo -e "${YELLOW}○${NC} NRI Plugin Process: Not running"
        fi
    else
        echo -e "${RED}✗${NC} Containerd: Not running"
    fi
    
    echo ""
}

# Help
show_help() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
    build           Build all binaries (default)
    build-image     Build binaries + installer Docker image
    push            Push Docker image to Docker Hub
    build-push      Build image and push to Docker Hub
    rebuild         Clean and rebuild all
    install         Build and install binaries
    install-all     Build, install binaries, and build Docker image
    reinstall       Clean, rebuild, and reinstall
    clean           Clean build artifacts
    uninstall       Remove installed binaries
    status          Show installation status
    help            Show this help

Components:
    - OCI Hook:     ${HOOK_INSTALL_PATH}
    - Tracer:       ${TRACER_INSTALL_PATH}
    - Wrapper:      ${WRAPPER_INSTALL_PATH}
    - NRI Plugin:   ${NRI_PLUGIN_PATH}
    - Docker Image: ${DOCKER_FULL_IMAGE}

⭐ Auto-detected Configuration:
    - Master IP:    ${MASTER_IP}
    - Redis:        ${REDIS_ADDR} (embedded in binary)
    - Docker Hub:   ${DOCKER_USERNAME}

Features:
    ✅ Redis address auto-detection (build-time embedding)
    ✅ SYGMAPolicy support (if policy_creator.go exists)
    ✅ Unified build script (binaries + Docker image)
    ✅ Docker Hub push support

Examples:
    # Build binaries only
    ./build.sh build

    # Build binaries + Docker image
    ./build.sh build-image

    # Build and push to Docker Hub
    ./build.sh build-push

    # Push existing image
    ./build.sh push

    # Install everything locally
    ./build.sh install-all

    # Check status
    ./build.sh status

Docker Hub Usage:
    # On deployment nodes, pull the image:
    docker pull ${DOCKER_FULL_IMAGE}
    
    # Or in Kubernetes manifests:
    image: ${DOCKER_FULL_IMAGE}

Notes:
    - First push requires Docker Hub login
    - Redis address is auto-detected and embedded at build time
    - Image is automatically imported to containerd
    - Use 'build-push' for complete build-and-publish workflow

EOF
}

# Main
main() {
    print_banner
    
    COMMAND="${1:-build}"
    
    case "${COMMAND}" in
        build)
            check_prerequisites
            check_sygmapolicy_support
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            log_success "Build complete!"
            echo ""
            ls -lh "${BUILD_OUTPUT_DIR}"
            echo ""
            log_info "Embedded Redis: ${REDIS_ADDR}"
            log_info "Next: ./build.sh build-image"
            ;;
        build-image)
            check_prerequisites
            check_sygmapolicy_support
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            build_installer_image
            log_success "Build + Image complete!"
            echo ""
            log_info "Push to Docker Hub: ./build.sh push"
            log_info "Or deploy locally: kubectl apply -f ../manifest/policy-agent.yaml"
            ;;
        push)
            push_image
            ;;
        build-push)
            check_prerequisites
            check_sygmapolicy_support
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            build_installer_image
            push_image
            log_success "Build + Push complete!"
            echo ""
            log_info "Image available: docker pull ${DOCKER_FULL_IMAGE}"
            ;;
        rebuild)
            check_prerequisites
            check_sygmapolicy_support
            clean
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            log_success "Rebuild complete!"
            echo ""
            ls -lh "${BUILD_OUTPUT_DIR}"
            ;;
        install)
            check_prerequisites
            check_sygmapolicy_support
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            install_binaries
            log_success "Installation complete!"
            echo ""
            status
            ;;
        install-all)
            check_prerequisites
            check_sygmapolicy_support
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            install_binaries
            build_installer_image
            log_success "Full installation complete!"
            echo ""
            status
            ;;
        reinstall)
            check_prerequisites
            check_sygmapolicy_support
            clean
            prepare_build_dir
            build_hook
            build_tracer
            build_wrapper
            build_nri
            install_binaries
            log_success "Reinstallation complete!"
            echo ""
            status
            ;;
        clean)
            clean
            ;;
        uninstall)
            uninstall
            ;;
        status)
            status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${COMMAND}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"