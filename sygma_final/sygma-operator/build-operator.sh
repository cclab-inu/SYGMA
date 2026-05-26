#!/bin/bash
# SYGMA Operator Build & Push Script
# Location: sygma_final/sygma-operator/build-operator.sh

set -e

# Configuration
DOCKER_USERNAME="acsac2026"
DOCKER_IMAGE="sygma-operator"
DOCKER_TAG="latest"
DOCKER_FULL_IMAGE="${DOCKER_USERNAME}/${DOCKER_IMAGE}:${DOCKER_TAG}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}=========================================="
    echo "SYGMA Operator Build & Push"
    echo "Image: ${DOCKER_FULL_IMAGE}"
    echo -e "==========================================${NC}"
}

check_env() {
    if [ ! -f "cmd/main.go" ]; then
        log_error "cmd/main.go not found!"
        log_info "Run from sygma_final/sygma-operator/ directory"
        exit 1
    fi
    
    if ! grep -q "flag.StringVar(&runMode" cmd/main.go 2>/dev/null; then
        log_warn "cmd/main.go missing --mode flag"
    fi
    
    if [ ! -f "Dockerfile" ]; then
        log_error "Dockerfile not found!"
        exit 1
    fi
}

build_binary() {
    log_info "Building operator binary..."
    make build > /dev/null 2>&1
    
    if [ ! -f "bin/manager" ]; then
        log_error "bin/manager not found after build"
        exit 1
    fi
    
    log_success "Binary built: bin/manager"
}

build_image() {
    log_info "Building Docker image..."
    
    if docker build -t "${DOCKER_FULL_IMAGE}" . > /dev/null 2>&1; then
        docker tag "${DOCKER_FULL_IMAGE}" "sygma-operator:v2"
        log_success "Image built: ${DOCKER_FULL_IMAGE}"
        
        # Import to containerd
        log_info "Importing to containerd..."
        if docker save "${DOCKER_FULL_IMAGE}" | sudo ctr -n k8s.io images import - > /dev/null 2>&1; then
            log_success "Imported to containerd"
        else
            log_warn "Containerd import failed (may already exist)"
        fi
    else
        log_error "Docker build failed"
        exit 1
    fi
}

push_image() {
    log_info "Pushing to Docker Hub..."
    
    # Check if image exists
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${DOCKER_FULL_IMAGE}$"; then
        log_error "Image not found: ${DOCKER_FULL_IMAGE}"
        log_info "Build first: ./build-operator.sh build"
        exit 1
    fi
    
    # Check login
    if ! docker info 2>/dev/null | grep -q "Username: ${DOCKER_USERNAME}"; then
        log_warn "Not logged in to Docker Hub"
        if ! docker login -u "${DOCKER_USERNAME}"; then
            log_error "Login failed"
            exit 1
        fi
    fi
    
    # Push
    if docker push "${DOCKER_FULL_IMAGE}" > /dev/null 2>&1; then
        log_success "Pushed to Docker Hub"
        echo -e "${GREEN}🐳 Image: ${DOCKER_FULL_IMAGE}${NC}"
    else
        log_error "Push failed"
        exit 1
    fi
}

show_help() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
    build       Build operator binary + Docker image (default)
    push        Push existing image to Docker Hub
    build-push  Build and push in one command
    clean       Clean build artifacts
    help        Show this help

Examples:
    ./build-operator.sh build
    ./build-operator.sh build-push
    ./build-operator.sh push

Docker Hub:
    Image: ${DOCKER_FULL_IMAGE}
    Pull:  docker pull ${DOCKER_FULL_IMAGE}

EOF
}

clean() {
    log_info "Cleaning build artifacts..."
    rm -rf bin/
    log_success "Cleaned"
}

main() {
    print_banner
    
    COMMAND="${1:-build}"
    
    case "${COMMAND}" in
        build)
            check_env
            build_binary
            build_image
            echo ""
            log_success "Build complete!"
            log_info "Push: ./build-operator.sh push"
            ;;
        push)
            push_image
            ;;
        build-push)
            check_env
            build_binary
            build_image
            push_image
            echo ""
            log_success "Build + Push complete!"
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${COMMAND}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"