#!/bin/bash
# SYGMA Migration - Cleanup old Phalanx files
# Location: /workspace/sygma-legacy/SYGMA/ocihook/cleanup-phalanx.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

print_banner() {
    echo -e "${BLUE}"
    echo "================================================"
    echo "  Phalanx → SYGMA Migration Cleanup Script"
    echo "================================================"
    echo -e "${NC}"
}

#   
PHALANX_FILES=(
    "/usr/local/bin/phalanx-hook"
    "/usr/local/bin/phalanx-tracer-static"
    "/usr/local/bin/phalanx-tracer-dynamic"
    "/usr/local/lib/phalanx/libseccomp_inject.so"
    "/opt/nri/plugins/00-phalanx"
)

PHALANX_DIRS=(
    "/usr/local/lib/phalanx"
)

PHALANX_SERVICES=(
    "phalanx-nri"
)

PHALANX_LOGS=(
    "/var/log/phalanx-hook.log"
    "/var/log/phalanx-nri.log"
)

check_running_containers() {
    log_info "Checking for running containers with Phalanx annotations..."
    
    if command -v kubectl &> /dev/null; then
        local phalanx_pods=$(kubectl get pods -A -o json 2>/dev/null | \
            jq -r '.items[] | select(.metadata.annotations | 
            to_entries[] | select(.key | startswith("phalanx.io"))) | 
            "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
        
        if [ -n "$phalanx_pods" ]; then
            log_warn "Found pods with phalanx.io annotations:"
            echo "$phalanx_pods"
            echo ""
            log_warn "These pods should be redeployed with sygma.io/mode annotation"
            echo ""
            read -p "Continue with cleanup? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Cleanup cancelled"
                exit 0
            fi
        else
            log_success "No pods with phalanx.io annotations found"
        fi
    else
        log_warn "kubectl not found, skipping pod check"
    fi
}

stop_services() {
    log_info "Stopping Phalanx services..."
    
    for service in "${PHALANX_SERVICES[@]}"; do
        if sudo systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Stopping service: $service"
            sudo systemctl stop "$service"
            log_success "Service stopped: $service"
        fi
        
        if sudo systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "Disabling service: $service"
            sudo systemctl disable "$service"
            log_success "Service disabled: $service"
        fi
        
        # Remove service file
        if [ -f "/etc/systemd/system/${service}.service" ]; then
            sudo rm -f "/etc/systemd/system/${service}.service"
            log_success "Service file removed: ${service}.service"
        fi
    done
    
    # Reload systemd
    if [ ${#PHALANX_SERVICES[@]} -gt 0 ]; then
        sudo systemctl daemon-reload
        log_success "Systemd reloaded"
    fi
}

remove_binaries() {
    log_info "Removing Phalanx binaries..."
    
    for file in "${PHALANX_FILES[@]}"; do
        if [ -f "$file" ]; then
            sudo rm -f "$file"
            log_success "Removed: $file"
        else
            log_info "Not found: $file"
        fi
    done
}

remove_directories() {
    log_info "Removing Phalanx directories..."
    
    for dir in "${PHALANX_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            sudo rm -rf "$dir"
            log_success "Removed: $dir"
        else
            log_info "Not found: $dir"
        fi
    done
}

backup_logs() {
    log_info "Backing up Phalanx logs..."
    
    BACKUP_DIR="/var/log/phalanx-backup-$(date +%Y%m%d_%H%M%S)"
    
    local has_logs=false
    for log_file in "${PHALANX_LOGS[@]}"; do
        if [ -f "$log_file" ]; then
            has_logs=true
            break
        fi
    done
    
    if [ "$has_logs" = true ]; then
        sudo mkdir -p "$BACKUP_DIR"
        
        for log_file in "${PHALANX_LOGS[@]}"; do
            if [ -f "$log_file" ]; then
                sudo cp "$log_file" "$BACKUP_DIR/"
                log_success "Backed up: $log_file → $BACKUP_DIR/"
            fi
        done
        
        log_success "Logs backed up to: $BACKUP_DIR"
    else
        log_info "No logs found to backup"
    fi
}

remove_logs() {
    log_info "Removing Phalanx logs..."
    
    for log_file in "${PHALANX_LOGS[@]}"; do
        if [ -f "$log_file" ]; then
            sudo rm -f "$log_file"
            log_success "Removed: $log_file"
        fi
    done
}

check_ebpf_maps() {
    log_info "Checking eBPF maps..."
    
    if [ -d "/sys/fs/bpf/sygma-legacy" ]; then
        log_warn "Found old eBPF directory: /sys/fs/bpf/sygma-legacy"
        log_info "This should be replaced with: /sys/fs/bpf/sygma"
        log_warn "Please ensure your eBPF programs are updated and reloaded"
    else
        log_success "No old eBPF directory found"
    fi
}

show_status() {
    log_info "Cleanup status:"
    echo ""
    
    echo "Binaries:"
    for file in "${PHALANX_FILES[@]}"; do
        if [ -f "$file" ]; then
            echo -e "  ${RED}✗${NC} Still exists: $file"
        else
            echo -e "  ${GREEN}✓${NC} Removed: $file"
        fi
    done
    
    echo ""
    echo "Directories:"
    for dir in "${PHALANX_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo -e "  ${RED}✗${NC} Still exists: $dir"
        else
            echo -e "  ${GREEN}✓${NC} Removed: $dir"
        fi
    done
    
    echo ""
    echo "Services:"
    for service in "${PHALANX_SERVICES[@]}"; do
        if sudo systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  ${RED}✗${NC} Still running: $service"
        elif sudo systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo -e "  ${YELLOW}○${NC} Stopped but enabled: $service"
        else
            echo -e "  ${GREEN}✓${NC} Removed: $service"
        fi
    done
    
    echo ""
}

show_migration_guide() {
    cat << 'EOF'

================================================
  Migration Guide: Phalanx → SYGMA
================================================

1. Update Pod Annotations:
   
   Before:
   apiVersion: v1
   kind: Pod
   metadata:
     annotations:
       phalanx.io/enforce: "true"
       phalanx.io/collect: "true"
       phalanx.io/binary: "myapp"
   
   After:
   apiVersion: v1
   kind: Pod
   metadata:
     annotations:
       sygma.io/mode: "enforcement"  # or "collection"

2. Redeploy Pods:
   
   # Delete old pods
   kubectl delete pod <pod-name> -n <namespace>
   
   # Or rolling restart deployment
   kubectl rollout restart deployment/<deployment-name> -n <namespace>

3. Update eBPF Programs:
   
   # Stop old eBPF programs
   sudo killall -9 phalanx-ebpf || true
   
   # Load new SYGMA eBPF programs
   # (Your specific eBPF loading commands here)

4. Verify Installation:
   
   # Check SYGMA components
   cd /workspace/sygma-legacy/SYGMA/ocihook
   ./build.sh status
   
   # Check NRI plugin
   sudo systemctl status sygma-nri

5. Test with Sample Pod:
   
   kubectl apply -f - <<EOT
   apiVersion: v1
   kind: Pod
   metadata:
     name: test-sygma
     annotations:
       sygma.io/mode: "collection"
   spec:
     containers:
     - name: test
       image: nginx:latest
   EOT
   
   # Check logs
   kubectl logs test-sygma
   tail -f /var/log/sygma-hook.log

================================================

EOF
}

main() {
    print_banner
    
    COMMAND="${1:-full}"
    
    case "${COMMAND}" in
        full)
            log_warn "This will remove all Phalanx components"
            echo ""
            read -p "Continue? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Cleanup cancelled"
                exit 0
            fi
            
            check_running_containers
            backup_logs
            stop_services
            remove_binaries
            remove_directories
            remove_logs
            check_ebpf_maps
            
            echo ""
            log_success "Phalanx cleanup complete!"
            echo ""
            show_status
            show_migration_guide
            ;;
        
        check)
            check_running_containers
            show_status
            ;;
        
        services)
            stop_services
            ;;
        
        binaries)
            remove_binaries
            ;;
        
        logs)
            backup_logs
            remove_logs
            ;;
        
        status)
            show_status
            ;;
        
        help|--help|-h)
            cat << EOF
Usage: $0 [COMMAND]

Commands:
    full        Complete cleanup (default)
    check       Check for Phalanx components
    services    Stop and remove services only
    binaries    Remove binaries only
    logs        Backup and remove logs
    status      Show cleanup status
    help        Show this help

Examples:
    # Full cleanup (interactive)
    ./cleanup-phalanx.sh full
    
    # Just check what needs cleanup
    ./cleanup-phalanx.sh check
    
    # Stop services only
    ./cleanup-phalanx.sh services
    
    # Show status
    ./cleanup-phalanx.sh status

EOF
            ;;
        
        *)
            log_error "Unknown command: ${COMMAND}"
            echo ""
            echo "Use: $0 help"
            exit 1
            ;;
    esac
}

main "$@"
