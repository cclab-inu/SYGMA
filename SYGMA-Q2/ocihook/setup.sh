#!/bin/bash
# SYGMA Host Setup Script - Correct Version
# Wrapper    (symlink !)

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  SYGMA Host Setup - PATH Hijacking${NC}"
echo -e "${BLUE}  (Binary Copy Method)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1.  
echo -e "${BLUE}[1/3] Creating directories...${NC}"
sudo mkdir -p /opt/sygma/bin
echo -e "${GREEN}✅ Created: /opt/sygma/bin/${NC}"

# 2. Wrapper 
echo ""
echo -e "${BLUE}[2/3] Checking wrapper binary...${NC}"
if [ ! -f /opt/sygma/wrapper ]; then
    echo -e "${RED}❌ Error: /opt/sygma/wrapper not found!${NC}"
    echo -e "${YELLOW}   Please run './build.sh install' first${NC}"
    exit 1
fi

if [ ! -x /opt/sygma/wrapper ]; then
    echo -e "${YELLOW}⚠️  Wrapper is not executable, fixing...${NC}"
    sudo chmod +x /opt/sygma/wrapper
fi

echo -e "${GREEN}✅ Wrapper found: /opt/sygma/wrapper${NC}"
file /opt/sygma/wrapper

# 3. ⭐ Wrapper     (symlink !)
echo ""
echo -e "${BLUE}[3/3] Copying wrapper as different binaries...${NC}"

#  
BINARIES=(
    "nginx"
    "redis-server"
    "postgres"
    "mysqld"
    "memcached"
    "mongod"
    "apache2"
    "httpd"
)

for binary in "${BINARIES[@]}"; do
    target="/opt/sygma/bin/${binary}"
    
    #   
    if [ -f "$target" ]; then
        sudo rm "$target"
    fi
    
    # ⭐  (symlink !)
    sudo cp /opt/sygma/wrapper "$target"
    sudo chmod +x "$target"
    
    echo -e "${GREEN}  ✅ Copied: /opt/sygma/bin/${binary} (wrapper)${NC}"
done

# 4. 
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verification:${NC}"
echo -e "${BLUE}========================================${NC}"

echo ""
echo -e "${YELLOW}Directory structure:${NC}"
ls -lah /opt/sygma/

echo ""
echo -e "${YELLOW}Binaries in /opt/sygma/bin/:${NC}"
ls -lah /opt/sygma/bin/

echo ""
echo -e "${YELLOW}File types:${NC}"
for binary in "${BINARIES[@]}"; do
    if [ -f "/opt/sygma/bin/${binary}" ]; then
        file "/opt/sygma/bin/${binary}"
    fi
done | head -3

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✅ Setup complete!${NC}"
echo -e "${BLUE}========================================${NC}"

echo ""
echo -e "${YELLOW}Note:${NC}"
echo "  All files in /opt/sygma/bin/ are COPIES of wrapper,"
echo "  NOT symlinks. Each has a different name so argv[0]"
echo "  will be correct (e.g., 'nginx', 'redis-server')."

echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Rebuild: ./build.sh install"
echo "  2. Test: kubectl apply -f test-pod.yaml"

echo ""
