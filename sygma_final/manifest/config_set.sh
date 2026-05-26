#!/bin/bash
# deploy-redis-hostnetwork.sh

set -e

# ⭐   IP  
MASTER_IP=$(hostname -I | awk '{print $1}')
echo "✅ Master IP: $MASTER_IP"

# ConfigMap 
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sygma-config
  namespace: default
data:
  redis-addr: "${MASTER_IP}:6379"
EOF

