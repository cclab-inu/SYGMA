#!/bin/bash
# NRI Plugin Debug Script

echo "=========================================="
echo "NRI Plugin Status Check"
echo "=========================================="

# 1. NRI Plugin  
echo ""
echo "1. NRI Plugin Binary:"
if [ -f /opt/nri/plugins/00-sygma ]; then
    ls -lh /opt/nri/plugins/00-sygma
    echo "✅ NRI Plugin exists"
else
    echo "❌ NRI Plugin NOT found"
    exit 1
fi

# 2. Containerd NRI  
echo ""
echo "2. Containerd NRI Configuration:"
if grep -q "disable = false" /etc/containerd/config.toml; then
    echo "✅ NRI enabled in containerd"
    sudo cat /etc/containerd/config.toml | grep -A 10 nri
else
    echo "❌ NRI disabled or not configured"
fi

# 3. NRI Socket 
echo ""
echo "3. NRI Socket:"
if [ -S /var/run/nri/nri.sock ]; then
    ls -lh /var/run/nri/nri.sock
    echo "✅ NRI socket exists"
else
    echo "❌ NRI socket NOT found"
fi

# 4. NRI Plugin  
echo ""
echo "4. NRI Plugin Process:"
ps aux | grep -E "00-sygma|sygma-nri" | grep -v grep
if [ $? -eq 0 ]; then
    echo "✅ NRI Plugin process running"
else
    echo "❌ NRI Plugin process NOT running"
fi

# 5. NRI  
echo ""
echo "5. NRI Logs:"
if [ -f /var/log/sygma-nri.log ]; then
    echo "Last 10 lines:"
    sudo tail -10 /var/log/sygma-nri.log
else
    echo "❌ NRI log file NOT found"
fi

# 6. Containerd  NRI 
echo ""
echo "6. Containerd Logs (NRI related):"
sudo journalctl -u containerd -n 50 --no-pager | grep -i nri | tail -10

echo ""
echo "=========================================="
