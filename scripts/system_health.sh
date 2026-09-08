#!/bin/bash
# Pre-audited maintenance script for server-agents-gateway
echo "--- Server Diagnostics ---"
date
uptime
echo "--- Docker Health ---"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not running"
echo "--- Storage Health ---"
df -h /
echo "--- Memory Health ---"
free -m
