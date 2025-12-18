#!/bin/bash
#
# Simple Concurrent Connection Test
# Keeps connections alive to measure TRUE concurrency
#

SERVER_HOST="127.0.0.1"
SERVER_PORT="1080"
SOCKS_USER="admin"
SOCKS_PASS="password123"

echo "=============================================="
echo "  CONCURRENT CONNECTION TEST"
echo "=============================================="
echo ""
echo "Goal: Verify server handles ≥500 concurrent"
echo "      connections simultaneously"
echo ""

# Clean slate
pkill -f "curl.*--socks5" 2>/dev/null
sleep 1

TARGET=500

echo "Starting $TARGET curl processes..."
echo "Each will connect through SOCKS5 and wait 30s"
echo ""

# Launch all connections
for i in $(seq 1 $TARGET); do
    # Use httpbin delay endpoint to keep connection alive
    curl --socks5 $SERVER_HOST:$SERVER_PORT \
         --proxy-user $SOCKS_USER:$SOCKS_PASS \
         --max-time 35 \
         "http://httpbin.org/delay/30" \
         > /dev/null 2>&1 &
    
    # Show progress every 50
    if [ $((i % 50)) -eq 0 ]; then
        echo "  Launched $i connections..."
    fi
done

echo ""
echo "All $TARGET connection attempts launched!"
echo ""
echo "Waiting 5 seconds for connections to establish..."
sleep 5
echo ""

# Count active processes
ACTIVE_CURL=$(pgrep -f "curl.*--socks5" | wc -l)

echo "=============================================="
echo "  MEASUREMENT (while connections are alive)"
echo "=============================================="
echo ""
echo "Active curl processes: $ACTIVE_CURL"
echo ""

# Get server stats
echo "Server statistics:"
./bin/client -c STATS

echo ""
echo "=============================================="
echo "  RESULT"
echo "=============================================="

# Extract max concurrent from stats
MAX_CONCURRENT=$(./bin/client -c STATS 2>/dev/null | grep "max_concurrent=" | cut -d= -f2 | tr -d ' ')

echo ""
if [ "$MAX_CONCURRENT" -ge 500 ]; then
    echo "✓ SUCCESS: Server handled $MAX_CONCURRENT concurrent connections"
    echo "✓ Requirement: ≥500 concurrent"
    echo "✓ Status: REQUIREMENT MET!"
else
    echo "✗ Server handled only $MAX_CONCURRENT concurrent connections"
    echo "✗ Requirement: ≥500 concurrent"
    echo "✗ Shortfall: $((500 - MAX_CONCURRENT)) connections"
    echo "✗ Status: REQUIREMENT NOT MET"
fi

echo ""
echo "Waiting for all connections to complete..."
wait

echo ""
echo "Test complete!"
echo ""
