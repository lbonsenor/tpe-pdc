#!/bin/bash
#
# Stress Test for SOCKS5 Proxy
# Tests maximum concurrent connections and throughput
#

SERVER_HOST="127.0.0.1"
SERVER_PORT="1080"
SOCKS_USER="admin"
SOCKS_PASS="password123"
TARGET_URL="http://example.com"

echo "========================================="
echo "SOCKS5 PROXY STRESS TEST"
echo "========================================="
echo ""

# Test 1: Maximum concurrent connections
echo "[TEST 1] Maximum Concurrent Connections"
echo "----------------------------------------"
echo "Testing with increasing number of simultaneous connections..."
echo ""

for CONNS in 10 50 100 200 500 1000; do
    echo -n "Testing $CONNS concurrent connections... "
    
    # Kill any previous curl processes
    pkill -f "curl.*--socks5" 2>/dev/null
    sleep 1
    
    # Start connections in parallel
    for i in $(seq 1 $CONNS); do
        curl --socks5 $SERVER_HOST:$SERVER_PORT \
             --proxy-user $SOCKS_USER:$SOCKS_PASS \
             --max-time 30 \
             $TARGET_URL > /dev/null 2>&1 &
    done
    
    # Wait a bit for connections to establish
    sleep 2
    
    # Count active connections
    ACTIVE=$(pgrep -f "curl.*--socks5" | wc -l)
    echo "$ACTIVE active"
    
    # Get server stats
    STATS=$(./bin/client -c STATS 2>/dev/null | grep "current=" | cut -d= -f2)
    echo "  Server reports: $STATS current connections"
    
    # Wait for completions
    wait
    sleep 1
    
    # Check for failures
    FAILURES=$(./bin/client -c STATS 2>/dev/null | grep "failed=" | cut -d= -f2)
    echo "  Failures: $FAILURES"
    echo ""
done

echo ""
echo "[TEST 2] Throughput Test"
echo "----------------------------------------"
echo "Downloading 10MB file through proxy..."
echo ""

# Create a test file if needed (or use a remote one)
TEST_FILE="http://ipv4.download.thinkbroadband.com/10MB.zip"

for PARALLEL in 1 5 10 20; do
    echo -n "With $PARALLEL parallel downloads... "
    
    START_TIME=$(date +%s)
    
    for i in $(seq 1 $PARALLEL); do
        curl --socks5 $SERVER_HOST:$SERVER_PORT \
             --proxy-user $SOCKS_USER:$SOCKS_PASS \
             --max-time 60 \
             -o /dev/null \
             $TEST_FILE 2>/dev/null &
    done
    
    wait
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    # Get total bytes transferred
    BYTES=$(./bin/client -c STATS 2>/dev/null | grep "bytes_total=" | cut -d= -f2)
    
    if [ $DURATION -gt 0 ]; then
        THROUGHPUT=$((BYTES / DURATION / 1024 / 1024))
        echo "${DURATION}s (${THROUGHPUT} MB/s avg)"
    else
        echo "< 1s"
    fi
done

echo ""
echo "[TEST 3] Connection Persistence"
echo "----------------------------------------"
echo "Testing long-lived connections..."
echo ""

# Start 10 long-running connections
for i in $(seq 1 10); do
    (
        sleep $((i * 2))
        curl --socks5 $SERVER_HOST:$SERVER_PORT \
             --proxy-user $SOCKS_USER:$SOCKS_PASS \
             --max-time 30 \
             $TARGET_URL > /dev/null 2>&1
    ) &
done

echo "Started 10 staggered connections..."
sleep 5

MAX_CONCURRENT=$(./bin/client -c STATS 2>/dev/null | grep "max_concurrent=" | cut -d= -f2)
echo "Max concurrent observed: $MAX_CONCURRENT"

wait

echo ""
echo "========================================="
echo "STRESS TEST COMPLETE"
echo "========================================="
echo ""
echo "Final Statistics:"
./bin/client -c STATS

echo ""
echo "NOTE: For production stress testing, use specialized tools like:"
echo "  - apache2-utils (ab)"
echo "  - wrk"
echo "  - hey"
echo "  - locust"
