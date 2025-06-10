#!/bin/bash
# Live monitoring script for NetworkMapper scans

# Find the most recent nmap temp file
TEMP_FILE=$(ls -t /tmp/nmap_*.xml 2>/dev/null | head -1)

if [ -z "$TEMP_FILE" ]; then
    echo "No active nmap scan found"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}NetworkMapper Scan Monitor${NC}"
echo "================================"
echo "Temp file: $TEMP_FILE"
echo "Started: $(stat -c %y "$TEMP_FILE" | cut -d. -f1)"
echo ""

# Monitor loop
while [ -f "$TEMP_FILE" ]; do
    clear
    echo -e "${BLUE}NetworkMapper Scan Monitor${NC}"
    echo "================================"
    
    # File stats
    echo -e "${YELLOW}File Statistics:${NC}"
    FILE_SIZE=$(ls -lh "$TEMP_FILE" 2>/dev/null | awk '{print $5}')
    echo "Size: ${FILE_SIZE:-0}"
    echo "Modified: $(stat -c %y "$TEMP_FILE" 2>/dev/null | cut -d. -f1)"
    echo ""
    
    # Parse XML for stats (handle incomplete XML gracefully)
    if [ -s "$TEMP_FILE" ]; then
        echo -e "${YELLOW}Scan Progress:${NC}"
        
        # Count hosts with IPv4 addresses (more reliable than <host> tags)
        TOTAL_HOSTS=$(grep -c 'addrtype="ipv4"' "$TEMP_FILE" 2>/dev/null || echo "0")
        echo "Hosts discovered: ${CYAN}$TOTAL_HOSTS${NC}"
        
        # Count hosts that are up
        HOSTS_UP=$(grep -c 'state="up"' "$TEMP_FILE" 2>/dev/null || echo "0")
        echo "Hosts responding: ${GREEN}$HOSTS_UP${NC}"
        
        # Count open ports
        OPEN_PORTS=$(grep -c 'state="open"' "$TEMP_FILE" 2>/dev/null || echo "0")
        echo "Open ports found: ${GREEN}$OPEN_PORTS${NC}"
        
        # Count services identified
        SERVICES=$(grep -c '<service name=' "$TEMP_FILE" 2>/dev/null || echo "0")
        echo "Services identified: ${CYAN}$SERVICES${NC}"
        
        # Show scan progress from nmaprun tag if available
        PROGRESS=$(grep -o 'percent="[0-9.]*"' "$TEMP_FILE" 2>/dev/null | tail -1 | cut -d'"' -f2)
        if [ ! -z "$PROGRESS" ]; then
            echo "Overall progress: ${YELLOW}${PROGRESS}%${NC}"
        fi
        
        # Detect current scan phase
        echo ""
        echo -e "${YELLOW}Current Phase:${NC}"
        if grep -q "taskbegin.*Ping Scan" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}Host Discovery${NC} (finding live hosts)"
        fi
        if grep -q "taskbegin.*ARP Ping Scan" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}ARP Discovery${NC} (Layer 2 scanning)"
        fi
        if grep -q "taskbegin.*SYN Stealth Scan" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}Port Scanning${NC} (checking for open ports)"
        fi
        if grep -q "taskbegin.*Service scan" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}Service Detection${NC} (identifying services)"
        fi
        if grep -q "taskbegin.*OS detection" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}OS Detection${NC} (fingerprinting systems)"
        fi
        if grep -q "taskbegin.*NSE" "$TEMP_FILE" 2>/dev/null; then
            echo "• ${CYAN}Script Scanning${NC} (running NSE scripts)"
        fi
        
        # Show recent discoveries
        echo ""
        echo -e "${GREEN}Recent Host Discoveries:${NC}"
        
        # Get last 5 unique IPs (simplified to avoid complex parsing)
        grep 'addrtype="ipv4"' "$TEMP_FILE" 2>/dev/null | \
            grep -o 'addr="[0-9.]*"' | \
            cut -d'"' -f2 | \
            tail -5 | \
            while read IP; do
                if [ ! -z "$IP" ]; then
                    # Count open ports for this IP (simplified)
                    PORT_COUNT=0
                    if grep -q "addr=\"$IP\"" "$TEMP_FILE" 2>/dev/null; then
                        # Create a temporary marker to find the host section
                        HOST_SECTION=$(grep -n "addr=\"$IP\"" "$TEMP_FILE" 2>/dev/null | head -1 | cut -d: -f1)
                        if [ ! -z "$HOST_SECTION" ]; then
                            # Count ports within next 100 lines after the IP
                            PORT_COUNT=$(tail -n +$HOST_SECTION "$TEMP_FILE" 2>/dev/null | head -100 | grep -c 'state="open"' || echo "0")
                        fi
                    fi
                    
                    # Try to get hostname (simplified)
                    HOSTNAME=""
                    if grep -q "addr=\"$IP\"" "$TEMP_FILE" 2>/dev/null; then
                        # Look for hostname within 20 lines after IP
                        HOST_LINE=$(grep -n "addr=\"$IP\"" "$TEMP_FILE" 2>/dev/null | head -1 | cut -d: -f1)
                        if [ ! -z "$HOST_LINE" ]; then
                            HOSTNAME=$(tail -n +$HOST_LINE "$TEMP_FILE" 2>/dev/null | head -20 | grep 'name=' | grep 'type="PTR"' | head -1 | grep -o 'name="[^"]*"' | cut -d'"' -f2)
                        fi
                    fi
                    
                    # Display the host info
                    if [ $PORT_COUNT -gt 0 ]; then
                        if [ ! -z "$HOSTNAME" ]; then
                            echo "  • $IP ($HOSTNAME) ${GREEN}[$PORT_COUNT open ports]${NC}"
                        else
                            echo "  • $IP ${GREEN}[$PORT_COUNT open ports]${NC}"
                        fi
                    else
                        if [ ! -z "$HOSTNAME" ]; then
                            echo "  • $IP ($HOSTNAME)"
                        else
                            echo "  • $IP"
                        fi
                    fi
                fi
            done
        
        # Show recent open ports with service names (simplified)
        echo ""
        echo -e "${GREEN}Recent Port Discoveries:${NC}"
        
        # Get recent ports
        grep 'portid=' "$TEMP_FILE" 2>/dev/null | grep -B1 -A1 'state="open"' | grep 'portid=' | tail -5 | \
            while read line; do
                PORT=$(echo "$line" | grep -o 'portid="[0-9]*"' | cut -d'"' -f2)
                PROTO=$(echo "$line" | grep -o 'protocol="[a-z]*"' | cut -d'"' -f2)
                
                if [ ! -z "$PORT" ] && [ ! -z "$PROTO" ]; then
                    echo "  • Port ${CYAN}$PORT/$PROTO${NC}"
                fi
            done
        
        # Show timing information
        echo ""
        echo -e "${YELLOW}Timing Information:${NC}"
        START_TIME=$(grep 'start=' "$TEMP_FILE" 2>/dev/null | head -1 | grep -o 'startstr="[^"]*"' | cut -d'"' -f2)
        if [ ! -z "$START_TIME" ]; then
            echo "Scan started: $START_TIME"
            
            # Calculate elapsed time
            if command -v date >/dev/null 2>&1; then
                START_EPOCH=$(date -d "$START_TIME" +%s 2>/dev/null || echo "")
                NOW_EPOCH=$(date +%s 2>/dev/null || echo "")
                if [ ! -z "$START_EPOCH" ] && [ ! -z "$NOW_EPOCH" ]; then
                    ELAPSED=$((NOW_EPOCH - START_EPOCH))
                    ELAPSED_MIN=$((ELAPSED / 60))
                    ELAPSED_SEC=$((ELAPSED % 60))
                    echo "Elapsed time: ${ELAPSED_MIN}m ${ELAPSED_SEC}s"
                fi
            fi
        fi
        
        # Check if scan is complete
        if grep -q '</nmaprun>' "$TEMP_FILE" 2>/dev/null; then
            echo ""
            echo -e "${GREEN}✓ Scan appears to be complete!${NC}"
            ENDTIME=$(grep 'nmaprun.*exit=' "$TEMP_FILE" 2>/dev/null | grep -o 'endstr="[^"]*"' | cut -d'"' -f2)
            if [ ! -z "$ENDTIME" ]; then
                echo "Finished at: $ENDTIME"
            fi
        fi
    else
        echo -e "${RED}Waiting for scan data...${NC}"
    fi
    
    echo ""
    echo "Press Ctrl+C to exit (scan will continue)"
    sleep 2
done

echo ""
echo "Scan completed or file removed"
