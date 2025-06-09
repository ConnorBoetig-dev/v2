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
NC='\033[0m' # No Color

clear
echo -e "${BLUE}NetworkMapper Scan Monitor${NC}"
echo "================================"
echo "Temp file: $TEMP_FILE"
echo "Started: $(stat -c %y $TEMP_FILE | cut -d. -f1)"
echo ""

# Monitor loop
while [ -f "$TEMP_FILE" ]; do
    clear
    echo -e "${BLUE}NetworkMapper Scan Monitor${NC}"
    echo "================================"
    
    # File stats
    echo -e "${YELLOW}File Statistics:${NC}"
    echo "Size: $(ls -lh $TEMP_FILE | awk '{print $5}')"
    echo "Modified: $(stat -c %y $TEMP_FILE | cut -d. -f1)"
    echo ""
    
    # Parse XML for stats
    if [ -s "$TEMP_FILE" ]; then
        echo -e "${YELLOW}Scan Progress:${NC}"
        
        # Count hosts
        TOTAL_HOSTS=$(grep -o '<host>' $TEMP_FILE 2>/dev/null | wc -l)
        echo "Hosts discovered: $TOTAL_HOSTS"
        
        # Count open ports
        OPEN_PORTS=$(grep -o 'state="open"' $TEMP_FILE 2>/dev/null | wc -l)
        echo "Open ports found: $OPEN_PORTS"
        
        # Show recent discoveries
        echo ""
        echo -e "${GREEN}Recent Discoveries:${NC}"
        
        # Get last few IPs
        grep -o 'addr="[0-9.]*"' $TEMP_FILE 2>/dev/null | tail -5 | while read line; do
            IP=$(echo $line | cut -d'"' -f2)
            echo "  • $IP"
        done
        
        # Get last few open ports
        echo ""
        echo -e "${GREEN}Recent Open Ports:${NC}"
        grep -B2 'state="open"' $TEMP_FILE 2>/dev/null | grep 'portid=' | tail -5 | while read line; do
            PORT=$(echo $line | grep -o 'portid="[0-9]*"' | cut -d'"' -f2)
            PROTO=$(echo $line | grep -o 'protocol="[a-z]*"' | cut -d'"' -f2)
            echo "  • Port $PORT/$PROTO"
        done
    fi
    
    echo ""
    echo "Press Ctrl+C to exit"
    sleep 2
done

echo ""
echo "Scan completed or file removed"
