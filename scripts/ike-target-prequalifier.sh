#!/bin/bash
# ike-target-prequalifier.sh
# Pre-qualify VPN targets before full scan
# Tests: connectivity, configuration, rate limiting, response time

INPUT_FILE="${1:-targets.txt}"
OUTPUT_FILE="qualified-targets.txt"
STATS_FILE="prequalification-stats.txt"
TIMEOUT=8
DELAY_BETWEEN_TESTS=3  # Wait 3 seconds between tests to avoid rate limiting

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script requires root privileges (ike-scan needs raw sockets)${NC}"
   exit 1
fi

# Check if ike-scan exists
if ! command -v ike-scan &> /dev/null; then
    echo -e "${RED}[!] ike-scan not found. Please install it first.${NC}"
    exit 1
fi

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[!] Input file not found: $INPUT_FILE${NC}"
    echo "Usage: $0 <targets_file>"
    exit 1
fi

# Initialize output files
> "$OUTPUT_FILE"
echo "=== IKE Target Pre-Qualification ===" > "$STATS_FILE"
echo "Started: $(date)" >> "$STATS_FILE"
echo "Timeout: ${TIMEOUT}s" >> "$STATS_FILE"
echo "Delay between tests: ${DELAY_BETWEEN_TESTS}s" >> "$STATS_FILE"
echo "" >> "$STATS_FILE"

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  IKE Target Pre-Qualification Tool${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo ""

total_targets=$(grep -v '^#' "$INPUT_FILE" | grep -v '^$' | wc -l | tr -d ' ')
current=0

while IFS= read -r ip; do
    # Skip empty lines and comments
    [[ -z "$ip" || "$ip" =~ ^#.* ]] && continue
    
    current=$((current + 1))
    echo -e "${CYAN}[${current}/${total_targets}] Testing: ${ip}${NC}"
    
    # Test 1: Basic Connectivity (Main Mode - no Group ID)
    echo -e "  [*] Test 1: Connectivity check..."
    start_time=$(date +%s.%N)
    connectivity_result=$(timeout ${TIMEOUT} ike-scan -M "$ip" --retry=1 2>&1)
    end_time=$(date +%s.%N)
    response_time=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")
    
    if echo "$connectivity_result" | grep -q "returned\|Handshake"; then
        echo -e "  ${GREEN}[✓] RESPONSIVE${NC} (${response_time}s)"
        
        sleep $DELAY_BETWEEN_TESTS  # Avoid rate limiting
        
        # Test 2: Configuration Check (does it reject invalid Group IDs?)
        echo -e "  [*] Test 2: Configuration check (invalid Group ID)..."
        invalid_test=$(timeout ${TIMEOUT} ike-scan -M -A --id=INVALID_PREQUALTEST_99999 "$ip" --retry=1 2>&1)
        
        if echo "$invalid_test" | grep -q "Aggressive Mode Handshake returned"; then
            echo -e "  ${YELLOW}[!] MISCONFIGURED${NC} - Accepts any Group ID (false positives)"
            echo "$ip,misconfigured,$response_time" >> "$STATS_FILE"
            
        else
            echo -e "  ${GREEN}[✓] PROPERLY CONFIGURED${NC} - Rejects invalid IDs"
            
            sleep $DELAY_BETWEEN_TESTS  # Avoid rate limiting
            
            # Test 3: Rate Limiting Check (fire 5 rapid requests)
            echo -e "  [*] Test 3: Rate limiting check (5 rapid requests)..."
            rate_limit_triggered=false
            
            for i in {1..5}; do
                test_result=$(timeout ${TIMEOUT} ike-scan -M -A --id=TEST_${i} "$ip" --retry=1 2>&1)
                if echo "$test_result" | grep -q "timed out\|no response"; then
                    rate_limit_triggered=true
                    echo -e "  ${YELLOW}[!] Rate limit triggered at request ${i}${NC}"
                    break
                fi
                sleep 0.5  # Small delay between rapid tests
            done
            
            if [ "$rate_limit_triggered" = true ]; then
                echo -e "  ${YELLOW}[⚠] RATE LIMITED${NC} - Use jitter mode (-j) for this target"
                echo "$ip,valid_but_rate_limited,$response_time" >> "$STATS_FILE"
                echo "$ip  # WARNING: Rate limited - use jitter (-j)" >> "$OUTPUT_FILE"
            else
                echo -e "  ${GREEN}[✓] NO RATE LIMITING${NC} - Safe for normal scanning"
                echo "$ip,qualified,$response_time" >> "$STATS_FILE"
                echo "$ip" >> "$OUTPUT_FILE"
            fi
        fi
        
    else
        echo -e "  ${RED}[✗] UNREACHABLE${NC} - No response (timeout or filtered)"
        echo "$ip,unreachable,$response_time" >> "$STATS_FILE"
    fi
    
    echo ""
    
    # Add delay between different targets to be extra cautious
    if [ $current -lt $total_targets ]; then
        sleep 2
    fi
done < "$INPUT_FILE"

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Pre-Qualification Complete${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo ""

# Summary statistics
total_qualified=$(grep -v '^#' "$OUTPUT_FILE" 2>/dev/null | wc -l | tr -d ' ')
total_misconfigured=$(grep -c "misconfigured" "$STATS_FILE" 2>/dev/null || echo "0")
total_unreachable=$(grep -c "unreachable" "$STATS_FILE" 2>/dev/null || echo "0")
total_rate_limited=$(grep -c "rate_limited" "$STATS_FILE" 2>/dev/null || echo "0")

echo "Results Summary:"
echo -e "  ${GREEN}Qualified targets: ${total_qualified}${NC}"
echo -e "  ${YELLOW}Misconfigured (false positives): ${total_misconfigured}${NC}"
echo -e "  ${YELLOW}Rate limited (use -j flag): ${total_rate_limited}${NC}"
echo -e "  ${RED}Unreachable: ${total_unreachable}${NC}"
echo ""
echo "Qualified targets saved to: ${OUTPUT_FILE}"
echo "Full statistics saved to: ${STATS_FILE}"
echo ""

if [ $total_qualified -gt 0 ]; then
    echo -e "${GREEN}Ready to scan! Use:${NC}"
    echo "  sudo ./ike-cazador.py $OUTPUT_FILE wordlists/your-wordlist.txt -v -r --timeout 8"
    
    if [ $total_rate_limited -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Note: Some targets showed rate limiting. Consider using jitter mode:${NC}"
        echo "  sudo ./ike-cazador.py $OUTPUT_FILE wordlists/your-wordlist.txt -v -r -j --timeout 8"
    fi
else
    echo -e "${RED}No qualified targets found. Suggestions:${NC}"
    echo "  - Verify targets are online and accessible"
    echo "  - Check firewall rules"
    echo "  - Try increasing timeout (adjust TIMEOUT variable in script)"
fi
