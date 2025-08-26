#!/bin/bash

# ╔══════════════════════════════════════════════╗
# ║         IKE-Cazador                          ║
# ║         Group ID Brute Force Script          ║
# ║         local-gh0st                          ║
# ╚══════════════════════════════════════════════╝

# === Configuration ===
WORDLIST="$2"
DELAY=0.2
LOGFILE="valid-groupids.log"

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# === Read group IDs into an array ===
mapfile -t GROUP_IDS < "$WORDLIST"

# === Optional flags ===
USE_JITTER=false
if [[ "$@" =~ "-j" ]]; then
    USE_JITTER=true
    echo -e "${GREEN}[*] Jitter enabled: random delay between 0.3s–0.99s per request${NC}"
fi

USE_ROTATION=false
if [[ "$@" =~ "-r" ]]; then
    USE_ROTATION=true
    echo -e "${GREEN}[*] Group-first rotation enabled (-r flag detected)${NC}"
fi

# === Check arguments ===
if [ -z "$1" ] || [ -z "$WORDLIST" ]; then
    echo -e "${YELLOW}Usage: $0 <target_ip OR targets_list.txt> <groupid_wordlist.txt>${NC}"
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
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        TARGETS+=("$line")
    done < "$1"
else
    TARGETS+=("$1")
fi

echo -e "${GREEN}[*] Loaded ${#TARGETS[@]} target(s)${NC}"
echo -e "${GREEN}[*] Using wordlist: $WORDLIST${NC}"
echo -e "${GREEN}[*] Logging valid results to: $LOGFILE${NC}"
echo ""

# === Main brute force loop ===
for GROUPID in "${GROUP_IDS[@]}"; do
    echo -e "${YELLOW}=== Testing Group ID: $GROUPID ===${NC}"

    if [ "$USE_ROTATION" = true ]; then
    # === Group-first rotation ===
    mapfile -t GROUP_IDS < "$WORDLIST"

    for GROUPID in "${GROUP_IDS[@]}"; do
        echo -e "${YELLOW}=== Testing Group ID: $GROUPID ===${NC}"

        for TARGET in "${TARGETS[@]}"; do
            echo -ne "${YELLOW}[~] Testing $GROUPID on $TARGET... ${NC}"

            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                echo "$TARGET : $GROUPID" >> "$LOGFILE"
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
else
    # === Default host-first rotation ===
    for TARGET in "${TARGETS[@]}"; do
        echo -e "${YELLOW}--- Scanning target: $TARGET ---${NC}"

        while IFS= read -r GROUPID || [[ -n "$GROUPID" ]]; do
            echo -ne "${YELLOW}[~] Testing group ID: ${GROUPID}${NC}... "

            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                echo "$TARGET : $GROUPID" >> "$LOGFILE"
            else
                echo -e "${RED}[INVALID]${NC}"
            fi

        # === Delay handling (jitter or fixed) ===

            if [ "$USE_JITTER" = true ]; then
                RANDOM_DELAY=$(awk -v min=0.3 -v max=0.99 'BEGIN{srand(); print min+rand()*(max-min)}')
                sleep "$RANDOM_DELAY"
            else
                sleep "$DELAY"
            fi
        done < "$WORDLIST"

        echo ""
    done
fi

echo -e "${GREEN}[+] Scan complete. Results saved to ${LOGFILE}.${NC}"
