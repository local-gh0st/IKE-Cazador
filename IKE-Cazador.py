#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import time
import random
import shutil
from collections import defaultdict

# === Colors ===
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[0;33m'
SOFT_YELLOW = '\033[0;33m'
BLUE = '\033[1;34m'
WHITE = '\033[0;37m'
NC = '\033[0m'

# === Configuration ===
DEFAULT_DELAY = 0.2
DEFAULT_LOGFILE = "valid-groupids.log"
DEFAULT_PORT = 500

# === Helper Functions ===
def is_valid_ip(ip):
    parts = ip.strip().split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def run_ike_scan(target, groupid, port):
    try:
        output = subprocess.run([
            "sudo", "ike-scan", "-A", "-M", f"--id={groupid}", "-d", str(port), target
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        return output.stdout.decode()
    except subprocess.TimeoutExpired:
        return ""

def print_usage():
    print(f"{YELLOW}Usage:{NC}")
    print(f"{WHITE}./IKE-Cazador.py <target_ip OR targets_list> <groupid_wordlist>{NC}")
    print(f"{YELLOW}(Will use built-in wordlist from '/danielmiessler/SecLists' if nothing else is specified).{NC}")
    print("")
    print(f"{YELLOW}[-r] ={NC} {WHITE}Use 'Group-first' rotation: tries each group ID against all hosts before moving to the next group ID (round-robin). Helps avoid hammering a single host and can bypass rate limits.{NC}")
    print(f"{YELLOW}[-j] ={NC} {WHITE}Add a 'delay' of .3-.99 seconds per attempt, should emulate more realistic user behavior{NC}")
    print(f"{YELLOW}[-p] ={NC} {WHITE}Destination port. Specify the IKE port with -p <x> (default: 500){NC}")

# === Argument Parsing ===
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-r', action='store_true', dest='use_rotation')
    parser.add_argument('-j', action='store_true', dest='use_jitter')
    parser.add_argument('-p', type=int, dest='port', default=DEFAULT_PORT)
    parser.add_argument('-debug', action='store_true', dest='show_debug')
    parser.add_argument('-h', '--help', action='store_true', dest='show_help')
    parser.add_argument('target_arg', nargs='?')
    parser.add_argument('wordlist', nargs='?')
    args = parser.parse_args()

    if args.show_help or not args.target_arg:
        print_usage()
        sys.exit(0 if args.show_help else 1)

    target_arg = args.target_arg
    wordlist = args.wordlist or "ike-groupid.txt"
    port = args.port
    use_rotation = args.use_rotation
    use_jitter = args.use_jitter
    show_debug = args.show_debug
    logfile = DEFAULT_LOGFILE

    # === Validate wordlist ===
    if not os.path.isfile(wordlist):
        print(f"{RED}[!] Wordlist not found: {wordlist}{NC}")
        sys.exit(1)

    # === Validate ike-scan ===
    if not shutil.which("ike-scan"):
        print(f"{RED}[!] ike-scan not found. Please install it and run this script with sudo.{NC}")
        sys.exit(1)

    # === Load targets ===
    targets = []
    if os.path.isfile(target_arg) and os.path.basename(target_arg) != os.path.basename(__file__):
        with open(target_arg) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if is_valid_ip(line):
                    targets.append(line)
        if not targets:
            print(f"{RED}[!] Target file '{target_arg}' does not contain any valid IP addresses.{NC}")
            sys.exit(1)
        print(f"{GREEN}[*] Loading targets from file: {target_arg}{NC}")
    elif is_valid_ip(target_arg):
        targets.append(target_arg)
    else:
        print(f"{RED}[!] Invalid target: '{target_arg}' is not a valid IP address or a valid target list file.{NC}")
        sys.exit(1)
    print(f"{GREEN}[*] Loaded {len(targets)} target(s){NC}")

    # === Wordlist message ===
    if wordlist == "ike-groupid.txt":
        print(f"{GREEN}[*] Using default wordlist: {wordlist}{NC}")
    else:
        print(f"{GREEN}[*] Using user-specified wordlist: {wordlist}{NC}")

    # === Port message ===
    if port == 500:
        print(f"{GREEN}[*] Using default UDP port: {port}{NC}")
    else:
        print(f"{GREEN}[*] Using user-specified UDP port: {port}{NC}")
    print(f"{GREEN}[*] Logging valid results to: {logfile}{NC}\n")

    # === Read group IDs ===
    with open(wordlist) as f:
        group_ids = [line.strip() for line in f if line.strip()]

    valid_pairs = []
    target_valid_groupids = defaultdict(list)
    multi_valid_targets = set()

    # === Main brute force loop ===
    if use_rotation:
        remaining_targets = targets.copy()
        for groupid in group_ids:
            print(f"{YELLOW}=== Testing Group ID: {groupid} ==={NC}")
            new_remaining_targets = []
            for target in remaining_targets:
                if target in multi_valid_targets:
                    continue
                print(f"{YELLOW}[~] {WHITE}Testing {groupid} on {target}... {NC}", end='')
                output = run_ike_scan(target, groupid, port)
                if "Aggressive Mode Handshake returned" in output:
                    print(f"{GREEN}[VALID]{NC}")
                    # Validation module
                    validation_false_positive = False
                    validation_ids = set()
                    while len(validation_ids) < 4:
                        rand_id = random.choice(group_ids)
                        if rand_id != groupid:
                            validation_ids.add(rand_id)
                    for i, val_id in enumerate(validation_ids):
                        count = 4 - i
                        print(f"{YELLOW}[~]{NC} {GREEN}Validation module: Testing group ID {val_id} on {target} to reduce likelihood of false positive...{NC} {YELLOW}[{count}]{NC}")
                        print(f"{YELLOW}[~]{NC} {WHITE}Testing group ID: {val_id} on {target}... {NC}", end='')
                        val_output = run_ike_scan(target, val_id, port)
                        if "Aggressive Mode Handshake returned" in val_output:
                            print(f"{GREEN}[VALID]{NC}")
                            validation_false_positive = True
                        else:
                            print(f"{RED}[INVALID]{NC}")
                        time.sleep(2)
                    if validation_false_positive:
                        print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Ignoring this target.{NC}")
                        multi_valid_targets.add(target)
                        continue
                    else:
                        with open(logfile, 'a') as logf:
                            logf.write(f"{target} : {groupid}\n")
                        valid_pairs.append((target, groupid))
                        target_valid_groupids[target].append(groupid)
                        print(f"{GREEN}[!] Stopping further tests for {target} due to likely success.{NC}")
                else:
                    print(f"{RED}[INVALID]{NC}")
                    new_remaining_targets.append(target)
            remaining_targets = new_remaining_targets
            print()
            if not remaining_targets:
                break
    else:
        for target in targets:
            print(f"{YELLOW}--- Scanning target: {target} ---{NC}")
            for groupid in group_ids:
                if target in multi_valid_targets:
                    break
                print(f"{YELLOW}[~] {WHITE}Testing group ID: {groupid} on {target}... {NC}", end='')
                output = run_ike_scan(target, groupid, port)
                if "Aggressive Mode Handshake returned" in output:
                    print(f"{GREEN}[VALID]{NC}")
                    # Validation module
                    validation_false_positive = False
                    validation_ids = set()
                    while len(validation_ids) < 4:
                        rand_id = random.choice(group_ids)
                        if rand_id != groupid:
                            validation_ids.add(rand_id)
                    for i, val_id in enumerate(validation_ids):
                        count = 4 - i
                        print(f"{YELLOW}[~]{NC} {GREEN}Validation module: Testing group ID {val_id} on {target} to reduce likelihood of false positive...{NC} {YELLOW}[{count}]{NC}")
                        print(f"{YELLOW}[~]{NC} {WHITE}Testing group ID: {val_id} on {target}... {NC}", end='')
                        val_output = run_ike_scan(target, val_id, port)
                        if "Aggressive Mode Handshake returned" in val_output:
                            print(f"{GREEN}[VALID]{NC}")
                            validation_false_positive = True
                        else:
                            print(f"{RED}[INVALID]{NC}")
                        time.sleep(2)
                    if validation_false_positive:
                        print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Ignoring this target.{NC}")
                        multi_valid_targets.add(target)
                        break
                    else:
                        with open(logfile, 'a') as logf:
                            logf.write(f"{target} : {groupid}\n")
                        valid_pairs.append((target, groupid))
                        target_valid_groupids[target].append(groupid)
                        print(f"{GREEN}[!] Stopping further tests for {target} due to likely success.{NC}")
                        break
                else:
                    print(f"{RED}[INVALID]{NC}")
                if use_jitter:
                    random_delay = random.uniform(0.3, 0.99)
                    time.sleep(random_delay)
                else:
                    time.sleep(DEFAULT_DELAY)
            print()

    print(f"{GREEN}[+] Scan complete. Results saved to {logfile}.{NC}")
    if valid_pairs:
        print(f"{SOFT_YELLOW}\n[{len(valid_pairs)}] Valid pairs found:{NC}")
        for target, groupid in valid_pairs:
            print(f"{GREEN}{target} : {groupid}{NC}")
    if multi_valid_targets:
        print(f"{RED}\n[!] WARNING: The following host(s) responded as VALID for multiple unrelated group IDs. This likely indicates a false positive and the PSK may not be crackable.{NC}")
        for target in multi_valid_targets:
            for groupid in target_valid_groupids[target]:
                print(f"{YELLOW}{target}{NC}:{WHITE}{groupid}{NC}")
    print(f"{SOFT_YELLOW}\n[+] To capture the hash for each valid target/group ID, run ike-scan.{NC}")
    print(f"{SOFT_YELLOW}1. Run command{NC}")
    print(f"{SOFT_YELLOW}2. ????{NC}")
    print(f"{SOFT_YELLOW}3. Profit{NC}")
    print()
    print(f"{SOFT_YELLOW}run:{NC}")
    for target, groupid in valid_pairs:
        print(f"{BLUE}ike-scan -A -M -P --id={groupid} {target}{NC}")
    if show_debug:
        print(f"DEBUG: target_arg = '{target_arg}'")
        print(f"DEBUG: wordlist = '{wordlist}'")
        print(f"DEBUG: targets = {targets}")

if __name__ == "__main__":
    main()
