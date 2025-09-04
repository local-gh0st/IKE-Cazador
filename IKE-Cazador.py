import argparse
import subprocess
import time
import random
import sys
import os

# === Colors ===
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[0;33m'
SOFT_YELLOW = '\033[0;33m'
BLUE = '\033[1;34m'
WHITE = '\033[0;37m'
NC = '\033[0m'

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
        result = subprocess.run(
            ["sudo", "ike-scan", "-A", "-M", "--id={}".format(groupid), "-d", str(port), target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        return "Aggressive Mode Handshake returned" in result.stdout.decode()
    except Exception:
        return False

def main():
    class CustomArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            print("usage: ike-cazador.py <target or target list> <groupID wordlist>\n")
            print(f"ike-cazador.py: error: {message}\n")
            print(f"{SOFT_YELLOW}Tip: For usage details, run with the -h or -help flag (e.g. python3 ike-cazador.py -h){NC}")
            self.exit(2)

    parser = CustomArgumentParser(add_help=False)
    parser.add_argument("target", help="Target IP or file containing IPs")
    parser.add_argument("wordlist", nargs="?", default="ike-groupid.txt", help="GroupID wordlist")
    parser.add_argument("-r", action="store_true", help="Use group-first rotation")
    parser.add_argument("-j", action="store_true", help="Enable jitter (random delay)")
    parser.add_argument("-p", type=int, default=500, help="Destination port (default: 500)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output and show progress bar")
    # Manual help handling
    if any(flag in sys.argv for flag in ["-h", "--help"]):
        print("usage: ike-cazador.py <target or target list> <groupID wordlist>\n")
        print("IKE-Cazador Group ID Brute Force Script\n")
        print("positional arguments:")
        print("  target           Target IP or file containing IPs")
        print("  wordlist         GroupID wordlist\n")
        print("options:")
        print("  -r               Use group-first rotation")
        print("  -j               Enable jitter (random delay)")
        print("  -p               Destination port (default: 500)")
        print("  -q, --quiet      Suppress non-essential output and show progress bar")
        print("  -h, --help       Show this help message and exit")
        sys.exit(0)
    args = parser.parse_args()
    USE_QUIET = args.quiet

    DELAY = 0.2
    LOGFILE = "valid-groupids.log"
    PORT = args.p
    USE_ROTATION = args.r
    USE_JITTER = args.j

    if USE_JITTER:
        print(f"{GREEN}[*] Jitter enabled: random delay between 0.3s–0.99s per request{NC}")
    if USE_ROTATION:
        print(f"{GREEN}[*] Rotation enabled: rotating through GroupID list, round-robin style{NC}")

    # === Load targets ===
    targets = []
    if os.path.isfile(args.target):
        valid_ips = []
        with open(args.target) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if is_valid_ip(line):
                    valid_ips.append(line)
        if not valid_ips:
            print(f"{RED}[!] Target file '{args.target}' does not contain any valid IP addresses.{NC}")
            sys.exit(1)
        unique_ips = list(dict.fromkeys(valid_ips))
        dup_count = len(valid_ips) - len(unique_ips)
        targets = unique_ips
        print(f"{GREEN}[*] Loading targets from file: {args.target}{NC}")
        if dup_count > 0:
            print(f"{YELLOW}[*] {dup_count} duplicate IP(s) detected, ignoring dupes{NC}")
    elif is_valid_ip(args.target):
        targets = [args.target]
    else:
        print(f"{RED}[!] Invalid target: '{args.target}' is not a valid IP address or a valid target list file.{NC}")
        sys.exit(1)

    print(f"{GREEN}[*] Loaded {len(targets)} target(s){NC}")

    # === Load wordlist ===
    if not os.path.isfile(args.wordlist):
        print(f"{RED}[!] Wordlist not found: {args.wordlist}{NC}")
        sys.exit(1)
    with open(args.wordlist) as f:
        group_ids = [line.strip() for line in f if line.strip()]

    if args.wordlist == "ike-groupid.txt":
        print(f"{GREEN}[*] Using default wordlist: {args.wordlist}{NC}")
    else:
        print(f"{GREEN}[*] Using user-specified wordlist: {args.wordlist}{NC}")

    if PORT == 500:
        print(f"{GREEN}[*] Using default UDP port: {PORT}{NC}")
    else:
        print(f"{GREEN}[*] Using user-specified UDP port: {PORT}{NC}")

    print(f"{GREEN}[*] Logging valid results to: {LOGFILE}{NC}\n")

    valid_pairs = []
    multi_valid_targets = []
    target_valid_groupids = {}

    # === Main brute force loop ===
    total_attempts = len(targets) * len(group_ids) if not USE_ROTATION else len(group_ids) * len(targets)
    attempt = 0
    if USE_QUIET:
        if USE_ROTATION:
            remaining_targets = targets.copy()
            for groupid in group_ids:
                new_remaining_targets = []
                for target in remaining_targets:
                    if target in multi_valid_targets:
                        attempt += 1
                        print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                        continue
                    if run_ike_scan(target, groupid, PORT):
                        print(f"\n{SOFT_YELLOW}Potential match found: {GREEN}{target}{NC} with groupID '{BLUE}{groupid}{NC}'. {YELLOW}Running validation module to reduce likelihood of false positives...{NC}")
                        # Validation module
                        validation_false_positive = False
                        validation_ids = []
                        while len(validation_ids) < 4:
                            rand_id = random.choice(group_ids)
                            if rand_id != groupid and rand_id not in validation_ids:
                                validation_ids.append(rand_id)
                        for val_id in validation_ids:
                            if run_ike_scan(target, val_id, PORT):
                                validation_false_positive = True
                            time.sleep(2)
                        if validation_false_positive:
                            target_valid_groupids[target] = [groupid] + validation_ids
                            multi_valid_targets.append(target)
                            print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.{NC}")
                            attempt += 1
                            print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                            continue
                        else:
                            with open(LOGFILE, "a") as logf:
                                logf.write(f"{target} : {groupid}\n")
                            valid_pairs.append((target, groupid))
                            target_valid_groupids.setdefault(target, []).append(groupid)
                    else:
                        new_remaining_targets.append(target)
                    attempt += 1
                    print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                remaining_targets = new_remaining_targets
                if not remaining_targets:
                    break
            print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}")
        else:
            for target in targets:
                for groupid in group_ids:
                    if target in multi_valid_targets:
                        attempt += 1
                        print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                        break
                    if run_ike_scan(target, groupid, PORT):
                        print(f"\n{SOFT_YELLOW}Potential match found: {GREEN}{target}{NC} with groupID '{BLUE}{groupid}{NC}'. {YELLOW}Running validation module to reduce likelihood of false positives...{NC}")
                        # Validation module
                        validation_false_positive = False
                        validation_ids = []
                        while len(validation_ids) < 4:
                            rand_id = random.choice(group_ids)
                            if rand_id != groupid and rand_id not in validation_ids:
                                validation_ids.append(rand_id)
                        for val_id in validation_ids:
                            if run_ike_scan(target, val_id, PORT):
                                validation_false_positive = True
                            time.sleep(2)
                        if validation_false_positive:
                            print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.{NC}")
                            multi_valid_targets.append(target)
                            attempt += 1
                            print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                            break
                        else:
                            with open(LOGFILE, "a") as logf:
                                logf.write(f"{target} : {groupid}\n")
                            valid_pairs.append((target, groupid))
                            target_valid_groupids.setdefault(target, []).append(groupid)
                            attempt += 1
                            print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                            break
                    attempt += 1
                    print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}", end='\r')
                    if USE_JITTER:
                        time.sleep(random.uniform(0.3, 0.99))
                    else:
                        time.sleep(DELAY)
            print(f"{YELLOW}Progress: {attempt}/{total_attempts} attempts{NC}")
    else:
        if USE_ROTATION:
            remaining_targets = targets.copy()
            for groupid in group_ids:
                print(f"{YELLOW}=== Testing Group ID: {groupid} ==={NC}")
                new_remaining_targets = []
                for target in remaining_targets:
                    if target in multi_valid_targets:
                        continue
                    print(f"{YELLOW}[~] {WHITE}Testing {groupid} on {target}... {NC}", end="")
                    if run_ike_scan(target, groupid, PORT):
                        print(f"{GREEN}[VALID]{NC}")
                        # Validation module
                        validation_false_positive = False
                        validation_ids = []
                        while len(validation_ids) < 4:
                            rand_id = random.choice(group_ids)
                            if rand_id != groupid and rand_id not in validation_ids:
                                validation_ids.append(rand_id)
                        for i, val_id in enumerate(validation_ids):
                            count = 4 - i
                            print(f"{YELLOW}[~]{NC} {GREEN}Validation module: Testing group ID {val_id} on {target} to reduce likelihood of false positive...{NC} {YELLOW}[{count}]{NC}")
                            print(f"{YELLOW}[~]{NC} {WHITE}Testing group ID: {val_id} on {target}... {NC}", end="")
                            if run_ike_scan(target, val_id, PORT):
                                print(f"{GREEN}[VALID]{NC}")
                                validation_false_positive = True
                            else:
                                print(f"{RED}[INVALID]{NC}")
                            time.sleep(2)
                        if validation_false_positive:
                            target_valid_groupids[target] = [groupid] + validation_ids
                            print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.{NC}")
                            multi_valid_targets.append(target)
                            continue
                        else:
                            with open(LOGFILE, "a") as logf:
                                logf.write(f"{target} : {groupid}\n")
                            valid_pairs.append((target, groupid))
                            target_valid_groupids.setdefault(target, []).append(groupid)
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
                    print(f"{YELLOW}[~] {WHITE}Testing group ID: {groupid} on {target}... {NC}", end="")
                    if run_ike_scan(target, groupid, PORT):
                        print(f"{GREEN}[VALID]{NC}")
                        # Validation module
                        validation_false_positive = False
                        validation_ids = []
                        while len(validation_ids) < 4:
                            rand_id = random.choice(group_ids)
                            if rand_id != groupid and rand_id not in validation_ids:
                                validation_ids.append(rand_id)
                        for i, val_id in enumerate(validation_ids):
                            count = 4 - i
                            print(f"{YELLOW}[~]{NC} {GREEN}Validation module: Testing group ID {val_id} on {target} to reduce likelihood of false positive...{NC} {YELLOW}[{count}]{NC}")
                            print(f"{YELLOW}[~]{NC} {WHITE}Testing group ID: {val_id} on {target}... {NC}", end="")
                            if run_ike_scan(target, val_id, PORT):
                                print(f"{GREEN}[VALID]{NC}")
                                validation_false_positive = True
                            else:
                                print(f"{RED}[INVALID]{NC}")
                            time.sleep(2)
                        if validation_false_positive:
                            print(f"{RED}[!] {target} responded as VALID for multiple unrelated group IDs. Likely a false positive. Cazador will now ignore this target and you probably should too.{NC}")
                            multi_valid_targets.append(target)
                            break
                        else:
                            with open(LOGFILE, "a") as logf:
                                logf.write(f"{target} : {groupid}\n")
                            valid_pairs.append((target, groupid))
                            target_valid_groupids.setdefault(target, []).append(groupid)
                            print(f"{GREEN}[!] Stopping further tests for {target} due to likely success.{NC}")
                            break
                    else:
                        print(f"{RED}[INVALID]{NC}")
                    if USE_JITTER:
                        time.sleep(random.uniform(0.3, 0.99))
                    else:
                        time.sleep(DELAY)
                print()

    print(f"{GREEN}[+] Scan complete. Results saved to {LOGFILE}.{NC}")

    if valid_pairs:
        print(f"{SOFT_YELLOW}\n[{len(valid_pairs)}] Valid pairs found:{NC}")
        for target, groupid in valid_pairs:
            print(f"{GREEN}{target} : {groupid}{NC}")

        print(f"{SOFT_YELLOW}\n[+] To capture the hash for each valid target/group ID, run ike-scan.{NC}")
        print(f"{SOFT_YELLOW}1. Run command{NC}")
        print(f"{SOFT_YELLOW}2. ????{NC}")
        print(f"{SOFT_YELLOW}3. Profit{NC}\n")
        print(f"{SOFT_YELLOW}run:{NC}")
        for target, groupid in valid_pairs:
            print(f"{BLUE}ike-scan -A -M -P --id={groupid} {target}{NC}")

    if not valid_pairs and not multi_valid_targets:
        print(f"{SOFT_YELLOW}[+] No valid results returned. Consider trying again with a different GroupID wordlist, or a customized list curated to match the name, industry, region, etc. of your target organization.{NC}")

    if multi_valid_targets:
        print(f"{RED}\n[!] WARNING: The following host(s) responded as VALID for multiple unrelated group IDs. This likely indicates a false positive and the PSK may not be crackable.{NC}")
        for target in multi_valid_targets:
            print(f"{YELLOW}{target}{NC}")

if __name__ == "__main__":
    main()
