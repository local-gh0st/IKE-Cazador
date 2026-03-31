"""
Output Handler - Terminal display and file logging
"""

import sys
from datetime import datetime
from .utils import Colors, format_time


class OutputHandler:
    """Handle all terminal display and file logging"""
    
    def __init__(self, session_dir, verbose=False, quiet=False, use_color=True):
        self.session_dir = session_dir
        self.verbose = verbose
        self.quiet = quiet
        self.use_color = use_color and sys.stdout.isatty()
        
        # Initialize colors
        self.c = Colors(enabled=self.use_color)
        
        # Create log files
        self.main_log = open(f"{session_dir}/phase1_full_log.txt", 'w')
        self.error_log = open(f"{session_dir}/errors.txt", 'w')
    
    def close(self):
        """Close log files"""
        self.main_log.close()
        self.error_log.close()
    
    def display_banner(self):
        """Display ASCII banner"""
        banner = f"""{self.c.PURPLE}{self.c.BOLD}═══════════════════════════════════════════════════════════
  IKE-CAZADOR | VPN Group ID Discovery Tool
  Version 1.0.0 | IKE Aggressive Mode Enumeration
═══════════════════════════════════════════════════════════{self.c.RESET}
"""
        print(banner)
    
    def display_config(self, config):
        """Display scan configuration"""
        if self.quiet:
            return
        
        print("Configuration:")
        print(f"  Targets: {len(config.targets)}")
        print(f"  Wordlist: {len(config.wordlist)} Group IDs")
        
        if config.round_robin:
            print(f"  Mode: Round-robin")
        else:
            print(f"  Mode: Sequential")
        
        if config.jitter_enabled:
            print(f"  Jitter: Enabled (500ms ±200ms)")
        else:
            print(f"  Jitter: Disabled")
        
        print(f"  Port: {config.port} (UDP)")
        print()
    
    def display_progress(self, completed, total, percentage, eta_seconds):
        """Display progress bar with ETA"""
        if self.quiet:
            return
        
        eta_str = format_time(eta_seconds)
        print(f"\r[*] Progress: {completed}/{total} ({percentage:.1f}%) - ETA: {eta_str}", 
              end='', flush=True)
    
    def display_potential_valid(self, target, group_id):
        """Display when potential valid Group ID found"""
        msg = f"\n{self.c.GREEN}[+]{self.c.RESET} Potential valid: {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET}"
        print(msg)
    
    def display_validation_start(self, target, group_id):
        """Display validation module start"""
        msg = f"{self.c.PURPLE}{self.c.BOLD}[*] Validation module starting...{self.c.RESET}"
        print(msg)
    
    def display_validation_test(self, num, total, test_id, target):
        """Display each validation test"""
        print(f"    [{num}/{total}] Testing {self.c.CYAN}\"{test_id}\"{self.c.RESET} against {self.c.CYAN}{target}{self.c.RESET}")
    
    def display_validation_test_result(self, test_id, valid):
        """Display result of validation test"""
        if valid:
            print(f"          Result: VALID {self.c.RED}✗{self.c.RESET} (unexpected!)")
        else:
            print(f"          Result: INVALID {self.c.GREEN}✓{self.c.RESET}")
    
    def display_validation_passed(self):
        """Display validation passed"""
        print(f"\n{self.c.GREEN}✓ VALIDATION PASSED{self.c.RESET}")
    
    def display_validation_failed(self, valid_count, total):
        """Display validation failed (false positive)"""
        print(f"\n{self.c.RED}[!] VALIDATION FAILED: {valid_count}/{total} random IDs succeeded{self.c.RESET}")
    
    def display_validation_suspicious(self, valid_count, total):
        """Display validation suspicious"""
        print(f"\n{self.c.YELLOW}[!] VALIDATION SUSPICIOUS: {valid_count}/{total} random IDs succeeded{self.c.RESET}")
    
    def display_true_positive(self, target, group_id):
        """Display confirmed true positive"""
        msg = f"{self.c.GREEN}[+]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET} → TRUE POSITIVE (validated)"
        print(msg)
    
    def display_false_positive(self, target, group_id):
        """Display false positive"""
        msg = f"{self.c.RED}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET} → FALSE POSITIVE (misconfigured VPN)"
        print(msg)
    
    def display_suspicious(self, target, group_id):
        """Display suspicious result"""
        msg = f"{self.c.YELLOW}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET} → SUSPICIOUS (manual verification recommended)"
        print(msg)
    
    def display_unreachable(self, target):
        """Display target unreachable"""
        msg = f"{self.c.RED}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} unreachable - skipping remaining tests"
        print(msg)
    
    def log_test(self, target, group_id, result):
        """Log test to main log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.main_log.write(f"\n[{timestamp}] Testing {target} + \"{group_id}\"\n")
        self.main_log.write(f"ike-scan -M -A --id={group_id} {target}\n")
        
        if result.raw_output:
            self.main_log.write(result.raw_output + "\n")
        
        self.main_log.write(f"Result: {result.status}\n")
        self.main_log.write("=" * 80 + "\n")
        self.main_log.flush()
    
    def log_error(self, target, group_id, result):
        """Log error to error log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.error_log.write(f"\n[{timestamp}] ERROR: {result.status}\n")
        self.error_log.write(f"Target: {target}\n")
        self.error_log.write(f"Group ID: {group_id}\n")
        self.error_log.write(f"Command: ike-scan -M -A --id={group_id} {target}\n")
        self.error_log.write("Output:\n")
        
        if result.raw_output:
            self.error_log.write(result.raw_output + "\n")
        elif result.error_message:
            self.error_log.write(result.error_message + "\n")
        else:
            self.error_log.write("<no output>\n")
        
        self.error_log.write("=" * 80 + "\n")
        self.error_log.flush()
    
    def display_phase1_summary(self, results, scan_time):
        """Display Phase 1 summary"""
        print(f"\n\n{self.c.PURPLE}{self.c.BOLD}═══════════════════════════════════════════════════════════")
        print(f"Phase 1 Complete")
        print(f"═══════════════════════════════════════════════════════════{self.c.RESET}\n")
        
        print(f"Scan time: {format_time(scan_time)}")
        
        # Valid Group IDs
        if results.valid:
            print(f"\n{self.c.GREEN}Valid Group IDs: {sum(len(v) for v in results.valid.values())}{self.c.RESET}")
            for target, group_ids in results.valid.items():
                for group_id, _ in group_ids:
                    print(f"  {self.c.GREEN}✓{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} : {group_id}")
        
        # Suspicious results
        if results.suspicious:
            print(f"\n{self.c.YELLOW}Suspicious Results: {sum(len(v) for v in results.suspicious.values())}{self.c.RESET}")
            for target, group_ids in results.suspicious.items():
                for group_id in group_ids:
                    print(f"  {self.c.YELLOW}⚠{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} : {group_id} {self.c.GRAY}(manual verification needed){self.c.RESET}")
        
        # False positives
        if results.false_positives:
            print(f"\n{self.c.RED}False Positives: {sum(len(v) for v in results.false_positives.values())}{self.c.RESET}")
            for target in results.false_positives:
                print(f"  {self.c.RED}✗{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} {self.c.GRAY}(misconfigured - accepts any Group ID){self.c.RESET}")
        
        # Unreachable targets
        if results.unreachable:
            print(f"\n{self.c.RED}Unreachable Targets: {len(results.unreachable)}{self.c.RESET}")
            for target in results.unreachable:
                print(f"  {self.c.RED}✗{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} {self.c.GRAY}(timeout/unreachable){self.c.RESET}")
        
        print(f"\nFull logs: {self.c.CYAN}{self.session_dir}/{self.c.RESET}")
    
    def display_phase2_commands(self, results, port):
        """Display Phase 2 commands for PSK capture"""
        print(f"\n{self.c.PURPLE}{self.c.BOLD}Next steps to capture PSK hashes:{self.c.RESET}\n")
        
        for target, group_ids in results.valid.items():
            for group_id, _ in group_ids:
                print(f"  {self.c.GRAY}# Target: {target} (Group ID: {group_id}){self.c.RESET}")
                cmd = f"ike-scan -M -A --id={group_id}"
                if port != 500:
                    cmd += f" --dport {port}"
                cmd += f" -P {target} > {self.session_dir}/{target}_{group_id}.txt"
                print(f"  {self.c.CYAN}{cmd}{self.c.RESET}\n")
    
    def display_psk_capture_start(self, target, group_id, port):
        """Display PSK capture starting"""
        print(f"\n{self.c.PURPLE}{self.c.BOLD}[Phase 2: PSK Hash Capture]{self.c.RESET}\n")
        print(f"[*] Capturing PSK for {self.c.CYAN}{target}{self.c.RESET} (Group ID: {self.c.CYAN}{group_id}{self.c.RESET})")
        
        cmd = f"ike-scan -M -A --id={group_id}"
        if port != 500:
            cmd += f" --dport {port}"
        cmd += f" -P {target}"
        print(f"{self.c.CYAN}{cmd}{self.c.RESET}\n")
    
    def display_psk_capture_result(self, target, group_id, result):
        """Display PSK capture result"""
        # Display raw ike-scan output
        if result.raw_output:
            print(result.raw_output)
        
        # Display parsed details
        if result.encryption:
            transform_str = f"{result.encryption}, {result.hash_algorithm}, {result.auth_method}, DH Group {result.dh_group}"
            print(f"Transform Set: {transform_str}")
        
        if result.hash_algorithm:
            print(f"Hash Algorithm: {result.hash_algorithm}")
        
        print(f"{self.c.GREEN}[+]{self.c.RESET} Saved to: {self.c.CYAN}{self.session_dir}/{target}_{group_id}.txt{self.c.RESET}")
    
    def display_phase2_summary(self, results):
        """Display Phase 2 summary with hashcat commands"""
        print(f"\n{self.c.PURPLE}{self.c.BOLD}[Phase 2 Complete]{self.c.RESET}\n")
        print(f"Next steps - Crack the PSK hashes:\n")
        
        # Hash algorithm to hashcat mode mapping
        HASH_TO_HASHCAT = {
            'MD5': 5300,
            'SHA': 5400,
            'SHA1': 5400,
        }
        
        for target, group_ids in results.valid.items():
            for group_id, ike_result in group_ids:
                hash_algo = ike_result.hash_algorithm
                hashcat_mode = HASH_TO_HASHCAT.get(hash_algo)
                
                print(f"  {self.c.GRAY}# Target: {target} (Group ID: {group_id}){self.c.RESET}")
                
                if ike_result.encryption:
                    transform_str = f"{ike_result.encryption}, {ike_result.hash_algorithm}, {ike_result.auth_method}, DH Group {ike_result.dh_group}"
                    print(f"  {self.c.GRAY}# Transform Set: {transform_str}{self.c.RESET}")
                
                if hash_algo:
                    print(f"  {self.c.GRAY}# Hash Algorithm: {hash_algo}{self.c.RESET}")
                
                if hashcat_mode:
                    print(f"  {self.c.CYAN}hashcat -m {hashcat_mode} -a 0 {self.session_dir}/{target}_{group_id}.txt wordlist.txt{self.c.RESET}\n")
                else:
                    print(f"  {self.c.GRAY}# Check hashcat documentation for {hash_algo} support{self.c.RESET}")
                    print(f"  {self.c.CYAN}hashcat -a 0 {self.session_dir}/{target}_{group_id}.txt wordlist.txt{self.c.RESET}\n")
