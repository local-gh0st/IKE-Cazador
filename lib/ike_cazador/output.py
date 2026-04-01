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
        self.valid_results_log = open(f"{session_dir}/valid_results.txt", 'w')
        self.error_log = open(f"{session_dir}/errors_and_misconfigured.txt", 'w')
    
    def close(self):
        """Close log files"""
        self.main_log.close()
        self.valid_results_log.close()
        self.error_log.close()
    
    def _pad_line(self, text, width=70):
        """Pad text to exact width for box alignment"""
        # Remove color codes for length calculation
        visible_text = text
        for color in [self.c.CYAN, self.c.GREEN, self.c.RED, self.c.YELLOW, self.c.PURPLE, 
                      self.c.BOLD, self.c.RESET, self.c.GRAY]:
            visible_text = visible_text.replace(color, '')
        
        visible_len = len(visible_text)
        padding_needed = width - visible_len
        return text + (' ' * padding_needed)
    
    def _draw_validation_box(self, lines):
        """Draw Unicode box around validation output"""
        width = 70
        
        # Top border
        print(f"{self.c.PURPLE}╔{'═' * width}╗{self.c.RESET}")
        
        # Content lines
        for line in lines:
            padded = self._pad_line(line, width)
            print(f"{self.c.PURPLE}║{self.c.RESET}{padded}{self.c.PURPLE}║{self.c.RESET}")
        
        # Bottom border
        print(f"{self.c.PURPLE}╚{'═' * width}╝{self.c.RESET}")
    
    def display_banner(self):
        """Display ASCII banner"""
        banner = f"""{self.c.PURPLE}{self.c.BOLD}═══════════════════════════════════════════════════════════
  IKE-CAZADOR | VPN Group ID Discovery Tool
  Version 1.2.0 | IKE Aggressive Mode Enumeration
═══════════════════════════════════════════════════════════{self.c.RESET}
"""
        print(banner)
    
    def display_config(self, config):
        """Display scan configuration with concurrency details"""
        if self.quiet:
            return
        
        print("Configuration:")
        print(f"  Targets: {len(config.targets)}")
        print(f"  Wordlist: {len(config.wordlist)} Group IDs")
        
        if config.round_robin:
            print(f"  Mode: Round-robin")
        else:
            print(f"  Mode: Sequential")
        
        # Display concurrency settings
        max_per_target = 1 if config.jitter_enabled else 2
        print(f"  Concurrency: {max_per_target} requests/target, 20 global max")
        
        if config.jitter_enabled:
            print(f"  Jitter: Enabled (0.5-1.5s variable delay)")
        else:
            print(f"  Jitter: Disabled")
        
        print(f"  Port: {config.port} (UDP)")
        print()
    
    def display_progress(self, completed, total, percentage, eta_seconds, current_target=None, current_id=None):
        """Display progress bar with ETA and current test"""
        if self.quiet:
            return
        
        eta_str = format_time(eta_seconds)
        msg = f"\r[*] Progress: {completed}/{total} ({percentage:.1f}%)"
        
        if current_target and current_id:
            msg += f" | Testing: {self.c.CYAN}{current_target}{self.c.RESET} + {self.c.CYAN}\"{current_id}\"{self.c.RESET}"
        
        msg += f" | ETA: {eta_str}"
        print(msg, end='', flush=True)
    
    def display_target_skipped(self, target, reason):
        """Display when target is skipped"""
        msg = f"\n{self.c.YELLOW}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} marked as {reason} - skipping all remaining tests"
        print(msg)
    
    def display_potential_valid(self, target, group_id):
        """Display when potential valid Group ID found"""
        msg = f"\n{self.c.GREEN}[+]{self.c.RESET} Potential valid: {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET}"
        print(msg)
    
    def display_validation_start(self, target, group_id):
        """Display validation module start with Unicode box"""
        lines = [
            f" {self.c.BOLD}VALIDATION MODULE - {self.c.CYAN}{target}{self.c.RESET}{self.c.BOLD} + \"{self.c.CYAN}{group_id}{self.c.RESET}{self.c.BOLD}\"{self.c.RESET}",
            ""
        ]
        
        # Header with separator
        print()
        print(f"{self.c.PURPLE}╔{'═' * 70}╗{self.c.RESET}")
        for line in lines:
            padded = self._pad_line(line, 70)
            print(f"{self.c.PURPLE}║{self.c.RESET}{padded}{self.c.PURPLE}║{self.c.RESET}")
        print(f"{self.c.PURPLE}╠{'═' * 70}╣{self.c.RESET}")
    
    def display_validation_test_inline(self, num, total, test_id, is_valid):
        """Display inline validation test result"""
        expected_text = "(expected)" if not is_valid else "(unexpected!)"
        status_symbol = f"{self.c.GREEN}✓{self.c.RESET}" if not is_valid else f"{self.c.RED}✗{self.c.RESET}"
        status_text = "INVALID" if not is_valid else "VALID"
        
        line = f" [{num}/{total}] {test_id} → {status_text} {status_symbol} {expected_text}"
        padded = self._pad_line(line, 70)
        print(f"{self.c.PURPLE}║{self.c.RESET}{padded}{self.c.PURPLE}║{self.c.RESET}")
    
    def display_validation_end(self):
        """Display end of validation box"""
        print(f"{self.c.PURPLE}╚{'═' * 70}╝{self.c.RESET}")
    
    def display_validation_verdict(self, verdict, target, valid_count=0, total=5):
        """Display validation verdict with action"""
        if verdict == 'TRUE_POSITIVE':
            print(f"\n{self.c.GREEN}[✓] VERDICT: TRUE POSITIVE{self.c.RESET}")
            print(f"{self.c.GREEN}[→]{self.c.RESET} Action: Continuing tests to find additional valid Group IDs")
        elif verdict == 'FALSE_POSITIVE':
            print(f"\n{self.c.RED}[✗] VERDICT: FALSE POSITIVE{self.c.RESET} ({valid_count}/{total} random IDs succeeded)")
            print(f"{self.c.RED}[→]{self.c.RESET} Action: Target {self.c.CYAN}{target}{self.c.RESET} EXCLUDED from remaining tests")
        elif verdict == 'SUSPICIOUS':
            print(f"\n{self.c.YELLOW}[⚠] VERDICT: SUSPICIOUS{self.c.RESET} ({valid_count}/{total} random IDs succeeded)")
            print(f"{self.c.YELLOW}[→]{self.c.RESET} Action: Manual review recommended - continuing tests")
    
    def display_true_positive(self, target, group_id):
        """Display confirmed true positive"""
        # Verdict already displayed by display_validation_verdict
        pass
    
    def display_false_positive(self, target, group_id):
        """Display false positive"""
        # Verdict already displayed by display_validation_verdict
        pass
    
    def display_suspicious(self, target, group_id):
        """Display suspicious result"""
        # Verdict already displayed by display_validation_verdict
        pass
    
    def display_unreachable(self, target):
        """Display target unreachable"""
        msg = f"{self.c.RED}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} unreachable - skipping remaining tests"
        print(msg)
    
    def display_temporarily_unreachable(self, target):
        """Display temporarily unreachable target (will retry in 30s)"""
        msg = f"{self.c.YELLOW}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} temporarily unreachable - will retry in 30s"
        print(msg)
    
    def display_retry_attempt(self, target):
        """Display retry attempt message"""
        msg = f"{self.c.CYAN}[*]{self.c.RESET} Retrying {self.c.CYAN}{target}{self.c.RESET} after 30s cooldown..."
        print(msg)
    
    def display_target_recovered(self, target):
        """Display target recovered message"""
        msg = f"{self.c.GREEN}[+]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} recovered - resuming tests"
        print(msg)
    
    def display_permanently_unreachable(self, target):
        """Display permanently unreachable target"""
        msg = f"{self.c.RED}[!]{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} permanently unreachable - skipping remaining tests"
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
    
    def log_valid_result(self, target, group_id, result):
        """Log valid Group ID to valid results file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.valid_results_log.write(f"\n[{timestamp}] VALID GROUP ID FOUND\n")
        self.valid_results_log.write(f"Target: {target}\n")
        self.valid_results_log.write(f"Group ID: {group_id}\n")
        self.valid_results_log.write(f"Command: ike-scan -M -A --id={group_id} {target}\n")
        
        if result.encryption:
            self.valid_results_log.write(f"Transform Set: Enc={result.encryption}, Hash={result.hash_algorithm}, Group={result.dh_group}, Auth={result.auth_method}\n")
        
        self.valid_results_log.write("\nFull Output:\n")
        if result.raw_output:
            self.valid_results_log.write(result.raw_output + "\n")
        
        self.valid_results_log.write("=" * 80 + "\n")
        self.valid_results_log.flush()
    
    def log_misconfigured_target(self, target, group_id):
        """Log misconfigured target to error log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.error_log.write(f"\n[{timestamp}] MISCONFIGURED TARGET DETECTED\n")
        self.error_log.write(f"Target: {target}\n")
        self.error_log.write(f"Initial Group ID: {group_id}\n")
        self.error_log.write(f"Issue: Target accepts ANY Group ID (false positive)\n")
        self.error_log.write(f"Action: Skipping all remaining tests for this target\n")
        self.error_log.write("=" * 80 + "\n")
        self.error_log.flush()
    
    def display_phase1_summary(self, results, scan_time, total_requests, validation_count=0):
        """Display Phase 1 summary with statistics"""
        print(f"\n\n{self.c.PURPLE}{self.c.BOLD}═══════════════════════════════════════════════════════════")
        print(f"Phase 1 Complete")
        print(f"═══════════════════════════════════════════════════════════{self.c.RESET}\n")
        
        print(f"Scan time: {format_time(scan_time)}")
        
        # Statistics section
        print(f"\n{self.c.BOLD}Scan Statistics:{self.c.RESET}")
        print(f"  Total tests: {total_requests:,}")
        
        valid_count = sum(len(v) for v in results.valid.values())
        print(f"  Valid Group IDs found: {valid_count}")
        print(f"  Validations performed: {validation_count}")
        
        targets_with_valid = len(results.valid)
        print(f"  Targets with valid Group IDs: {targets_with_valid}")
        print(f"  Targets marked unreachable: {len(results.permanently_unreachable)}")
        print(f"  Misconfigured targets: {len(results.misconfigured)}")
        
        suspicious_count = sum(len(v) for v in results.suspicious.values())
        print(f"  Suspicious results: {suspicious_count}")
        
        error_count = sum(len(v) for v in results.errors.values())
        print(f"  Total errors/timeouts: {error_count}")
        
        # Valid Group IDs
        if results.valid:
            print(f"\n{self.c.GREEN}Valid Group IDs: {valid_count}{self.c.RESET}")
            for target, group_ids in results.valid.items():
                for group_id, _ in group_ids:
                    print(f"  {self.c.GREEN}✓{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} : {group_id}")
        
        # Suspicious results
        if results.suspicious:
            print(f"\n{self.c.YELLOW}Suspicious Results: {suspicious_count}{self.c.RESET}")
            for target, group_ids in results.suspicious.items():
                for group_id in group_ids:
                    print(f"  {self.c.YELLOW}⚠{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} : {group_id} {self.c.GRAY}(manual verification needed){self.c.RESET}")
        
        # False positives / Misconfigured targets
        if results.false_positives:
            print(f"\n{self.c.RED}Misconfigured Targets (Accept Any Group ID): {len(results.false_positives)}{self.c.RESET}")
            for target, group_ids in results.false_positives.items():
                count = len(group_ids)
                print(f"  {self.c.RED}✗{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} {self.c.GRAY}(tested {count} ID{'s' if count > 1 else ''} before detection){self.c.RESET}")
        
        # Unreachable targets
        if results.permanently_unreachable:
            print(f"\n{self.c.RED}Unreachable Targets: {len(results.permanently_unreachable)}{self.c.RESET}")
            for target in results.permanently_unreachable:
                print(f"  {self.c.RED}✗{self.c.RESET} {self.c.CYAN}{target}{self.c.RESET} {self.c.GRAY}(timeout/unreachable){self.c.RESET}")
        
        print(f"\n{self.c.BOLD}Output Files:{self.c.RESET}")
        print(f"  All tests: {self.c.CYAN}{self.session_dir}/phase1_full_log.txt{self.c.RESET}")
        if results.valid or results.suspicious:
            print(f"  Valid results: {self.c.GREEN}{self.session_dir}/valid_results.txt{self.c.RESET}")
        if results.false_positives or results.errors or results.permanently_unreachable:
            print(f"  Errors/Misconfigured: {self.c.RED}{self.session_dir}/errors_and_misconfigured.txt{self.c.RESET}")
    
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
