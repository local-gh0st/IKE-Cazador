# IKE-CAZADOR - Technical Design Document

**Version:** 1.0.0  
**Last Updated:** March 31, 2026  
**Status:** Design Phase - Ready for Implementation

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Component Specifications](#component-specifications)
4. [Data Structures](#data-structures)
5. [Algorithms](#algorithms)
6. [ike-scan Integration](#ike-scan-integration)
7. [Phase 1: Group ID Discovery](#phase-1-group-id-discovery)
8. [Phase 2: PSK Hash Capture](#phase-2-psk-hash-capture)
9. [Validation Module](#validation-module)
10. [Error Handling](#error-handling)
11. [Output & Logging](#output--logging)
12. [CLI Specification](#cli-specification)
13. [Color Scheme](#color-scheme)
14. [File Organization](#file-organization)
15. [Testing Strategy](#testing-strategy)
16. [Implementation Roadmap](#implementation-roadmap)

---

## Executive Summary

### Purpose
IKE-CAZADOR is a professional penetration testing tool designed to discover valid VPN Group IDs through enumeration of IKE/IPsec VPN endpoints configured with Aggressive Mode. The tool provides accurate, reliable results with robust false positive detection and comprehensive logging suitable for security assessments and client reports.

### Key Features
- **Two-Phase Operation:** Group ID discovery followed by optional PSK hash capture
- **False Positive Detection:** Statistical validation using random junk strings
- **Multi-Target Support:** Efficient scanning of enterprise-scale networks
- **Stealth Features:** Jitter timing and round-robin request distribution
- **Professional Output:** Color-coded terminal display with comprehensive logging

### Design Philosophy
1. **Accuracy over speed** - Zero tolerance for false positives
2. **Transparency over magic** - Clear confidence indicators and validation details
3. **Production quality** - Suitable for professional security engagements
4. **Maintainability** - Clean, modular architecture for future enhancements

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ike-cazador.py                           │
│                      (Main Entry Point)                         │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ├─► Startup Checks
                     │   ├─ Root privilege check
                     │   ├─ ike-scan dependency check
                     │   ├─ TMUX session detection
                     │   └─ Wordlist existence check
                     │
                     ├─► Phase 1: Group ID Discovery
                     │   │
                     │   ├─► Scanner Module
                     │   │   ├─ Sequential mode
                     │   │   ├─ Round-robin mode
                     │   │   └─ Jitter timing
                     │   │
                     │   ├─► IKE Tester
                     │   │   ├─ ike-scan execution
                     │   │   ├─ Response parsing
                     │   │   └─ Timeout handling
                     │   │
                     │   └─► Validator
                     │       ├─ Random junk generation
                     │       ├─ Statistical validation
                     │       └─ Confidence scoring
                     │
                     ├─► Phase 2: PSK Capture (Optional)
                     │   ├─ User prompt
                     │   ├─ Full handshake capture with -P flag
                     │   ├─ Transform set extraction
                     │   └─ Next-step command generation
                     │
                     └─► Output System
                         ├─ Terminal display (colored)
                         ├─ Session logs
                         ├─ Error logs
                         └─ Results summary
```

### Module Breakdown

```
ike-cazador/
├── ike-cazador.py              # Main executable
│
└── lib/
    └── ike_cazador/
        ├── __init__.py         # Package initialization
        ├── ike_tester.py       # ike-scan wrapper and parser
        ├── scanner.py          # Main scanning orchestration
        ├── validator.py        # False positive detection
        ├── output.py           # Terminal display and logging
        └── utils.py            # Shared utilities (colors, helpers)
```

---

## Component Specifications

### 1. Main Entry Point (`ike-cazador.py`)

**Responsibilities:**
- Parse command-line arguments
- Perform startup checks (root, dependencies, tmux)
- Display banner
- Initialize components
- Execute Phase 1 and Phase 2
- Handle graceful shutdown

**Interface:**
```python
def main():
    """Main entry point"""
    # Parse arguments
    args = parse_arguments()
    
    # Startup checks
    check_root_privileges()
    check_ike_scan_installed()
    check_tmux_session()
    check_wordlist_exists(args.wordlist)
    
    # Display banner
    display_banner()
    
    # Phase 1: Group ID Discovery
    results = run_phase1(args)
    
    # Phase 2: PSK Capture (if valid IDs found)
    if results.has_valid_ids():
        if prompt_phase2():
            run_phase2(results, args)
    
    # Display summary and exit
    display_final_summary(results)
```

---

### 2. IKE Tester (`lib/ike_cazador/ike_tester.py`)

**Responsibilities:**
- Execute ike-scan subprocess with timeout
- Parse ike-scan output
- Determine validity of Group ID
- Extract transform set details
- Handle errors and timeouts

**Interface:**
```python
class IKETester:
    """Wrapper for ike-scan command execution and parsing"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.ike_scan_path = self._find_ike_scan()
    
    def test_group_id(self, target, group_id, port=500):
        """
        Test a single Group ID against a target
        
        Returns:
            IKEResult object with validity status and details
        """
        output, status = self._execute_ike_scan(target, group_id, port)
        return self._parse_output(output, status)
    
    def capture_psk(self, target, group_id, output_file, port=500):
        """
        Capture full PSK handshake with -P flag for Phase 2
        
        Returns:
            IKEResult object with transform set and PSK parameters
        """
        output, status = self._execute_ike_scan_with_psk(
            target, group_id, port, output_file
        )
        return self._parse_output(output, status)
    
    def _execute_ike_scan(self, target, group_id, port):
        """Execute ike-scan subprocess with timeout"""
        cmd = ['ike-scan', '-M', '-A', f'--id={group_id}']
        if port != 500:
            cmd.extend(['--dport', str(port)])
        cmd.append(target)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True
            )
            return result.stdout, result.returncode
        except subprocess.TimeoutExpired:
            return None, 'TIMEOUT'
        except Exception as e:
            return None, f'ERROR: {str(e)}'
    
    def _parse_output(self, output, status):
        """Parse ike-scan output to determine validity and extract details"""
        result = IKEResult()
        
        if status == 'TIMEOUT':
            result.status = 'TIMEOUT'
            return result
        
        if status != 0 and not isinstance(status, int):
            result.status = 'ERROR'
            result.error_message = status
            return result
        
        if output is None:
            result.status = 'ERROR'
            result.error_message = 'No output received'
            return result
        
        # Check for invalid responses
        if 'NO-PROPOSAL-CHOSEN' in output:
            result.status = 'INVALID'
            result.error_type = 'NO-PROPOSAL-CHOSEN'
            return result
        
        if '0 returned handshake' in output:
            result.status = 'INVALID'
            result.error_type = 'NO_HANDSHAKE'
            return result
        
        # Check for valid handshake
        if 'Aggressive Mode Handshake returned' in output and \
           '1 returned handshake' in output:
            result.status = 'VALID'
            result.raw_output = output
            
            # Extract transform set details
            self._extract_transform_set(output, result)
            
            # Extract PSK parameters if present (Phase 2 with -P flag)
            self._extract_psk_parameters(output, result)
        
        return result
    
    def _extract_transform_set(self, output, result):
        """Extract transform set from SA line"""
        # Pattern: SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)
        pattern = r'SA=\(Enc=(\S+)\s+Hash=(\S+)\s+Group=([^\s]+)\s+Auth=(\S+)'
        match = re.search(pattern, output)
        
        if match:
            result.encryption = match.group(1)
            result.hash_algorithm = match.group(2)
            result.dh_group = match.group(3)
            result.auth_method = match.group(4)
    
    def _extract_psk_parameters(self, output, result):
        """Extract PSK parameters line if present"""
        # Pattern: IKE PSK parameters ...: <hex_string>
        pattern = r'IKE PSK parameters[^:]*:\s*(\S+)'
        match = re.search(pattern, output, re.DOTALL)
        
        if match:
            result.psk_parameters = match.group(1).strip()
```

**Data Structure:**
```python
class IKEResult:
    """Result from ike-scan test"""
    
    def __init__(self):
        self.status = None          # 'VALID', 'INVALID', 'TIMEOUT', 'ERROR'
        self.raw_output = None      # Full ike-scan output
        self.error_type = None      # 'NO-PROPOSAL-CHOSEN', 'NO_HANDSHAKE', etc.
        self.error_message = None   # Error details
        
        # Transform set details (if valid)
        self.encryption = None      # '3DES', 'AES-256', etc.
        self.hash_algorithm = None  # 'MD5', 'SHA1', 'SHA256', etc.
        self.dh_group = None        # '2:modp1024', '14:modp2048', etc.
        self.auth_method = None     # 'PSK', 'RSA', etc.
        
        # PSK capture details (Phase 2 with -P flag)
        self.psk_parameters = None  # Full hex string for cracking
```

---

### 3. Scanner Module (`lib/ike_cazador/scanner.py`)

**Responsibilities:**
- Orchestrate multi-target, multi-wordlist scanning
- Implement sequential and round-robin modes
- Apply jitter timing when enabled
- Track progress and calculate ETA
- Coordinate with validator for suspicious results

**Interface:**
```python
class Scanner:
    """Main scanning orchestration"""
    
    def __init__(self, ike_tester, validator, output_handler, config):
        self.ike_tester = ike_tester
        self.validator = validator
        self.output = output_handler
        self.config = config
        
        self.start_time = None
        self.completed_requests = 0
        self.total_requests = 0
    
    def scan(self, targets, wordlist):
        """
        Execute Phase 1 Group ID discovery
        
        Args:
            targets: List of target IPs/hostnames
            wordlist: List of Group IDs to test
        
        Returns:
            ScanResults object
        """
        self.start_time = time.time()
        self.total_requests = len(targets) * len(wordlist)
        
        results = ScanResults()
        
        # Choose scanning mode
        if self.config.round_robin:
            self._scan_round_robin(targets, wordlist, results)
        else:
            self._scan_sequential(targets, wordlist, results)
        
        return results
    
    def _scan_sequential(self, targets, wordlist, results):
        """Sequential mode: test all IDs against target1, then target2, etc."""
        for target in targets:
            for group_id in wordlist:
                self._test_and_validate(target, group_id, results)
    
    def _scan_round_robin(self, targets, wordlist, results):
        """Round-robin mode: test ID1 against all targets, then ID2, etc."""
        for group_id in wordlist:
            for target in targets:
                self._test_and_validate(target, group_id, results)
    
    def _test_and_validate(self, target, group_id, results):
        """Test a single target+group_id combination"""
        
        # Skip if target already marked unreachable
        if results.is_unreachable(target):
            return
        
        # Apply jitter if enabled
        if self.config.jitter_enabled:
            self._apply_jitter()
        
        # Update progress
        self.completed_requests += 1
        self._display_progress()
        
        # Execute ike-scan test
        result = self.ike_tester.test_group_id(
            target, 
            group_id, 
            port=self.config.port
        )
        
        # Log to file
        self.output.log_test(target, group_id, result)
        
        # Handle result
        if result.status == 'VALID':
            self._handle_valid_result(target, group_id, result, results)
        elif result.status in ['TIMEOUT', 'ERROR']:
            self._handle_error_result(target, group_id, result, results)
        # INVALID results are just logged, no action needed
    
    def _handle_valid_result(self, target, group_id, result, results):
        """Handle potential valid Group ID"""
        self.output.display_potential_valid(target, group_id)
        
        # Run validation module
        validation_result = self.validator.validate(
            target, 
            group_id, 
            self.config
        )
        
        if validation_result == 'TRUE_POSITIVE':
            results.add_valid(target, group_id, result)
            self.output.display_true_positive(target, group_id)
        elif validation_result == 'FALSE_POSITIVE':
            results.add_false_positive(target, group_id)
            self.output.display_false_positive(target, group_id)
        elif validation_result == 'SUSPICIOUS':
            results.add_suspicious(target, group_id)
            self.output.display_suspicious(target, group_id)
    
    def _handle_error_result(self, target, group_id, result, results):
        """Handle timeout or error"""
        results.add_error(target, group_id, result)
        self.output.log_error(target, group_id, result)
        
        # If multiple consecutive errors for same target, mark unreachable
        if results.get_error_count(target) >= 3:
            results.mark_unreachable(target)
            self.output.display_unreachable(target)
    
    def _apply_jitter(self):
        """Apply randomized delay for stealth"""
        # Base delay: 500ms, Jitter: ±200ms (300-700ms range)
        base_delay = 0.5
        jitter = random.uniform(-0.2, 0.2)
        actual_delay = base_delay + jitter
        time.sleep(actual_delay)
    
    def _display_progress(self):
        """Display progress with ETA"""
        percentage = (self.completed_requests / self.total_requests) * 100
        
        # Calculate ETA
        elapsed = time.time() - self.start_time
        avg_time_per_request = elapsed / self.completed_requests
        remaining_requests = self.total_requests - self.completed_requests
        eta_seconds = avg_time_per_request * remaining_requests
        
        self.output.display_progress(
            self.completed_requests,
            self.total_requests,
            percentage,
            eta_seconds
        )
```

**Data Structure:**
```python
class ScanResults:
    """Container for all scan results"""
    
    def __init__(self):
        self.valid = {}           # {target: [(group_id, IKEResult), ...]}
        self.false_positives = {} # {target: [group_id, ...]}
        self.suspicious = {}      # {target: [group_id, ...]}
        self.errors = {}          # {target: [(group_id, IKEResult), ...]}
        self.unreachable = set()  # {target, ...}
    
    def add_valid(self, target, group_id, result):
        if target not in self.valid:
            self.valid[target] = []
        self.valid[target].append((group_id, result))
    
    def has_valid_ids(self):
        return len(self.valid) > 0
    
    def is_unreachable(self, target):
        return target in self.unreachable
    
    def get_error_count(self, target):
        return len(self.errors.get(target, []))
    
    # ... additional helper methods
```

---

### 4. Validator Module (`lib/ike_cazador/validator.py`)

**Responsibilities:**
- Generate random junk strings for validation testing
- Execute validation tests against suspected valid Group IDs
- Determine confidence level (true positive, false positive, suspicious)
- Display validation progress

**Interface:**
```python
class Validator:
    """False positive detection through random validation"""
    
    def __init__(self, ike_tester, output_handler):
        self.ike_tester = ike_tester
        self.output = output_handler
        
        # Validation parameters
        self.num_tests = 5          # Test 5 random IDs
        self.junk_length = 15       # 15 characters of random junk
        self.fp_threshold = 3       # 3+ successes = false positive
        self.suspicious_threshold = 2  # 2 successes = suspicious
    
    def validate(self, target, suspected_group_id, config):
        """
        Validate a suspected valid Group ID
        
        Returns:
            'TRUE_POSITIVE', 'FALSE_POSITIVE', or 'SUSPICIOUS'
        """
        self.output.display_validation_start(target, suspected_group_id)
        
        # Generate random test IDs
        test_ids = self._generate_test_ids(suspected_group_id, self.num_tests)
        
        valid_count = 0
        
        for i, test_id in enumerate(test_ids, 1):
            self.output.display_validation_test(i, self.num_tests, test_id, target)
            
            result = self.ike_tester.test_group_id(
                target,
                test_id,
                port=config.port
            )
            
            if result.status == 'VALID':
                valid_count += 1
                self.output.display_validation_test_result(test_id, valid=True)
            else:
                self.output.display_validation_test_result(test_id, valid=False)
        
        # Determine confidence
        if valid_count >= self.fp_threshold:
            # 3+ random IDs succeeded = false positive
            self.output.display_validation_failed(valid_count, self.num_tests)
            return 'FALSE_POSITIVE'
        elif valid_count >= self.suspicious_threshold:
            # 2 random IDs succeeded = suspicious
            self.output.display_validation_suspicious(valid_count, self.num_tests)
            return 'SUSPICIOUS'
        else:
            # 0-1 random IDs succeeded = true positive
            self.output.display_validation_passed()
            return 'TRUE_POSITIVE'
    
    def _generate_test_ids(self, suspected_id, count):
        """
        Generate test IDs by appending random junk to suspected ID
        
        Example: "admin" -> ["admin_k3h5lm9xz4p8q2w", "admin_9z8x7c6v5b4n3m2", ...]
        """
        import string
        
        test_ids = []
        for _ in range(count):
            junk = ''.join(random.choices(
                string.ascii_lowercase + string.digits,
                k=self.junk_length
            ))
            test_ids.append(f"{suspected_id}_{junk}")
        
        return test_ids
```

---

### 5. Output Handler (`lib/ike_cazador/output.py`)

**Responsibilities:**
- Display formatted terminal output with colors
- Log all tests to session log files
- Log errors to separate error log
- Generate final summary
- Create next-step commands for Phase 2

**Key Methods:**
```python
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
    
    def display_banner(self):
        """Display ASCII banner"""
        banner = f"""
{self.c.PURPLE}{self.c.BOLD}═══════════════════════════════════════════════════════════
  IKE-CAZADOR | VPN Group ID Discovery Tool
  Version 1.0.0 | IKE Aggressive Mode Enumeration
═══════════════════════════════════════════════════════════{self.c.RESET}
"""
        print(banner)
    
    def display_progress(self, completed, total, percentage, eta_seconds):
        """Display progress bar with ETA"""
        if self.quiet:
            return
        
        eta_str = self._format_time(eta_seconds)
        print(f"\r[*] Progress: {completed}/{total} ({percentage:.1f}%) - ETA: {eta_str}", end='', flush=True)
    
    def display_potential_valid(self, target, group_id):
        """Display when potential valid Group ID found"""
        msg = f"\n{self.c.GREEN}[+]{self.c.RESET} Potential valid: {self.c.CYAN}{target}{self.c.RESET} + {self.c.CYAN}\"{group_id}\"{self.c.RESET}"
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
    
    # ... additional display and logging methods
```

---

## Data Structures

### Configuration Object
```python
class Config:
    """Configuration for the scan"""
    
    def __init__(self, args):
        self.targets = self._parse_targets(args.target)
        self.wordlist = self._load_wordlist(args.wordlist)
        self.port = args.port
        self.jitter_enabled = args.jitter
        self.round_robin = args.rotate
        self.verbose = args.verbose
        self.quiet = args.quiet
        self.timeout = 10  # seconds
        
        # Create session directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = f"captures/scan_{timestamp}"
        os.makedirs(self.session_dir, exist_ok=True)
    
    def _parse_targets(self, target_input):
        """Parse target input (single IP/URL or file)"""
        if os.path.isfile(target_input):
            with open(target_input, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            return [target_input]
    
    def _load_wordlist(self, wordlist_path):
        """Load Group ID wordlist"""
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
```

---

## Algorithms

### Main Scanning Algorithm (Pseudocode)

```
FUNCTION run_phase1(config):
    scanner = Scanner(ike_tester, validator, output, config)
    results = scanner.scan(config.targets, config.wordlist)
    RETURN results

FUNCTION Scanner.scan(targets, wordlist):
    total_requests = len(targets) × len(wordlist)
    results = ScanResults()
    
    IF round_robin_mode:
        FOR EACH group_id IN wordlist:
            FOR EACH target IN targets:
                test_and_validate(target, group_id, results)
    ELSE:
        FOR EACH target IN targets:
            FOR EACH group_id IN wordlist:
                test_and_validate(target, group_id, results)
    
    RETURN results

FUNCTION test_and_validate(target, group_id, results):
    # Skip unreachable targets
    IF target IN results.unreachable:
        RETURN
    
    # Apply jitter if enabled
    IF jitter_enabled:
        sleep(random(300ms, 700ms))
    
    # Execute ike-scan
    result = ike_tester.test_group_id(target, group_id)
    
    # Log to file
    log_test(target, group_id, result)
    
    # Handle result based on status
    IF result.status == 'VALID':
        display("Potential valid found")
        
        # Run validation module
        validation = validator.validate(target, group_id)
        
        IF validation == 'TRUE_POSITIVE':
            results.add_valid(target, group_id)
            display("TRUE POSITIVE - validated")
        ELSE IF validation == 'FALSE_POSITIVE':
            results.add_false_positive(target, group_id)
            display("FALSE POSITIVE - misconfigured VPN")
        ELSE IF validation == 'SUSPICIOUS':
            results.add_suspicious(target, group_id)
            display("SUSPICIOUS - manual verification needed")
    
    ELSE IF result.status IN ['TIMEOUT', 'ERROR']:
        results.add_error(target, group_id, result)
        log_error(target, group_id, result)
        
        # Mark unreachable after 3 consecutive errors
        IF error_count(target) >= 3:
            results.mark_unreachable(target)
            display("Target unreachable")
    
    # 'INVALID' status - just logged, no action
```

### Validation Algorithm (Pseudocode)

```
FUNCTION Validator.validate(target, suspected_group_id):
    # Generate 5 random test IDs
    test_ids = []
    FOR i = 1 TO 5:
        random_junk = generate_random_string(15 chars)
        test_id = suspected_group_id + "_" + random_junk
        test_ids.append(test_id)
    
    # Test each random ID
    valid_count = 0
    FOR EACH test_id IN test_ids:
        result = ike_tester.test_group_id(target, test_id)
        display_validation_test(test_id, result)
        
        IF result.status == 'VALID':
            valid_count += 1
    
    # Determine confidence
    IF valid_count >= 3:
        # 3+ random IDs succeeded = false positive
        RETURN 'FALSE_POSITIVE'
    ELSE IF valid_count >= 2:
        # 2 random IDs succeeded = suspicious
        RETURN 'SUSPICIOUS'
    ELSE:
        # 0-1 random IDs succeeded = true positive
        RETURN 'TRUE_POSITIVE'
```

---

## ike-scan Integration

### Command Format

**Phase 1 (Group ID Discovery):**
```bash
ike-scan -M -A --id=<GROUP_ID> <TARGET>
```

**Phase 2 (PSK Capture):**
```bash
ike-scan -M -A --id=<GROUP_ID> -P <TARGET> > output.txt
```

**Flags:**
- `-M`: Multiline output (human-readable)
- `-A`: Aggressive Mode
- `--id=<GROUP_ID>`: Specify Group ID to test
- `-P`: Save IKE PSK parameters (Phase 2 only)
- `--dport <PORT>`: Custom destination port (default 500)

### Output Parsing Patterns

**Pattern 1: Invalid Group ID**
```
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
107.0.208.129    Notify message 14 (NO-PROPOSAL-CHOSEN)
    HDR=(CKY-R=77bcea5a71d9e550)
Ending ike-scan 1.9.6: 1 hosts scanned in 0.049 seconds (20.35 hosts/sec). 0 returned handshake; 1 returned notify
```

**Detection:**
- Contains "NO-PROPOSAL-CHOSEN" OR
- Contains "0 returned handshake"
- **Result:** INVALID

**Pattern 2: Valid Group ID (Minimal)**
```
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
61.145.159.170    Aggressive Mode Handshake returned
Ending ike-scan 1.9.6: 1 hosts scanned in 0.244 seconds (4.10 hosts/sec). 1 returned handshake; 0 returned notify
```

**Detection:**
- Contains "Aggressive Mode Handshake returned" AND
- Contains "1 returned handshake"
- **Result:** VALID

**Pattern 3: Valid with Transform Set (Phase 2)**
```
12.0.69.106    Aggressive Mode Handshake returned
    HDR=(CKY-R=8745394141c96e4c)
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    KeyExchange(128 bytes)
    Nonce(20 bytes)
    ID(Type=ID_FQDN, Value=18B1693509D0)
    VID=404bf439522ca3f6 (SonicWall-a)
    VID=5b362bc820f60007 (SonicWall-7)
    Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
<long hex string>
```

**Extraction:**
- **Transform Set:** `SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)`
  - Encryption: 3DES
  - Hash Algorithm: SHA1
  - DH Group: 2:modp1024
  - Auth Method: PSK
- **PSK Parameters:** Full hex string after "IKE PSK parameters"

**Regex Patterns:**
```python
# Transform set extraction
transform_pattern = r'SA=\(Enc=(\S+)\s+Hash=(\S+)\s+Group=([^\s]+)\s+Auth=(\S+)'

# PSK parameters extraction
psk_pattern = r'IKE PSK parameters[^:]*:\s*(\S+)'
```

### Hash Algorithm to Hashcat Mode Mapping

```python
HASH_TO_HASHCAT = {
    'MD5': 5300,    # IKE-PSK MD5
    'SHA': 5400,    # Sometimes shows as SHA
    'SHA1': 5400,   # IKE-PSK SHA1
    'SHA256': None, # Check hashcat documentation
    'SHA384': None,
    'SHA512': None,
}
```

---

## Phase 1: Group ID Discovery

### Workflow

```
1. Startup
   ├─ Check root privileges
   ├─ Check ike-scan installed
   ├─ Check TMUX session (warn if not)
   ├─ Verify wordlist exists
   └─ Display banner

2. Configuration Display
   ├─ Show number of targets
   ├─ Show wordlist size
   ├─ Show mode (sequential/round-robin)
   ├─ Show jitter status
   └─ Show port

3. Scanning Loop
   FOR EACH target+group_id combination:
       ├─ Execute ike-scan
       ├─ Parse result
       ├─ Log to file
       ├─ IF VALID:
       │   ├─ Display potential valid
       │   ├─ Pause scanning
       │   ├─ Run validation module
       │   ├─ Determine confidence
       │   └─ Resume scanning
       ├─ IF ERROR/TIMEOUT:
       │   ├─ Log error
       │   └─ Check if target unreachable
       └─ Update progress

4. Phase 1 Summary
   ├─ Display scan duration
   ├─ Show valid Group IDs (by target)
   ├─ Show false positives
   ├─ Show suspicious results
   ├─ Show unreachable targets
   └─ Show path to logs
```

---

## Phase 2: PSK Hash Capture

### Workflow

```
1. Check if Valid IDs Found
   IF no valid IDs:
       ├─ Display "No valid Group IDs found"
       ├─ Suggest trying different wordlist
       └─ EXIT
   
   ELSE:
       CONTINUE to Phase 2 prompt

2. Display Next Steps
   ├─ Show all valid Group IDs
   ├─ Generate ike-scan commands for each
   └─ Display commands

3. Prompt User
   "Would you like this tool to run these commands automatically? [Y/n]: "
   
   IF user says 'n':
       ├─ Display "Commands shown above for manual execution"
       └─ EXIT
   
   IF user says 'Y' (default):
       CONTINUE to automatic capture

4. Automatic PSK Capture
   FOR EACH target + valid_group_id:
       ├─ Display capture starting
       ├─ Show command being executed
       ├─ Execute: ike-scan -M -A --id=<ID> -P <TARGET> > output.txt
       ├─ Display full ike-scan output to terminal
       ├─ Parse transform set
       ├─ Parse hash algorithm
       ├─ Display transform set details
       ├─ Display hash algorithm
       ├─ Display where saved
       └─ Log everything to file

5. Phase 2 Summary
   ├─ Display all captures completed
   ├─ Show session directory
   └─ Generate hashcat commands with correct modes
```

---

## Validation Module

### Statistical Approach

**Hypothesis:** A properly configured VPN should have only 1-2 valid Group IDs, not accept arbitrary strings.

**Method:** Append random junk to suspected valid Group ID and test if VPN still accepts it.

**Example:**
- Suspected valid: `admin`
- Test IDs: `admin_k3h5lm9xz4p8q2w`, `admin_9z8x7c6v5b4n3m2`, etc.
- If these succeed → VPN accepts anything (misconfigured)

### Validation Parameters

```python
NUM_VALIDATION_TESTS = 5       # Test 5 random IDs
JUNK_LENGTH = 15               # 15 chars of random alphanumeric
FALSE_POSITIVE_THRESHOLD = 3   # 3+ successes = false positive
SUSPICIOUS_THRESHOLD = 2       # 2 successes = suspicious
```

### Confidence Levels

| Valid Count | Result | Meaning |
|------------|---------|---------|
| 0-1 | TRUE_POSITIVE | High confidence - validated |
| 2 | SUSPICIOUS | Medium confidence - manual verification recommended |
| 3+ | FALSE_POSITIVE | VPN misconfigured - accepts any Group ID |

---

## Error Handling

### Error Categories

1. **Network Errors**
   - Target unreachable
   - Timeout (no response after 10s)
   - Connection refused

2. **ike-scan Errors**
   - ike-scan not installed
   - ike-scan crashes
   - Permission denied (not root)

3. **Invalid Input**
   - Invalid IP/hostname
   - Wordlist not found
   - Invalid port number

### Error Handling Strategy

**Startup Errors (Fatal):**
```python
# Exit gracefully with helpful message
if not is_root():
    print("[!] Error: This tool requires root privileges")
    print("[!] ike-scan needs raw socket access for IKE testing")
    print("[!] Please run again with sudo:")
    print(f"    sudo {' '.join(sys.argv)}")
    sys.exit(1)
```

**Runtime Errors (Non-Fatal):**
```python
# Log error, skip this test, continue with remaining
try:
    result = ike_tester.test_group_id(target, group_id)
except Exception as e:
    log_error(target, group_id, str(e))
    continue  # Move to next test
```

**Target Unreachable (Skip Target):**
```python
# After 3 consecutive errors for same target, mark unreachable
if error_count(target) >= 3:
    results.mark_unreachable(target)
    print(f"[!] {target} unreachable - skipping remaining tests")
    continue  # Skip to next target
```

---

## Output & Logging

### Session Directory Structure

```
captures/
└── scan_20260331_143000/
    ├── phase1_results.txt          # Human-readable summary
    ├── phase1_full_log.txt         # Every command + response
    ├── errors.txt                  # All errors with timestamps
    ├── 192.168.1.3_admin.txt       # PSK capture (Phase 2)
    ├── 192.168.1.5_vpn.txt         # PSK capture (Phase 2)
    └── summary.txt                 # Final report with next steps
```

---

## CLI Specification

### Command Format

```bash
ike-cazador.py <target> [wordlist] [options]
```

### Positional Arguments

```
target          Single IP, hostname, or path to file with targets (one per line)
wordlist        Path to Group ID wordlist (optional, defaults to bundled wordlist)
```

### Optional Arguments

```
-p, --port PORT         Destination port (default: 500)
-j, --jitter            Enable jitter timing (500ms ±200ms delay)
-r, --rotate            Round-robin mode (rotate between targets)
-v, --verbose           Verbose output (show all ike-scan commands)
-q, --quiet             Quiet mode (minimal output)
--no-color              Disable colored output
--timeout SECONDS       ike-scan timeout in seconds (default: 10)
-h, --help              Show help message
--version               Show version
```

### Usage Examples

```bash
# Single target with default wordlist
sudo ./ike-cazador.py 192.168.1.1

# Multiple targets with custom wordlist
sudo ./ike-cazador.py targets.txt custom_wordlist.txt

# With jitter and round-robin for stealth
sudo ./ike-cazador.py targets.txt -j -r

# Custom port
sudo ./ike-cazador.py 192.168.1.1 -p 4500

# Quiet mode for automation
sudo ./ike-cazador.py targets.txt -q
```

---

## Color Scheme

### Color Definitions (OpenCode Style)

```python
class Colors:
    """ANSI color codes matching OpenCode palette"""
    
    # Primary colors (soft, visible on black)
    PURPLE = '\033[38;5;141m'      # Headers, section separators
    CYAN = '\033[38;5;117m'        # Technical identifiers (IPs, Group IDs, commands)
    ORANGE = '\033[38;5;215m'      # Warnings, important notes
    GREEN = '\033[38;5;114m'       # Success, valid results
    RED = '\033[38;5;203m'         # Errors, false positives
    YELLOW = '\033[38;5;221m'      # Suspicious status
    GRAY = '\033[38;5;246m'        # Secondary info, comments
    WHITE = '\033[97m'             # Normal text (default)
    
    # Formatting
    BOLD = '\033[1m'               # Bold text
    DIM = '\033[2m'                # Dim text
    RESET = '\033[0m'              # Reset to default
```

### Color Usage Guidelines

- **Most text should be normal/white**
- **PURPLE + BOLD:** Major phase headers only
- **GREEN:** Success indicators (`[+]`, `✓`)
- **RED:** Error indicators (`[!]`, `✗`)
- **CYAN:** Technical identifiers (IPs, Group IDs, commands)
- **GRAY:** Secondary information

---

## File Organization

### Project Structure

```
ike-cazador/
├── ike-cazador.py                      # Main executable
├── README.md                           # User documentation
├── TECHNICAL_DESIGN.md                 # This document
├── LICENSE                             # License file
│
├── wordlists/
│   └── group-id-wordlist.txt           # Default 450 Group IDs
│
├── lib/
│   └── ike_cazador/
│       ├── __init__.py
│       ├── ike_tester.py               # ike-scan wrapper
│       ├── scanner.py                  # Scanning orchestration
│       ├── validator.py                # False positive detection
│       ├── output.py                   # Display and logging
│       └── utils.py                    # Shared utilities
│
├── captures/                           # Generated at runtime (gitignored)
└── tests/                              # Unit tests (future)
```

---

## Testing Strategy

### Unit Tests

1. **IKE Tester Tests:**
   - Mock ike-scan subprocess calls
   - Test parsing of valid handshake
   - Test parsing of invalid responses
   - Test timeout handling

2. **Validator Tests:**
   - Test random ID generation
   - Test confidence scoring logic

3. **Scanner Tests:**
   - Test sequential mode
   - Test round-robin mode
   - Test jitter timing

---

## Implementation Roadmap

### Phase 1: Core Infrastructure (Week 1)
- Project structure setup
- CLI argument parsing
- Startup checks
- Banner display
- Config object

### Phase 2: IKE Tester (Week 1-2)
- ike-scan subprocess execution
- Output parsing
- Transform set extraction
- Error handling

### Phase 3: Scanner Module (Week 2)
- Sequential/round-robin modes
- Jitter timing
- Progress tracking

### Phase 4: Validator Module (Week 2-3)
- Random string generation
- Validation logic
- Confidence scoring

### Phase 5: Output System (Week 3)
- Terminal display with colors
- Logging system

### Phase 6: Phase 1 Integration (Week 3-4)
- Full workflow
- Testing

### Phase 7: Phase 2 Implementation (Week 4)
- PSK capture
- Command generation

### Phase 8: Testing & Polish (Week 4-5)
- Integration testing
- Documentation

---

## Success Criteria

### Must Have
✅ Accurate Group ID discovery  
✅ Multi-target support  
✅ False positive detection  
✅ Professional output  
✅ Comprehensive logging  

### Should Have
✅ PSK hash capture  
✅ Transform set extraction  
✅ Stealth features (jitter, round-robin)  

---

**END OF TECHNICAL DESIGN DOCUMENT**
