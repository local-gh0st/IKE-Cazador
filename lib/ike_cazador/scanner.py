"""
Scanner - Main scanning orchestration
"""

import time
import random
import asyncio


class ScanResults:
    """Container for all scan results"""
    
    def __init__(self):
        self.valid = {}           # {target: [(group_id, IKEResult), ...]}
        self.false_positives = {} # {target: [group_id, ...]}
        self.suspicious = {}      # {target: [group_id, ...]}
        self.errors = {}          # {target: [(group_id, IKEResult), ...]}
        self.unreachable = set()  # {target, ...}
        self.misconfigured = set() # {target, ...} - accepts ANY Group ID
    
    def add_valid(self, target, group_id, result):
        """Add valid Group ID"""
        if target not in self.valid:
            self.valid[target] = []
        self.valid[target].append((group_id, result))
    
    def add_false_positive(self, target, group_id):
        """Add false positive"""
        if target not in self.false_positives:
            self.false_positives[target] = []
        self.false_positives[target].append(group_id)
    
    def add_suspicious(self, target, group_id):
        """Add suspicious result"""
        if target not in self.suspicious:
            self.suspicious[target] = []
        self.suspicious[target].append(group_id)
    
    def add_error(self, target, group_id, result):
        """Add error"""
        if target not in self.errors:
            self.errors[target] = []
        self.errors[target].append((group_id, result))
    
    def mark_unreachable(self, target):
        """Mark target as unreachable"""
        self.unreachable.add(target)
    
    def is_unreachable(self, target):
        """Check if target is marked unreachable"""
        return target in self.unreachable
    
    def mark_misconfigured(self, target):
        """Mark target as misconfigured (accepts any Group ID)"""
        self.misconfigured.add(target)
    
    def is_misconfigured(self, target):
        """Check if target is marked as misconfigured"""
        return target in self.misconfigured
    
    def get_error_count(self, target):
        """Get error count for target"""
        return len(self.errors.get(target, []))
    
    def has_valid_ids(self):
        """Check if any valid IDs found"""
        return len(self.valid) > 0


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
        
        # Choose scanning mode - run async wrapper
        if self.config.round_robin:
            asyncio.run(self._scan_round_robin_async(targets, wordlist, results))
        else:
            asyncio.run(self._scan_sequential_async(targets, wordlist, results))
        
        # Clear progress line
        if not self.config.quiet:
            print()  # Newline after progress
        
        return results
    
    async def _scan_sequential_async(self, targets, wordlist, results):
        """Sequential mode with conservative parallelism (2x for single target)"""
        for target in targets:
            if results.is_unreachable(target) or results.is_misconfigured(target):
                # Skip this entire target - already marked unreachable or misconfigured
                self.completed_requests += len(wordlist)
                continue
            
            # Process Group IDs in batches of 2 (conservative - won't overwhelm single VPN)
            batch_size = 2
            for i in range(0, len(wordlist), batch_size):
                batch = wordlist[i:i + batch_size]
                
                # Fire batch in parallel
                tasks = [
                    self._test_and_validate_async(target, group_id, results)
                    for group_id in batch
                    if not results.is_misconfigured(target)  # Check before each batch
                ]
                
                if tasks:
                    await asyncio.gather(*tasks)
    
    async def _scan_round_robin_async(self, targets, wordlist, results):
        """Round-robin mode: test all targets in parallel per Group ID"""
        for group_id in wordlist:
            # Determine concurrency limit
            # Max 20 concurrent to avoid CPU overload
            active_targets = [t for t in targets 
                            if not results.is_unreachable(t) 
                            and not results.is_misconfigured(t)]
            
            if not active_targets:
                # All targets skipped, update progress
                self.completed_requests += len(targets)
                continue
            
            # Determine concurrency limit
            config_max = getattr(self.config, 'max_concurrent', None)
            if config_max is None:
                # Auto: use number of active targets (capped at 20)
                max_concurrent = min(len(active_targets), 20)
            else:
                # User specified a limit
                max_concurrent = config_max
            
            # Fire all active targets in parallel (respecting max_concurrent limit)
            tasks = []
            for target in active_targets:
                tasks.append(self._test_and_validate_async(target, group_id, results))
            
            # Execute with concurrency limit
            if max_concurrent >= len(tasks):
                # No limit needed, fire all
                await asyncio.gather(*tasks)
            else:
                # Process in batches to respect max_concurrent
                for i in range(0, len(tasks), max_concurrent):
                    batch = tasks[i:i + max_concurrent]
                    await asyncio.gather(*batch)
            
            # Update progress for any skipped targets
            skipped = len(targets) - len(active_targets)
            self.completed_requests += skipped
    
    def _test_and_validate(self, target, group_id, results):
        """Test a single target+group_id combination"""
        
        # Skip if target already marked unreachable or misconfigured
        if results.is_unreachable(target) or results.is_misconfigured(target):
            self.completed_requests += 1
            return
        
        # Apply jitter if enabled
        if self.config.jitter_enabled:
            self._apply_jitter()
        
        # Update progress
        self.completed_requests += 1
        self._display_progress(current_target=target, current_id=group_id)
        
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
    
    async def _test_and_validate_async(self, target, group_id, results):
        """Async version: Test a single target+group_id combination"""
        
        # Skip if target already marked unreachable or misconfigured
        if results.is_unreachable(target) or results.is_misconfigured(target):
            self.completed_requests += 1
            return
        
        # Apply jitter if enabled (async sleep)
        if self.config.jitter_enabled:
            await self._apply_jitter_async()
        
        # Update progress
        self.completed_requests += 1
        self._display_progress(current_target=target, current_id=group_id)
        
        # Execute ike-scan test (async)
        result = await self.ike_tester.test_group_id_async(
            target, 
            group_id, 
            port=self.config.port
        )
        
        # Log to file
        self.output.log_test(target, group_id, result)
        
        # Handle result
        if result.status == 'VALID':
            await self._handle_valid_result_async(target, group_id, result, results)
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
            self.output.log_valid_result(target, group_id, result)
        elif validation_result == 'FALSE_POSITIVE':
            results.add_false_positive(target, group_id)
            results.mark_misconfigured(target)  # Skip all remaining tests for this target
            self.output.display_false_positive(target, group_id)
            self.output.log_misconfigured_target(target, group_id)
            self.output.display_target_skipped(target, "misconfigured")
        elif validation_result == 'SUSPICIOUS':
            results.add_suspicious(target, group_id)
            self.output.display_suspicious(target, group_id)
            self.output.log_valid_result(target, group_id, result)  # Log suspicious as well
        
        # Resume progress display
        print()  # Newline after validation
    
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
    
    async def _apply_jitter_async(self):
        """Async version: Apply randomized delay for stealth"""
        # Base delay: 500ms, Jitter: ±200ms (300-700ms range)
        base_delay = 0.5
        jitter = random.uniform(-0.2, 0.2)
        actual_delay = base_delay + jitter
        await asyncio.sleep(actual_delay)
    
    async def _handle_valid_result_async(self, target, group_id, result, results):
        """Async version: Handle potential valid Group ID"""
        self.output.display_potential_valid(target, group_id)
        
        # Run validation module (async)
        validation_result = await self.validator.validate_async(
            target, 
            group_id, 
            self.config
        )
        
        if validation_result == 'TRUE_POSITIVE':
            results.add_valid(target, group_id, result)
            self.output.display_true_positive(target, group_id)
            self.output.log_valid_result(target, group_id, result)
        elif validation_result == 'FALSE_POSITIVE':
            results.add_false_positive(target, group_id)
            results.mark_misconfigured(target)  # Skip all remaining tests for this target
            self.output.display_false_positive(target, group_id)
            self.output.log_misconfigured_target(target, group_id)
            self.output.display_target_skipped(target, "misconfigured")
        elif validation_result == 'SUSPICIOUS':
            results.add_suspicious(target, group_id)
            self.output.display_suspicious(target, group_id)
            self.output.log_valid_result(target, group_id, result)  # Log suspicious as well
        
        # Resume progress display
        print()  # Newline after validation
    
    def _display_progress(self, current_target=None, current_id=None):
        """Display progress with ETA"""
        percentage = (self.completed_requests / self.total_requests) * 100
        
        # Calculate ETA
        elapsed = time.time() - self.start_time
        if self.completed_requests > 0:
            avg_time_per_request = elapsed / self.completed_requests
            remaining_requests = self.total_requests - self.completed_requests
            eta_seconds = avg_time_per_request * remaining_requests
        else:
            eta_seconds = 0
        
        self.output.display_progress(
            self.completed_requests,
            self.total_requests,
            percentage,
            eta_seconds,
            current_target,
            current_id
        )
