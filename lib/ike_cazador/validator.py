"""
Validator - False positive detection through random validation
"""

import random
import string
import asyncio


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
            
            # Log validation test
            self.output.log_test(target, test_id, result)
            
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
        test_ids = []
        for _ in range(count):
            junk = ''.join(random.choices(
                string.ascii_lowercase + string.digits,
                k=self.junk_length
            ))
            test_ids.append(f"{suspected_id}_{junk}")
        
        return test_ids
    
    async def validate_async(self, target, suspected_group_id, config):
        """
        Async version: Validate a suspected valid Group ID with SEQUENTIAL tests
        
        Returns:
            'TRUE_POSITIVE', 'FALSE_POSITIVE', or 'SUSPICIOUS'
        """
        self.output.display_validation_start(target, suspected_group_id)
        
        # Generate random test IDs
        test_ids = self._generate_test_ids(suspected_group_id, self.num_tests)
        
        valid_count = 0
        
        # Execute tests SEQUENTIALLY with verbose output
        for i, test_id in enumerate(test_ids, 1):
            result = await self.ike_tester.test_group_id_async(
                target,
                test_id,
                port=config.port
            )
            
            # Log validation test
            self.output.log_test(target, test_id, result)
            
            is_valid = result.status == 'VALID'
            if is_valid:
                valid_count += 1
            
            # Display inline result immediately
            self.output.display_validation_test_inline(i, self.num_tests, test_id, is_valid)
        
        # Close validation box
        self.output.display_validation_end()
        
        # Determine verdict
        if valid_count >= self.fp_threshold:
            # 3+ random IDs succeeded = false positive
            verdict = 'FALSE_POSITIVE'
        elif valid_count >= self.suspicious_threshold:
            # 2 random IDs succeeded = suspicious
            verdict = 'SUSPICIOUS'
        else:
            # 0-1 random IDs succeeded = true positive
            verdict = 'TRUE_POSITIVE'
        
        self.output.display_validation_verdict(verdict, target, valid_count, self.num_tests)
        return verdict
