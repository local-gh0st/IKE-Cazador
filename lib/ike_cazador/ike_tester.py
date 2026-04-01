"""
IKE Tester - ike-scan wrapper and output parser
"""

import subprocess
import asyncio
import re
import shutil
import tempfile
import os
import uuid


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


class IKETester:
    """Wrapper for ike-scan command execution and parsing"""
    
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.ike_scan_path = self._find_ike_scan()
    
    def _find_ike_scan(self):
        """Find ike-scan binary"""
        path = shutil.which('ike-scan')
        if not path:
            raise FileNotFoundError(
                "ike-scan not found. Please install ike-scan:\n"
                "  Debian/Kali: apt-get install ike-scan\n"
                "  macOS: brew install ike-scan"
            )
        return path
    
    def _sanitize_for_filename(self, text):
        """Sanitize text for safe use in filenames"""
        # Replace problematic characters with underscores
        return text.replace('.', '_').replace(':', '_').replace('/', '_').replace('\\', '_')
    
    def test_group_id(self, target, group_id, port=500):
        """
        Test a single Group ID against a target
        
        Returns:
            IKEResult object with validity status and details
        """
        output, status = self._execute_ike_scan(target, group_id, port)
        return self._parse_output(output, status)
    
    def capture_psk(self, target, group_id, port=500):
        """
        Capture full PSK handshake with -P flag for Phase 2
        
        Returns:
            IKEResult object with transform set and PSK parameters
        """
        output, status = self._execute_ike_scan_with_psk(target, group_id, port)
        return self._parse_output(output, status)
    
    def _execute_ike_scan(self, target, group_id, port):
        """Execute ike-scan subprocess with timeout (Phase 1) using temp file"""
        cmd = ['ike-scan', '-M', '-A', f'--id={group_id}']
        if port != 500:
            cmd.extend(['--dport', str(port)])
        cmd.append(target)
        
        # Create unique temp file for synchronous execution
        safe_target = self._sanitize_for_filename(target)
        safe_group_id = self._sanitize_for_filename(group_id)
        unique_id = uuid.uuid4().hex[:8]
        
        temp_file = None
        temp_path = None
        
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode='w+',
                prefix=f'ike_scan_{safe_target}_{safe_group_id}_{unique_id}_',
                suffix='.txt',
                delete=False
            )
            temp_path = temp_file.name
            temp_file.close()
            
            with open(temp_path, 'w') as outfile:
                result = subprocess.run(
                    cmd,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                    text=True
                )
                
                with open(temp_path, 'r') as infile:
                    stdout = infile.read()
                
                return stdout, result.returncode
                
        except subprocess.TimeoutExpired:
            return None, 'TIMEOUT'
        except Exception as e:
            return None, f'ERROR: {str(e)}'
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
    
    def _execute_ike_scan_with_psk(self, target, group_id, port):
        """Execute ike-scan with -P flag for PSK capture (Phase 2) using temp file"""
        cmd = ['ike-scan', '-M', '-A', f'--id={group_id}', '-P']
        if port != 500:
            cmd.extend(['--dport', str(port)])
        cmd.append(target)
        
        # Create unique temp file
        safe_target = self._sanitize_for_filename(target)
        safe_group_id = self._sanitize_for_filename(group_id)
        unique_id = uuid.uuid4().hex[:8]
        
        temp_file = None
        temp_path = None
        
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode='w+',
                prefix=f'ike_scan_psk_{safe_target}_{safe_group_id}_{unique_id}_',
                suffix='.txt',
                delete=False
            )
            temp_path = temp_file.name
            temp_file.close()
            
            with open(temp_path, 'w') as outfile:
                result = subprocess.run(
                    cmd,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                    text=True
                )
                
                with open(temp_path, 'r') as infile:
                    stdout = infile.read()
                
                return stdout, result.returncode
                
        except subprocess.TimeoutExpired:
            return None, 'TIMEOUT'
        except Exception as e:
            return None, f'ERROR: {str(e)}'
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
    
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
            result.raw_output = output
            return result
        
        if '0 returned handshake' in output:
            result.status = 'INVALID'
            result.error_type = 'NO_HANDSHAKE'
            result.raw_output = output
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
        
        # Unknown response pattern
        result.status = 'INVALID'
        result.error_type = 'UNKNOWN_RESPONSE'
        result.raw_output = output
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
    
    async def test_group_id_async(self, target, group_id, port=500):
        """
        Async version: Test a single Group ID against a target
        
        Returns:
            IKEResult object with validity status and details
        """
        output, status = await self._execute_ike_scan_async(target, group_id, port)
        return self._parse_output(output, status)
    
    async def _execute_ike_scan_async(self, target, group_id, port):
        """Execute ike-scan subprocess asynchronously with timeout using temp file"""
        cmd = [self.ike_scan_path, '-M', '-A', f'--id={group_id}']
        if port != 500:
            cmd.extend(['--dport', str(port)])
        cmd.append(target)
        
        # Create unique temp file to isolate stdout from concurrent processes
        safe_target = self._sanitize_for_filename(target)
        safe_group_id = self._sanitize_for_filename(group_id)
        unique_id = uuid.uuid4().hex[:8]
        
        temp_file = None
        temp_path = None
        fd = None
        
        try:
            # Create temp file with descriptive name for debugging
            temp_file = tempfile.NamedTemporaryFile(
                mode='w+',
                prefix=f'ike_scan_{safe_target}_{safe_group_id}_{unique_id}_',
                suffix='.txt',
                delete=False
            )
            temp_path = temp_file.name
            temp_file.close()  # Close so subprocess can write to it
            
            # Open temp file using low-level file descriptor for async subprocess
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=fd,  # Pass integer file descriptor
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    _, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=self.timeout
                    )
                    
                finally:
                    # Close file descriptor before reading
                    if fd is not None:
                        os.close(fd)
                        fd = None
                
                # Read output from temp file after process completes
                with open(temp_path, 'r') as infile:
                    stdout = infile.read()
                
                # Verify output was captured
                if not stdout or stdout.strip() == '':
                    return None, f'ERROR: No output captured from ike-scan'
                
                return stdout, proc.returncode
                    
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return None, 'TIMEOUT'
                    
        except Exception as e:
            return None, f'ERROR: {str(e)}'
        
        finally:
            # Ensure file descriptor is closed
            if fd is not None:
                try:
                    os.close(fd)
                except:
                    pass
            
            # Clean up temp file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass  # Non-critical if cleanup fails
