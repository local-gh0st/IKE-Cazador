"""
Utility classes and helpers for IKE-CAZADOR
"""

import os
import sys
from datetime import datetime


class Colors:
    """ANSI color codes matching OpenCode palette"""
    
    # Primary colors (soft, visible on black)
    PURPLE = '\033[38;5;141m'      # Headers, section separators
    CYAN = '\033[38;5;117m'        # Technical identifiers
    ORANGE = '\033[38;5;215m'      # Warnings
    GREEN = '\033[38;5;114m'       # Success
    RED = '\033[38;5;203m'         # Errors
    YELLOW = '\033[38;5;221m'      # Suspicious
    GRAY = '\033[38;5;246m'        # Secondary info
    WHITE = '\033[97m'             # Normal text
    
    # Formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    
    def __init__(self, enabled=True):
        """Disable colors if not TTY or user requested --no-color"""
        if not enabled:
            self.PURPLE = ''
            self.CYAN = ''
            self.ORANGE = ''
            self.GREEN = ''
            self.RED = ''
            self.YELLOW = ''
            self.GRAY = ''
            self.WHITE = ''
            self.BOLD = ''
            self.DIM = ''
            self.RESET = ''


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
        self.no_color = args.no_color
        self.timeout = args.timeout
        
        # Create session directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = f"captures/scan_{timestamp}"
        os.makedirs(self.session_dir, exist_ok=True)
    
    def _parse_targets(self, target_input):
        """Parse target input (single IP/URL or file)"""
        if os.path.isfile(target_input):
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return targets
        else:
            return [target_input]
    
    def _load_wordlist(self, wordlist_path):
        """Load Group ID wordlist"""
        if not os.path.isfile(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        
        with open(wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not wordlist:
            raise ValueError(f"Wordlist is empty: {wordlist_path}")
        
        return wordlist


def format_time(seconds):
    """Format seconds into human-readable time string"""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        return f"{hours}h {mins}m"
