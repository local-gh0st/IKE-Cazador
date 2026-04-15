"""
CLI argument parsing and input validation pipeline.

Validates targets (IP, hostname, URL, FQDN), resolves DNS, deduplicates,
and validates wordlist before any scanning begins.
"""

import argparse
import ipaddress
import os
import re
import socket
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# Default paths (relative to the ike-cazador.py entry point)
_SCRIPT_DIR = Path(__file__).parent.parent
DEFAULT_WORDLIST = _SCRIPT_DIR / 'wordlists' / 'default-ike-wordlist.txt'


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ike-cazador',
        description="""Notify Messages Cheat Sheet:
  Notify-7   INVALID_EXCHANGE_TYPE      AM not supported on this device
  Notify-14  NO_PROPOSAL_CHOSEN         Transform not accepted by device
  Notify-18  INVALID_ID_INFORMATION     Transform accepted, group ID not found (smoking gun for AM)
  Notify-24  AUTHENTICATION_FAILED      Group and transform OK, auth failed. Likely: Bad source IP or requires cert/RSA auth
  Notify-29  UNSUPPORTED_EXCHANGE_TYPE  AM explicitly disabled

IKE Aggressive Mode discovery and PSK hash capture tool""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ike-cazador.py targets.txt
  sudo python3 ike-cazador.py targets.txt custom-wordlist.txt --conservative
  sudo python3 ike-cazador.py 203.0.113.5 -p 4500
  sudo python3 ike-cazador.py vpn.example.com --interface eth0
  sudo python3 ike-cazador.py targets.txt --cleanup-sas --delay 100
        """,
    )

    parser.add_argument(
        'targets',
        nargs='?',
        default=None,
        help='Single IP/hostname/URL/FQDN, or path to a targets file (one per line). '
             'Not required when using --resume.',
    )
    parser.add_argument(
        'wordlist',
        nargs='?',
        default=None,
        help=f'Group ID wordlist (default: wordlists/default-ike-wordlist.txt)',
    )
    parser.add_argument(
        '--resume',
        metavar='RUN_DIR', default=None,
        help='Resume from a prior run: skip Phase 1 and go straight to Phase 2. '
             'Provide the prior results directory (e.g. ike-cazador-results/20260414_161904) '
             'or path to its results.json. A new wordlist may be specified as the second argument.',
    )

    net = parser.add_argument_group('Network')
    net.add_argument(
        '-p', '--port',
        type=int, default=500, metavar='PORT',
        help='Destination port (default: 500, use 4500 for NAT-T)',
    )
    net.add_argument(
        '--interface',
        metavar='IFACE', default=None,
        help='Network interface to use (default: system default)',
    )

    timing = parser.add_argument_group('Timing and Reliability')
    timing.add_argument(
        '--timeout',
        type=float, default=3.0, metavar='SECS',
        help='Per-probe timeout in seconds (default: 3)',
    )
    timing.add_argument(
        '--retries',
        type=int, default=2, metavar='N',
        help='Retries per probe before counting a timeout (default: 2)',
    )
    timing.add_argument(
        '--dead-threshold',
        type=int, default=5, metavar='N', dest='dead_threshold',
        help='Consecutive timeouts before marking host dead (default: 5)',
    )
    timing.add_argument(
        '--max-host-time',
        type=float, default=120.0, metavar='SECS', dest='max_host_time',
        help='Hard ceiling on total probe time per host in seconds (default: 120)',
    )
    timing.add_argument(
        '--delay',
        type=int, default=250, metavar='MS',
        help='Milliseconds between probe rounds in Phase 2 (default: 250)',
    )
    timing.add_argument(
        '--p1-delay',
        type=int, default=200, metavar='MS', dest='p1_probe_delay_ms',
        help='Milliseconds between DH-group probes within Phase 1 per-host (default: 200). '
             'Increase if targets are rate-limiting rapid probes.',
    )
    timing.add_argument(
        '--p1-cooldown',
        type=int, default=1500, metavar='MS', dest='p1_deep_cooldown_ms',
        help='Milliseconds to wait before starting the single-transform deep scan '
             'fallback (default: 1500). Gives rate-limited devices time to reset '
             'their flood counter after the bundled probe burst.',
    )
    timing.add_argument(
        '--concurrency',
        type=int, default=20, metavar='N',
        help='Max concurrent in-flight probes (default: 20)',
    )

    output_grp = parser.add_argument_group('Output')
    output_grp.add_argument(
        '-o', '--output',
        metavar='DIR', default='ike-cazador-results',
        help='Output directory (default: ike-cazador-results/)',
    )
    output_grp.add_argument(
        '--no-pcap',
        action='store_true', dest='no_pcap',
        help='Disable PCAP capture',
    )
    output_grp.add_argument(
        '-v', '--verbose',
        action='count', default=0,
        help='Verbosity (-v or -vv)',
    )

    safety = parser.add_argument_group('Safety')
    safety.add_argument(
        '--cleanup-sas',
        action='store_true', dest='cleanup_sas',
        help='Send ISAKMP DELETE after each capture to clean up half-open SAs',
    )
    safety.add_argument(
        '--conservative',
        action='store_true',
        help='Safer preset for production targets: --delay 150 --cleanup-sas --dead-threshold 3 --timeout 5',
    )

    return parser


def apply_presets(args: argparse.Namespace) -> argparse.Namespace:
    """Apply the --conservative preset if requested."""
    if args.conservative:
        args.delay                = 150
        args.p1_probe_delay_ms    = 500
        args.p1_deep_cooldown_ms  = 3000
        args.cleanup_sas          = True
        args.dead_threshold       = 3
        args.timeout              = 5.0
    return args


# ---------------------------------------------------------------------------
# Input validation pipeline
# ---------------------------------------------------------------------------

def _strip_url_to_host(raw: str) -> str:
    """
    Strip URL scheme and path to extract bare hostname or IP.
    https://vpn.example.com/path  →  vpn.example.com
    vpn.example.com               →  vpn.example.com  (unchanged)
    """
    raw = raw.strip()
    if '://' in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        # Strip port if present
        return host
    # Strip trailing slash
    return raw.rstrip('/')


def _is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _is_valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def _is_valid_hostname(s: str) -> bool:
    """
    Basic hostname/FQDN validation.
    Allows: letters, digits, hyphens, dots. Max 253 chars, labels max 63 chars.
    """
    if not s or len(s) > 253:
        return False
    if s.endswith('.'):
        s = s[:-1]  # strip trailing dot
    labels = s.split('.')
    pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    return all(pattern.match(label) for label in labels)


def _resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IPv4 or IPv6 address. Returns None on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                     socket.SOCK_DGRAM)
        for res in results:
            addr = res[4][0]
            if _is_valid_ipv4(addr) or _is_valid_ipv6(addr):
                return addr
        return None
    except socket.gaierror:
        return None


def validate_and_resolve_targets(
    raw_targets: list[str],
    console=None,
) -> tuple[list[str], list[str]]:
    """
    Run the full input validation pipeline:
      1. Strip blank lines and comments
      2. Strip URL scheme/path
      3. Classify: IPv4 / IPv6 / hostname
      4. Resolve hostnames to IPs
      5. Deduplicate at IP level

    Returns:
        (valid_ips, warnings)
        valid_ips: deduplicated list of IP address strings
        warnings:  list of human-readable warning strings
    """
    seen_ips:   dict[str, str] = {}   # ip → original input
    valid_ips:  list[str] = []
    warnings:   list[str] = []
    ipv6_count  = 0

    for raw in raw_targets:
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue

        # Step 1: Strip URL scheme
        host = _strip_url_to_host(raw)
        if host != raw:
            warnings.append(f'Stripped URL scheme: "{raw}" → "{host}"')

        # Step 2: Classify and validate
        if _is_valid_ipv4(host):
            ip = host

        elif _is_valid_ipv6(host):
            ip = host
            ipv6_count += 1

        elif _is_valid_hostname(host):
            # Step 3: DNS resolution
            resolved = _resolve_hostname(host)
            if resolved is None:
                warnings.append(f'DNS resolution failed for "{host}" — skipped')
                continue
            warnings.append(f'Resolved: {host} → {resolved}')
            ip = resolved

        else:
            warnings.append(f'Invalid target "{raw}" — not a valid IP, hostname, or URL, skipped')
            continue

        # Step 4: Deduplicate at IP level
        if ip in seen_ips:
            original = seen_ips[ip]
            if original != raw:
                warnings.append(
                    f'Duplicate removed: "{raw}" resolves to {ip}, '
                    f'already in list as "{original}"'
                )
            continue

        seen_ips[ip] = raw
        valid_ips.append(ip)

    if ipv6_count > 0:
        warnings.append(
            f'{ipv6_count} IPv6 target(s) included — note: IKEv1 Aggressive Mode '
            f'over IPv6 is extremely rare in production deployments'
        )

    return valid_ips, warnings


def load_targets_from_arg(target_arg: str) -> list[str]:
    """
    Load targets from either a file path or a single host string.
    Auto-detects whether the argument is a file or a direct target.
    """
    p = Path(target_arg)
    if p.exists() and p.is_file():
        lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        return [line.strip() for line in lines if line.strip()]
    else:
        # Single target
        return [target_arg]


def validate_wordlist(wordlist_arg: Optional[str]) -> tuple[str, list[str]]:
    """
    Validate and resolve the wordlist path.
    Returns (path_str, words_list) or raises SystemExit on error.
    """
    if wordlist_arg:
        path = Path(wordlist_arg)
    else:
        path = DEFAULT_WORDLIST

    if not path.exists():
        if wordlist_arg:
            print(f'[!] Wordlist not found: {path}', file=sys.stderr)
        else:
            print(
                f'[!] Default wordlist not found: {path}\n'
                f'    Re-clone the repository or specify a wordlist:\n'
                f'    sudo python3 ike-cazador.py targets.txt /path/to/wordlist.txt',
                file=sys.stderr
            )
        sys.exit(1)

    if not path.is_file():
        print(f'[!] Wordlist path is not a file: {path}', file=sys.stderr)
        sys.exit(1)

    words = [
        line.strip()
        for line in path.read_text(encoding='utf-8', errors='replace').splitlines()
        if line.strip() and not line.strip().startswith('#')
    ]

    if not words:
        print(f'[!] Wordlist is empty: {path}', file=sys.stderr)
        sys.exit(1)

    return str(path), words


def check_root() -> None:
    """Hard exit if not running as root."""
    if os.geteuid() != 0:
        print(
            '\n[!] ike-cazador requires root privileges.\n'
            '    Reason: binding to UDP source port 500 (privileged port)\n'
            '            and raw socket access for packet crafting\n\n'
            '    Run with: sudo python3 ike-cazador.py [options]\n',
            file=sys.stderr
        )
        sys.exit(1)
