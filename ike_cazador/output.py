"""
Output manager — file output, hash saving, JSON results, summary.

Directory structure:
  ike-cazador-results/YYYYMMDD_HHMMSS/
  ├── hashes/
  │   ├── all_hashes.txt            raw hashcat-ready (all captures combined)
  │   ├── valid/
  │   │   ├── all_valid.txt         raw hashcat-ready (valid/named groups only)
  │   │   └── <ip>_<group>.txt      per-capture files with context header
  │   └── wildcard-flagged/
  │       ├── all_wildcard.txt      raw hashcat-ready (wildcard captures)
  │       └── <ip>_<group>.txt
  ├── logs/
  │   ├── scan.log                  full timestamped event log
  │   └── traffic.pcap              (unless --no-pcap)
  ├── results.json
  └── summary.txt
"""

import json
import os
import re
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .hash_extractor import CapturedHash
    from .wildcard import WildcardState


def _transform_to_ike_scan(transform_str: str) -> tuple:
    """
    Convert our transform string format to ike-scan flag values.

    Returns (trans_flag, dhgroup_flag) where:
      trans_flag    = value for --trans=  e.g. '5,2,1,1' or '7/128,2,65001,2'
      dhgroup_flag  = '--dhgroup=N ' when DH group ≠ 2, else '' (empty)

    Auth codes in ike-scan --trans format:
      1     = PSK (shared key)
      65001 = XAUTH_PSK (Cisco Easy VPN / AnyConnect)
      3     = RSA signatures

    ike-scan defaults its KE payload to DH Group 2.  Any other group MUST
    be specified with --dhgroup=N.

    Examples:
      '3DES/SHA1/PSK/G1'       →  ('5,2,1,1',       '--dhgroup=1 ')
      '3DES/SHA1/PSK/G2'       →  ('5,2,1,2',       '')
      'AES128/SHA1/XAUTH/G2'   →  ('7/128,2,65001,2','')
      'AES256/SHA256/PSK/G14'  →  ('7/256,4,1,14',  '--dhgroup=14 ')
    """
    try:
        parts = transform_str.split('/')
        # parts[0]=enc, parts[1]=hash, parts[2]=auth(PSK/XAUTH/RSA), parts[3]=G{n}
        enc_map = {
            'DES':    '1',
            '3DES':   '5',
            'AES128': '7/128',
            'AES192': '7/192',
            'AES256': '7/256',
        }
        hash_map = {
            'MD5':    '1',
            'SHA1':   '2',
            'SHA256': '4',
            'SHA384': '5',
            'SHA512': '6',
        }
        auth_map = {
            'PSK':   '1',
            'XAUTH': '65001',
            'RSA':   '3',
        }
        enc   = enc_map.get(parts[0], '5')         # default 3DES
        hash_ = hash_map.get(parts[1], '2')        # default SHA1
        auth  = auth_map.get(parts[2], '1')        # default PSK
        dh    = parts[3].lstrip('G')               # strip 'G' prefix: G14 → 14

        trans_flag   = f'{enc},{hash_},{auth},{dh}'
        # ike-scan KE payload defaults to G2 — explicit flag needed for all other groups
        dhgroup_flag = '' if dh == '2' else f'--dhgroup={dh} '
        return trans_flag, dhgroup_flag
    except Exception:
        return '5,2,1,2', ''   # safe fallback: 3DES/SHA1/PSK/G2


class OutputManager:
    """Manages all file output for a scan run."""

    def __init__(self, base_dir: str, run_timestamp: str, no_pcap: bool = False):
        self.run_timestamp = run_timestamp
        self.run_dir       = Path(base_dir) / run_timestamp
        self.hashes_dir    = self.run_dir / 'hashes'
        self.valid_dir     = self.hashes_dir / 'valid'
        self.wildcard_dir  = self.hashes_dir / 'wildcard-flagged'
        self.logs_dir      = self.run_dir / 'logs'
        self.no_pcap       = no_pcap
        self.pcap_path     = self.logs_dir / 'traffic.pcap'
        self.log_path      = self.logs_dir / 'scan.log'
        self.results_path  = self.run_dir / 'results.json'
        self.summary_path  = self.run_dir / 'summary.txt'

        # Runtime state
        self._captures:      list['CapturedHash'] = []
        self._phase1_results: dict = {}
        self._phase2_results: dict = {}
        self._pcap_packets:  list = []
        self._logger:        Optional[logging.Logger] = None
        self._start_time:    float = time.time()
        self._generated_hashcat_files: dict = {}   # populated by _write_combined_hash_files

        self._setup_directories()
        self._setup_logger()

    def _setup_directories(self) -> None:
        """Create all output directories."""
        for d in [self.run_dir, self.hashes_dir, self.valid_dir,
                  self.wildcard_dir, self.logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def _setup_logger(self) -> None:
        """Configure file-only logger with ISO 8601 timestamps."""
        logger = logging.getLogger(f'ike_cazador.{self.run_timestamp}')
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        handler = logging.FileHandler(self.log_path, encoding='utf-8')
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt='%(asctime)s.%(msecs)03dZ [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        self._logger = logger

        self.log_info(f'ike-cazador run started — output directory: {self.run_dir}')

    def log_info(self, msg: str) -> None:
        if self._logger:
            self._logger.info(msg)

    def log_debug(self, msg: str) -> None:
        if self._logger:
            self._logger.debug(msg)

    def log_warning(self, msg: str) -> None:
        if self._logger:
            self._logger.warning(msg)

    def log_error(self, msg: str) -> None:
        if self._logger:
            self._logger.error(msg)

    def log_phase1_probe(self, host: str, group_id: str, dh_group: str,
                          response_type: str, detail: str = '') -> None:
        self.log_debug(
            f'[Phase1] [{host}] probe group_id="{group_id}" dh={dh_group} '
            f'→ {response_type} {detail}'
        )

    def log_phase2_probe(self, host: str, word: str, word_idx: int,
                          response_type: str, detail: str = '') -> None:
        self.log_debug(
            f'[Phase2] [{host}] word[{word_idx}]="{word}" → {response_type} {detail}'
        )

    def log_capture(self, host: str, group_id: str, hashcat_mode: int,
                     wildcard: bool, file_path: str) -> None:
        label = 'WILDCARD' if wildcard else 'VALID'
        self.log_info(
            f'[Phase2] [{host}] HASH_CAPTURED group_id="{group_id}" '
            f'mode={hashcat_mode} type={label} → {file_path}'
        )

    def log_host_dead(self, host: str, last_word: str, last_idx: int,
                       remaining: int, reason: str) -> None:
        self.log_warning(
            f'[Phase2] [{host}] HOST_{reason} last_word="{last_word}" '
            f'word_idx={last_idx} words_remaining={remaining}'
        )

    def record_phase1_result(self, host: str, result: dict) -> None:
        """Store Phase 1 classification for a host."""
        self._phase1_results[host] = result
        self.log_info(
            f'[Phase1] [{host}] classified as {result.get("status", "UNKNOWN")} '
            f'transform={result.get("transform", "none")} '
            f'vendor={result.get("vendor", "unknown")}'
        )

    def record_phase2_result(self, host: str, result: dict) -> None:
        """Store Phase 2 final state for a host."""
        self._phase2_results[host] = result

    def save_hash(self, capture: 'CapturedHash') -> str:
        """
        Save a captured hash to the appropriate directory.
        Returns the file path where the hash was saved.
        """
        self._captures.append(capture)

        # Determine target directory
        dest_dir = self.wildcard_dir if capture.is_wildcard else self.valid_dir

        # Sanitize group ID for filename
        safe_group = re.sub(r'[^a-zA-Z0-9_\-]', '_', capture.group_id)[:32]
        safe_ip    = capture.target_ip.replace(':', '_')  # IPv6 safety
        filename   = f'{safe_ip}_{safe_group}.txt'
        filepath   = dest_dir / filename

        # Per-capture file with context header
        mode_str  = f'hashcat mode: -m {capture.hashcat_mode}'
        alg_name  = capture.hash_alg.name if capture.hash_alg else 'unknown'
        wildcard_note = ' [WILDCARD-FLAGGED]' if capture.is_wildcard else ''

        with open(filepath, 'w') as f:
            f.write(f'# ike-cazador capture{wildcard_note}\n')
            f.write(f'# host:      {capture.target_ip}\n')
            f.write(f'# group_id:  {capture.group_id}\n')
            f.write(f'# transform: {capture.transform_str}\n')
            f.write(f'# hash_alg:  {alg_name}\n')
            f.write(f'# {mode_str}\n')
            f.write(f'# timestamp: {datetime.now(timezone.utc).isoformat()}\n')
            f.write(f'#\n')
            f.write(f'{capture.hashcat_line}\n')

        self.log_capture(
            capture.target_ip, capture.group_id,
            capture.hashcat_mode, capture.is_wildcard, str(filepath)
        )

        return str(filepath)

    def move_hash_to_wildcard(self, capture: 'CapturedHash') -> None:
        """
        Move a hash file from valid/ to wildcard-flagged/ after wildcard confirmation.
        Updates the capture's is_wildcard flag.
        """
        safe_group = re.sub(r'[^a-zA-Z0-9_\-]', '_', capture.group_id)[:32]
        safe_ip    = capture.target_ip.replace(':', '_')
        filename   = f'{safe_ip}_{safe_group}.txt'

        src = self.valid_dir / filename
        dst = self.wildcard_dir / filename

        if src.exists():
            # Rewrite the file with wildcard flag
            capture.is_wildcard = True
            dst.write_text(src.read_text().replace(
                '# ike-cazador capture\n',
                '# ike-cazador capture [WILDCARD-FLAGGED]\n'
            ))
            src.unlink()
            self.log_info(
                f'[Wildcard] [{capture.target_ip}] hash moved to wildcard-flagged: {filename}'
            )

    def add_pcap_packet(self, raw: bytes, direction: str = 'out') -> None:
        """Buffer a raw packet for PCAP writing."""
        if not self.no_pcap:
            self._pcap_packets.append((time.time(), raw, direction))

    def flush_pcap(self) -> None:
        """Write buffered packets to PCAP file."""
        if self.no_pcap or not self._pcap_packets:
            return
        try:
            import io
            import sys
            import warnings
            from scapy.utils import wrpcap
            from scapy.packet import Raw
            import contextlib

            packets = []
            for ts, raw_data, direction in self._pcap_packets:
                pkt = Raw(load=raw_data)
                packets.append(pkt)

            # Suppress Scapy output using contextlib.redirect_stderr (exception-safe)
            # and warnings.catch_warnings for any warnings.warn() calls.
            with warnings.catch_warnings(), contextlib.redirect_stderr(io.StringIO()):
                warnings.simplefilter('ignore')
                wrpcap(str(self.pcap_path), packets)

            self.log_info(f'PCAP written: {self.pcap_path} ({len(packets)} packets)')
        except Exception as e:
            self.log_error(f'Failed to write PCAP: {e}')
            # Also print to stderr so operator sees it even without checking logs
            import sys as _sys
            print(f'\n  [!] PCAP write failed: {e}\n'
                  f'      Use --no-pcap to suppress, or check Scapy installation.',
                  file=_sys.stderr)

    def _write_combined_hash_files(self) -> None:
        """Write combined hash files — both annotated and hashcat-ready (clean) formats."""
        valid_captures    = [c for c in self._captures if not c.is_wildcard]
        wildcard_captures = [c for c in self._captures if c.is_wildcard]
        all_captures      = self._captures

        def write_combined(captures, path):
            """Annotated format: comment headers + hash lines. Human-readable context."""
            if not captures:
                return
            with open(path, 'w') as f:
                f.write(f'# ike-cazador combined hash file\n')
                f.write(f'# generated: {datetime.now(timezone.utc).isoformat()}\n')
                f.write(f'# total captures: {len(captures)}\n')
                f.write(f'# NOTE: use hashcat_ready_5400.txt / psk_crack_ready.txt for cracking\n')
                f.write('#\n')
                for c in captures:
                    alg = c.hash_alg.name if c.hash_alg else 'unknown'
                    wc  = ' [wildcard]' if c.is_wildcard else ''
                    f.write(f'# {c.target_ip} | {c.group_id} | {c.transform_str} | mode={c.hashcat_mode}{wc}\n')
                    f.write(f'{c.hashcat_line}\n')

        def _is_large_dh(capture) -> bool:
            """
            Returns True if the hash's g_xr field exceeds 128 bytes (DH Group 14+).
            hashcat modes 5300/5400 have a salt-length limit of 1024 hex chars.
            g_xr(256B) + g_xi(256B) + ... for G14 = 1264 hex chars → exceeds limit.
            G2 (g_xr=128B) and G1 (g_xr=96B) are safely below the limit at 744/604 chars.
            """
            fields = capture.hashcat_line.split(':')
            if len(fields) < 1:
                return False
            g_xr_bytes = len(fields[0]) // 2
            return g_xr_bytes > 128

        def write_hashcat_ready_by_mode(captures, base_dir) -> dict:
            """
            Write mode-specific hashcat-ready files and psk_crack_ready.txt.

            hashcat files (hash lines only, no comments):
              hashcat_ready_5400.txt  — SHA1, G1/G2/G5 only (salt ≤ 1024 hex chars)
              hashcat_ready_5300.txt  — MD5,  G1/G2/G5 only
              (G14+ hashes exceed hashcat 5400 salt limit — use psk-crack instead)

            psk-crack file (all hashes, any DH group):
              psk_crack_ready.txt  — every captured hash, psk-crack handles large DH groups

            sha256 file (no current tool supports cracking):
              sha256_captures.txt  — SHA256/384/512 hashes

            Returns dict of {filename: count} for files actually written.
            """
            if not captures:
                return {}

            from ike_cazador.constants import HashAlg
            generated = {}

            # Separate by crackability:
            # sha1_small = SHA1 + small DH (G1/G2/G5) → hashcat -m 5400
            # md5_small  = MD5  + small DH           → hashcat -m 5300
            # sha256     = SHA256/384/512 any DH      → neither tool (future)
            # large_dh   = any non-SHA256, large DH  → psk-crack only
            sha1_small  = [c for c in captures
                           if c.hashcat_mode == 5400
                           and c.hash_alg not in (HashAlg.SHA256, HashAlg.SHA384, HashAlg.SHA512)
                           and not _is_large_dh(c)]
            md5_small   = [c for c in captures
                           if c.hashcat_mode == 5300
                           and not _is_large_dh(c)]
            sha256_caps = [c for c in captures
                           if c.hash_alg in (HashAlg.SHA256, HashAlg.SHA384, HashAlg.SHA512)]
            # psk-crack handles ALL hashes regardless of DH group or hash alg
            psk_all     = [c for c in captures
                           if c.hash_alg not in (HashAlg.SHA256, HashAlg.SHA384, HashAlg.SHA512)]

            def _write_lines(cap_list, path, header=None):
                with open(path, 'w') as f:
                    if header:
                        f.write(header)
                    for c in cap_list:
                        f.write(f'{c.hashcat_line}\n')

            if sha1_small:
                _write_lines(sha1_small, base_dir / 'hashcat_ready_5400.txt')
                generated['hashcat_ready_5400.txt'] = len(sha1_small)

            if md5_small:
                _write_lines(md5_small, base_dir / 'hashcat_ready_5300.txt')
                generated['hashcat_ready_5300.txt'] = len(md5_small)

            if psk_all:
                _write_lines(
                    psk_all,
                    base_dir / 'psk_crack_ready.txt',
                    header=(
                        '# psk-crack compatible format — all hashes (any DH group)\n'
                        '# Usage: psk-crack -d <wordlist> psk_crack_ready.txt\n'
                        '# psk-crack handles G14/G15/G20 hashes that exceed hashcat salt limits\n'
                        '#\n'
                    )
                )
                generated['psk_crack_ready.txt'] = len(psk_all)

            if sha256_caps:
                _write_lines(
                    sha256_caps,
                    base_dir / 'sha256_captures.txt',
                    header=(
                        '# SHA256 IKE-PSK hashes — no cracking tool currently supports these\n'
                        '# hashcat modes 5300/5400 only support MD5/SHA1\n'
                        '# psk-crack does not support SHA256\n'
                        '#\n'
                    )
                )
                generated['sha256_captures.txt'] = len(sha256_caps)

            return generated

        generated_files = {}
        if all_captures:
            write_combined(all_captures, self.hashes_dir / 'all_hashes.txt')
            generated_files = write_hashcat_ready_by_mode(all_captures, self.hashes_dir)
        if valid_captures:
            write_combined(valid_captures, self.valid_dir / 'all_valid.txt')
            write_hashcat_ready_by_mode(valid_captures, self.valid_dir)
        if wildcard_captures:
            write_combined(wildcard_captures, self.wildcard_dir / 'all_wildcard.txt')
            write_hashcat_ready_by_mode(wildcard_captures, self.wildcard_dir)

        # Store for caller to pass to show_final_summary
        self._generated_hashcat_files = generated_files

    def finalize(self, interrupted: bool = False,
                 wordlist_path: str = '',
                 target_count: int = 0) -> None:
        """Write all final output files."""
        elapsed = time.time() - self._start_time

        # Combined hash files
        self._write_combined_hash_files()

        # PCAP
        self.flush_pcap()

        # results.json
        results = {
            'run_timestamp':  self.run_timestamp,
            'status':         'interrupted' if interrupted else 'complete',
            'elapsed_seconds': round(elapsed, 1),
            'target_count':   target_count,
            'wordlist':       wordlist_path,
            'phase1':         self._phase1_results,
            'phase2':         self._phase2_results,
            'captures': [
                {
                    'host':         c.target_ip,
                    'group_id':     c.group_id,
                    'transform':    c.transform_str,
                    'hash_alg':     c.hash_alg.name if c.hash_alg else 'unknown',
                    'hashcat_mode': c.hashcat_mode,
                    'is_wildcard':  c.is_wildcard,
                    'hashcat_line': c.hashcat_line,
                }
                for c in self._captures
            ],
        }

        with open(self.results_path, 'w') as f:
            json.dump(results, f, indent=2)

        # summary.txt
        self._write_summary(results, elapsed, interrupted)

        self.log_info(
            f'Run {"interrupted" if interrupted else "complete"} — '
            f'{len(self._captures)} hash(es) captured in {elapsed:.1f}s'
        )

    def _write_summary(self, results: dict, elapsed: float,
                        interrupted: bool) -> None:
        """Write human-readable summary.txt."""
        valid_count    = sum(1 for c in self._captures if not c.is_wildcard)
        wildcard_count = sum(1 for c in self._captures if c.is_wildcard)
        total_count    = len(self._captures)

        aggressive_hosts = [
            h for h, r in results['phase1'].items()
            if r.get('status') in ('AGGRESSIVE', 'AGGRESSIVE_RSA',
                                    'AGGRESSIVE_WILDCARD')
        ]
        not_vuln_hosts = [
            h for h, r in results['phase1'].items()
            if r.get('status') == 'NOT_VULNERABLE'
        ]
        unknown_hosts = [
            h for h, r in results['phase1'].items()
            if r.get('status') == 'UNKNOWN'
        ]
        # UNKNOWN hosts that DID respond (Notify-14) — IKE is running, transform unknown
        unknown_responsive = [
            h for h in unknown_hosts
            if results['phase1'][h].get('got_any_response', False)
        ]
        fw_filtered_hosts = [
            h for h, r in results['phase1'].items()
            if r.get('status') == 'FIREWALL_FILTERED'
        ]
        no_response_hosts = [
            h for h, r in results['phase1'].items()
            if r.get('status') == 'NO_RESPONSE'
        ]

        minutes, seconds = divmod(int(elapsed), 60)
        elapsed_str = f'{minutes}m {seconds}s' if minutes else f'{seconds}s'
        status_str = 'INTERRUPTED' if interrupted else 'COMPLETE'

        lines = [
            '=' * 72,
            'ike-cazador — Scan Summary',
            '=' * 72,
            f'Status:      {status_str}',
            f'Timestamp:   {self.run_timestamp}',
            f'Duration:    {elapsed_str}',
            f'Targets:     {results["target_count"]}',
            f'Wordlist:    {results["wordlist"]}',
            '',
            '--- Phase 1: Discovery ---',
            f'Aggressive Mode confirmed: {len(aggressive_hosts)}',
            f'Not vulnerable:            {len(not_vuln_hosts)}',
            f'Unknown:                   {len(unknown_hosts)}',
            f'Firewall-filtered:         {len(fw_filtered_hosts)}',
            f'No response:               {len(no_response_hosts)}',
            '',
        ]

        if fw_filtered_hosts:
            lines.append('Firewall-filtered hosts (ICMP admin-prohibited detected):')
            for h in fw_filtered_hosts:
                r = results['phase1'][h]
                lines.append(f'  {h:<20}  {r.get("detail", "")}')
            lines.append(
                '  NOTE: These hosts may be IKE-capable. A REJECT firewall rule is '
                'blocking the return path. Try scanning from a different network or '
                'source IP. DROP-based firewalls are silent and indistinguishable '
                'from offline hosts.'
            )
            lines.append('')

        if aggressive_hosts:
            lines.append('Aggressive Mode hosts:')
            for h in aggressive_hosts:
                r = results['phase1'][h]
                lines.append(f'  {h:<20}  {r.get("status",""):<25}  {r.get("transform","")}')
            lines.append('')

            # AM confirmation commands — one per aggressive host
            # Users can run these to collect client-deliverable evidence
            lines.append('--- ike-scan AM Confirmation Commands ---')
            lines.append('# Run these to confirm IKE Aggressive Mode is enabled on each host.')
            lines.append('# Responses that CONFIRM the finding (AM is enabled):')
            lines.append('#   Notify-14 (NO-PROPOSAL-CHOSEN)      = AM enabled, transform not matched')
            lines.append('#   Notify-18 (INVALID-ID-INFORMATION)  = AM enabled, transform accepted, group not found')
            lines.append('#   Notify-24 (AUTHENTICATION-FAILED)   = AM enabled, auth failed (bad source IP or cert/RSA auth)')
            lines.append('#   Aggressive Mode Handshake returned   = AM enabled, PSK hash capturable')
            lines.append('# Responses indicating AM is DISABLED (finding NOT confirmed):')
            lines.append('#   Notify-5  (INVALID-MAJOR-VERSION)     = IKEv1 not supported on this device')
            lines.append('#   Notify-7  (INVALID-EXCHANGE-TYPE)     = AM explicitly disabled on this device')
            lines.append('#   Notify-29 (UNSUPPORTED-EXCHANGE-TYPE) = AM not supported on this device')
            lines.append('#   No response (silence)                 = inconclusive — device may be offline, firewalled, or rate-limited')
            lines.append('')
            for h in aggressive_hosts:
                r        = results['phase1'][h]
                tx_str   = r.get('transform', 'none')
                if tx_str and tx_str != 'none':
                    trans, dhgrp = _transform_to_ike_scan(tx_str)
                    cmd = (f'ike-scan -M -A -n CONFIRM '
                           f'--trans={trans} {dhgrp}{h}')
                    lines.append(f'{cmd}  # {tx_str}')
                else:
                    # No confirmed transform — omit --trans, ike-scan uses defaults
                    lines.append(
                        f'ike-scan -M -A -n CONFIRM {h}'
                        f'  # transform unconfirmed — any AM response confirms finding'
                    )
            lines.append('')

        lines += [
            '--- Phase 2: Hash Captures ---',
            f'Total hashes captured:  {total_count}',
            f'  Named group (valid):  {valid_count}',
            f'  Wildcard-flagged:     {wildcard_count}',
            '',
        ]

        if total_count > 0:
            lines.append('Captured hashes:')
            for c in self._captures:
                wc = ' [WILDCARD]' if c.is_wildcard else ''
                lines.append(
                    f'  {c.target_ip:<20}  group="{c.group_id}"  '
                    f'mode={c.hashcat_mode}  {c.transform_str}{wc}'
                )
            lines.append('')
            lines.append('Hash files:')
            lines.append(f'  Annotated (with context):')
            lines.append(f'    All:       {self.hashes_dir}/all_hashes.txt')
            if valid_count:
                lines.append(f'    Valid:     {self.valid_dir}/all_valid.txt')
            if wildcard_count:
                lines.append(f'    Wildcard:  {self.wildcard_dir}/all_wildcard.txt')
            lines.append(f'  Crack-ready (hash lines only):')
            gf = self._generated_hashcat_files
            if 'hashcat_ready_5400.txt' in gf:
                n = gf['hashcat_ready_5400.txt']
                lines.append(f'    hashcat -m 5400 {self.hashes_dir}/hashcat_ready_5400.txt <wordlist>  ({n} SHA1)')
            if 'hashcat_ready_5300.txt' in gf:
                n = gf['hashcat_ready_5300.txt']
                lines.append(f'    hashcat -m 5300 {self.hashes_dir}/hashcat_ready_5300.txt <wordlist>  ({n} MD5)')
            if 'psk_crack_ready.txt' in gf:
                n = gf['psk_crack_ready.txt']
                lines.append(f'    psk-crack -d <wordlist> {self.hashes_dir}/psk_crack_ready.txt  ({n} hashes, all DH groups)')
            if 'sha256_captures.txt' in gf:
                n = gf['sha256_captures.txt']
                lines.append(f'    {self.hashes_dir}/sha256_captures.txt  ({n} SHA256 — no tool support yet)')
        else:
            lines.append('No hashes captured.')

        # ike-scan validation commands — only for hosts with captured hashes
        if total_count > 0:
            from collections import defaultdict
            lines.append('')
            lines.append('--- ike-scan Validation Commands ---')
            lines.append('# Use these to manually verify PSK captures after cracking.')
            lines.append('# -P captures the PSK hash for offline cracking.')
            lines.append('')

            # Group captures by host (preserves insertion order)
            by_host: dict = defaultdict(list)
            for c in self._captures:
                by_host[c.target_ip].append(c)

            for ip, caps in by_host.items():
                is_wc        = any(c.is_wildcard for c in caps)
                tx_str       = caps[0].transform_str
                trans, dhgrp = _transform_to_ike_scan(tx_str)
                label        = '[WILDCARD]' if is_wc else '[NAMED GROUP]'
                n_flag       = 'WILDCARD' if is_wc else caps[0].group_id

                lines.append(f'# {ip}  {label}  transform: {tx_str}')
                lines.append(
                    f'ike-scan -M -A -n {n_flag} --trans={trans} {dhgrp}{ip} -P'
                )
                if is_wc:
                    group_ids = ', '.join(c.group_id for c in caps)
                    lines.append(f'# Captured group IDs: {group_ids}')
                lines.append('')

        lines += ['', '=' * 72, '']

        with open(self.summary_path, 'w') as f:
            f.write('\n'.join(lines))

    @property
    def capture_count(self) -> int:
        return len(self._captures)
