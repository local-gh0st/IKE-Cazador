"""
Scanner — Phase 1 discovery and Phase 2 wordlist enumeration.

Phase 1: Probe each target with 9 DH group probes (random string group ID).
         Bundled-transform probes first (9 DH groups, all enc/hash combos bundled).
         If all 8 bundled probes exhaust without a hit, falls through to a
         single-transform sequential deep scan (24 probes, priority-ordered).
         This catches rate-limiting devices (e.g. Cisco VPN Concentrator 3000)
         that need a pause between probes before responding.
         Classify: AGGRESSIVE | NOT_VULNERABLE | IKEV2_ONLY | UNKNOWN | NO_RESPONSE.

Phase 2: Round-robin wordlist enumeration against confirmed AGGRESSIVE hosts.
         Transform locked in from Phase 1 (or re-discovered if needed).
         Dead host detection: 5 consecutive timeouts → DEAD / RATE_LIMITED.
         Wildcard cap: 5 captures per confirmed wildcard host.
"""

import asyncio
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from .constants import (
    DHGroup, DH_PROBE_ORDER, ResponseType, HostStatus, Phase2Status,
    IKE_PORT, WILDCARD_CAP, RANDOM_GROUP_PREFIX,
    EncAlg, HashAlg, AuthMethod,
)
from .transforms import (
    Transform, DHKeypair, TRANSFORMS_BY_GROUP, generate_dh_keypair,
)
from .packet_builder import (
    ProbeMetadata, build_am1, build_delete_packet,
    generate_nonce, generate_cookie,
)
from .packet_parser import ParsedResponse, parse_response
from .hash_extractor import CapturedHash, extract_hash, validate_capture
from .wildcard import WildcardTracker, generate_random_group_id
from .vendor_id import summarize_vendors
from .output import OutputManager


# Common group IDs for Phase 1 named-group probes (used if random-string gets silence)
PHASE1_NAMED_PROBES = ['vpn', 'cisco', 'remote']


# ---------------------------------------------------------------------------
# Single-transform deep-scan priority list.
# Used as a fallback after all 8 bundled DH-group probes return Notify-14.
#
# Root cause this solves: some devices (e.g. Cisco VPN Concentrator 3000)
# rate-limit rapid probe bursts.  By the time we reach their only supported
# DH group (G1) we have already sent 5+ fast probes and the device silently
# drops our G1 packet.  Sending probes one at a time with a pause between
# each gives the device time to recover and respond correctly.
#
# Ordered most-common-first to maximise hit rate on early probes.
# Auth method is always included explicitly for clarity.
# ---------------------------------------------------------------------------
SINGLE_TRANSFORM_PRIORITY: list[Transform] = [
    # --- Priority 1: Legacy Group 1 (Cisco VPN Concentrator 3000, early PIX/IOS) ---
    # These MUST come first — the VPN Concentrator 3000 rate-limits aggressively
    # and only accepts G1.  If we wait until probe 9 it has already blacklisted us.
    Transform(EncAlg.DES_CBC,        0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_1),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_1),
    Transform(EncAlg.DES_CBC,        0,   HashAlg.MD5,    AuthMethod.PSK,       DHGroup.GROUP_1),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.MD5,    AuthMethod.PSK,       DHGroup.GROUP_1),
    # --- Priority 2: Cisco ASA / IOS modern, Group 2 ---
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.MD5,    AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.DES_CBC,        0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.DES_CBC,        0,   HashAlg.MD5,    AuthMethod.PSK,       DHGroup.GROUP_2),
    # --- Priority 3: Modern Group 14 ---
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.AES_CBC,        192, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.AES_CBC,        192, HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_14),
    # --- Priority 3b: AES-192 for Group 2 (fills coverage gap) ---
    Transform(EncAlg.AES_CBC,        192, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        192, HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_2),
    # --- Priority 3c: AES-192 for Group 5 ---
    Transform(EncAlg.AES_CBC,        192, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_5),
    # --- Priority 4: Group 5 (Cisco VPN Concentrator, Fortinet/Juniper) ---
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_5),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_5),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.PSK,       DHGroup.GROUP_5),
    # --- Priority 5: XAUTH variants (Cisco Easy VPN / AnyConnect legacy) ---
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.XAUTH_PSK, DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA1,   AuthMethod.XAUTH_PSK, DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.XAUTH_PSK, DHGroup.GROUP_2),
    # --- Priority 6: ECP groups (Cisco ASA 9.x+, Fortinet FortiGate) ---
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_19),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_19),
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA384, AuthMethod.PSK,       DHGroup.GROUP_20),
    # --- Priority 7: G16 (4096-bit MODP) — was completely absent ---
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_16),
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA384, AuthMethod.PSK,       DHGroup.GROUP_16),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA256, AuthMethod.PSK,       DHGroup.GROUP_16),
    # --- Priority 8: SHA512 variants missing from G2/G14 ---
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA512, AuthMethod.PSK,       DHGroup.GROUP_2),
    Transform(EncAlg.AES_CBC,        256, HashAlg.SHA512, AuthMethod.PSK,       DHGroup.GROUP_14),
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA512, AuthMethod.PSK,       DHGroup.GROUP_14),
    # --- Priority 9: XAUTH on G5, G14 (Cisco Easy VPN alternative groups) ---
    Transform(EncAlg.AES_CBC,        128, HashAlg.SHA1,   AuthMethod.XAUTH_PSK, DHGroup.GROUP_14),
    Transform(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   AuthMethod.XAUTH_PSK, DHGroup.GROUP_5),
]


@dataclass
class TargetState:
    """Complete runtime state for one target host."""
    ip:                     str
    port:                   int

    # Phase 1
    p1_status:              HostStatus = HostStatus.PENDING
    p1_dh_groups_tried:     list[DHGroup] = field(default_factory=list)
    p1_detail:              str = ''
    p1_deep_scanning:       bool = False   # True while single-transform fallback is running
    p1_deep_transform_str:  str = ''       # current single-transform being tried (for TUI)

    # Locked transform (from Phase 1 AM2 or Notify-18, or Phase 2 discovery)
    locked_transform:       Optional[Transform] = None
    locked_keypair:         Optional[DHKeypair] = None
    locked_dh_group:        Optional[DHGroup]   = None
    transform_confirmed:    bool = False

    # Vendor / response metadata
    vendor_str:             str = 'Unknown'
    idir_b:                 Optional[bytes] = None

    # Phase 2
    p2_status:              Phase2Status = Phase2Status.ACTIVE
    consecutive_timeouts:   int = 0
    total_probe_time:       float = 0.0
    last_response_word:     str = ''
    last_response_idx:      int = -1
    last_seen_time:         float = 0.0   # updated on every response by recv loop
    words_attempted:        int = 0
    captures:               list[CapturedHash] = field(default_factory=list)
    wildcard_confirmed:     bool = False
    wildcard_cap_reached:   bool = False
    # Tracks response type counts for zero-capture diagnosis in final summary
    # e.g. {'NOTIFY_AUTH_FAILED': 13} → cert/RSA auth detected
    p2_response_counts:     dict = field(default_factory=dict)
    # True when ANY Phase 1 bundled probe received ANY response (even Notify-14).
    # Distinguishes UNKNOWN-but-responsive (IKE running) from truly silent hosts.
    got_any_response:       bool = False

    @property
    def is_p2_active(self) -> bool:
        return self.p2_status == Phase2Status.ACTIVE

    @property
    def p2_active_label(self) -> str:
        if self.p2_status == Phase2Status.ACTIVE:
            return f'[~] SCANNING w/{self.words_attempted}'
        elif self.p2_status == Phase2Status.DEAD:
            return f'[!] UNRESPONSIVE @ w/{self.last_response_idx}'
        elif self.p2_status == Phase2Status.RATE_LIMITED:
            return f'[!] RATE LIMITED @ w/{self.last_response_idx}'
        elif self.p2_status == Phase2Status.CAPPED:
            return f'[=] WILDCARD CAP reached ({len(self.captures)} captures)'
        elif self.p2_status == Phase2Status.COMPLETE:
            return f'[+] COMPLETE ({len(self.captures)} captures)'
        return '?'


def derive_zero_capture_reason(ts: 'TargetState') -> str:
    """
    Diagnose why a Phase 2 host captured 0 hashes by examining its
    response type distribution.

    Response patterns and their meanings:
      All NOTIFY_INVALID_ID  → group IDs not in device config (wordlist miss)
      All NOTIFY_AUTH_FAILED → groups exist, PSK auth failed or RSA/cert Phase 1
      All NOTIFY_NO_PROPOSAL → transform rejected in Phase 2
      Silence / missing      → rate limited or offline
      Mixed                  → unclear, show breakdown

    Note on XAUTH: the XAUTH vendor ID is NOT an issue for PSK hash capture.
    Devices with XAUTH+PSK (e.g. Cisco VPN Concentrator, ASA with XAUTH) use
    PSK for Phase 1 and return AM2+HASH_R normally.  The tool captures those
    hashes correctly.  NOTIFY_AUTH_FAILED here indicates something different —
    most likely RSA/certificate Phase 1 auth, not XAUTH.
    """
    if len(ts.captures) > 0:
        return ''   # has captures — no zero-capture diagnosis needed

    counts = ts.p2_response_counts
    total  = sum(counts.values())

    if total == 0:
        if ts.p2_status == Phase2Status.RATE_LIMITED:
            return 'Timed out — try --delay 500'
        if ts.p2_status == Phase2Status.DEAD:
            return 'Unresponsive in Phase 2'
        return 'No responses received'

    auth_failed = counts.get('NOTIFY_AUTH_FAILED', 0)
    invalid_id  = counts.get('NOTIFY_INVALID_ID', 0)
    no_proposal = counts.get('NOTIFY_NO_PROPOSAL', 0)
    confirmed   = counts.get('CONFIRMED_AM2', 0)

    if auth_failed == total:
        return 'Notify-24: auth failed — bad source IP or cert/RSA auth'
    if invalid_id == total:
        return 'Notify-18: group not in device config — try a more expansive or customized wordlist'
    if no_proposal == total:
        return 'Notify-14: transform rejected'

    if auth_failed > total * 0.7:
        return (f'Notify-24 ({auth_failed}/{total}): auth failed — '
                f'source IP may not be configured peer, or cert/RSA auth')
    if invalid_id > total * 0.7:
        return f'Notify-18 ({invalid_id}/{total}): group not in config — try targeted wordlist'

    silent_words = ts.words_attempted - total if ts.words_attempted > total else 0
    if silent_words > 2 and (auth_failed + invalid_id) < total * 0.5:
        return f'Rate limited after {total} responses'

    parts = []
    if auth_failed:
        parts.append(f'{auth_failed}×24')
    if invalid_id:
        parts.append(f'{invalid_id}×18')
    if no_proposal:
        parts.append(f'{no_proposal}×14')
    return f'Mixed: {", ".join(parts)}' if parts else 'No captures'


class Scanner:
    """
    Async IKE Aggressive Mode scanner.

    Orchestrates Phase 1 and Phase 2 with asyncio, round-robin rotation,
    and per-host dead detection.
    """

    def __init__(
        self,
        targets:              list[str],
        port:                 int,
        wordlist:             list[str],
        output:               OutputManager,
        timeout:              float = 3.0,
        retries:              int   = 2,
        dead_threshold:       int   = 5,
        max_host_time:        float = 120.0,
        delay_ms:             int   = 250,
        p1_probe_delay_ms:    int   = 200,
        p1_deep_cooldown_ms:  int   = 1500,
        concurrency:          int   = 20,
        cleanup_sas:          bool  = False,
        interface:            Optional[str] = None,
        tui_callback:         Optional[Callable] = None,
    ):
        self.targets             = targets
        self.port                = port
        self.wordlist            = wordlist
        self.output              = output
        self.timeout             = timeout
        self.retries             = retries
        self.dead_threshold      = dead_threshold
        self.max_host_time       = max_host_time
        self.delay_ms            = delay_ms
        self.p1_probe_delay_ms   = p1_probe_delay_ms
        self.p1_deep_cooldown_ms = p1_deep_cooldown_ms
        self.concurrency         = concurrency
        self.cleanup_sas         = cleanup_sas
        self.interface           = interface
        self.tui_callback        = tui_callback

        self.target_states: dict[str, TargetState] = {
            ip: TargetState(ip=ip, port=port) for ip in targets
        }
        self.wildcard_tracker = WildcardTracker()

        # Pause / stop control
        self._paused  = asyncio.Event()
        self._paused.set()  # not paused initially
        self._stop    = False

        # Socket (shared UDP socket bound to source port 500)
        self._sock: Optional[socket.socket] = None

        # Pending probes: cky_i → (TargetState, ProbeMetadata, sent_timestamp)
        # Entries are kept for `retention_window` seconds after send so that
        # late-arriving AM2 responses (after the per-probe timeout has elapsed)
        # can still be matched and processed.  This fixes the bug where
        # slow devices (response latency > 3s) had their hashes discarded.
        self._pending_probes: dict[bytes, tuple[TargetState, ProbeMetadata, float]] = {}
        self._retention_window: float = 30.0   # seconds to keep metadata after send

        # _sync_recv_active: True during any synchronous probe-response exchange
        # (Phase 1, pre-Phase-2 discovery). When True, _send_probe_and_receive
        # uses _sync_queues routed by _sync_recv_loop — eliminates socket contention.
        self._sync_recv_active: bool = False
        # Per-probe response queues — keyed by CKY-I, used by _sync_recv_loop
        self._sync_queues: dict[bytes, asyncio.Queue] = {}

        # Active list reference — set by run_phase2 so _continuous_recv_loop
        # can call _handle_capture with the correct active list
        self._p2_active_list: Optional[list] = None

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    async def run_phase1(self) -> dict[str, TargetState]:
        """
        Phase 1: Probe all targets concurrently to classify AM capability.
        Returns the target_states dict with p1_status populated.

        Supports soft-stop via self._stop = True (set by stop() or SIGINT handler).
        When stopped early, returns whatever has been classified so far — callers
        can proceed to Phase 2 with any confirmed AGGRESSIVE hosts.
        """
        self.output.log_info(f'Phase 1 starting — {len(self.targets)} target(s)')
        self._setup_socket()

        # Start the shared sync recv loop — routes all incoming packets to
        # the correct probe's asyncio.Queue via CKY-I matching.
        # Eliminates socket contention when many probes run concurrently.
        self._sync_queues = {}
        self._sync_recv_active = True
        p1_recv_task = asyncio.create_task(self._sync_recv_loop())

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [
            self._phase1_probe_target(ts, semaphore)
            for ts in self.target_states.values()
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except (asyncio.CancelledError, KeyboardInterrupt):
            self.output.log_info('Phase 1 stopped early — recording partial results')
        finally:
            self._sync_recv_active = False
            p1_recv_task.cancel()
            try:
                await p1_recv_task
            except asyncio.CancelledError:
                pass
            self._sync_queues.clear()
            # Close socket after Phase 1 — prevents "Address already in use" on re-run
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

        # Any host still in PROBING status after gather = task raised an exception
        # (e.g. unsupported DH group, socket error) or was interrupted mid-probe.
        # Reclassify based on whether it got any responses at all.
        for ts in self.target_states.values():
            if ts.p1_status == HostStatus.PROBING:
                if ts.got_any_response:
                    # Got Notify-14 responses — AM is confirmed running
                    ts.p1_status = HostStatus.AGGRESSIVE
                    ts.p1_detail = (
                        'AM confirmed via Notify-14 — device processed AM exchange. '
                        'Transform not matched: PSK capture not possible without '
                        'the correct transform configuration.'
                    )
                    self.output.log_info(
                        f'[Phase1] [{ts.ip}] reclassified PROBING → AGGRESSIVE '
                        f'(Notify-14 responses received — AM is running)'
                    )
                else:
                    ts.p1_status = HostStatus.NO_RESPONSE
                    ts.p1_detail = 'No response received during Phase 1 probing'
                    self.output.log_info(
                        f'[Phase1] [{ts.ip}] reclassified PROBING → NO_RESPONSE'
                    )

        # Record Phase 1 results in output manager (partial or complete)
        for ip, ts in self.target_states.items():
            self.output.record_phase1_result(ip, {
                'status':           ts.p1_status.name,
                'transform':        str(ts.locked_transform) if ts.locked_transform else 'none',
                'vendor':           ts.vendor_str,
                'detail':           ts.p1_detail,
                'got_any_response': ts.got_any_response,
            })

        self.output.log_info('Phase 1 complete')
        return self.target_states

    async def run_phase2(self) -> None:
        """
        Phase 2: Round-robin wordlist enumeration against AGGRESSIVE hosts.

        Architecture: a continuous background recv loop handles ALL incoming
        UDP packets independently of the send loop.  Probe metadata is kept
        for `retention_window` seconds so late-arriving AM2 responses are
        still processed even after the per-probe timeout has elapsed.
        """
        phase2_targets = [
            ts for ts in self.target_states.values()
            if ts.p1_status in (HostStatus.AGGRESSIVE,)
        ]

        if not phase2_targets:
            self.output.log_info('Phase 2 skipped — no AGGRESSIVE hosts')
            return

        self.output.log_info(
            f'Phase 2 starting — {len(phase2_targets)} host(s), '
            f'{len(self.wordlist)} word(s)'
        )

        # Re-open socket if Phase 1 closed it
        if not self._sock:
            self._setup_socket()

        active = list(phase2_targets)
        self._p2_active_list = active

        # --- Pre-Phase-2: Discover transforms for hosts with locked_transform=None ---
        # These are hosts detected via Notify-24 in Phase 1 where we couldn't safely
        # lock a specific transform (Notify-24 fires before transform selection).
        # We probe each transform individually now, before the round-robin starts,
        # so the wordlist loop doesn't stall doing blocking discovery per word.
        unconfirmed = [ts for ts in active if not ts.locked_transform]
        if unconfirmed:
            self.output.log_info(
                f'[Phase2] Pre-scan transform discovery for {len(unconfirmed)} '
                f'host(s) with unconfirmed transform (detected via Notify-24)'
            )
            # Activate _sync_recv_loop for the discovery pass.
            # _pre_phase2_discover uses _send_probe_and_receive which needs
            # the queue-based receiver to avoid socket contention when many
            # hosts discover transforms concurrently (e.g. 169 hosts at once).
            self._sync_queues = {}
            self._sync_recv_active = True
            disc_recv_task = asyncio.create_task(self._sync_recv_loop())
            try:
                disc_tasks = [
                    self._pre_phase2_discover(ts, active)
                    for ts in unconfirmed
                ]
                await asyncio.gather(*disc_tasks, return_exceptions=True)
            finally:
                self._sync_recv_active = False
                disc_recv_task.cancel()
                try:
                    await disc_recv_task
                except asyncio.CancelledError:
                    pass
                self._sync_queues.clear()

            # Remove any hosts that still have no transform after discovery
            still_unconfirmed = [ts for ts in active if not ts.locked_transform]
            for ts in still_unconfirmed:
                self.output.log_info(
                    f'[Phase2] [{ts.ip}] no transform confirmed after pre-scan — '
                    f'host will not receive wordlist probes'
                )
                ts.p2_status = Phase2Status.COMPLETE  # update status so TUI shows correctly
                if ts in active:
                    active.remove(ts)

        # Start background tasks
        recv_task    = asyncio.create_task(self._continuous_recv_loop())
        cleanup_task = asyncio.create_task(self._stale_probe_cleanup())

        try:
            for word_idx, word in enumerate(self.wordlist):
                if self._stop:
                    break

                # Pause support
                await self._paused.wait()

                if not active:
                    self.output.log_info('All hosts exhausted — Phase 2 ending early')
                    break

                # Round-robin: send one probe per active host for this word
                send_tasks = []
                for ts in list(active):
                    if not ts.is_p2_active:
                        active.remove(ts)
                        continue
                    send_tasks.append(
                        self._phase2_send_probe(ts, word, word_idx, active)
                    )

                if send_tasks:
                    await asyncio.gather(*send_tasks, return_exceptions=True)

                # Respect inter-probe delay
                if self.delay_ms > 0:
                    await asyncio.sleep(self.delay_ms / 1000.0)

                # Notify TUI of progress
                if self.tui_callback:
                    remaining = len([ts for ts in active if ts.is_p2_active])
                    self.tui_callback('p2_progress', {
                        'word_idx':    word_idx,
                        'total_words': len(self.wordlist),
                        'active_hosts': remaining,
                        'captures':    self.output.capture_count,
                    })

        finally:
            # Give late responses time to arrive before stopping the recv loop
            self.output.log_info(
                f'Phase 2 send loop complete — waiting {self._retention_window:.0f}s '
                f'for late responses...'
            )
            await asyncio.sleep(min(self._retention_window, 10.0))
            recv_task.cancel()
            cleanup_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            self._p2_active_list = None
            # Close socket after Phase 2
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

        self.output.log_info(
            f'Phase 2 complete — {self.output.capture_count} hash(es) captured'
        )

    def pause(self) -> None:
        self._paused.clear()
        self.output.log_info('Scan paused by user')

    def resume(self) -> None:
        self._paused.set()
        self.output.log_info('Scan resumed by user')

    def stop(self) -> None:
        self._stop = True
        self._paused.set()  # unblock if paused
        self.output.log_info('Scan stopped by user')

    # -----------------------------------------------------------------------
    # Phase 1 internals
    # -----------------------------------------------------------------------

    async def _sync_recv_loop(self) -> None:
        """
        Shared background recv task for any synchronous probe-response exchange.
        Used by Phase 1 and pre-Phase-2 discovery.

        Continuously receives all UDP packets on the shared socket and routes
        each one to the correct probe's asyncio.Queue using the CKY-I (initiator
        cookie) as the key.

        This eliminates socket contention: when many probes run concurrently via
        asyncio.gather, each probe awaits ONLY its own queue — no packet is
        dropped because it arrived while a different probe was polling.

        Activated by setting _sync_recv_active = True and starting this task.
        Deactivated by cancelling the task and clearing _sync_queues.
        """
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, self._try_recv),
                    timeout=0.05
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                continue

            if data is None:
                continue

            raw, (src_ip, src_port) = data
            if len(raw) < 8:
                continue

            # Route by CKY-I — first 8 bytes of ISAKMP header
            cky_i = raw[0:8]
            q = self._sync_queues.get(cky_i)
            if q is not None:
                try:
                    q.put_nowait((raw, src_ip))
                except asyncio.QueueFull:
                    pass  # probe already got a response, drop duplicate

    async def _phase1_probe_target(
        self, ts: TargetState, semaphore: asyncio.Semaphore
    ) -> None:
        """
        Probe one target across all 9 DH groups until a definitive result.
        Uses random string group ID for all Phase 1 probes.

        After all 8 bundled DH-group probes exhaust, falls through to:
          1. Named-group probes (vpn/cisco/remote × G2/G14)
          2. Single-transform deep scan (24-probe fallback, sequential with delay)

        The inter-probe delay (p1_probe_delay_ms) between each DH group probe
        prevents triggering rate-limiters on devices like Cisco VPN Concentrator 3000.
        """
        async with semaphore:
            ts.p1_status = HostStatus.PROBING

            if self.tui_callback:
                self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})

            # --- Bundled-transform probes across all 9 DH groups ---
            # All 8 groups are always tried — no early exit based on silence.
            # A device that responds to G2 but rate-limits G1/G14/etc. must
            # still reach the deep scan where G1 is found.  Missing a live host
            # is worse than spending extra time on a dead one.
            random_group_id = generate_random_group_id()
            got_any_bundled_response = False

            for dh_group in DH_PROBE_ORDER:
                if self._stop:
                    return

                ts.p1_dh_groups_tried.append(dh_group)

                if self.tui_callback:
                    self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})

                try:
                    result, _ = await self._send_probe_and_receive(
                        ts, random_group_id, TRANSFORMS_BY_GROUP[dh_group]
                    )
                except (ValueError, KeyError) as e:
                    # Unsupported DH group (e.g. missing from MODP_GROUPS) — skip
                    self.output.log_debug(
                        f'[Phase1] [{ts.ip}] G{int(dh_group)} probe skipped: {e}'
                    )
                    continue

                # Inter-probe delay — lets rate-limiting devices recover
                # before we send the next DH group probe
                if self.p1_probe_delay_ms > 0:
                    await asyncio.sleep(self.p1_probe_delay_ms / 1000.0)

                if result is None:
                    # Timeout — try next DH group (no early exit)
                    continue

                # Got a response — record it
                got_any_bundled_response = True
                ts.got_any_response = True   # IKE is definitely running on this host
                classified = self._classify_phase1_response(
                    result, ts, dh_group, group_id=random_group_id
                )
                if classified:
                    # Definitive result obtained
                    if self.tui_callback:
                        self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})
                    self.output.log_info(
                        f'[Phase1] [{ts.ip}] → {ts.p1_status.name} '
                        f'via group="{random_group_id}" dh=G{int(dh_group)}'
                    )
                    return

                # Notify-14 — try next DH group
                self.output.log_phase1_probe(
                    ts.ip, random_group_id, f'G{int(dh_group)}',
                    'NOTIFY_14', result.message
                )

            # --- After all 8 bundled probes: if zero responses, classify immediately ---
            # If the host sent NO response to any of our 9 DH group probes, skip
            # the named-group probes and deep scan — they will not help either.
            # A host that is truly alive will have sent at least one Notify-14.
            # Note: this does NOT apply to rate-limited hosts that responded to
            # earlier probes (got_any_bundled_response = True for those).
            if not got_any_bundled_response:
                icmp_result = self._poll_icmp_errors(ts.ip)
                if icmp_result:
                    icmp_type, icmp_code = icmp_result
                    if icmp_code in (9, 10, 13):
                        ts.p1_status = HostStatus.FIREWALL_FILTERED
                        ts.p1_detail = (
                            f'ICMP type={icmp_type} code={icmp_code} (Admin Prohibited) '
                            f'— device may be IKE-capable but return path is filtered'
                        )
                    else:
                        ts.p1_status = HostStatus.NO_RESPONSE
                        ts.p1_detail = (
                            f'ICMP type={icmp_type} code={icmp_code} — no IKE response'
                        )
                else:
                    ts.p1_status = HostStatus.NO_RESPONSE
                    ts.p1_detail = (
                        f'No response to any of 9 DH group probes on port {self.port}. '
                        f'Host may be offline, port may be filtered, or source IP '
                        f'is not whitelisted. Ensure targets list contains known IKE hosts.'
                    )
                self.output.log_info(
                    f'[Phase1] [{ts.ip}] zero responses across all 9 DH groups — '
                    f'classified as {ts.p1_status.name}, skipping named/deep scan'
                )
                ts.p1_deep_scanning      = False
                ts.p1_deep_transform_str = ''
                if self.tui_callback:
                    self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})
                return

            # --- If all random-string DH probes returned Notify-14 or silence,
            #     try named group probes (G2 and G14 only, most common) ---
            for named_group in PHASE1_NAMED_PROBES:
                for dh_group in [DHGroup.GROUP_2, DHGroup.GROUP_14]:
                    if self._stop:
                        return
                    result, _ = await self._send_probe_and_receive(
                        ts, named_group, TRANSFORMS_BY_GROUP[dh_group]
                    )
                    if self.p1_probe_delay_ms > 0:
                        await asyncio.sleep(self.p1_probe_delay_ms / 1000.0)
                    if result is None:
                        continue
                    got_any_bundled_response = True
                    ts.got_any_response = True
                    classified = self._classify_phase1_response(
                        result, ts, dh_group, group_id=named_group
                    )
                    if classified:
                        if self.tui_callback:
                            self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})
                        self.output.log_info(
                            f'[Phase1] [{ts.ip}] → {ts.p1_status.name} '
                            f'via named_group="{named_group}" dh=G{int(dh_group)}'
                        )
                        return

            # --- Single-transform deep scan fallback ---
            # Only runs when bundled probes all returned Notify-14 or silence.
            # Sends each transform individually with the inter-probe delay,
            # giving rate-limited devices time to recover between probes.
            #
            # Cooldown: wait before starting the deep scan to allow aggressive
            # rate-limiters (e.g. Cisco VPN Concentrator 3000) to reset their
            # per-source-IP IKE flood counter after the bundled probe burst.
            if self.p1_deep_cooldown_ms > 0:
                self.output.log_debug(
                    f'[Phase1] [{ts.ip}] cooldown {self.p1_deep_cooldown_ms}ms '
                    f'before deep scan'
                )
                await asyncio.sleep(self.p1_deep_cooldown_ms / 1000.0)

            found = await self._phase1_single_transform_fallback(ts, random_group_id)
            if found:
                return

            # --- IKEv2 probe — before final UNKNOWN classification ---
            # If all IKEv1 transforms exhausted with Notify-14 responses,
            # try one IKEv2 IKE_SA_INIT probe.
            if got_any_bundled_response:
                is_v2 = await self._probe_ikev2(ts)
                if is_v2:
                    ts.p1_status = HostStatus.IKEV2_ONLY
                    ts.p1_detail = (
                        'Responded to IKEv2 probe — IKEv2-only or dual-stack gateway. '
                        'Not vulnerable to IKEv1 Aggressive Mode PSK capture. '
                        'Use IKEv2-specific assessment tooling.'
                    )
                    ts.p1_deep_scanning      = False
                    ts.p1_deep_transform_str = ''
                    self.output.log_info(
                        f'[Phase1] [{ts.ip}] IKEv2 probe confirmed → IKEV2_ONLY'
                    )
                    if self.tui_callback:
                        self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})
                    return

            # --- Final classification ---
            # The device responded to every probe with Notify-14 (NO_PROPOSAL_CHOSEN).
            #
            # Notify-14 = the device UNDERSTOOD and PROCESSED the AM request.
            # It evaluated our SA proposal and rejected the transform.
            # A device with AM DISABLED would return Notify-7/Notify-29 or silence.
            # Notify-14 from an AM probe is DEFINITIVE PROOF that AM is running.
            #
            # Therefore: AGGRESSIVE — AM is confirmed enabled.
            # The transform was not matched, so no PSK capture is possible,
            # but the FINDING is valid and must be reported.
            ts.p1_status = HostStatus.AGGRESSIVE
            ts.p1_detail = (
                f'AM confirmed via Notify-14 — device processed AM exchange '
                f'({len(SINGLE_TRANSFORM_PRIORITY)} transforms probed, none matched). '
                f'PSK capture not possible without the correct transform. '
                f'Use ike-scan commands in summary.txt to validate the finding.'
            )

            ts.p1_deep_scanning      = False
            ts.p1_deep_transform_str = ''

            if self.tui_callback:
                self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})

    async def _phase1_single_transform_fallback(
        self, ts: TargetState, group_id: str
    ) -> bool:
        """
        Single-transform deep scan fallback — called after all 8 bundled DH-group
        probes exhaust without a definitive result.

        Sends each transform from SINGLE_TRANSFORM_PRIORITY individually,
        with p1_probe_delay_ms between each probe.  This gives rate-limiting
        devices (e.g. Cisco VPN Concentrator 3000) time to recover between
        probes, which is what the bundled scan cannot guarantee.

        Returns True if a definitive result was obtained, False if all 24
        probes exhausted without a hit.
        """
        self.output.log_info(
            f'[Phase1-Deep] [{ts.ip}] starting single-transform fallback '
            f'({len(SINGLE_TRANSFORM_PRIORITY)} probes)'
        )
        ts.p1_deep_scanning = True

        for i, transform in enumerate(SINGLE_TRANSFORM_PRIORITY):
            if self._stop:
                return False

            ts.p1_deep_transform_str = str(transform)
            if self.tui_callback:
                self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})

            result, _ = await self._send_probe_and_receive(
                ts, group_id, [transform]
            )

            # Always wait between single-transform probes — this is the
            # whole point of the deep scan
            if self.p1_probe_delay_ms > 0:
                await asyncio.sleep(self.p1_probe_delay_ms / 1000.0)

            if result is None:
                self.output.log_debug(
                    f'[Phase1-Deep] [{ts.ip}] probe {i+1}/{len(SINGLE_TRANSFORM_PRIORITY)} '
                    f'{transform} → TIMEOUT'
                )
                continue

            # Any response from deep scan = IKE is running
            ts.got_any_response = True
            self.output.log_debug(
                f'[Phase1-Deep] [{ts.ip}] probe {i+1}/{len(SINGLE_TRANSFORM_PRIORITY)} '
                f'{transform} → {result.response_type.name}'
            )

            classified = self._classify_phase1_response(
                result, ts, transform.dh_group, group_id=group_id
            )
            if classified:
                ts.p1_deep_scanning      = False
                ts.p1_deep_transform_str = ''
                self.output.log_info(
                    f'[Phase1-Deep] [{ts.ip}] → {ts.p1_status.name} '
                    f'via single-transform {transform} '
                    f'(probe {i+1}/{len(SINGLE_TRANSFORM_PRIORITY)})'
                )
                if self.tui_callback:
                    self.tui_callback('p1_update', {'host': ts.ip, 'state': ts})
                return True

        # All single-transform probes exhausted
        self.output.log_info(
            f'[Phase1-Deep] [{ts.ip}] all {len(SINGLE_TRANSFORM_PRIORITY)} '
            f'single-transform probes exhausted — host classified as UNKNOWN'
        )
        return False

    async def _probe_ikev2(self, ts: TargetState) -> bool:
        """
        Send one minimal IKEv2 IKE_SA_INIT probe to check if the device is
        IKEv2-capable.  Called after all IKEv1 transforms are exhausted.

        Returns True if the device responds with an IKEv2 packet (version 0x20).
        Returns False on timeout or IKEv1 response.

        The probe is a minimal 28-byte IKEv2 header with no payloads — just
        enough to trigger a version response from any IKEv2 responder.
        Uses the same socket and port as Phase 1 IKEv1 probes.
        """
        import struct as _struct

        cky_i = os.urandom(8)
        header = (
            cky_i +
            b'\x00' * 8 +
            _struct.pack('!BBBBI', 0, 0x20, 34, 0x08, 0) +
            _struct.pack('!I', 28)
        )

        loop = asyncio.get_running_loop()
        self.output.log_debug(f'[Phase1-IKEv2] [{ts.ip}] sending IKEv2 probe')

        # M-8 fix: during Phase 1, _sync_recv_loop is active and consumes ALL
        # packets by CKY-I lookup in _sync_queues.  Register a queue for this
        # probe's CKY-I so the loop routes the IKEv2 response here instead of
        # dropping it (IKEv2 responses were silently lost under concurrent scan).
        ikev2_q: asyncio.Queue = asyncio.Queue(maxsize=4)
        self._sync_queues[cky_i] = ikev2_q

        try:
            await loop.sock_sendto(self._sock, header, (ts.ip, ts.port))
        except Exception as e:
            self.output.log_debug(f'[Phase1-IKEv2] [{ts.ip}] send error: {e}')
            self._sync_queues.pop(cky_i, None)
            return False

        try:
            raw_bytes, src_ip = await asyncio.wait_for(
                ikev2_q.get(), timeout=self.timeout
            )
            result = raw_bytes if src_ip == ts.ip else None
        except asyncio.TimeoutError:
            self.output.log_debug(f'[Phase1-IKEv2] [{ts.ip}] no response to IKEv2 probe')
            result = None
        finally:
            self._sync_queues.pop(cky_i, None)

        if result is None:
            return False

        raw = result
        if len(raw) < 18:
            return False

        version_byte = raw[17]
        major_version = version_byte >> 4
        is_v2 = (major_version == 2)
        self.output.log_debug(
            f'[Phase1-IKEv2] [{ts.ip}] response {len(raw)}B '
            f'version=0x{version_byte:02x} → {"IKEv2" if is_v2 else "IKEv1"}'
        )
        return is_v2

    def _classify_phase1_response(
        self, result: ParsedResponse, ts: TargetState,
        dh_group: DHGroup, group_id: str = ''
    ) -> bool:
        """
        Classify a Phase 1 response. Returns True if definitive result reached.
        Mutates ts.p1_status and ts.locked_transform.

        group_id is passed so the wildcard guard can distinguish random-string
        probes (gps...) from named-group probes (vpn, cisco, etc.).
        Only random-string probes confirm wildcard behavior.
        """
        rtype = result.response_type

        if rtype == ResponseType.CONFIRMED_AM2:
            ts.p1_status = HostStatus.AGGRESSIVE
            ts.p1_detail = f'AM2 received — {result.message}'
            ts.vendor_str = summarize_vendors(result.vendor_ids)
            ts.idir_b = result.idir_b
            self._lock_transform_from_response(ts, result, dh_group)

            # Only mark wildcard when the probe used a random-string group ID.
            # Named-group probes (vpn, cisco, remote) returning AM2 means the
            # device has that specific group configured — NOT wildcard behavior.
            if group_id.startswith(RANDOM_GROUP_PREFIX):
                wc_state = self.wildcard_tracker.get_or_create(ts.ip)
                wc_state.status = 'CONFIRMED'
                ts.wildcard_confirmed = True

            return True

        elif rtype == ResponseType.AM2_RSA_AUTH:
            ts.p1_status = HostStatus.AGGRESSIVE_RSA
            ts.p1_detail = 'AM enabled but RSA/certificate auth — no PSK to capture'
            ts.vendor_str = summarize_vendors(result.vendor_ids)
            return True

        elif rtype == ResponseType.NOTIFY_INVALID_ID:
            # Smoking gun: transform accepted, group not found
            ts.p1_status = HostStatus.AGGRESSIVE
            ts.p1_detail = 'Notify-18 — AM enabled, transform confirmed, group not found'
            ts.vendor_str = summarize_vendors(result.vendor_ids)
            self._lock_transform_from_dh_group(ts, dh_group)
            return True

        elif rtype == ResponseType.NOTIFY_AUTH_FAILED:
            # Notify-24: transform accepted, group found, but authentication failed.
            # Common causes:
            #   - Source IP not in device's configured VPN peer whitelist
            #   - Certificate/RSA auth required instead of PSK
            #
            # IMPORTANT: We do NOT lock a specific transform here because Notify-24
            # fires before the device selects a transform — we cannot know which
            # transform in our bundle was accepted. Locking position 1 (AES256/SHA256)
            # would cause Phase 2 to send the wrong transform and get Notify-14.
            # Instead, mark as AGGRESSIVE with no locked transform; Phase 2 will
            # probe each transform individually to find the accepted one.
            ts.p1_status = HostStatus.AGGRESSIVE
            ts.p1_detail = ('Notify-24 — AM processed, auth failed. '
                            'Source IP may not be a configured peer, or cert/RSA auth. '
                            'Transform unconfirmed — Phase 2 will probe individually.')
            ts.vendor_str = summarize_vendors(result.vendor_ids)
            ts.locked_dh_group = dh_group   # we know the DH group, not the specific transform
            # Do NOT call _lock_transform_from_dh_group — leave locked_transform=None
            # so Phase 2 triggers per-transform discovery
            return True

        elif rtype == ResponseType.NOTIFY_NO_AM:
            ts.p1_status = HostStatus.NOT_VULNERABLE
            ts.p1_detail = f'Notify-{result.notify_type} — AM explicitly not supported'
            return True

        elif rtype == ResponseType.IKEV2:
            ts.p1_status = HostStatus.IKEV2_ONLY
            ts.p1_detail = 'IKEv2 response — Aggressive Mode PSK attack does not apply'
            return True

        elif rtype == ResponseType.MAIN_MODE_RESPONSE:
            ts.p1_status = HostStatus.NOT_VULNERABLE
            ts.p1_detail = 'Main Mode response observed'
            return True

        elif rtype == ResponseType.NOTIFY_NO_PROPOSAL:
            # Transform mismatch — not definitive, try next DH group
            return False

        elif rtype == ResponseType.CISCO_FRAGMENT:
            # Fragment received — not yet reassembled, treat as pending
            return False

        else:
            # Unknown/malformed — not definitive
            return False

    def _lock_transform_from_response(
        self, ts: TargetState, response: ParsedResponse, dh_group: DHGroup
    ) -> None:
        """
        Lock in the accepted transform from an AM2 response.

        Matches on enc + dh_group + key_len + hash_alg + auth_method.
        auth_method is critical: without it, XAUTH_PSK (65001) devices get
        locked to the PSK (1) variant causing Notify-14 in Phase 2.

        Search order:
        1. TRANSFORMS_BY_GROUP[dh_group] — bundled transforms (PSK variants)
        2. SINGLE_TRANSFORM_PRIORITY — includes XAUTH and other auth variants
        3. Fallback to first transform in group
        """
        if response.accepted_enc and response.dh_group:
            # Build the combined search list: bundled + single-transform priority
            candidates = (
                list(TRANSFORMS_BY_GROUP.get(response.dh_group, [])) +
                [t for t in SINGLE_TRANSFORM_PRIORITY
                 if t.dh_group == response.dh_group]
            )
            for t in candidates:
                enc_match  = int(t.enc) == response.accepted_enc
                dh_match   = int(t.dh_group) == int(response.dh_group)
                kl_match   = (t.key_len == 0 or
                               t.key_len == (response.accepted_key_len or 0))
                hash_match = (response.accepted_hash_alg is None or
                              int(t.hash_alg) == response.accepted_hash_alg)
                auth_match = (response.accepted_auth_method is None or
                              int(t.auth) == response.accepted_auth_method)

                if enc_match and dh_match and kl_match and hash_match and auth_match:
                    ts.locked_transform    = t
                    ts.locked_dh_group     = response.dh_group
                    ts.transform_confirmed = True
                    return

        # Fallback: use first transform for the DH group
        self._lock_transform_from_dh_group(ts, dh_group)

    def _lock_transform_from_dh_group(self, ts: TargetState, dh_group: DHGroup) -> None:
        """Lock in the first (strongest) transform for a DH group."""
        transforms = TRANSFORMS_BY_GROUP.get(dh_group, [])
        if transforms:
            ts.locked_transform = transforms[0]
            ts.locked_dh_group  = dh_group
            ts.transform_confirmed = True

    # -----------------------------------------------------------------------
    # Phase 2 internals
    # -----------------------------------------------------------------------

    async def _continuous_recv_loop(self) -> None:
        """
        Background task that runs for the entire duration of Phase 2.
        Receives ALL incoming UDP packets and routes them via _pending_probes.

        This decouples response handling from the per-probe send/wait cycle,
        so late-arriving AM2 responses (after the per-probe timeout) are still
        captured and processed correctly.
        """
        loop = asyncio.get_running_loop()
        self.output.log_debug('[Phase2] Continuous recv loop started')

        while not self._stop:
            try:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, self._try_recv),
                    timeout=0.1
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                continue

            if data is None:
                await asyncio.sleep(0.005)
                continue

            raw, (src_ip, src_port) = data

            # Route via CKY-I cookie
            if len(raw) < 8:
                continue
            cky_i = raw[0:8]

            entry = self._pending_probes.get(cky_i)
            if entry is None:
                continue   # not our probe, ignore

            # Entry is either (ts, probe_meta, sent_at) for normal Phase 2 probes
            # or (ts, probe, sent_at, wc_q) for wildcard validation probes.
            # Wildcard probes use a dedicated queue — deliver there instead of capture.
            if len(entry) == 4:
                ts, probe_meta, sent_at, wc_q = entry
                if src_ip == ts.ip:
                    try:
                        wc_q.put_nowait((raw, src_ip))
                    except asyncio.QueueFull:
                        pass
                continue

            ts, probe_meta, sent_at = entry

            # Verify source IP matches what we probed
            if src_ip != ts.ip:
                continue

            # Log to PCAP
            self.output.add_pcap_packet(raw, direction='in')

            # Full parse
            parsed = parse_response(raw, cky_i, src_ip)

            # Update last-response tracking (resets dead-host counter)
            ts.last_seen_time = time.time()
            ts.consecutive_timeouts = 0

            late = time.time() - sent_at
            self.output.log_debug(
                f'[Phase2-Recv] [{ts.ip}] cky={cky_i.hex()[:12]} '
                f'type={parsed.response_type.name} '
                f'word="{probe_meta.group_id}" late={late:.2f}s'
            )

            # Track response type for zero-capture diagnosis
            rname = parsed.response_type.name
            ts.p2_response_counts[rname] = ts.p2_response_counts.get(rname, 0) + 1

            # Remove from pending — we have the response
            self._pending_probes.pop(cky_i, None)

            active = self._p2_active_list or []

            if parsed.response_type == ResponseType.CONFIRMED_AM2:
                ts.last_response_word = probe_meta.group_id
                ts.last_response_idx  = probe_meta.word_idx
                await self._handle_capture_with_meta(
                    ts, probe_meta.group_id, probe_meta.word_idx,
                    parsed, probe_meta, active
                )

            elif parsed.response_type == ResponseType.NOTIFY_NO_PROPOSAL:
                ts.last_response_word = probe_meta.group_id
                ts.last_response_idx  = probe_meta.word_idx
                self.output.log_phase2_probe(
                    ts.ip, probe_meta.group_id, probe_meta.word_idx,
                    'NOTIFY_14', parsed.message
                )

            elif parsed.response_type in (
                ResponseType.NOTIFY_AUTH_FAILED,
                ResponseType.NOTIFY_INVALID_ID,
                ResponseType.NOTIFY_NO_AM,
                ResponseType.NOTIFY_OTHER,
            ):
                ts.last_response_word = probe_meta.group_id
                ts.last_response_idx  = probe_meta.word_idx
                self.output.log_phase2_probe(
                    ts.ip, probe_meta.group_id, probe_meta.word_idx,
                    parsed.response_type.name, parsed.message
                )

            # Notify TUI
            if self.tui_callback:
                self.tui_callback('p2_host_update', {'host': ts.ip, 'state': ts})

        self.output.log_debug('[Phase2] Continuous recv loop stopped')

    async def _stale_probe_cleanup(self) -> None:
        """
        Periodically removes probe metadata older than retention_window.
        Also handles dead-host detection: if a host has had no response
        for dead_threshold × timeout seconds, mark it inactive.
        """
        while not self._stop:
            try:
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break

            now = time.time()
            # Use entry[2] for sent_at — handles both 3-tuple (normal probes)
            # and 4-tuple (wildcard validation probes) without crashing.
            stale_keys = [
                k for k, entry in self._pending_probes.items()
                if len(entry) >= 3 and now - entry[2] > self._retention_window
            ]
            for k in stale_keys:
                entry = self._pending_probes.pop(k, None)
                if entry:
                    ts       = entry[0]
                    sent_at  = entry[2]
                    # 4-tuple = wildcard validation probe — has its own timeout/queue,
                    # skip dead-host logic (the wc_q.get() handles the timeout itself)
                    if len(entry) == 4:
                        self.output.log_debug(
                            f'[Phase2] [{ts.ip}] wildcard probe stale after '
                            f'{now - sent_at:.1f}s — cleaned up'
                        )
                        continue
                    probe_meta = entry[1]
                    # Increment timeout counter for this host
                    ts.consecutive_timeouts += 1
                    self.output.log_debug(
                        f'[Phase2] [{ts.ip}] probe stale after '
                        f'{now - sent_at:.1f}s — '
                        f'consecutive_timeouts={ts.consecutive_timeouts}'
                    )
                    # Dead host detection
                    active = self._p2_active_list or []
                    if ts.consecutive_timeouts >= self.dead_threshold and ts.is_p2_active:
                        reason = 'RATE_LIMITED' if ts.last_response_idx >= 0 else 'DEAD'
                        remaining = len(self.wordlist) - (ts.last_response_idx + 1)
                        self._mark_host_inactive(
                            ts, ts.last_response_word or probe_meta.group_id,
                            ts.last_response_idx, reason, active
                        )

    async def _phase2_send_probe(
        self, ts: TargetState, word: str, word_idx: int, active_list: list
    ) -> None:
        """
        Send one wordlist probe to one host.
        Does NOT wait for a response — the continuous recv loop handles that.
        """
        # Check hard ceiling on total probe time
        if ts.total_probe_time >= self.max_host_time:
            reason = 'RATE_LIMITED' if ts.captures else 'DEAD'
            self._mark_host_inactive(ts, word, word_idx, reason, active_list)
            return

        # Wildcard cap check
        wc_state = self.wildcard_tracker.get(ts.ip)
        if wc_state and wc_state.is_capped:
            ts.p2_status = Phase2Status.CAPPED
            if ts in active_list:
                active_list.remove(ts)
            return

        # Ensure we have a locked transform — if not, do inline discovery
        if not ts.locked_transform:
            found = await self._phase2_discover_transform(ts, word, word_idx, active_list)
            if not found:
                return

        # Send probe (fire and forget — recv loop handles the response)
        t0 = time.time()
        await self._send_probe_only(ts, word, word_idx)
        ts.total_probe_time += time.time() - t0
        ts.words_attempted  += 1

    async def _pre_phase2_discover(self, ts: TargetState, active_list: list) -> None:
        """
        Pre-Phase-2 transform discovery for hosts where locked_transform=None.
        These hosts were detected via Notify-24 in Phase 1 — we know the DH group
        (stored in ts.locked_dh_group) but not the specific transform.

        Strategy: probe each transform in the DH group individually.
        A response of NOTIFY_AUTH_FAILED or NOTIFY_INVALID_ID means the transform
        was accepted — lock it and proceed.  NOTIFY_NO_PROPOSAL means rejected.

        This runs BEFORE the wordlist loop so it doesn't block round-robin probing.
        Uses the FIRST wordlist word as the test group ID.
        """
        test_word = self.wordlist[0] if self.wordlist else 'vpn'

        # When a specific DH group is locked (Notify-24 hosts), probe only that group.
        # When no group is locked (Notify-14 exhaustion hosts), try ALL groups —
        # maximises coverage in case Phase 1 missed a transform.
        if ts.locked_dh_group:
            groups_to_probe = [ts.locked_dh_group]
        else:
            groups_to_probe = list(DH_PROBE_ORDER)

        for dh_group in groups_to_probe:
            transforms_to_try = TRANSFORMS_BY_GROUP.get(dh_group, [])

            self.output.log_info(
                f'[Phase2-Discover] [{ts.ip}] probing {len(transforms_to_try)} '
                f'transforms for G{int(dh_group)} individually'
            )

            for transform in transforms_to_try:
                result, probe_meta = await self._send_probe_and_receive(
                    ts, test_word, [transform]
                )
                if result is None:
                    continue  # timeout — try next

                rtype = result.response_type
                if rtype == ResponseType.CONFIRMED_AM2:
                    # Found it — and got a hash.
                    # Use probe_meta returned directly from _send_probe_and_receive
                    # (it was already popped from _pending_probes, so get() would return None).
                    self._lock_transform_from_response(ts, result, dh_group)
                    if probe_meta:
                        await self._handle_capture_with_meta(
                            ts, test_word, 0, result, probe_meta, active_list
                        )
                    self.output.log_info(
                        f'[Phase2-Discover] [{ts.ip}] transform confirmed via AM2: {transform}'
                    )
                    return

                elif rtype in (ResponseType.NOTIFY_INVALID_ID,
                               ResponseType.NOTIFY_AUTH_FAILED):
                    # Transform accepted — lock it and proceed to wordlist
                    ts.locked_transform    = transform
                    ts.locked_dh_group     = dh_group
                    ts.transform_confirmed = True
                    self.output.log_info(
                        f'[Phase2-Discover] [{ts.ip}] transform confirmed via '
                        f'{rtype.name}: {transform}'
                    )
                    return

                elif rtype == ResponseType.NOTIFY_NO_PROPOSAL:
                    # Transform rejected — try next
                    self.output.log_debug(
                        f'[Phase2-Discover] [{ts.ip}] {transform} rejected (Notify-14)'
                    )
                    continue

        # All groups and transforms exhausted — leave locked_transform=None
        # (caller will remove host from active list)
        self.output.log_warning(
            f'[Phase2-Discover] [{ts.ip}] no transform accepted — '
            f'host removed from Phase 2'
        )

    async def _phase2_discover_transform(
        self, ts: TargetState, word: str, word_idx: int, active_list: list
    ) -> bool:
        """
        Inline transform discovery for hosts that still have no locked transform
        when Phase 2 is already running (fallback path — normally pre-discovery
        handles this before the wordlist loop starts).

        Returns True if transform locked, False if all transforms exhausted.
        """
        dh_group = ts.locked_dh_group or DHGroup.GROUP_2
        transforms = TRANSFORMS_BY_GROUP.get(dh_group, [])

        for transform in transforms:
            result, probe_meta = await self._send_probe_and_receive(
                ts, word, [transform]
            )
            if result is None:
                continue

            rtype = result.response_type
            if rtype == ResponseType.CONFIRMED_AM2:
                self._lock_transform_from_response(ts, result, dh_group)
                if probe_meta:
                    await self._handle_capture_with_meta(
                        ts, word, word_idx, result, probe_meta, active_list
                    )
                return True

            elif rtype in (ResponseType.NOTIFY_INVALID_ID,
                           ResponseType.NOTIFY_AUTH_FAILED):
                ts.locked_transform    = transform
                ts.locked_dh_group     = dh_group
                ts.transform_confirmed = True
                return True

            elif rtype == ResponseType.NOTIFY_NO_PROPOSAL:
                continue

        self.output.log_warning(
            f'[Phase2] [{ts.ip}] no transform identified — skipping'
        )
        ts.p2_status = Phase2Status.COMPLETE
        if ts in active_list:
            active_list.remove(ts)
        return False

    async def _handle_capture_with_meta(
        self, ts: TargetState, word: str, word_idx: int,
        result: ParsedResponse, probe_meta: 'ProbeMetadata', active_list: list
    ) -> None:
        """
        Process a valid AM2 response — extract hash and trigger wildcard check.
        Takes ProbeMetadata directly (no _pending_probes lookup needed).
        """
        capture = extract_hash(probe_meta, result)
        if not capture:
            self.output.log_warning(
                f'[Phase2] [{ts.ip}] Failed to extract hash for word="{word}"'
            )
            return

        # Self-test: validate structural integrity before saving.
        # Catches extraction bugs (idir_b bleeding, wrong field sizes, etc.)
        # without requiring the PSK — we cannot re-derive HASH_R without it.
        passed, val_warnings = validate_capture(capture)
        if not passed:
            self.output.log_warning(
                f'[Phase2] [{ts.ip}] HASH_VALIDATION_FAILED word="{word}" '
                f'reason={val_warnings} — hash NOT saved'
            )
            return
        for w in val_warnings:
            self.output.log_warning(f'[Phase2] [{ts.ip}] hash advisory: {w}')

        # Hard cap guard — check BEFORE saving to prevent the async race condition
        # where two concurrent responses from the same wildcard host both pass the
        # cap check before either has been appended to ts.captures.
        wc_state    = self.wildcard_tracker.get_or_create(ts.ip)

        # A capture with a random-string group ID (gps... prefix) is definitional
        # proof of wildcard behavior — the device responded to our tool-generated
        # random string.  Always flag these as wildcard regardless of wc_state,
        # which may not be updated yet due to async validation timing.
        if probe_meta.group_id.startswith(RANDOM_GROUP_PREFIX):
            is_wildcard = True
        else:
            is_wildcard = wc_state.is_confirmed or ts.wildcard_confirmed

        if is_wildcard and len(ts.captures) >= WILDCARD_CAP:
            self.output.log_debug(
                f'[Phase2] [{ts.ip}] cap already reached ({len(ts.captures)}) '
                f'— discarding late capture for word="{word}"'
            )
            return

        capture.is_wildcard = is_wildcard

        # Save hash
        file_path = self.output.save_hash(capture)
        ts.captures.append(capture)

        self.output.log_phase2_probe(
            ts.ip, word, word_idx, 'CONFIRMED_AM2',
            f'hash captured ({len(result.hash_r)} bytes) → {file_path}'
        )

        # Record signals for wildcard characterization
        wc_state.record_capture(
            g_xr=result.ke_bytes,
            nr_b=result.nonce_r,
            vendor_ids=result.vendor_ids,
            idir_b=result.idir_b,
            transform_str=str(ts.locked_transform),
        )

        # If not yet confirmed wildcard, trigger async validation probe
        if not wc_state.is_confirmed and not ts.wildcard_confirmed:
            asyncio.create_task(
                self._wildcard_validation_probe(ts, result, capture, active_list)
            )

        # Check wildcard cap
        if wc_state.is_capped or len(ts.captures) >= WILDCARD_CAP:
            if wc_state.is_confirmed:
                ts.wildcard_cap_reached = True
                ts.p2_status = Phase2Status.CAPPED
                if ts in active_list:
                    active_list.remove(ts)
                self.output.log_info(
                    f'[Phase2] [{ts.ip}] wildcard cap reached ({WILDCARD_CAP} captures)'
                )

        # Send cleanup DELETE if requested
        if self.cleanup_sas:
            asyncio.create_task(
                self._send_delete(ts.ip, ts.port, result.cky_i, result.cky_r)
            )

        if self.tui_callback:
            self.tui_callback('p2_capture', {
                'host':     ts.ip,
                'group_id': word,
                'file':     file_path,
                'wildcard': is_wildcard,
                'mode':     capture.hashcat_mode,
            })

    async def _wildcard_validation_probe(
        self, ts: TargetState, original_response: ParsedResponse,
        original_capture: CapturedHash, active_list: list
    ) -> None:
        """
        Send a random-string probe to validate whether the host is a wildcard.
        If AM2 returned → wildcard confirmed → move hash to wildcard-flagged/.
        If Notify returned → legitimate named group → hash stays in valid/.

        CRITICAL-2 fix: routes through _pending_probes + a per-task asyncio.Queue
        that _continuous_recv_loop delivers to.  Does NOT touch _sync_queues or
        _sync_recv_active — mutating those from a fire-and-forget task would
        clobber all concurrent Phase 2 probe state.
        """
        random_id = generate_random_group_id()
        transforms = [ts.locked_transform] if ts.locked_transform else \
                     TRANSFORMS_BY_GROUP.get(DHGroup.GROUP_2, [])

        # Build probe manually so we control the CKY-I and can register the queue
        dh_group  = transforms[0].dh_group
        keypair   = generate_dh_keypair(dh_group)
        nonce_i   = generate_nonce(20)
        cky_i     = generate_cookie()

        probe = build_am1(
            target_ip=ts.ip,
            target_port=ts.port,
            group_id=random_id,
            transforms=transforms,
            keypair=keypair,
            nonce_i=nonce_i,
            cky_i=cky_i,
        )

        # Register a per-task queue in _pending_probes so _continuous_recv_loop
        # delivers the response here when CKY-I matches, without touching any
        # shared sync-recv state.
        wc_q: asyncio.Queue = asyncio.Queue(maxsize=4)
        # Store sentinel tuple: (ts, probe, sent_at, wc_q) — recv loop checks for queue
        self._pending_probes[cky_i] = (ts, probe, time.time(), wc_q)
        self.output.add_pcap_packet(probe.raw_am1, direction='out')

        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(self._sock, probe.raw_am1, (ts.ip, ts.port))
        except Exception as e:
            self.output.log_debug(f'[Wildcard] [{ts.ip}] send error: {e}')
            self._pending_probes.pop(cky_i, None)
            return

        # Wait for _continuous_recv_loop to deliver the response
        result = None
        try:
            raw_bytes, src_ip = await asyncio.wait_for(
                wc_q.get(), timeout=self.timeout
            )
            if src_ip == ts.ip:
                from .packet_parser import parse_response
                result = parse_response(raw_bytes, cky_i, src_ip)
                self.output.add_pcap_packet(raw_bytes, direction='in')
        except asyncio.TimeoutError:
            self.output.log_debug(f'[Wildcard] [{ts.ip}] validation probe timeout')
        finally:
            self._pending_probes.pop(cky_i, None)

        wc_state = self.wildcard_tracker.get_or_create(ts.ip)

        if result and result.response_type == ResponseType.CONFIRMED_AM2:
            # Wildcard confirmed
            wc_state.confirm_wildcard()
            ts.wildcard_confirmed = True

            # Move ALL existing captures for this host to wildcard-flagged/.
            # Not just original_capture — prior wordlist captures (e.g. "vpn", "cisco")
            # were saved to valid/ before wildcard was confirmed and must be moved.
            # move_hash_to_wildcard() checks src.exists() so already-moved files are skipped.
            moved = 0
            for cap in list(ts.captures):
                if not cap.is_wildcard:
                    self.output.move_hash_to_wildcard(cap)
                    cap.is_wildcard = True
                    moved += 1
            self.output.log_info(
                f'[Wildcard] [{ts.ip}] CONFIRMED via random probe "{random_id}" — '
                f'moved {moved} existing capture(s) to wildcard-flagged/ — '
                f'confidence={wc_state.confidence_level} ({wc_state.confidence_score}/100)'
            )
            # Log confidence signals
            for sig in wc_state.confidence_signals:
                self.output.log_info(f'[Wildcard] [{ts.ip}]   {sig}')
        else:
            # Legitimate named group
            wc_state.clear_suspected()
            self.output.log_info(
                f'[Wildcard] [{ts.ip}] validation "{random_id}" → NOT wildcard — '
                f'"{original_capture.group_id}" is a legitimate named group'
            )

    def _mark_host_inactive(
        self, ts: TargetState, word: str, word_idx: int,
        reason: str, active_list: list
    ) -> None:
        """Mark a host as DEAD or RATE_LIMITED and remove from active rotation."""
        remaining = len(self.wordlist) - word_idx - 1
        if reason == 'RATE_LIMITED':
            ts.p2_status = Phase2Status.RATE_LIMITED
        else:
            ts.p2_status = Phase2Status.DEAD

        self.output.log_host_dead(
            ts.ip, ts.last_response_word or word,
            ts.last_response_idx if ts.last_response_idx >= 0 else word_idx,
            remaining, reason
        )

        if ts in active_list:
            active_list.remove(ts)

        if self.tui_callback:
            self.tui_callback('p2_host_dead', {
                'host':      ts.ip,
                'reason':    reason,
                'last_word': ts.last_response_word or word,
                'remaining': remaining,
            })

    # -----------------------------------------------------------------------
    # Network I/O
    # -----------------------------------------------------------------------

    def _setup_socket(self) -> None:
        """Create and configure the UDP socket bound to source port matching target port.

        IKE protocol (RFC 2409): source port must equal destination port.
        Port 500 for standard IKE, port 4500 for NAT-T.  Binding to the wrong
        source port causes devices to silently drop the probe.
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.interface:
            try:
                self._sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    self.interface.encode()
                )
            except Exception as e:
                self.output.log_warning(f'Failed to bind to interface {self.interface}: {e}')

        # Bind source port to match the target port (IKE requires src==dst port)
        self._sock.bind(('0.0.0.0', self.port))
        self._sock.setblocking(False)

        # Enable ICMP error reporting on the UDP socket.
        # SO_RECVERR / IP_RECVERR causes the kernel to queue ICMP errors
        # (unreachable, admin-prohibited, fragmentation-needed) into the
        # socket's error queue.  We read them non-blocking via MSG_ERRQUEUE.
        # Zero runtime cost — purely a socket option set once at startup.
        try:
            SO_RECVERR = 11
            IP_RECVERR = 11
            self._sock.setsockopt(socket.SOL_SOCKET, SO_RECVERR, 1)
            self._sock.setsockopt(socket.SOL_IP,     IP_RECVERR, 1)
            self.output.log_debug('Socket: SO_RECVERR / IP_RECVERR enabled (ICMP error detection)')
        except Exception as e:
            self.output.log_warning(f'SO_RECVERR not available: {e} — ICMP detection disabled')

        # Set DF (Don't Fragment) bit on outbound packets.
        # ICMP type=3 code=4 (fragmentation needed) will then be queued
        # via MSG_ERRQUEUE if path MTU is too small for our probe packets.
        # All our AM1 packets are < 650 bytes so fragmentation is not a
        # current risk, but this enables path-MTU diagnostics.
        try:
            IP_MTU_DISCOVER = 10
            IP_PMTUDISC_DO  = 2
            self._sock.setsockopt(socket.SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            self.output.log_debug('Socket: IP_PMTUDISC_DO (DF bit) enabled')
        except Exception as e:
            self.output.log_warning(f'IP_PMTUDISC_DO not available: {e}')

        self.output.log_info(f'Socket bound to 0.0.0.0:{self.port}')

    def _poll_icmp_errors(self, target_ip: str) -> Optional[tuple[int, int]]:
        """
        Poll the socket's error queue for ICMP errors related to target_ip.
        Non-blocking — returns immediately with None if no errors are queued.
        Returns (icmp_type, icmp_code) if a relevant ICMP error is found.

        Relevant codes:
          type=3 code=3  — Port unreachable (UDP port not open)
          type=3 code=9  — Network admin prohibited (firewall REJECT)
          type=3 code=10 — Host admin prohibited (firewall REJECT)
          type=3 code=13 — Communication admin prohibited (stateful FW REJECT)
          type=3 code=4  — Fragmentation needed, DF set (path MTU too small)

        DROP-based firewalls send no ICMP and are undetectable.
        Only REJECT-based firewalls generate ICMP and are caught here.
        """
        if not self._sock:
            return None

        MSG_ERRQUEUE = 0x2000
        # sock_extended_err: uint32 errno, uint8 origin, uint8 type,
        #                     uint8 code, uint8 pad, uint32 info, uint32 data
        # Followed by sockaddr_in of the ICMP sender
        try:
            import struct
            # Receive up to 512 bytes of error + 256 bytes cmsg
            data, ancdata, flags, addr = self._sock.recvmsg(512, 256, MSG_ERRQUEUE)
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                # SOL_IP=0, IP_RECVERR=11
                if cmsg_level == 0 and cmsg_type == 11 and len(cmsg_data) >= 8:
                    ee_errno, ee_origin, ee_type, ee_code = struct.unpack_from(
                        '=IBBB', cmsg_data, 0
                    )
                    # ee_origin=2 means ICMP
                    if ee_origin == 2 and ee_type == 3:
                        self.output.log_debug(
                            f'[ICMP] [{target_ip}] type={ee_type} code={ee_code} '
                            f'errno={ee_errno}'
                        )
                        return (ee_type, ee_code)
        except BlockingIOError:
            pass   # No errors queued — normal case
        except OSError:
            pass   # SO_RECVERR not enabled or not supported
        except Exception as e:
            self.output.log_debug(f'[ICMP] poll error: {e}')

        return None

    async def _send_probe_and_receive(
        self,
        ts:         TargetState,
        group_id:   str,
        transforms: list[Transform],
    ) -> tuple:
        """
        Build and send one AM1 probe, wait for response with retries.
        Returns (ParsedResponse, ProbeMetadata) on success, (None, None) on timeout.

        Both values are returned so callers can use the ProbeMetadata for hash
        extraction without relying on _pending_probes (which is popped on success).
        """
        loop = asyncio.get_running_loop()

        # Generate fresh keypair, nonce, cookie for this probe
        dh_group = transforms[0].dh_group
        keypair  = generate_dh_keypair(dh_group)
        nonce_i  = generate_nonce(20)
        cky_i    = generate_cookie()

        # Build AM1 packet
        probe = build_am1(
            target_ip=ts.ip,
            target_port=ts.port,
            group_id=group_id,
            transforms=transforms,
            keypair=keypair,
            nonce_i=nonce_i,
            cky_i=cky_i,
        )

        # Store probe metadata with timestamp — retained for retention_window seconds
        # so the continuous recv loop can process late-arriving responses
        self._pending_probes[cky_i] = (ts, probe, time.time())

        # Log raw packet to PCAP
        self.output.add_pcap_packet(probe.raw_am1, direction='out')

        # Choose recv strategy based on whether the sync recv loop is active:
        # Active  (_sync_recv_active=True): queue-based, zero drops under concurrent load.
        #   Used for Phase 1 and pre-Phase-2 discovery.
        # Inactive: legacy polling (only used for wildcard validation which is
        #   a single-coroutine path with no concurrency concern).
        if self._sync_recv_active:
            # Queue path — register queue before sending so _sync_recv_loop
            # can route the response before the send even completes
            probe_q: asyncio.Queue = asyncio.Queue(maxsize=4)
            self._sync_queues[cky_i] = probe_q

            # Send with retries
            for attempt in range(self.retries + 1):
                try:
                    await loop.sock_sendto(self._sock, probe.raw_am1, (ts.ip, ts.port))
                except Exception as e:
                    self.output.log_error(f'Send error to {ts.ip}: {e}')
                    continue

                # Wait for response via queue (routed by _sync_recv_loop)
                try:
                    raw, src_ip = await asyncio.wait_for(
                        probe_q.get(), timeout=self.timeout
                    )
                    if src_ip != ts.ip:
                        continue  # wrong source — keep waiting
                    parsed = parse_response(raw, cky_i, src_ip)
                    self.output.add_pcap_packet(raw, direction='in')
                    self._sync_queues.pop(cky_i, None)
                    self._pending_probes.pop(cky_i, None)
                    return parsed, probe
                except asyncio.TimeoutError:
                    pass  # retry

            # All retries exhausted
            self._sync_queues.pop(cky_i, None)
            self._pending_probes.pop(cky_i, None)
            return None, None

        # Legacy polling path (Phase 2 inline discovery, wildcard validation, etc.)
        # Send with retries
        last_result = None
        for attempt in range(self.retries + 1):
            try:
                await loop.sock_sendto(self._sock, probe.raw_am1, (ts.ip, ts.port))
            except Exception as e:
                self.output.log_error(f'Send error to {ts.ip}: {e}')
                continue

            # Wait for response
            result = await self._recv_with_timeout(ts.ip, cky_i)
            if result is not None:
                # Log received packet to PCAP
                self.output.add_pcap_packet(result.raw, direction='in')
                # Clean up probe tracking (synchronous path — Phase 1 or inline discovery)
                self._pending_probes.pop(cky_i, None)
                return result, probe

            last_result = None  # timeout on this attempt

        # All retries exhausted — clean up only for synchronous callers (Phase 1).
        # Phase 2 fire-and-forget probes are cleaned up by the recv loop or stale cleanup.
        if cky_i in self._pending_probes:
            entry = self._pending_probes.get(cky_i)
            # Only remove if it was just added (no word_idx set) — i.e. Phase 1 caller
            if entry and entry[1].word_idx == -1:
                self._pending_probes.pop(cky_i, None)
        return None, None  # timeout

    async def _send_probe_only(
        self,
        ts:       TargetState,
        group_id: str,
        word_idx: int,
    ) -> None:
        """
        Fire-and-forget probe send for Phase 2.
        Builds and sends AM1 using the host's locked transform.
        Stores metadata with word_idx so the continuous recv loop can
        correlate late responses to the correct word.
        Does NOT wait for a response.
        """
        if not ts.locked_transform:
            return

        loop     = asyncio.get_running_loop()
        dh_group = ts.locked_transform.dh_group
        keypair  = generate_dh_keypair(dh_group)
        nonce_i  = generate_nonce(20)
        cky_i    = generate_cookie()

        probe = build_am1(
            target_ip=ts.ip,
            target_port=ts.port,
            group_id=group_id,
            transforms=[ts.locked_transform],
            keypair=keypair,
            nonce_i=nonce_i,
            cky_i=cky_i,
        )
        # Stamp with word_idx so recv loop can log correctly
        probe.word_idx = word_idx

        # Store with timestamp — recv loop and stale cleanup use this
        self._pending_probes[cky_i] = (ts, probe, time.time())

        self.output.add_pcap_packet(probe.raw_am1, direction='out')

        try:
            await loop.sock_sendto(self._sock, probe.raw_am1, (ts.ip, ts.port))
        except Exception as e:
            self.output.log_error(f'[Phase2] Send error to {ts.ip}: {e}')
            self._pending_probes.pop(cky_i, None)

    async def _recv_with_timeout(
        self, expected_ip: str, expected_cky_i: bytes
    ) -> Optional[ParsedResponse]:
        """
        Wait up to self.timeout seconds for a UDP response from expected_ip
        matching the expected initiator cookie.
        """
        loop     = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout

        while loop.time() < deadline:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break

            try:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, self._try_recv),
                    timeout=min(remaining, 0.1)
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

            if data is None:
                await asyncio.sleep(0.01)
                continue

            raw, (src_ip, src_port) = data

            # Quick cookie check before full parse
            if len(raw) >= 8 and raw[0:8] != expected_cky_i:
                # Not for us — skip (another probe's response)
                continue

            if src_ip != expected_ip:
                continue

            # Full parse
            parsed = parse_response(raw, expected_cky_i, src_ip)
            return parsed

        return None  # timeout

    def _try_recv(self):
        """Non-blocking recv attempt. Returns (data, addr) or None."""
        try:
            return self._sock.recvfrom(65535)
        except BlockingIOError:
            return None
        except Exception:
            return None

    async def _send_delete(
        self, ip: str, port: int, cky_i: bytes, cky_r: bytes
    ) -> None:
        """Send an ISAKMP Informational DELETE to clean up a half-open SA."""
        try:
            loop        = asyncio.get_running_loop()
            delete_pkt  = build_delete_packet(cky_i, cky_r, target_port=port)
            await loop.sock_sendto(self._sock, delete_pkt, (ip, port))
            self.output.log_debug(
                f'[Cleanup] DELETE sent to {ip} for SA '
                f'cky_i={cky_i.hex()} cky_r={cky_r.hex()}'
            )
        except Exception as e:
            self.output.log_debug(f'[Cleanup] DELETE failed to {ip}: {e}')
