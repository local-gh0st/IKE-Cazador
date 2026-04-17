#!/usr/bin/env python3
"""
ike-cazador — IKE Aggressive Mode Discovery and PSK Hash Capture Tool

Usage:
    sudo python3 ike-cazador.py <targets> [wordlist] [options]

Requires root (source port 500 bind + raw socket).
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import termios
import tty
import warnings
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Suppress Scapy logging/warnings BEFORE any Scapy import.
# ---------------------------------------------------------------------------
logging.getLogger('scapy.runtime').setLevel(logging.CRITICAL)
logging.getLogger('scapy.loading').setLevel(logging.CRITICAL)
logging.getLogger('scapy.supersocket').setLevel(logging.CRITICAL)
logging.getLogger('scapy').setLevel(logging.CRITICAL)
warnings.filterwarnings('ignore')

# Ensure the package directory is importable
sys.path.insert(0, str(Path(__file__).parent))

from ike_cazador.cli import (
    build_parser, apply_presets, check_root,
    load_targets_from_arg, validate_and_resolve_targets, validate_wordlist,
)
from ike_cazador.output import OutputManager
from ike_cazador.scanner import Scanner, derive_zero_capture_reason
from ike_cazador.tui import TUI


# ---------------------------------------------------------------------------
# Terminal state management
# ---------------------------------------------------------------------------

def _save_terminal() -> object:
    """Save current terminal state. Returns saved state or None."""
    try:
        return termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        return None


def _restore_terminal(saved_state) -> None:
    """Restore terminal to a previously saved state."""
    if saved_state is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, saved_state)
    except Exception:
        pass


def _read_keypress() -> str:
    """Read a single keypress from stdin (raw mode, self-restoring)."""
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        # Always restore — prevents terminal staying in raw mode on exception
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ch.lower()



async def main() -> int:
    # -----------------------------------------------------------------------
    # 1. Save terminal state immediately — before ANY tty manipulation
    # -----------------------------------------------------------------------
    saved_tty = _save_terminal()

    # -----------------------------------------------------------------------
    # 2. Root check
    # -----------------------------------------------------------------------
    check_root()

    # -----------------------------------------------------------------------
    # 3. Parse arguments
    # -----------------------------------------------------------------------
    parser = build_parser()
    args   = parser.parse_args()
    args   = apply_presets(args)

    # -----------------------------------------------------------------------
    # 4. Validate wordlist
    # -----------------------------------------------------------------------
    wordlist_path, wordlist = validate_wordlist(args.wordlist)

    # -----------------------------------------------------------------------
    # 5a. RESUME mode: skip Phase 1, load prior results
    # -----------------------------------------------------------------------
    if args.resume:
        tui = TUI()
        tui.console.print()
        tui.console.print('[bold cyan]ike-cazador[/]  |  IKE Aggressive Mode PSK Capture Tool')
        tui.console.print('[dim]─' * 60 + '[/]')
        tui.console.print()
        tui.console.print(f'  [yellow]RESUME MODE[/] — loading Phase 1 results from: {args.resume}',
                          justify='left')
        try:
            prior_states, prior_wordlist, prior_port = _load_resume(args.resume)
        except ValueError as e:
            tui.console.print(f'  [red][!] {e}[/]', justify='left')
            return 1

        aggressive = [(ip, ts) for ip, ts in prior_states.items()
                      if ts.p1_status.name == 'AGGRESSIVE']
        tui.console.print(
            f'  Loaded {len(prior_states)} hosts — '
            f'[green]{len(aggressive)}[/] aggressive, '
            f'wordlist: {wordlist_path} ({len(wordlist)} words)',
            justify='left'
        )
        tui.console.print()

        run_ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output = OutputManager(
            base_dir=args.output,
            run_timestamp=run_ts,
            no_pcap=args.no_pcap,
        )
        output.log_info(
            f'ike-cazador RESUME | source={args.resume} '
            f'wordlist={wordlist_path} ({len(wordlist)} words)'
        )

        scanner = Scanner(
            targets            = list(prior_states.keys()),
            port               = args.port,
            wordlist           = wordlist,
            output             = output,
            timeout            = args.timeout,
            retries            = args.retries,
            dead_threshold     = args.dead_threshold,
            max_host_time      = args.max_host_time,
            delay_ms           = args.delay,
            p1_probe_delay_ms  = args.p1_probe_delay_ms,
            p1_deep_cooldown_ms = args.p1_deep_cooldown_ms,
            concurrency        = args.concurrency,
            cleanup_sas        = args.cleanup_sas,
            interface          = args.interface,
            tui_callback       = tui.callback,
        )
        # Inject prior Phase 1 state into scanner
        scanner.target_states = prior_states

        _restore_terminal(saved_tty)
        try:
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        except Exception:
            pass

        proceed, chosen_delay = tui.show_phase2_confirmation(
            phase1_states=prior_states,
            wordlist_path=wordlist_path,
            total_words=len(wordlist),
            delay_ms=args.delay,
            concurrency=args.concurrency,
        )
        if not proceed:
            tui.console.print('\n[dim]Phase 2 cancelled.[/]')
            return 0

        scanner.delay_ms = chosen_delay
        scanner._setup_socket()
        tui.start_phase2(prior_states, len(wordlist), delay_ms=chosen_delay)

        interrupted = False
        try:
            await scanner.run_phase2()
        except KeyboardInterrupt:
            scanner.stop()
            interrupted = True
        finally:
            tui.stop_phase2()
            _restore_terminal(saved_tty)

        output.finalize(
            interrupted=interrupted,
            wordlist_path=wordlist_path,
            target_count=len(prior_states),
        )
        valid_count    = sum(1 for c in output._captures if not c.is_wildcard)
        wildcard_count = sum(1 for c in output._captures if c.is_wildcard)
        zero_reasons = {
            ts.ip: derive_zero_capture_reason(ts)
            for ts in prior_states.values()
            if ts.p1_status.name == 'AGGRESSIVE' and len(ts.captures) == 0
        }
        tui.show_final_summary(
            run_dir              = str(output.run_dir),
            captures             = output.capture_count,
            valid                = valid_count,
            wildcard             = wildcard_count,
            phase2_states        = prior_states,
            zero_capture_reasons = zero_reasons,
            generated_files      = output._generated_hashcat_files,
        )
        return 0

    # -----------------------------------------------------------------------
    # 5b. Normal mode: load and validate targets
    # -----------------------------------------------------------------------
    if not args.targets:
        print('[!] No targets provided. Use --resume for prior run or specify targets.',
              file=sys.stderr)
        return 1
    raw_targets = load_targets_from_arg(args.targets)

    tui = TUI()
    tui.console.print()
    tui.console.print('[bold cyan]ike-cazador[/]  |  IKE Aggressive Mode PSK Capture Tool')
    tui.console.print('[dim]─' * 60 + '[/]')
    tui.console.print()

    valid_ips, warnings_list = validate_and_resolve_targets(raw_targets)

    for w in warnings_list:
        if 'failed' in w.lower() or 'invalid' in w.lower():
            tui.console.print(f'  [yellow][!][/] {w}')
        elif 'resolved' in w.lower() or 'stripped' in w.lower():
            tui.console.print(f'  [dim][*][/] {w}')
        elif 'duplicate' in w.lower():
            tui.console.print(f'  [dim][~][/] {w}')
        else:
            tui.console.print(f'  [dim]    {w}[/]')

    if warnings_list:
        tui.console.print()

    if not valid_ips:
        tui.console.print('[red bold][!] No valid targets after validation. Exiting.[/]')
        return 1

    tui.console.print(
        f'  [bold]Targets:[/]   {len(valid_ips)} host(s)  |  '
        f'[bold]Wordlist:[/]  {len(wordlist)} words  |  '
        f'[bold]Port:[/]  {args.port}'
    )
    if args.conservative:
        tui.console.print('  [yellow]Conservative mode enabled[/] — '
                          'p1-delay=500ms, delay=150ms, cleanup-sas, dead-threshold=3')
    if args.cleanup_sas and not args.conservative:
        tui.console.print('  [yellow]--cleanup-sas enabled[/] — '
                          'ISAKMP DELETE will be sent after each capture')
    tui.console.print()

    # -----------------------------------------------------------------------
    # 6. Set up output manager
    # -----------------------------------------------------------------------
    run_ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    output = OutputManager(
        base_dir=args.output,
        run_timestamp=run_ts,
        no_pcap=args.no_pcap,
    )
    output.log_info(
        f'ike-cazador started | targets={len(valid_ips)} '
        f'wordlist={wordlist_path} ({len(wordlist)} words) port={args.port}'
    )

    # -----------------------------------------------------------------------
    # 7. Initialize scanner
    # -----------------------------------------------------------------------
    scanner = Scanner(
        targets              = valid_ips,
        port                 = args.port,
        wordlist             = wordlist,
        output               = output,
        timeout              = args.timeout,
        retries              = args.retries,
        dead_threshold       = args.dead_threshold,
        max_host_time        = args.max_host_time,
        delay_ms             = args.delay,
        p1_probe_delay_ms    = args.p1_probe_delay_ms,
        p1_deep_cooldown_ms  = args.p1_deep_cooldown_ms,
        concurrency          = args.concurrency,
        cleanup_sas          = args.cleanup_sas,
        interface            = args.interface,
        tui_callback         = tui.callback,
    )

    # -----------------------------------------------------------------------
    # 8. Phase 1: Discovery
    #
    # Ctrl+C during Phase 1 triggers a SOFT STOP — probing halts cleanly
    # and whatever hosts have already been confirmed as AGGRESSIVE are
    # carried forward to Phase 2.  This avoids having to re-run the whole
    # scan when a user spots the hosts they care about and wants to move on.
    #
    # Implementation: install a custom SIGINT handler that sets scanner._stop
    # instead of raising KeyboardInterrupt.  The gather() tasks check _stop
    # at each inter-probe delay and return early.  The handler is restored
    # to the default immediately after Phase 1 finishes.
    # -----------------------------------------------------------------------
    p1_soft_stop = False

    def _p1_sigint_handler(signum, frame):
        nonlocal p1_soft_stop
        p1_soft_stop = True
        scanner.stop()   # sets _stop=True; tasks see it on next iteration
        output.log_info('Phase 1: Ctrl+C received — stopping probes, '
                        'proceeding with confirmed hosts')

    old_sigint = signal.signal(signal.SIGINT, _p1_sigint_handler)

    tui.start_phase1(valid_ips)
    try:
        phase1_states = await scanner.run_phase1()
    finally:
        signal.signal(signal.SIGINT, old_sigint)   # always restore SIGINT
        tui.stop_phase1()

    # -----------------------------------------------------------------------
    # 9. Phase 2 confirmation prompt
    #
    # CRITICAL: restore terminal state and flush stdin before the prompt.
    # -----------------------------------------------------------------------
    _restore_terminal(saved_tty)
    try:
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass

    if p1_soft_stop:
        # Phase 1 was interrupted — show what we have and ask user to decide
        aggressive_count = sum(
            1 for ts in phase1_states.values()
            if ts.p1_status.name == 'AGGRESSIVE'
        )
        still_probing = sum(
            1 for ts in phase1_states.values()
            if ts.p1_status.name in ('PENDING', 'PROBING')
        )
        tui.console.print()
        tui.console.print('[yellow]Phase 1 stopped early (Ctrl+C).[/]', justify='left')
        if still_probing:
            tui.console.print(
                f'  [dim]{still_probing} host(s) were still being probed '
                f'and have been classified as NO_RESPONSE.[/]',
                justify='left'
            )
        if aggressive_count == 0:
            tui.console.print(
                '  No aggressive mode hosts confirmed yet. '
                'Phase 1 results saved.',
                justify='left'
            )
            output.finalize(interrupted=True, wordlist_path=wordlist_path,
                            target_count=len(valid_ips))
            return 0
        tui.console.print(
            f'  [green]{aggressive_count}[/] host(s) confirmed aggressive '
            f'— proceeding to Phase 2 confirmation.',
            justify='left'
        )
        tui.console.print()

    proceed, chosen_delay = tui.show_phase2_confirmation(
        phase1_states=phase1_states,
        wordlist_path=wordlist_path,
        total_words=len(wordlist),
        delay_ms=args.delay,
        concurrency=args.concurrency,
    )

    if not proceed:
        output.finalize(interrupted=False, wordlist_path=wordlist_path,
                        target_count=len(valid_ips))
        tui.console.print('\n[dim]Phase 2 cancelled. Phase 1 results saved.[/]', justify='left')
        tui.console.print(f'\n  Results: [dim]{output.run_dir}[/]', justify='left')
        tui.console.print('  [dim]Review summary.txt for ike-scan commands and findings.[/]', justify='left')
        return 0

    # Apply the user's chosen speed to scanner and TUI
    scanner.delay_ms = chosen_delay

    # Mark AM-confirmed-no-transform hosts as COMPLETE so Phase 2 skips them.
    # These hosts have AM enabled (Notify-14 confirmed) but no matching transform
    # was found — there's no point probing the wordlist against them.
    from ike_cazador.constants import Phase2Status
    for ts in scanner.target_states.values():
        if (ts.p1_status.name == 'AGGRESSIVE' and
                not ts.locked_transform and not ts.locked_dh_group):
            ts.p2_status = Phase2Status.COMPLETE

    # -----------------------------------------------------------------------
    # 10. Phase 2: Wordlist brute-force
    #
    # No keyboard listener thread — screen=True Live mode handles the display
    # in the alternate terminal buffer.  Ctrl+C (KeyboardInterrupt) is the
    # cancel mechanism; it works correctly through screen=True.
    # -----------------------------------------------------------------------
    tui.start_phase2(phase1_states, len(wordlist), delay_ms=chosen_delay)

    interrupted = False
    try:
        await scanner.run_phase2()
    except KeyboardInterrupt:
        scanner.stop()
        interrupted = True
    finally:
        tui.stop_phase2()
        _restore_terminal(saved_tty)

    # -----------------------------------------------------------------------
    # 11. Finalize output
    # -----------------------------------------------------------------------
    output.finalize(
        interrupted=interrupted,
        wordlist_path=wordlist_path,
        target_count=len(valid_ips),
    )

    valid_count    = sum(1 for c in output._captures if not c.is_wildcard)
    wildcard_count = sum(1 for c in output._captures if c.is_wildcard)

    # Compute specific zero-capture reason for each Phase 2 host that got 0 hashes
    zero_capture_reasons = {
        ts.ip: derive_zero_capture_reason(ts)
        for ts in scanner.target_states.values()
        if ts.p1_status.name == 'AGGRESSIVE' and len(ts.captures) == 0
    }

    tui.show_final_summary(
        run_dir              = str(output.run_dir),
        captures             = output.capture_count,
        valid                = valid_count,
        wildcard             = wildcard_count,
        phase2_states        = scanner.target_states,
        zero_capture_reasons = zero_capture_reasons,
        generated_files      = output._generated_hashcat_files,
    )

    if interrupted:
        tui.console.print('[yellow]Scan interrupted by user. All results saved.[/]')

    # Always show results path — even if no hashes captured, summary.txt has
    # AM confirmation commands and investigation findings.
    tui.console.print(
        f'\n  Results: [dim]{output.run_dir}[/]',
        justify='left'
    )
    tui.console.print(
        f'  [dim]Review summary.txt for ike-scan commands and findings.[/]',
        justify='left'
    )

    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
