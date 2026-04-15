"""
Rich terminal UI — Phase 1 and Phase 2 display.

Phase 1: Live in-place table with per-host status and DH probe progress.
Phase 2: Progress bar + live host table + recent captures feed.

Uses ASCII bracket indicators [+]/[-]/[~]/[!] for cross-terminal compatibility.
Colors applied via Rich markup (green/red/yellow) — no double-width Unicode symbols.
Auto-detects terminal width via shutil.get_terminal_size().
"""

import shutil
import threading
import time
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeRemainingColumn, MofNCompleteColumn,
)
from rich.layout import Layout
from rich.text import Text
from rich import box

if TYPE_CHECKING:
    from .scanner import TargetState, Scanner
from .constants import HostStatus, Phase2Status, DHGroup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status_markup(status: HostStatus, detail: str = '') -> Text:
    """Return a colored Rich Text for a host status."""
    if status == HostStatus.AGGRESSIVE:
        return Text('[+] AGGRESSIVE', style='bold green')
    elif status == HostStatus.AGGRESSIVE_RSA:
        return Text('[+] AGGRESSIVE (RSA AUTH)', style='green')
    elif status == HostStatus.AGGRESSIVE_WILDCARD:
        return Text('[+] AGGRESSIVE (WILDCARD)', style='bold cyan')
    elif status == HostStatus.NOT_VULNERABLE:
        return Text('[-] NOT VULNERABLE', style='red')
    elif status == HostStatus.IKEV2_ONLY:
        return Text('[-] IKEV2 ONLY', style='red')
    elif status == HostStatus.UNKNOWN:
        return Text('[?] UNKNOWN', style='yellow')
    elif status == HostStatus.NO_RESPONSE:
        return Text('[-] NO RESPONSE', style='dim red')
    elif status == HostStatus.FIREWALL_FILTERED:
        return Text('[!] FIREWALL FILTERED', style='bold yellow')
    elif status == HostStatus.PROBING:
        return Text('[~] PROBING', style='yellow')
    else:
        return Text('[~] PENDING', style='dim')


def _p2_status_markup(ts: 'TargetState') -> Text:
    """Return a colored Rich Text for Phase 2 host status."""
    if ts.p2_status == Phase2Status.ACTIVE:
        cap = len(ts.captures)
        cap_str = f'  ({cap} capture{"s" if cap != 1 else ""})' if cap else ''
        return Text(f'[~] SCANNING w/{ts.words_attempted}{cap_str}', style='yellow')
    elif ts.p2_status == Phase2Status.DEAD:
        return Text(f'[!] UNRESPONSIVE @ w/{ts.last_response_idx}', style='bold red')
    elif ts.p2_status == Phase2Status.RATE_LIMITED:
        return Text(f'[!] RATE LIMITED @ w/{ts.last_response_idx}', style='bold magenta')
    elif ts.p2_status == Phase2Status.CAPPED:
        return Text(f'[=] WILDCARD CAP ({len(ts.captures)} captures)', style='cyan')
    elif ts.p2_status == Phase2Status.COMPLETE:
        cap = len(ts.captures)
        return Text(f'[+] COMPLETE ({cap} capture{"s" if cap != 1 else ""})', style='green')
    return Text('?', style='dim')


def _dh_probes_str(ts: 'TargetState') -> str:
    """Build a compact string showing which DH groups have been tried."""
    tried = ts.p1_dh_groups_tried
    if not tried:
        return '—'
    parts = []
    for g in tried:
        parts.append(f'G{int(g)}-')
    return ' '.join(parts) if parts else '—'


def _term_width() -> int:
    """Get terminal width, min 80."""
    return max(80, shutil.get_terminal_size((100, 40)).columns)


# ---------------------------------------------------------------------------
# TUI class
# ---------------------------------------------------------------------------

class TUI:
    """
    Manages all terminal output for ike-cazador.
    Receives events from the scanner via callback.
    """

    def __init__(self):
        self.console = Console()
        self._live:   Optional[Live] = None
        self._phase   = 1
        self._lock    = threading.Lock()

        # Render rate throttle.
        # Phase 1: max 4 renders/sec (0.25s) — hosts resolve infrequently, fast is fine.
        # Phase 2: max 1 render/sec (1.0s) — probes fire rapidly, slow is better.
        # Captures and dead-host events always render immediately regardless of throttle.
        self._last_p1_render:   float = 0.0
        self._last_p2_render:   float = 0.0
        self._p1_render_interval: float = 0.25   # 4/sec for Phase 1
        self._p2_render_interval: float = 1.0    # 1/sec for Phase 2 routine updates

        # Phase 1 state
        self._p1_states: dict[str, 'TargetState'] = {}
        self._p1_total   = 0
        self._p1_resolved = 0

        # Phase 2 state
        self._p2_states:  dict[str, 'TargetState'] = {}
        self._p2_total_words = 0
        self._p2_current_word = 0
        self._p2_captures: list[dict] = []
        self._p2_start_time = 0.0
        self._p2_delay_ms   = 200   # configured delay, used for config-based ETA
        self._progress: Optional[Progress] = None

    # -----------------------------------------------------------------------
    # Event callback (called from scanner)
    # -----------------------------------------------------------------------

    def callback(self, event: str, data: dict) -> None:
        with self._lock:
            now = time.time()

            if event == 'p1_update':
                ts = data['state']
                self._p1_states[ts.ip] = ts
                if ts.p1_status not in (HostStatus.PENDING, HostStatus.PROBING):
                    self._p1_resolved = sum(
                        1 for s in self._p1_states.values()
                        if s.p1_status not in (HostStatus.PENDING, HostStatus.PROBING)
                    )
                # Phase 1: throttle to 4/sec
                if self._live and (now - self._last_p1_render) >= self._p1_render_interval:
                    self._last_p1_render = now
                    self._live.update(self._render_phase1())

            elif event == 'p2_progress':
                self._p2_current_word = data['word_idx'] + 1
                # Phase 2 routine progress: throttle to 1/sec — probes are fast,
                # updating every probe causes visible flicker
                if self._live and (now - self._last_p2_render) >= self._p2_render_interval:
                    self._last_p2_render = now
                    self._live.update(self._render_phase2())

            elif event == 'p2_host_update':
                ts = data['state']
                self._p2_states[ts.ip] = ts
                # Routine host update: same 1/sec throttle
                if self._live and (now - self._last_p2_render) >= self._p2_render_interval:
                    self._last_p2_render = now
                    self._live.update(self._render_phase2())

            elif event == 'p2_capture':
                self._p2_captures.append(data)
                ts_ip = data['host']
                if ts_ip in self._p2_states:
                    # Capture found — always render immediately
                    self._last_p2_render = now
                    if self._live:
                        self._live.update(self._render_phase2())

            elif event == 'p2_host_dead':
                # Host dead/rate-limited — always render immediately
                self._last_p2_render = now
                if self._live:
                    self._live.update(self._render_phase2())

    # -----------------------------------------------------------------------
    # Phase 1 display
    # -----------------------------------------------------------------------

    def start_phase1(self, targets: list[str]) -> None:
        """Start Phase 1 live display."""
        self._phase = 1
        self._p1_total = len(targets)
        # Pre-populate states as PENDING
        from .scanner import TargetState
        for ip in targets:
            if ip not in self._p1_states:
                ts = TargetState(ip=ip, port=500)
                ts.p1_status = HostStatus.PENDING
                self._p1_states[ip] = ts

        self._live = Live(
            self._render_phase1(),
            console=self.console,
            refresh_per_second=4,
            transient=True,
        )
        self._live.__enter__()

    def stop_phase1(self) -> None:
        """Stop Phase 1 live display."""
        if self._live:
            self._live.update(self._render_phase1())
            self._live.__exit__(None, None, None)
            self._live = None
            # Move to a fresh line and reset Rich's internal cursor state.
            # With transient=True, the panel is erased and the cursor moves
            # back to where the panel started.  A real newline here ensures
            # the confirmation prompt starts at column 0 on a clean line.
            self.console.print()
            self.console.print('', end='', highlight=False)

    def _render_phase1(self) -> Panel:
        width = _term_width()

        # Header progress bar (text-based)
        resolved  = self._p1_resolved
        total     = self._p1_total
        bar_width = min(40, width - 30)
        filled    = int(bar_width * resolved / max(total, 1))
        bar       = '#' * filled + '.' * (bar_width - filled)
        progress_line = f'[{bar}] {resolved} / {total} hosts resolved'

        # Probe order hint
        probe_order = 'G2 > G14 > G5 > G19 > G20 > G1 > G15 > G21'

        # Build table
        tbl = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style='bold white',
            width=width - 4,
            pad_edge=False,
        )
        tbl.add_column('TARGET',  min_width=20, no_wrap=True)
        tbl.add_column('STATUS',  min_width=28, no_wrap=True)
        tbl.add_column('DETAILS', min_width=30, no_wrap=False)

        for ip, ts in self._p1_states.items():
            status_text = _status_markup(ts.p1_status)

            if ts.p1_status == HostStatus.PROBING:
                if ts.p1_deep_scanning:
                    # Deep scan fallback in progress — show current single transform
                    t_str = ts.p1_deep_transform_str or '...'
                    detail = f'DEEP SCAN: {t_str}'
                else:
                    detail = _dh_probes_str(ts)
            elif ts.p1_status == HostStatus.AGGRESSIVE:
                if ts.locked_transform:
                    t = str(ts.locked_transform)
                elif ts.locked_dh_group:
                    t = f'G{int(ts.locked_dh_group)} (transform unconfirmed — detected via Notify-24)'
                else:
                    t = '— (transform unknown)'
                vendor = f' | {ts.vendor_str}' if ts.vendor_str != 'Unknown' else ''
                detail = f'{t}{vendor}'
                if ts.wildcard_confirmed:
                    detail += ' [WILDCARD]'
            elif ts.p1_status == HostStatus.AGGRESSIVE_RSA:
                detail = 'RSA/cert auth — no PSK capture possible'
            elif ts.p1_status == HostStatus.NOT_VULNERABLE:
                detail = ts.p1_detail or 'No aggressive mode response'
            elif ts.p1_status == HostStatus.IKEV2_ONLY:
                detail = 'IKEv2 — AM PSK attack does not apply'
            elif ts.p1_status == HostStatus.UNKNOWN:
                detail = 'All 8 DH groups exhausted — transform unknown'
            elif ts.p1_status == HostStatus.NO_RESPONSE:
                detail = 'No IKE response on port 500'
            elif ts.p1_status == HostStatus.FIREWALL_FILTERED:
                detail = 'ICMP admin-prohibited — return path firewall-filtered (REJECT rule)'
            else:
                detail = '—'

            tbl.add_row(ip, status_text, detail)

        content = Text()
        content.append(f'  Probing {total} host(s) across 8 DH groups\n', style='dim')
        content.append(f'  Probe order: {probe_order}\n', style='dim')
        content.append(f'  {progress_line}\n\n')

        from rich.console import Group as RichGroup
        body = RichGroup(content, tbl)

        return Panel(
            body,
            title='[bold cyan]ike-cazador[/]  |  Phase 1: Aggressive Mode Discovery',
            border_style='cyan',
            width=width,
        )

    # -----------------------------------------------------------------------
    # Phase 2 display
    # -----------------------------------------------------------------------

    def start_phase2(self, target_states: dict, total_words: int,
                     delay_ms: int = 200) -> None:
        """Start Phase 2 live display.

        Uses screen=True — takes over the terminal alternate screen buffer.
        The panel renders at a fixed position and updates in place at 1Hz
        regardless of terminal size, number of hosts, or scan speed.
        No scrolling, no buffer flooding.  When Phase 2 exits, the terminal
        is restored and 'Scan Complete' prints as normal text below.
        """
        self._phase           = 2
        self._p2_states       = {ip: ts for ip, ts in target_states.items()
                                  if ts.p1_status == HostStatus.AGGRESSIVE}
        self._p2_total_words  = total_words
        self._p2_start_time   = time.time()
        self._p2_delay_ms     = delay_ms   # stored for config-based ETA estimate

        self._live = Live(
            self._render_phase2(),
            console=self.console,
            refresh_per_second=1,
            screen=True,
        )
        self._live.__enter__()

    def stop_phase2(self) -> None:
        """Stop Phase 2 live display."""
        if self._live:
            self._live.update(self._render_phase2())
            self._live.__exit__(None, None, None)
            self._live = None
            self.console.print('', end='', highlight=False)

    def _render_phase2(self) -> Panel:
        width   = _term_width()
        total_w = self._p2_total_words
        current_w = self._p2_current_word
        n_active  = sum(1 for ts in self._p2_states.values() if ts.is_p2_active)
        n_captures = sum(len(ts.captures) for ts in self._p2_states.values())

        elapsed = time.time() - self._p2_start_time
        eta_str = self._calc_eta(current_w, total_w, elapsed, n_active)
        # inner = usable chars inside panel borders
        inner = max(40, width - 4)

        # Stats section — fixed max width so bar size is predictable.
        # Cap ETA at 9 chars to prevent progress line wrapping on unusual ETA values.
        eta_capped = eta_str[:9]   # no padding — shorter ETAs leave more room for bar
        stats = f'  {current_w}/{total_w}  |  {n_active} up  |  {n_captures} hits  |  ETA:{eta_capped}'

        # Bar width = usable_content_width - 2(indent) - 2(brackets) - len(stats)
        # usable_content_width = width - 4 (panel border + padding) = inner
        bar_w  = max(10, inner - 4 - len(stats))
        filled = int(bar_w * current_w / max(total_w, 1))
        bar    = '#' * filled + '.' * (bar_w - filled)
        progress = f'[{bar}]{stats}'

        # Column widths — fixed so separator never wraps
        col_t = 20   # TARGET
        col_s = 32   # STATUS
        sep_w = col_t + col_s + 12   # approximate details width

        from rich.text import Text as RText

        body = RText()

        # Line 1: wordlist/hosts info
        body.append(f'  Wordlist: {total_w} words   Hosts: {len(self._p2_states)}\n')

        # Line 2: progress bar (always exactly 1 line due to fixed bar_w)
        body.append(f'  {progress}\n')

        # Line 3: table column headers
        body.append(
            f'  {"TARGET":<{col_t}}  {"STATUS":<{col_s}}  DETAILS\n',
            style='bold white'
        )

        # Line 4: separator (fixed width, never wraps)
        body.append(f'  {"─" * min(sep_w, inner - 4)}\n', style='dim')

        # Lines 5..4+N: host rows (1 per host, always present)
        for ip, ts in self._p2_states.items():
            captures = len(ts.captures)
            wc_str   = ' [WC]' if ts.wildcard_confirmed else ''
            if ts.p2_status == Phase2Status.DEAD:
                remaining  = total_w - ts.last_response_idx - 1
                status_str = f'[!] DEAD @ w/{ts.last_response_idx}'
                detail     = f'{captures} cap | {remaining} left'
                style      = 'bold red'
            elif ts.p2_status == Phase2Status.RATE_LIMITED:
                remaining  = total_w - ts.last_response_idx - 1
                status_str = f'[!] RATE LIM @ w/{ts.last_response_idx}'
                detail     = f'{captures} cap | {remaining} left | WAF?'
                style      = 'bold magenta'
            elif ts.p2_status == Phase2Status.CAPPED:
                status_str = f'[=] WILDCARD CAP ({captures})'
                detail     = f'{captures} capture(s){wc_str}'
                style      = 'cyan'
            elif ts.p2_status == Phase2Status.COMPLETE:
                status_str = f'[+] COMPLETE ({captures})'
                detail     = f'{captures} capture(s){wc_str}'
                style      = 'green'
            else:
                status_str = f'[~] SCANNING w/{ts.words_attempted}'
                detail     = f'{captures} capture(s){wc_str}'
                style      = 'yellow'

            body.append(
                f'  {ip:<{col_t}}  {status_str:<{col_s}}  {detail}\n',
                style=style
            )

        # Last capture line — ALWAYS 1 line (blank placeholder when no captures yet)
        # This keeps panel height constant regardless of scan progress.
        recent = self._p2_captures
        if recent:
            cap = recent[-1]
            wc  = ' [WC]' if cap.get('wildcard') else ''
            body.append(
                f'  Last: {cap["host"]:<18}  "{cap["group_id"]}"  m={cap["mode"]}{wc}\n',
                style='green'
            )
        else:
            body.append('  Last: —\n', style='dim')

        # Controls footer — no blank line before
        body.append('  Ctrl+C to cancel and save results', style='dim')

        return Panel(
            body,
            title='[bold cyan]ike-cazador[/]  |  Phase 2: Wordlist Brute-Force',
            border_style='cyan',
            width=width,
        )

    def _calc_eta(self, current: int, total: int, elapsed: float,
                  active_hosts: int) -> str:
        """
        Estimate remaining Phase 2 time.

        Uses actual rate once 5+ words have completed (reliable data).
        Before that, uses config-based estimate based on delay_ms only.
        Phase 2 sends to all hosts simultaneously (fire-and-forget), then
        waits delay_ms once — NOT delay_ms × n_hosts sequentially.
        """
        remaining = total - current
        if remaining <= 0:
            return 'done'

        # Config-based estimate: one word round = send to all hosts (parallel)
        # then wait delay_ms once. Host count does NOT multiply the time.
        ms_per_round = max(self._p2_delay_ms, 50)
        config_eta   = (remaining * ms_per_round) / 1000.0

        # Actual-rate estimate — only trust once 10+ words complete AND
        # the actual rate isn't wildly slower than config estimate.
        # The first few word rounds are slow due to pre-discovery overhead
        # (Notify-24 hosts needing per-transform probing before wordlist starts).
        # Cap actual_eta at 3× config_eta to avoid multi-hour nonsense ETAs
        # caused by pre-discovery inflating the early elapsed time.
        if current >= 10 and elapsed > 1.0:
            rate       = current / elapsed
            actual_eta = remaining / rate
            # Cap at 3× config to prevent pre-discovery skew
            eta_secs   = min(actual_eta, config_eta * 3)
        else:
            eta_secs = config_eta

        if eta_secs < 5:
            return '< 5s'
        m, s = divmod(int(eta_secs), 60)
        h, m = divmod(m, 60)
        if h:
            return f'{h}h {m:02d}m'
        return f'{m}m {s:02d}s'
    # -----------------------------------------------------------------------
    # Phase 2 confirmation prompt
    # -----------------------------------------------------------------------

    def show_phase2_confirmation(
        self,
        phase1_states: dict,
        wordlist_path: str,
        total_words:   int,
        delay_ms:      int,
        concurrency:   int,
    ) -> tuple:
        """
        Display Phase 1 summary and Phase 2 speed selection prompt.
        Returns (proceed: bool, chosen_delay_ms: int).

        Speed presets:
          [F] Fast         — 100ms delay
          [Y] Standard     — 250ms delay  (default, Enter)
          [S] Slow         — 500ms delay  (conservative, rate-limit safe)
          [N] Cancel
        """
        width = _term_width()

        aggressive = [(ip, ts) for ip, ts in phase1_states.items()
                       if ts.p1_status == HostStatus.AGGRESSIVE]
        rsa_auth   = [(ip, ts) for ip, ts in phase1_states.items()
                       if ts.p1_status == HostStatus.AGGRESSIVE_RSA]
        not_vuln   = [(ip, ts) for ip, ts in phase1_states.items()
                       if ts.p1_status in (HostStatus.NOT_VULNERABLE,
                                            HostStatus.IKEV2_ONLY)]
        unknown    = [(ip, ts) for ip, ts in phase1_states.items()
                       if ts.p1_status == HostStatus.UNKNOWN]
        no_resp    = [(ip, ts) for ip, ts in phase1_states.items()
                       if ts.p1_status == HostStatus.NO_RESPONSE]
        fw_filtered = [(ip, ts) for ip, ts in phase1_states.items()
                        if ts.p1_status == HostStatus.FIREWALL_FILTERED]

        # Estimate Phase 2 time
        if aggressive:
            total_probes = len(aggressive) * total_words
            # Correct formula: one word round = delay_ms wait (sends are parallel
            # fire-and-forget, NOT delay_ms × n_hosts sequential).
            # Add 10s for late-response retention window at end.
            send_secs = total_words * delay_ms / 1000.0
            est_secs  = send_secs + 10
            m, s      = divmod(int(est_secs), 60)
            eta_str   = f'{m}m {s:02d}s' if m else f'{s}s'
        else:
            total_probes = 0
            eta_str      = 'N/A'

        self.console.print()
        sep = '─' * min(72, _term_width() - 4)
        self.console.print(sep)
        self.console.print('[bold cyan]Phase 1 Complete[/]')
        self.console.print(sep)
        self.console.print()

        # Summary counts
        self.console.print(
            f'  [bold]{len(phase1_states)}[/] host(s) scanned  |  '
            f'[green bold]{len(aggressive)}[/] aggressive  |  '
            f'[red]{len(not_vuln)}[/] not vulnerable  |  '
            f'[yellow]{len(unknown)}[/] unknown  |  '
            f'[dim]{len(no_resp)}[/] no response  |  '
            f'[bold yellow]{len(fw_filtered)}[/] firewall-filtered',
            justify='left',
        )
        self.console.print()

        if aggressive:
            self.console.print('  [bold green]Hosts queued for Phase 2:[/]', justify='left')
            for ip, ts in aggressive:
                if ts.locked_transform:
                    t = str(ts.locked_transform)
                elif ts.locked_dh_group:
                    t = f'G{int(ts.locked_dh_group)} (unconfirmed — Notify-24)'
                else:
                    t = '—'
                wc  = '  [WILDCARD LIKELY]' if ts.wildcard_confirmed else ''
                self.console.print(f'    {ip:<22}  {t}{wc}', justify='left')
            self.console.print()

        if rsa_auth:
            self.console.print('  [yellow]RSA/cert auth (skipped — no PSK):[/]', justify='left')
            for ip, _ in rsa_auth:
                self.console.print(f'    {ip}', justify='left')
            self.console.print()

        if not_vuln:
            self.console.print('  [red]Not vulnerable (skipped):[/]', justify='left')
            for ip, ts in not_vuln:
                self.console.print(f'    {ip:<22}  {ts.p1_detail}', style='dim', justify='left')
            self.console.print()

        if unknown:
            self.console.print('  [yellow]Unknown (all 8 DH groups exhausted, skipped):[/]', justify='left')
            for ip, _ in unknown:
                self.console.print(f'    {ip}', style='dim', justify='left')
            self.console.print()

        if fw_filtered:
            self.console.print('  [bold yellow]Firewall-filtered (skipped):[/]', justify='left')
            self.console.print(
                '  [dim]  ICMP admin-prohibited received — device may be IKE-capable[/]',
                justify='left'
            )
            self.console.print(
                '  [dim]  but the return path is blocked by a REJECT firewall rule.[/]',
                justify='left'
            )
            self.console.print(
                '  [dim]  Try scanning from a different source IP or network segment.[/]',
                justify='left'
            )
            for ip, ts in fw_filtered:
                self.console.print(f'    {ip}', style='dim yellow', justify='left')
            self.console.print()

        if not aggressive:
            self.console.print('  [red bold]No aggressive mode hosts found. Nothing to do in Phase 2.[/]', justify='left')
            self.console.print()
            return False, delay_ms

        self.console.print(sep)
        self.console.print(f'  Wordlist:          {wordlist_path}  ({total_words} words)', justify='left')
        total_probes = len(aggressive) * total_words
        self.console.print(
            f'  Estimated probes:  ~{total_probes:,}  '
            f'({len(aggressive)} host(s) × {total_words} words)',
            justify='left',
        )
        self.console.print()

        # Speed preset options with individual ETAs
        presets = [
            ('F', 'Fast         ', 100,  'higher rate-limit risk'),
            ('Y', 'Standard     ', 250,  'recommended — default'),
            ('S', 'Slow         ', 500,  'rate-limit safe (conservative)'),
        ]
        self.console.print('  Scan speed:', justify='left')
        for key, label, d_ms, note in presets:
            # Correct formula: one word round = delay_ms (fire-and-forget, not sequential)
            # + 10s for late-response retention window at end
            eta_secs      = total_words * d_ms / 1000.0 + 10
            m, s          = divmod(int(eta_secs), 60)
            eta           = f'{m}m {s:02d}s' if m else f'{s}s'
            default_marker = '  ← default' if key == 'Y' else ''
            self.console.print(
                f'    [{key}] {label}  {d_ms}ms delay   ETA: ~{eta:<10}  ({note}){default_marker}',
                style='dim', justify='left'
            )
        self.console.print('    [N] Cancel', style='dim', justify='left')
        self.console.print()

        try:
            ans = input('  Enter/Y = Standard, F = Fast, S = Slow, N = Cancel: ').strip().lower()
            self.console.print()
        except (EOFError, KeyboardInterrupt):
            self.console.print()
            return False, delay_ms

        if ans == 'f':
            return True, 100
        if ans == 's':
            return True, 500
        if ans == 'n':
            return False, delay_ms
        return True, 250   # Y, Enter, or anything else → Standard

    def show_paused(self) -> None:
        self.console.print(
            '\n  [bold yellow][PAUSED][/]  '
            'Press [bold]R[/] to resume or [bold]Q[/] to quit and save.',
            justify='left',
        )

    def show_final_summary(self, run_dir: str, captures: int,
                            valid: int, wildcard: int,
                            phase2_states: Optional[dict] = None,
                            zero_capture_reasons: Optional[dict] = None,
                            generated_files: Optional[dict] = None) -> None:
        """Print final summary after the scan completes."""
        from rich.text import Text as RText
        sep = '─' * min(72, _term_width() - 4)
        self.console.print()
        self.console.print(sep)
        self.console.print('[bold cyan]Scan Complete[/]', justify='left')
        self.console.print(sep)

        # Per-host Phase 2 results table
        if phase2_states:
            p2_hosts = [ts for ts in phase2_states.values()
                        if ts.p1_status.name == 'AGGRESSIVE']
            if p2_hosts:
                self.console.print('\n  Phase 2 Results:', justify='left')
                col_ip  = 22
                col_st  = 12
                col_cap = 9
                # DETAILS column starts at: 2(prefix) + col_ip + 2 + col_st + 2 + col_cap + 2 = 51
                # Use remaining terminal width for DETAILS so content never wraps.
                # Subtract 4 from col_det to avoid the separator line itself overflowing
                # (Rich adds internal padding that the raw terminal width doesn't account for).
                details_start = 2 + col_ip + 2 + col_st + 2 + col_cap + 2
                col_det = max(25, _term_width() - details_start - 4)
                hdr = (f'  {"HOST":<{col_ip}}  {"TYPE":<{col_st}}'
                       f'  {"CAPTURES":<{col_cap}}  DETAILS')
                self.console.print(hdr, style='bold white', justify='left')
                self.console.print(
                    f'  {"─"*col_ip}  {"─"*col_st}  {"─"*col_cap}  {"─"*col_det}',
                    style='dim', justify='left'
                )
                zero_reasons = zero_capture_reasons or {}
                for ts in p2_hosts:
                    caps    = len(ts.captures)
                    is_wc   = ts.wildcard_confirmed
                    wc_tag  = 'WILDCARD' if is_wc else 'NAMED'
                    style   = 'cyan' if is_wc else 'green' if caps > 0 else 'dim'

                    # DETAILS: transform string for success, short reason for zero captures
                    if caps > 0:
                        if ts.locked_transform:
                            details = str(ts.locked_transform)
                        elif ts.locked_dh_group:
                            details = f'G{int(ts.locked_dh_group)} (transform confirmed in Phase 2)'
                        else:
                            details = '—'
                    else:
                        details = zero_reasons.get(ts.ip, '—')

                    row = (f'  {ts.ip:<{col_ip}}  {wc_tag:<{col_st}}'
                           f'  {caps:<{col_cap}}  {details}')
                    self.console.print(row, style=style, justify='left')
                self.console.print()

        # Totals
        self.console.print(
            f'  Total hashes captured:  [bold]{captures}[/]',
            justify='left'
        )
        if valid:
            self.console.print(
                f'  Named group (valid):    [green]{valid}[/]',
                justify='left'
            )
        if wildcard:
            self.console.print(
                f'  Wildcard-flagged:       [cyan]{wildcard}[/]',
                justify='left'
            )
        if captures > 0:
            gf = generated_files or {}
            self.console.print()
            self.console.print('  To crack:', justify='left')

            # hashcat commands — only shown for files that were actually created
            if 'hashcat_ready_5400.txt' in gf:
                n = gf['hashcat_ready_5400.txt']
                self.console.print(
                    f'    hashcat -m 5400 {run_dir}/hashes/hashcat_ready_5400.txt <wordlist>'
                    f'  ({n} SHA1 hash{"es" if n != 1 else ""})',
                    style='dim', justify='left'
                )
            if 'hashcat_ready_5300.txt' in gf:
                n = gf['hashcat_ready_5300.txt']
                self.console.print(
                    f'    hashcat -m 5300 {run_dir}/hashes/hashcat_ready_5300.txt <wordlist>'
                    f'  ({n} MD5 hash{"es" if n != 1 else ""})',
                    style='dim', justify='left'
                )

            # psk-crack — recommended for all hashes, required for G14+ (exceeds hashcat salt limit)
            if 'psk_crack_ready.txt' in gf:
                n = gf['psk_crack_ready.txt']
                self.console.print(
                    f'    psk-crack -d <wordlist> {run_dir}/hashes/psk_crack_ready.txt'
                    f'  ({n} hash{"es" if n != 1 else ""}, all DH groups)',
                    style='dim', justify='left'
                )

            # Notes for unsupported types
            if 'sha256_captures.txt' in gf:
                n = gf['sha256_captures.txt']
                self.console.print(
                    f'    ({n} SHA256 hash{"es" if n != 1 else ""} in hashes/sha256_captures.txt'
                    f' — no cracking tool currently supports IKE-PSK SHA256)',
                    style='dim', justify='left'
                )

            # Note if G14+ hashes were excluded from hashcat files
            large_dh_total = gf.get('psk_crack_ready.txt', 0)
            small_dh_total = gf.get('hashcat_ready_5400.txt', 0) + gf.get('hashcat_ready_5300.txt', 0)
            if large_dh_total > small_dh_total:
                self.console.print(
                    f'    (Note: G14/G15+ hashes exceed hashcat salt limit — '
                    f'use psk-crack for those)',
                    style='dim', justify='left'
                )
        self.console.print(f'\n  Results saved to:  {run_dir}', justify='left')
        self.console.print()
