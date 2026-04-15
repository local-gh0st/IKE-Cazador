"""
Wildcard detection and crackability confidence scoring.

Two paths to wildcard confirmation:
  Path A (Phase 1): Random-string probe gets AM2 → wildcard confirmed immediately
  Path B (Phase 2): 5+ captures from same host → accumulation-based confirmation

Per-wildcard confidence scoring:
  Score starts at 50 (neutral)
  Positive signals: fresh g_xr, vendor VIDs, legitimate IDir_b, consistent transforms
  Negative signals: reused g_xr, no VIDs, IDir_b zeros/echo, inconsistent transforms
  
  >= 70: HIGH    — likely real PSK, crack first
  40-69: MEDIUM  — possible real PSK, worth attempting
  < 40:  LOW     — likely garbage PSK, low priority
"""

import secrets
import string
from dataclasses import dataclass, field
from typing import Optional

from .constants import (
    RANDOM_GROUP_PREFIX, RANDOM_GROUP_SUFFIX_LEN,
    WILDCARD_CONFIRM_THRESHOLD, WILDCARD_CAP,
    WILDCARD_CONFIDENCE_HIGH, WILDCARD_CONFIDENCE_MEDIUM,
)


def generate_random_group_id() -> str:
    """
    Generate a cryptographically random group ID for wildcard detection.
    Uses 'gps' prefix + 7 random alphanumeric characters.
    Probability of accidentally matching a real group name: negligible.
    """
    alphabet = string.ascii_lowercase + string.digits
    suffix = ''.join(secrets.choice(alphabet) for _ in range(RANDOM_GROUP_SUFFIX_LEN))
    return f"{RANDOM_GROUP_PREFIX}{suffix}"


@dataclass
class WildcardState:
    """
    Per-host wildcard detection state machine.

    States:
      CLEAN       → no captures yet or legitimacy confirmed
      SUSPECTED   → first capture received, validation probe pending
      CONFIRMED   → random-string probe returned AM2, OR 5+ captures
      CAPPED      → confirmed wildcard, capture limit reached
    """
    host:               str
    status:             str = 'CLEAN'       # CLEAN | SUSPECTED | CONFIRMED | CAPPED
    capture_count:      int = 0
    validation_probe_id: Optional[str] = None   # random string we used for validation

    # Signals collected during characterization
    g_xr_values_seen:   list[bytes] = field(default_factory=list)
    nr_b_values_seen:   list[bytes] = field(default_factory=list)
    vendor_ids_seen:    list[bytes] = field(default_factory=list)
    idir_b_values:      list[bytes] = field(default_factory=list)
    transform_selected: list[str]   = field(default_factory=list)

    # Confidence score (computed once confirmed)
    confidence_score:   int = 50
    confidence_level:   str = 'UNKNOWN'     # HIGH | MEDIUM | LOW | UNKNOWN
    confidence_signals: list[str] = field(default_factory=list)

    @property
    def is_confirmed(self) -> bool:
        return self.status in ('CONFIRMED', 'CAPPED')

    @property
    def is_capped(self) -> bool:
        return self.status == 'CAPPED'

    def record_capture(self, g_xr: bytes, nr_b: bytes, vendor_ids: list[bytes],
                        idir_b: bytes, transform_str: str) -> None:
        """Record signals from a new capture for wildcard characterization."""
        self.capture_count += 1

        if g_xr:
            self.g_xr_values_seen.append(g_xr)
        if nr_b:
            self.nr_b_values_seen.append(nr_b)
        if vendor_ids:
            for v in vendor_ids:
                if v not in self.vendor_ids_seen:
                    self.vendor_ids_seen.append(v)
        if idir_b:
            if idir_b not in self.idir_b_values:
                self.idir_b_values.append(idir_b)
        if transform_str:
            self.transform_selected.append(transform_str)

        # Check accumulation threshold
        if self.capture_count >= WILDCARD_CONFIRM_THRESHOLD:
            if self.status not in ('CONFIRMED', 'CAPPED'):
                self.status = 'CONFIRMED'
                self._compute_confidence()

        # Check cap
        if self.capture_count >= WILDCARD_CAP and self.is_confirmed:
            self.status = 'CAPPED'

    def confirm_wildcard(self) -> None:
        """Called when random-string validation probe returns AM2."""
        self.status = 'CONFIRMED'
        self._compute_confidence()

    def clear_suspected(self) -> None:
        """Called when random-string validation probe returns Notify (not wildcard)."""
        self.status = 'CLEAN'

    @property
    def g_xr_reused(self) -> bool:
        """True if any g_xr value appeared more than once across captures."""
        if len(self.g_xr_values_seen) < 2:
            return False
        return len(set(v.hex() for v in self.g_xr_values_seen)) < len(self.g_xr_values_seen)

    @property
    def nr_b_reused(self) -> bool:
        """True if any nr_b value appeared more than once across captures."""
        if len(self.nr_b_values_seen) < 2:
            return False
        return len(set(v.hex() for v in self.nr_b_values_seen)) < len(self.nr_b_values_seen)

    @property
    def idir_b_echoes_group(self) -> bool:
        """
        True if IDir_b matches one of the group IDs we sent (broken stub behavior).
        We check if IDir_b looks like a group name string rather than an IP.
        """
        # If IDir_b contains only the group name bytes, it echoed our request
        # In practice: real devices return ID_IPV4_ADDR (4 bytes) or a hostname
        # A stub echoing our group ID would have ID_USER_FQDN with our group name
        # We detect this by checking if IDir_b body length > 4 and looks like ASCII group name
        # (Heuristic — not definitive, but a useful signal)
        return False  # Placeholder — set during scanner based on comparison

    @property
    def idir_b_all_zeros(self) -> bool:
        """True if IDir_b body is all zero bytes."""
        for idir in self.idir_b_values:
            # idir_b includes type(1) + proto(1) + port(2) + data
            if len(idir) >= 4:
                data = idir[4:]
                if data and data == b'\x00' * len(data):
                    return True
        return False

    @property
    def transform_consistent(self) -> bool:
        """True if the device consistently picks the same transform."""
        if len(self.transform_selected) < 2:
            return True
        return len(set(self.transform_selected)) == 1

    def _compute_confidence(self) -> None:
        """
        Compute crackability confidence score for this wildcard host.
        Score range: 0-100. Threshold: >=70 HIGH, 40-69 MEDIUM, <40 LOW.
        """
        score = 50
        signals = []

        # Positive signals
        if self.g_xr_values_seen and not self.g_xr_reused:
            score += 20
            signals.append('[+] Fresh g_xr per session — real device behavior')

        if len(self.nr_b_values_seen) >= 2 and not self.nr_b_reused:
            score += 10
            signals.append('[+] Fresh Nr_b per session — healthy PRNG')

        if self.vendor_ids_seen:
            score += 15
            signals.append(f'[+] {len(self.vendor_ids_seen)} vendor ID(s) present — real device')

        if self.idir_b_values and not self.idir_b_all_zeros:
            score += 15
            signals.append('[+] Valid IDir_b — device has configured identity')

        if self.transform_consistent and len(self.transform_selected) >= 2:
            score += 10
            signals.append('[+] Consistent transform selection — real configured policy')

        # Negative signals
        if self.g_xr_reused:
            score -= 30
            reuse_count = len(self.g_xr_values_seen) - len(set(v.hex() for v in self.g_xr_values_seen))
            signals.append(f'[-] g_xr reused {reuse_count} time(s) — stub/broken PRNG')

        if self.nr_b_reused:
            score -= 20
            signals.append('[-] Nr_b reused — broken nonce generation')

        if not self.vendor_ids_seen:
            score -= 15
            signals.append('[-] No vendor IDs — unidentified implementation')

        if self.idir_b_all_zeros:
            score -= 25
            signals.append('[-] IDir_b is all zeros — invalid/stub identity')

        if not self.transform_consistent and len(self.transform_selected) >= 2:
            score -= 20
            signals.append('[-] Inconsistent transform selection — may always pick first offered')

        # Clamp to 0-100
        score = max(0, min(100, score))
        self.confidence_score = score
        self.confidence_signals = signals

        if score >= WILDCARD_CONFIDENCE_HIGH:
            self.confidence_level = 'HIGH'
        elif score >= WILDCARD_CONFIDENCE_MEDIUM:
            self.confidence_level = 'MEDIUM'
        else:
            self.confidence_level = 'LOW'


class WildcardTracker:
    """
    Manages WildcardState instances for all hosts being scanned.
    """
    def __init__(self):
        self._states: dict[str, WildcardState] = {}

    def get_or_create(self, host: str) -> WildcardState:
        if host not in self._states:
            self._states[host] = WildcardState(host=host)
        return self._states[host]

    def get(self, host: str) -> Optional[WildcardState]:
        return self._states.get(host)

    def is_confirmed_wildcard(self, host: str) -> bool:
        state = self._states.get(host)
        return state.is_confirmed if state else False

    def is_capped(self, host: str) -> bool:
        state = self._states.get(host)
        return state.is_capped if state else False

    def all_states(self) -> list[WildcardState]:
        return list(self._states.values())
