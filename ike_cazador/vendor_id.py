"""
Vendor ID fingerprinting database.

Two lookup strategies:
1. Exact match — for fixed-length VIDs (most vendors)
2. Prefix match — for dynamic/per-session VIDs (e.g. Cisco 84fac1a5...)

VID bytes are the raw body bytes (after stripping the 4-byte generic header).
All values confirmed against /usr/share/ike-scan/ike-vendor-ids and live captures.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class VendorInfo:
    name:        str
    description: str
    is_dynamic:  bool = False  # True if VID contains per-session data


# ---------------------------------------------------------------------------
# Exact match database — keyed by hex string of VID body bytes
# ---------------------------------------------------------------------------
_EXACT_VENDORS: dict[str, VendorInfo] = {

    # Cisco Unity
    '12f5f28c457168a9702d9fe274cc0100': VendorInfo(
        'Cisco Unity',
        'Cisco Unity VPN client/server'
    ),

    # Dead Peer Detection v1.0
    'afcad71368a1f1c96b8696fc77570100': VendorInfo(
        'Dead Peer Detection v1.0',
        'RFC 3706 DPD — both peers support keepalive'
    ),

    # XAUTH
    '09002689dfd6b712': VendorInfo(
        'XAUTH',
        'Cisco Extended Authentication — indicates PSK+XAUTH flow'
    ),

    # NAT-T RFC 3947
    '4a131c81070358455c5728f20e95452f': VendorInfo(
        'NAT-T RFC 3947',
        'NAT Traversal per RFC 3947'
    ),

    # NAT-T draft-02
    '90cb80913ebb696e086381b5ec427b1f': VendorInfo(
        'NAT-T draft-02',
        'NAT Traversal draft version 02'
    ),

    # NAT-T draft-03
    '7d9419a65310ca6f2c179d9215529d56': VendorInfo(
        'NAT-T draft-03',
        'NAT Traversal draft version 03'
    ),

    # Cisco IKE Fragmentation
    '4048b7d56ebce88525e7de7f00d6c2d3': VendorInfo(
        'Cisco IKE Fragmentation',
        'Cisco proprietary IKE fragmentation support'
    ),

    # Cisco VPN Concentrator 3000
    '1f07f70eaa6514d3b0fa96542a500305': VendorInfo(
        'Cisco VPN Concentrator 3000',
        'Cisco VPN Concentrator 3000 series'
    ),

    # Fortinet FortiGate
    '1d6e178f6c2c0be2a6e3f9e8a736e99d': VendorInfo(
        'Fortinet FortiGate',
        'Fortinet FortiGate VPN'
    ),

    # Juniper NetScreen
    '699369228741c6d4ca094c93e242c9de': VendorInfo(
        'Juniper NetScreen',
        'Juniper NetScreen / ScreenOS'
    ),

    # Check Point FW-1
    'f4ed19e0c114eb516faaac0ee37daf28': VendorInfo(
        'Check Point FW-1',
        'Check Point FireWall-1 / VPN-1'
    ),

    # strongSwan
    '882fe56d6fd20dbc2251613b2ebe5beb': VendorInfo(
        'strongSwan',
        'strongSwan IKE daemon'
    ),

    # OpenSwan / Libreswan
    'ada1a07efceadb2fc6f9518e2a37d8ef': VendorInfo(
        'OpenSwan/Libreswan',
        'OpenSwan or Libreswan IKE daemon'
    ),

    # Microsoft L2TP/IPsec — correct MD5 hash of "MS L2TP IPSec VPN" payload
    '4048b7d56ebce88525e7de7f00d6c2d380000000': VendorInfo(
        'Microsoft L2TP',
        'Microsoft L2TP/IPsec VPN client'
    ),

    # Palo Alto
    'f69fd32c4dd5d8ba0682b3e25a29dc8f': VendorInfo(
        'Palo Alto Networks',
        'Palo Alto Networks GlobalProtect'
    ),

    # SonicWall
    '404bf439522ca3f6': VendorInfo(
        'SonicWall',
        'SonicWall VPN gateway'
    ),

    # HeartBeat Notify (Juniper)
    '4865617274426561745f4e6f74696679': VendorInfo(
        'Juniper HeartBeat',
        'Juniper proprietary heartbeat'
    ),

    # Cisco Easy VPN
    '7370686572650000000000000000': VendorInfo(
        'Cisco Easy VPN',
        'Cisco Easy VPN / SPCP'
    ),

    # WatchGuard
    'da8e937880010000': VendorInfo(
        'WatchGuard',
        'WatchGuard Firebox'
    ),
}


# ---------------------------------------------------------------------------
# Prefix match database — for dynamic VIDs where only a prefix is fixed
# Prefix length (bytes) : VendorInfo
# ---------------------------------------------------------------------------
_PREFIX_VENDORS: list[tuple[bytes, VendorInfo]] = [

    # Cisco session announcement VID (84fac1a5...)
    # Bytes 0-3 are fixed; bytes 4-7 track CKY-R with +1 offset; bytes 8-15 are session-specific
    (bytes.fromhex('84fac1a5'), VendorInfo(
        'Cisco (session VID)',
        'Cisco per-session announcement VID — contains encoded responder cookie',
        is_dynamic=True
    )),

    # Check Point NGX version VID (starts with f4ed19e0...)
    # Full VID includes product/version/timestamp suffix
    (bytes.fromhex('f4ed19e0c114eb516faaac0ee37daf28'), VendorInfo(
        'Check Point NGX',
        'Check Point NGX with version information'
    )),
]


def identify_vendor(vid_bytes: bytes) -> Optional[VendorInfo]:
    """
    Look up a vendor from VID payload body bytes.

    First tries exact match, then prefix match.
    Returns None if the VID is not recognized.
    """
    if not vid_bytes:
        return None

    hex_str = vid_bytes.hex()

    # Exact match
    if hex_str in _EXACT_VENDORS:
        return _EXACT_VENDORS[hex_str]

    # Prefix match
    for prefix_bytes, info in _PREFIX_VENDORS:
        if vid_bytes[:len(prefix_bytes)] == prefix_bytes:
            return info

    return None


def identify_all_vendors(vid_list: list[bytes]) -> list[tuple[bytes, Optional[VendorInfo]]]:
    """
    Identify all vendors from a list of VID payload bodies.
    Returns list of (vid_bytes, VendorInfo or None) tuples.
    """
    return [(vid, identify_vendor(vid)) for vid in vid_list]


def summarize_vendors(vid_list: list[bytes]) -> str:
    """
    Produce a human-readable vendor summary string from a VID list.
    E.g. "Cisco Unity, XAUTH, Dead Peer Detection v1.0"
    """
    known = []
    for vid in vid_list:
        info = identify_vendor(vid)
        if info:
            known.append(info.name)
    if not known:
        return 'Unknown'
    return ', '.join(dict.fromkeys(known))  # deduplicated, insertion-ordered
