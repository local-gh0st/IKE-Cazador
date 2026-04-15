"""
IKE Aggressive Mode AM1 packet builder.

Constructs raw AM1 packets using Scapy's ISAKMP layer.
Returns both the raw bytes and all probe metadata needed for hash extraction.
"""

import os
import struct
from dataclasses import dataclass

from .constants import (
    ExchangeType, PayloadType, IDType, AttrType,
    IPSEC_DOI, SIT_IDENTITY_ONLY, PROTO_ISAKMP,
    SA_LIFE_TYPE_SECONDS, SA_LIFE_DURATION,
    EncAlg, HashAlg, AuthMethod, DHGroup,
    ISAKMP_HEADER_LEN,
)
from .transforms import Transform, DHKeypair


# ---------------------------------------------------------------------------
# Probe metadata — everything needed for hash extraction later
# ---------------------------------------------------------------------------
@dataclass
class ProbeMetadata:
    """All fields sent in AM1, needed to compute HASH_R for cracking."""
    target_ip:      str
    target_port:    int
    group_id:       str
    transform:      Transform
    keypair:        DHKeypair         # our DH keypair
    nonce_i:        bytes             # our nonce (Ni_b)
    cky_i:          bytes             # our initiator cookie
    sai_b:          bytes             # SA payload body (without generic header) — for hashcat
    raw_am1:        bytes             # complete raw packet bytes
    word_idx:       int   = -1        # wordlist index (for late-response correlation in Phase 2)


def _build_transform_payload_bytes(t: Transform, transform_num: int, next_p: int) -> bytes:
    """
    Build one ISAKMP Transform payload as raw bytes.
    Returns the complete payload including the 4-byte generic header.

    Transform generic header: next(1) + reserved(1) + length(2)
    Transform body:           num(1) + id(1) + reserved(2) + attributes
    Attributes (TV format):   type(2, high bit set) + value(2)
    Life Duration (TLV):      type(2, high bit clear) + length(2) + value(variable)
    """
    # Build attributes
    attrs = b''

    # Attr 1: Encryption Algorithm (TV)
    attrs += struct.pack('!HH', 0x8001, int(t.enc))

    # Attr 14: Key Length (TV, AES only)
    if t.key_len > 0:
        attrs += struct.pack('!HH', 0x800E, t.key_len)

    # Attr 2: Hash Algorithm (TV)
    attrs += struct.pack('!HH', 0x8002, int(t.hash_alg))

    # Attr 3: Authentication Method (TV)
    attrs += struct.pack('!HH', 0x8003, int(t.auth))

    # Attr 4: Group Description (TV)
    attrs += struct.pack('!HH', 0x8004, int(t.dh_group))

    # Attr 11: Life Type = Seconds (TV)
    attrs += struct.pack('!HH', 0x800B, SA_LIFE_TYPE_SECONDS)

    # Attr 12: Life Duration = 28800 (TLV, 4-byte value)
    attrs += struct.pack('!HHI', 0x000C, 4, SA_LIFE_DURATION)

    # Transform body: num(1) + id(1=KEY_IKE) + reserved(2) + attributes
    transform_body = struct.pack('!BBH', transform_num, 1, 0) + attrs

    # Generic header: next(1) + reserved(1) + total_length(2)
    total_len = 4 + len(transform_body)
    header = struct.pack('!BBH', next_p, 0, total_len)

    return header + transform_body


def _build_sa_payload(transforms: list[Transform]) -> tuple[bytes, bytes]:
    """
    Build the complete SA payload for an AM1 packet containing multiple transforms.

    Returns:
        (sa_payload_bytes, sai_b) where:
        - sa_payload_bytes: full SA payload including generic header (for packet)
        - sai_b: SA body WITHOUT the 4-byte generic header (for hashcat)
    """
    # Build SA body manually using struct for precision
    # SA body = DOI(4) + Situation(4) + Proposal + Transforms
    doi_situation = struct.pack('!II', IPSEC_DOI, SIT_IDENTITY_ONLY)

    # Build each transform
    transform_payloads = []
    for i, t in enumerate(transforms):
        is_last = (i == len(transforms) - 1)
        next_p = 0 if is_last else 3  # 3 = TRANSFORM payload type
        t_bytes = _build_transform_payload_bytes(t, i + 1, next_p)
        transform_payloads.append(t_bytes)

    transforms_bytes = b''.join(transform_payloads)

    # Proposal payload body: proposal_num(1) + protocol(1) + spi_size(1) + num_transforms(1)
    proposal_body = struct.pack('!BBBB',
                                1,                      # proposal number
                                PROTO_ISAKMP,           # protocol = ISAKMP
                                0,                      # SPI size = 0 for Phase 1
                                len(transforms))        # number of transforms

    proposal_body += transforms_bytes

    # Proposal generic header: next(1) + reserved(1) + length(2)
    proposal_len = len(proposal_body) + 4
    proposal_header = struct.pack('!BBH', 0, 0, proposal_len)  # next=0 (last)
    proposal_full = proposal_header + proposal_body

    # SA body = DOI + Situation + Proposal
    sa_body = doi_situation + proposal_full

    # SA generic header: next(1) + reserved(1) + length(2)
    sa_len = len(sa_body) + 4
    sa_header = struct.pack('!BBH', 4, 0, sa_len)  # next=4 (KE payload follows)
    sa_full = sa_header + sa_body

    # sai_b for hashcat = SA body WITHOUT the 4-byte generic header
    sai_b = sa_body

    return sa_full, sai_b


def _build_ke_payload(keypair: DHKeypair, next_payload: int) -> bytes:
    """Build KE payload: generic header + DH public value bytes."""
    ke_body = keypair.public_bytes
    ke_len = len(ke_body) + 4
    ke_header = struct.pack('!BBH', next_payload, 0, ke_len)
    return ke_header + ke_body


def _build_nonce_payload(nonce: bytes, next_payload: int) -> bytes:
    """Build Nonce payload: generic header + random nonce bytes."""
    nonce_len = len(nonce) + 4
    nonce_header = struct.pack('!BBH', next_payload, 0, nonce_len)
    return nonce_header + nonce


def _build_id_payload(group_id: str, next_payload: int) -> bytes:
    """
    Build ID payload for IKE Aggressive Mode.
    Uses ID_USER_FQDN (type 3) for group ID strings.
    For IP addresses, uses ID_IPV4_ADDR (type 1).

    ID payload body: id_type(1) + proto_id(1) + port(2) + id_data
    """
    import ipaddress

    # Try to parse as IPv4 first
    try:
        addr = ipaddress.IPv4Address(group_id)
        id_type = int(IDType.IPV4_ADDR)
        id_data = addr.packed  # 4 bytes
    except ValueError:
        # Use USER_FQDN for group name strings
        id_type = int(IDType.USER_FQDN)
        id_data = group_id.encode('ascii', errors='replace')

    # ID body: id_type(1) + proto_id(1) + port(2) + id_data
    id_body = struct.pack('!BBH', id_type, 0, 0) + id_data
    id_len = len(id_body) + 4
    id_header = struct.pack('!BBH', next_payload, 0, id_len)
    return id_header + id_body


def _build_isakmp_header(cky_i: bytes, next_payload: int, total_len: int) -> bytes:
    """
    Build ISAKMP header (28 bytes).
    CKY-R is all zeros in AM1 (we don't know the responder cookie yet).

    Header: CKY-I(8) + CKY-R(8) + next_payload(1) + version(1) +
            exch_type(1) + flags(1) + msg_id(4) + length(4)
    """
    cky_r = b'\x00' * 8
    version = 0x10       # IKEv1
    exch_type = int(ExchangeType.AGGRESSIVE)
    flags = 0x00         # not encrypted, not committed
    msg_id = 0           # Phase 1 uses msg_id = 0

    return (cky_i + cky_r +
            struct.pack('!BBBBI', next_payload, version, exch_type, flags, msg_id) +
            struct.pack('!I', total_len))


def build_am1(
    target_ip:  str,
    target_port: int,
    group_id:   str,
    transforms: list[Transform],
    keypair:    DHKeypair,
    nonce_i:    bytes,
    cky_i:      bytes,
) -> ProbeMetadata:
    """
    Build a complete IKE Aggressive Mode Message 1 (AM1) packet.

    Payload chain: SA → KE → Nonce → ID

    Returns ProbeMetadata containing raw bytes and all fields needed for
    hash extraction after receiving AM2.
    """
    # Build payloads (without chaining next_payload headers — we set those explicitly)
    sa_bytes, sai_b = _build_sa_payload(transforms)

    # Chain: SA(next=4/KE) → KE(next=10/Nonce) → Nonce(next=5/ID) → ID(next=0/None)
    ke_bytes    = _build_ke_payload(keypair, next_payload=10)   # 10 = Nonce
    nonce_bytes = _build_nonce_payload(nonce_i, next_payload=5) # 5 = ID
    id_bytes    = _build_id_payload(group_id, next_payload=0)   # 0 = None (last)

    # Update SA next_payload to point to KE (4)
    # sa_bytes[0] is the next_payload byte of the SA generic header
    sa_bytes = bytes([4]) + sa_bytes[1:]  # next=4 (KE)

    # Assemble payload chain
    payload_chain = sa_bytes + ke_bytes + nonce_bytes + id_bytes

    # Total packet length
    total_len = ISAKMP_HEADER_LEN + len(payload_chain)

    # first payload type = SA = 1
    header = _build_isakmp_header(cky_i, next_payload=1, total_len=total_len)

    raw_am1 = header + payload_chain

    # RFC 3947 NAT-T encapsulation: IKE traffic on port 4500 must be prefixed
    # with a 4-byte non-ESP marker (0x00000000) to distinguish IKE packets from
    # ESP data packets that share the same port.  Without this marker, devices
    # running NAT-T silently drop the probe as an unrecognised packet type.
    if target_port != 500:
        raw_am1 = b'\x00\x00\x00\x00' + raw_am1

    return ProbeMetadata(
        target_ip=target_ip,
        target_port=target_port,
        group_id=group_id,
        transform=transforms[0],  # will be updated to actual accepted transform after AM2
        keypair=keypair,
        nonce_i=nonce_i,
        cky_i=cky_i,
        sai_b=sai_b,
        raw_am1=raw_am1,
    )


def build_delete_packet(cky_i: bytes, cky_r: bytes, target_port: int = 500) -> bytes:
    """
    Build an unencrypted ISAKMP Informational/DELETE packet to clean up
    a half-open SA on the target device after AM2 capture.

    Works reliably on Cisco ASA. Behavior varies on FortiGate/Juniper.

    DELETE payload: DOI(4) + protocol(1) + SPI_size(1) + num_SPIs(2) + SPI(16)
    SPI for ISAKMP Phase 1 = CKY-I(8) || CKY-R(8)
    """
    doi      = struct.pack('!I', IPSEC_DOI)
    protocol = struct.pack('!B', PROTO_ISAKMP)
    spi_size = struct.pack('!B', 16)   # 2 × 8-byte cookies
    num_spis = struct.pack('!H', 1)
    spi      = cky_i + cky_r

    delete_body = doi + protocol + spi_size + num_spis + spi
    delete_len  = len(delete_body) + 4
    delete_header = struct.pack('!BBH', 0, 0, delete_len)
    delete_payload = delete_header + delete_body

    total_len = ISAKMP_HEADER_LEN + len(delete_payload)
    msg_id = int.from_bytes(os.urandom(4), 'big')

    header = (cky_i + cky_r +
              struct.pack('!BBBBI',
                          12,       # next_payload = DELETE (12)
                          0x10,     # version IKEv1
                          5,        # exchange type = INFORMATIONAL
                          0,        # flags = not encrypted
                          msg_id) +
              struct.pack('!I', total_len))

    pkt = header + delete_payload

    # NAT-T: prefix non-ESP marker on port 4500
    if target_port != 500:
        pkt = b'\x00\x00\x00\x00' + pkt

    return pkt


def generate_nonce(size: int = 20) -> bytes:
    """Generate a cryptographically random nonce."""
    return os.urandom(size)


def generate_cookie() -> bytes:
    """Generate a cryptographically random 8-byte initiator cookie."""
    return os.urandom(8)
