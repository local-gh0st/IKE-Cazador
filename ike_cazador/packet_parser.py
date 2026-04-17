"""
IKE response packet parser — 4-layer validation pipeline.

Layer 0: Raw bytes pre-guards (length, version, cookie routing)
Layer 1: Scapy parse (try/except wrapped)
Layer 2: Header field validation (exchange type, flags, cookies)
Layer 3: Payload presence + field sanity checks

Critical rules:
- NEVER use `while layer: layer = layer.payload` loops
- ALWAYS use haslayer() / getlayer() exclusively
- notify_msg_type is an int — compare with int()
- IDir_b = bytes(id_layer)[4:] — type-agnostic extraction
- Check version byte at raw byte level BEFORE Scapy parsing
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_SA,
    ISAKMP_payload_KE,
    ISAKMP_payload_Nonce,
    ISAKMP_payload_ID,
    ISAKMP_payload_Hash,
    ISAKMP_payload_Notify,
    ISAKMP_payload_VendorID,
)

from .constants import (
    ResponseType, NotifyType, ExchangeType,
    ISAKMP_VERSION, IKEV2_VERSION, ISAKMP_HEADER_LEN,
    ISAKMP_FLAG_ENCRYPT, HASH_SIZES, HashAlg, DHGroup, DH_KE_SIZES,
)


# ---------------------------------------------------------------------------
# Parsed response dataclass
# ---------------------------------------------------------------------------
@dataclass
class ParsedResponse:
    """Complete parsed and validated result from an IKE response."""
    response_type:   ResponseType

    # ISAKMP header fields
    cky_i:           bytes = b''          # echoed initiator cookie
    cky_r:           bytes = b''          # responder cookie
    exch_type:       int   = 0
    flags:           int   = 0
    version:         int   = 0

    # AM2 payload fields (only populated for CONFIRMED_AM2)
    sa_bytes:        Optional[bytes] = None   # full SA payload bytes (with header)
    sai_b:           Optional[bytes] = None   # SA body without 4-byte generic header
    ke_bytes:        Optional[bytes] = None   # raw KE public value bytes
    nonce_r:         Optional[bytes] = None   # responder nonce bytes
    idir_b:          Optional[bytes] = None   # ID body: bytes(id_layer)[4:]
    hash_r:          Optional[bytes] = None   # HASH_R bytes
    hash_alg:        Optional[HashAlg] = None # hash algorithm from accepted SA transform
    dh_group:        Optional[DHGroup] = None # DH group from accepted SA transform
    accepted_enc:    Optional[int] = None     # encryption alg from accepted transform
    accepted_key_len: Optional[int] = None    # AES key length (0 if not AES)
    accepted_hash_alg: Optional[int] = None  # hash algorithm code from accepted transform
    accepted_auth_method: Optional[int] = None  # auth method: 1=PSK, 65001=XAUTH_PSK

    # Notify fields
    notify_type:     Optional[int] = None

    # Vendor IDs
    vendor_ids:      list[bytes] = field(default_factory=list)

    # Cisco fragment fields
    fragment_id:     Optional[int] = None
    fragment_seq:    Optional[int] = None
    fragment_last:   bool = False
    fragment_data:   Optional[bytes] = None

    # Raw packet
    raw:             bytes = b''

    # Diagnostic message
    message:         str = ''


# ---------------------------------------------------------------------------
# Fragment reassembly buffer
# key = (src_ip, fragment_id)  value = list of (seq, data) sorted by seq
# ---------------------------------------------------------------------------
_fragment_buffer: dict[tuple, list] = {}


def parse_response(raw: bytes, sent_cky_i: bytes,
                   src_ip: str = '') -> ParsedResponse:
    """
    Main entry point. Parse a raw UDP payload received on port 500 or 4500.

    Args:
        raw:        raw bytes from recvfrom()
        sent_cky_i: the CKY-I we sent in the probe (for cookie validation)
        src_ip:     source IP of the response (for fragment reassembly keying)

    Returns ParsedResponse with response_type set appropriately.
    """

    # -----------------------------------------------------------------------
    # Layer 0: Raw bytes pre-guards
    # -----------------------------------------------------------------------

    # RFC 3947 NAT-T: responses on port 4500 are prefixed with a 4-byte
    # non-ESP marker (0x00000000).  Strip it before parsing so the rest of
    # the pipeline sees a standard ISAKMP packet regardless of port.
    if len(raw) >= 4 and raw[:4] == b'\x00\x00\x00\x00':
        raw = raw[4:]
    if len(raw) < ISAKMP_HEADER_LEN:
        return ParsedResponse(
            response_type=ResponseType.TRUNCATED,
            raw=raw,
            message=f'Packet too short: {len(raw)} bytes (need {ISAKMP_HEADER_LEN})'
        )

    # ISAKMP header layout (RFC 2408 §3.1):
    #   0-7:   Initiator Cookie
    #   8-15:  Responder Cookie
    #   16:    Next Payload
    #   17:    Version (major << 4 | minor)
    #   18:    Exchange Type
    #   19:    Flags
    #   20-23: Message ID
    #   24-27: Length

    # Extract fields from raw bytes — never trust Scapy defaults
    raw_cky_i        = raw[0:8]
    raw_cky_r        = raw[8:16]
    next_payload_raw = raw[16]
    version_byte     = raw[17]
    major_version    = version_byte >> 4
    exch_type_raw    = raw[18]
    flags_raw        = raw[19]

    # Check for IKEv2 (version byte 0x20)
    if major_version == 2:
        return ParsedResponse(
            response_type=ResponseType.IKEV2,
            version=version_byte,
            raw=raw,
            message='IKEv2 response — not vulnerable to Aggressive Mode PSK attack'
        )

    if major_version != 1:
        return ParsedResponse(
            response_type=ResponseType.MALFORMED,
            version=version_byte,
            raw=raw,
            message=f'Unknown IKE major version: {major_version}'
        )

    # Check for Cisco fragmentation: next_payload == 132 (0x84)
    if next_payload_raw == 132:
        return _handle_cisco_fragment(raw, raw_cky_i, raw_cky_r, src_ip)

    # -----------------------------------------------------------------------
    # Layer 1: Scapy parse (wrapped in try/except)
    # -----------------------------------------------------------------------
    try:
        p = ISAKMP(raw)
    except struct.error as e:
        return ParsedResponse(
            response_type=ResponseType.MALFORMED,
            raw=raw,
            message=f'Scapy struct.error: {e}'
        )
    except Exception as e:
        return ParsedResponse(
            response_type=ResponseType.MALFORMED,
            raw=raw,
            message=f'Scapy parse error: {e}'
        )

    # -----------------------------------------------------------------------
    # Layer 2: Header field validation
    # -----------------------------------------------------------------------

    # Verify packet length field matches actual received bytes
    try:
        declared_len = struct.unpack('!I', raw[24:28])[0]
    except struct.error:
        declared_len = 0

    # Cookie validation
    # CKY-R must be non-zero (except in the first message from initiator)
    resp_cookie = raw_cky_r
    init_cookie = raw_cky_i

    # Check initiator cookie matches what we sent
    if sent_cky_i and init_cookie != sent_cky_i:
        return ParsedResponse(
            response_type=ResponseType.MALFORMED,
            cky_i=init_cookie,
            cky_r=resp_cookie,
            raw=raw,
            message=f'Cookie mismatch: expected {sent_cky_i.hex()}, got {init_cookie.hex()}'
        )

    # Check encryption flag — AM2 must be cleartext
    if flags_raw & ISAKMP_FLAG_ENCRYPT:
        return ParsedResponse(
            response_type=ResponseType.ENCRYPTED,
            cky_i=init_cookie,
            cky_r=resp_cookie,
            exch_type=exch_type_raw,
            flags=flags_raw,
            raw=raw,
            message='Response is encrypted — unexpected for AM2'
        )

    # -----------------------------------------------------------------------
    # Layer 3: Classify by exchange type and payload contents
    # -----------------------------------------------------------------------
    exch = exch_type_raw

    if exch == int(ExchangeType.INFORMATIONAL):
        return _parse_informational(p, init_cookie, resp_cookie, flags_raw, raw)

    elif exch == int(ExchangeType.AGGRESSIVE):
        return _parse_aggressive(p, init_cookie, resp_cookie, flags_raw, raw)

    elif exch == int(ExchangeType.IDENTITY_PROTECT):
        return ParsedResponse(
            response_type=ResponseType.MAIN_MODE_RESPONSE,
            cky_i=init_cookie,
            cky_r=resp_cookie,
            exch_type=exch,
            raw=raw,
            message='Main Mode response — device may not support Aggressive Mode'
        )

    else:
        return ParsedResponse(
            response_type=ResponseType.UNKNOWN_EXCHANGE,
            cky_i=init_cookie,
            cky_r=resp_cookie,
            exch_type=exch,
            raw=raw,
            message=f'Unknown exchange type: {exch}'
        )


def _parse_informational(p: ISAKMP, cky_i: bytes, cky_r: bytes,
                          flags: int, raw: bytes) -> ParsedResponse:
    """Parse an ISAKMP Informational Exchange (exchange type 5)."""
    vendor_ids = _extract_vendor_ids(p)

    if not p.haslayer(ISAKMP_payload_Notify):
        return ParsedResponse(
            response_type=ResponseType.UNKNOWN_EXCHANGE,
            cky_i=cky_i,
            cky_r=cky_r,
            exch_type=int(ExchangeType.INFORMATIONAL),
            vendor_ids=vendor_ids,
            raw=raw,
            message='Informational exchange with no Notify payload'
        )

    notify = p.getlayer(ISAKMP_payload_Notify)
    # notify_msg_type is an int — safe direct comparison
    ntype = int(notify.notify_msg_type)

    resp_type, msg = _classify_notify(ntype)

    return ParsedResponse(
        response_type=resp_type,
        cky_i=cky_i,
        cky_r=cky_r,
        exch_type=int(ExchangeType.INFORMATIONAL),
        flags=flags,
        notify_type=ntype,
        vendor_ids=vendor_ids,
        raw=raw,
        message=msg
    )


def _parse_aggressive(p: ISAKMP, cky_i: bytes, cky_r: bytes,
                       flags: int, raw: bytes) -> ParsedResponse:
    """
    Parse an Aggressive Mode response (exchange type 4).
    Could be a valid AM2 or a Notify-in-AM-exchange (some broken devices).
    """
    vendor_ids = _extract_vendor_ids(p)

    # Check for Notify — some devices send exch_type=4 but with a Notify payload
    if p.haslayer(ISAKMP_payload_Notify) and not p.haslayer(ISAKMP_payload_Hash):
        notify = p.getlayer(ISAKMP_payload_Notify)
        ntype = int(notify.notify_msg_type)
        resp_type, msg = _classify_notify(ntype)
        return ParsedResponse(
            response_type=resp_type,
            cky_i=cky_i,
            cky_r=cky_r,
            exch_type=int(ExchangeType.AGGRESSIVE),
            flags=flags,
            notify_type=ntype,
            vendor_ids=vendor_ids,
            raw=raw,
            message=f'AM exchange with Notify payload: {msg}'
        )

    # Check for RSA/SIG auth (SIG payload present, Hash absent)
    # Scapy doesn't have a dedicated SIG layer — check payload type 9 in raw
    has_hash  = p.haslayer(ISAKMP_payload_Hash)
    has_sa    = p.haslayer(ISAKMP_payload_SA)
    has_ke    = p.haslayer(ISAKMP_payload_KE)
    has_nonce = p.haslayer(ISAKMP_payload_Nonce)
    has_id    = p.haslayer(ISAKMP_payload_ID)

    # Check for SIG payload (type 9) in raw — indicates RSA auth
    if has_sa and has_ke and has_nonce and has_id and not has_hash:
        if _has_payload_type(raw, 9):
            return ParsedResponse(
                response_type=ResponseType.AM2_RSA_AUTH,
                cky_i=cky_i,
                cky_r=cky_r,
                exch_type=int(ExchangeType.AGGRESSIVE),
                flags=flags,
                vendor_ids=vendor_ids,
                raw=raw,
                message='AM2 with RSA/certificate auth (SIG payload) — no PSK to capture'
            )

    # Validate all required AM2 payloads are present
    if not all([has_sa, has_ke, has_nonce, has_id, has_hash]):
        missing = []
        if not has_sa:    missing.append('SA')
        if not has_ke:    missing.append('KE')
        if not has_nonce: missing.append('Nonce')
        if not has_id:    missing.append('ID')
        if not has_hash:  missing.append('Hash')
        return ParsedResponse(
            response_type=ResponseType.AM2_MALFORMED,
            cky_i=cky_i,
            cky_r=cky_r,
            exch_type=int(ExchangeType.AGGRESSIVE),
            flags=flags,
            vendor_ids=vendor_ids,
            raw=raw,
            message=f'AM2 missing required payloads: {", ".join(missing)}'
        )

    # Extract all payload data
    sa_layer    = p.getlayer(ISAKMP_payload_SA)
    ke_layer    = p.getlayer(ISAKMP_payload_KE)
    nonce_layer = p.getlayer(ISAKMP_payload_Nonce)
    id_layer    = p.getlayer(ISAKMP_payload_ID)
    hash_layer  = p.getlayer(ISAKMP_payload_Hash)

    # SA bytes — full payload for accepted-transform parsing.
    # Bound to the declared length to avoid including bytes from the next payload.
    sa_raw = bytes(sa_layer)
    try:
        import struct as _struct
        sa_declared_len = _struct.unpack('!H', sa_raw[2:4])[0] if len(sa_raw) >= 4 else len(sa_raw)
        sa_bytes = sa_raw[:sa_declared_len]
    except Exception:
        sa_bytes = sa_raw
    # sai_b = SA body without the 4-byte generic payload header
    sai_b = sa_bytes[4:] if len(sa_bytes) > 4 else b''

    # KE bytes — the raw DH public value
    # Use .ke field directly (Scapy StrLenField) — bytes(ke_layer)[4:] would
    # include trailing payload bytes from the chain after the KE payload.
    ke_value = ke_layer.ke if ke_layer.ke else b''

    # Nonce bytes — responder's nonce
    nonce_r = nonce_layer.nonce if nonce_layer.nonce else b''

    # IDir_b — extract exactly the ID payload body, bounded by the declared
    # length field in the generic payload header.
    #
    # bytes(id_layer)[4:] CANNOT be used — Scapy's bytes() includes the entire
    # payload chain (VID payloads etc.) following the ID layer, bloating idir_b
    # with 40-60 extra bytes and making every hashcat crack attempt fail.
    #
    # The fix: read the declared length from raw bytes[2:4] of the generic
    # header, then take exactly raw[4:declared_len] as the ID body.
    # This correctly handles ID_IPV4_ADDR (8 bytes), ID_FQDN (variable),
    # ID_USER_FQDN (variable), and all other ID types.
    id_bytes_raw = bytes(id_layer)
    if len(id_bytes_raw) >= 4:
        import struct as _struct
        declared_id_len = _struct.unpack('!H', id_bytes_raw[2:4])[0]
        idir_b = id_bytes_raw[4:declared_id_len]
    else:
        idir_b = b''

    # Hash — HASH_R
    # Use .hash field directly (Scapy StrLenField) — bytes(hash_layer)[4:]
    # includes ALL bytes after the generic header including the next payload,
    # producing 22 bytes when the actual HMAC output is 20 (SHA1).
    hash_r = hash_layer.hash if hash_layer.hash else b''

    # -----------------------------------------------------------------------
    # Layer 3 field sanity checks
    # -----------------------------------------------------------------------

    # CKY-R must be non-zero
    if cky_r == b'\x00' * 8:
        return ParsedResponse(
            response_type=ResponseType.AM2_MALFORMED,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message='Responder cookie is all zeros — invalid AM2'
        )

    # Hash must not be all zeros
    if hash_r == b'\x00' * len(hash_r):
        return ParsedResponse(
            response_type=ResponseType.AM2_MALFORMED,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message='HASH_R is all zeros — invalid capture'
        )

    # Hash size must be a known valid HMAC output size
    valid_hash_sizes = {16, 20, 28, 32, 48, 64}
    if len(hash_r) not in valid_hash_sizes:
        return ParsedResponse(
            response_type=ResponseType.AM2_MALFORMED,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message=f'Invalid HASH_R size: {len(hash_r)} bytes'
        )

    # KE value must be non-empty
    if len(ke_value) == 0:
        return ParsedResponse(
            response_type=ResponseType.AM2_MALFORMED,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message='Empty KE payload'
        )

    # Determine hash algorithm from hash size
    hash_alg = _hash_alg_from_size(len(hash_r))
    dh_group, enc_alg, key_len, hash_alg_code, auth_code = _parse_accepted_transform(sa_bytes)

    return ParsedResponse(
        response_type=ResponseType.CONFIRMED_AM2,
        cky_i=cky_i,
        cky_r=cky_r,
        exch_type=int(ExchangeType.AGGRESSIVE),
        flags=flags,
        version=ISAKMP_VERSION,
        sa_bytes=sa_bytes,
        sai_b=sai_b,
        ke_bytes=ke_value,
        nonce_r=nonce_r,
        idir_b=idir_b,
        hash_r=hash_r,
        hash_alg=hash_alg,
        dh_group=dh_group,
        accepted_enc=enc_alg,
        accepted_key_len=key_len,
        accepted_hash_alg=hash_alg_code,
        accepted_auth_method=auth_code,
        vendor_ids=vendor_ids,
        raw=raw,
        message=f'Valid AM2 — HASH_R captured ({len(hash_r)} bytes, '
                f'hash_alg={hash_alg.name if hash_alg else "unknown"})'
    )


def _classify_notify(ntype: int) -> tuple[ResponseType, str]:
    """Map a Notify type integer to a ResponseType and human message."""
    if ntype == int(NotifyType.NO_PROPOSAL_CHOSEN):
        return ResponseType.NOTIFY_NO_PROPOSAL, 'NO_PROPOSAL_CHOSEN — transform mismatch or group not found'
    elif ntype == int(NotifyType.INVALID_ID_INFORMATION):
        return ResponseType.NOTIFY_INVALID_ID, 'INVALID_ID_INFORMATION — AM enabled, transform accepted, group not found'
    elif ntype == int(NotifyType.AUTHENTICATION_FAILED):
        return ResponseType.NOTIFY_AUTH_FAILED, 'AUTHENTICATION_FAILED — AM state machine processed request'
    elif ntype in (int(NotifyType.INVALID_EXCHANGE_TYPE),
                   int(NotifyType.UNSUPPORTED_EXCHANGE_TYPE)):
        return ResponseType.NOTIFY_NO_AM, f'Notify-{ntype} — Aggressive Mode not supported'
    elif ntype == int(NotifyType.INVALID_MAJOR_VERSION):
        return ResponseType.NOTIFY_NO_AM, 'INVALID_MAJOR_VERSION'
    else:
        return ResponseType.NOTIFY_OTHER, f'Notify type {ntype}'


def _extract_vendor_ids(p: ISAKMP) -> list[bytes]:
    """Extract all Vendor ID payload bytes from a parsed ISAKMP packet."""
    vids = []
    # Walk payload chain safely using haslayer check approach
    # Collect all VID layers
    layer = p
    while layer:
        if layer.haslayer(ISAKMP_payload_VendorID):
            vid_layer = layer.getlayer(ISAKMP_payload_VendorID)
            if vid_layer:
                vid_bytes = bytes(vid_layer)
                # VID payload body = bytes after 4-byte generic header
                if len(vid_bytes) > 4:
                    vids.append(vid_bytes[4:])
                # Move past this layer to find more VIDs
                layer = vid_layer.payload
            else:
                break
        else:
            break
    return vids


def _has_payload_type(raw: bytes, payload_type: int) -> bool:
    """
    Walk the raw ISAKMP payload chain looking for a specific payload type.
    Avoids infinite loops by tracking position and bounding iterations.
    """
    if len(raw) < ISAKMP_HEADER_LEN:
        return False

    pos = ISAKMP_HEADER_LEN
    next_payload = raw[16]  # first payload type from ISAKMP header
    max_iterations = 20     # safety bound

    for _ in range(max_iterations):
        if next_payload == 0:
            break
        if next_payload == payload_type:
            return True
        if pos + 4 > len(raw):
            break
        # Read payload length from generic header
        payload_len = struct.unpack('!H', raw[pos+2:pos+4])[0]
        if payload_len < 4:
            break
        next_payload = raw[pos]  # next_payload is first byte of generic header
        pos += payload_len
        if pos >= len(raw):
            break

    return False


def _hash_alg_from_size(size: int) -> Optional[HashAlg]:
    """Infer hash algorithm from HASH_R size."""
    for alg, s in HASH_SIZES.items():
        if s == size:
            return alg
    return None


def _parse_accepted_transform(sa_bytes: bytes) -> tuple:
    """
    Parse the accepted transform from the AM2 SA response payload.
    Returns (dh_group, enc_alg_code, key_len, hash_alg_code, auth_code).

    auth_code distinguishes PSK (1) from XAUTH_PSK (65001) and RSA variants.
    This is critical for correct transform locking — without it, an XAUTH
    device gets locked to the PSK variant and Phase 2 sends the wrong auth
    method, receiving Notify-14 for every wordlist word.
    """
    try:
        TRANSFORM_HDR_OFFSET = 20

        if len(sa_bytes) < TRANSFORM_HDR_OFFSET + 4:
            return None, None, 0, None, None

        transform_len = struct.unpack(
            '!H', sa_bytes[TRANSFORM_HDR_OFFSET + 2 : TRANSFORM_HDR_OFFSET + 4]
        )[0]

        attr_start = TRANSFORM_HDR_OFFSET + 8
        attr_end   = TRANSFORM_HDR_OFFSET + transform_len

        if attr_end > len(sa_bytes) or attr_start >= attr_end:
            return None, None, 0, None, None

        dh_group:      Optional[DHGroup] = None
        enc_alg:       Optional[int]     = None
        hash_alg_code: Optional[int]     = None
        auth_code:     Optional[int]     = None
        key_len:       int               = 0
        offset = attr_start

        while offset + 4 <= attr_end and offset + 4 <= len(sa_bytes):
            attr_type_raw = struct.unpack('!H', sa_bytes[offset:offset+2])[0]
            is_tv     = bool(attr_type_raw & 0x8000)
            attr_type = attr_type_raw & 0x7FFF

            if is_tv:
                attr_val = struct.unpack('!H', sa_bytes[offset+2:offset+4])[0]
                if attr_type == 1:    # Encryption Algorithm
                    enc_alg = attr_val
                elif attr_type == 2:  # Hash Algorithm
                    hash_alg_code = attr_val
                elif attr_type == 3:  # Authentication Method (PSK=1, XAUTH_PSK=65001)
                    auth_code = attr_val
                elif attr_type == 4:  # Group Description (DH group)
                    try:
                        dh_group = DHGroup(attr_val)
                    except ValueError:
                        dh_group = None
                elif attr_type == 14: # Key Length (AES)
                    key_len = attr_val
                offset += 4
            else:
                if offset + 4 > len(sa_bytes):
                    break
                attr_len = struct.unpack('!H', sa_bytes[offset+2:offset+4])[0]
                offset += 4 + attr_len

        return dh_group, enc_alg, key_len, hash_alg_code, auth_code

    except (struct.error, IndexError):
        return None, None, 0, None, None


def _handle_cisco_fragment(raw: bytes, cky_i: bytes, cky_r: bytes,
                            src_ip: str) -> ParsedResponse:
    """
    Handle a Cisco proprietary IKE fragment packet.
    Fragment payload: fragment_id(2) + fragment_seq(1) + last_flag(1) + data
    """
    if len(raw) < ISAKMP_HEADER_LEN + 4:
        return ParsedResponse(
            response_type=ResponseType.CISCO_FRAGMENT,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message='Cisco fragment too short to parse'
        )

    payload_start = ISAKMP_HEADER_LEN
    try:
        fragment_id  = struct.unpack('!H', raw[payload_start:payload_start+2])[0]
        fragment_seq = raw[payload_start+2]
        fragment_last = bool(raw[payload_start+3])
        fragment_data = raw[payload_start+4:]
    except (struct.error, IndexError):
        return ParsedResponse(
            response_type=ResponseType.CISCO_FRAGMENT,
            cky_i=cky_i,
            cky_r=cky_r,
            raw=raw,
            message='Failed to parse Cisco fragment header'
        )

    # Add to reassembly buffer
    buf_key = (src_ip, fragment_id)
    if buf_key not in _fragment_buffer:
        _fragment_buffer[buf_key] = []
    _fragment_buffer[buf_key].append((fragment_seq, fragment_data))

    if fragment_last:
        # Reassemble: sort by sequence number, concatenate data
        fragments = sorted(_fragment_buffer.pop(buf_key), key=lambda x: x[0])
        reassembled = b''.join(f[1] for f in fragments)
        # buf_key already removed by pop() above — no second pop needed
        # Rebuild a complete ISAKMP packet: original header + reassembled payload
        # Replace the next_payload byte with the actual first payload type
        # The reassembled data starts with the first payload
        if len(reassembled) > 0:
            new_raw = raw[:16] + bytes([reassembled[0] if reassembled else 0]) + \
                      raw[17:ISAKMP_HEADER_LEN] + reassembled
            # Fix the length field
            new_len = struct.pack('!I', len(new_raw))
            new_raw = new_raw[:24] + new_len + new_raw[28:]
            # Re-parse the reassembled packet
            return parse_response(new_raw, cky_i, src_ip)

    return ParsedResponse(
        response_type=ResponseType.CISCO_FRAGMENT,
        cky_i=cky_i,
        cky_r=cky_r,
        fragment_id=fragment_id,
        fragment_seq=fragment_seq,
        fragment_last=fragment_last,
        fragment_data=fragment_data,
        raw=raw,
        message=f'Cisco fragment {fragment_seq} (last={fragment_last}) buffered for reassembly'
    )
