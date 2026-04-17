"""
Hash extraction and hashcat format generation.

Produces hashcat mode 5300 (IKE-PSK MD5) and 5400 (IKE-PSK SHA1/SHA2) format lines.

Hashcat IKE-PSK format:
  g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
  All fields lowercase hex, colon-delimited.

Field sources:
  g_xr     = ke_bytes from AM2 response (responder DH public value)
  g_xi     = keypair.public_bytes from our probe (initiator DH public value)
  cky_r    = responder cookie from AM2 header
  cky_i    = initiator cookie we sent in AM1
  sai_b    = SA body WITHOUT 4-byte generic header (from our sent AM1)
  idir_b   = bytes(id_layer)[4:] from AM2 (responder identity, type-agnostic)
  ni_b     = nonce_i from our probe (initiator nonce)
  nr_b     = nonce_r from AM2 response (responder nonce)
  hash_r   = HASH_R from AM2 Hash payload

Note: sai_b comes from what WE SENT in AM1, not parsed from AM2.
"""

from dataclasses import dataclass
from typing import Optional

from .constants import HashAlg, HASHCAT_MODES, HASH_SIZES
from .packet_builder import ProbeMetadata
from .packet_parser import ParsedResponse


@dataclass
class CapturedHash:
    """A fully extracted, validated PSK hash capture ready for hashcat."""
    target_ip:      str
    group_id:       str
    hashcat_line:   str             # complete colon-delimited hashcat line
    hashcat_mode:   int             # 5300 (MD5) or 5400 (SHA1/SHA256)
    hash_alg:       Optional[HashAlg]
    transform_str:  str             # human-readable e.g. "3DES/SHA1/PSK/G2"
    cky_i:          bytes
    cky_r:          bytes
    is_wildcard:    bool = False


def extract_hash(probe: ProbeMetadata, response: ParsedResponse) -> Optional[CapturedHash]:
    """
    Build a CapturedHash from a probe and its AM2 response.

    Returns None if any required field is missing or invalid.
    """
    # All fields are required
    required = {
        'ke_bytes (g_xr)':  response.ke_bytes,
        'nonce_r (nr_b)':   response.nonce_r,
        'idir_b':           response.idir_b,
        'hash_r':           response.hash_r,
        'cky_r':            response.cky_r,
        'sai_b':            probe.sai_b,
        'nonce_i (ni_b)':   probe.nonce_i,
        'g_xi':             probe.keypair.public_bytes,
        'cky_i':            probe.cky_i,
    }

    for field_name, val in required.items():
        if not val:
            return None

    # Validate hash size
    hash_r = response.hash_r
    if len(hash_r) not in HASH_SIZES.values():
        return None

    # All-zero check on critical fields
    if hash_r == b'\x00' * len(hash_r):
        return None
    if response.ke_bytes == b'\x00' * len(response.ke_bytes):
        return None

    # Determine hashcat mode from hash algorithm.
    # SHA256/SHA384/SHA512 have no current hashcat IKE-PSK mode.
    # They are captured to sha256_captures.txt; use psk-crack for cracking.
    hash_alg = response.hash_alg
    if hash_alg == HashAlg.MD5:
        hashcat_mode = 5300
    elif hash_alg == HashAlg.SHA1:
        hashcat_mode = 5400
    else:
        # SHA256, SHA384, SHA512 — no hashcat mode; psk-crack handles these
        hashcat_mode = None

    # Build hashcat line: all fields as lowercase hex, colon-delimited
    # Order: g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
    fields = [
        response.ke_bytes.hex(),              # g_xr  (responder DH public value)
        probe.keypair.public_bytes.hex(),     # g_xi  (our DH public value)
        response.cky_r.hex(),                 # cky_r (responder cookie)
        probe.cky_i.hex(),                    # cky_i (initiator cookie)
        probe.sai_b.hex(),                    # sai_b (SA body, no generic header)
        response.idir_b.hex(),                # idir_b (responder ID body, no generic header)
        probe.nonce_i.hex(),                  # ni_b  (initiator nonce)
        response.nonce_r.hex(),               # nr_b  (responder nonce)
        response.hash_r.hex(),                # hash_r (HASH_R)
    ]

    hashcat_line = ':'.join(fields)

    return CapturedHash(
        target_ip=probe.target_ip,
        group_id=probe.group_id,
        hashcat_line=hashcat_line,
        hashcat_mode=hashcat_mode,
        hash_alg=hash_alg,
        transform_str=str(probe.transform),
        cky_i=probe.cky_i,
        cky_r=response.cky_r,
        is_wildcard=False,  # set by caller based on wildcard detection
    )


def validate_capture(capture: 'CapturedHash') -> tuple:
    """
    Structural self-test for a captured hash.

    Validates field sizes and known constraints WITHOUT the PSK
    (we cannot re-derive HASH_R without it).  Catches extraction bugs
    like idir_b byte-bleeding or truncated fields before bad hashes
    reach the output files.

    Returns (passed: bool, warnings: list[str]).
    warnings are non-fatal advisories (e.g. hashcat salt limit exceeded).
    passed=False means the hash should NOT be saved.
    """
    parts = capture.hashcat_line.split(':')
    warnings: list = []

    if len(parts) != 9:
        return False, [f'Wrong field count: {len(parts)} (expect 9)']

    # Parse field byte sizes
    try:
        field_bytes = [len(p) // 2 for p in parts]
    except Exception:
        return False, ['Could not parse field lengths']

    g_xr_bytes   = field_bytes[0]
    idir_b_bytes = field_bytes[5]
    nr_b_bytes   = field_bytes[7]
    hash_r_bytes = field_bytes[8]
    cky_r_bytes  = field_bytes[2]
    cky_i_bytes  = field_bytes[3]

    # --- Critical checks (return False on failure) ---

    # All fields must be valid hex
    for i, (name, part) in enumerate(zip(
        ['g_xr','g_xi','cky_r','cky_i','sai_b','idir_b','ni_b','nr_b','hash_r'],
        parts
    )):
        if len(part) % 2 != 0:
            return False, [f'Field {name} has odd hex length ({len(part)})']
        try:
            bytes.fromhex(part)
        except ValueError:
            return False, [f'Field {name} contains non-hex characters']

    # hash_r must be a known HMAC output size.
    # 28 bytes (SHA-224) included for consistency with packet_parser.py valid_hash_sizes,
    # though SHA-224 is never negotiated in IKEv1 in practice.
    if hash_r_bytes not in (16, 20, 28, 32, 48, 64):
        return False, [f'hash_r size {hash_r_bytes}B is not a known HMAC size (16/20/28/32/48/64)']

    # hash_r must not be all zeros
    if bytes.fromhex(parts[8]) == b'\x00' * hash_r_bytes:
        return False, ['hash_r is all zeros — invalid capture']

    # Cookies must be exactly 8 bytes
    if cky_r_bytes != 8 or cky_i_bytes != 8:
        return False, [f'Cookie size wrong: cky_r={cky_r_bytes}B cky_i={cky_i_bytes}B (expect 8B each)']

    # idir_b minimum: the ID body has already had its 4-byte generic header
    # stripped at parse time (bytes[4:declared_len]). What remains is:
    # IDtype(1) + proto(1) + port(2) + id_data — minimum 5 bytes total.
    # For IPv4: exactly 8 bytes (4 header + 4 IP)
    # For FQDN: 4 header + N chars
    if idir_b_bytes < 5:
        return False, [f'idir_b too short: {idir_b_bytes}B — likely extraction error (VID bleed fixed)']

    # idir_b should not be excessively long — if >50 bytes on an IPv4 device it indicates
    # the old VID-bleeding bug is still present somewhere
    idir_id_type = int(parts[5][:2], 16)
    if idir_id_type == 1 and idir_b_bytes != 8:
        return False, [
            f'idir_b type=ID_IPV4_ADDR but size={idir_b_bytes}B (expect exactly 8B) — '
            f'VID payload may be bleeding into idir_b'
        ]

    # nr_b must be at least 16 bytes
    if nr_b_bytes < 16:
        return False, [f'nr_b too short: {nr_b_bytes}B (min 16B)']

    # g_xr must be a known DH group KE size
    known_ke_sizes = {96, 128, 192, 256, 384, 64, 66, 132}  # G1,G2,G5,G14,G15,G19,G20,G21
    if g_xr_bytes not in known_ke_sizes:
        warnings.append(
            f'g_xr size {g_xr_bytes}B is not a standard DH group KE size — '
            f'known sizes: {sorted(known_ke_sizes)}'
        )

    # --- Non-fatal warnings ---

    # hashcat salt length check
    salt_hex_len = sum(len(p) for p in parts[:8])
    if salt_hex_len > 1024:
        warnings.append(
            f'Salt length {salt_hex_len} hex chars exceeds hashcat 5300/5400 limit (1024). '
            f'Use psk-crack instead of hashcat for this hash.'
        )

    # idir_b ID type sanity check
    if idir_id_type not in (1, 2, 3, 9, 11):
        warnings.append(
            f'idir_b ID type 0x{idir_id_type:02x} is non-standard '
            f'(expect 0x01=IPv4 / 0x02=FQDN / 0x03=USER_FQDN)'
        )

    return True, warnings
