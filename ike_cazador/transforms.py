"""
DH key generation and transform set definitions.

For MODP groups (1, 2, 5, 14, 15): uses os.urandom() of the correct byte size.
This is intentional and sufficient for IKE PSK hash capture — the device
sends AM2 with HASH_R computed over the raw g_xi bytes as received. The DH
exchange never needs to complete; we only need the hash for offline cracking.

For ECP groups (19, 20, 21): uses the cryptography library's EC primitives
to generate a valid point on the curve. ECP requires properly formatted
x||y coordinates (no 0x04 prefix per RFC 5903 §7). Random bytes would
not be a valid EC point and some devices validate this.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, SECP384R1, SECP521R1,
    generate_private_key as ec_generate_private_key,
)
from cryptography.hazmat.backends import default_backend

from .constants import DHGroup, EncAlg, HashAlg, AuthMethod, DH_KE_SIZES


ECP_CURVES = {
    DHGroup.GROUP_19: SECP256R1,
    DHGroup.GROUP_20: SECP384R1,
    DHGroup.GROUP_21: SECP521R1,
}

MODP_GROUPS = {
    DHGroup.GROUP_1, DHGroup.GROUP_2, DHGroup.GROUP_5,
    DHGroup.GROUP_14, DHGroup.GROUP_15, DHGroup.GROUP_16,
}


# ---------------------------------------------------------------------------
# DH Keypair dataclass
# ---------------------------------------------------------------------------
@dataclass
class DHKeypair:
    group: DHGroup
    public_bytes: bytes    # raw KE payload bytes (correct size, no prefix)
    private_key: object    # private key object (ECP) or None (MODP random)


def generate_dh_keypair(group: DHGroup) -> DHKeypair:
    """
    Generate a DH keypair for the given group.

    MODP groups: os.urandom(ke_size) — sufficient for PSK hash capture.
    ECP groups:  real EC keypair via cryptography library, strip 0x04 prefix.

    Returns DHKeypair with public_bytes ready for the IKE KE payload.
    """
    ke_size = DH_KE_SIZES[group]

    if group in ECP_CURVES:
        # ECP group — must be a valid EC point (devices may validate)
        curve_cls   = ECP_CURVES[group]
        private_key = ec_generate_private_key(curve_cls(), default_backend())
        pub         = private_key.public_key()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        # UncompressedPoint = 0x04 || x || y — strip the leading 0x04 per RFC 5903 §7
        raw          = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        public_bytes = raw[1:]   # strip 0x04 prefix
        assert len(public_bytes) == ke_size, (
            f"ECP G{int(group)}: expected {ke_size}B, got {len(public_bytes)}B"
        )
        return DHKeypair(group=group, public_bytes=public_bytes, private_key=private_key)

    elif group in MODP_GROUPS:
        # MODP group — random bytes of exact size
        # Devices compute HASH_R over these raw bytes; DH completion not required
        public_bytes = os.urandom(ke_size)
        return DHKeypair(group=group, public_bytes=public_bytes, private_key=None)

    else:
        raise ValueError(f"Unsupported DH group: {group}")


# ---------------------------------------------------------------------------
# Transform definitions
# Each transform is (enc_alg, key_length_or_0, hash_alg, auth_method, dh_group)
# key_length=0 means no KEY_LENGTH attribute (DES, 3DES, etc.)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Transform:
    enc:        EncAlg
    key_len:    int        # 0 = no KEY_LENGTH attribute
    hash_alg:   HashAlg
    auth:       AuthMethod
    dh_group:   DHGroup

    def __str__(self) -> str:
        enc_name = {
            EncAlg.DES_CBC:        "DES",
            EncAlg.TRIPLE_DES_CBC: "3DES",
            EncAlg.AES_CBC:        f"AES{self.key_len}",
        }.get(self.enc, self.enc.name)
        hash_name = {
            HashAlg.MD5:    "MD5",
            HashAlg.SHA1:   "SHA1",
            HashAlg.SHA256: "SHA256",
            HashAlg.SHA384: "SHA384",
            HashAlg.SHA512: "SHA512",
        }.get(self.hash_alg, self.hash_alg.name)
        from .constants import AuthMethod as AM
        auth_name = {
            AM.PSK:       "PSK",
            AM.XAUTH_PSK: "XAUTH",
            AM.RSA_SIG:   "RSA",
        }.get(self.auth, "PSK")
        return f"{enc_name}/{hash_name}/{auth_name}/G{int(self.dh_group)}"


# Helper to build a Transform with PSK auth
def _t(enc: EncAlg, key_len: int, hash_alg: HashAlg, group: DHGroup) -> Transform:
    return Transform(enc=enc, key_len=key_len, hash_alg=hash_alg,
                     auth=AuthMethod.PSK, dh_group=group)


# ---------------------------------------------------------------------------
# Transform sets per DH group — all bundled into a single SA proposal per probe
# Ordered strongest-first within each group (device picks its preferred match)
# ---------------------------------------------------------------------------
TRANSFORMS_BY_GROUP: dict[DHGroup, list[Transform]] = {

    DHGroup.GROUP_2: [  # 1024-bit MODP — most common legacy
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_2),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_2),  # gap filled
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA512, DHGroup.GROUP_2),  # gap filled
        _t(EncAlg.AES_CBC,        192, HashAlg.SHA256, DHGroup.GROUP_2),
        _t(EncAlg.AES_CBC,        192, HashAlg.SHA1,   DHGroup.GROUP_2),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA384, DHGroup.GROUP_2),  # gap filled
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_2),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA1,   DHGroup.GROUP_2),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA256, DHGroup.GROUP_2),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   DHGroup.GROUP_2),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.MD5,    DHGroup.GROUP_2),
        _t(EncAlg.DES_CBC,        0,   HashAlg.SHA1,   DHGroup.GROUP_2),
        _t(EncAlg.DES_CBC,        0,   HashAlg.MD5,    DHGroup.GROUP_2),
    ],

    DHGroup.GROUP_14: [  # 2048-bit MODP — modern standard
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA512, DHGroup.GROUP_14),  # gap filled
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_14),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_14),
        _t(EncAlg.AES_CBC,        192, HashAlg.SHA512, DHGroup.GROUP_14),  # gap filled
        _t(EncAlg.AES_CBC,        192, HashAlg.SHA256, DHGroup.GROUP_14),
        _t(EncAlg.AES_CBC,        192, HashAlg.SHA1,   DHGroup.GROUP_14),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA512, DHGroup.GROUP_14),  # gap filled
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_14),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA1,   DHGroup.GROUP_14),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA256, DHGroup.GROUP_14),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   DHGroup.GROUP_14),
    ],

    DHGroup.GROUP_5: [  # 1536-bit MODP — transitional
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_5),  # gap filled
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_5),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA384, DHGroup.GROUP_5),  # gap filled
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_5),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA1,   DHGroup.GROUP_5),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   DHGroup.GROUP_5),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.MD5,    DHGroup.GROUP_5),
    ],

    DHGroup.GROUP_19: [  # ECP P-256 — modern Cisco/Fortinet
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_19),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_19),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA1,   DHGroup.GROUP_19),
    ],

    DHGroup.GROUP_20: [  # ECP P-384 — NSA Suite B
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_20),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_20),
    ],

    DHGroup.GROUP_1: [  # 768-bit MODP — ancient legacy
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.SHA1,   DHGroup.GROUP_1),
        _t(EncAlg.TRIPLE_DES_CBC, 0,   HashAlg.MD5,    DHGroup.GROUP_1),
        _t(EncAlg.DES_CBC,        0,   HashAlg.SHA1,   DHGroup.GROUP_1),
        _t(EncAlg.DES_CBC,        0,   HashAlg.MD5,    DHGroup.GROUP_1),
    ],

    DHGroup.GROUP_15: [  # 3072-bit MODP — uncommon high-security
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_15),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_15),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_15),
    ],

    DHGroup.GROUP_16: [  # 4096-bit MODP — high-security (was missing entirely)
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA256, DHGroup.GROUP_16),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_16),
        _t(EncAlg.AES_CBC,        128, HashAlg.SHA256, DHGroup.GROUP_16),
    ],

    DHGroup.GROUP_21: [  # ECP P-521 — rare, requires cryptography EC lib
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA512, DHGroup.GROUP_21),
        _t(EncAlg.AES_CBC,        256, HashAlg.SHA384, DHGroup.GROUP_21),
    ],
}
