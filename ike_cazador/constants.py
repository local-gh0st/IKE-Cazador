"""
IKE Aggressive Mode constants, enums, and protocol definitions.
All values sourced from RFC 2408, RFC 2409, RFC 3526, RFC 5903, and IANA ISAKMP registry.
"""

from enum import IntEnum


# ---------------------------------------------------------------------------
# ISAKMP Exchange Types (RFC 2408 §3.1)
# ---------------------------------------------------------------------------
class ExchangeType(IntEnum):
    NONE            = 0
    BASE            = 1
    IDENTITY_PROTECT = 2   # Main Mode
    AUTH_ONLY       = 3
    AGGRESSIVE      = 4
    INFORMATIONAL   = 5
    QUICK_MODE      = 32


# ---------------------------------------------------------------------------
# ISAKMP Payload Types (RFC 2408 §3.1)
# ---------------------------------------------------------------------------
class PayloadType(IntEnum):
    NONE        = 0
    SA          = 1
    PROPOSAL    = 2
    TRANSFORM   = 3
    KEY_EXCHANGE = 4
    ID          = 5
    CERT        = 6
    CERT_REQUEST = 7
    HASH        = 8
    SIG         = 9
    NONCE       = 10
    NOTIFICATION = 11
    DELETE      = 12
    VENDOR_ID   = 13
    FRAGMENT    = 132   # Cisco proprietary IKE fragmentation


# ---------------------------------------------------------------------------
# ISAKMP Notify Message Types (RFC 2408 §3.14 + IANA extensions)
# ---------------------------------------------------------------------------
class NotifyType(IntEnum):
    INVALID_PAYLOAD_TYPE            = 1
    DOI_NOT_SUPPORTED               = 2
    SITUATION_NOT_SUPPORTED         = 3
    INVALID_COOKIE                  = 4
    INVALID_MAJOR_VERSION           = 5
    INVALID_MINOR_VERSION           = 6
    INVALID_EXCHANGE_TYPE           = 7
    INVALID_FLAGS                   = 8
    INVALID_MESSAGE_ID              = 9
    INVALID_PROTOCOL_ID             = 10
    INVALID_SPI                     = 11
    INVALID_TRANSFORM_ID            = 12
    ATTRIBUTES_NOT_SUPPORTED        = 13
    NO_PROPOSAL_CHOSEN              = 14
    BAD_PROPOSAL_SYNTAX             = 15
    PAYLOAD_MALFORMED               = 16
    INVALID_KEY_INFORMATION         = 17
    INVALID_ID_INFORMATION          = 18   # AM enabled, transform OK, group not found
    INVALID_CERT_ENCODING           = 19
    INVALID_CERTIFICATE             = 20
    CERT_TYPE_UNSUPPORTED           = 21
    INVALID_CERT_AUTHORITY          = 22
    INVALID_HASH_INFORMATION        = 23
    AUTHENTICATION_FAILED           = 24
    INVALID_SIGNATURE               = 25
    ADDRESS_NOTIFICATION            = 26
    NOTIFY_SA_LIFETIME              = 27
    CERTIFICATE_UNAVAILABLE         = 28
    UNSUPPORTED_EXCHANGE_TYPE       = 29
    UNEQUAL_PAYLOAD_LENGTHS         = 30


# ---------------------------------------------------------------------------
# IKE Identity Types (RFC 2407 §4.6.2)
# ---------------------------------------------------------------------------
class IDType(IntEnum):
    IPV4_ADDR       = 1
    FQDN            = 2
    USER_FQDN       = 3
    IPV4_ADDR_SUBNET = 4
    IPV6_ADDR       = 5
    IPV6_ADDR_SUBNET = 6
    IPV4_ADDR_RANGE  = 7
    IPV6_ADDR_RANGE  = 8
    DER_ASN1_DN     = 9
    DER_ASN1_GN     = 10
    KEY_ID          = 11


# ---------------------------------------------------------------------------
# IKE Encryption Algorithms (ISAKMP Attribute Type 1)
# ---------------------------------------------------------------------------
class EncAlg(IntEnum):
    DES_CBC         = 1
    IDEA_CBC        = 2
    BLOWFISH_CBC    = 3
    RC5_R16_B64_CBC = 4
    TRIPLE_DES_CBC  = 5
    CAST_CBC        = 6
    AES_CBC         = 7   # requires KEY_LENGTH attribute


# ---------------------------------------------------------------------------
# IKE Hash Algorithms (ISAKMP Attribute Type 2)
# Codes 4-6 from IANA ISAKMP Hash Algorithm registry (RFC 4868 extension)
# ---------------------------------------------------------------------------
class HashAlg(IntEnum):
    MD5     = 1
    SHA1    = 2
    TIGER   = 3
    SHA256  = 4
    SHA384  = 5
    SHA512  = 6


# ---------------------------------------------------------------------------
# IKE Authentication Methods (ISAKMP Attribute Type 3)
# ---------------------------------------------------------------------------
class AuthMethod(IntEnum):
    PSK             = 1
    DSS_SIG         = 2
    RSA_SIG         = 3
    RSA_ENC         = 4
    RSA_ENC_REVISED = 5
    XAUTH_PSK       = 65001  # Cisco XAUTH with PSK


# ---------------------------------------------------------------------------
# DH Groups (RFC 2409, RFC 3526, RFC 5903)
# ---------------------------------------------------------------------------
class DHGroup(IntEnum):
    GROUP_1  = 1    # 768-bit MODP  (deprecated)
    GROUP_2  = 2    # 1024-bit MODP (legacy standard)
    GROUP_5  = 5    # 1536-bit MODP (transitional)
    GROUP_14 = 14   # 2048-bit MODP (modern standard)
    GROUP_15 = 15   # 3072-bit MODP (high security)
    GROUP_16 = 16   # 4096-bit MODP (rare)
    GROUP_19 = 19   # 256-bit ECP P-256 (modern, requires cryptography lib)
    GROUP_20 = 20   # 384-bit ECP P-384 (NSA Suite B)
    GROUP_21 = 21   # 521-bit ECP P-521 (rare)


# ---------------------------------------------------------------------------
# DH Group KE payload sizes (bytes)
# MODP: bits / 8
# ECP:  2 * ceil(bits / 8)  — x || y, NO 0x04 prefix (RFC 5903 §7)
# ---------------------------------------------------------------------------
DH_KE_SIZES = {
    DHGroup.GROUP_1:  96,   # 768  / 8
    DHGroup.GROUP_2:  128,  # 1024 / 8
    DHGroup.GROUP_5:  192,  # 1536 / 8
    DHGroup.GROUP_14: 256,  # 2048 / 8
    DHGroup.GROUP_15: 384,  # 3072 / 8
    DHGroup.GROUP_16: 512,  # 4096 / 8
    DHGroup.GROUP_19: 64,   # 2 * 32
    DHGroup.GROUP_20: 96,   # 2 * 48
    DHGroup.GROUP_21: 132,  # 2 * 66  (ceil(521/8) = 66)
}

# Phase 1 probe order — most common first for fastest discovery.
# G1 is placed 3rd (not last) so Cisco VPN Concentrator 3000 devices get
# probed before their per-source-IP rate limiter engages.  G2 and G14 still
# come first to cover the vast majority of modern devices quickly.
DH_PROBE_ORDER = [
    DHGroup.GROUP_2,    # most common legacy (Cisco ASA default)
    DHGroup.GROUP_14,   # modern standard
    DHGroup.GROUP_1,    # legacy Cisco VPN Concentrator 3000 — must be early
    DHGroup.GROUP_5,    # transitional
    DHGroup.GROUP_19,   # ECP P-256 (modern Cisco/Fortinet)
    DHGroup.GROUP_20,   # ECP P-384 (NSA Suite B)
    DHGroup.GROUP_15,   # uncommon high-security
    DHGroup.GROUP_21,   # rare ECP P-521
]


# ---------------------------------------------------------------------------
# Hashcat modes for IKE PSK
# ---------------------------------------------------------------------------
HASHCAT_MODES = {
    HashAlg.MD5:    5300,
    HashAlg.SHA1:   5400,
    HashAlg.SHA256: 5400,  # SHA256 uses same format, mode 5400 with longer hash
}

HASH_SIZES = {
    HashAlg.MD5:    16,
    HashAlg.SHA1:   20,
    HashAlg.SHA256: 32,
    HashAlg.SHA384: 48,
    HashAlg.SHA512: 64,
}


# ---------------------------------------------------------------------------
# ISAKMP protocol constants
# ---------------------------------------------------------------------------
ISAKMP_VERSION      = 0x10   # IKEv1 (major=1, minor=0)
IKEV2_VERSION       = 0x20   # IKEv2 marker
ISAKMP_HEADER_LEN   = 28
IPSEC_DOI           = 1
SIT_IDENTITY_ONLY   = 1
PROTO_ISAKMP        = 1
ISAKMP_FLAG_ENCRYPT = 0x01   # Encryption bit in flags field
SA_LIFE_TYPE_SECONDS = 1
SA_LIFE_DURATION    = 28800  # 8 hours in seconds


# ---------------------------------------------------------------------------
# ISAKMP Attribute Types (TV format)
# ---------------------------------------------------------------------------
class AttrType(IntEnum):
    ENCRYPTION_ALG  = 1
    HASH_ALG        = 2
    AUTH_METHOD     = 3
    GROUP_DESC      = 4
    GROUP_TYPE      = 5
    LIFE_TYPE       = 11
    LIFE_DURATION   = 12
    KEY_LENGTH      = 14


# ---------------------------------------------------------------------------
# Host classification results
# ---------------------------------------------------------------------------
class HostStatus(IntEnum):
    PENDING             = 0
    PROBING             = 1
    AGGRESSIVE          = 2    # AM confirmed, PSK auth, capturable
    AGGRESSIVE_RSA      = 3    # AM confirmed, RSA/cert auth, not PSK
    AGGRESSIVE_WILDCARD = 4    # AM confirmed + wildcard detected
    NOT_VULNERABLE      = 5    # All probes exhausted, no AM confirmed
    IKEV2_ONLY          = 6    # Device responded with IKEv2
    UNKNOWN             = 7    # All 8 DH groups returned Notify-14
    NO_RESPONSE         = 8    # Total silence across all probes
    FIREWALL_FILTERED   = 9    # ICMP admin-prohibited — return path blocked


# ---------------------------------------------------------------------------
# Phase 2 host states
# ---------------------------------------------------------------------------
class Phase2Status(IntEnum):
    ACTIVE           = 0
    COMPLETE         = 1
    DEAD             = 2         # Never responded in Phase 2
    RATE_LIMITED     = 3         # Was responding, then went silent
    CAPPED           = 4         # Wildcard host hit capture cap


# ---------------------------------------------------------------------------
# Response classifications from parser
# ---------------------------------------------------------------------------
class ResponseType(IntEnum):
    CONFIRMED_AM2       = 0   # Full AM2 with HASH_R — capturable
    AM2_RSA_AUTH        = 1   # AM2 with SIG instead of Hash — RSA auth
    AM2_MALFORMED       = 2   # AM2 structure invalid
    NOTIFY_NO_PROPOSAL  = 3   # Notify-14
    NOTIFY_INVALID_ID   = 4   # Notify-18 — smoking gun
    NOTIFY_AUTH_FAILED  = 5   # Notify-24
    NOTIFY_NO_AM        = 6   # Notify-7 or Notify-29
    NOTIFY_OTHER        = 7   # Any other Notify type
    MAIN_MODE_RESPONSE  = 8   # Exchange type 2
    IKEV2               = 9   # Version byte 0x20
    CISCO_FRAGMENT      = 10  # next_payload == 132
    TRUNCATED           = 11  # len < 28
    MALFORMED           = 12  # Parse error
    UNKNOWN_EXCHANGE    = 13  # Unrecognized exchange type
    ENCRYPTED           = 14  # Encryption flag set (unexpected)
    TIMEOUT             = 15  # No response received


# ---------------------------------------------------------------------------
# Wildcard confidence thresholds
# ---------------------------------------------------------------------------
WILDCARD_CONFIRM_THRESHOLD  = 5    # captures before accumulation-based confirm
WILDCARD_CAP                = 5    # max captures from a confirmed wildcard host
WILDCARD_CONFIDENCE_HIGH    = 70   # >= HIGH: likely real PSK, crack first
WILDCARD_CONFIDENCE_MEDIUM  = 40   # 40-69: possible real PSK
                                   # < 40:  likely garbage PSK


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
RANDOM_GROUP_PREFIX     = "gps"   # prefix for wildcard validation probes
RANDOM_GROUP_SUFFIX_LEN = 7       # total random chars after prefix
IKE_PORT                = 500
NATT_PORT               = 4500
