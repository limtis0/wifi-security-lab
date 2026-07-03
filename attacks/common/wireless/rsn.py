from __future__ import annotations

import struct

# OUI for IEEE 802.11 standard AKMs
RSN_OUI = b"\x00\x0f\xac"

# AKM suite type identifiers
AKM_PSK = 2        # WPA2-PSK (00-0F-AC:2)
AKM_SAE = 8        # SAE (00-0F-AC:8)

# Cipher suite identifiers
CIPHER_CCMP = 4    # AES-CCMP (00-0F-AC:4)

RSN_VERSION = 1


def build_wpa2_only_rsn() -> bytes:
    """Build an RSN IE body with only WPA2-PSK AKM and CCMP cipher.

    Returns the RSN IE info bytes (not including the element ID/length header).
    """
    version = struct.pack("<H", RSN_VERSION)
    group_cipher = RSN_OUI + struct.pack("B", CIPHER_CCMP)
    pairwise_count = struct.pack("<H", 1)
    pairwise_cipher = RSN_OUI + struct.pack("B", CIPHER_CCMP)
    akm_count = struct.pack("<H", 1)
    akm_suite = RSN_OUI + struct.pack("B", AKM_PSK)
    # RSN capabilities: no PMF required, no PMF capable
    rsn_capabilities = struct.pack("<H", 0x0000)

    return (
        version
        + group_cipher
        + pairwise_count
        + pairwise_cipher
        + akm_count
        + akm_suite
        + rsn_capabilities
    )


def strip_sae_from_rsn(original_rsn_bytes: bytes) -> bytes:
    """Remove the SAE AKM suite from RSN IE bytes, keeping all others.

    If only SAE was present, returns RSN with zero AKM suites.
    """
    offset = 0

    # Version (2 bytes)
    version = original_rsn_bytes[offset:offset + 2]
    offset += 2

    # Group cipher suite (4 bytes)
    group_cipher = original_rsn_bytes[offset:offset + 4]
    offset += 4

    # Pairwise cipher suite count + suites
    pairwise_count = struct.unpack_from("<H", original_rsn_bytes, offset)[0]
    offset += 2
    pairwise_suites = original_rsn_bytes[offset:offset + pairwise_count * 4]
    offset += pairwise_count * 4

    # AKM suite count + suites
    akm_count = struct.unpack_from("<H", original_rsn_bytes, offset)[0]
    offset += 2

    filtered_akm_suites = []
    for akm_index in range(akm_count):
        akm_suite = original_rsn_bytes[offset:offset + 4]
        offset += 4
        # Keep the suite only if it's not SAE
        akm_type = akm_suite[3]
        if akm_type != AKM_SAE:
            filtered_akm_suites.append(akm_suite)

    # Remaining bytes (RSN capabilities, PMKID, etc.)
    remaining = original_rsn_bytes[offset:]

    # Reassemble
    new_akm_count = struct.pack("<H", len(filtered_akm_suites))
    new_pairwise_count = struct.pack("<H", pairwise_count)

    return (
        version
        + group_cipher
        + new_pairwise_count
        + pairwise_suites
        + new_akm_count
        + b"".join(filtered_akm_suites)
        + remaining
    )
