from __future__ import annotations

import os
import struct

from scapy.all import Dot11, Dot11Auth

SAE_ALGORITHM_NUMBER = 3
SAE_COMMIT_SEQUENCE = 1
SAE_CONFIRM_SEQUENCE = 2
SAE_STATUS_SUCCESS = 0

# ECC group sizes in bytes (scalar size, element = 2x scalar for uncompressed point)
ECC_GROUP_SIZES = {
    19: 32,   # NIST P-256
    20: 48,   # NIST P-384
    21: 66,   # NIST P-521
}


def build_sae_commit_frame(
    target_bssid: str,
    source_mac: str,
    group_id: int = 19,
) -> Dot11:
    """Build an SAE Commit authentication frame.

    The scalar and element are random — the AP's response time depends on
    its own hash-to-curve computation, not on the values we send.
    """
    scalar_size = ECC_GROUP_SIZES.get(group_id, 32)
    element_size = scalar_size * 2

    # SAE Commit body: group_id (2B) + scalar + element
    commit_body = (
        struct.pack("<H", group_id)
        + os.urandom(scalar_size)
        + os.urandom(element_size)
    )

    frame = (
        Dot11(
            type=0,
            subtype=11,
            addr1=target_bssid,
            addr2=source_mac,
            addr3=target_bssid,
        )
        / Dot11Auth(
            algo=SAE_ALGORITHM_NUMBER,
            seqnum=SAE_COMMIT_SEQUENCE,
            status=SAE_STATUS_SUCCESS,
        )
    )

    # Append the commit body as raw bytes after the Auth header
    return frame / commit_body


def build_sae_confirm_frame(
    target_bssid: str,
    source_mac: str,
    send_confirm: int,
    confirm_token: bytes,
) -> Dot11:
    """Build an SAE Confirm authentication frame."""
    confirm_body = struct.pack("<H", send_confirm) + confirm_token

    frame = (
        Dot11(
            type=0,
            subtype=11,
            addr1=target_bssid,
            addr2=source_mac,
            addr3=target_bssid,
        )
        / Dot11Auth(
            algo=SAE_ALGORITHM_NUMBER,
            seqnum=SAE_CONFIRM_SEQUENCE,
            status=SAE_STATUS_SUCCESS,
        )
    )

    return frame / confirm_body


def is_sae_commit_response(packet, expected_bssid: str) -> bool:
    """Check if a packet is an SAE Commit response from the expected AP."""
    if not packet.haslayer(Dot11):
        return False

    dot11 = packet[Dot11]
    if dot11.type != 0 or dot11.subtype != 11:
        return False

    if dot11.addr2 != expected_bssid:
        return False

    if not packet.haslayer(Dot11Auth):
        return False

    auth = packet[Dot11Auth]
    return auth.algo == SAE_ALGORITHM_NUMBER and auth.seqnum == SAE_COMMIT_SEQUENCE
