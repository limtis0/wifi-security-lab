from __future__ import annotations

import struct

from attacks.common.wireless.rsn import (
    AKM_PSK,
    AKM_SAE,
    RSN_OUI,
    build_wpa2_only_rsn,
    strip_sae_from_rsn,
)


def _build_rsn_with_akms(akm_types: list[int]) -> bytes:
    """Helper to build RSN IE bytes with specified AKM types."""
    version = struct.pack("<H", 1)
    group_cipher = RSN_OUI + struct.pack("B", 4)
    pairwise_count = struct.pack("<H", 1)
    pairwise_cipher = RSN_OUI + struct.pack("B", 4)
    akm_count = struct.pack("<H", len(akm_types))
    akm_suites = b"".join(RSN_OUI + struct.pack("B", akm_type) for akm_type in akm_types)
    capabilities = struct.pack("<H", 0)
    return version + group_cipher + pairwise_count + pairwise_cipher + akm_count + akm_suites + capabilities


# --- build_wpa2_only_rsn ---


class TestBuildWpa2OnlyRsn:
    def test_contains_wpa2_psk_akm(self):
        rsn_bytes = build_wpa2_only_rsn()
        expected_akm = RSN_OUI + struct.pack("B", AKM_PSK)

        assert expected_akm in rsn_bytes

    def test_does_not_contain_sae_akm(self):
        rsn_bytes = build_wpa2_only_rsn()
        sae_akm = RSN_OUI + struct.pack("B", AKM_SAE)

        assert sae_akm not in rsn_bytes


# --- strip_sae_from_rsn ---


class TestStripSaeFromRsn:
    def test_removes_sae_keeps_psk(self):
        original = _build_rsn_with_akms([AKM_PSK, AKM_SAE])
        stripped = strip_sae_from_rsn(original)

        psk_akm = RSN_OUI + struct.pack("B", AKM_PSK)
        sae_akm = RSN_OUI + struct.pack("B", AKM_SAE)

        assert psk_akm in stripped
        assert sae_akm not in stripped

    def test_sae_only_results_in_zero_akms(self):
        original = _build_rsn_with_akms([AKM_SAE])
        stripped = strip_sae_from_rsn(original)

        # AKM count should be 0 — find it after pairwise suites
        # version(2) + group(4) + pairwise_count(2) + pairwise(4) = offset 12
        akm_count = struct.unpack_from("<H", stripped, 12)[0]
        assert akm_count == 0
