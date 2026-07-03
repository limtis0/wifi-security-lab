from __future__ import annotations

from scapy.all import Dot11, Dot11Auth

from attacks.common.wireless.sae import (
    SAE_ALGORITHM_NUMBER,
    SAE_COMMIT_SEQUENCE,
    SAE_CONFIRM_SEQUENCE,
    build_sae_commit_frame,
    build_sae_confirm_frame,
    is_sae_commit_response,
)


# --- build_sae_commit_frame ---


class TestBuildSaeCommitFrame:
    def test_frame_is_auth_with_sae_algorithm(self):
        frame = build_sae_commit_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
        )

        assert frame[Dot11].type == 0
        assert frame[Dot11].subtype == 11
        assert frame[Dot11Auth].algo == SAE_ALGORITHM_NUMBER
        assert frame[Dot11Auth].seqnum == SAE_COMMIT_SEQUENCE

    def test_frame_has_correct_mac_addresses(self):
        frame = build_sae_commit_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
        )

        assert frame[Dot11].addr1 == "00:11:22:33:44:55"
        assert frame[Dot11].addr2 == "aa:bb:cc:dd:ee:ff"

    def test_different_group_ids_produce_different_body(self):
        frame_p256 = build_sae_commit_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
            group_id=19,
        )
        frame_p384 = build_sae_commit_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
            group_id=20,
        )

        # P-384 frame body should be longer than P-256 (48B scalar vs 32B)
        bytes_p256 = bytes(frame_p256[Dot11Auth].payload)
        bytes_p384 = bytes(frame_p384[Dot11Auth].payload)
        assert len(bytes_p384) > len(bytes_p256)


# --- build_sae_confirm_frame ---


class TestBuildSaeConfirmFrame:
    def test_frame_is_auth_with_confirm_sequence(self):
        frame = build_sae_confirm_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
            send_confirm=1,
            confirm_token=b"\xde\xad\xbe\xef",
        )

        assert frame[Dot11Auth].algo == SAE_ALGORITHM_NUMBER
        assert frame[Dot11Auth].seqnum == SAE_CONFIRM_SEQUENCE

    def test_frame_body_contains_confirm_token(self):
        token = b"\xde\xad\xbe\xef"
        frame = build_sae_confirm_frame(
            target_bssid="00:11:22:33:44:55",
            source_mac="aa:bb:cc:dd:ee:ff",
            send_confirm=1,
            confirm_token=token,
        )

        body_bytes = bytes(frame[Dot11Auth].payload)
        assert token in body_bytes


# --- is_sae_commit_response ---


class TestIsSaeCommitResponse:
    def _make_sae_auth_packet(self, bssid: str) -> Dot11:
        return (
            Dot11(type=0, subtype=11, addr2=bssid)
            / Dot11Auth(algo=SAE_ALGORITHM_NUMBER, seqnum=SAE_COMMIT_SEQUENCE)
        )

    def test_matches_sae_auth_from_expected_bssid(self):
        packet = self._make_sae_auth_packet("00:11:22:33:44:55")

        assert is_sae_commit_response(packet, "00:11:22:33:44:55") is True

    def test_rejects_non_auth_frame(self):
        # Data frame (type=2)
        packet = Dot11(type=2, subtype=0, addr2="00:11:22:33:44:55")

        assert is_sae_commit_response(packet, "00:11:22:33:44:55") is False

    def test_rejects_auth_from_wrong_bssid(self):
        packet = self._make_sae_auth_packet("ff:ff:ff:ff:ff:ff")

        assert is_sae_commit_response(packet, "00:11:22:33:44:55") is False
