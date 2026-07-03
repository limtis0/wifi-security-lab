from __future__ import annotations

import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)

# NIST P-256 curve parameters
P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _mac_to_bytes(mac_address: str) -> bytes:
    return bytes.fromhex(mac_address.replace(":", ""))


def _is_quadratic_residue(value: int, prime: int) -> bool:
    """Check if value is a quadratic residue mod prime using Euler's criterion."""
    if value == 0:
        return True
    result = pow(value, (prime - 1) // 2, prime)
    return result == 1


def sae_hash_to_element_iteration_count(
    password: str,
    mac_a: str,
    mac_b: str,
    group_id: int = 19,
    max_iterations: int = 40,
) -> int:
    """Compute the SAE hash-to-curve iteration count for a password + MAC pair.

    Implements the vulnerable try-and-increment from IEEE 802.11-2016 Section 12.4.4.2.2
    (pre-Dragonblood constant-time patch). The number of iterations leaks through timing.

    Returns the 1-based counter value when a valid curve point is first found,
    or max_iterations if none found within the limit.
    """
    if group_id != 19:
        raise ValueError(f"Only NIST P-256 (group 19) is supported, got group {group_id}")

    mac_a_bytes = _mac_to_bytes(mac_a)
    mac_b_bytes = _mac_to_bytes(mac_b)

    # Sort MACs: key = max || min (per IEEE 802.11 spec)
    if mac_a_bytes > mac_b_bytes:
        sorted_macs = mac_a_bytes + mac_b_bytes
    else:
        sorted_macs = mac_b_bytes + mac_a_bytes

    password_bytes = password.encode("utf-8")

    for counter in range(1, max_iterations + 1):
        hash_input = password_bytes + counter.to_bytes(1, "little")
        seed = hmac.new(sorted_macs, hash_input, hashlib.sha256).digest()

        # Interpret seed as big-endian integer, reduce mod p
        x_candidate = int.from_bytes(seed, "big") % P256_PRIME

        # Check if x³ + ax + b is a quadratic residue mod p
        y_squared = (pow(x_candidate, 3, P256_PRIME) + P256_A * x_candidate + P256_B) % P256_PRIME

        if _is_quadratic_residue(y_squared, P256_PRIME):
            return counter

    return max_iterations
