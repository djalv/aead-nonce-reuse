"""Known-plaintext recovery from aligned ciphertexts sharing a keystream."""


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings; callers choose the overlap explicitly."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal lengths.")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def recover_plaintext(
    known_plaintext: bytes,
    known_ciphertext: bytes,
    target_ciphertext: bytes,
) -> bytes:
    """Recover the overlapping prefix when the ciphertexts share a keystream.

    Inputs must start at the same stream position and exclude authentication
    tags. Only the supplied plaintext prefix is known to the attacker. With
    distinct keystreams, the returned candidate generally does not match the
    target; this function cannot detect that condition without extra knowledge.
    """
    length = min(len(known_plaintext), len(known_ciphertext), len(target_ciphertext))
    keystream = xor_bytes(known_plaintext[:length], known_ciphertext[:length])
    return xor_bytes(target_ciphertext[:length], keystream)
