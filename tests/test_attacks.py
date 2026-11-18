import pytest

from nonce_reuse.aead import Cipher, EncryptedMessage
from nonce_reuse.attacks import recover_plaintext, xor_bytes


def test_xor_preserves_all_byte_values() -> None:
    assert xor_bytes(b"\x00\xff\x80", b"\xff\xff\x01") == b"\xff\x00\x81"
    assert xor_bytes(b"", b"") == b""


@pytest.mark.parametrize("left,right", [(b"a", b""), (b"a", b"ab")])
def test_xor_rejects_silent_truncation(left: bytes, right: bytes) -> None:
    with pytest.raises(ValueError, match="equal lengths"):
        xor_bytes(left, right)


@pytest.mark.parametrize(
    "known,source,target,expected",
    [
        (b"\x10\x20", b"\xba\x9b", b"\xfe\xfe", b"\x54\x45"),
        (b"\x10", b"\xba\x9b", b"\xfe\xfe", b"\x54"),
        (b"\x10\x20", b"\xba", b"\xfe\xfe", b"\x54"),
        (b"\x10\x20", b"\xba\x9b", b"\xfe", b"\x54"),
        (b"", b"\xba", b"\xfe", b""),
        (b"\x10", b"", b"\xfe", b""),
        (b"\x10", b"\xba", b"", b""),
    ],
)
def test_recovery_uses_only_the_available_overlap(
    known: bytes, source: bytes, target: bytes, expected: bytes
) -> None:
    assert recover_plaintext(known, source, target) == expected


@pytest.mark.parametrize("known", [b"", b"k", bytes(range(256))])
@pytest.mark.parametrize("target", [b"", b"secret", bytes(reversed(range(256)))])
def test_reused_keystream_recovery_with_real_aead(
    cipher: Cipher, known: bytes, target: bytes
) -> None:
    nonce = bytes(12)
    source_message = EncryptedMessage.from_combined(nonce, cipher.encrypt(nonce, known, None))
    target_message = EncryptedMessage.from_combined(nonce, cipher.encrypt(nonce, target, None))

    recovered = recover_plaintext(known, source_message.ciphertext, target_message.ciphertext)

    assert recovered == target[: min(len(known), len(target))]


def test_only_the_known_prefix_is_recovered_even_when_ciphertexts_are_longer(
    cipher: Cipher,
) -> None:
    nonce = bytes(12)
    known = b"public header and further known text"
    target = b"private text that must remain partially unknown"
    source_message = EncryptedMessage.from_combined(nonce, cipher.encrypt(nonce, known, None))
    target_message = EncryptedMessage.from_combined(nonce, cipher.encrypt(nonce, target, None))

    recovered = recover_plaintext(known[:6], source_message.ciphertext, target_message.ciphertext)

    assert recovered == b"privat"
    assert len(recovered) == 6
