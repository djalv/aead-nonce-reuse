import pytest
from cryptography.exceptions import InvalidTag

from nonce_reuse.aead import Algorithm, Cipher, EncryptedMessage, make_cipher


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 64, 4096])
@pytest.mark.parametrize("aad", [None, b"public metadata"])
def test_message_round_trip_preserves_bytes_and_separates_tag(
    cipher: Cipher, size: int, aad: bytes | None
) -> None:
    plaintext = bytes(index % 256 for index in range(size))
    nonce = bytes(12)
    combined = cipher.encrypt(nonce, plaintext, aad)

    message = EncryptedMessage.from_combined(nonce, combined)

    assert len(message.ciphertext) == size
    assert len(message.tag) == 16
    assert message.combined == combined
    assert cipher.decrypt(message.nonce, message.combined, aad) == plaintext


@pytest.mark.parametrize("key_length", [0, 16, 24, 31, 33])
def test_study_configuration_rejects_keys_other_than_256_bits(
    algorithm: Algorithm, key_length: int
) -> None:
    with pytest.raises(ValueError, match="32-byte key"):
        make_cipher(algorithm, bytes(key_length))


def test_unknown_algorithm_is_rejected(key: bytes) -> None:
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        make_cipher("unknown", key)


@pytest.mark.parametrize("nonce_length", [0, 8, 11, 13])
def test_message_rejects_nonce_outside_study_configuration(nonce_length: int) -> None:
    with pytest.raises(ValueError, match="12-byte nonce"):
        EncryptedMessage(bytes(nonce_length), b"ciphertext", bytes(16))


@pytest.mark.parametrize("tag_length", [0, 15, 17])
def test_message_rejects_incomplete_or_oversized_tag(tag_length: int) -> None:
    with pytest.raises(ValueError, match="16-byte tag"):
        EncryptedMessage(bytes(12), b"ciphertext", bytes(tag_length))


@pytest.mark.parametrize("size", [0, 1, 15])
def test_combined_message_requires_a_complete_tag(size: int) -> None:
    with pytest.raises(ValueError, match="shorter than its tag"):
        EncryptedMessage.from_combined(bytes(12), bytes(size))


@pytest.mark.parametrize("changed", ["ciphertext", "tag", "aad", "nonce", "key", "truncation"])
def test_authenticated_decryption_rejects_independent_changes(
    algorithm: Algorithm, cipher: Cipher, key: bytes, changed: str
) -> None:
    nonce, aad = bytes(12), b"metadata"
    combined = cipher.encrypt(nonce, b"payload", aad)

    if changed == "ciphertext":
        combined = bytes([combined[0] ^ 1]) + combined[1:]
    elif changed == "tag":
        combined = combined[:-1] + bytes([combined[-1] ^ 1])
    elif changed == "aad":
        aad = b"other metadata"
    elif changed == "nonce":
        nonce = b"\x01" + nonce[1:]
    elif changed == "key":
        cipher = make_cipher(algorithm, bytes([key[0] ^ 1]) + key[1:])
    else:
        combined = combined[:-1]

    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, combined, aad)
