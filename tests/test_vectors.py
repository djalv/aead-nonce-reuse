"""Known answers copied from NIST CAVP and RFC 8439, not generated locally."""

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from nonce_reuse.aead import Algorithm, EncryptedMessage, make_cipher

VECTORS = json.loads((Path(__file__).parent / "vectors" / "aead.json").read_text(encoding="utf-8"))[
    "vectors"
]
ACCEPTED = [vector for vector in VECTORS if vector["expected"] == "accept"]
REJECTED = [vector for vector in VECTORS if vector["expected"] == "reject"]


@pytest.mark.parametrize("vector", ACCEPTED, ids=lambda vector: vector["id"])
def test_encryption_matches_published_ciphertext_and_tag(vector) -> None:
    cipher = make_cipher(Algorithm(vector["algorithm"]), bytes.fromhex(vector["key_hex"]))
    nonce = bytes.fromhex(vector["nonce_hex"])
    plaintext = bytes.fromhex(vector["plaintext_hex"])
    aad = bytes.fromhex(vector["aad_hex"])

    message = EncryptedMessage.from_combined(nonce, cipher.encrypt(nonce, plaintext, aad))

    assert message.ciphertext == bytes.fromhex(vector["ciphertext_hex"])
    assert message.tag == bytes.fromhex(vector["tag_hex"])


@pytest.mark.parametrize("vector", ACCEPTED, ids=lambda vector: vector["id"])
def test_decryption_matches_published_plaintext(vector) -> None:
    cipher = make_cipher(Algorithm(vector["algorithm"]), bytes.fromhex(vector["key_hex"]))
    nonce = bytes.fromhex(vector["nonce_hex"])
    data = bytes.fromhex(vector["ciphertext_hex"] + vector["tag_hex"])

    plaintext = cipher.decrypt(nonce, data, bytes.fromhex(vector["aad_hex"]))

    assert plaintext == bytes.fromhex(vector["plaintext_hex"])


@pytest.mark.parametrize("vector", REJECTED, ids=lambda vector: vector["id"])
def test_decryption_rejects_published_failure_vectors(vector) -> None:
    cipher = make_cipher(Algorithm(vector["algorithm"]), bytes.fromhex(vector["key_hex"]))
    nonce = bytes.fromhex(vector["nonce_hex"])
    data = bytes.fromhex(vector["ciphertext_hex"] + vector["tag_hex"])

    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, data, bytes.fromhex(vector["aad_hex"]))
