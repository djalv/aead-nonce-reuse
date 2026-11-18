"""The two AEAD configurations and their ciphertext representation."""

from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

type Cipher = AESGCM | ChaCha20Poly1305


class Algorithm(StrEnum):
    AES_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"


def make_cipher(algorithm: Algorithm, key: bytes) -> Cipher:
    """Create a cipher using the study's 256-bit key configuration."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"The study requires a {KEY_SIZE}-byte key.")
    match algorithm:
        case Algorithm.AES_GCM:
            return AESGCM(key)
        case Algorithm.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key)
        case _:
            raise ValueError(f"Unsupported algorithm: {algorithm}")


@dataclass(frozen=True)
class EncryptedMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"The study requires a {NONCE_SIZE}-byte nonce.")
        if len(self.tag) != TAG_SIZE:
            raise ValueError(f"The study requires a {TAG_SIZE}-byte tag.")

    @classmethod
    def from_combined(cls, nonce: bytes, data: bytes) -> "EncryptedMessage":
        if len(data) < TAG_SIZE:
            raise ValueError("The encrypted message is shorter than its tag.")
        return cls(nonce, data[:-TAG_SIZE], data[-TAG_SIZE:])

    @property
    def combined(self) -> bytes:
        """Reassemble the ciphertext and tag expected by the library."""
        return self.ciphertext + self.tag
