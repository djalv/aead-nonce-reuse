"""Controlled demonstrations with public fixtures, including deliberate misuse."""

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from nonce_reuse.aead import Algorithm, Cipher, EncryptedMessage, make_cipher
from nonce_reuse.attacks import recover_plaintext, xor_bytes
from nonce_reuse.nonces import NonceCounter

# These values are public demonstration fixtures, never production secrets.
DEMO_KEY = bytes(range(32))
DEMO_AAD = b"nonce-reuse-study:public-demo"
KNOWN_PLAINTEXT = b"Transfer USD 100 to account 1234."
TARGET_PLAINTEXT = b"Transfer USD 900 to account 5678."
LONG_TARGET = b"Transfer EUR 900 to account 5678. Confirm before noon."


@dataclass(frozen=True)
class RecoveryResult:
    known_plaintext: bytes
    target_plaintext: bytes
    known_message: EncryptedMessage
    target_message: EncryptedMessage
    recovered_plaintext: bytes
    round_trips_verified: bool

    @property
    def overlap(self) -> int:
        return min(len(self.known_plaintext), len(self.target_plaintext))

    @property
    def nonce_reused(self) -> bool:
        return self.known_message.nonce == self.target_message.nonce

    @property
    def ciphertext_xor(self) -> bytes:
        length = self.overlap
        return xor_bytes(
            self.known_message.ciphertext[:length],
            self.target_message.ciphertext[:length],
        )

    @property
    def plaintext_xor(self) -> bytes:
        length = self.overlap
        return xor_bytes(self.known_plaintext[:length], self.target_plaintext[:length])

    @property
    def xor_matches(self) -> bool:
        return self.ciphertext_xor == self.plaintext_xor

    @property
    def prefix_recovered(self) -> bool:
        return self.recovered_plaintext == self.target_plaintext[: self.overlap]

    @property
    def fully_recovered(self) -> bool:
        return self.recovered_plaintext == self.target_plaintext


@dataclass(frozen=True)
class AlgorithmResult:
    algorithm: Algorithm
    same_plaintext_control: RecoveryResult
    distinct_nonces: RecoveryResult
    reused_nonce: RecoveryResult
    partial_recovery: RecoveryResult
    tampering: dict[str, dict[str, bool]]

    def verify(self) -> None:
        """Fail the demonstration if an expected observation does not hold."""
        control = self.same_plaintext_control
        expected_changes = {"ciphertext", "tag", "aad", "key", "nonce", "truncation"}
        checks = {
            "round trips": all(
                case.round_trips_verified
                for case in (
                    control,
                    self.distinct_nonces,
                    self.reused_nonce,
                    self.partial_recovery,
                )
            ),
            "same-plaintext control": (
                not control.nonce_reused
                and control.known_message.ciphertext != control.target_message.ciphertext
            ),
            "distinct-nonce control": (
                not self.distinct_nonces.nonce_reused
                and not self.distinct_nonces.xor_matches
                and not self.distinct_nonces.prefix_recovered
            ),
            "full recovery": (
                self.reused_nonce.nonce_reused
                and self.reused_nonce.xor_matches
                and self.reused_nonce.fully_recovered
            ),
            "partial recovery": (
                self.partial_recovery.nonce_reused
                and self.partial_recovery.xor_matches
                and self.partial_recovery.prefix_recovered
                and not self.partial_recovery.fully_recovered
            ),
            "tampering rejection": (
                set(self.tampering) == {"distinct_nonces", "reused_nonce"}
                and all(
                    set(context) == expected_changes and all(context.values())
                    for context in self.tampering.values()
                )
            ),
        }
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            raise RuntimeError(f"{self.algorithm}: failed observations: {', '.join(failed)}")


def _recover_pair(
    cipher: Cipher,
    plaintexts: tuple[bytes, bytes],
    nonces: tuple[bytes, bytes],
) -> RecoveryResult:
    known_plaintext, target_plaintext = plaintexts
    known_nonce, target_nonce = nonces
    known_message = EncryptedMessage.from_combined(
        known_nonce, cipher.encrypt(known_nonce, known_plaintext, DEMO_AAD)
    )
    target_message = EncryptedMessage.from_combined(
        target_nonce, cipher.encrypt(target_nonce, target_plaintext, DEMO_AAD)
    )
    # The recovery receives no key, nonce, tag, or target plaintext.
    recovered = recover_plaintext(
        known_plaintext, known_message.ciphertext, target_message.ciphertext
    )
    round_trips = (
        cipher.decrypt(known_nonce, known_message.combined, DEMO_AAD) == known_plaintext
        and cipher.decrypt(target_nonce, target_message.combined, DEMO_AAD) == target_plaintext
    )
    return RecoveryResult(
        known_plaintext, target_plaintext, known_message, target_message, recovered, round_trips
    )


def _flip_first(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


def _tampering_results(
    cipher: Cipher, wrong_key_cipher: Cipher, message: EncryptedMessage
) -> dict[str, bool]:
    attempts = {
        "ciphertext": (
            cipher,
            message.nonce,
            _flip_first(message.ciphertext) + message.tag,
            DEMO_AAD,
        ),
        "tag": (cipher, message.nonce, message.ciphertext + _flip_first(message.tag), DEMO_AAD),
        "aad": (cipher, message.nonce, message.combined, _flip_first(DEMO_AAD)),
        "key": (wrong_key_cipher, message.nonce, message.combined, DEMO_AAD),
        "nonce": (cipher, _flip_first(message.nonce), message.combined, DEMO_AAD),
        "truncation": (cipher, message.nonce, message.combined[:-1], DEMO_AAD),
    }
    rejected = {}
    for name, (attempt_cipher, nonce, data, aad) in attempts.items():
        try:
            attempt_cipher.decrypt(nonce, data, aad)
        except InvalidTag:
            rejected[name] = True
        else:
            rejected[name] = False
    return rejected


def run_demonstration(algorithm: Algorithm) -> AlgorithmResult:
    """Run independent fixture scenarios; nonce reuse is intentional here."""
    nonces = NonceCounter(start=1)
    nonce_a = nonces.next_nonce()
    nonce_b = nonces.next_nonce()
    partial_nonce = nonces.next_nonce()
    control_nonces = (nonces.next_nonce(), nonces.next_nonce())
    plaintexts = (KNOWN_PLAINTEXT, TARGET_PLAINTEXT)

    # Each scenario is a separate public-fixture transcript, not a nonce policy.
    control = _recover_pair(
        make_cipher(algorithm, DEMO_KEY),
        (KNOWN_PLAINTEXT, KNOWN_PLAINTEXT),
        control_nonces,
    )
    distinct = _recover_pair(make_cipher(algorithm, DEMO_KEY), plaintexts, (nonce_a, nonce_b))
    reused = _recover_pair(make_cipher(algorithm, DEMO_KEY), plaintexts, (nonce_a, nonce_a))
    partial = _recover_pair(
        make_cipher(algorithm, DEMO_KEY),
        (KNOWN_PLAINTEXT[:16], LONG_TARGET),
        (partial_nonce, partial_nonce),
    )
    cipher = make_cipher(algorithm, DEMO_KEY)
    wrong_key_cipher = make_cipher(algorithm, _flip_first(DEMO_KEY))
    result = AlgorithmResult(
        algorithm,
        control,
        distinct,
        reused,
        partial,
        tampering={
            "distinct_nonces": _tampering_results(
                cipher, wrong_key_cipher, distinct.target_message
            ),
            "reused_nonce": _tampering_results(cipher, wrong_key_cipher, reused.target_message),
        },
    )
    result.verify()
    return result


def run_demonstrations() -> tuple[AlgorithmResult, ...]:
    return tuple(run_demonstration(algorithm) for algorithm in Algorithm)
