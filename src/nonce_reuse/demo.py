"""Text and JSON views of the observed demonstration results."""

from importlib.metadata import version

from nonce_reuse.aead import EncryptedMessage
from nonce_reuse.experiments import AlgorithmResult, RecoveryResult

FIXTURE_NOTICE = (
    "All keys, nonces, plaintexts, and AAD are public demonstration fixtures. "
    "The recovery function receives only the known plaintext and two ciphertexts. "
    "Target plaintexts in this report are evaluation data. "
    "Fixed inputs are for reproduction, not operational encryption."
)


def _message_data(message: EncryptedMessage) -> dict[str, str]:
    return {
        "nonce_hex": message.nonce.hex(),
        "ciphertext_hex": message.ciphertext.hex(),
        "tag_hex": message.tag.hex(),
    }


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="backslashreplace")


def _recovery_data(result: RecoveryResult) -> dict[str, object]:
    return {
        "known_plaintext_hex": result.known_plaintext.hex(),
        "known_plaintext_text": _text(result.known_plaintext),
        "target_plaintext_hex": result.target_plaintext.hex(),
        "target_plaintext_text": _text(result.target_plaintext),
        "known_message": _message_data(result.known_message),
        "target_message": _message_data(result.target_message),
        "recovered_hex": result.recovered_plaintext.hex(),
        "recovered_text": _text(result.recovered_plaintext),
        "ciphertext_xor_hex": result.ciphertext_xor.hex(),
        "plaintext_xor_hex": result.plaintext_xor.hex(),
        "recovered_bytes": len(result.recovered_plaintext),
        "target_bytes": len(result.target_plaintext),
        "round_trips_verified": result.round_trips_verified,
        "nonce_reused": result.nonce_reused,
        "xor_matches": result.xor_matches,
        "prefix_recovered": result.prefix_recovered,
        "fully_recovered": result.fully_recovered,
    }


def demonstration_data(results: tuple[AlgorithmResult, ...]) -> dict[str, object]:
    return {
        "fixture_notice": FIXTURE_NOTICE,
        "cryptography_version": version("cryptography"),
        "algorithms": [
            {
                "algorithm": result.algorithm.value,
                "same_plaintext_control": _recovery_data(result.same_plaintext_control),
                "distinct_nonces": _recovery_data(result.distinct_nonces),
                "reused_nonce": _recovery_data(result.reused_nonce),
                "partial_recovery": _recovery_data(result.partial_recovery),
                "tampering_rejected": result.tampering,
            }
            for result in results
        ],
    }


def render_demonstrations(results: tuple[AlgorithmResult, ...]) -> str:
    lines = [
        "Nonce reuse demonstrations",
        "",
        "Keys, nonces and messages are public demonstration fixtures.",
    ]
    for result in results:
        distinct, reused, partial = (
            result.distinct_nonces,
            result.reused_nonce,
            result.partial_recovery,
        )
        rows = (
            ("Nonces are equal", distinct.nonce_reused, reused.nonce_reused),
            ("Ciphertext XOR equals plaintext XOR", distinct.xor_matches, reused.xor_matches),
            (
                "Full known-plaintext recovery succeeds",
                distinct.fully_recovered,
                reused.fully_recovered,
            ),
            (
                "Both round trips succeed",
                distinct.round_trips_verified,
                reused.round_trips_verified,
            ),
        )
        lines.extend(
            ["", result.algorithm.value, f"{'Observation':<43} {'Distinct':>10} {'Reused':>10}"]
        )
        for name, distinct_value, reused_value in rows:
            lines.append(
                f"{name:<43} {'yes' if distinct_value else 'no':>10} "
                f"{'yes' if reused_value else 'no':>10}"
            )
        control = result.same_plaintext_control
        different = control.known_message.ciphertext != control.target_message.ciphertext
        lines.extend(
            [
                f"Same plaintext, distinct nonces: ciphertexts differ = {'yes' if different else 'no'}",
                "",
                f"Known plaintext:  {_text(reused.known_plaintext)}",
                f"Target plaintext: {_text(reused.target_plaintext)}",
                "Ciphertexts below exclude authentication tags:",
                f"  C1:              {reused.known_message.ciphertext.hex()}",
                f"  C2 (distinct):   {distinct.target_message.ciphertext.hex()}",
                f"  C2 (reused):     {reused.target_message.ciphertext.hex()}",
                f"Ciphertext XOR (reused): {reused.ciphertext_xor.hex()}",
                f"Plaintext XOR:           {reused.plaintext_xor.hex()}",
                f"Recovered (reused): {_text(reused.recovered_plaintext)}",
                f"Partial recovery: {len(partial.recovered_plaintext)}/{len(partial.target_plaintext)} bytes",
                f"Recovered prefix: {_text(partial.recovered_plaintext)!r}",
            ]
        )
        for context, rejected in result.tampering.items():
            names = ", ".join(name for name, passed in rejected.items() if passed)
            lines.append(f"Rejected changes ({context}): {names}")
    lines.extend(
        [
            "",
            "Recovery uses only the known plaintext and two ciphertext bodies, without recovering the key.",
            "Distinct nonces prevented recovery in these cases.",
            "Tampering rejection does not prove resistance to tag forgery after nonce reuse.",
        ]
    )
    return "\n".join(lines)
