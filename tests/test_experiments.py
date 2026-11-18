from dataclasses import replace

import pytest

from nonce_reuse.aead import Algorithm
from nonce_reuse.experiments import AlgorithmResult, run_demonstration


@pytest.fixture
def result(algorithm: Algorithm) -> AlgorithmResult:
    return run_demonstration(algorithm)


def test_distinct_nonces_prevent_this_fixtures_recovery(result: AlgorithmResult) -> None:
    same = result.same_plaintext_control
    assert same.known_plaintext == same.target_plaintext
    assert same.known_message.nonce != same.target_message.nonce
    assert same.known_message.ciphertext != same.target_message.ciphertext
    distinct = result.distinct_nonces
    assert distinct.known_message.nonce != distinct.target_message.nonce
    assert distinct.recovered_plaintext != distinct.target_plaintext
    assert not distinct.xor_matches
    assert same.round_trips_verified and distinct.round_trips_verified


def test_nonce_reuse_reveals_xor_and_recovers_the_target(result: AlgorithmResult) -> None:
    reused = result.reused_nonce
    assert reused.known_message.nonce == reused.target_message.nonce
    ciphertext_xor = bytes(
        a ^ b
        for a, b in zip(
            reused.known_message.ciphertext, reused.target_message.ciphertext, strict=True
        )
    )
    plaintext_xor = bytes(
        a ^ b for a, b in zip(reused.known_plaintext, reused.target_plaintext, strict=True)
    )
    assert ciphertext_xor == plaintext_xor
    assert reused.recovered_plaintext == reused.target_plaintext
    assert reused.round_trips_verified


def test_partial_recovery_stops_at_the_shorter_known_message(result: AlgorithmResult) -> None:
    partial = result.partial_recovery
    assert len(partial.known_plaintext) == 16
    assert len(partial.target_plaintext) == 54
    assert partial.recovered_plaintext == partial.target_plaintext[:16]
    assert partial.recovered_plaintext != partial.target_plaintext
    assert partial.xor_matches and partial.round_trips_verified
    assert partial.known_message.nonce != result.reused_nonce.known_message.nonce


def test_all_tampering_cases_are_observed_in_both_contexts(result: AlgorithmResult) -> None:
    assert set(result.tampering) == {"distinct_nonces", "reused_nonce"}
    for rejected in result.tampering.values():
        assert set(rejected) == {"ciphertext", "tag", "aad", "key", "nonce", "truncation"}
        assert all(rejected.values())


def test_failed_recovery_cannot_be_reported_as_a_success(result: AlgorithmResult) -> None:
    invalid = replace(result, reused_nonce=result.distinct_nonces)
    with pytest.raises(RuntimeError, match="full recovery"):
        invalid.verify()


def test_accepted_tampering_cannot_be_reported_as_a_success(result: AlgorithmResult) -> None:
    tampering = {name: values.copy() for name, values in result.tampering.items()}
    tampering["reused_nonce"]["tag"] = False
    invalid = replace(result, tampering=tampering)
    with pytest.raises(RuntimeError, match="tampering rejection"):
        invalid.verify()


@pytest.mark.parametrize("omission", ["all", "context", "change"])
def test_missing_tampering_observations_cannot_pass_verification(
    result: AlgorithmResult, omission: str
) -> None:
    tampering = {name: values.copy() for name, values in result.tampering.items()}
    if omission == "all":
        tampering.clear()
    elif omission == "context":
        tampering.pop("reused_nonce")
    else:
        tampering["reused_nonce"].pop("tag")

    with pytest.raises(RuntimeError, match="tampering rejection"):
        replace(result, tampering=tampering).verify()
