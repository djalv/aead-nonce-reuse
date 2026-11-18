import pytest

from nonce_reuse.aead import Cipher
from nonce_reuse.nonces import NonceCounter


def test_allocated_nonces_are_fixed_width_and_unique() -> None:
    counter = NonceCounter()

    nonces = [counter.next_nonce() for _ in range(1024)]

    assert all(len(nonce) == 12 for nonce in nonces)
    assert len(set(nonces)) == 1024
    assert [int.from_bytes(nonce, "big") for nonce in nonces] == list(range(1024))


def test_one_counter_continues_across_allocation_batches() -> None:
    counter = NonceCounter()

    preparation = [counter.next_nonce() for _ in range(4)]
    execution = [counter.next_nonce() for _ in range(4)]

    assert set(preparation).isdisjoint(execution)
    assert int.from_bytes(execution[0], "big") == 4


@pytest.mark.parametrize("start", [255, 65535])
def test_counter_carries_across_byte_boundaries(start: int) -> None:
    counter = NonceCounter(start=start)

    first, second = counter.next_nonce(), counter.next_nonce()

    assert int.from_bytes(first, "big") == start
    assert int.from_bytes(second, "big") == start + 1
    assert first != second


def test_exhaustion_never_wraps_or_emits_another_nonce() -> None:
    counter = NonceCounter(start=(1 << 96) - 1)

    assert counter.next_nonce() == b"\xff" * 12
    for _ in range(2):
        with pytest.raises(OverflowError, match="exhausted"):
            counter.next_nonce()


def test_last_two_nonces_are_available_once_each() -> None:
    counter = NonceCounter(start=(1 << 96) - 2)

    assert counter.next_nonce() == b"\xff" * 11 + b"\xfe"
    assert counter.next_nonce() == b"\xff" * 12
    with pytest.raises(OverflowError):
        counter.next_nonce()


@pytest.mark.parametrize("start", [-1, 1 << 96])
def test_counter_rejects_initial_values_outside_nonce_space(start: int) -> None:
    with pytest.raises(ValueError, match="96 bits"):
        NonceCounter(start=start)


@pytest.mark.parametrize("start", [-0.5, None, True, "0"])
def test_counter_rejects_noninteger_initial_values(start) -> None:
    with pytest.raises(TypeError, match="integer"):
        NonceCounter(start=start)


def test_sequential_nonces_work_with_both_aead_algorithms(cipher: Cipher) -> None:
    counter = NonceCounter()
    plaintext, aad = b"nonce allocation integration check", b"metadata"
    allocated = set()
    for _ in range(16):
        nonce = counter.next_nonce()
        assert nonce not in allocated
        allocated.add(nonce)
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        assert cipher.decrypt(nonce, ciphertext, aad) == plaintext
