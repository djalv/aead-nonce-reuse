"""Nonce allocation for sequential, in-memory experiment runs."""

from nonce_reuse.aead import NONCE_SIZE

NONCE_LIMIT = 1 << (8 * NONCE_SIZE)


class NonceCounter:
    """Allocate distinct 96-bit nonces until the counter is exhausted.

    Keep one counter for the lifetime of a key in a single-writer run. A new
    run must use a fresh key. This class does not persist state or coordinate
    threads, processes, or independent senders sharing a key.
    """

    def __init__(self, *, start: int = 0) -> None:
        if type(start) is not int:
            raise TypeError("The initial counter value must be an integer.")
        if not 0 <= start < NONCE_LIMIT:
            raise ValueError("The initial counter value must fit in 96 bits.")
        self._next_value = start

    def next_nonce(self) -> bytes:
        if self._next_value >= NONCE_LIMIT:
            raise OverflowError("Nonce counter exhausted; use a fresh key for a new counter.")
        nonce = self._next_value.to_bytes(NONCE_SIZE, "big")
        self._next_value += 1
        return nonce
