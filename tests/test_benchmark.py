from itertools import count

import pytest

from nonce_reuse import benchmark
from nonce_reuse.aead import Algorithm, make_cipher
from nonce_reuse.benchmark import BenchmarkConfig, BenchmarkSession, Case, Operation, run_benchmarks
from nonce_reuse.nonces import NonceCounter


@pytest.mark.parametrize("operation", tuple(Operation))
def test_setup_and_validation_are_outside_the_timer(algorithm, operation, monkeypatch) -> None:
    events = []
    native_next = NonceCounter.next_nonce

    def allocate(counter):
        events.append("nonce")
        return native_next(counter)

    def observed_cipher(selected, key):
        cipher = make_cipher(selected, key)

        class ObservedCipher:
            def encrypt(self, nonce, data, aad):
                events.append("encrypt")
                return cipher.encrypt(nonce, data, aad)

            def decrypt(self, nonce, data, aad):
                events.append("decrypt")
                return cipher.decrypt(nonce, data, aad)

        return ObservedCipher()

    ticks = iter([100, 1100])

    def clock():
        events.append("clock")
        return next(ticks)

    monkeypatch.setattr(NonceCounter, "next_nonce", allocate)
    monkeypatch.setattr(benchmark, "make_cipher", observed_cipher)
    monkeypatch.setattr(benchmark.time, "perf_counter_ns", clock)
    config = BenchmarkConfig(sizes=(64,), max_operations=2)
    session = BenchmarkSession(Case(algorithm, operation, 64), config)

    sample = session.measure(2, phase="measurement", batch_index=0)

    if operation == Operation.ENCRYPT:
        assert events == [
            "nonce",
            "nonce",
            "clock",
            "encrypt",
            "encrypt",
            "clock",
            "decrypt",
            "decrypt",
        ]
    else:
        assert events == [
            "nonce",
            "encrypt",
            "nonce",
            "encrypt",
            "clock",
            "decrypt",
            "decrypt",
            "clock",
        ]
    assert sample.elapsed_ns == 1000
    assert (sample.nonce_start, sample.nonce_stop) == (0, 2)


def test_no_encryption_reuses_a_key_nonce_pair_across_any_phase(monkeypatch) -> None:
    encrypted = set()
    keys = []
    public_keys = (index.to_bytes(32, "big") for index in range(4))
    monkeypatch.setattr(benchmark, "token_bytes", lambda size: next(public_keys))

    def observed_cipher(algorithm, key):
        keys.append(key)
        cipher = make_cipher(algorithm, key)

        class ObservedCipher:
            def encrypt(self, nonce, data, aad):
                assert (key, nonce) not in encrypted
                encrypted.add((key, nonce))
                return cipher.encrypt(nonce, data, aad)

            def decrypt(self, nonce, data, aad):
                return cipher.decrypt(nonce, data, aad)

        return ObservedCipher()

    ticks = count(0, 1000)
    monkeypatch.setattr(benchmark, "make_cipher", observed_cipher)
    monkeypatch.setattr(benchmark.time, "perf_counter_ns", lambda: next(ticks))
    config = BenchmarkConfig(
        sizes=(16,), samples=3, target_ns=100, warmup_batches=1, max_operations=2
    )

    samples, _ = run_benchmarks(config)

    assert len(keys) == len(set(keys)) == 4
    assert len(encrypted) == sum(sample.operations for sample in samples)
    assert {sample.phase for sample in samples} == {"warmup", "calibration", "measurement"}
    assert {sample.case.operation for sample in samples} == set(Operation)
    assert {sample.case.algorithm for sample in samples} == set(Algorithm)


def test_measured_case_order_alternates_each_round(quick_run) -> None:
    _, samples, _ = quick_run
    rounds = [
        [row.case for row in samples if row.phase == "measurement" and row.batch_index == index]
        for index in range(3)
    ]
    assert len(set(rounds[0])) == 4
    assert rounds[1] == list(reversed(rounds[0]))
    assert rounds[2] == rounds[0]


def test_calibration_stops_at_the_memory_cap(monkeypatch) -> None:
    ticks = count(0, 1000)
    monkeypatch.setattr(benchmark.time, "perf_counter_ns", lambda: next(ticks))
    config = BenchmarkConfig(
        sizes=(64,),
        samples=2,
        target_ns=10000,
        warmup_batches=1,
        max_operations=100,
        payload_budget_bytes=2 * (64 + 16) * 3,
    )

    samples, _ = run_benchmarks(config)

    assert max(sample.operations for sample in samples) == 3
    assert all(row.operations == 3 for row in samples if row.phase == "measurement")


@pytest.mark.parametrize(
    "settings",
    [
        {"samples": 1},
        {"target_ns": 0},
        {"warmup_batches": 0},
        {"max_operations": 0},
        {"sizes": ()},
        {"sizes": (64, 64)},
        {"sizes": (0,)},
        {"payload_budget_bytes": 1},
    ],
)
def test_invalid_benchmark_configuration_fails_before_running(settings) -> None:
    with pytest.raises(ValueError):
        BenchmarkConfig(**settings)


def test_clock_must_advance(monkeypatch) -> None:
    monkeypatch.setattr(benchmark.time, "perf_counter_ns", lambda: 100)
    config = BenchmarkConfig(sizes=(64,))
    session = BenchmarkSession(Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64), config)
    with pytest.raises(RuntimeError, match="clock did not advance"):
        session.measure(1, phase="measurement", batch_index=0)


def test_incorrect_output_aborts_measurement(monkeypatch) -> None:
    cipher = make_cipher(Algorithm.AES_GCM, bytes(32))

    class IncorrectDecryption:
        encrypt = cipher.encrypt

        def decrypt(self, nonce, data, aad):
            return b"incorrect plaintext"

    monkeypatch.setattr(benchmark, "make_cipher", lambda algorithm, key: IncorrectDecryption())
    config = BenchmarkConfig(sizes=(64,))
    session = BenchmarkSession(Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64), config)
    with pytest.raises(RuntimeError, match="differs from the original"):
        session.measure(1, phase="measurement", batch_index=0)


@pytest.mark.parametrize("operations", [-1, 0, 3])
def test_measurement_rejects_batches_outside_its_cap(operations) -> None:
    config = BenchmarkConfig(sizes=(64,), max_operations=2)
    session = BenchmarkSession(Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64), config)
    with pytest.raises(ValueError, match="outside the configured cap"):
        session.measure(operations, phase="measurement", batch_index=0)
