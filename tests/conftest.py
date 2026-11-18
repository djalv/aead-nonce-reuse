from itertools import count

import pytest

from nonce_reuse.aead import Algorithm, Cipher, make_cipher


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--reverse-order", action="store_true", help="Run collected tests in reverse order."
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--reverse-order"):
        items.reverse()


@pytest.fixture(params=tuple(Algorithm), ids=lambda algorithm: algorithm.value)
def algorithm(request: pytest.FixtureRequest) -> Algorithm:
    return request.param


@pytest.fixture
def key() -> bytes:
    return bytes(range(32))


@pytest.fixture
def cipher(algorithm: Algorithm, key: bytes) -> Cipher:
    return make_cipher(algorithm, key)


@pytest.fixture
def quick_run(monkeypatch):
    from nonce_reuse import benchmark

    ticks = count(0, 1000)
    monkeypatch.setattr(benchmark.time, "perf_counter_ns", lambda: next(ticks))
    config = benchmark.BenchmarkConfig(
        sizes=(16,), samples=3, target_ns=100, warmup_batches=1, max_operations=2
    )
    samples, metadata = benchmark.run_benchmarks(config)
    return config, samples, metadata
