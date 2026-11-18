import csv

import pytest

from nonce_reuse.aead import Algorithm
from nonce_reuse.analysis import summarize, write_tables
from nonce_reuse.benchmark import Case, Operation, Sample


def test_summary_uses_batch_means_and_excludes_warmup(tmp_path) -> None:
    case = Case(Algorithm.AES_GCM, Operation.ENCRYPT, 1024)
    samples = [
        Sample(case, "warmup", 0, 1, 9_000_000_000, 0, 1),
        Sample(case, "measurement", 0, 100, 100_000_000, 1, 101),
        Sample(case, "measurement", 1, 100, 300_000_000, 101, 201),
    ]

    (summary,) = summarize(samples)

    assert summary.batches == 2
    assert summary.median_ns == 2_000_000
    assert summary.q1_ns == 1_500_000
    assert summary.q3_ns == 2_500_000
    assert summary.throughput == pytest.approx(0.48828125)
    assert summary.throughput_low == pytest.approx(0.390625)
    assert summary.throughput_high == pytest.approx(0.6510416666666666)
    write_tables([summary], tmp_path)
    with (tmp_path / "benchmarks.csv").open() as handle:
        (row,) = list(csv.DictReader(handle))
    assert float(row["median_ns"]) == 2_000_000
    assert float(row["throughput_mib_s"]) == pytest.approx(0.48828125)
    assert "2000.000" in (tmp_path / "benchmarks.md").read_text()


@pytest.mark.parametrize("count", [0, 1])
def test_summary_requires_enough_measured_batches(count: int) -> None:
    case = Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64)
    samples = [Sample(case, "measurement", 0, 1, 1000, 0, 1)] * count
    with pytest.raises(ValueError):
        summarize(samples)


@pytest.mark.parametrize("operations,elapsed", [(0, 1000), (-1, 1000), (1, 0), (1, -1)])
def test_summary_rejects_invalid_batch_arithmetic(operations, elapsed):
    case = Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64)
    samples = [Sample(case, "measurement", index, operations, elapsed, 0, 1) for index in range(2)]
    with pytest.raises(ValueError, match="positive"):
        summarize(samples)


def test_summary_rejects_a_changing_calibrated_count():
    case = Case(Algorithm.AES_GCM, Operation.ENCRYPT, 64)
    samples = [
        Sample(case, "measurement", 0, 1, 1000, 0, 1),
        Sample(case, "measurement", 1, 2, 2000, 1, 3),
    ]
    with pytest.raises(ValueError, match="fixed"):
        summarize(samples)


def test_empty_table_input_does_not_create_partial_files(tmp_path):
    output = tmp_path / "tables"
    with pytest.raises(ValueError, match="no benchmark summaries"):
        write_tables([], output)
    assert not output.exists()
