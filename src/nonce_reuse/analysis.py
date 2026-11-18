"""Summarize measured batches and regenerate tables and figures."""

import csv
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median, quantiles

from nonce_reuse.benchmark import Case, Sample
from nonce_reuse.benchmark_data import load_benchmark


def mib_per_second(message_bytes: int, nanoseconds: float) -> float:
    return message_bytes * 1e9 / (nanoseconds * 2**20)


@dataclass(frozen=True)
class Summary:
    case: Case
    batches: int
    operations_per_batch: int
    median_ns: float
    q1_ns: float
    q3_ns: float
    min_batch_ns: int
    max_batch_ns: int

    @property
    def throughput(self) -> float:
        return mib_per_second(self.case.message_bytes, self.median_ns)

    @property
    def throughput_low(self) -> float:
        return mib_per_second(self.case.message_bytes, self.q3_ns)

    @property
    def throughput_high(self) -> float:
        return mib_per_second(self.case.message_bytes, self.q1_ns)

    def to_row(self) -> dict:
        values = asdict(self)
        values.pop("case")
        return {**asdict(self.case), **values, "throughput_mib_s": self.throughput}


def summarize(samples: list[Sample]) -> list[Summary]:
    groups: dict[Case, list[Sample]] = defaultdict(list)
    for sample in samples:
        if sample.phase == "measurement":
            groups[sample.case].append(sample)
    if not groups:
        raise ValueError("There are no measured batches to summarize.")
    summaries = []
    for case, rows in groups.items():
        if len(rows) < 2:
            raise ValueError("At least two measured batches are required for quartiles.")
        if any(row.operations <= 0 or row.elapsed_ns <= 0 for row in rows):
            raise ValueError("Operation counts and batch durations must be positive.")
        if any(row.operations != rows[0].operations for row in rows):
            raise ValueError("Operation counts must stay fixed after calibration.")
        latencies = [row.elapsed_ns / row.operations for row in rows]
        q1, _, q3 = quantiles(latencies, n=4, method="inclusive")
        summaries.append(
            Summary(
                case,
                len(rows),
                rows[0].operations,
                median(latencies),
                q1,
                q3,
                min(row.elapsed_ns for row in rows),
                max(row.elapsed_ns for row in rows),
            )
        )
    return summaries


def size_label(size: int) -> str:
    if size >= 2**20 and size % 2**20 == 0:
        return f"{size // 2**20} MiB"
    if size >= 1024 and size % 1024 == 0:
        return f"{size // 1024} KiB"
    return f"{size} B"


def write_tables(summaries: list[Summary], output_dir: Path) -> Path:
    if not summaries:
        raise ValueError("There are no benchmark summaries to write.")
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [summary.to_row() for summary in summaries]
    with (output_dir / "benchmarks.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# AEAD benchmark results",
        "",
        "Median of batch-mean API latencies; IQR bounds are Q1 and Q3 across batches.",
        "Throughput uses plaintext bytes and the median latency. No samples were removed.",
        "",
        "| Algorithm | Operation | Plaintext | Median (us/op) | Q1–Q3 (us/op) | MiB/s | Batches |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            f"| {summary.case.algorithm.value} | {summary.case.operation.value} "
            f"| {size_label(summary.case.message_bytes)} | {summary.median_ns / 1000:.3f} "
            f"| {summary.q1_ns / 1000:.3f}–{summary.q3_ns / 1000:.3f} "
            f"| {summary.throughput:.2f} | {summary.batches} |"
        )
    path = output_dir / "benchmarks.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def analyze_benchmark(raw_dir: Path, output_dir: Path) -> list[Summary]:
    from nonce_reuse.plots import write_figures

    if (output_dir / "tables/benchmarks.csv").resolve() == (raw_dir / "benchmarks.csv").resolve():
        raise ValueError("The analysis output would overwrite the raw benchmark CSV.")
    samples, metadata = load_benchmark(raw_dir)
    summaries = summarize(samples)
    write_tables(summaries, output_dir / "tables")
    write_figures(summaries, metadata, output_dir / "figures")
    return summaries
