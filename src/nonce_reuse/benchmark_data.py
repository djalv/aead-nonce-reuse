"""Store and validate batch observations before deriving statistics."""

import csv
import io
import json
from collections import defaultdict
from dataclasses import asdict, fields
from hashlib import sha256
from pathlib import Path

from nonce_reuse.aead import Algorithm
from nonce_reuse.benchmark import BenchmarkConfig, Case, Operation, Sample
from nonce_reuse.nonces import NONCE_LIMIT

RAW_FIELDS = (
    "algorithm",
    "operation",
    "message_bytes",
    "phase",
    "batch_index",
    "operations",
    "elapsed_ns",
    "nonce_start",
    "nonce_stop",
)


def _read_config(metadata: dict) -> BenchmarkConfig:
    try:
        values = metadata["config"]
        if not isinstance(values, dict) or set(values) != {
            field.name for field in fields(BenchmarkConfig)
        }:
            raise ValueError("The benchmark configuration is incomplete or has unknown fields.")
        if not isinstance(values["sizes"], (list, tuple)):
            raise ValueError("Message sizes must be a list of integers.")
        return BenchmarkConfig(**{**values, "sizes": tuple(values["sizes"])})
    except (KeyError, TypeError) as error:
        raise ValueError("Invalid benchmark configuration.") from error


def _validate_environment(metadata: dict) -> None:
    environment = metadata.get("environment")
    if not isinstance(environment, dict) or not isinstance(environment.get("python"), str):
        raise ValueError("Environment metadata must include the Python version.")
    cpu = environment.get("cpu", {})
    if not isinstance(cpu, dict) or ("model" in cpu and not isinstance(cpu["model"], str)):
        raise ValueError("Invalid CPU metadata.")


def _validate_case(case: Case, rows: list[Sample], config: BenchmarkConfig) -> None:
    stop = 0
    for row in rows:
        if (
            not 1 <= row.operations <= config.operation_cap(case.message_bytes)
            or row.elapsed_ns <= 0
        ):
            raise ValueError("Invalid operation count or batch duration.")
        if row.nonce_start != stop or row.nonce_stop != stop + row.operations:
            raise ValueError("Nonce intervals overlap, restart, or contain gaps.")
        stop = row.nonce_stop
        if stop > NONCE_LIMIT:
            raise ValueError("Nonce interval exceeds the counter space.")
    phases = {
        name: [row for row in rows if row.phase == name]
        for name in ("warmup", "calibration", "measurement")
    }
    if not phases["calibration"]:
        raise ValueError("Calibration observations are missing.")
    expected_phases = (
        ["warmup"]
        + ["calibration"] * len(phases["calibration"])
        + ["warmup"] * config.warmup_batches
        + ["measurement"] * config.samples
    )
    if [row.phase for row in rows] != expected_phases:
        raise ValueError("Batch phases or sample counts do not match the protocol.")
    for phase_rows in phases.values():
        if [row.batch_index for row in phase_rows] != list(range(len(phase_rows))):
            raise ValueError("Batch indices are missing or duplicated.")
    cap = config.operation_cap(case.message_bytes)
    if phases["warmup"][0].operations != min(16, cap):
        raise ValueError("The preliminary warm-up count does not match the protocol.")
    calibration = phases["calibration"]
    if calibration[0].operations != 1:
        raise ValueError("Calibration must start with one operation.")
    for previous, current in zip(calibration, calibration[1:]):
        if previous.elapsed_ns >= config.target_ns or previous.operations == cap:
            raise ValueError("Calibration continued after its stopping condition.")
        estimate = previous.operations * config.target_ns * 11 // (previous.elapsed_ns * 10)
        expected = min(cap, max(previous.operations + 1, estimate))
        if current.operations != expected:
            raise ValueError("Calibration counts do not follow the recorded protocol.")
    if calibration[-1].elapsed_ns < config.target_ns and calibration[-1].operations != cap:
        raise ValueError("Calibration stopped before reaching the target or operation cap.")
    calibrated = phases["calibration"][-1].operations
    if any(row.operations != calibrated for row in phases["measurement"] + phases["warmup"][1:]):
        raise ValueError("Operation counts changed after calibration.")


def validate_samples(samples: list[Sample], config: BenchmarkConfig) -> None:
    grouped: dict[Case, list[Sample]] = defaultdict(list)
    measuring = False
    for sample in samples:
        integers = (
            sample.batch_index,
            sample.operations,
            sample.elapsed_ns,
            sample.nonce_start,
            sample.nonce_stop,
        )
        if any(type(value) is not int for value in integers):
            raise ValueError("Batch indices, counts, durations, and nonce bounds must be integers.")
        if measuring and sample.phase != "measurement":
            raise ValueError("All setup batches must precede measurement rounds.")
        if sample.phase == "measurement":
            measuring = True
        grouped[sample.case].append(sample)
    if set(grouped) != set(config.cases):
        raise ValueError("The observations do not cover the configured benchmark matrix.")
    for case, rows in grouped.items():
        _validate_case(case, rows, config)
    expected_order = [
        case
        for index in range(config.samples)
        for case in (config.cases if index % 2 == 0 else tuple(reversed(config.cases)))
    ]
    if [row.case for row in samples if row.phase == "measurement"] != expected_order:
        raise ValueError("The measurement schedule does not match alternating rounds.")


def ensure_new_run(raw_dir: Path) -> None:
    for name in ("benchmarks.csv", "benchmark-environment.json"):
        path = raw_dir / name
        if path.exists() or path.is_symlink():
            raise FileExistsError("Benchmark data already exists; choose a new output directory.")


def save_benchmark(samples: list[Sample], metadata: dict, raw_dir: Path) -> None:
    config = _read_config(metadata)
    _validate_environment(metadata)
    validate_samples(samples, config)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=RAW_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(sample.to_row() for sample in samples)
    payload = buffer.getvalue().encode("utf-8")
    last_calibration = {row.case: row for row in samples if row.phase == "calibration"}
    calibration = []
    for case in config.cases:
        row = last_calibration[case]
        calibration.append(
            {
                **asdict(case),
                "operations": row.operations,
                "operation_cap": config.operation_cap(case.message_bytes),
                "target_reached": row.elapsed_ns >= config.target_ns,
            }
        )
    manifest = {
        **metadata,
        "samples_sha256": sha256(payload).hexdigest(),
        "calibration": calibration,
    }
    try:
        manifest_text = json.dumps(manifest, indent=2, allow_nan=False) + "\n"
    except (TypeError, ValueError) as error:
        raise ValueError("Benchmark metadata is not valid JSON data.") from error
    ensure_new_run(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        for name, data in (
            ("benchmarks.csv", payload),
            ("benchmark-environment.json", manifest_text.encode("utf-8")),
        ):
            path = raw_dir / name
            with path.open("xb") as handle:
                created.append(path)
                handle.write(data)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def load_benchmark(raw_dir: Path) -> tuple[list[Sample], dict]:
    metadata = json.loads((raw_dir / "benchmark-environment.json").read_text(encoding="utf-8"))
    payload = (raw_dir / "benchmarks.csv").read_bytes()
    if not isinstance(metadata, dict) or metadata.get("format_version") != 1:
        raise ValueError("Unsupported benchmark data format.")
    if sha256(payload).hexdigest() != metadata.get("samples_sha256"):
        raise ValueError("The batch CSV does not match its metadata SHA-256.")
    try:
        config = _read_config(metadata)
        _validate_environment(metadata)
        reader = csv.DictReader(io.StringIO(payload.decode("utf-8")))
        if tuple(reader.fieldnames or ()) != RAW_FIELDS:
            raise ValueError("The batch CSV columns do not match the data format.")
        raw_rows = list(reader)
        if any(None in row or any(value is None for value in row.values()) for row in raw_rows):
            raise ValueError("A batch CSV row has missing or extra values.")
        samples = [
            Sample(
                case=Case(
                    Algorithm(row["algorithm"]),
                    Operation(row["operation"]),
                    int(row["message_bytes"]),
                ),
                phase=row["phase"],
                batch_index=int(row["batch_index"]),
                operations=int(row["operations"]),
                elapsed_ns=int(row["elapsed_ns"]),
                nonce_start=int(row["nonce_start"]),
                nonce_stop=int(row["nonce_stop"]),
            )
            for row in raw_rows
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid benchmark data: {error}") from error
    validate_samples(samples, config)
    return samples, metadata
