"""Batch measurements of the AEAD APIs, with setup and validation untimed."""

import gc
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from secrets import token_bytes
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend

from nonce_reuse.aead import KEY_SIZE, TAG_SIZE, Algorithm, make_cipher
from nonce_reuse.nonces import NonceCounter

MESSAGE_SIZES = (64, 4096, 1048576)
BENCHMARK_AAD = b"nonce-reuse-study:benchmark"


class Operation(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


@dataclass(frozen=True)
class Case:
    algorithm: Algorithm
    operation: Operation
    message_bytes: int


@dataclass(frozen=True)
class BenchmarkConfig:
    sizes: tuple[int, ...] = MESSAGE_SIZES
    samples: int = 30
    target_ns: int = 20_000_000
    warmup_batches: int = 3
    max_operations: int = 65536
    payload_budget_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.sizes, tuple) or not self.sizes:
            raise ValueError("Message sizes must be a nonempty tuple.")
        if any(type(size) is not int or size <= 0 for size in self.sizes):
            raise ValueError("Message sizes must be positive integers.")
        if len(set(self.sizes)) != len(self.sizes):
            raise ValueError("Message sizes must be distinct.")
        integer_settings = (
            self.samples,
            self.target_ns,
            self.warmup_batches,
            self.max_operations,
            self.payload_budget_bytes,
        )
        if any(type(value) is not int for value in integer_settings):
            raise ValueError("Counts, durations, and budgets must be integers.")
        if self.samples < 2 or self.target_ns <= 0 or self.warmup_batches < 1:
            raise ValueError("Use at least two samples and positive timing/warm-up settings.")
        if self.max_operations < 1:
            raise ValueError("The operation cap must be positive.")
        if self.payload_budget_bytes < 2 * (max(self.sizes) + TAG_SIZE):
            raise ValueError("The payload budget cannot hold one operation of the largest size.")

    @property
    def cases(self) -> tuple[Case, ...]:
        return tuple(
            Case(algorithm, operation, size)
            for size in self.sizes
            for operation in Operation
            for algorithm in Algorithm
        )

    def operation_cap(self, message_bytes: int) -> int:
        return min(
            self.max_operations, self.payload_budget_bytes // (2 * (message_bytes + TAG_SIZE))
        )


@dataclass(frozen=True)
class Sample:
    case: Case
    phase: str
    batch_index: int
    operations: int
    elapsed_ns: int
    nonce_start: int
    nonce_stop: int

    def to_row(self) -> dict:
        return {
            **asdict(self.case),
            "phase": self.phase,
            "batch_index": self.batch_index,
            "operations": self.operations,
            "elapsed_ns": self.elapsed_ns,
            "nonce_start": self.nonce_start,
            "nonce_stop": self.nonce_stop,
        }


class BenchmarkSession:
    """Own one key and nonce counter for a single benchmark configuration."""

    def __init__(self, case: Case, config: BenchmarkConfig) -> None:
        if case not in config.cases:
            raise ValueError("The benchmark case is not part of the configured matrix.")
        self.case = case
        self.max_operations = config.operation_cap(case.message_bytes)
        self._cipher = make_cipher(case.algorithm, token_bytes(KEY_SIZE))
        self._nonces = NonceCounter()
        pattern = bytes(range(256))
        self._plaintext = (pattern * ((case.message_bytes + 255) // 256))[: case.message_bytes]

    def measure(self, operations: int, *, phase: str, batch_index: int) -> Sample:
        if not 1 <= operations <= self.max_operations:
            raise ValueError("Batch operation count is outside the configured cap.")
        inputs = []
        for _ in range(operations):
            nonce = self._nonces.next_nonce()
            data = self._plaintext
            if self.case.operation == Operation.DECRYPT:
                data = self._cipher.encrypt(nonce, data, BENCHMARK_AAD)
            inputs.append((nonce, data))
        operation = (
            self._cipher.encrypt
            if self.case.operation == Operation.ENCRYPT
            else self._cipher.decrypt
        )
        outputs = [b""] * operations
        start = time.perf_counter_ns()
        for index, (nonce, data) in enumerate(inputs):
            outputs[index] = operation(nonce, data, BENCHMARK_AAD)
        elapsed = time.perf_counter_ns() - start
        if elapsed <= 0:
            raise RuntimeError("The benchmark clock did not advance.")
        for (nonce, _), output in zip(inputs, outputs, strict=True):
            try:
                plaintext = (
                    self._cipher.decrypt(nonce, output, BENCHMARK_AAD)
                    if self.case.operation == Operation.ENCRYPT
                    else output
                )
            except InvalidTag as error:
                raise RuntimeError("Benchmark output failed authentication.") from error
            if plaintext != self._plaintext:
                raise RuntimeError("Benchmark output differs from the original plaintext.")
        return Sample(
            self.case,
            phase,
            batch_index,
            operations,
            elapsed,
            int.from_bytes(inputs[0][0], "big"),
            int.from_bytes(inputs[-1][0], "big") + 1,
        )


def _calibrate(session: BenchmarkSession, config: BenchmarkConfig, rows: list[Sample]) -> int:
    count, batch = 1, 0
    while True:
        sample = session.measure(count, phase="calibration", batch_index=batch)
        rows.append(sample)
        if sample.elapsed_ns >= config.target_ns or count == session.max_operations:
            return count
        # Scale toward the target with 10% headroom; keep counts integral and bounded.
        estimate = count * config.target_ns * 11 // (sample.elapsed_ns * 10)
        count = min(session.max_operations, max(count + 1, estimate))
        batch += 1


def _environment() -> dict:
    import platform

    cpu = {}
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        fields = dict(
            line.split(":", 1)
            for line in cpuinfo.read_text().split("\n\n", 1)[0].splitlines()
            if ":" in line
        )
        fields = {key.strip(): value.strip() for key, value in fields.items()}
        flags = fields.get("flags", "").split()
        cpu = {
            "model": fields.get("model name", "unknown"),
            "features": {flag: flag in flags for flag in ("aes", "pclmulqdq", "avx2")},
        }
    for name in ("scaling_governor", "scaling_driver"):
        path = Path("/sys/devices/system/cpu/cpu0/cpufreq") / name
        if path.is_file():
            cpu[name] = path.read_text().strip()
    clock = time.get_clock_info("perf_counter")
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "dependencies": {name: version(name) for name in ("cryptography", "matplotlib", "numpy")},
        "openssl": default_backend().openssl_version_text(),
        "gc_enabled": gc.isenabled(),
        "clock": {
            "implementation": clock.implementation,
            "resolution_seconds": clock.resolution,
            "monotonic": clock.monotonic,
            "adjustable": clock.adjustable,
        },
    }


def run_benchmarks(
    config: BenchmarkConfig,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[Sample], dict]:
    started = datetime.now(timezone.utc).isoformat()
    environment = _environment()
    load_before = os.getloadavg() if hasattr(os, "getloadavg") else None
    sessions = [BenchmarkSession(case, config) for case in config.cases]
    rows: list[Sample] = []
    counts: list[int] = []
    for session in sessions:
        rows.append(session.measure(min(16, session.max_operations), phase="warmup", batch_index=0))
        count = _calibrate(session, config, rows)
        counts.append(count)
        for batch in range(config.warmup_batches):
            rows.append(session.measure(count, phase="warmup", batch_index=batch + 1))
    for round_index in range(config.samples):
        order = list(range(len(sessions)))
        if round_index % 2:
            order.reverse()
        for index in order:
            rows.append(
                sessions[index].measure(counts[index], phase="measurement", batch_index=round_index)
            )
        if progress is not None:
            progress(round_index + 1, config.samples)
    metadata = {
        "format_version": 1,
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "config": asdict(config),
        "aad_hex": BENCHMARK_AAD.hex(),
        "environment": environment,
        "load_before": load_before,
        "load_after": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "measurement_code_sha256": {
            name: sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
            for name in ("benchmark.py", "aead.py", "nonces.py")
        },
    }
    return rows, metadata
