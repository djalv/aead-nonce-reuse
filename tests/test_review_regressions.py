"""Regressions for data integrity and the documented command workflows."""

import csv
import io
import json
import shutil
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from nonce_reuse.__main__ import main
from nonce_reuse.analysis import analyze_benchmark, summarize, write_tables
from nonce_reuse.benchmark import BenchmarkConfig, Sample
from nonce_reuse.benchmark_data import load_benchmark, save_benchmark, validate_samples

PROJECT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "field", ["samples", "target_ns", "warmup_batches", "max_operations", "payload_budget_bytes"]
)
@pytest.mark.parametrize("value", [True, 2.5, float("nan"), "30"])
def test_configuration_rejects_noninteger_settings(field, value):
    with pytest.raises(ValueError, match="integers"):
        BenchmarkConfig(**{field: value})


def _reallocate(samples: list[Sample]) -> list[Sample]:
    stops = {}
    result = []
    for row in samples:
        start = stops.get(row.case, 0)
        stops[row.case] = start + row.operations
        result.append(replace(row, nonce_start=start, nonce_stop=stops[row.case]))
    return result


@pytest.mark.parametrize(
    "field,value", [("elapsed_ns", float("nan")), ("operations", True), ("nonce_start", 0.0)]
)
def test_batch_validation_rejects_noninteger_arithmetic(quick_run, field, value):
    config, original, _ = quick_run
    rows = original.copy()
    rows[0] = replace(rows[0], **{field: value})
    with pytest.raises(ValueError, match="integers"):
        validate_samples(rows, config)


@pytest.mark.parametrize(
    "change,reason",
    [
        ("warmup", "preliminary warm-up"),
        ("initial_calibration", "start with one"),
        ("early_stop", "stopped before"),
        ("extra_calibration", "continued after"),
        ("late_setup", "precede measurement"),
    ],
)
def test_protocol_validation_rejects_incomplete_calibration(quick_run, change, reason):
    config, original, _ = quick_run
    rows = original.copy()
    if change == "late_setup":
        rows = rows[1:] + rows[:1]
    elif change == "warmup":
        rows[0] = replace(rows[0], operations=1)
    else:
        index = next(i for i, row in enumerate(rows) if row.phase == "calibration")
        if change == "initial_calibration":
            rows[index] = replace(rows[index], operations=2)
        elif change == "early_stop":
            rows[index] = replace(rows[index], elapsed_ns=1)
        else:
            rows.insert(index + 1, replace(rows[index], batch_index=1))
    with pytest.raises(ValueError, match=reason):
        validate_samples(_reallocate(rows), config)


@pytest.mark.parametrize("change", ["missing_environment", "missing_python", "invalid_cpu"])
def test_invalid_environment_is_rejected_before_analysis_writes(quick_run, tmp_path, change):
    _, rows, metadata = quick_run
    raw = tmp_path / "raw"
    save_benchmark(rows, metadata, raw)
    path = raw / "benchmark-environment.json"
    manifest = json.loads(path.read_text())
    if change == "missing_environment":
        manifest.pop("environment")
    elif change == "missing_python":
        manifest["environment"].pop("python")
    else:
        manifest["environment"]["cpu"] = []
    path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="metadata"):
        analyze_benchmark(raw, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("change", ["header", "extra_value", "missing_value"])
def test_csv_schema_is_checked_even_with_a_matching_hash(quick_run, tmp_path, change):
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)
    path = tmp_path / "benchmarks.csv"
    rows = list(csv.reader(io.StringIO(path.read_text())))
    if change == "header":
        rows[0][1] = rows[0][0]
    elif change == "extra_value":
        rows[1].append("extra")
    else:
        rows[1].pop()
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    payload = output.getvalue().encode()
    path.write_bytes(payload)
    manifest_path = tmp_path / "benchmark-environment.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["samples_sha256"] = sha256(payload).hexdigest()
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="CSV"):
        load_benchmark(tmp_path)


def test_analysis_cannot_overwrite_its_raw_input(quick_run, tmp_path):
    _, samples, metadata = quick_run
    raw = tmp_path / "tables"
    save_benchmark(samples, metadata, raw)
    before = (raw / "benchmarks.csv").read_bytes()

    with pytest.raises(ValueError, match="overwrite"):
        analyze_benchmark(raw, tmp_path)
    assert (raw / "benchmarks.csv").read_bytes() == before


@pytest.mark.parametrize("invalid", [object(), float("nan")])
def test_unserializable_metadata_does_not_damage_an_existing_run(quick_run, tmp_path, invalid):
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    with pytest.raises(ValueError, match="JSON"):
        save_benchmark(samples, {**metadata, "invalid": invalid}, tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_existing_measurements_are_not_replaced(quick_run, tmp_path):
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(FileExistsError, match="new output directory"):
        save_benchmark(samples, metadata, tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_failed_bundle_write_cleans_up_only_new_files(quick_run, tmp_path, monkeypatch):
    _, samples, metadata = quick_run
    existing = tmp_path / "security-demonstrations.json"
    existing.write_text("keep")
    native_open = Path.open

    def failed_open(path, *args, **kwargs):
        if path == tmp_path / "benchmark-environment.json":
            raise OSError("simulated write failure")
        return native_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failed_open)
    with pytest.raises(OSError, match="simulated"):
        save_benchmark(samples, metadata, tmp_path)
    assert sorted(path.name for path in tmp_path.iterdir()) == [existing.name]
    assert existing.read_text() == "keep"


def test_existing_benchmark_output_is_rejected_before_measurement(tmp_path, monkeypatch, capsys):
    from nonce_reuse import benchmark

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "benchmarks.csv").write_text("existing observations")

    def should_not_run(*args, **kwargs):
        pytest.fail("Measurement started before checking the output directory")

    monkeypatch.setattr(benchmark, "run_benchmarks", should_not_run)
    with pytest.raises(SystemExit):
        main(["benchmark", "--output-dir", str(tmp_path)])
    assert "new output directory" in capsys.readouterr().err


def test_recorded_measurements_reproduce_tables_and_archived_source(tmp_path):
    samples, metadata = load_benchmark(PROJECT / "results/raw")
    write_tables(summarize(samples), tmp_path)
    for name in ("benchmarks.csv", "benchmarks.md"):
        assert (tmp_path / name).read_bytes() == (PROJECT / "results/tables" / name).read_bytes()
    for name, expected in metadata["measurement_code_sha256"].items():
        assert (
            sha256((PROJECT / "results/measurement-source" / name).read_bytes()).hexdigest()
            == expected
        )


def test_check_command_reports_real_algorithm_and_plot_checks(capsys):
    assert main(["check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["checks"]["matplotlib_png"]
    assert len(result["checks"]["algorithms"]) == 2
    assert all(all(checks.values()) for checks in result["checks"]["algorithms"].values())


@pytest.mark.skipif(
    not (shutil.which("libreoffice") or shutil.which("soffice")),
    reason="LibreOffice is not installed",
)
def test_document_command_exports_office_files(tmp_path, capsys):
    assert main(["docs", "--source-root", str(PROJECT), "--output-dir", str(tmp_path)]) == 0
    for name in ("report", "slides", "demo-backup"):
        assert (tmp_path / f"{name}.pdf").read_bytes().startswith(b"%PDF-")
    assert "report.pdf" in capsys.readouterr().out


def test_invalid_office_files_are_reported_without_tracebacks(tmp_path, capsys):
    for relative in ("report/report.docx", "slides/slides.pptx", "slides/demo-backup.pptx"):
        path = tmp_path / relative
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"not an office document")
    with pytest.raises(SystemExit) as error:
        main(["docs", "--source-root", str(tmp_path), "--output-dir", str(tmp_path / "pdf")])
    assert error.value.code == 1
    message = capsys.readouterr().err
    assert "Failed to export" in message and "Traceback" not in message
