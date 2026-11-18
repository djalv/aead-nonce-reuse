import json
from dataclasses import replace

import pytest

from nonce_reuse.benchmark_data import load_benchmark, save_benchmark, validate_samples


def test_saved_observations_round_trip_with_metadata_hash(quick_run, tmp_path) -> None:
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)

    loaded, manifest = load_benchmark(tmp_path)

    assert loaded == samples
    assert len(manifest["samples_sha256"]) == 64
    assert len(manifest["calibration"]) == 4
    assert manifest["config"]["samples"] == 3


def test_mixed_or_changed_csv_is_rejected(quick_run, tmp_path) -> None:
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)
    path = tmp_path / "benchmarks.csv"
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="SHA-256"):
        load_benchmark(tmp_path)


@pytest.mark.parametrize("change", ["wrong_root", "fractional_samples"])
def test_invalid_metadata_is_reported_as_a_data_error(quick_run, tmp_path, change) -> None:
    _, samples, metadata = quick_run
    save_benchmark(samples, metadata, tmp_path)
    path = tmp_path / "benchmark-environment.json"
    invalid = []
    if change == "fractional_samples":
        invalid = json.loads(path.read_text())
        invalid["config"]["samples"] = 2.5
    path.write_text(json.dumps(invalid))

    with pytest.raises(ValueError):
        load_benchmark(tmp_path)


@pytest.mark.parametrize("change", ["nonce", "duration", "case", "sample", "schedule"])
def test_inconsistent_observations_are_rejected(quick_run, change) -> None:
    config, original, _ = quick_run
    samples = original.copy()
    if change == "nonce":
        samples[1] = replace(samples[1], nonce_start=0)
    elif change == "duration":
        samples[0] = replace(samples[0], elapsed_ns=0)
    elif change == "case":
        samples = [row for row in samples if row.case != samples[0].case]
    elif change == "sample":
        samples = samples[:-1]
    else:
        measured = [index for index, row in enumerate(samples) if row.phase == "measurement"]
        first, second = measured[:2]
        samples[first], samples[second] = samples[second], samples[first]

    with pytest.raises(ValueError):
        validate_samples(samples, config)
