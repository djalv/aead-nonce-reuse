import json

import pytest

from nonce_reuse.__main__ import main
from nonce_reuse.attacks import recover_plaintext


def test_demo_shows_both_algorithms_without_creating_files(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    assert main(["demo"]) == 0

    output = capsys.readouterr().out
    assert "AES-256-GCM" in output and "ChaCha20-Poly1305" in output
    assert "Transfer USD 900 to account 5678." in output
    assert "16/54 bytes" in output
    assert "public demonstration fixtures" in output
    assert list(tmp_path.iterdir()) == []


def test_json_output_can_reproduce_recovery_without_a_key(tmp_path, capsys) -> None:
    output_file = tmp_path / "results" / "security.json"

    assert main(["demo", "--json", "--output", str(output_file)]) == 0

    output = capsys.readouterr().out
    assert output_file.read_text(encoding="utf-8") == output
    data = json.loads(output)
    assert len(data["algorithms"]) == 2
    for algorithm in data["algorithms"]:
        for name in ("reused_nonce", "partial_recovery"):
            case = algorithm[name]
            recovered = recover_plaintext(
                bytes.fromhex(case["known_plaintext_hex"]),
                bytes.fromhex(case["known_message"]["ciphertext_hex"]),
                bytes.fromhex(case["target_message"]["ciphertext_hex"]),
            )
            assert recovered.hex() == case["recovered_hex"]
            assert recovered == bytes.fromhex(case["target_plaintext_hex"])[: len(recovered)]
            assert len(bytes.fromhex(case["known_message"]["tag_hex"])) == 16


def test_output_write_errors_are_reported_without_a_traceback(tmp_path, capsys) -> None:
    with pytest.raises(SystemExit) as error:
        main(["demo", "--output", str(tmp_path)])
    assert error.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("Error:")
    assert "Traceback" not in output.err


def test_benchmark_and_analysis_commands_produce_reproducible_tables(
    tmp_path, capsys, monkeypatch
) -> None:
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "matplotlib"))
    output = tmp_path / "measurement"

    assert (
        main(["benchmark", "--samples", "2", "--target-ms", "1", "--output-dir", str(output)]) == 0
    )
    assert "Measured round 2/2" in capsys.readouterr().err
    manifest = json.loads((output / "raw/benchmark-environment.json").read_text())
    assert manifest["config"]["samples"] == 2
    assert manifest["config"]["sizes"] == [64, 4096, 1048576]
    for name in ("latency", "throughput"):
        assert (output / f"figures/{name}.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert (output / f"figures/{name}.pdf").read_bytes().startswith(b"%PDF-")
    regenerated = tmp_path / "regenerated"

    assert (
        main(["analyze", "--input-dir", str(output / "raw"), "--output-dir", str(regenerated)]) == 0
    )

    for name in ("benchmarks.csv", "benchmarks.md"):
        assert (output / "tables" / name).read_bytes() == (
            regenerated / "tables" / name
        ).read_bytes()


@pytest.mark.parametrize("option,value", [("--samples", "1"), ("--target-ms", "0")])
def test_invalid_benchmark_options_fail_without_writing_results(
    option, value, tmp_path, capsys
) -> None:
    output = tmp_path / "results"
    with pytest.raises(SystemExit) as error:
        main(["benchmark", option, value, "--output-dir", str(output)])
    assert error.value.code == 1
    assert not output.exists()
    assert capsys.readouterr().err.startswith("Error:")
