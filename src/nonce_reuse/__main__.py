"""Command line entry point for the study."""

import argparse
import json
import sys
from pathlib import Path


def _check(_args: argparse.Namespace) -> None:
    from nonce_reuse.check import run_checks

    print(json.dumps(run_checks(), ensure_ascii=False, indent=2))


def _demo(args: argparse.Namespace) -> None:
    from nonce_reuse.demo import demonstration_data, render_demonstrations
    from nonce_reuse.experiments import run_demonstrations

    results = run_demonstrations()
    serialized = json.dumps(demonstration_data(results), indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized if args.json else render_demonstrations(results))


def _docs(args: argparse.Namespace) -> None:
    from nonce_reuse.documents import export_documents

    for output in export_documents(args.source_root, args.output_dir):
        print(output)


def _benchmark(args: argparse.Namespace) -> None:
    from nonce_reuse.analysis import analyze_benchmark
    from nonce_reuse.benchmark import BenchmarkConfig, run_benchmarks
    from nonce_reuse.benchmark_data import ensure_new_run, save_benchmark

    config = BenchmarkConfig(samples=args.samples, target_ns=args.target_ms * 1_000_000)
    ensure_new_run(args.output_dir / "raw")

    def progress(round_index: int, total: int) -> None:
        print(f"Measured round {round_index}/{total}", file=sys.stderr, flush=True)

    samples, metadata = run_benchmarks(config, progress)
    save_benchmark(samples, metadata, args.output_dir / "raw")
    analyze_benchmark(args.output_dir / "raw", args.output_dir)
    print((args.output_dir / "tables" / "benchmarks.md").read_text(encoding="utf-8"))


def _analyze(args: argparse.Namespace) -> None:
    from nonce_reuse.analysis import analyze_benchmark

    analyze_benchmark(args.input_dir, args.output_dir)
    print((args.output_dir / "tables" / "benchmarks.md").read_text(encoding="utf-8"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nonce-reuse",
        description="Study of nonce reuse in authenticated encryption.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Check the environment and both algorithms.")
    check.set_defaults(handler=_check)
    demonstration = commands.add_parser("demo", help="Demonstrate correct use and nonce reuse.")
    demonstration.add_argument("--json", action="store_true", help="Print results as JSON.")
    demonstration.add_argument("--output", type=Path, help="Also save the results as JSON.")
    demonstration.set_defaults(handler=_demo)
    documents = commands.add_parser(
        "docs", help="Export DOCX and PPTX files to PDF with LibreOffice."
    )
    documents.add_argument(
        "--source-root",
        type=Path,
        default=Path("."),
        help="Project root containing report/ and slides/ (default: current directory).",
    )
    documents.add_argument(
        "--output-dir",
        type=Path,
        default=Path("build"),
        help="PDF output directory (default: build/).",
    )
    documents.set_defaults(handler=_docs)
    benchmark = commands.add_parser("benchmark", help="Measure the full benchmark matrix.")
    benchmark.add_argument(
        "--samples", type=int, default=30, help="Measured batches per case (default: 30)."
    )
    benchmark.add_argument(
        "--target-ms",
        type=int,
        default=20,
        help="Calibration target in milliseconds (default: 20).",
    )
    benchmark.add_argument(
        "--output-dir",
        type=Path,
        default=Path("build/benchmark"),
        help="Result directory (default: build/benchmark).",
    )
    benchmark.set_defaults(handler=_benchmark)
    analyze = commands.add_parser("analyze", help="Regenerate tables and plots from saved batches.")
    analyze.add_argument(
        "--input-dir",
        type=Path,
        default=Path("results/raw"),
        help="Raw CSV and metadata directory (default: results/raw).",
    )
    analyze.add_argument(
        "--output-dir",
        type=Path,
        default=Path("build/analysis"),
        help="Analysis directory (default: build/analysis).",
    )
    analyze.set_defaults(handler=_analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
