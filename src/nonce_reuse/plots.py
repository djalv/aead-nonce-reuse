"""Export benchmark figures from the same summaries used by the tables."""

from pathlib import Path

from nonce_reuse.aead import Algorithm
from nonce_reuse.analysis import Summary, size_label
from nonce_reuse.benchmark import Operation

COLORS = {Algorithm.AES_GCM: "#145da0", Algorithm.CHACHA20_POLY1305: "#b65a28"}
MARKERS = {Algorithm.AES_GCM: "o", Algorithm.CHACHA20_POLY1305: "s"}


def write_figures(summaries: list[Summary], metadata: dict, output_dir: Path) -> None:
    import matplotlib
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    output_dir.mkdir(parents=True, exist_ok=True)
    with matplotlib.rc_context(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "text.usetex": False,
            "pdf.fonttype": 42,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    ):
        for metric in ("latency", "throughput"):
            figure = Figure(figsize=(10.5, 4.8), facecolor="white")
            FigureCanvasAgg(figure)
            axes = figure.subplots(1, 2)
            for operation, axis in zip(Operation, axes, strict=True):
                for algorithm in Algorithm:
                    selected = sorted(
                        (
                            row
                            for row in summaries
                            if row.case.operation == operation and row.case.algorithm == algorithm
                        ),
                        key=lambda row: row.case.message_bytes,
                    )
                    sizes = [row.case.message_bytes for row in selected]
                    if metric == "latency":
                        values = [row.median_ns / 1000 for row in selected]
                        lower = [(row.median_ns - row.q1_ns) / 1000 for row in selected]
                        upper = [(row.q3_ns - row.median_ns) / 1000 for row in selected]
                    else:
                        values = [row.throughput for row in selected]
                        lower = [row.throughput - row.throughput_low for row in selected]
                        upper = [row.throughput_high - row.throughput for row in selected]
                    axis.errorbar(
                        sizes,
                        values,
                        yerr=[lower, upper],
                        label=algorithm.value,
                        color=COLORS[algorithm],
                        marker=MARKERS[algorithm],
                        linewidth=1.8,
                        markersize=5,
                        capsize=3,
                    )
                ticks = sorted({row.case.message_bytes for row in summaries})
                axis.set_xscale("log", base=2)
                axis.set_yscale("log")
                axis.set_xticks(ticks, labels=[size_label(size) for size in ticks])
                axis.set_xlabel("Plaintext size")
                axis.set_ylabel(
                    "Latency (us/operation)" if metric == "latency" else "Throughput (MiB/s)"
                )
                axis.set_title(operation.value.title(), fontsize=12)
                axis.grid(axis="y", which="major", alpha=0.22)
            title = (
                "AEAD API latency"
                if metric == "latency"
                else "AEAD throughput from median API latency"
            )
            figure.suptitle(title, y=0.98, fontsize=15, fontweight="bold")
            figure.text(
                0.5,
                0.91,
                "Median across batches; error bars show interquartile range",
                ha="center",
                fontsize=10,
            )
            handles, labels = axes[0].get_legend_handles_labels()
            figure.legend(
                handles,
                labels,
                loc="upper center",
                bbox_to_anchor=(0.5, 0.87),
                ncols=2,
                frameon=False,
            )
            environment = metadata["environment"]
            model = environment.get("cpu", {}).get("model", "CPU model unavailable")
            figure.text(
                0.5, 0.065, f"{model} | Python {environment['python']}", ha="center", fontsize=8
            )
            batches = sorted({row.batches for row in summaries})
            figure.text(
                0.5,
                0.025,
                f"Batches/configuration: {', '.join(map(str, batches))}. Python loop included; setup and validation excluded.",
                ha="center",
                fontsize=8,
            )
            figure.subplots_adjust(left=0.085, right=0.98, top=0.71, bottom=0.22, wspace=0.30)
            for extension in ("png", "pdf"):
                figure.savefig(output_dir / f"{metric}.{extension}", dpi=180, facecolor="white")
