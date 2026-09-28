#!/usr/bin/env python3
"""Measure target perturbation and observer cost for Samurai's two paths."""

import argparse
import json
import os
import re
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

WORKLOAD = re.compile(r"requested=(\d+) completed=(\d+) elapsed_seconds=([0-9.]+)")
EVENTS = "task-clock,context-switches,cpu-migrations,page-faults"


def perf(path: Path) -> dict[str, float]:
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split(";")
        if len(fields) >= 3:
            try:
                result[fields[2].strip()] = float(fields[0].replace(",", "").strip())
            except ValueError:
                pass
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--yields", type=int, default=250_000)
    parser.add_argument("--target-cpus", default="0,1,2,3")
    parser.add_argument("--raw-consumer-cpu", default="5")
    parser.add_argument(
        "--modes",
        default="baseline,aggregate,aya_aggregate,raw,aya_raw",
        help="comma-separated modes, executed in the given order",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")

    root = Path(__file__).resolve().parents[1]
    aya_root = root.parent / "aya"
    workload = root / "target/release/examples/scheduler_workload"
    modes = {
        "aggregate": [
            root / "target/release/examples/record",
            root / "target/aggregate.bpf.o",
            str(args.seconds),
        ],
        "raw": [
            root / "target/release/examples/raw_record",
            root / "target/record.bpf.o",
            str(args.seconds),
            args.raw_consumer_cpu,
        ],
        "aya_aggregate": [
            aya_root / "target/release/examples/scheduler_compare",
            "aggregate",
            root / "target/aggregate.bpf.o",
            str(args.seconds),
        ],
        "aya_raw": [
            aya_root / "target/release/examples/scheduler_compare",
            "raw",
            root / "target/record.bpf.o",
            str(args.seconds),
            args.raw_consumer_cpu,
        ],
    }
    selected_modes = tuple(mode.strip() for mode in args.modes.split(",") if mode.strip())
    valid_modes = {"baseline", *modes}
    unknown_modes = set(selected_modes) - valid_modes
    if unknown_modes:
        raise SystemExit(f"unknown modes: {', '.join(sorted(unknown_modes))}")
    if not selected_modes:
        raise SystemExit("select at least one mode")
    result_dir = root / "target/complete-benchmark" / str(time.time_ns())
    result_dir.mkdir(parents=True)
    records = []

    for pair in range(1, args.pairs + 1):
        order = selected_modes if pair % 2 else tuple(reversed(selected_modes))
        for mode in order:
            with tempfile.TemporaryDirectory() as temporary:
                temporary = Path(temporary)
                target_perf = temporary / "target.perf"
                profiler_perf = temporary / "profiler.perf"
                profiler = None
                if mode != "baseline":
                    profiler = subprocess.Popen(
                        ["perf", "stat", "-x", ";", "-o", str(profiler_perf), "-e", EVENTS, "--", *map(str, modes[mode])],
                        cwd=root,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    time.sleep(0.5)
                target = subprocess.run(
                    ["perf", "stat", "-x", ";", "-o", str(target_perf), "-e", EVENTS, "--", str(workload), str(args.yields), args.target_cpus],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                match = WORKLOAD.search(target.stdout)
                if not match:
                    raise RuntimeError(target.stdout + target.stderr)
                profiler_stdout = ""
                profiler_stderr = ""
                profiler_metrics = {}
                if profiler is not None:
                    profiler_stdout, profiler_stderr = profiler.communicate()
                    if profiler.returncode:
                        raise RuntimeError(profiler_stdout + profiler_stderr)
                    profiler_metrics = perf(profiler_perf)
                record = {
                    "pair": pair,
                    "mode": mode,
                    "requested": int(match.group(1)),
                    "completed": int(match.group(2)),
                    "target_seconds": float(match.group(3)),
                    "target_perf": perf(target_perf),
                    "profiler_perf": profiler_metrics,
                    "profiler_stdout": profiler_stdout,
                    "profiler_stderr": profiler_stderr,
                }
                records.append(record)
                print(
                    f"pair={pair} mode={mode} target_seconds={record['target_seconds']:.6f} "
                    f"target_task_ms={record['target_perf']['task-clock']:.2f} "
                    f"profiler_task_ms={profiler_metrics.get('task-clock', 0):.2f}"
                )

    (result_dir / "results.json").write_text(json.dumps(records, indent=2))
    baseline_records = [r["target_seconds"] for r in records if r["mode"] == "baseline"]
    baseline = statistics.mean(baseline_records) if baseline_records else None
    print(f"results={result_dir}")
    for mode in selected_modes:
        selected = [r for r in records if r["mode"] == mode]
        elapsed = statistics.mean(r["target_seconds"] for r in selected)
        observer = statistics.mean(r["profiler_perf"].get("task-clock", 0) for r in selected)
        slowdown = (
            f"target_slowdown={(elapsed / baseline - 1) * 100:+.2f}% "
            if baseline
            else ""
        )
        print(
            f"mode={mode} target_mean_seconds={elapsed:.6f} "
            f"{slowdown}"
            f"profiler_task_mean_ms={observer:.3f}"
        )


if __name__ == "__main__":
    main()
