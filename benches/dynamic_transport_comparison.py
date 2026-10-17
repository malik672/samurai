#!/usr/bin/env python3
"""Paired Aya RingBuf versus Mold benchmark for pointer captures."""

import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

from transport_comparison import bootstrap_interval, invoking_user, metadata, run_measured


def run(command, *, cwd, environment, uid, gid):
    subprocess.run(
        [str(value) for value in command],
        cwd=cwd,
        env=environment,
        user=uid,
        group=gid,
        check=True,
    )


def build(root, aya, user, capacity, payload_bytes):
    uid, gid, home, environment = user
    run(
        [home / ".cargo/bin/cargo", "build", "--release", "--example", "dynamic_controlled"],
        cwd=root, environment=environment, uid=uid, gid=gid,
    )
    run(
        [
            "clang", "-target", "bpfel", "-mcpu=v3", "-O2", "-Wall", "-Wextra",
            "-Werror", "-I", "examples/bpf", f"-DCAPACITY={capacity}",
            f"-DPAYLOAD_BYTES={payload_bytes}", "-c", "examples/bpf/dynamic_controlled.c",
            "-o", "target/dynamic-controlled.bpf.o",
        ],
        cwd=root, environment=environment, uid=uid, gid=gid,
    )
    run(
        [
            "clang", "-target", "bpfel", "-mcpu=v3", "-O2", "-Wall", "-Wextra",
            "-Werror", f"-DPAYLOAD_BYTES={payload_bytes}", "-c", "benches/dynamic_aya.c",
            "-o", "target/dynamic-aya.bpf.o",
        ],
        cwd=root, environment=environment, uid=uid, gid=gid,
    )
    run(
        [
            home / ".cargo/bin/cargo", "build", "--release", "-p", "aya",
            "--example", "dynamic_controlled_bench",
        ],
        cwd=aya, environment=environment, uid=uid, gid=gid,
    )


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--calls", type=int, default=100_000)
    parser.add_argument("--producer-cpus", default="0,1,2,3")
    parser.add_argument("--consumer-cpus", default="5,4,6,7")
    parser.add_argument("--shape", choices=("string", "bytes", "both"), default="both")
    parser.add_argument(
        "--mold-consumers", choices=("per-lane", "single"), default="per-lane"
    )
    parser.add_argument("--latency", action="store_true")
    parser.add_argument("--capacity", type=int, default=8192)
    parser.add_argument("--consumer-pause-every", type=int, default=0)
    parser.add_argument("--consumer-pause-us", type=int, default=0)
    parser.add_argument("--payload-bytes", type=int, choices=(8, 32, 128), default=128)
    return parser.parse_args()


def paired_changes(rows, metric):
    pairs = {}
    for row in rows:
        pairs.setdefault(row["pair"], {})[row["mode"]] = row[metric]
    return [(pair["mold"] / pair["aya"] - 1) * 100 for pair in pairs.values()]


def print_summaries(shape, rows, include_latency):
    for metric in (
        "producer_rate", "end_to_end_delivered_rate", "task_clock_ms",
        "context_switches", "max_rss_kib",
    ):
        changes = paired_changes(rows, metric)
        lower, upper = bootstrap_interval(changes)
        print(
            f"shape={shape} metric={metric} "
            f"mold_change={statistics.mean(changes):+.2f}% "
            f"bootstrap_95%=[{lower:+.2f}%,{upper:+.2f}%]"
        )
    if not include_latency:
        return
    for mode in ("aya", "mold"):
        selected = [row for row in rows if row["mode"] == mode]
        print(
            f"shape={shape} mode={mode} "
            f"latency_p50_us={statistics.median(row['latency_p50_ns'] for row in selected)/1000:.2f} "
            f"latency_p95_us={statistics.median(row['latency_p95_ns'] for row in selected)/1000:.2f} "
            f"latency_p99_us={statistics.median(row['latency_p99_ns'] for row in selected)/1000:.2f} "
            f"latency_max_us={max(row['latency_max_ns'] for row in selected)/1000:.2f}"
        )


def main():
    args = parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")
    if args.capacity <= 0 or args.capacity & (args.capacity - 1):
        raise SystemExit("--capacity must be a positive power of two")
    if bool(args.consumer_pause_every) != bool(args.consumer_pause_us):
        raise SystemExit("set both consumer-pause options")

    root = Path(__file__).resolve().parents[1]
    aya = root.parent / "aya"
    user = invoking_user()
    build(root, aya, user, args.capacity, args.payload_bytes)

    run_environment = os.environ.copy()
    if args.latency:
        run_environment["BENCH_LATENCY"] = "1"
    if args.consumer_pause_every:
        run_environment["BENCH_PAUSE_EVERY"] = str(args.consumer_pause_every)
        run_environment["BENCH_PAUSE_US"] = str(args.consumer_pause_us)

    shapes = ("string", "bytes") if args.shape == "both" else (args.shape,)
    all_rows = []
    for shape in shapes:
        aya_consumer = args.consumer_cpus.split(",")[0]
        mold_consumers = (
            args.consumer_cpus if args.mold_consumers == "per-lane" else aya_consumer
        )
        commands = {
            "aya": [
                aya / "target/release/examples/dynamic_controlled_bench", shape,
                root / "target/dynamic-aya.bpf.o", args.calls,
                args.producer_cpus, aya_consumer,
            ],
            "mold": [
                root / "target/release/examples/dynamic_controlled", shape,
                root / "target/dynamic-controlled.bpf.o", args.calls,
                args.producer_cpus, mold_consumers,
            ],
        }
        for _ in range(args.warmups):
            for command in commands.values():
                subprocess.run(
                    [str(value) for value in command], check=True,
                    stdout=subprocess.DEVNULL, env=run_environment,
                )

        rows = []
        for pair in range(1, args.pairs + 1):
            order = ("aya", "mold") if pair % 2 else ("mold", "aya")
            for mode in order:
                row = run_measured(commands[mode], env=run_environment)
                row.update(
                    pair=pair, mode=mode, shape=shape,
                    payload_bytes=args.payload_bytes,
                )
                rows.append(row)
                all_rows.append(row)
                print(
                    f"shape={shape} pair={pair} mode={mode} "
                    f"rate={row['producer_rate']:.0f}/s "
                    f"delivered={row['end_to_end_delivered_rate']:.0f}/s "
                    f"loss={row['loss_pct']:.4f}% "
                    f"task_ms={row['task_clock_ms']:.2f} "
                    f"rss_mib={row['max_rss_kib']/1024:.1f}"
                )
        print_summaries(shape, rows, args.latency)

    output = root / "target" / "dynamic-transport-comparison" / str(time.time_ns())
    output.mkdir(parents=True)
    (output / "results.json").write_text(
        json.dumps(
            {"metadata": metadata(user), "args": vars(args), "rows": all_rows},
            indent=2,
        )
    )
    print(f"results={output}")


if __name__ == "__main__":
    main()
