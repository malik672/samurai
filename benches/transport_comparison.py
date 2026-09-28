#!/usr/bin/env python3
"""Paired Aya RingBuf versus Samurai Mold transport benchmark."""

import argparse
import json
import os
import platform
import pwd
import random
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

EVENTS = "task-clock,context-switches,cpu-migrations,page-faults"
SCENARIOS = {
    "equal": {"lanes": 4, "capacity": 16_384},  # 4 MiB versus Aya's 4 MiB ring
    "retained": {"lanes": 8, "capacity": 524_288},  # Samurai production default
}


def key_values(line):
    return dict(field.split("=", 1) for field in line.split() if "=" in field)


def invoking_user():
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    gid = int(os.environ.get("SUDO_GID", os.getgid()))
    account = pwd.getpwuid(uid)
    home = Path(account.pw_dir)
    environment = os.environ.copy()
    environment.update(
        HOME=str(home),
        CARGO_HOME=str(home / ".cargo"),
        RUSTUP_HOME=str(home / ".rustup"),
        PATH=f"{home / '.cargo' / 'bin'}:{environment.get('PATH', '')}",
    )
    return uid, gid, home, environment


def build(root, scenario, shape, user):
    uid, gid, home, environment = user
    subprocess.run(
        [home / ".cargo/bin/cargo", "build", "--release", "--example", "marked_controlled"],
        cwd=root,
        env=environment,
        user=uid,
        group=gid,
        check=True,
    )
    output = root / "target" / f"marked-{scenario}.bpf.o"
    subprocess.run(
        [
            "clang", "-target", "bpfel", "-mcpu=v3", "-O2",
            f"-DLANES={shape['lanes']}", f"-DCAPACITY={shape['capacity']}",
            "-c", "examples/bpf/marked_controlled.c", "-o", output,
        ],
        cwd=root,
        env=environment,
        user=uid,
        group=gid,
        check=True,
    )
    return output


def parse_perf(path):
    values = {}
    for line in path.read_text().splitlines():
        fields = line.split(";")
        if len(fields) >= 3:
            try:
                values[fields[2].strip()] = float(fields[0].replace(",", "").strip())
            except ValueError:
                pass
    return values


def parse_rss(path):
    rss = None
    for line in path.read_text().splitlines():
        if "Maximum resident set size (kbytes)" in line:
            rss = int(line.rsplit(":", 1)[1])
    if rss is None:
        raise RuntimeError(f"maximum RSS missing from {path}")
    return rss


def run_measured(command):
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        perf_output = directory / "perf.csv"
        time_output = directory / "time.txt"
        wrapped = [
            "/usr/bin/time", "-v", "-o", str(time_output),
            "perf", "stat", "-x", ";", "-o", str(perf_output),
            "-e", EVENTS, "--", *map(str, command),
        ]
        started_ns = time.perf_counter_ns()
        completed = subprocess.run(wrapped, text=True, capture_output=True)
        elapsed_ns = time.perf_counter_ns() - started_ns
        if completed.returncode:
            raise RuntimeError(completed.stdout + completed.stderr)
        fields = key_values(completed.stdout.strip())
        perf = parse_perf(perf_output)
        requested = int(fields["requested"])
        received = int(fields["received"])
        dropped = int(fields["dropped"])
        unaccounted = int(fields["unaccounted"])
        if unaccounted or received + dropped != requested:
            raise RuntimeError(f"invalid accounting: {completed.stdout}")
        max_rss_kib = parse_rss(time_output)
        elapsed_seconds = elapsed_ns / 1_000_000_000
        producer_seconds = float(fields["producer_seconds"])
        return {
            "requested": requested,
            "received": received,
            "dropped": dropped,
            "loss_pct": float(fields["loss_pct"]),
            "producer_rate": float(fields["requested_per_second"]),
            "delivered_producer_rate": received / producer_seconds,
            "end_to_end_delivered_rate": received / elapsed_seconds,
            "producer_seconds": producer_seconds,
            "elapsed_seconds": elapsed_seconds,
            "consumer_cpu_ms": float(fields["consumer_cpu_ms"]),
            "task_clock_ms": perf.get("task-clock"),
            "context_switches": perf.get("context-switches"),
            "cpu_migrations": perf.get("cpu-migrations"),
            "page_faults": perf.get("page-faults"),
            "max_rss_kib": max_rss_kib,
            "max_backlog": int(fields["max_backlog"]) if "max_backlog" in fields else None,
            "map_bytes": int(fields["map_bytes"]) if "map_bytes" in fields else 4 << 20,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": [str(value) for value in command],
        }


def paired_change(rows, metric):
    pairs = {}
    for row in rows:
        pairs.setdefault(row["pair"], {})[row["mode"]] = row[metric]
    return [(pair["mold"] / pair["aya"] - 1) * 100 for pair in pairs.values()]


def bootstrap_interval(changes, samples=20_000):
    rng = random.Random(0x5A6D_7572_6169)
    means = sorted(
        statistics.mean(rng.choice(changes) for _ in changes) for _ in range(samples)
    )
    return means[int(samples * 0.025)], means[int(samples * 0.975)]


def metadata(user):
    _uid, _gid, home, environment = user
    commands = {
        "uname": ["uname", "-a"],
        "lscpu": ["lscpu"],
        "rustc": [home / ".cargo/bin/rustc", "-Vv"],
        "clang": ["clang", "--version"],
    }
    return {
        "timestamp_ns": time.time_ns(),
        "platform": platform.platform(),
        **{
            name: subprocess.run(
                command, text=True, capture_output=True, check=True, env=environment
            ).stdout.strip()
            for name, command in commands.items()
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=(*SCENARIOS, "both"), default="equal")
    parser.add_argument("--pairs", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--calls", type=int, default=2_000_000)
    parser.add_argument("--producer-cpus", default="0,1,2,3")
    parser.add_argument("--consumer-cpus", default="5,4,6,7")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")

    root = Path(__file__).resolve().parents[1]
    aya = root.parent / "aya"
    selected = SCENARIOS if args.scenario == "both" else {args.scenario: SCENARIOS[args.scenario]}
    user = invoking_user()
    run_metadata = metadata(user)

    for scenario, shape in selected.items():
        mold_object = build(root, scenario, shape, user)
        commands = {
            "aya": [
                aya / "target/release/examples/mold_controlled_bench", "shared",
                aya / "target/bpfel-unknown-none/release/mold-bench",
                str(args.calls), args.producer_cpus, args.consumer_cpus,
            ],
            "mold": [
                root / "target/release/examples/marked_controlled", mold_object,
                str(args.calls), args.producer_cpus, args.consumer_cpus,
            ],
        }
        for _ in range(args.warmups):
            for command in commands.values():
                subprocess.run([str(value) for value in command], check=True, stdout=subprocess.DEVNULL)

        rows = []
        for pair in range(1, args.pairs + 1):
            order = ("aya", "mold") if pair % 2 else ("mold", "aya")
            for mode in order:
                row = run_measured(commands[mode])
                row.update(pair=pair, mode=mode, scenario=scenario)
                rows.append(row)
                print(
                    f"scenario={scenario} pair={pair} mode={mode} "
                    f"producer_rate={row['producer_rate']:.0f}/s "
                    f"delivered_rate={row['end_to_end_delivered_rate']:.0f}/s "
                    f"loss={row['loss_pct']:.4f}% "
                    f"task_ms={row['task_clock_ms']:.2f} rss_mib={row['max_rss_kib']/1024:.1f}"
                )

        output = root / "target" / "transport-comparison" / scenario / str(time.time_ns())
        output.mkdir(parents=True)
        (output / "results.json").write_text(
            json.dumps({"metadata": run_metadata, "shape": shape, "rows": rows}, indent=2)
        )
        print(f"results={output}")
        for mode in ("aya", "mold"):
            selected_rows = [row for row in rows if row["mode"] == mode]
            print(
                f"scenario={scenario} mode={mode} "
                f"mean_producer_rate={statistics.mean(row['producer_rate'] for row in selected_rows):.0f}/s "
                f"mean_delivered_rate={statistics.mean(row['end_to_end_delivered_rate'] for row in selected_rows):.0f}/s "
                f"median_delivered_rate={statistics.median(row['end_to_end_delivered_rate'] for row in selected_rows):.0f}/s "
                f"mean_task_ms={statistics.mean(row['task_clock_ms'] for row in selected_rows):.2f} "
                f"median_task_ms={statistics.median(row['task_clock_ms'] for row in selected_rows):.2f} "
                f"mean_switches={statistics.mean(row['context_switches'] for row in selected_rows):.1f} "
                f"mean_rss_mib={statistics.mean(row['max_rss_kib'] for row in selected_rows)/1024:.1f} "
                f"mean_loss={statistics.mean(row['loss_pct'] for row in selected_rows):.4f}%"
            )
        for metric in (
            "producer_rate",
            "delivered_producer_rate",
            "end_to_end_delivered_rate",
            "task_clock_ms",
            "context_switches",
            "max_rss_kib",
        ):
            changes = paired_change(rows, metric)
            lower, upper = bootstrap_interval(changes)
            print(
                f"scenario={scenario} metric={metric} mold_change={statistics.mean(changes):+.2f}% "
                f"bootstrap_95%=[{lower:+.2f}%,{upper:+.2f}%]"
            )


if __name__ == "__main__":
    main()
