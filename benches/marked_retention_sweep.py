#!/usr/bin/env python3
"""Measure marked Mold retention sizes under identical controlled load."""

import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path


def fields(line):
    return dict(part.split("=", 1) for part in line.split() if "=" in part)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--calls", type=int, default=2_000_000)
    parser.add_argument("--capacities", default="16384,65536,262144,524288,1048576")
    parser.add_argument("--producer-cpus", default="0,1,2,3")
    parser.add_argument("--consumer-cpus", default="5,4,6,7")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")

    root = Path(__file__).resolve().parents[1]
    capacities = [int(value) for value in args.capacities.split(",")]
    records = []
    for trial in range(1, args.trials + 1):
        order = capacities if trial % 2 else list(reversed(capacities))
        for capacity in order:
            obj = root / "target" / f"marked-controlled-{capacity}.bpf.o"
            command = [
                root / "target/release/examples/marked_controlled",
                obj,
                str(args.calls),
                args.producer_cpus,
                args.consumer_cpus,
            ]
            done = subprocess.run([str(value) for value in command], text=True, capture_output=True)
            if done.returncode:
                raise RuntimeError(done.stdout + done.stderr)
            row = fields(done.stdout.strip())
            record = {
                "trial": trial,
                "capacity": capacity,
                "rate": float(row["requested_per_second"]),
                "loss": float(row["loss_pct"]),
                "max_backlog": int(row["max_backlog"]),
                "map_bytes": int(row["map_bytes"]),
                "worst_lane": int(row["worst_lane"]),
                "worst_worker": int(row["worst_worker"]),
                "involuntary": int(row["worst_involuntary"]),
                "offcpu_ms": float(row["worst_wall_ms"]) - float(row["worst_cpu_ms"]),
                "max_checkpoint_offcpu_ms": float(row["max_checkpoint_offcpu_ms"]),
                "stdout": done.stdout,
            }
            records.append(record)
            print(
                f"trial={trial} capacity={capacity} rate={record['rate']:.0f}/s "
                f"loss={record['loss']:.4f}% backlog={record['max_backlog']} "
                f"worker={record['worst_worker']} max_pause_ms={record['max_checkpoint_offcpu_ms']:.3f}"
            )

    output = root / "target" / "marked-retention-sweep" / str(time.time_ns())
    output.mkdir(parents=True)
    (output / "results.json").write_text(json.dumps(records, indent=2))
    print(f"results={output}")
    for capacity in capacities:
        rows = [row for row in records if row["capacity"] == capacity]
        zero_loss = sum(row["loss"] == 0 for row in rows)
        print(
            f"capacity={capacity} map_mib={rows[0]['map_bytes'] / 2**20:.1f} "
            f"zero_loss={zero_loss}/{len(rows)} mean_rate={statistics.mean(row['rate'] for row in rows):.0f}/s "
            f"mean_loss={statistics.mean(row['loss'] for row in rows):.4f}% "
            f"max_backlog={max(row['max_backlog'] for row in rows)} "
            f"max_pause_ms={max(row['max_checkpoint_offcpu_ms'] for row in rows):.3f}"
        )


if __name__ == "__main__":
    main()
