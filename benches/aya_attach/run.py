"""Run both attachment variants under perf, alternating order on one CPU."""
import argparse
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--cpu", type=int, default=5)
parser.add_argument("--pairs", type=int, default=10)
parser.add_argument("--iterations", type=int, default=500)
parser.add_argument("--warmup", type=int, default=25)
args = parser.parse_args()
if args.pairs < 2 or args.iterations < 1 or args.warmup < 1:
    parser.error("need at least two pairs, one iteration, and one warmup")
if args.cpu not in os.sched_getaffinity(0):
    parser.error("selected CPU is outside the allowed affinity mask")
root = Path(__file__).resolve().parents[2]
build = root / "target/aya-attach-benchmark"
out = build / f"results-{time.time_ns()}"
out.mkdir(parents=True)
rows = []
print(f"Saving results to {out}", flush=True)
for pair in range(args.pairs):
    for mode in (("aya", "fixed") if pair % 2 == 0 else ("fixed", "aya")):
        perf_file = out / f"{pair:02d}-{mode}.perf.csv"
        command = ["taskset", "-c", str(args.cpu), "perf", "stat", "-x", ";",
                   "-o", str(perf_file), "-e",
                   "task-clock,context-switches,cpu-migrations,page-faults", "--",
                   str(build / f"{mode}-attach"), str(build / "program.o"),
                   str(args.iterations), str(args.warmup)]
        process = subprocess.run(command, text=True, capture_output=True)
        (out / f"{pair:02d}-{mode}.log").write_text(process.stdout + process.stderr)
        if process.returncode:
            raise SystemExit(f"{mode} failed:\n{process.stdout}{process.stderr}\n"
                             f"perf output:\n{perf_file.read_text() if perf_file.exists() else ''}")
        ns = float(re.search(r"attach_ns_per_op=([\d.]+)", process.stdout)[1])
        rows.append(dict(pair=pair, mode=mode, ns_per_op=ns,
                         stdout=process.stdout, perf=perf_file.read_text()))
        (out / "results.json").write_text(json.dumps(dict(config=vars(args), rows=rows), indent=2))
        print(f"pair {pair + 1}/{args.pairs} {mode}: {ns:.3f} ns/attach", flush=True)

values = {mode: [r["ns_per_op"] for r in rows if r["mode"] == mode]
          for mode in ("aya", "fixed")}
summary = []
for mode, times in values.items():
    summary.append(f"{mode}: mean {statistics.mean(times):.3f}, "
                   f"median {statistics.median(times):.3f} ns/attach")
deltas = [a - b for a, b in zip(values["aya"], values["fixed"])]
rng = random.Random(0)
boot = sorted(statistics.mean(rng.choices(deltas, k=len(deltas))) for _ in range(10000))
summary.append(f"Mean paired saving: {statistics.mean(deltas):.3f} ns/attach "
               f"({100 * statistics.mean(deltas) / statistics.mean(values['aya']):.2f}%)")
summary.append(f"Approximate paired bootstrap 95% interval: [{boot[250]:.3f}, {boot[9749]:.3f}] ns")
summary.append("Perf includes startup, load, warmup, attachment, and detach; "
               "only attach_ns_per_op isolates attachment.")
(out / "summary.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
