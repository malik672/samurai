"""Actual Aya comparison. --kernel includes BPF_PROG_LOAD and requires privileges."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument("--cpu", type=int, default=5)
p.add_argument("--pairs", type=int, default=20)
p.add_argument("--iterations", type=int, default=500)
p.add_argument("--kernel", action="store_true")
args = p.parse_args()
if args.pairs < 2 or args.iterations < 1 or args.cpu not in os.sched_getaffinity(0):
    p.error("need >=2 pairs, positive iterations, and an available CPU")
root = Path(__file__).resolve().parents[2]
build = root / "target/aya-ownership"
phase = "kernel" if args.kernel else "prepare"
out = build / f"results-{phase}-{time.time_ns()}"
out.mkdir()
cases = ["single_small", "unique_32_small", "aliases_32_small", "unique_32_large", "aliases_32_large"]
if args.kernel:
    cases.append("counter_32")
meta = dict(config=vars(args), phase=phase, revision=(build / "revision.txt").read_text().strip(),
            rustc=(build / "rustc.txt").read_text(),
            lscpu=subprocess.check_output(["lscpu"], text=True),
            binary_hashes={f"{m}-{k}": hashlib.sha256((build / f"{m}-{k}").read_bytes()).hexdigest()
                           for m in ("clone", "arc", "raw") for k in ("time", "memory")})
(out / "metadata.json").write_text(json.dumps(meta, indent=2))
for patch in ("arc.patch", "raw.patch"):
    (out / patch).write_text((build / patch).read_text())
rows = []
memory = []
rng = random.Random(1701)
print(f"Results: {out}", flush=True)

def run(case, mode, kind, label):
    perf = out / f"{label}-{case}-{mode}-{kind}.perf"
    command = ["taskset", "-c", str(args.cpu)]
    if kind == "time":
        command += ["perf", "stat", "-x", ";", "-o", str(perf), "-e",
                    "task-clock,context-switches,cpu-migrations,page-faults" if args.kernel
                    else "task-clock:u,context-switches:u,cpu-migrations:u,page-faults:u", "--"]
    command += [str(build / f"{mode}-{kind}"), str(build / f"{case}.o"), phase,
                str(args.iterations if kind == "time" else 1)]
    process = subprocess.run(command, text=True, capture_output=True)
    (out / f"{label}-{case}-{mode}-{kind}.log").write_text(process.stdout + process.stderr)
    if process.returncode:
        raise SystemExit(f"Failed {case}/{mode}/{phase}: {process.stdout}{process.stderr}\n"
                         + (perf.read_text() if perf.exists() else ""))
    prefix = "TIME" if kind == "time" else "MEM"
    line = next(line for line in process.stdout.splitlines() if line.startswith(prefix))
    values = {key: float(value) for key, value in re.findall(r"(\w+)=(-?[\d.]+)", line)}
    if kind == "time":
        assert values["programs"] == (1 if case == "single_small" else 32)
    else:
        assert values["after_drop"] == 0, "tracked allocations remain after dropping Ebpf"
    return dict(case=case, mode=mode, round=label, **values)

orders = list(itertools.permutations(("clone", "arc", "raw")))
for pair in range(args.pairs):
    order = cases.copy()
    rng.shuffle(order)
    for case in order:
        for mode in orders[pair % len(orders)]:
            rows.append(run(case, mode, "time", pair))
    (out / "timings.json").write_text(json.dumps(rows, indent=2))
    print(f"Timing round {pair + 1}/{args.pairs} complete", flush=True)
for repeat in range(3):
    for case in cases:
        for mode in ("clone", "arc", "raw"):
            memory.append(run(case, mode, "memory", repeat))
(out / "memory.json").write_text(json.dumps(memory, indent=2))
summary = []
for case in cases:
    per_mode = {m: [r for r in rows if r["case"] == case and r["mode"] == m] for m in ("clone", "arc", "raw")}
    mean = {m: statistics.mean(r["load_ns"] for r in per_mode[m]) for m in per_mode}
    summary.append(f"{case}: " + ", ".join(f"{m} {mean[m]:.1f} ns" for m in mean))
    for baseline, variant in (("clone", "arc"), ("clone", "raw"), ("arc", "raw")):
        pairs = list(zip(per_mode[baseline], per_mode[variant]))
        bootstrap = []
        for _ in range(10000):
            sample = rng.choices(pairs, k=len(pairs))
            a = sum(x[0]["load_ns"] for x in sample)
            b = sum(x[1]["load_ns"] for x in sample)
            bootstrap.append(100 * (b / a - 1))
        bootstrap.sort()
        summary.append(f"  {variant} vs {baseline}: {100*(mean[variant]/mean[baseline]-1):+.2f}% "
                       f"paired bootstrap 95% [{bootstrap[250]:+.2f}%, {bootstrap[9749]:+.2f}%]")
    for mode in ("clone", "arc", "raw"):
        samples = [r for r in memory if r['case'] == case and r['mode'] == mode]
        med = {k: statistics.median(r[k] for r in samples) for k in
               ("allocations", "allocated_bytes", "retained_bytes", "peak_bytes")}
        summary.append(f"  {mode} memory: {med}")
(out / "summary.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
