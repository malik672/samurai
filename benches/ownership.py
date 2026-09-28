"""Run after cargo test --release --lib --no-run --message-format=json > target/ownership-build.json."""
import json
import os
from pathlib import Path
import statistics
import itertools
import time
import subprocess

root = Path(__file__).resolve().parents[1]
os.chdir(root)
artifacts = [json.loads(line) for line in Path("target/ownership-build.json").read_text().splitlines()]
binary = next(a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact"
              and a.get("target", {}).get("name") == "samurai" and a.get("executable"))
out = Path(f"target/ownership-results-{time.time_ns()}")
out.mkdir(exist_ok=True)
rows = []
orders = list(itertools.permutations(("clone", "arc", "borrow")))
for pair in range(12):
    for mode in orders[pair % len(orders)]:
        perf = out / f"{pair}-{mode}.perf"
        result = subprocess.run([
            "taskset", "-c", "5", "perf", "stat", "-x", ";", "-o", str(perf),
            "-e", "task-clock:u,context-switches:u,cpu-migrations:u,page-faults:u", "--",
            binary, "bpf::object::tests::benchmark_function_ownership", "--exact", "--ignored",
            "--nocapture", "--test-threads=1",
        ], env={**os.environ, "SAMURAI_OWNERSHIP_MODE": mode}, text=True, capture_output=True)
        (out / f"{pair}-{mode}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr + perf.read_text())
        for line in result.stdout.splitlines():
            if "OWNERSHIP " in line:
                label, variant, ns = line.split("OWNERSHIP ", 1)[1].split()
                rows.append(dict(pair=pair, case=label, mode=variant, ns=float(ns)))
        print(f"pair {pair + 1}: {mode} complete", flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2))
summary = []
for label in dict.fromkeys(r["case"] for r in rows):
    medians = {m: statistics.median(r["ns"] for r in rows if r["case"] == label and r["mode"] == m)
               for m in ("clone", "arc", "borrow")}
    summary.append(f"{label}: clone={medians['clone']:.1f} ns, arc={medians['arc']:.1f} ns, "
                   f"borrow={medians['borrow']:.1f} ns; "
                   f"borrow vs clone={(medians['borrow'] / medians['clone'] - 1) * 100:+.1f}%; "
                   f"borrow vs arc={(medians['borrow'] / medians['arc'] - 1) * 100:+.1f}%")

(out / "summary.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))

print(f"Raw results: {out}")
