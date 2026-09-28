"""Run from the repository root after compiling tracepoint_read.rs."""
import json
from pathlib import Path
import re
import statistics
import subprocess

out = Path("target/tracepoint-benchmark")
out.mkdir(exist_ok=True)
fixture = out / "id"
fixture.write_text("1234\n")
results = []
for pair in range(12):
    order = ("aya", "fixed") if pair % 2 == 0 else ("fixed", "aya")
    for mode in order:
        perf_file = out / f"{pair:02d}-{mode}.perf.csv"
        command = [
            "taskset", "-c", "5", "perf", "stat", "-x", ";",
            "-o", str(perf_file), "-e",
            "task-clock:u,context-switches:u,cpu-migrations:u,page-faults:u",
            "--", "target/tracepoint-read-bench", mode, str(fixture), "500000",
        ]
        run = subprocess.run(command, text=True, capture_output=True, check=True)
        ns = float(re.search(r"ns_per_op=([\d.]+)", run.stdout)[1])
        results.append({"pair": pair, "mode": mode, "ns_per_op": ns,
                        "stdout": run.stdout, "perf": perf_file.read_text()})
        print(f"{pair:02d} {mode}: {ns:.3f} ns/op", flush=True)
(out / "results.json").write_text(json.dumps(results, indent=2))
for mode in ("aya", "fixed"):
    values = [row["ns_per_op"] for row in results if row["mode"] == mode]
    print(f"{mode}: median={statistics.median(values):.3f}, "
          f"min={min(values):.3f}, max={max(values):.3f} ns/op")
