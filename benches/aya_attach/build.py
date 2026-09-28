"""Build original and patched Aya at an identical, pinned revision."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "target/aya-attach-source"
FIXED = ROOT / "target/aya-attach-fixed-source"
OUT = ROOT / "target/aya-attach-benchmark"
REV = "15593549d93cd39decf008f6d859fd054ba40bcf"

def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)

if not SOURCE.exists():
    run("git", "clone", "https://github.com/aya-rs/aya.git", str(SOURCE))
    run("git", "-C", str(SOURCE), "checkout", "--detach", REV)
actual = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip()
if actual != REV:
    raise SystemExit(f"Expected Aya {REV}; found {actual}")
if subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain"], text=True).strip():
    raise SystemExit("Original Aya checkout must be clean")
if not FIXED.exists():
    shutil.copytree(SOURCE, FIXED, ignore=shutil.ignore_patterns(".git", "target"))

relative = Path("aya/src/programs/trace_point.rs")
original = (SOURCE / relative).read_text()
start = original.index("    let id = match fs::read_to_string(&filename)")
end = original.index("\n    Ok(id)", start)
# Extract the exact current reader; retain Aya's filename-bearing error wrapper.
samurai = (ROOT / "src/utils/tracepoint.rs").read_text()
reader = samurai[samurai.index("fn read_id("):samurai.index("#[cfg(test)]")]
patched = original[:start] + '''    let id = fs::File::open(&filename)
        .and_then(read_id)
        .map_err(|io_error| TracePointError::FileError { filename, io_error })?;
''' + original[end:]
patched += "\nuse std::io::Read;\n\n" + reader
(FIXED / relative).write_text(patched)
OUT.mkdir(parents=True, exist_ok=True)
diff = subprocess.run(["diff", "-u", str(SOURCE / relative), str(FIXED / relative)],
                      capture_output=True, text=True)
if diff.returncode not in (0, 1):
    raise SystemExit(diff.stderr)
(OUT / "reader.patch").write_text(diff.stdout)
(OUT / "revision.txt").write_text(REV + "\n")
run("clang", "-target", "bpf", "-O2", "-c", str(ROOT / "benches/aya_attach/program.c"),
    "-o", str(OUT / "program.o"))

for mode, source in (("aya", SOURCE), ("fixed", FIXED)):
    project = OUT / mode
    project.mkdir(exist_ok=True)
    (project / "Cargo.toml").write_text(f'''[package]
name = "aya-attach-bench"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
aya = {{ path = "{source / 'aya'}" }}
[[bin]]
name = "aya-attach-bench"
path = "{ROOT / 'benches/aya_attach/main.rs'}"
''')
    if mode == "fixed":
        shutil.copyfile(OUT / "aya/Cargo.lock", project / "Cargo.lock")
    command = ["cargo", "build", "--release", "--manifest-path", str(project / "Cargo.toml")]
    if mode == "fixed":
        command.append("--locked")
    run(*command)
    shutil.copyfile(project / "target/release/aya-attach-bench", OUT / f"{mode}-attach")
    (OUT / f"{mode}-attach").chmod(0o755)
print(f"Built both variants in {OUT}")
