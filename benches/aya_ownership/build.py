"""Build identical real-Aya harnesses, changing only Function ownership."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "target/aya-attach-source"
PATCHED = ROOT / "target/aya-ownership-source"
RAW = ROOT / "target/aya-ownership-raw-source"
OUT = ROOT / "target/aya-ownership"
REV = "15593549d93cd39decf008f6d859fd054ba40bcf"

def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)

assert subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip() == REV
assert not subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain"], text=True).strip()
if not PATCHED.exists():
    shutil.copytree(SOURCE, PATCHED, ignore=shutil.ignore_patterns(".git", "target"))
OUT.mkdir(parents=True, exist_ok=True)

def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)

relative = Path("aya/src/bpf.rs")
text = (SOURCE / relative).read_text()
text = replace_once(text, "        let programs = obj\n", "        let mut shared_functions = HashMap::new();\n        let programs = obj\n")
text = replace_once(text,
    "                let function_obj = obj.functions[&prog_obj.function_key()].clone();",
    """                let function_obj = Arc::clone(shared_functions
                    .entry(prog_obj.function_key())
                    .or_insert_with(|| Arc::new(obj.functions
                        .remove(&prog_obj.function_key()).expect("program function"))));""")
(PATCHED / relative).write_text(text)
relative = Path("aya/src/programs/mod.rs")
text = (SOURCE / relative).read_text()
text = text.replace("(aya_obj::Program, aya_obj::Function)", "(aya_obj::Program, Arc<aya_obj::Function>)")
text = replace_once(text, "    let obj = obj.as_ref().unwrap();", "    let (program, function) = obj.as_ref().unwrap();\n    let obj = (program, function.as_ref());")
(PATCHED / relative).write_text(text)
patches = []
for relative in ("aya/src/bpf.rs", "aya/src/programs/mod.rs"):
    diff = subprocess.run(["diff", "-u", str(SOURCE / relative), str(PATCHED / relative)], text=True, capture_output=True)
    assert diff.returncode in (0, 1)
    patches.append(diff.stdout)
(OUT / "arc.patch").write_text("\n".join(patches))
(OUT / "revision.txt").write_text(REV + "\n")
(OUT / "rustc.txt").write_text(subprocess.check_output(["rustc", "--version"], text=True))

# Benchmark-only: retain the original BTreeMap unchanged after relocation.
# Moving its owner does not move heap nodes. Escaping programs is unsupported.
if not RAW.exists():
    shutil.copytree(SOURCE, RAW, ignore=shutil.ignore_patterns(".git", "target"))
relative = Path("aya/src/bpf.rs")
text = (SOURCE / relative).read_text()
text = replace_once(text,
    "                let function_obj = obj.functions[&prog_obj.function_key()].clone();",
    "                let function_obj: *const aya_obj::Function = &obj.functions[&prog_obj.function_key()];")
text = replace_once(text, "        Ok(Ebpf { maps, programs })",
    "        Ok(Ebpf { maps, programs, _owned_functions: obj.functions })")
text = replace_once(text, "    programs: HashMap<String, Program>,\n}",
    "    programs: HashMap<String, Program>,\n    // Immutable after pointers are taken; dropped after program wrappers.\n    _owned_functions: std::collections::BTreeMap<(usize, u64), aya_obj::Function>,\n}")
(RAW / relative).write_text(text)
relative = Path("aya/src/programs/mod.rs")
text = (SOURCE / relative).read_text().replace("(aya_obj::Program, aya_obj::Function)",
    "(aya_obj::Program, *const aya_obj::Function)")
text = replace_once(text, "    let obj = obj.as_ref().unwrap();",
    "    let (program, function) = obj.as_ref().unwrap();\n    // BENCHMARK ONLY: owner Ebpf must still be alive.\n    let obj = (program, unsafe { &**function });")
(RAW / relative).write_text(text)
patches = []
for relative in ("aya/src/bpf.rs", "aya/src/programs/mod.rs"):
    diff = subprocess.run(["diff", "-u", str(SOURCE / relative), str(RAW / relative)], text=True, capture_output=True)
    assert diff.returncode in (0, 1)
    patches.append(diff.stdout)
(OUT / "raw.patch").write_text("\n".join(patches))

# Valid compiled programs: 32 independent instructions sequences, or ELF aliases
# pointing to one function. Volatile stack arithmetic prevents constant folding.
for name, count, aliases, steps, mapped in [
    ("single_small", 1, False, 0, False),
    ("unique_32_small", 32, False, 0, False),
    ("aliases_32_small", 32, True, 0, False),
    ("unique_32_large", 32, False, 256, False),
    ("aliases_32_large", 32, True, 256, False),
    ("counter_32", 32, False, 0, True),
]:
    source = 'typedef unsigned int u32; typedef unsigned long long u64;\n'
    if mapped:
        source += '''struct map_def { u32 type, key_size, value_size, max_entries, flags; };
__attribute__((section("maps"), used)) struct map_def counts = {2,4,8,32,0};
static void *(*const lookup)(void *, const void *) = (void *)1;
'''
    for i in range(count):
        if aliases and i:
            source += f'extern int program_{i}(void *ctx) __attribute__((alias("program_0")));\n'
            continue
        body = ''
        if steps:
            body += 'volatile u64 value = 1;\n'
            for j in range(steps):
                body += f'value = (value * 33) ^ {j + 1};\n'
        if mapped:
            body += f'u32 key = {i}; u64 *v = lookup(&counts, &key); if (v) __sync_fetch_and_add(v, 1);\n'
        source += f'__attribute__((section("tracepoint/sched/sched_switch"), used)) int program_{i}(void *ctx) {{ {body} return 0; }}\n'
    source += '__attribute__((section("license"), used)) char program_license[] = "GPL";\n'
    c = OUT / f"{name}.c"
    c.write_text(source)
    run("clang", "-target", "bpfel", "-O2", "-c", str(c), "-o", str(OUT / f"{name}.o"))

for mode, source in (("clone", SOURCE), ("arc", PATCHED), ("raw", RAW)):
    project = OUT / mode
    project.mkdir(exist_ok=True)
    (project / "Cargo.toml").write_text(f'''[package]
name = "aya-ownership-bench"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
alloc-stats = []
[dependencies]
aya = {{ path = "{source / 'aya'}" }}
[[bin]]
name = "aya-ownership-bench"
path = "{ROOT / 'benches/aya_ownership/main.rs'}"
''')
    shutil.copyfile(ROOT / "target/aya-attach-benchmark/aya/Cargo.lock", project / "Cargo.lock")
    for kind in ("time", "memory"):
        command = ["cargo", "build", "--offline", "--release", "--manifest-path", str(project / "Cargo.toml")]
        if kind == "memory":
            command += ["--features", "alloc-stats"]
        run(*command)
        shutil.copyfile(project / "target/release/aya-ownership-bench", OUT / f"{mode}-{kind}")
        (OUT / f"{mode}-{kind}").chmod(0o755)
assert (OUT / "clone/Cargo.lock").read_bytes() == (OUT / "arc/Cargo.lock").read_bytes() == (OUT / "raw/Cargo.lock").read_bytes()
print(f"Built in {OUT}")
