use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=examples/bpf/generic_tracepoint.c");
    println!("cargo:rerun-if-changed=examples/bpf/mold.h");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=SAMURAI_MOLD_LANES");
    println!("cargo:rerun-if-env-changed=SAMURAI_MOLD_CAPACITY");

    let lanes = env::var("SAMURAI_MOLD_LANES").unwrap_or_else(|_| "8".to_owned());
    let capacity = env::var("SAMURAI_MOLD_CAPACITY").unwrap_or_else(|_| "16384".to_owned());
    let lanes_value = lanes
        .parse::<usize>()
        .expect("SAMURAI_MOLD_LANES must be a positive integer");
    let capacity_value = capacity
        .parse::<usize>()
        .expect("SAMURAI_MOLD_CAPACITY must be a positive integer");
    assert!(
        lanes_value > 0,
        "SAMURAI_MOLD_LANES must be greater than zero"
    );
    assert!(
        capacity_value.is_power_of_two(),
        "SAMURAI_MOLD_CAPACITY must be a power of two"
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"))
        .join("generic-tracepoint.bpf.o");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(clang)
        .args([
            "-target",
            "bpfel",
            "-mcpu=v3",
            "-O2",
            "-I",
            "examples/bpf",
            &format!("-DMOLD_LANES={lanes_value}"),
            &format!("-DMOLD_CAPACITY={capacity_value}"),
            "-c",
            "examples/bpf/generic_tracepoint.c",
            "-o",
        ])
        .arg(&output)
        .status()
        .expect("building Samurai requires clang with a BPF target");
    assert!(
        status.success(),
        "clang failed to build the generic BPF reader"
    );
}
