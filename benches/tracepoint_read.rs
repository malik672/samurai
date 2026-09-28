//! Standalone benchmark: rustc --edition=2024 -O benches/tracepoint_read.rs -o target/tracepoint-read-bench
//! Usage: tracepoint-read-bench <aya|fixed> <id-file> <iterations>
//! Measures open/read/parse/close, excluding path construction and mount discovery.
use std::{fs, hint::black_box, io, path::Path, time::Instant};

// The included production file ends with its tests; this benchmark-only shim
// adds one adapter afterward so the private parser can be measured directly.
#[allow(dead_code, clippy::items_after_test_module)]
mod current {
    include!("../src/utils/tracepoint.rs");

    pub fn read(path: &std::path::Path) -> std::io::Result<u64> {
        read_id(std::fs::File::open(path)?)
    }
}

// Aya's successful read/parse path, with errors mapped to std::io::Error.
// https://github.com/aya-rs/aya/blob/main/aya/src/programs/trace_point.rs
// Aya's MIT notice is in LICENSES/aya-MIT.txt.
fn aya(path: &Path) -> io::Result<u64> {
    let text = fs::read_to_string(path)?;
    text.trim().parse().map_err(io::Error::other)
}

fn measure(read: impl Fn(&Path) -> io::Result<u64>, path: &Path, count: u64) -> io::Result<()> {
    let expected = read(path)?;
    for _ in 0..10_000 {
        black_box(read(black_box(path))?);
    }
    let start = Instant::now();
    let mut checksum = 0u64;
    for _ in 0..count {
        checksum = checksum.wrapping_add(black_box(read(black_box(path))?));
    }
    let elapsed = start.elapsed();
    assert_eq!(checksum, expected.wrapping_mul(count));
    println!(
        "iterations={count} ns_per_op={:.3} checksum={checksum}",
        elapsed.as_nanos() as f64 / count as f64
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 4, "expected mode, path, iterations");
    let path = Path::new(&args[2]);
    let count: u64 = args[3].parse().expect("invalid iterations");
    assert!(count > 0);
    match args[1].as_str() {
        "aya" => measure(aya, path, count),
        "fixed" => measure(current::read, path, count),
        _ => panic!("expected aya or fixed"),
    }
}
