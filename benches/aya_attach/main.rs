use aya::{Ebpf, programs::TracePoint};
use std::{error::Error, hint::black_box, time::{Duration, Instant}};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: aya-attach-bench <bpf-object> <iterations> <warmup>".into());
    }
    let count: u64 = args[2].parse()?;
    let warmup: u64 = args[3].parse()?;
    if count == 0 { return Err("iterations must be positive".into()); }
    let mut bpf = Ebpf::load_file(&args[1])?;
    let program: &mut TracePoint = bpf.program_mut("bench_tracepoint")
        .ok_or("missing benchmark program")?.try_into()?;
    program.load()?;

    // Warm caches and Aya's lazy feature detection before measuring.
    for _ in 0..warmup {
        let link = program.attach("sched", "sched_switch")?;
        program.detach(link)?;
    }

    let mut attach_time = Duration::ZERO;
    let total_start = Instant::now();
    for _ in 0..count {
        let start = Instant::now();
        let link = black_box(program.attach("sched", "sched_switch")?);
        attach_time += start.elapsed();
        // Detach is deliberately outside the attachment timer.
        program.detach(link)?;
    }
    println!("iterations={count} attach_ns_per_op={:.3} loop_seconds={:.6}",
        attach_time.as_nanos() as f64 / count as f64,
        total_start.elapsed().as_secs_f64());
    Ok(())
}
