use samurai::{
    aggregate::AggregateSchedulerRecorder, bpf::object::ObjectLoader,
    utils::tracepoint::TracepointResolver,
};
use std::{cmp::Reverse, io, time::Duration};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: record <aggregate-object.o> [seconds=10]; record <object.o> --check",
        ));
    }
    let loader = ObjectLoader::from_file(&args[0])?;
    if args.get(1).is_some_and(|argument| argument == "--check") {
        println!("programs: {:?}", loader.program_names().collect::<Vec<_>>());
        println!("maps: {:?}", loader.map_names().collect::<Vec<_>>());
        return Ok(());
    }
    let seconds = args
        .get(1)
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(10);

    let loaded = loader.load()?;
    let program = loaded.program("aggregate_switch").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "aggregate_switch program not found",
        )
    })?;
    let tasks = loaded
        .lru_per_cpu_hash("tasks")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tasks map not found"))?;
    let records = loaded
        .per_cpu_map("records")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "records map not found"))?;

    let recording = AggregateSchedulerRecorder::new(program, tasks, records)?
        .record(&TracepointResolver::new(), Duration::from_secs(seconds))?;
    println!(
        "kernel_records={} retained_records={} evicted_records={} seconds={seconds}",
        recording.kernel_records(),
        recording.retained_records(),
        recording.evicted_records(),
    );

    let profile = recording.profile();
    let mut ranked: Vec<_> = profile.tasks().map(|(pid, stats)| (pid, *stats)).collect();
    ranked.sort_unstable_by_key(|task| Reverse(task.1.runtime_ns));
    println!("PID       CPU%   RUNTIME_MS  IN       OUT      VOL      INVOL");
    for (pid, stats) in ranked.into_iter().take(20) {
        println!(
            "{pid:<9} {:>6.2} {:>11.3} {:>8} {:>8} {:>8} {:>8}",
            stats.runtime_ns as f64 * 100.0 / (seconds as f64 * 1_000_000_000.0),
            stats.runtime_ns as f64 / 1_000_000.0,
            stats.switches_in,
            stats.switches_out,
            stats.voluntary_switches,
            stats.involuntary_switches,
        );
    }
    Ok(())
}
