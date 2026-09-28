use samurai::{
    bpf::object::ObjectLoader,
    profile::SchedulerProfile,
    record::{ContextSwitchRecord, RingBufferRecorder},
    utils::{affinity::pin_current_thread, tracepoint::TracepointResolver},
};
use std::{
    cmp::Reverse,
    io,
    time::{Duration, Instant},
};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: raw_record <object.o> [seconds=2] [consumer-cpu] [task-capacity=16384]; raw_record <object.o> --check",
        ));
    }
    let loader = ObjectLoader::from_file(&args[0])?;
    if args.len() == 2 && args[1] == "--check" {
        println!("programs: {:?}", loader.program_names().collect::<Vec<_>>());
        println!("maps: {:?}", loader.map_names().collect::<Vec<_>>());
        return Ok(());
    }

    let seconds: u64 = args
        .get(1)
        .map(|value| value.parse())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(2);
    let consumer_cpu: Option<usize> = args
        .get(2)
        .map(|value| value.parse())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let task_capacity: usize = args
        .get(3)
        .map(|value| value.parse())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(16_384);
    if seconds == 0 || task_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seconds and task capacity must be positive",
        ));
    }
    if let Some(cpu) = consumer_cpu {
        pin_current_thread(cpu)?;
    }

    let loaded = loader.load()?;
    let program = loaded.program("record_switch").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "record_switch program not found")
    })?;
    let events = loaded
        .ring_buffer("events")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "events ring buffer not found"))?;
    let dropped = loaded
        .per_cpu_map("dropped")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dropped map not found"))?;
    let consumer_tids = loaded
        .map("consumer_tids")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "consumer_tids map not found"))?;
    let mut excluded = [0u8; 16];
    let tid = u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
        .map_err(|_| io::Error::other("consumer TID is outside u32 range"))?;
    excluded[..4].copy_from_slice(&tid.to_ne_bytes());
    consumer_tids.write(0, &excluded)?;
    let cpu_count = dropped.cpu_count();
    let mut dropped_by_cpu = vec![0; cpu_count];
    let mut profile = SchedulerProfile::with_capacity(task_capacity, cpu_count)?;
    let mut samples: [Option<ContextSwitchRecord>; 8] = [None; 8];
    let mut sample_count = 0usize;
    let mut recorder = RingBufferRecorder::new(events)?;
    let attachment = program.attach(&TracepointResolver::new(), "sched", "sched_switch")?;
    let deadline = Instant::now() + Duration::from_secs(seconds);

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        recorder.poll(remaining)?;
        recorder.consume_available(|event| {
            profile.observe(event)?;
            if sample_count < samples.len() {
                samples[sample_count] = Some(event);
                sample_count += 1;
            }
            Ok(())
        })?;
    }
    drop(attachment);
    while recorder.consume_available(|event| profile.observe(event))? != 0 {}

    for event in samples.into_iter().flatten() {
        println!(
            "{} CPU {}: {} -> {} runtime={} ns state={}",
            event.timestamp_ns,
            event.cpu,
            event.previous_pid,
            event.next_pid,
            event.runtime_ns,
            event.previous_state
        );
    }

    let received = profile.records();
    dropped.read_u64(0, &mut dropped_by_cpu)?;
    let dropped: u64 = dropped_by_cpu.iter().sum();
    let produced = received + dropped;
    let observed_cpus = profile
        .cpus()
        .iter()
        .filter(|stats| stats.records != 0)
        .count();
    let loss = if produced == 0 {
        0.0
    } else {
        dropped as f64 * 100.0 / produced as f64
    };
    let affinity = consumer_cpu
        .map(|cpu| cpu.to_string())
        .unwrap_or_else(|| "unbound".to_owned());
    println!(
        "received={received} dropped={dropped} produced={produced} loss={loss:.2}% records/s={:.0} cpus={observed_cpus} consumer_cpu={affinity}",
        produced as f64 / seconds as f64
    );

    let mut tasks: Vec<_> = profile.tasks().map(|(pid, stats)| (pid, *stats)).collect();
    tasks.sort_unstable_by_key(|task| Reverse(task.1.runtime_ns));
    println!(
        "PID       CPU%   RUNTIME_MS  IN       OUT      VOL      INVOL    AVG_SLICE_US MAX_SLICE_US"
    );
    for (pid, stats) in tasks.into_iter().take(20) {
        let cpu_percent = stats.runtime_ns as f64 * 100.0 / (seconds as f64 * 1_000_000_000.0);
        println!(
            "{pid:<9} {cpu_percent:>6.2} {:>11.3} {:>8} {:>8} {:>8} {:>8} {:>12.3} {:>12.3}",
            stats.runtime_ns as f64 / 1_000_000.0,
            stats.switches_in,
            stats.switches_out,
            stats.voluntary_switches,
            stats.involuntary_switches,
            stats.average_timeslice_ns() as f64 / 1_000.0,
            stats.max_timeslice_ns as f64 / 1_000.0,
        );
    }
    Ok(())
}
