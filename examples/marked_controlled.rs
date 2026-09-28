use samurai::{
    bpf::{map::MappedArray, object::ObjectLoader},
    utils::{
        affinity::{parse_cpu_list, pin_current_thread},
        tracepoint::TracepointResolver,
    },
};
use std::{
    hint::black_box,
    io,
    sync::{
        Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering, fence},
    },
    thread,
    time::Instant,
};

const CONSUMER_MARK_INTERVAL: u64 = 128;

#[repr(C)]
struct Slot {
    mark: AtomicU64,
    kind: u64,
    words: [u64; 6],
}

#[repr(C)]
struct Frontier {
    producer_mark: AtomicU64,
    producer_padding: [u64; 7],
    consumer_mark: AtomicU64,
    consumer_padding: [u64; 7],
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: marked_controlled <object> <calls-per-producer> <producer-cpus> <consumer-cpus>",
        ));
    }
    let calls: u64 = args[1].parse().map_err(invalid)?;
    let producer_cpus = parse_cpu_list(&args[2])?;
    let consumer_cpus = parse_cpu_list(&args[3])?;
    if producer_cpus.is_empty() || consumer_cpus.len() < producer_cpus.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "each producer CPU needs a consumer CPU",
        ));
    }

    let loaded = ObjectLoader::from_file(&args[0])?.load()?;
    let slots = loaded.map("slots").ok_or_else(|| missing("slots"))?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?;
    let target = loaded.map("target").ok_or_else(|| missing("target"))?;
    let program = loaded
        .program("controlled_marked")
        .ok_or_else(|| missing("controlled_marked"))?;
    target.write(0, &std::process::id().to_ne_bytes())?;
    let slots = slots.mmap()?;
    let frontiers = frontiers.mmap()?;
    if slots.value_size() != size_of::<Slot>() || frontiers.value_size() != 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected marked mold ABI",
        ));
    }
    let lanes = frontiers.entries();
    if lanes == 0 || slots.entries() % lanes != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "slot count is not divisible by the fixed lane count",
        ));
    }
    let capacity = slots.entries() / lanes;
    if capacity == 0 || !capacity.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lane capacity must be a non-zero power of two",
        ));
    }
    if producer_cpus.iter().any(|cpu| *cpu >= lanes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "producer CPU has no corresponding Mold lane",
        ));
    }

    let stop = AtomicBool::new(false);
    let start =
        Barrier::new(producer_cpus.len() + consumer_cpus.len().min(producer_cpus.len()) + 1);
    let attachment = program.attach(&TracepointResolver::new(), "syscalls", "sys_enter_getpid")?;
    let mut results = Vec::new();
    let mut producer_seconds = 0.0;
    thread::scope(|scope| -> io::Result<()> {
        let consumers: Vec<_> = producer_cpus
            .iter()
            .copied()
            .zip(consumer_cpus.iter().copied())
            .map(|(lane_cpu, worker_cpu)| {
                let slots = &slots;
                let frontiers = &frontiers;
                let stop = &stop;
                let start = &start;
                scope.spawn(move || {
                    consume_lane(
                        slots, frontiers, capacity, lane_cpu, worker_cpu, stop, start,
                    )
                })
            })
            .collect();
        let producers: Vec<_> = producer_cpus
            .iter()
            .copied()
            .map(|cpu| {
                let start = &start;
                scope.spawn(move || -> io::Result<()> {
                    pin_current_thread(cpu)?;
                    start.wait();
                    for _ in 0..calls {
                        black_box(unsafe { libc::syscall(libc::SYS_getpid) });
                    }
                    Ok(())
                })
            })
            .collect();
        let wall = Instant::now();
        start.wait();
        for producer in producers {
            producer
                .join()
                .map_err(|_| io::Error::other("producer panicked"))??;
        }
        producer_seconds = wall.elapsed().as_secs_f64();
        drop(attachment);
        stop.store(true, Ordering::Release);
        for consumer in consumers {
            results.push(
                consumer
                    .join()
                    .map_err(|_| io::Error::other("consumer panicked"))??,
            );
        }
        Ok(())
    })?;
    let received: u64 = results.iter().map(|r| r.received).sum();
    let gaps: u64 = results.iter().map(|r| r.gaps).sum();
    let cpu_ns: u64 = results.iter().map(|r| r.cpu_ns).sum();
    let max_backlog = results.iter().map(|r| r.max_backlog).max().unwrap_or(0);
    let worst = results
        .iter()
        .max_by_key(|result| result.max_backlog)
        .expect("at least one consumer");
    let worst_pause = results
        .iter()
        .max_by_key(|result| result.max_checkpoint_offcpu_ns)
        .expect("at least one consumer");
    let checksum: u64 = results
        .iter()
        .map(|r| r.checksum)
        .fold(0, u64::wrapping_add);
    let requested = calls * producer_cpus.len() as u64;
    println!(
        "mode=marked producers={} calls_per_producer={calls} requested={requested} received={received} dropped={gaps} unaccounted={} loss_pct={:.4} producer_seconds={producer_seconds:.6} requested_per_second={:.0} consumer_cpu_ms={:.3} lanes={lanes} capacity={capacity} map_bytes={} max_backlog={max_backlog} worst_lane={} worst_worker={} worst_involuntary={} worst_wall_ms={:.3} worst_cpu_ms={:.3} max_checkpoint_offcpu_ms={:.3} pause_lane={} pause_worker={} consumer_mark_interval={CONSUMER_MARK_INTERVAL} checksum={checksum}",
        producer_cpus.len(),
        requested.abs_diff(received + gaps),
        gaps as f64 * 100.0 / requested.max(1) as f64,
        requested as f64 / producer_seconds,
        cpu_ns as f64 / 1_000_000.0,
        slots.entries() * slots.value_size(),
        worst.lane_cpu,
        worst.worker_cpu,
        worst.involuntary,
        worst.wall_ns as f64 / 1_000_000.0,
        worst.cpu_ns as f64 / 1_000_000.0,
        worst_pause.max_checkpoint_offcpu_ns as f64 / 1_000_000.0,
        worst_pause.lane_cpu,
        worst_pause.worker_cpu,
    );
    Ok(())
}

struct Result {
    received: u64,
    gaps: u64,
    cpu_ns: u64,
    checksum: u64,
    max_backlog: u64,
    lane_cpu: usize,
    worker_cpu: usize,
    involuntary: i64,
    wall_ns: u64,
    max_checkpoint_offcpu_ns: u64,
}

fn consume_lane(
    slots: &MappedArray<'_>,
    frontiers: &MappedArray<'_>,
    capacity: usize,
    lane_cpu: usize,
    worker_cpu: usize,
    stop: &AtomicBool,
    start: &Barrier,
) -> io::Result<Result> {
    pin_current_thread(worker_cpu)?;
    let frontier = frontiers.value_ptr(lane_cpu)?.cast::<Frontier>();
    let frontier = unsafe { frontier.as_ref() };
    let mut expected = 1u64;
    let (mut received, mut gaps, mut checksum) = (0u64, 0u64, 0u64);
    let mut max_backlog = 0u64;
    start.wait();
    let wall_start = Instant::now();
    let cpu_start = thread_cpu_ns();
    let mut checkpoint_wall_ns = 0;
    let mut checkpoint_cpu_ns = cpu_start;
    let mut max_checkpoint_offcpu_ns = 0;
    let usage_start = thread_usage();
    loop {
        let published = frontier.producer_mark.load(Ordering::Acquire);
        if expected <= published {
            max_backlog = max_backlog.max(published - (expected - 1));
            let oldest = published.saturating_sub(capacity as u64 - 1).max(1);
            if expected < oldest {
                gaps += oldest - expected;
                expected = oldest;
                frontier
                    .consumer_mark
                    .store(expected - 1, Ordering::Release);
            }
            let index = lane_cpu * capacity + ((expected - 1) & (capacity as u64 - 1)) as usize;
            let slot = slots.value_ptr(index)?.cast::<Slot>();
            let slot = unsafe { slot.as_ref() };
            let first = slot.mark.load(Ordering::Acquire);
            if first == expected {
                let words = unsafe { std::ptr::read_volatile(&raw const slot.words) };
                fence(Ordering::Acquire);
                if slot.mark.load(Ordering::Acquire) == first {
                    checksum = checksum.wrapping_add(words[0]);
                    received += 1;
                    expected += 1;
                    if received % CONSUMER_MARK_INTERVAL == 0 {
                        frontier
                            .consumer_mark
                            .store(expected - 1, Ordering::Release);
                        let wall_ns = wall_start.elapsed().as_nanos() as u64;
                        let cpu_ns = thread_cpu_ns();
                        max_checkpoint_offcpu_ns = max_checkpoint_offcpu_ns.max(
                            (wall_ns - checkpoint_wall_ns)
                                .saturating_sub(cpu_ns - checkpoint_cpu_ns),
                        );
                        checkpoint_wall_ns = wall_ns;
                        checkpoint_cpu_ns = cpu_ns;
                    }
                    continue;
                }
            } else if first > expected {
                continue;
            }
        }
        if stop.load(Ordering::Acquire) && expected > published {
            break;
        }
        std::hint::spin_loop();
    }
    frontier
        .consumer_mark
        .store(expected - 1, Ordering::Release);
    let usage_end = thread_usage();
    let wall_ns = wall_start.elapsed().as_nanos() as u64;
    let cpu_ns = thread_cpu_ns();
    max_checkpoint_offcpu_ns = max_checkpoint_offcpu_ns
        .max((wall_ns - checkpoint_wall_ns).saturating_sub(cpu_ns - checkpoint_cpu_ns));
    Ok(Result {
        received,
        gaps,
        cpu_ns: cpu_ns - cpu_start,
        checksum,
        max_backlog,
        lane_cpu,
        worker_cpu,
        involuntary: usage_end.ru_nivcsw - usage_start.ru_nivcsw,
        wall_ns,
        max_checkpoint_offcpu_ns,
    })
}

fn thread_usage() -> libc::rusage {
    let mut usage = unsafe { std::mem::zeroed() };
    unsafe {
        libc::getrusage(libc::RUSAGE_THREAD, &raw mut usage);
    }
    usage
}

fn thread_cpu_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut t);
    }
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
fn invalid(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}
