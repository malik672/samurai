use samurai::{
    bpf::{map::MappedArray, object::ObjectLoader},
    tracepoint_schema::parse_format,
    utils::{
        affinity::{parse_cpu_list, pin_current_thread},
        tracepoint::TracepointResolver,
    },
};
use std::{
    ffi::CString,
    fs::File,
    hint::black_box,
    io,
    os::fd::AsRawFd,
    sync::{
        Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering, fence},
    },
    thread,
    time::Instant,
};

const CONSUMER_MARK_INTERVAL: u64 = 128;

#[repr(C)]
struct Frontier {
    producer_mark: AtomicU64,
    producer_padding: [u64; 7],
    consumer_mark: AtomicU64,
    consumer_padding: [u64; 7],
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: dynamic_controlled <string|bytes> <object> <calls-per-producer> <producer-cpus> <consumer-cpus>",
        ));
    }
    let (mode, event, pointer_field, length_field, program_name, mode_id) = match args[0].as_str() {
        "string" => (
            "string",
            "sys_enter_openat",
            "filename",
            None,
            "controlled_string",
            1u32,
        ),
        "bytes" => (
            "bytes",
            "sys_enter_write",
            "buf",
            Some("count"),
            "controlled_bytes",
            2u32,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mode must be string or bytes",
            ));
        }
    };
    let calls: u64 = args[2].parse().map_err(invalid)?;
    let measure_latency = std::env::var_os("BENCH_LATENCY").is_some();
    let pause_every = env_u64("BENCH_PAUSE_EVERY")?;
    let pause_us = env_u64("BENCH_PAUSE_US")?;
    let producer_cpus = parse_cpu_list(&args[3])?;
    let consumer_cpus = parse_cpu_list(&args[4])?;
    if producer_cpus.is_empty()
        || (consumer_cpus.len() != 1 && consumer_cpus.len() < producer_cpus.len())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use one shared consumer CPU or one consumer CPU per producer",
        ));
    }

    let resolver = TracepointResolver::new();
    let fields = parse_format(&resolver.format("syscalls", event)?)?;
    let offset = |name: &str| -> io::Result<u32> {
        let value = fields
            .iter()
            .find(|field| field.name == name)
            .ok_or_else(|| missing(name))?
            .offset;
        u32::try_from(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "field offset exceeds u32"))
    };
    let pointer_offset = offset(pointer_field)?;
    let length_offset = length_field.map(offset).transpose()?.unwrap_or(0);
    let loaded = ObjectLoader::from_file(&args[1])?.load()?;
    let slots = loaded.map("slots").ok_or_else(|| missing("slots"))?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?;
    let config = loaded.map("config").ok_or_else(|| missing("config"))?;
    let mut config_value = [0u8; 20];
    config_value[..4].copy_from_slice(&std::process::id().to_ne_bytes());
    config_value[4..8].copy_from_slice(&pointer_offset.to_ne_bytes());
    config_value[8..12].copy_from_slice(&length_offset.to_ne_bytes());
    config_value[12..16].copy_from_slice(&mode_id.to_ne_bytes());
    config.write(0, &config_value)?;
    let slots = slots.mmap()?;
    let frontiers = frontiers.mmap()?;
    if slots.value_size() < 3 * size_of::<u64>() || frontiers.value_size() != 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected dynamic Mold ABI",
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
    let _attachments = producer_cpus
        .iter()
        .map(|&cpu| {
            let name = format!("{program_name}_cpu{cpu}");
            loaded
                .program(&name)
                .ok_or_else(|| missing(&name))?
                .attach_to_cpu(&resolver, "syscalls", event, cpu)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let path = CString::new("/dev/null").unwrap();
    let sink = File::options().write(true).open("/dev/null")?;
    let payload = [0x5au8; 128];
    let mut results = Vec::new();
    let mut producer_seconds = 0.0;
    thread::scope(|scope| -> io::Result<()> {
        let shared_consumer = (consumer_cpus.len() == 1).then(|| {
            let lane_cpus = &producer_cpus;
            let worker_cpu = consumer_cpus[0];
            let slots = &slots;
            let frontiers = &frontiers;
            let stop = &stop;
            let start = &start;
            scope.spawn(move || {
                consume_lanes(
                    slots,
                    frontiers,
                    capacity,
                    lane_cpus,
                    worker_cpu,
                    stop,
                    start,
                    measure_latency,
                    pause_every,
                    pause_us,
                    calls,
                )
            })
        });
        let consumers: Vec<_> = if shared_consumer.is_none() {
            producer_cpus
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
                            slots,
                            frontiers,
                            capacity,
                            lane_cpu,
                            worker_cpu,
                            stop,
                            start,
                            measure_latency,
                            pause_every,
                            pause_us,
                            calls,
                        )
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let producers: Vec<_> = producer_cpus
            .iter()
            .copied()
            .map(|cpu| {
                let start = &start;
                let path = &path;
                let sink = &sink;
                let payload = &payload;
                scope.spawn(move || -> io::Result<()> {
                    pin_current_thread(cpu)?;
                    start.wait();
                    for _ in 0..calls {
                        if mode_id == 1 {
                            let fd = unsafe {
                                libc::syscall(
                                    libc::SYS_openat,
                                    libc::AT_FDCWD,
                                    path.as_ptr(),
                                    libc::O_RDONLY,
                                    0,
                                )
                            };
                            if fd >= 0 {
                                unsafe { libc::close(fd as i32) };
                            }
                            black_box(fd);
                        } else {
                            black_box(unsafe {
                                libc::write(
                                    sink.as_raw_fd(),
                                    payload.as_ptr().cast(),
                                    payload.len(),
                                )
                            });
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        config_value[16..20].copy_from_slice(&1u32.to_ne_bytes());
        config.write(0, &config_value)?;
        let wall = Instant::now();
        start.wait();
        for producer in producers {
            producer
                .join()
                .map_err(|_| io::Error::other("producer panicked"))??;
        }
        producer_seconds = wall.elapsed().as_secs_f64();
        config_value[16..20].copy_from_slice(&0u32.to_ne_bytes());
        config.write(0, &config_value)?;
        stop.store(true, Ordering::Release);
        if let Some(consumer) = shared_consumer {
            results.extend(
                consumer
                    .join()
                    .map_err(|_| io::Error::other("consumer panicked"))??,
            );
        }
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
    let worst_values = (
        worst.lane_cpu,
        worst.worker_cpu,
        worst.involuntary,
        worst.wall_ns,
        worst.cpu_ns,
    );
    let worst_pause_values = (
        worst_pause.max_checkpoint_offcpu_ns,
        worst_pause.lane_cpu,
        worst_pause.worker_cpu,
    );
    let checksum: u64 = results
        .iter()
        .map(|r| r.checksum)
        .fold(0, u64::wrapping_add);
    let mut latencies: Vec<_> = results
        .iter_mut()
        .flat_map(|result| std::mem::take(&mut result.latencies))
        .collect();
    latencies.sort_unstable();
    let (latency_p50_ns, latency_p95_ns, latency_p99_ns, latency_max_ns) =
        latency_summary(&latencies);
    let requested = calls * producer_cpus.len() as u64;
    println!(
        "mode=mold shape={mode} attachment=per_cpu_gated_v4 producers={} calls_per_producer={calls} requested={requested} received={received} dropped={gaps} unaccounted={} loss_pct={:.4} producer_seconds={producer_seconds:.6} requested_per_second={:.0} consumer_cpu_ms={:.3} lanes={lanes} capacity={capacity} map_bytes={} max_backlog={max_backlog} worst_lane={} worst_worker={} worst_involuntary={} worst_wall_ms={:.3} worst_cpu_ms={:.3} max_checkpoint_offcpu_ms={:.3} pause_lane={} pause_worker={} consumer_mark_interval={CONSUMER_MARK_INTERVAL} latency_samples={} latency_p50_ns={latency_p50_ns} latency_p95_ns={latency_p95_ns} latency_p99_ns={latency_p99_ns} latency_max_ns={latency_max_ns} checksum={checksum}",
        producer_cpus.len(),
        requested.abs_diff(received + gaps),
        gaps as f64 * 100.0 / requested.max(1) as f64,
        requested as f64 / producer_seconds,
        cpu_ns as f64 / 1_000_000.0,
        slots.entries() * slots.value_size(),
        worst_values.0,
        worst_values.1,
        worst_values.2,
        worst_values.3 as f64 / 1_000_000.0,
        worst_values.4 as f64 / 1_000_000.0,
        worst_pause_values.0 as f64 / 1_000_000.0,
        worst_pause_values.1,
        worst_pause_values.2,
        latencies.len(),
    );
    Ok(())
}

struct LaneCursor {
    lane_cpu: usize,
    expected: u64,
    received: u64,
    gaps: u64,
    checksum: u64,
    max_backlog: u64,
    latencies: Vec<u64>,
}

fn consume_lanes(
    slots: &MappedArray<'_>,
    frontiers: &MappedArray<'_>,
    capacity: usize,
    lane_cpus: &[usize],
    worker_cpu: usize,
    stop: &AtomicBool,
    start: &Barrier,
    measure_latency: bool,
    pause_every: u64,
    pause_us: u64,
    calls_per_lane: u64,
) -> io::Result<Vec<Result>> {
    pin_current_thread(worker_cpu)?;
    let latency_capacity = if measure_latency {
        usize::try_from(calls_per_lane)
            .map_err(|_| io::Error::other("latency sample count is too large"))?
    } else {
        0
    };
    let mut cursors: Vec<_> = lane_cpus
        .iter()
        .copied()
        .map(|lane_cpu| LaneCursor {
            lane_cpu,
            expected: 1,
            received: 0,
            gaps: 0,
            checksum: 0,
            max_backlog: 0,
            latencies: Vec::with_capacity(latency_capacity),
        })
        .collect();
    start.wait();
    let wall_start = Instant::now();
    let cpu_start = thread_cpu_ns();
    let usage_start = thread_usage();
    let mut total_received = 0u64;
    loop {
        let mut caught_up = true;
        for cursor in &mut cursors {
            let frontier = frontiers.value_ptr(cursor.lane_cpu)?.cast::<Frontier>();
            let frontier = unsafe { frontier.as_ref() };
            let published = frontier.producer_mark.load(Ordering::Acquire);
            if cursor.expected <= published {
                caught_up = false;
                cursor.max_backlog = cursor.max_backlog.max(published - (cursor.expected - 1));
                let oldest = published.saturating_sub(capacity as u64 - 1).max(1);
                if cursor.expected < oldest {
                    cursor.gaps += oldest - cursor.expected;
                    cursor.expected = oldest;
                    frontier
                        .consumer_mark
                        .store(cursor.expected - 1, Ordering::Release);
                }
                let index = cursor.lane_cpu * capacity
                    + ((cursor.expected - 1) & (capacity as u64 - 1)) as usize;
                let slot = slots.value_ptr(index)?.cast::<u8>();
                let mark = unsafe { slot.cast::<AtomicU64>().as_ref() };
                let first = mark.load(Ordering::Acquire);
                if first == cursor.expected {
                    let timestamp =
                        unsafe { std::ptr::read_volatile(slot.add(16).cast::<u64>().as_ptr()) };
                    fence(Ordering::Acquire);
                    if mark.load(Ordering::Acquire) == first {
                        cursor.checksum = cursor.checksum.wrapping_add(timestamp);
                        if measure_latency {
                            cursor
                                .latencies
                                .push(monotonic_ns().saturating_sub(timestamp));
                        }
                        cursor.received += 1;
                        total_received += 1;
                        cursor.expected += 1;
                        maybe_pause(total_received, pause_every, pause_us);
                        if cursor.received % CONSUMER_MARK_INTERVAL == 0 {
                            frontier
                                .consumer_mark
                                .store(cursor.expected - 1, Ordering::Release);
                        }
                    }
                }
            }
        }
        if stop.load(Ordering::Acquire) && caught_up {
            break;
        }
        std::hint::spin_loop();
    }
    let usage_end = thread_usage();
    let wall_ns = wall_start.elapsed().as_nanos() as u64;
    let cpu_ns = thread_cpu_ns() - cpu_start;
    let involuntary = usage_end.ru_nivcsw - usage_start.ru_nivcsw;
    let mut results = Vec::with_capacity(cursors.len());
    for (index, cursor) in cursors.into_iter().enumerate() {
        let frontier = unsafe {
            frontiers
                .value_ptr(cursor.lane_cpu)?
                .cast::<Frontier>()
                .as_ref()
        };
        frontier
            .consumer_mark
            .store(cursor.expected - 1, Ordering::Release);
        results.push(Result {
            received: cursor.received,
            gaps: cursor.gaps,
            cpu_ns: if index == 0 { cpu_ns } else { 0 },
            checksum: cursor.checksum,
            max_backlog: cursor.max_backlog,
            lane_cpu: cursor.lane_cpu,
            worker_cpu,
            involuntary: if index == 0 { involuntary } else { 0 },
            wall_ns,
            max_checkpoint_offcpu_ns: 0,
            latencies: cursor.latencies,
        });
    }
    Ok(results)
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
    latencies: Vec<u64>,
}

fn consume_lane(
    slots: &MappedArray<'_>,
    frontiers: &MappedArray<'_>,
    capacity: usize,
    lane_cpu: usize,
    worker_cpu: usize,
    stop: &AtomicBool,
    start: &Barrier,
    measure_latency: bool,
    pause_every: u64,
    pause_us: u64,
    calls: u64,
) -> io::Result<Result> {
    pin_current_thread(worker_cpu)?;
    let frontier = frontiers.value_ptr(lane_cpu)?.cast::<Frontier>();
    let frontier = unsafe { frontier.as_ref() };
    let mut expected = 1u64;
    let (mut received, mut gaps, mut checksum) = (0u64, 0u64, 0u64);
    let mut latencies = Vec::with_capacity(if measure_latency {
        usize::try_from(calls).map_err(|_| io::Error::other("latency sample count is too large"))?
    } else {
        0
    });
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
            let slot = slots.value_ptr(index)?.cast::<u8>();
            let mark = unsafe { slot.cast::<AtomicU64>().as_ref() };
            let first = mark.load(Ordering::Acquire);
            if first == expected {
                let timestamp =
                    unsafe { std::ptr::read_volatile(slot.add(16).cast::<u64>().as_ptr()) };
                fence(Ordering::Acquire);
                if mark.load(Ordering::Acquire) == first {
                    checksum = checksum.wrapping_add(timestamp);
                    if measure_latency {
                        latencies.push(monotonic_ns().saturating_sub(timestamp));
                    }
                    received += 1;
                    expected += 1;
                    maybe_pause(received, pause_every, pause_us);
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
        latencies,
    })
}

fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time);
    }
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn latency_summary(values: &[u64]) -> (u64, u64, u64, u64) {
    let percentile = |numerator: usize| {
        values
            .get(values.len().saturating_sub(1) * numerator / 100)
            .copied()
            .unwrap_or(0)
    };
    (
        percentile(50),
        percentile(95),
        percentile(99),
        values.last().copied().unwrap_or(0),
    )
}

fn env_u64(name: &str) -> io::Result<u64> {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().map_err(invalid))
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn maybe_pause(received: u64, every: u64, pause_us: u64) {
    if every != 0 && pause_us != 0 && received % every == 0 {
        thread::sleep(std::time::Duration::from_micros(pause_us));
    }
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
