#![allow(
    unused_crate_dependencies,
    reason = "examples inherit workspace dependencies"
)]

use aya::{
    EbpfLoader,
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use integration_common::mold_bench::{DynamicConfig, DynamicEvent};
use std::{
    error::Error,
    ffi::CString,
    fs,
    hint::black_box,
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: dynamic_controlled_bench <string|bytes> <object> <calls> <producer-cpus> <consumer-cpu>".into());
    }
    let mode = match args[0].as_str() {
        "string" => 1u32,
        "bytes" => 2,
        _ => return Err("mode must be string or bytes".into()),
    };
    let calls: u64 = args[2].parse()?;
    let cpus = parse_cpus(&args[3])?;
    let producer_count = cpus.len();
    let consumer_cpu: usize = args[4].parse()?;
    let (event, pointer_name) = if mode == 1 {
        ("sys_enter_openat", "filename")
    } else {
        ("sys_enter_write", "buf")
    };
    let pointer_offset = tracepoint_offset(event, pointer_name)?;
    let object = fs::read(&args[1])?;
    let pin_dir = format!("/sys/fs/bpf/samurai-dynamic-{}", std::process::id());
    fs::create_dir(&pin_dir)?;
    let map_names = ["DYNAMIC", "DYNAMIC_DROPPED", "DYNAMIC_CONFIG"];
    let mut bpfs = Vec::with_capacity(cpus.len());
    let name = if mode == 1 {
        "controlled_string"
    } else {
        "controlled_bytes"
    };
    for &cpu in &cpus {
        let mut loader = EbpfLoader::new();
        for map_name in map_names {
            loader.map_pin_path(map_name, PathBuf::from(format!("{pin_dir}/{map_name}")));
        }
        let mut bpf = loader.load(&object)?;
        let mut cpu_filter: Array<_, u32> = bpf
            .take_map("DYNAMIC_CPU")
            .ok_or("missing CPU filter")?
            .try_into()?;
        cpu_filter.set(0, &(cpu as u32), 0)?;
        let program: &mut TracePoint =
            bpf.program_mut(name).ok_or("missing program")?.try_into()?;
        program.load()?;
        program.attach_to_cpu("syscalls", event, cpu as u32)?;
        bpfs.push(bpf);
    }
    for map_name in map_names {
        fs::remove_file(format!("{pin_dir}/{map_name}"))?;
    }
    fs::remove_dir(&pin_dir)?;
    let first = bpfs.first_mut().ok_or("no producer CPUs")?;
    let ring = RingBuf::try_from(first.take_map("DYNAMIC").ok_or("missing DYNAMIC")?)?;
    let dropped: PerCpuArray<_, u64> = first
        .take_map("DYNAMIC_DROPPED")
        .ok_or("missing dropped")?
        .try_into()?;
    let mut config: Array<_, DynamicConfig> = first
        .take_map("DYNAMIC_CONFIG")
        .ok_or("missing config")?
        .try_into()?;
    config.set(
        0,
        &DynamicConfig {
            pid: std::process::id(),
            pointer_offset,
            length_offset: 0,
            mode,
        },
        0,
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(cpus.len() + 2));
    let consumer = {
        let stop = stop.clone();
        let barrier = barrier.clone();
        thread::spawn(move || consume(ring, stop, barrier, consumer_cpu))
    };
    let sink = fs::File::options().write(true).open("/dev/null")?;
    let path = CString::new("/dev/null")?;
    let payload = [0x5au8; 128];
    let producers = cpus
        .into_iter()
        .map(|cpu| {
            let barrier = barrier.clone();
            let path = path.clone();
            let sink = sink.try_clone().unwrap();
            thread::spawn(move || {
                pin(cpu).unwrap();
                barrier.wait();
                for _ in 0..calls {
                    trigger(mode, &path, sink.as_raw_fd(), &payload);
                }
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let start = Instant::now();
    for producer in producers {
        producer.join().map_err(|_| "producer panic")?;
    }
    let producer_seconds = start.elapsed().as_secs_f64();
    drop(bpfs);
    stop.store(true, Ordering::Release);
    let (received, cpu_ns, checksum) = consumer.join().map_err(|_| "consumer panic")??;
    let dropped: u64 = dropped.get(&0, 0)?.iter().sum();
    let requested = calls * producer_count as u64;
    println!(
        "mode=aya shape={} attachment=cpu_filtered_v2 requested={} received={} dropped={} unaccounted={} loss_pct={:.4} producer_seconds={:.6} requested_per_second={:.0} consumer_cpu_ms={:.3} checksum={}",
        if mode == 1 { "string" } else { "bytes" },
        requested,
        received,
        dropped,
        requested.abs_diff(received + dropped),
        dropped as f64 * 100.0 / requested.max(1) as f64,
        producer_seconds,
        requested as f64 / producer_seconds,
        cpu_ns as f64 / 1e6,
        checksum
    );
    Ok(())
}

fn consume(
    mut ring: RingBuf<aya::maps::MapData>,
    stop: Arc<AtomicBool>,
    barrier: Arc<Barrier>,
    cpu: usize,
) -> std::io::Result<(u64, u64, u64)> {
    pin(cpu)?;
    barrier.wait();
    let start = cpu_ns();
    let (mut n, mut sum) = (0u64, 0u64);
    loop {
        while let Some(item) = ring.next() {
            if item.len() == size_of::<DynamicEvent>() {
                let event = unsafe { &*item.as_ptr().cast::<DynamicEvent>() };
                n += 1;
                sum = sum
                    .wrapping_add(event.timestamp_ns)
                    .wrapping_add(event.payload[0] as u64);
            }
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        std::hint::spin_loop();
    }
    Ok((n, cpu_ns() - start, sum))
}
fn trigger(mode: u32, path: &CString, fd: RawFd, payload: &[u8; 128]) {
    if mode == 1 {
        let value = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_RDONLY,
                0,
            )
        };
        if value >= 0 {
            unsafe { libc::close(value as i32) };
        }
        black_box(value);
    } else {
        black_box(unsafe { libc::write(fd, payload.as_ptr().cast(), 128) });
    }
}
fn parse_cpus(value: &str) -> Result<Vec<usize>, Box<dyn Error>> {
    Ok(value.split(',').map(str::parse).collect::<Result<_, _>>()?)
}
fn tracepoint_offset(event: &str, field: &str) -> Result<u32, Box<dyn Error>> {
    let text = fs::read_to_string(format!(
        "/sys/kernel/tracing/events/syscalls/{event}/format"
    ))
    .or_else(|_| {
        fs::read_to_string(format!(
            "/sys/kernel/debug/tracing/events/syscalls/{event}/format"
        ))
    })?;
    for line in text.lines() {
        if line.contains(&format!(" {field};")) {
            for part in line.split(';') {
                if let Some(value) = part.trim().strip_prefix("offset:") {
                    return Ok(value.parse()?);
                }
            }
        }
    }
    Err("field offset missing".into())
}
fn pin(cpu: usize) -> std::io::Result<()> {
    let mut set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
fn cpu_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
