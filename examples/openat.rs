use samurai::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, TypedMoldEntry},
    record::OpenAtRecord,
    utils::tracepoint::TracepointResolver,
};
use std::{
    io, thread,
    time::{Duration, Instant},
};

const OPENAT_WORDS: usize = 6;
const SAMPLE_LIMIT: u64 = 20;

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: openat <openat.bpf.o> [seconds=5]",
        ));
    }
    let seconds = args
        .get(1)
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(5);

    let loaded = ObjectLoader::from_file(&args[0])?.load()?;
    let slots = loaded
        .map("slots")
        .ok_or_else(|| missing("slots"))?
        .mmap()?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?
        .mmap()?;
    let mold = MappedMold::<OPENAT_WORDS>::new(&slots, &frontiers)?;
    let mut workers = (0..mold.lanes())
        .map(|lane| mold.worker(lane))
        .collect::<io::Result<Vec<_>>>()?;
    let program = loaded
        .program("record_openat")
        .ok_or_else(|| missing("record_openat"))?;
    let attachment = program.attach(&TracepointResolver::new(), "syscalls", "sys_enter_openat")?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let (mut received, mut dropped, mut printed) = (0u64, 0u64, 0u64);
    while Instant::now() < deadline {
        if !drain_once(&mut workers, &mut received, &mut dropped, &mut printed)? {
            thread::sleep(Duration::from_millis(1));
        }
    }
    drop(attachment);

    loop {
        let progressed = drain_once(&mut workers, &mut received, &mut dropped, &mut printed)?;
        if !progressed
            && workers
                .iter()
                .map(|worker| worker.is_caught_up())
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .all(|caught_up| caught_up)
        {
            break;
        }
    }
    for worker in &mut workers {
        worker.publish_consumer_mark()?;
    }

    let produced = received + dropped;
    println!(
        "received={received} dropped={dropped} produced={produced} loss={:.4}% records/s={:.0} lanes={} capacity={}",
        dropped as f64 * 100.0 / produced.max(1) as f64,
        produced as f64 / seconds.max(1) as f64,
        mold.lanes(),
        mold.capacity(),
    );
    Ok(())
}

fn drain_once(
    workers: &mut [samurai::mold::MappedMoldWorker<'_, '_, OPENAT_WORDS>],
    received: &mut u64,
    dropped: &mut u64,
    printed: &mut u64,
) -> io::Result<bool> {
    let mut progressed = false;
    for worker in workers {
        match worker.try_next_record::<OpenAtRecord>()? {
            Some(TypedMoldEntry::Data(record)) => {
                *received += 1;
                progressed = true;
                if *printed < SAMPLE_LIMIT {
                    println!(
                        "{} CPU {} pid={} openat(dfd={}, flags={:#x}, mode={:#o})",
                        record.timestamp_ns,
                        record.cpu,
                        record.pid,
                        record.directory_fd,
                        record.flags,
                        record.mode,
                    );
                    *printed += 1;
                }
            }
            Some(TypedMoldEntry::Gap(missed)) => {
                *dropped += missed;
                progressed = true;
            }
            Some(TypedMoldEntry::Done) => progressed = true,
            None => {}
        }
    }
    Ok(progressed)
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}
