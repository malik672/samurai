//! Privileged integration cases adapted from Aya's bpf_probe_read tests.
//! Source: test/integration-test/src/tests/bpf_probe_read.rs at
//! 8bcb4e390fde09ffd8d7e8c060e473c03d9b6601 (MIT; see LICENSES/aya-MIT.txt).
use samurai::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, MoldEntry},
    tracepoint_schema::{CaptureKind, CapturePlan, GENERIC_CAPTURE_WORDS},
    utils::{affinity::pin_current_thread, tracepoint::TracepointResolver},
};
use std::{collections::BTreeMap, ffi::CString, io};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: openat_helper_test <generic-tracepoint.bpf.o> [cpu=0]",
        ));
    }
    let cpu = args
        .get(1)
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(0);
    // Pin before discovery, loading, attachment, and the four target syscalls.
    // This prevents scheduler migration from moving a syscall away while the
    // focused compatibility assertions are running.
    pin_current_thread(cpu)?;
    let object = args.first().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing generic tracepoint object",
        )
    })?;
    let resolver = TracepointResolver::new();
    let fields = ["filename".to_owned()];
    let plan = CapturePlan::discover(&resolver, "syscalls", "sys_enter_openat", Some(&fields))?;
    let filename = plan
        .fields
        .iter()
        .find(|field| field.name == "filename")
        .ok_or_else(|| missing("filename capture field"))?;
    if filename.kind != CaptureKind::UserString {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "openat filename policy was not applied",
        ));
    }
    let filename_word = filename.destination_word;
    let operations = plan.operations()?;

    let loaded = ObjectLoader::from_file(object)?.load()?;
    loaded
        .map("capture_config")
        .ok_or_else(|| missing("capture_config"))?
        .write(0, &(operations.len() as u64).to_ne_bytes())?;
    let operation_map = loaded
        .map("capture_operations")
        .ok_or_else(|| missing("capture_operations"))?;
    for (index, operation) in operations.iter().enumerate() {
        operation_map.write(index as u32, &operation.to_bytes())?;
    }
    let wanted_pid = std::process::id();
    let slots = loaded
        .map("slots")
        .ok_or_else(|| missing("slots"))?
        .mmap()?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?
        .mmap()?;
    let mold = MappedMold::<GENERIC_CAPTURE_WORDS>::new(&slots, &frontiers)?;
    let mut workers = (0..mold.lanes())
        .map(|lane| mold.worker(lane))
        .collect::<io::Result<Vec<_>>>()?;
    let program = loaded
        .program("record_generic_tracepoint")
        .ok_or_else(|| missing("record_generic_tracepoint"))?;
    let attachment = program.attach(&resolver, "syscalls", "sys_enter_openat")?;

    call_openat(CString::new("/dev/null").unwrap().as_ptr());
    let long = CString::new(vec![b'a'; 128]).unwrap();
    call_openat(long.as_ptr());
    call_openat(CString::new("").unwrap().as_ptr());
    call_openat(std::ptr::dangling::<libc::c_char>());
    drop(attachment);

    let mut records = Vec::new();
    let mut observed_pids = BTreeMap::<u32, usize>::new();
    let mut gaps = 0;
    loop {
        let mut progressed = false;
        for worker in &mut workers {
            match worker.try_next()? {
                Some(MoldEntry::Data(words)) => {
                    let pid = (words[1] >> 32) as u32;
                    *observed_pids.entry(pid).or_default() += 1;
                    if pid == wanted_pid {
                        let metadata = words[filename_word];
                        let length = metadata as u32 as usize;
                        let error = (metadata >> 32) as u32 as i32;
                        let mut path = Vec::with_capacity(length);
                        for index in 0..length {
                            path.push(
                                words[filename_word + 1 + index / 8].to_ne_bytes()[index % 8],
                            );
                        }
                        records.push((path, error));
                    }
                    progressed = true;
                }
                Some(MoldEntry::Gap(missed)) => {
                    gaps += missed;
                    progressed = true;
                }
                Some(MoldEntry::Done) => progressed = true,
                None => {}
            }
        }
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
    assert_eq!(gaps, 0, "helper test must not lose records");
    assert_eq!(
        records.len(),
        4,
        "expected exactly four openat calls for pid {wanted_pid}; observed records by pid: {observed_pids:?}"
    );
    assert_eq!(records[0].0, b"/dev/null");
    assert_eq!(records[0].1, 0);
    assert_eq!(records[1].0, &[b'a'; 127]);
    assert_eq!(records[1].1, 0);
    assert_eq!(records[2].0, b"");
    assert_eq!(records[2].1, 0);
    assert_eq!(records[3].0, b"");
    assert!(records[3].1 < 0);
    println!(
        "openat helper cases passed on CPU {cpu}: normal, truncated, empty, invalid-pointer error={}",
        records[3].1,
    );
    Ok(())
}

fn call_openat(path: *const libc::c_char) {
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, libc::O_RDONLY, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
    }
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}
