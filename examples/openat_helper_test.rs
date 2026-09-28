//! Privileged integration cases adapted from Aya's bpf_probe_read tests.
//! Source: test/integration-test/src/tests/bpf_probe_read.rs at
//! 8bcb4e390fde09ffd8d7e8c060e473c03d9b6601 (MIT; see LICENSES/aya-MIT.txt).
use samurai::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, TypedMoldEntry},
    record::OpenAtRecord,
    utils::{affinity::pin_current_thread, tracepoint::TracepointResolver},
};
use std::{collections::BTreeMap, ffi::CString, io};

const WORDS: usize = 16;

fn main() -> io::Result<()> {
    // The legacy tracepoint perf event is opened on CPU 0. Keep this focused
    // helper test on that CPU so its four syscalls cannot race attachment
    // propagation while the assertions are running.
    pin_current_thread(0)?;
    let object = std::env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: openat_helper_test <openat-test.bpf.o>",
        )
    })?;
    let loaded = ObjectLoader::from_file(object)?.load()?;
    let wanted_pid = std::process::id();
    let slots = loaded
        .map("slots")
        .ok_or_else(|| missing("slots"))?
        .mmap()?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?
        .mmap()?;
    let mold = MappedMold::<WORDS>::new(&slots, &frontiers)?;
    let mut workers = (0..mold.lanes())
        .map(|lane| mold.worker(lane))
        .collect::<io::Result<Vec<_>>>()?;
    let program = loaded
        .program("record_openat")
        .ok_or_else(|| missing("record_openat"))?;
    let attachment = program.attach(&TracepointResolver::new(), "syscalls", "sys_enter_openat")?;

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
            match worker.try_next_record::<OpenAtRecord>()? {
                Some(TypedMoldEntry::Data(record)) => {
                    *observed_pids.entry(record.pid).or_default() += 1;
                    if record.pid == wanted_pid {
                        records.push(record);
                    }
                    progressed = true;
                }
                Some(TypedMoldEntry::Gap(missed)) => {
                    gaps += missed;
                    progressed = true;
                }
                Some(TypedMoldEntry::Done) => progressed = true,
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
    records.sort_unstable_by_key(|record| record.timestamp_ns);
    assert_eq!(gaps, 0, "helper test must not lose records");
    assert_eq!(
        records.len(),
        4,
        "expected exactly four openat calls for pid {wanted_pid}; observed records by pid: {observed_pids:?}"
    );
    assert_eq!(records[0].path_bytes(), b"/dev/null");
    assert_eq!(records[0].path_error, 0);
    assert_eq!(records[1].path_bytes(), &[b'a'; 63]);
    assert_eq!(records[1].path_error, 0);
    assert_eq!(records[2].path_bytes(), b"");
    assert_eq!(records[2].path_error, 0);
    assert_eq!(records[3].path_bytes(), b"");
    assert!(records[3].path_error < 0);
    println!(
        "openat helper cases passed: normal, truncated, empty, invalid-pointer error={}",
        records[3].path_error
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
