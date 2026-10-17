//! Command-line entry points for tracing and inspecting Linux tracepoints.

use crate::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, MappedMoldWorker, MoldEntry},
    policy::PolicyRegistry,
    smr::{EncodedBatch, SmrWriter},
    tracepoint_schema::{
        CaptureField, CaptureKind, CapturePlan, DEFAULT_DYNAMIC_CAPTURE_BYTES,
        GENERIC_CAPTURE_WORDS, capture_plan_with_registry, parse_format,
    },
    utils::tracepoint::TracepointResolver,
};
use rustc_hash::FxHashSet;
use std::{
    collections::VecDeque,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Child, Command, ExitStatus},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

const RECORD_BATCH_SIZE: usize = 256;
const RECORD_QUEUE_BATCHES: usize = 64;
const DATA_FRAME_BYTES: usize = 1 + 4 + GENERIC_CAPTURE_WORDS * 8;

struct WriterBatch {
    lane: usize,
    batch: Box<EncodedBatch>,
}

struct PausedCommand {
    child: Child,
    release: Option<OwnedFd>,
}

impl PausedCommand {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn start(&mut self) -> io::Result<()> {
        let release = self
            .release
            .take()
            .ok_or_else(|| io::Error::other("profiled command was already started"))?;
        let message = b"go\n";
        let mut offset = 0;
        while offset < message.len() {
            let written = unsafe {
                libc::write(
                    release.as_raw_fd(),
                    message[offset..].as_ptr().cast(),
                    message.len() - offset,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "profiled command start barrier accepted no bytes",
                ));
            }
            offset += written as usize;
        }
        drop(release);
        Ok(())
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn terminate_and_wait(&mut self) -> io::Result<ExitStatus> {
        let pid = i32::try_from(self.child.id())
            .map_err(|_| io::Error::other("profiled command PID exceeds i32"))?;
        let result = unsafe { libc::kill(-pid, libc::SIGTERM) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        self.child.wait()
    }
}

impl Drop for PausedCommand {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
            let _ = self.child.wait();
        }
    }
}

/// Run the inspector example with its positional arguments.
pub fn run_inspect_args(args: Vec<String>) -> io::Result<()> {
    if args.as_slice() == ["--find-relative"] {
        return find_relative();
    }
    match args.as_slice() {
        [category, event] => run_inspect(category, event, None),
        [category, event, fields] => {
            let fields = parse_fields(fields)?;
            run_inspect(category, event, Some(&fields))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: inspect_tracepoint <category> <event> [field,...] | inspect_tracepoint --find-relative",
        )),
    }
}

/// Shared trace implementation used by the CLI and the focused example.
pub fn run_trace(
    category: &str,
    event: &str,
    fields: Option<&[String]>,
    cpu_spec: Option<&str>,
    target_pid: Option<u32>,
    command: Option<&str>,
    count_limit: Option<u64>,
    duration: Option<Duration>,
    output_path: &Path,
    object_path: Option<&Path>,
) -> io::Result<()> {
    let resolver = TracepointResolver::new();
    let plan = CapturePlan::discover(&resolver, category, event, fields)?;
    let operations = plan.operations()?;
    if command.is_some_and(|command| command.trim().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "profiled command must not be empty",
        ));
    }
    let pid_filter_requested = target_pid.is_some() || command.is_some();
    let fork_pid_offsets = pid_filter_requested
        .then_some(())
        .map(|_| discover_fork_pid_offsets(&resolver))
        .transpose()?;

    let mut loader = match object_path {
        Some(path) => ObjectLoader::from_file(path)?,
        None => ObjectLoader::parse(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/generic-tracepoint.bpf.o"
        )))?,
    };
    let cpus = resolve_cpus(cpu_spec)?;
    loader.configure_mold(
        cpus.len(),
        *cpus
            .last()
            .expect("CPU selection was validated as nonempty"),
    )?;
    let loaded = loader.load()?;
    let mut profiled_command = command.map(spawn_paused_command).transpose()?;
    let filter_pid = target_pid.or_else(|| profiled_command.as_ref().map(PausedCommand::pid));
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
    let cpu_to_lane = loaded
        .map("cpu_to_lane")
        .ok_or_else(|| missing("cpu_to_lane"))?;
    for (lane, &cpu) in cpus.iter().enumerate() {
        let cpu = u32::try_from(cpu)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CPU number is too large"))?;
        let encoded_lane = u32::try_from(lane + 1)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many Mold lanes"))?;
        cpu_to_lane.write(cpu, &encoded_lane.to_ne_bytes())?;
    }

    let mut lifecycle_attachments = Vec::new();
    if let Some(pid) = filter_pid {
        let tracked_pids = loaded
            .hash_map("tracked_pids")
            .ok_or_else(|| missing("tracked_pids"))?;
        seed_process_tree(pid, tracked_pids)?;
        let (parent_offset, child_offset) =
            fork_pid_offsets.expect("PID filtering discovered the fork schema");
        let mut config = [0u8; 12];
        config[..4].copy_from_slice(&1u32.to_ne_bytes());
        config[4..8].copy_from_slice(&parent_offset.to_ne_bytes());
        config[8..12].copy_from_slice(&child_offset.to_ne_bytes());
        loaded
            .map("pid_filter_config")
            .ok_or_else(|| missing("pid_filter_config"))?
            .write(0, &config)?;
        // Tracepoint BPF attachment is global. The lifecycle programs see
        // forks and exits on every CPU through one attachment each.
        lifecycle_attachments.push(
            loaded
                .program("track_process_fork")
                .ok_or_else(|| missing("track_process_fork"))?
                .attach(&resolver, "sched", "sched_process_fork")?,
        );
        lifecycle_attachments.push(
            loaded
                .program("track_process_exit")
                .ok_or_else(|| missing("track_process_exit"))?
                .attach(&resolver, "sched", "sched_process_exit")?,
        );
        // Close the ordinary setup race for descendants created during the
        // first /proc walk. Future children are propagated by BPF.
        seed_process_tree(pid, tracked_pids)?;
    }

    let slots = loaded
        .map("slots")
        .ok_or_else(|| missing("slots"))?
        .mmap()?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?
        .mmap()?;
    let mold = MappedMold::<GENERIC_CAPTURE_WORDS>::new(&slots, &frontiers)?;
    if mold.lanes() != cpus.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "loaded Mold lane count does not match the selected CPUs",
        ));
    }
    let writer = SmrWriter::create(output_path, &plan, &cpus)?;
    let record_words = plan.words;
    let (sender, receiver) = sync_channel::<WriterBatch>(RECORD_QUEUE_BATCHES);
    let mut recycle_receivers = Vec::with_capacity(cpus.len());
    let mut recycle_senders = Vec::with_capacity(cpus.len());
    for _ in &cpus {
        let (recycle_sender, recycle_receiver) = sync_channel(2);
        for _ in 0..2 {
            recycle_sender
                .send(Box::new(EncodedBatch::with_capacity(
                    RECORD_BATCH_SIZE * DATA_FRAME_BYTES,
                    record_words,
                )))
                .map_err(|_| io::Error::other("failed to initialize SMR buffer pool"))?;
        }
        recycle_senders.push(recycle_sender);
        recycle_receivers.push(recycle_receiver);
    }
    // One global attachment observes every CPU. `cpu_to_lane` is the in-BPF
    // CPU filter and maps enabled CPU IDs onto compact Mold lanes.
    let attachments = [loaded
        .program("record_generic_tracepoint")
        .ok_or_else(|| missing("record_generic_tracepoint"))?
        .attach(&resolver, category, event)?];

    install_stop_handlers()?;
    let deadline = duration
        .map(|duration| {
            Instant::now()
                .checked_add(duration)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "duration is too large"))
        })
        .transpose()?;
    let recording = AtomicBool::new(true);
    let worker_failed = AtomicBool::new(false);
    let received_total = AtomicU64::new(0);
    let (results, writer, command_status) = thread::scope(|scope| -> io::Result<_> {
        let writer_handle = scope.spawn(move || -> io::Result<SmrWriter> {
            let mut writer = writer;
            while let Ok(mut message) = receiver.recv() {
                writer.write_encoded_batch(&message.batch)?;
                message.batch.clear();
                // A lane drops its receiver after sending its final batch.
                // The write already succeeded, so that is normal shutdown.
                let _ = recycle_senders[message.lane].send(message.batch);
            }
            Ok(writer)
        });
        let handles = cpus
            .iter()
            .enumerate()
            .zip(recycle_receivers)
            .map(|((lane, &cpu), recycle_receiver)| {
                let worker = mold.worker(lane)?;
                let sender = sender.clone();
                let recording = &recording;
                let received_total = &received_total;
                let worker_failed = &worker_failed;
                Ok(scope.spawn(move || {
                    let result = consume_lane(
                        worker,
                        lane,
                        cpu,
                        record_words,
                        recording,
                        received_total,
                        sender,
                        recycle_receiver,
                    );
                    if result.is_err() {
                        worker_failed.store(true, Ordering::Release);
                    }
                    result
                }))
            })
            .collect::<io::Result<Vec<_>>>()?;

        if let Some(command) = profiled_command.as_mut() {
            command.start()?;
        }

        let mut command_status = None;
        loop {
            if let Some(command) = profiled_command.as_mut()
                && let Some(status) = command.try_wait()?
            {
                command_status = Some(status);
                break;
            }
            if count_limit.is_some_and(|limit| received_total.load(Ordering::Relaxed) >= limit)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || STOP_REQUESTED.load(Ordering::Relaxed)
                || worker_failed.load(Ordering::Acquire)
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if command_status.is_none()
            && let Some(command) = profiled_command.as_mut()
        {
            command_status = Some(command.terminate_and_wait()?);
        }
        drop(attachments);
        drop(lifecycle_attachments);
        recording.store(false, Ordering::Release);

        let results = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| io::Error::other("Mold consumer thread panicked"))?
            })
            .collect::<io::Result<Vec<_>>>()?;
        drop(sender);
        let writer = writer_handle
            .join()
            .map_err(|_| io::Error::other("SMR writer thread panicked"))??;
        Ok((results, writer, command_status))
    })?;
    let received = results.iter().map(|result| result.received).sum::<u64>();
    let dropped = results.iter().map(|result| result.dropped).sum::<u64>();
    let bytes = writer.finish(received, dropped)?;
    let mut tracked_descendants = None;
    if filter_pid.is_some() {
        let stats = loaded
            .map("pid_filter_stats")
            .ok_or_else(|| missing("pid_filter_stats"))?;
        let insertion_failures = stats.read_u64(0)?;
        let descendants_added = stats.read_u64(1)?;
        let tasks_removed = stats.read_u64(2)?;
        if insertion_failures != 0 {
            return Err(io::Error::other(format!(
                "PID filter capacity was exhausted; {insertion_failures} descendants were not tracked"
            )));
        }
        tracked_descendants = Some((descendants_added, tasks_removed));
    }
    println!(
        "recorded={} received={received} dropped={dropped} bytes={bytes} event={category}:{event} cpus={cpus:?}",
        output_path.display()
    );
    if let Some((descendants_added, tasks_removed)) = tracked_descendants {
        println!("pid_filter_added={descendants_added} pid_filter_removed={tasks_removed}");
    }
    if let Some(status) = command_status
        && !status.success()
    {
        return Err(io::Error::other(format!(
            "profiled command exited with {status}"
        )));
    }
    Ok(())
}

fn spawn_paused_command(command_text: &str) -> io::Result<PausedCommand> {
    let mut pipe = [0i32; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = pipe[0];
    let write_fd = pipe[1];
    let sudo_identity = sudo_identity()?;
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("IFS= read -r _ <&3 || exit 125; exec /bin/sh -c \"$1\"")
        .arg("samurai-command")
        .arg(command_text);
    unsafe {
        command.pre_exec(move || {
            libc::close(write_fd);
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some((uid, gid)) = sudo_identity {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if read_fd != 3 {
                if libc::dup2(read_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(read_fd);
            } else if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }
    };
    unsafe {
        libc::close(read_fd);
    }
    Ok(PausedCommand {
        child,
        release: Some(unsafe { OwnedFd::from_raw_fd(write_fd) }),
    })
}

fn sudo_identity() -> io::Result<Option<(libc::uid_t, libc::gid_t)>> {
    let uid = std::env::var_os("SUDO_UID");
    let gid = std::env::var_os("SUDO_GID");
    match (uid, gid) {
        (None, None) => Ok(None),
        (Some(uid), Some(gid)) => {
            let uid = uid
                .to_string_lossy()
                .parse::<libc::uid_t>()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid SUDO_UID: {error}"),
                    )
                })?;
            let gid = gid
                .to_string_lossy()
                .parse::<libc::gid_t>()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid SUDO_GID: {error}"),
                    )
                })?;
            Ok(Some((uid, gid)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SUDO_UID and SUDO_GID must either both be set or both be absent",
        )),
    }
}

fn discover_fork_pid_offsets(resolver: &TracepointResolver) -> io::Result<(u32, u32)> {
    let format = resolver.format("sched", "sched_process_fork")?;
    let fields = parse_format(&format)?;
    let offset = |name: &str| -> io::Result<u32> {
        let field = fields
            .iter()
            .find(|field| field.name == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("sched_process_fork has no {name} field"),
                )
            })?;
        if field.size != size_of::<u32>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sched_process_fork {name} is not four bytes"),
            ));
        }
        u32::try_from(field.offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name} offset exceeds u32"),
            )
        })
    };
    Ok((offset("parent_pid")?, offset("child_pid")?))
}

fn seed_process_tree(root: u32, tracked: &crate::bpf::map::HashMap) -> io::Result<()> {
    let root_path = format!("/proc/{root}");
    if !Path::new(&root_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("target PID {root} does not exist"),
        ));
    }
    let mut seen = FxHashSet::default();
    let mut pending = VecDeque::new();
    seen.insert(root);
    pending.push_back(root);
    while let Some(pid) = pending.pop_front() {
        tracked.write(&pid.to_ne_bytes(), &[1])?;
        let task_path = format!("/proc/{pid}/task");
        let tasks = match fs::read_dir(task_path) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for task in tasks {
            let task = task?;
            let tid = task
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid task ID: {error}"),
                    )
                })?;
            tracked.write(&tid.to_ne_bytes(), &[1])?;
            let children = match fs::read_to_string(task.path().join("children")) {
                Ok(children) => children,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for child in parse_child_pids(&children)? {
                if seen.insert(child) {
                    pending.push_back(child);
                }
            }
        }
    }
    Ok(())
}

fn parse_child_pids(children: &str) -> io::Result<Vec<u32>> {
    children
        .split_whitespace()
        .map(|child| {
            child.parse::<u32>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid child PID: {error}"),
                )
            })
        })
        .collect()
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_stop_handlers() -> io::Result<()> {
    STOP_REQUESTED.store(false, Ordering::Relaxed);
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // The handler only writes an atomic flag; recording and FD teardown stay
        // in normal thread context.
        let previous =
            unsafe { libc::signal(signal, request_stop as *const () as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn resolve_cpus(spec: Option<&str>) -> io::Result<Vec<usize>> {
    let online_text = fs::read_to_string("/sys/devices/system/cpu/online")?;
    let online = parse_cpu_ranges(&online_text)?;
    let cpus = match spec {
        None | Some("all") => online.clone(),
        Some(spec) => parse_cpu_ranges(spec)?,
    };
    if cpus.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU selection is empty",
        ));
    }
    for cpu in &cpus {
        if !online.contains(cpu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("CPU {cpu} is not online"),
            ));
        }
    }
    Ok(cpus)
}

fn parse_cpu_ranges(value: &str) -> io::Result<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in value.trim().split(',') {
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (parse_cpu(start)?, parse_cpu(end)?),
            None => {
                let cpu = parse_cpu(part)?;
                (cpu, cpu)
            }
        };
        if start > end || end - start > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CPU range {part:?}"),
            ));
        }
        cpus.extend(start..=end);
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

fn parse_cpu(value: &str) -> io::Result<usize> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid CPU number {value:?}: {error}"),
        )
    })
}

struct WorkerResult {
    received: u64,
    dropped: u64,
}

fn consume_lane(
    mut worker: MappedMoldWorker<'_, '_, GENERIC_CAPTURE_WORDS>,
    lane: usize,
    cpu: usize,
    record_words: usize,
    recording: &AtomicBool,
    received_total: &AtomicU64,
    sender: SyncSender<WriterBatch>,
    recycle: Receiver<Box<EncodedBatch>>,
) -> io::Result<WorkerResult> {
    let mut result = WorkerResult {
        received: 0,
        dropped: 0,
    };
    let cpu = u32::try_from(cpu)
        .map_err(|_| io::Error::other("CPU number does not fit in SMR format"))?;
    let mut batch = recycle
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SMR writer stopped"))?;
    loop {
        match worker.try_next()? {
            Some(MoldEntry::Data(words)) => {
                result.received += 1;
                received_total.fetch_add(1, Ordering::Relaxed);
                batch.push_data(cpu, &words[..record_words]);
            }
            Some(MoldEntry::Gap(missed)) => {
                result.dropped += missed;
                batch.push_gap(cpu, missed);
            }
            Some(MoldEntry::Done) => {}
            None => {
                if !recording.load(Ordering::Acquire) && worker.is_caught_up()? {
                    send_batch(&sender, lane, batch)?;
                    worker.publish_consumer_mark()?;
                    return Ok(result);
                }
                std::hint::spin_loop();
            }
        }
        if batch.is_full(RECORD_BATCH_SIZE) {
            send_batch(&sender, lane, batch)?;
            batch = recycle
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SMR writer stopped"))?;
        }
    }
}

fn send_batch(
    sender: &SyncSender<WriterBatch>,
    lane: usize,
    batch: Box<EncodedBatch>,
) -> io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    sender
        .send(WriterBatch { lane, batch })
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SMR writer stopped"))
}

pub fn run_inspect(category: &str, event: &str, selected: Option<&[String]>) -> io::Result<()> {
    let resolver = TracepointResolver::new();
    let format = resolver.format(category, event)?;
    let available = parse_format(&format)?;
    let tracepoint = resolver.open(category, event)?;
    let all_names;
    let names = match selected {
        Some(fields) => fields,
        None => {
            all_names = available
                .iter()
                .filter(|field| !field.name.starts_with("common_"))
                .map(|field| field.name.clone())
                .collect::<Vec<_>>();
            &all_names
        }
    };

    println!(
        "Event: {category}:{event}\nID:    {}\n\nFields:",
        tracepoint.id
    );
    for name in names {
        let selected = [name.clone()];
        match capture_plan_with_registry(
            category,
            event,
            &format,
            Some(&selected),
            DEFAULT_DYNAMIC_CAPTURE_BYTES,
            PolicyRegistry::builtin(),
        ) {
            Ok(plan) => {
                let capture = &plan.fields[0];
                if let Some(field) = available.iter().find(|field| field.name == *name) {
                    println!("  {}\n    declaration: {}", name, field.declaration);
                }
                print_field(capture, plan.operations()?.len());
            }
            Err(error) => println!("  {name}: unsupported ({error})"),
        }
    }
    Ok(())
}

pub fn run_list(category: Option<&str>) -> io::Result<()> {
    let events = TracepointResolver::new().list(category)?;
    if category.is_some() {
        for (event_category, event) in events {
            println!("{event_category}:{event}");
        }
    } else {
        let mut previous = String::new();
        for (event_category, event) in events {
            if previous != event_category {
                println!("{event_category}");
                previous.clone_from(&event_category);
            }
            println!("  {event}");
        }
    }
    Ok(())
}

pub fn run_validate(category: &str, event: &str, selected: Option<&[String]>) -> io::Result<()> {
    let resolver = TracepointResolver::new();
    let tracepoint = resolver.open(category, event)?;
    let plan = CapturePlan::discover(&resolver, category, event, selected)?;
    let operations = plan.operations()?;
    let bytes = plan
        .words
        .checked_mul(size_of::<u64>())
        .ok_or_else(|| io::Error::other("record size overflow"))?;
    println!("Event: {}:{}", category, event);
    println!("ID: {}", tracepoint.id);
    println!("Fields: {}", plan.fields.len());
    println!("Mold words: {} ({} bytes)", plan.words, bytes);
    println!("Tracepoint context span: {} bytes", plan.context_size);
    println!("Capture operations: {}", operations.len());
    println!("BPF stack budget: valid");
    println!("Mold record size: valid");
    println!("Policies: valid");
    Ok(())
}

pub fn find_relative() -> io::Result<()> {
    let roots = [
        Path::new("/sys/kernel/tracing/events"),
        Path::new("/sys/kernel/debug/tracing/events"),
    ];
    let root = roots
        .iter()
        .find(|root| root.is_dir())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tracefs events not mounted"))?;
    let mut matches = 0usize;
    for category in fs::read_dir(root)? {
        let category = category?;
        if !category.file_type()?.is_dir() {
            continue;
        }
        for event in fs::read_dir(category.path())? {
            let event = event?;
            let format_path = event.path().join("format");
            let Ok(format) = fs::read_to_string(format_path) else {
                continue;
            };
            let Ok(fields) = parse_format(&format) else {
                continue;
            };
            for field in fields
                .iter()
                .filter(|field| field.kind == CaptureKind::RelativeDataLoc)
            {
                println!(
                    "{}:{} field={} declaration={}",
                    category.file_name().to_string_lossy(),
                    event.file_name().to_string_lossy(),
                    field.name,
                    field.declaration,
                );
                matches += 1;
            }
        }
    }
    println!("relative_data_loc_fields={matches}");
    Ok(())
}

fn print_field(field: &CaptureField, operations: usize) {
    print!(
        "    offset: {}\n    size: {}\n    capture: {}\n    words: {}\n    operations: {operations}",
        field.source_offset,
        field.size,
        kind_name(field.kind),
        field.words,
    );
    if field.capture_size != 0 {
        print!("\n    max_len: {}", field.capture_size);
    }
    if let Some((offset, size)) = field.length_source {
        print!("\n    length source: offset={offset}, size={size}");
    }
    println!();
}

const fn kind_name(kind: CaptureKind) -> &'static str {
    match kind {
        CaptureKind::Scalar => "Scalar",
        CaptureKind::FixedArray => "FixedArray",
        CaptureKind::FixedStruct => "FixedStruct",
        CaptureKind::PointerAddress => "PointerAddress",
        CaptureKind::FunctionPointer => "FunctionPointer",
        CaptureKind::DataLoc => "DataLoc",
        CaptureKind::RelativeDataLoc => "RelativeDataLoc",
        CaptureKind::UserString => "UserString",
        CaptureKind::UserBytes => "UserBytes",
        CaptureKind::KernelString => "KernelString",
        CaptureKind::KernelBytes => "KernelBytes",
    }
}

pub fn parse_fields(fields: &str) -> io::Result<Vec<String>> {
    let fields = fields
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if fields.is_empty() || fields.iter().any(String::is_empty) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "field list must contain comma-separated field names",
        ));
    }
    Ok(fields)
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}

#[cfg(test)]
mod tests {
    use super::parse_child_pids;

    #[test]
    fn parses_proc_children_with_kernel_whitespace() {
        assert_eq!(parse_child_pids("101 202 303 \n").unwrap(), [101, 202, 303]);
        assert!(parse_child_pids("").unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_proc_child_pid() {
        let error = parse_child_pids("101 invalid 303").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
