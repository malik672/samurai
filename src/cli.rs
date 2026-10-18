//! Command-line entry points for tracing and inspecting Linux tracepoints.

use crate::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, MappedMoldWorker, MoldEntry},
    policy::PolicyRegistry,
    smr::{EncodedBatch, PROCESS_COMM_BYTES, PROCESS_METADATA_CAPACITY, SmrProcess, SmrWriter},
    tracepoint_schema::{
        CaptureField, CaptureKind, CapturePlan, DEFAULT_DYNAMIC_CAPTURE_BYTES,
        GENERIC_CAPTURE_WORDS, TracepointField, capture_plan_with_registry, parse_format,
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
const PROCESS_METADATA_VALUE_BYTES: usize = 8 + PROCESS_COMM_BYTES;
const CAPTURE_OPERATIONS_PER_EVENT: usize = GENERIC_CAPTURE_WORDS - 4;

struct WriterBatch {
    lane: usize,
    batch: Box<EncodedBatch>,
}

struct PausedCommand {
    child: Child,
    release: Option<OwnedFd>,
}

struct SudoIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    user: String,
    home: String,
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
    run_capture(
        resolver,
        vec![plan],
        cpu_spec,
        target_pid,
        command,
        count_limit,
        duration,
        output_path,
        object_path,
    )
}

pub fn run_files_preset(
    cpu_spec: Option<&str>,
    target_pid: Option<u32>,
    command: Option<&str>,
    count_limit: Option<u64>,
    duration: Option<Duration>,
    output_path: &Path,
) -> io::Result<()> {
    let resolver = TracepointResolver::new();
    let specifications: [(&str, &[&str]); 8] = [
        ("sys_enter_openat", &["filename", "flags", "mode"]),
        ("sys_exit_openat", &["ret"]),
        ("sys_enter_close", &["fd"]),
        ("sys_exit_close", &["ret"]),
        ("sys_enter_read", &["fd", "count"]),
        ("sys_exit_read", &["ret"]),
        ("sys_enter_write", &["fd", "count"]),
        ("sys_exit_write", &["ret"]),
    ];
    let plans = specifications
        .into_iter()
        .map(|(event, fields)| {
            let fields = fields
                .iter()
                .map(|field| (*field).to_owned())
                .collect::<Vec<_>>();
            CapturePlan::discover(&resolver, "syscalls", event, Some(&fields))
        })
        .collect::<io::Result<Vec<_>>>()?;
    run_capture(
        resolver,
        plans,
        cpu_spec,
        target_pid,
        command,
        count_limit,
        duration,
        output_path,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_capture(
    resolver: TracepointResolver,
    plans: Vec<CapturePlan>,
    cpu_spec: Option<&str>,
    target_pid: Option<u32>,
    command: Option<&str>,
    count_limit: Option<u64>,
    duration: Option<Duration>,
    output_path: &Path,
    object_path: Option<&Path>,
) -> io::Result<()> {
    let operations = plans
        .iter()
        .map(CapturePlan::operations)
        .collect::<io::Result<Vec<_>>>()?;
    if command.is_some_and(|command| command.trim().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "profiled command must not be empty",
        ));
    }
    let pid_filter_requested = target_pid.is_some() || command.is_some();
    let fork_metadata_offsets = pid_filter_requested
        .then_some(())
        .map(|_| discover_fork_metadata_offsets(&resolver))
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
    let capture_config = loaded
        .map("capture_config")
        .ok_or_else(|| missing("capture_config"))?;
    let operation_map = loaded
        .map("capture_operations")
        .ok_or_else(|| missing("capture_operations"))?;
    for (event_id, event_operations) in operations.iter().enumerate() {
        capture_config.write(
            event_id as u32,
            &(event_operations.len() as u64).to_ne_bytes(),
        )?;
        for (index, operation) in event_operations.iter().enumerate() {
            let slot = event_id * CAPTURE_OPERATIONS_PER_EVENT + index;
            operation_map.write(slot as u32, &operation.to_bytes())?;
        }
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
        let process_metadata = loaded
            .hash_map("process_metadata")
            .ok_or_else(|| missing("process_metadata"))?;
        seed_process_tree(pid, tracked_pids, process_metadata)?;
        let (parent_offset, child_offset, child_comm_offset) =
            fork_metadata_offsets.expect("PID filtering discovered the fork schema");
        let mut config = [0u8; 16];
        config[..4].copy_from_slice(&1u32.to_ne_bytes());
        config[4..8].copy_from_slice(&parent_offset.to_ne_bytes());
        config[8..12].copy_from_slice(&child_offset.to_ne_bytes());
        config[12..16].copy_from_slice(&child_comm_offset.to_ne_bytes());
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
        lifecycle_attachments.push(
            loaded
                .program("track_process_exec")
                .ok_or_else(|| missing("track_process_exec"))?
                .attach(&resolver, "sched", "sched_process_exec")?,
        );
        // Close the ordinary setup race for descendants created during the
        // first /proc walk. Future children are propagated by BPF.
        seed_process_tree(pid, tracked_pids, process_metadata)?;
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
    let writer = SmrWriter::create_multi(output_path, &plans, &cpus)?;
    let event_words = plans.iter().map(|plan| plan.words).collect::<Vec<_>>();
    let (sender, receiver) = sync_channel::<WriterBatch>(RECORD_QUEUE_BATCHES);
    let mut recycle_receivers = Vec::with_capacity(cpus.len());
    let mut recycle_senders = Vec::with_capacity(cpus.len());
    for _ in &cpus {
        let (recycle_sender, recycle_receiver) = sync_channel(2);
        for _ in 0..2 {
            recycle_sender
                .send(Box::new(EncodedBatch::with_capacity(
                    RECORD_BATCH_SIZE * DATA_FRAME_BYTES,
                    &event_words,
                )))
                .map_err(|_| io::Error::other("failed to initialize SMR buffer pool"))?;
        }
        recycle_senders.push(recycle_sender);
        recycle_receivers.push(recycle_receiver);
    }
    // One global attachment observes every CPU. `cpu_to_lane` is the in-BPF
    // CPU filter and maps enabled CPU IDs onto compact Mold lanes.
    let attachments = plans
        .iter()
        .enumerate()
        .map(|(event_id, plan)| {
            let name = format!("record_generic_tracepoint_{event_id}");
            loaded.program(&name).ok_or_else(|| missing(&name))?.attach(
                &resolver,
                &plan.category,
                &plan.event,
            )
        })
        .collect::<io::Result<Vec<_>>>()?;

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
    let mut process_metadata = Vec::with_capacity(if filter_pid.is_some() {
        PROCESS_METADATA_CAPACITY
    } else {
        0
    });
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
    let mut tracked_descendants = None;
    if filter_pid.is_some() {
        let stats = loaded
            .map("pid_filter_stats")
            .ok_or_else(|| missing("pid_filter_stats"))?;
        let insertion_failures = stats.read_u64(0)?;
        let descendants_added = stats.read_u64(1)?;
        let tasks_removed = stats.read_u64(2)?;
        let metadata_failures = stats.read_u64(3)?;
        if insertion_failures != 0 {
            return Err(io::Error::other(format!(
                "PID filter capacity was exhausted; {insertion_failures} descendants were not tracked"
            )));
        }
        if metadata_failures != 0 {
            return Err(io::Error::other(format!(
                "process metadata capture failed {metadata_failures} times"
            )));
        }
        read_process_metadata(
            loaded
                .hash_map("process_metadata")
                .ok_or_else(|| missing("process_metadata"))?,
            &mut process_metadata,
        )?;
        tracked_descendants = Some((descendants_added, tasks_removed));
    }
    let bytes = writer.finish(received, dropped, &process_metadata)?;
    println!(
        "recorded={} received={received} dropped={dropped} bytes={bytes} events={} cpus={cpus:?}",
        output_path.display(),
        plans.len()
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
    if let Some(identity) = &sudo_identity {
        command
            .env("HOME", &identity.home)
            .env("USER", &identity.user)
            .env("LOGNAME", &identity.user);
    }
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
            if let Some(identity) = &sudo_identity {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(identity.gid) != 0
                    || libc::setuid(identity.uid) != 0
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

fn sudo_identity() -> io::Result<Option<SudoIdentity>> {
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
            let passwd = fs::read_to_string("/etc/passwd")?;
            let mut matching = passwd.lines().filter_map(|line| {
                let mut fields = line.split(':');
                let user = fields.next()?;
                fields.next()?;
                let candidate_uid = fields.next()?.parse::<libc::uid_t>().ok()?;
                fields.next()?;
                fields.next()?;
                let home = fields.next()?;
                (candidate_uid == uid).then(|| (user.to_owned(), home.to_owned()))
            });
            let (user, home) = matching.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SUDO_UID is absent from /etc/passwd",
                )
            })?;
            if matching.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SUDO_UID is not unique in /etc/passwd",
                ));
            }
            Ok(Some(SudoIdentity {
                uid,
                gid,
                user,
                home,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SUDO_UID and SUDO_GID must either both be set or both be absent",
        )),
    }
}

fn discover_fork_metadata_offsets(resolver: &TracepointResolver) -> io::Result<(u32, u32, u32)> {
    let format = resolver.format("sched", "sched_process_fork")?;
    let fields = parse_format(&format)?;
    let field = |name: &str| -> io::Result<&TracepointField> {
        fields
            .iter()
            .find(|field| field.name == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("sched_process_fork has no {name} field"),
                )
            })
    };
    let pid_offset = |name: &str| -> io::Result<u32> {
        let field = field(name)?;
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
    let child_comm = field("child_comm")?;
    if child_comm.size != PROCESS_COMM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sched_process_fork child_comm is not 16 bytes",
        ));
    }
    let child_comm_offset = u32::try_from(child_comm.offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child_comm offset exceeds u32"))?;
    Ok((
        pid_offset("parent_pid")?,
        pid_offset("child_pid")?,
        child_comm_offset,
    ))
}

fn seed_process_tree(
    root: u32,
    tracked: &crate::bpf::map::HashMap,
    metadata: &crate::bpf::map::HashMap,
) -> io::Result<()> {
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
        if let Some(process) = read_proc_process(pid)? {
            metadata.write(&pid.to_ne_bytes(), &encode_process_metadata(process))?;
        }
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

fn read_proc_process(pid: u32) -> io::Result<Option<SmrProcess>> {
    let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let parent_pid = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process status lacks PPid"))?
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut comm = [0; PROCESS_COMM_BYTES];
    let name = status
        .lines()
        .find_map(|line| line.strip_prefix("Name:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process status lacks Name"))?
        .trim()
        .as_bytes();
    let length = name.len().min(PROCESS_COMM_BYTES - 1);
    comm[..length].copy_from_slice(&name[..length]);
    Ok(Some(SmrProcess {
        pid,
        parent_pid,
        comm,
    }))
}

fn encode_process_metadata(process: SmrProcess) -> [u8; PROCESS_METADATA_VALUE_BYTES] {
    let mut value = [0; PROCESS_METADATA_VALUE_BYTES];
    value[..4].copy_from_slice(&process.parent_pid.to_ne_bytes());
    value[8..].copy_from_slice(&process.comm);
    value
}

fn read_process_metadata(
    map: &crate::bpf::map::HashMap,
    processes: &mut Vec<SmrProcess>,
) -> io::Result<()> {
    if map.key_size() != size_of::<u32>()
        || map.value_size() != PROCESS_METADATA_VALUE_BYTES
        || map.max_entries() != PROCESS_METADATA_CAPACITY
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process_metadata map does not match the Samurai ABI",
        ));
    }
    let mut key = [0u8; 4];
    let mut next = [0u8; 4];
    let mut value = [0u8; PROCESS_METADATA_VALUE_BYTES];
    let mut has_current = false;
    while map.next_key(has_current.then_some(key.as_slice()), &mut next)? {
        key = next;
        map.read(&key, &mut value)?;
        let pid = u32::from_ne_bytes(key);
        let parent_pid = u32::from_ne_bytes(value[..4].try_into().unwrap());
        if value[4..8] != [0; 4] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process metadata reserved bytes are nonzero",
            ));
        }
        let mut comm = [0; PROCESS_COMM_BYTES];
        comm.copy_from_slice(&value[8..]);
        processes.push(SmrProcess {
            pid,
            parent_pid,
            comm,
        });
        has_current = true;
    }
    processes.sort_unstable_by_key(|process| process.pid);
    if processes.windows(2).any(|pair| pair[0].pid == pair[1].pid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process metadata map returned a duplicate PID",
        ));
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
    let mut idle_polls = 0u32;
    loop {
        match worker.try_next()? {
            Some(MoldEntry::Data(words)) => {
                idle_polls = 0;
                result.received += 1;
                received_total.fetch_add(1, Ordering::Relaxed);
                batch.push_data(cpu, &words)?;
            }
            Some(MoldEntry::Gap(missed)) => {
                idle_polls = 0;
                result.dropped += missed;
                batch.push_gap(cpu, missed);
            }
            Some(MoldEntry::Done) => {
                idle_polls = 0;
            }
            None => {
                if !recording.load(Ordering::Acquire) && worker.is_caught_up()? {
                    send_batch(&sender, lane, batch)?;
                    worker.publish_consumer_mark()?;
                    return Ok(result);
                }
                idle_polls = idle_polls.saturating_add(1);
                if idle_polls <= 64 {
                    std::hint::spin_loop();
                } else if idle_polls <= 128 {
                    thread::yield_now();
                } else {
                    thread::sleep(Duration::from_millis(5));
                }
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
