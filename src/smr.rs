//! Versioned on-disk recordings produced by the Samurai CLI.

use crate::tracepoint_schema::{CaptureKind, CapturePlan, GENERIC_CAPTURE_WORDS};
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    path::Path,
};

pub const MAGIC: [u8; 8] = *b"SAMURAI\0";
pub const VERSION: u16 = 5;
pub const DATA_FRAME: u8 = 1;
pub const GAP_FRAME: u8 = 2;
pub const PROCESS_FRAME: u8 = 3;
pub const FOOTER_FRAME: u8 = 255;
pub const PROCESS_METADATA_CAPACITY: usize = 65_536;
pub const PROCESS_COMM_BYTES: usize = 16;
pub const MAX_CAPTURE_EVENTS: usize = 8;

pub struct EncodedBatch {
    bytes: Vec<u8>,
    frames: usize,
    event_words: Vec<u16>,
}

impl EncodedBatch {
    pub fn with_capacity(bytes: usize, event_words: &[usize]) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            frames: 0,
            event_words: event_words
                .iter()
                .map(|words| u16::try_from(*words).expect("capture word count fits in u16"))
                .collect(),
        }
    }

    pub fn push_data(&mut self, cpu: u32, words: &[u64]) -> io::Result<()> {
        if words.len() != GENERIC_CAPTURE_WORDS {
            return Err(invalid(
                "Mold record does not match the generic capture ABI",
            ));
        }
        let event_id = usize::try_from(words[GENERIC_CAPTURE_WORDS - 1])
            .map_err(|_| data("BPF emitted an invalid event ID"))?;
        let data_words = usize::from(
            *self
                .event_words
                .get(event_id)
                .ok_or_else(|| data("BPF emitted an unconfigured event ID"))?,
        );
        self.bytes.push(DATA_FRAME);
        self.bytes.extend_from_slice(&cpu.to_le_bytes());
        self.bytes
            .extend_from_slice(&u16::try_from(event_id).unwrap().to_le_bytes());
        self.bytes
            .extend_from_slice(&(words[GENERIC_CAPTURE_WORDS - 2] as u32).to_le_bytes());
        for word in &words[..data_words] {
            self.bytes.extend_from_slice(&word.to_le_bytes());
        }
        self.frames += 1;
        Ok(())
    }

    pub fn push_gap(&mut self, cpu: u32, missed: u64) {
        self.bytes.push(GAP_FRAME);
        self.bytes.extend_from_slice(&cpu.to_le_bytes());
        self.bytes.extend_from_slice(&missed.to_le_bytes());
        self.frames += 1;
    }

    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }
    pub fn is_full(&self, frame_limit: usize) -> bool {
        self.frames == frame_limit
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.frames = 0;
    }
}

pub struct SmrWriter {
    output: File,
    bytes_written: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SmrSummary {
    pub version: u16,
    pub category: String,
    pub event: String,
    pub words: u16,
    pub cpus: Vec<u32>,
    pub fields: Vec<String>,
    pub events: Vec<SmrEvent>,
    pub processes: Vec<SmrProcess>,
    pub received: u64,
    pub dropped: u64,
    pub bytes: u64,
    pub started_realtime_ns: u64,
    pub started_monotonic_ns: u64,
    pub ended_realtime_ns: u64,
    pub ended_monotonic_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmrEvent {
    pub category: String,
    pub event: String,
    pub words: u16,
    pub fields: Vec<SmrField>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmrProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub comm: [u8; PROCESS_COMM_BYTES],
}

impl SmrProcess {
    pub fn name(&self) -> String {
        let end = self
            .comm
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmrField {
    pub name: String,
    pub kind: CaptureKind,
    pub signed: bool,
    pub destination: u16,
    pub words: u16,
    pub size: u16,
    pub capture_size: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RankedCount {
    pub value: String,
    pub count: u64,
    /// Maximum over-count introduced by the bounded Space-Saving table.
    pub error: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FieldAnalysis {
    pub name: String,
    pub values: Vec<RankedCount>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SmrAnalysis {
    pub summary: SmrSummary,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub out_of_order: u64,
    pub cpu_counts: Vec<(u32, u64)>,
    pub event_counts: Vec<(String, u64)>,
    pub pid_counts: Vec<RankedCount>,
    pub fields: Vec<FieldAnalysis>,
    pub file_activity: Option<Vec<FileActivity>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FileActivity {
    pub path: String,
    pub opens: u64,
    pub closes: u64,
    pub read_requested: u64,
    pub read_completed: u64,
    pub write_requested: u64,
    pub write_completed: u64,
    pub errors: u64,
}

#[derive(Clone, Copy)]
enum FileEventKind {
    OpenEnter,
    OpenExit,
    CloseEnter,
    CloseExit,
    ReadEnter,
    ReadExit,
    WriteEnter,
    WriteExit,
}

#[derive(Clone, Copy)]
struct RawFileEvent {
    timestamp: u64,
    ordinal: u64,
    pid: u32,
    tid: u32,
    kind: FileEventKind,
    first: u64,
    second: u64,
    path_len: usize,
    path: [u8; 128],
}

const TOP_PIDS: usize = 16;
const TOP_FIELD_VALUES: usize = 64;
const MAX_VALUE_BYTES: usize = GENERIC_CAPTURE_WORDS * 8;

#[derive(Clone)]
struct HeavyEntry {
    bytes: [u8; MAX_VALUE_BYTES],
    len: usize,
    count: u64,
    error: u64,
}

struct HeavyHitters {
    entries: Vec<HeavyEntry>,
}

impl HeavyHitters {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    fn observe(&mut self, value: &[u8]) -> io::Result<()> {
        if value.len() > MAX_VALUE_BYTES {
            return Err(data("decoded field value exceeds the fixed analysis bound"));
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.len == value.len() && entry.bytes[..entry.len] == *value)
        {
            entry.count = entry
                .count
                .checked_add(1)
                .ok_or_else(|| data("analysis count overflow"))?;
            return Ok(());
        }
        if self.entries.len() < self.entries.capacity() {
            let mut entry = HeavyEntry {
                bytes: [0; MAX_VALUE_BYTES],
                len: value.len(),
                count: 1,
                error: 0,
            };
            entry.bytes[..value.len()].copy_from_slice(value);
            self.entries.push(entry);
            return Ok(());
        }
        let entry = self
            .entries
            .iter_mut()
            .min_by_key(|entry| entry.count)
            .expect("heavy-hitter capacity is nonzero");
        let previous = entry.count;
        entry.bytes[..value.len()].copy_from_slice(value);
        entry.len = value.len();
        entry.count = previous
            .checked_add(1)
            .ok_or_else(|| data("analysis count overflow"))?;
        entry.error = previous;
        Ok(())
    }

    fn ranked(mut self, render: impl Fn(&[u8]) -> String) -> Vec<RankedCount> {
        self.entries.sort_unstable_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.bytes[..left.len].cmp(&right.bytes[..right.len]))
        });
        self.entries
            .into_iter()
            .map(|entry| RankedCount {
                value: render(&entry.bytes[..entry.len]),
                count: entry.count,
                error: entry.error,
            })
            .collect()
    }
}

struct SmrHeader {
    version: u16,
    cpus: Vec<u32>,
    events: Vec<SmrEvent>,
    started_realtime_ns: u64,
    started_monotonic_ns: u64,
}

fn read_header(input: &mut impl Read) -> io::Result<SmrHeader> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(data("not a Samurai recording"));
    }
    let version = read_u16(input)?;
    if !(2..=VERSION).contains(&version) {
        return Err(data("unsupported Samurai recording version"));
    }
    if read_u16(input)? != 0x0102 {
        return Err(data("invalid Samurai recording byte-order marker"));
    }
    let words = read_u16(input)?;
    if usize::from(words) < 2 || usize::from(words) > GENERIC_CAPTURE_WORDS {
        return Err(data("invalid Samurai recording word count"));
    }
    let cpu_count = read_u16(input)?;
    let descriptor_count = read_u16(input)?;
    if read_u16(input)? != 0 {
        return Err(data("nonzero reserved header field"));
    }
    let started_realtime_ns = read_u64(input)?;
    let started_monotonic_ns = read_u64(input)?;
    let (legacy_category, legacy_event) = if version < 4 {
        (Some(read_string(input)?), Some(read_string(input)?))
    } else {
        (None, None)
    };
    let cpus = (0..cpu_count)
        .map(|_| read_u32(input))
        .collect::<io::Result<Vec<_>>>()?;
    if cpus.is_empty() || cpus.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(data(
            "recording CPU list must be nonempty, sorted, and unique",
        ));
    }
    let events = if version < 4 {
        vec![SmrEvent {
            category: legacy_category.unwrap(),
            event: legacy_event.unwrap(),
            words,
            fields: read_fields(input, descriptor_count, words)?,
        }]
    } else {
        if descriptor_count == 0 || usize::from(descriptor_count) > MAX_CAPTURE_EVENTS {
            return Err(data("invalid recording event count"));
        }
        let mut events = Vec::with_capacity(usize::from(descriptor_count));
        for _ in 0..descriptor_count {
            let category = read_string(input)?;
            let event = read_string(input)?;
            let event_words = read_u16(input)?;
            let field_count = read_u16(input)?;
            let maximum_words = if version >= 5 {
                GENERIC_CAPTURE_WORDS as u16 - 2
            } else {
                GENERIC_CAPTURE_WORDS as u16 - 1
            };
            if !(2..=maximum_words).contains(&event_words) {
                return Err(data("invalid event record word count"));
            }
            let fields = read_fields(input, field_count, event_words)?;
            events.push(SmrEvent {
                category,
                event,
                words: event_words,
                fields,
            });
        }
        events
    };
    Ok(SmrHeader {
        version,
        cpus,
        events,
        started_realtime_ns,
        started_monotonic_ns,
    })
}

fn read_fields(
    input: &mut impl Read,
    field_count: u16,
    event_words: u16,
) -> io::Result<Vec<SmrField>> {
    let mut fields = Vec::with_capacity(usize::from(field_count));
    for _ in 0..field_count {
        let name = read_string(input)?;
        let kind = decode_kind(read_u8(input)?)?;
        let signed = match read_u8(input)? {
            0 => false,
            1 => true,
            _ => return Err(data("invalid field signed flag")),
        };
        let destination = read_u16(input)?;
        let field_words = read_u16(input)?;
        let size = read_u16(input)?;
        let capture_size = read_u32(input)?;
        if field_words == 0
            || usize::from(destination) + usize::from(field_words) > usize::from(event_words)
        {
            return Err(data("invalid field metadata"));
        }
        fields.push(SmrField {
            name,
            kind,
            signed,
            destination,
            words: field_words,
            size,
            capture_size,
        });
    }
    Ok(fields)
}

fn scan(
    path: &Path,
    mut data_frame: impl FnMut(u32, usize, u32, &[u8]) -> io::Result<()>,
    mut gap_frame: impl FnMut(u32, u64) -> io::Result<()>,
) -> io::Result<(SmrSummary, ())> {
    let file = File::open(path)?;
    let bytes = file.metadata()?.len();
    let mut input = BufReader::new(file);
    let header = read_header(&mut input)?;

    let mut observed = 0u64;
    let mut observed_gaps = 0u64;
    let mut processes = Vec::with_capacity(PROCESS_METADATA_CAPACITY);
    let mut last_process_pid = None;
    let mut record = [0u8; GENERIC_CAPTURE_WORDS * 8];
    loop {
        match read_u8(&mut input)? {
            DATA_FRAME => {
                let cpu = read_u32(&mut input)?;
                if header.cpus.binary_search(&cpu).is_err() {
                    return Err(data("data frame references an unrecorded CPU"));
                }
                let event_id = if header.version >= 4 {
                    usize::from(read_u16(&mut input)?)
                } else {
                    0
                };
                let event = header
                    .events
                    .get(event_id)
                    .ok_or_else(|| data("data frame references an unknown event"))?;
                let record = &mut record[..usize::from(event.words) * 8];
                let tid = if header.version >= 5 {
                    read_u32(&mut input)?
                } else {
                    0
                };
                input.read_exact(record)?;
                let payload_cpu = u64::from_le_bytes(record[8..16].try_into().unwrap()) as u32;
                if payload_cpu != cpu {
                    return Err(data("frame CPU does not match its payload"));
                }
                let tid = if tid == 0 {
                    (u64::from_le_bytes(record[8..16].try_into().unwrap()) >> 32) as u32
                } else {
                    tid
                };
                data_frame(cpu, event_id, tid, record)?;
                observed = observed
                    .checked_add(1)
                    .ok_or_else(|| data("record count overflow"))?;
            }
            GAP_FRAME => {
                let cpu = read_u32(&mut input)?;
                if header.cpus.binary_search(&cpu).is_err() {
                    return Err(data("gap frame references an unrecorded CPU"));
                }
                let missed = read_u64(&mut input)?;
                gap_frame(cpu, missed)?;
                observed_gaps = observed_gaps
                    .checked_add(missed)
                    .ok_or_else(|| data("gap count overflow"))?;
            }
            PROCESS_FRAME => {
                if header.version < 3 {
                    return Err(data(
                        "process frame is unsupported by this recording version",
                    ));
                }
                let pid = read_u32(&mut input)?;
                let parent_pid = read_u32(&mut input)?;
                let mut comm = [0; PROCESS_COMM_BYTES];
                input.read_exact(&mut comm)?;
                if pid == 0 || last_process_pid.is_some_and(|previous| pid <= previous) {
                    return Err(data("process frames must have sorted unique nonzero PIDs"));
                }
                last_process_pid = Some(pid);
                processes.push(SmrProcess {
                    pid,
                    parent_pid,
                    comm,
                });
            }
            FOOTER_FRAME => {
                let received = read_u64(&mut input)?;
                let dropped = read_u64(&mut input)?;
                let ended_realtime_ns = read_u64(&mut input)?;
                let ended_monotonic_ns = read_u64(&mut input)?;
                if ended_realtime_ns < header.started_realtime_ns
                    || ended_monotonic_ns < header.started_monotonic_ns
                {
                    return Err(data("recording clock anchors run backwards"));
                }
                if received != observed || dropped != observed_gaps {
                    return Err(data("recording footer totals do not match its frames"));
                }
                let mut trailing = [0];
                if input.read(&mut trailing)? != 0 {
                    return Err(data("recording contains data after its footer"));
                }
                let first_event = &header.events[0];
                let summary = SmrSummary {
                    version: header.version,
                    category: first_event.category.clone(),
                    event: first_event.event.clone(),
                    words: first_event.words,
                    cpus: header.cpus,
                    fields: first_event
                        .fields
                        .iter()
                        .map(|field| field.name.clone())
                        .collect(),
                    events: header.events,
                    processes,
                    received,
                    dropped,
                    bytes,
                    started_realtime_ns: header.started_realtime_ns,
                    started_monotonic_ns: header.started_monotonic_ns,
                    ended_realtime_ns,
                    ended_monotonic_ns,
                };
                return Ok((summary, ()));
            }
            _ => return Err(data("recording contains an unknown frame type")),
        }
    }
}

pub fn inspect(path: &Path) -> io::Result<SmrSummary> {
    scan(path, |_, _, _, _| Ok(()), |_, _| Ok(())).map(|(summary, _)| summary)
}

pub fn analyze(path: &Path) -> io::Result<SmrAnalysis> {
    let inspected = inspect(path)?;
    let mut metadata = BufReader::new(File::open(path)?);
    let header = read_header(&mut metadata)?;
    let mut first_timestamp_ns = None::<u64>;
    let mut last_timestamp_ns = None::<u64>;
    let mut previous_timestamp_ns = None::<u64>;
    let mut out_of_order = 0u64;
    let mut cpu_counts = vec![0u64; header.cpus.len()];
    let mut pid_counts = HeavyHitters::new(TOP_PIDS);
    let file_preset = is_file_preset(&header.events);
    let raw_capacity = if file_preset {
        usize::try_from(inspected.received)
            .map_err(|_| data("recording event count exceeds addressable memory"))?
    } else {
        0
    };
    let mut raw_file_events = Vec::with_capacity(raw_capacity);
    let mut ordinal = 0u64;
    let mut event_counts = vec![0u64; header.events.len()];
    let mut field_counts = header
        .events
        .iter()
        .map(|event| {
            (0..event.fields.len())
                .map(|_| HeavyHitters::new(TOP_FIELD_VALUES))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let (summary, ()) = scan(
        path,
        |cpu, event_id, tid, record| {
            let timestamp = u64::from_le_bytes(record[..8].try_into().unwrap());
            first_timestamp_ns =
                Some(first_timestamp_ns.map_or(timestamp, |old| old.min(timestamp)));
            last_timestamp_ns = Some(last_timestamp_ns.map_or(timestamp, |old| old.max(timestamp)));
            if previous_timestamp_ns.is_some_and(|previous| timestamp < previous) {
                out_of_order = out_of_order
                    .checked_add(1)
                    .ok_or_else(|| data("analysis count overflow"))?;
            }
            previous_timestamp_ns = Some(timestamp);
            let cpu_index = header
                .cpus
                .binary_search(&cpu)
                .expect("scan validated the frame CPU");
            cpu_counts[cpu_index] = cpu_counts[cpu_index]
                .checked_add(1)
                .ok_or_else(|| data("analysis count overflow"))?;
            let identity = u64::from_le_bytes(record[8..16].try_into().unwrap());
            pid_counts.observe(&((identity >> 32) as u32).to_le_bytes())?;
            if file_preset {
                raw_file_events.push(decode_file_event(
                    &header.events[event_id],
                    record,
                    tid,
                    ordinal,
                )?);
                ordinal += 1;
            }
            event_counts[event_id] = event_counts[event_id]
                .checked_add(1)
                .ok_or_else(|| data("analysis count overflow"))?;
            for (field, counts) in header.events[event_id]
                .fields
                .iter()
                .zip(&mut field_counts[event_id])
            {
                let start = usize::from(field.destination) * 8;
                let end = start + usize::from(field.words) * 8;
                counts.observe(&record[start..end])?;
            }
            Ok(())
        },
        |_, _| Ok(()),
    )?;

    let cpu_counts = header.cpus.into_iter().zip(cpu_counts).collect();
    let pid_counts = pid_counts.ranked(|bytes| {
        let pid = u32::from_le_bytes(bytes.try_into().expect("PID keys are four bytes"));
        match summary
            .processes
            .binary_search_by_key(&pid, |process| process.pid)
        {
            Ok(index) => {
                let process = summary.processes[index];
                format!(
                    "{} (PID {}, parent {})",
                    process.name(),
                    process.pid,
                    process.parent_pid
                )
            }
            Err(_) => pid.to_string(),
        }
    });
    let event_counts = header
        .events
        .iter()
        .zip(event_counts)
        .map(|(event, count)| (format!("{}:{}", event.category, event.event), count))
        .collect();
    let fields = header
        .events
        .into_iter()
        .zip(field_counts)
        .flat_map(|(event, counts)| {
            let event_name = format!("{}:{}", event.category, event.event);
            event
                .fields
                .into_iter()
                .zip(counts)
                .map(move |(field, counts)| FieldAnalysis {
                    name: format!("{event_name}.{}", field.name),
                    values: counts.ranked(|bytes| render_field_value(&field, bytes)),
                })
        })
        .collect();
    let file_activity = if file_preset {
        Some(correlate_file_activity(raw_file_events)?)
    } else {
        None
    };
    Ok(SmrAnalysis {
        summary,
        first_timestamp_ns,
        last_timestamp_ns,
        out_of_order,
        cpu_counts,
        event_counts,
        pid_counts,
        fields,
        file_activity,
    })
}

fn render_field_value(field: &SmrField, bytes: &[u8]) -> String {
    match field.kind {
        CaptureKind::Scalar if field.signed => {
            i64::from_le_bytes(bytes[..8].try_into().unwrap()).to_string()
        }
        CaptureKind::Scalar | CaptureKind::PointerAddress | CaptureKind::FunctionPointer
            if field.size <= 8 =>
        {
            u64::from_le_bytes(bytes[..8].try_into().unwrap()).to_string()
        }
        CaptureKind::UserString | CaptureKind::KernelString => {
            let metadata = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let error = metadata >> 32;
            if error != 0 {
                return format!("<read error {}>", error as u32 as i32);
            }
            let length = (metadata as u32 as usize).min(bytes.len().saturating_sub(8));
            String::from_utf8_lossy(&bytes[8..8 + length]).into_owned()
        }
        CaptureKind::DataLoc
        | CaptureKind::RelativeDataLoc
        | CaptureKind::UserBytes
        | CaptureKind::KernelBytes => {
            let metadata = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let captured = (metadata as u32 as usize).min(bytes.len().saturating_sub(8));
            let original = metadata >> 32;
            format!(
                "{} (captured {captured}/{original} bytes)",
                hex(&bytes[8..8 + captured])
            )
        }
        _ => hex(&bytes[..usize::from(field.size).min(bytes.len())]),
    }
}

fn is_file_preset(events: &[SmrEvent]) -> bool {
    const NAMES: [&str; 8] = [
        "sys_enter_openat",
        "sys_exit_openat",
        "sys_enter_close",
        "sys_exit_close",
        "sys_enter_read",
        "sys_exit_read",
        "sys_enter_write",
        "sys_exit_write",
    ];
    events.len() == NAMES.len()
        && events
            .iter()
            .zip(NAMES)
            .all(|(event, name)| event.category == "syscalls" && event.event == name)
}

fn decode_file_event(
    event: &SmrEvent,
    record: &[u8],
    tid: u32,
    ordinal: u64,
) -> io::Result<RawFileEvent> {
    let kind = match event.event.as_str() {
        "sys_enter_openat" => FileEventKind::OpenEnter,
        "sys_exit_openat" => FileEventKind::OpenExit,
        "sys_enter_close" => FileEventKind::CloseEnter,
        "sys_exit_close" => FileEventKind::CloseExit,
        "sys_enter_read" => FileEventKind::ReadEnter,
        "sys_exit_read" => FileEventKind::ReadExit,
        "sys_enter_write" => FileEventKind::WriteEnter,
        "sys_exit_write" => FileEventKind::WriteExit,
        _ => return Err(data("file preset contains an unexpected event")),
    };
    let scalar = |name: &str| -> io::Result<u64> {
        let field = event
            .fields
            .iter()
            .find(|field| field.name == name)
            .ok_or_else(|| data("file preset field is missing"))?;
        let start = usize::from(field.destination) * 8;
        Ok(u64::from_le_bytes(
            record[start..start + 8].try_into().unwrap(),
        ))
    };
    let mut path = [0u8; 128];
    let mut path_len = 0;
    let (first, second) = match kind {
        FileEventKind::OpenEnter => {
            let field = event
                .fields
                .iter()
                .find(|field| field.name == "filename")
                .ok_or_else(|| data("file preset filename field is missing"))?;
            let start = usize::from(field.destination) * 8;
            let metadata = u64::from_le_bytes(record[start..start + 8].try_into().unwrap());
            if metadata >> 32 == 0 {
                path_len = (metadata as u32 as usize).min(path.len());
                path[..path_len].copy_from_slice(&record[start + 8..start + 8 + path_len]);
            }
            (scalar("flags")?, scalar("mode")?)
        }
        FileEventKind::ReadEnter | FileEventKind::WriteEnter => (scalar("fd")?, scalar("count")?),
        FileEventKind::CloseEnter => (scalar("fd")?, 0),
        FileEventKind::OpenExit
        | FileEventKind::CloseExit
        | FileEventKind::ReadExit
        | FileEventKind::WriteExit => (scalar("ret")?, 0),
    };
    let identity = u64::from_le_bytes(record[8..16].try_into().unwrap());
    Ok(RawFileEvent {
        timestamp: u64::from_le_bytes(record[..8].try_into().unwrap()),
        ordinal,
        pid: (identity >> 32) as u32,
        tid,
        kind,
        first,
        second,
        path_len,
        path,
    })
}

enum PendingFileCall {
    Open { pid: u32, path: String },
    Close { pid: u32, fd: u32 },
    Read { pid: u32, fd: u32, requested: u64 },
    Write { pid: u32, fd: u32, requested: u64 },
}

fn correlate_file_activity(mut events: Vec<RawFileEvent>) -> io::Result<Vec<FileActivity>> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    events.sort_unstable_by_key(|event| (event.timestamp, event.ordinal));
    let capacity = events.len().min(PROCESS_METADATA_CAPACITY);
    let mut pending = FxHashMap::with_capacity_and_hasher(capacity, FxBuildHasher);
    let mut descriptors = FxHashMap::with_capacity_and_hasher(capacity, FxBuildHasher);
    let mut activity = FxHashMap::with_capacity_and_hasher(capacity, FxBuildHasher);
    for event in events {
        match event.kind {
            FileEventKind::OpenEnter => {
                let path = if event.path_len == 0 {
                    "<unreadable path>".to_owned()
                } else {
                    String::from_utf8_lossy(&event.path[..event.path_len]).into_owned()
                };
                pending.insert(
                    event.tid,
                    PendingFileCall::Open {
                        pid: event.pid,
                        path,
                    },
                );
            }
            FileEventKind::CloseEnter => {
                pending.insert(
                    event.tid,
                    PendingFileCall::Close {
                        pid: event.pid,
                        fd: event.first as u32,
                    },
                );
            }
            FileEventKind::ReadEnter => {
                pending.insert(
                    event.tid,
                    PendingFileCall::Read {
                        pid: event.pid,
                        fd: event.first as u32,
                        requested: event.second,
                    },
                );
            }
            FileEventKind::WriteEnter => {
                pending.insert(
                    event.tid,
                    PendingFileCall::Write {
                        pid: event.pid,
                        fd: event.first as u32,
                        requested: event.second,
                    },
                );
            }
            FileEventKind::OpenExit => {
                let Some(PendingFileCall::Open { pid, path }) = pending.remove(&event.tid) else {
                    continue;
                };
                let stats = activity
                    .entry(path.clone())
                    .or_insert_with(|| empty_file_activity(path.clone()));
                let result = event.first as i64;
                if result >= 0 {
                    checked_add(&mut stats.opens, 1)?;
                    descriptors.insert((pid, result as u32), path);
                } else {
                    checked_add(&mut stats.errors, 1)?;
                }
            }
            FileEventKind::CloseExit => {
                let Some(PendingFileCall::Close { pid, fd }) = pending.remove(&event.tid) else {
                    continue;
                };
                if let Some(path) = descriptors.get(&(pid, fd)).cloned() {
                    let stats = activity
                        .entry(path.clone())
                        .or_insert_with(|| empty_file_activity(path));
                    if event.first as i64 == 0 {
                        checked_add(&mut stats.closes, 1)?;
                        descriptors.remove(&(pid, fd));
                    } else {
                        checked_add(&mut stats.errors, 1)?;
                    }
                }
            }
            FileEventKind::ReadExit | FileEventKind::WriteExit => {
                let Some(call) = pending.remove(&event.tid) else {
                    continue;
                };
                let (pid, fd, requested, write) = match (event.kind, call) {
                    (FileEventKind::ReadExit, PendingFileCall::Read { pid, fd, requested }) => {
                        (pid, fd, requested, false)
                    }
                    (FileEventKind::WriteExit, PendingFileCall::Write { pid, fd, requested }) => {
                        (pid, fd, requested, true)
                    }
                    _ => continue,
                };
                let path = descriptors
                    .get(&(pid, fd))
                    .cloned()
                    .unwrap_or_else(|| format!("<PID {pid} FD {fd}>"));
                let stats = activity
                    .entry(path.clone())
                    .or_insert_with(|| empty_file_activity(path));
                if write {
                    checked_add(&mut stats.write_requested, requested)?;
                } else {
                    checked_add(&mut stats.read_requested, requested)?;
                }
                let result = event.first as i64;
                if result < 0 {
                    checked_add(&mut stats.errors, 1)?;
                } else if write {
                    checked_add(&mut stats.write_completed, result as u64)?;
                } else {
                    checked_add(&mut stats.read_completed, result as u64)?;
                }
            }
        }
    }
    let mut activity = activity.into_values().collect::<Vec<_>>();
    activity.sort_unstable_by(|left, right| {
        (right.read_completed + right.write_completed)
            .cmp(&(left.read_completed + left.write_completed))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(activity)
}

fn checked_add(value: &mut u64, increment: u64) -> io::Result<()> {
    *value = value
        .checked_add(increment)
        .ok_or_else(|| data("file activity count overflow"))?;
    Ok(())
}

fn empty_file_activity(path: String) -> FileActivity {
    FileActivity {
        path,
        opens: 0,
        closes: 0,
        read_requested: 0,
        read_completed: 0,
        write_requested: 0,
        write_completed: 0,
        errors: 0,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

impl SmrWriter {
    pub fn create(path: &Path, plan: &CapturePlan, cpus: &[usize]) -> io::Result<Self> {
        Self::create_multi(path, std::slice::from_ref(plan), cpus)
    }

    pub fn create_multi(path: &Path, plans: &[CapturePlan], cpus: &[usize]) -> io::Result<Self> {
        validate_plans(plans, cpus)?;
        let file = File::create(path)?;
        let mut writer = Self {
            output: file,
            bytes_written: 0,
        };
        writer.write_header(plans, cpus)?;
        Ok(writer)
    }

    fn write_header(&mut self, plans: &[CapturePlan], cpus: &[usize]) -> io::Result<()> {
        self.bytes(&MAGIC)?;
        self.u16(VERSION)?;
        self.u16(0x0102)?;
        self.u16(usize_u16(
            plans.iter().map(|plan| plan.words).max().unwrap(),
            "record word count",
        )?)?;
        self.u16(usize_u16(cpus.len(), "CPU count")?)?;
        self.u16(usize_u16(plans.len(), "event count")?)?;
        self.u16(0)?;
        let (realtime_ns, monotonic_ns) = clock_pair()?;
        self.u64(realtime_ns)?;
        self.u64(monotonic_ns)?;
        for &cpu in cpus {
            self.u32(u32::try_from(cpu).map_err(|_| invalid("CPU number is too large"))?)?;
        }
        for plan in plans {
            self.string(&plan.category)?;
            self.string(&plan.event)?;
            self.u16(usize_u16(plan.words, "record word count")?)?;
            self.u16(usize_u16(plan.fields.len(), "field count")?)?;
            for field in &plan.fields {
                self.string(&field.name)?;
                self.u8(kind_code(field.kind))?;
                self.u8(u8::from(field.signed))?;
                self.u16(usize_u16(field.destination_word, "field destination")?)?;
                self.u16(usize_u16(field.words, "field word count")?)?;
                self.u16(usize_u16(field.size, "field size")?)?;
                self.u32(
                    u32::try_from(field.capture_size)
                        .map_err(|_| invalid("capture size is too large"))?,
                )?;
            }
        }
        self.output.flush()
    }

    pub fn write_encoded_batch(&mut self, batch: &EncodedBatch) -> io::Result<()> {
        self.bytes(batch.bytes())
    }

    pub fn finish(
        mut self,
        received: u64,
        dropped: u64,
        processes: &[SmrProcess],
    ) -> io::Result<u64> {
        if processes.windows(2).any(|pair| pair[0].pid >= pair[1].pid)
            || processes.iter().any(|process| process.pid == 0)
        {
            return Err(invalid(
                "process metadata must have sorted unique nonzero PIDs",
            ));
        }
        for process in processes {
            self.u8(PROCESS_FRAME)?;
            self.u32(process.pid)?;
            self.u32(process.parent_pid)?;
            self.bytes(&process.comm)?;
        }
        self.u8(FOOTER_FRAME)?;
        self.u64(received)?;
        self.u64(dropped)?;
        let (realtime_ns, monotonic_ns) = clock_pair()?;
        self.u64(realtime_ns)?;
        self.u64(monotonic_ns)?;
        self.output.flush()?;
        Ok(self.bytes_written)
    }

    fn string(&mut self, value: &str) -> io::Result<()> {
        self.u16(usize_u16(value.len(), "string length")?)?;
        self.bytes(value.as_bytes())
    }

    fn u8(&mut self, value: u8) -> io::Result<()> {
        self.bytes(&[value])
    }
    fn u16(&mut self, value: u16) -> io::Result<()> {
        self.bytes(&value.to_le_bytes())
    }
    fn u32(&mut self, value: u32) -> io::Result<()> {
        self.bytes(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) -> io::Result<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.output.write_all(bytes)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("recording size overflow"))?;
        Ok(())
    }
}

fn clock_pair() -> io::Result<(u64, u64)> {
    fn read(clock: libc::clockid_t) -> io::Result<u64> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
            return Err(io::Error::last_os_error());
        }
        u64::try_from(value.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| nanos.checked_add(value.tv_nsec as u64))
            .ok_or_else(|| io::Error::other("clock value does not fit in u64 nanoseconds"))
    }
    Ok((read(libc::CLOCK_REALTIME)?, read(libc::CLOCK_MONOTONIC)?))
}

fn validate_plans(plans: &[CapturePlan], cpus: &[usize]) -> io::Result<()> {
    if plans.is_empty() || plans.len() > MAX_CAPTURE_EVENTS {
        return Err(invalid(
            "capture event count is outside the generic capture ABI",
        ));
    }
    for plan in plans {
        if !(2..GENERIC_CAPTURE_WORDS - 1).contains(&plan.words) {
            return Err(invalid(
                "record word count is outside the generic capture ABI",
            ));
        }
        if cpus.is_empty() {
            return Err(invalid("CPU selection is empty"));
        }
        if cpus.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("CPU selection must be sorted and unique"));
        }
        for &cpu in cpus {
            u32::try_from(cpu).map_err(|_| invalid("CPU number is too large"))?;
        }
        for field in &plan.fields {
            if field.words == 0
                || field
                    .destination_word
                    .checked_add(field.words)
                    .is_none_or(|end| end > plan.words)
            {
                return Err(invalid("capture field lies outside the record"));
            }
        }
    }
    Ok(())
}

fn usize_u16(value: usize, name: &str) -> io::Result<u16> {
    u16::try_from(value).map_err(|_| invalid(&format!("{name} is too large")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u8(input: &mut impl Read) -> io::Result<u8> {
    let mut bytes = [0; 1];
    input.read_exact(&mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(input: &mut impl Read) -> io::Result<u16> {
    let mut bytes = [0; 2];
    input.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_string(input: &mut impl Read) -> io::Result<String> {
    let length = usize::from(read_u16(input)?);
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| data("recording contains invalid UTF-8 metadata"))
}

const fn kind_code(kind: CaptureKind) -> u8 {
    match kind {
        CaptureKind::Scalar => 0,
        CaptureKind::FixedArray => 1,
        CaptureKind::FixedStruct => 2,
        CaptureKind::PointerAddress => 3,
        CaptureKind::FunctionPointer => 4,
        CaptureKind::DataLoc => 5,
        CaptureKind::RelativeDataLoc => 6,
        CaptureKind::UserString => 7,
        CaptureKind::UserBytes => 8,
        CaptureKind::KernelString => 9,
        CaptureKind::KernelBytes => 10,
    }
}

fn decode_kind(code: u8) -> io::Result<CaptureKind> {
    match code {
        0 => Ok(CaptureKind::Scalar),
        1 => Ok(CaptureKind::FixedArray),
        2 => Ok(CaptureKind::FixedStruct),
        3 => Ok(CaptureKind::PointerAddress),
        4 => Ok(CaptureKind::FunctionPointer),
        5 => Ok(CaptureKind::DataLoc),
        6 => Ok(CaptureKind::RelativeDataLoc),
        7 => Ok(CaptureKind::UserString),
        8 => Ok(CaptureKind::UserBytes),
        9 => Ok(CaptureKind::KernelString),
        10 => Ok(CaptureKind::KernelBytes),
        _ => Err(data("invalid field capture kind")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracepoint_schema::CaptureField;

    #[test]
    fn round_trips_header_records_gaps_and_footer() {
        let path = std::env::temp_dir().join(format!(
            "samurai-smr-{}-{}.smr",
            std::process::id(),
            clock_pair().unwrap().0
        ));
        let plan = CapturePlan {
            category: "sched".to_owned(),
            event: "sched_switch".to_owned(),
            fields: vec![CaptureField {
                name: "next_pid".to_owned(),
                source_offset: 8,
                size: 4,
                signed: true,
                destination_word: 2,
                words: 1,
                kind: CaptureKind::Scalar,
                capture_size: 0,
                length_source: None,
            }],
            words: 3,
            context_size: 12,
        };
        let mut writer = SmrWriter::create(&path, &plan, &[2, 7]).unwrap();
        let mut batch = EncodedBatch::with_capacity(128, &[plan.words]);
        let mut words = [42; GENERIC_CAPTURE_WORDS];
        words[1] = (9u64 << 32) | 7;
        words[GENERIC_CAPTURE_WORDS - 1] = 0;
        batch.push_data(7, &words).unwrap();
        batch.push_gap(2, 3);
        writer.write_encoded_batch(&batch).unwrap();
        let process = SmrProcess {
            pid: 9,
            parent_pid: 4,
            comm: {
                let mut comm = [0; PROCESS_COMM_BYTES];
                comm[..5].copy_from_slice(b"rustc");
                comm
            },
        };
        let bytes = writer.finish(1, 3, &[process]).unwrap();

        let summary = inspect(&path).unwrap();
        assert_eq!(summary.category, "sched");
        assert_eq!(summary.event, "sched_switch");
        assert_eq!(summary.cpus, [2, 7]);
        assert_eq!(summary.fields, ["next_pid"]);
        assert_eq!(summary.processes, [process]);
        assert_eq!(summary.received, 1);
        assert_eq!(summary.dropped, 3);
        assert_eq!(summary.bytes, bytes);

        let analysis = analyze(&path).unwrap();
        assert_eq!(analysis.cpu_counts, [(2, 0), (7, 1)]);
        assert_eq!(analysis.pid_counts[0].value, "rustc (PID 9, parent 4)");
        assert_eq!(analysis.pid_counts[0].count, 1);
        assert_eq!(
            analysis.event_counts,
            [("sched:sched_switch".to_owned(), 1)]
        );
        assert_eq!(analysis.fields[0].name, "sched:sched_switch.next_pid");
        assert_eq!(analysis.fields[0].values[0].value, "42");
        assert_eq!(analysis.fields[0].values[0].count, 1);
        assert_eq!(analysis.first_timestamp_ns, Some(42));
        assert_eq!(analysis.last_timestamp_ns, Some(42));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn round_trips_multiple_event_schemas_and_frames() {
        let path = std::env::temp_dir().join(format!(
            "samurai-smr-multi-{}-{}.smr",
            std::process::id(),
            clock_pair().unwrap().0
        ));
        let plan = |event: &str, field: &str| CapturePlan {
            category: "syscalls".to_owned(),
            event: event.to_owned(),
            fields: vec![CaptureField {
                name: field.to_owned(),
                source_offset: 16,
                size: 8,
                signed: false,
                destination_word: 2,
                words: 1,
                kind: CaptureKind::Scalar,
                capture_size: 0,
                length_source: None,
            }],
            words: 3,
            context_size: 24,
        };
        let plans = [
            plan("sys_enter_read", "count"),
            plan("sys_enter_write", "count"),
        ];
        let mut writer = SmrWriter::create_multi(&path, &plans, &[3]).unwrap();
        let mut batch = EncodedBatch::with_capacity(256, &[3, 3]);
        let mut words = [0; GENERIC_CAPTURE_WORDS];
        words[0] = 10;
        words[1] = (12u64 << 32) | 3;
        words[2] = 64;
        batch.push_data(3, &words).unwrap();
        words[0] = 11;
        words[2] = 128;
        words[GENERIC_CAPTURE_WORDS - 1] = 1;
        batch.push_data(3, &words).unwrap();
        writer.write_encoded_batch(&batch).unwrap();
        writer.finish(2, 0, &[]).unwrap();

        let analysis = analyze(&path).unwrap();
        assert_eq!(analysis.summary.events.len(), 2);
        assert_eq!(
            analysis.event_counts,
            [
                ("syscalls:sys_enter_read".to_owned(), 1),
                ("syscalls:sys_enter_write".to_owned(), 1),
            ]
        );
        assert_eq!(analysis.fields[0].values[0].value, "64");
        assert_eq!(analysis.fields[1].values[0].value, "128");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn correlates_file_descriptors_with_completed_io() {
        let raw = |timestamp, kind, first, second, path: &[u8]| {
            let mut stored_path = [0; 128];
            stored_path[..path.len()].copy_from_slice(path);
            RawFileEvent {
                timestamp,
                ordinal: timestamp,
                pid: 7,
                tid: 9,
                kind,
                first,
                second,
                path_len: path.len(),
                path: stored_path,
            }
        };
        let activity = correlate_file_activity(vec![
            raw(1, FileEventKind::OpenEnter, 0, 0, b"/tmp/result"),
            raw(2, FileEventKind::OpenExit, 4, 0, b""),
            raw(3, FileEventKind::WriteEnter, 4, 20, b""),
            raw(4, FileEventKind::WriteExit, 12, 0, b""),
            raw(5, FileEventKind::ReadEnter, 4, 30, b""),
            raw(6, FileEventKind::ReadExit, 8, 0, b""),
            raw(7, FileEventKind::CloseEnter, 4, 0, b""),
            raw(8, FileEventKind::CloseExit, 0, 0, b""),
        ])
        .unwrap();
        assert_eq!(activity.len(), 1);
        assert_eq!(activity[0].path, "/tmp/result");
        assert_eq!(activity[0].opens, 1);
        assert_eq!(activity[0].closes, 1);
        assert_eq!(activity[0].write_requested, 20);
        assert_eq!(activity[0].write_completed, 12);
        assert_eq!(activity[0].read_requested, 30);
        assert_eq!(activity[0].read_completed, 8);
        assert_eq!(activity[0].errors, 0);
    }
}
