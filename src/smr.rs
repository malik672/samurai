//! Versioned on-disk recordings produced by the Samurai CLI.

use crate::tracepoint_schema::{CaptureKind, CapturePlan, GENERIC_CAPTURE_WORDS};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    path::Path,
};

pub const MAGIC: [u8; 8] = *b"SAMURAI\0";
pub const VERSION: u16 = 2;
pub const DATA_FRAME: u8 = 1;
pub const GAP_FRAME: u8 = 2;
pub const FOOTER_FRAME: u8 = 255;

pub struct EncodedBatch {
    bytes: Vec<u8>,
    frames: usize,
    data_words: usize,
}

impl EncodedBatch {
    pub fn with_capacity(bytes: usize, data_words: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            frames: 0,
            data_words,
        }
    }

    pub fn push_data(&mut self, cpu: u32, words: &[u64]) {
        assert_eq!(
            words.len(),
            self.data_words,
            "SMR data width changed after startup"
        );
        self.bytes.push(DATA_FRAME);
        self.bytes.extend_from_slice(&cpu.to_le_bytes());
        for word in words {
            self.bytes.extend_from_slice(&word.to_le_bytes());
        }
        self.frames += 1;
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
    pub category: String,
    pub event: String,
    pub words: u16,
    pub cpus: Vec<u32>,
    pub fields: Vec<String>,
    pub received: u64,
    pub dropped: u64,
    pub bytes: u64,
    pub started_realtime_ns: u64,
    pub started_monotonic_ns: u64,
    pub ended_realtime_ns: u64,
    pub ended_monotonic_ns: u64,
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
    pub pid_counts: Vec<RankedCount>,
    pub fields: Vec<FieldAnalysis>,
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
    category: String,
    event: String,
    words: u16,
    cpus: Vec<u32>,
    fields: Vec<SmrField>,
    started_realtime_ns: u64,
    started_monotonic_ns: u64,
}

fn read_header(input: &mut impl Read) -> io::Result<SmrHeader> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(data("not a Samurai recording"));
    }
    if read_u16(input)? != VERSION {
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
    let field_count = read_u16(input)?;
    if read_u16(input)? != 0 {
        return Err(data("nonzero reserved header field"));
    }
    let started_realtime_ns = read_u64(input)?;
    let started_monotonic_ns = read_u64(input)?;
    let category = read_string(input)?;
    let event = read_string(input)?;
    let cpus = (0..cpu_count)
        .map(|_| read_u32(input))
        .collect::<io::Result<Vec<_>>>()?;
    if cpus.is_empty() || cpus.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(data(
            "recording CPU list must be nonempty, sorted, and unique",
        ));
    }
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
            || usize::from(destination) + usize::from(field_words) > usize::from(words)
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
    Ok(SmrHeader {
        category,
        event,
        words,
        cpus,
        fields,
        started_realtime_ns,
        started_monotonic_ns,
    })
}

fn scan(
    path: &Path,
    mut data_frame: impl FnMut(u32, &[u8]) -> io::Result<()>,
    mut gap_frame: impl FnMut(u32, u64) -> io::Result<()>,
) -> io::Result<(SmrSummary, Vec<SmrField>)> {
    let file = File::open(path)?;
    let bytes = file.metadata()?.len();
    let mut input = BufReader::new(file);
    let header = read_header(&mut input)?;

    let mut observed = 0u64;
    let mut observed_gaps = 0u64;
    let mut record = [0u8; GENERIC_CAPTURE_WORDS * 8];
    loop {
        match read_u8(&mut input)? {
            DATA_FRAME => {
                let cpu = read_u32(&mut input)?;
                if header.cpus.binary_search(&cpu).is_err() {
                    return Err(data("data frame references an unrecorded CPU"));
                }
                let record = &mut record[..usize::from(header.words) * 8];
                input.read_exact(record)?;
                let payload_cpu = u64::from_le_bytes(record[8..16].try_into().unwrap()) as u32;
                if payload_cpu != cpu {
                    return Err(data("frame CPU does not match its payload"));
                }
                data_frame(cpu, record)?;
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
                let summary = SmrSummary {
                    category: header.category,
                    event: header.event,
                    words: header.words,
                    cpus: header.cpus,
                    fields: header
                        .fields
                        .iter()
                        .map(|field| field.name.clone())
                        .collect(),
                    received,
                    dropped,
                    bytes,
                    started_realtime_ns: header.started_realtime_ns,
                    started_monotonic_ns: header.started_monotonic_ns,
                    ended_realtime_ns,
                    ended_monotonic_ns,
                };
                return Ok((summary, header.fields));
            }
            _ => return Err(data("recording contains an unknown frame type")),
        }
    }
}

pub fn inspect(path: &Path) -> io::Result<SmrSummary> {
    scan(path, |_, _| Ok(()), |_, _| Ok(())).map(|(summary, _)| summary)
}

pub fn analyze(path: &Path) -> io::Result<SmrAnalysis> {
    let mut metadata = BufReader::new(File::open(path)?);
    let header = read_header(&mut metadata)?;
    let mut first_timestamp_ns = None::<u64>;
    let mut last_timestamp_ns = None::<u64>;
    let mut previous_timestamp_ns = None::<u64>;
    let mut out_of_order = 0u64;
    let mut cpu_counts = vec![0u64; header.cpus.len()];
    let mut pid_counts = HeavyHitters::new(TOP_PIDS);
    let mut field_counts = (0..header.fields.len())
        .map(|_| HeavyHitters::new(TOP_FIELD_VALUES))
        .collect::<Vec<_>>();

    let (summary, fields) = scan(
        path,
        |cpu, record| {
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
            for (field, counts) in header.fields.iter().zip(&mut field_counts) {
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
        u32::from_le_bytes(bytes.try_into().expect("PID keys are four bytes")).to_string()
    });
    let fields = fields
        .into_iter()
        .zip(field_counts)
        .map(|(field, counts)| FieldAnalysis {
            name: field.name.clone(),
            values: counts.ranked(|bytes| render_field_value(&field, bytes)),
        })
        .collect();
    Ok(SmrAnalysis {
        summary,
        first_timestamp_ns,
        last_timestamp_ns,
        out_of_order,
        cpu_counts,
        pid_counts,
        fields,
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
        validate_plan(plan, cpus)?;
        let file = File::create(path)?;
        let mut writer = Self {
            output: file,
            bytes_written: 0,
        };
        writer.write_header(plan, cpus)?;
        Ok(writer)
    }

    fn write_header(&mut self, plan: &CapturePlan, cpus: &[usize]) -> io::Result<()> {
        self.bytes(&MAGIC)?;
        self.u16(VERSION)?;
        self.u16(0x0102)?;
        self.u16(usize_u16(plan.words, "record word count")?)?;
        self.u16(usize_u16(cpus.len(), "CPU count")?)?;
        self.u16(usize_u16(plan.fields.len(), "field count")?)?;
        self.u16(0)?;
        let (realtime_ns, monotonic_ns) = clock_pair()?;
        self.u64(realtime_ns)?;
        self.u64(monotonic_ns)?;
        self.string(&plan.category)?;
        self.string(&plan.event)?;
        for &cpu in cpus {
            self.u32(u32::try_from(cpu).map_err(|_| invalid("CPU number is too large"))?)?;
        }
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
        self.output.flush()
    }

    pub fn write_encoded_batch(&mut self, batch: &EncodedBatch) -> io::Result<()> {
        self.bytes(batch.bytes())
    }

    pub fn finish(mut self, received: u64, dropped: u64) -> io::Result<u64> {
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

fn validate_plan(plan: &CapturePlan, cpus: &[usize]) -> io::Result<()> {
    if !(2..=GENERIC_CAPTURE_WORDS).contains(&plan.words) {
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
        let mut batch = EncodedBatch::with_capacity(128, plan.words);
        let mut words = [42; GENERIC_CAPTURE_WORDS];
        words[1] = 7;
        batch.push_data(7, &words[..plan.words]);
        batch.push_gap(2, 3);
        writer.write_encoded_batch(&batch).unwrap();
        let bytes = writer.finish(1, 3).unwrap();

        let summary = inspect(&path).unwrap();
        assert_eq!(summary.category, "sched");
        assert_eq!(summary.event, "sched_switch");
        assert_eq!(summary.cpus, [2, 7]);
        assert_eq!(summary.fields, ["next_pid"]);
        assert_eq!(summary.received, 1);
        assert_eq!(summary.dropped, 3);
        assert_eq!(summary.bytes, bytes);

        let analysis = analyze(&path).unwrap();
        assert_eq!(analysis.cpu_counts, [(2, 0), (7, 1)]);
        assert_eq!(analysis.pid_counts[0].value, "0");
        assert_eq!(analysis.pid_counts[0].count, 1);
        assert_eq!(analysis.fields[0].name, "next_pid");
        assert_eq!(analysis.fields[0].values[0].value, "42");
        assert_eq!(analysis.fields[0].values[0].count, 1);
        assert_eq!(analysis.first_timestamp_ns, Some(42));
        assert_eq!(analysis.last_timestamp_ns, Some(42));
        std::fs::remove_file(path).unwrap();
    }
}
