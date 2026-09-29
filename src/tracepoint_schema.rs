//! Generate fixed Mold schemas from Linux tracepoint format descriptions.
use std::{collections::HashSet, fmt::Write as _, io};

const MOLD_METADATA_WORDS: usize = 2;
const BPF_STACK_RECORD_BUDGET: usize = 384;
pub const GENERIC_CAPTURE_WORDS: usize = 34;
pub const GENERIC_CAPTURE_OPERATIONS: usize = GENERIC_CAPTURE_WORDS - MOLD_METADATA_WORDS;
pub const DEFAULT_DYNAMIC_CAPTURE_BYTES: usize = 64;

const CAPTURE_SIGNED: u32 = 1 << 0;
const CAPTURE_DATA_LOC: u32 = 1 << 1;
const CAPTURE_RELATIVE: u32 = 1 << 2;
const CAPTURE_DYNAMIC_METADATA: u32 = 1 << 3;
const CAPTURE_USER_STRING: u32 = 1 << 4;
const CAPTURE_POINTER_BYTES: u32 = 1 << 5;
const CAPTURE_KERNEL_MEMORY: u32 = 1 << 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureKind {
    Scalar,
    FixedArray,
    FixedStruct,
    PointerAddress,
    FunctionPointer,
    DataLoc,
    RelativeDataLoc,
    UserString,
    UserBytes,
    KernelString,
    KernelBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerCapture {
    Address,
    UserString {
        max_len: usize,
    },
    UserBytes {
        length_field: &'static str,
        max_len: usize,
    },
    KernelString {
        max_len: usize,
    },
    KernelBytes {
        length_field: &'static str,
        max_len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePolicy {
    pub category: &'static str,
    pub event: &'static str,
    pub field: &'static str,
    pub capture: PointerCapture,
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyRegistry {
    policies: &'static [CapturePolicy],
}

const BUILTIN_POLICIES: &[CapturePolicy] = &[CapturePolicy {
    category: "syscalls",
    event: "sys_enter_openat",
    field: "filename",
    capture: PointerCapture::UserString { max_len: 128 },
}];

impl PolicyRegistry {
    pub const fn builtin() -> Self {
        Self {
            policies: BUILTIN_POLICIES,
        }
    }

    pub const fn empty() -> Self {
        Self { policies: &[] }
    }

    pub const fn from_static(policies: &'static [CapturePolicy]) -> Self {
        Self { policies }
    }

    fn capture_for(
        self,
        category: &str,
        event: &str,
        field: &TracepointField,
        available: &[TracepointField],
    ) -> io::Result<(PointerCapture, Option<(usize, usize)>)> {
        let Some(policy) = self.policies.iter().find(|policy| {
            policy.category == category && policy.event == event && policy.field == field.name
        }) else {
            return Ok((PointerCapture::Address, None));
        };
        if field.kind != CaptureKind::PointerAddress {
            return Err(invalid(format!(
                "policy for {category}:{event}.{} requires a pointer, running kernel declares {}",
                field.name, field.declaration
            )));
        }
        if !matches!(field.size, 4 | 8) {
            return Err(invalid(format!(
                "policy for {category}:{event}.{} requires a 4- or 8-byte pointer",
                field.name
            )));
        }
        let length = match policy.capture {
            PointerCapture::UserBytes { length_field, .. }
            | PointerCapture::KernelBytes { length_field, .. } => {
                let source = available
                    .iter()
                    .find(|candidate| candidate.name == length_field)
                    .ok_or_else(|| {
                        invalid(format!(
                            "policy for {category}:{event}.{} requires missing length field {length_field}",
                            field.name
                        ))
                    })?;
                if source.kind != CaptureKind::Scalar
                    || source.signed
                    || !matches!(source.size, 1 | 2 | 4 | 8)
                {
                    return Err(invalid(format!(
                        "policy length field {length_field} must be an unsigned fixed scalar"
                    )));
                }
                Some((source.offset, source.size))
            }
            _ => None,
        };
        Ok((policy.capture, length))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracepointField {
    pub declaration: String,
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub signed: bool,
    pub array_len: Option<usize>,
    pub kind: CaptureKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedTracepoint {
    pub rust: String,
    pub bpf_c: String,
    pub words: usize,
    pub capacity: usize,
}

/// A startup-time plan for copying fixed tracepoint fields into Mold words.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePlan {
    pub category: String,
    pub event: String,
    pub fields: Vec<CaptureField>,
    pub words: usize,
    pub context_size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureField {
    pub name: String,
    pub source_offset: usize,
    pub size: usize,
    pub signed: bool,
    pub destination_word: usize,
    pub words: usize,
    pub kind: CaptureKind,
    /// Maximum bytes copied for a dynamic field; zero for fixed fields.
    pub capture_size: usize,
    pub length_source: Option<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureOperation {
    pub source_offset: u32,
    pub size: u16,
    pub destination_word: u16,
    pub flags: u32,
    pub data_offset: u32,
    pub auxiliary_offset: u32,
    pub pointer_size: u16,
    pub auxiliary_size: u16,
}

impl CaptureOperation {
    /// Stable 24-byte ABI consumed by `examples/bpf/generic_tracepoint.c`.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..4].copy_from_slice(&self.source_offset.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.size.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.destination_word.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.data_offset.to_ne_bytes());
        bytes[16..20].copy_from_slice(&self.auxiliary_offset.to_ne_bytes());
        bytes[20..22].copy_from_slice(&self.pointer_size.to_ne_bytes());
        bytes[22..24].copy_from_slice(&self.auxiliary_size.to_ne_bytes());
        bytes
    }
}

impl CapturePlan {
    /// Discover and validate a fixed-field plan from the running kernel.
    pub fn discover(
        resolver: &crate::utils::tracepoint::TracepointResolver,
        category: &str,
        event: &str,
        selected: Option<&[String]>,
    ) -> io::Result<Self> {
        Self::discover_bounded(
            resolver,
            category,
            event,
            selected,
            DEFAULT_DYNAMIC_CAPTURE_BYTES,
        )
    }

    pub fn discover_bounded(
        resolver: &crate::utils::tracepoint::TracepointResolver,
        category: &str,
        event: &str,
        selected: Option<&[String]>,
        dynamic_capture_bytes: usize,
    ) -> io::Result<Self> {
        let format = resolver.format(category, event)?;
        capture_plan_with_registry(
            category,
            event,
            &format,
            selected,
            dynamic_capture_bytes,
            PolicyRegistry::builtin(),
        )
    }

    /// Lower fields into bounded operations understood by the generic BPF reader.
    pub fn operations(&self) -> io::Result<Vec<CaptureOperation>> {
        let mut operations = Vec::new();
        for field in &self.fields {
            if matches!(
                field.kind,
                CaptureKind::UserString | CaptureKind::KernelString
            ) {
                if field.capture_size != 128 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "generic BPF reader currently supports 128-byte user strings",
                    ));
                }
                operations.push(CaptureOperation {
                    source_offset: u32::try_from(field.source_offset).map_err(|_| {
                        io::Error::new(io::ErrorKind::Unsupported, "tracepoint offset exceeds u32")
                    })?,
                    size: 128,
                    destination_word: u16::try_from(field.destination_word).unwrap(),
                    flags: CAPTURE_USER_STRING
                        | if field.kind == CaptureKind::KernelString {
                            CAPTURE_KERNEL_MEMORY
                        } else {
                            0
                        },
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: u16::try_from(field.size).unwrap(),
                    auxiliary_size: 0,
                });
                continue;
            }
            if matches!(
                field.kind,
                CaptureKind::UserBytes | CaptureKind::KernelBytes
            ) {
                let (length_offset, length_size) = field.length_source.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "byte policy lacks length source",
                    )
                })?;
                let memory_flags = CAPTURE_POINTER_BYTES
                    | if field.kind == CaptureKind::KernelBytes {
                        CAPTURE_KERNEL_MEMORY
                    } else {
                        0
                    };
                operations.push(CaptureOperation {
                    source_offset: u32::try_from(field.source_offset).unwrap(),
                    size: u16::try_from(field.capture_size).unwrap(),
                    destination_word: u16::try_from(field.destination_word).unwrap(),
                    flags: memory_flags | CAPTURE_DYNAMIC_METADATA,
                    data_offset: 0,
                    auxiliary_offset: u32::try_from(length_offset).unwrap(),
                    pointer_size: u16::try_from(field.size).unwrap(),
                    auxiliary_size: u16::try_from(length_size).unwrap(),
                });
                let mut copied = 0usize;
                while copied < field.capture_size {
                    let size = (field.capture_size - copied).min(8);
                    operations.push(CaptureOperation {
                        source_offset: u32::try_from(field.source_offset).unwrap(),
                        size: u16::try_from(size).unwrap(),
                        destination_word: u16::try_from(field.destination_word + 1 + copied / 8)
                            .unwrap(),
                        flags: memory_flags,
                        data_offset: u32::try_from(copied).unwrap(),
                        auxiliary_offset: u32::try_from(length_offset).unwrap(),
                        pointer_size: u16::try_from(field.size).unwrap(),
                        auxiliary_size: u16::try_from(length_size).unwrap(),
                    });
                    copied += size;
                }
                continue;
            }
            if matches!(
                field.kind,
                CaptureKind::DataLoc | CaptureKind::RelativeDataLoc
            ) {
                let dynamic_flags = CAPTURE_DATA_LOC
                    | if field.kind == CaptureKind::RelativeDataLoc {
                        CAPTURE_RELATIVE
                    } else {
                        0
                    };
                operations.push(CaptureOperation {
                    source_offset: u32::try_from(field.source_offset).map_err(|_| {
                        io::Error::new(io::ErrorKind::Unsupported, "tracepoint offset exceeds u32")
                    })?,
                    size: u16::try_from(field.capture_size).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            "dynamic capture bound exceeds u16",
                        )
                    })?,
                    destination_word: u16::try_from(field.destination_word).unwrap(),
                    flags: dynamic_flags | CAPTURE_DYNAMIC_METADATA,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                });
                let mut copied = 0usize;
                while copied < field.capture_size {
                    let size = (field.capture_size - copied).min(size_of::<u64>());
                    operations.push(CaptureOperation {
                        source_offset: u32::try_from(field.source_offset).unwrap(),
                        size: u16::try_from(size).unwrap(),
                        destination_word: u16::try_from(field.destination_word + 1 + copied / 8)
                            .unwrap(),
                        flags: dynamic_flags,
                        data_offset: u32::try_from(copied).unwrap(),
                        auxiliary_offset: 0,
                        pointer_size: 0,
                        auxiliary_size: 0,
                    });
                    copied += size;
                }
                continue;
            }
            let mut copied = 0usize;
            while copied < field.size {
                let size = (field.size - copied).min(size_of::<u64>());
                operations.push(CaptureOperation {
                    source_offset: u32::try_from(field.source_offset + copied).map_err(|_| {
                        io::Error::new(io::ErrorKind::Unsupported, "tracepoint offset exceeds u32")
                    })?,
                    size: u16::try_from(size).unwrap(),
                    destination_word: u16::try_from(field.destination_word + copied / 8).unwrap(),
                    flags: if field.kind == CaptureKind::Scalar && field.signed {
                        CAPTURE_SIGNED
                    } else {
                        0
                    },
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                });
                copied += size;
            }
        }
        if operations.len() > GENERIC_CAPTURE_OPERATIONS {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "capture requires {} operations; generic reader supports {GENERIC_CAPTURE_OPERATIONS}",
                    operations.len()
                ),
            ));
        }
        Ok(operations)
    }
}

pub fn capture_plan(
    category: &str,
    event: &str,
    format: &str,
    selected: Option<&[String]>,
) -> io::Result<CapturePlan> {
    capture_plan_bounded(
        category,
        event,
        format,
        selected,
        DEFAULT_DYNAMIC_CAPTURE_BYTES,
    )
}

pub fn capture_plan_bounded(
    category: &str,
    event: &str,
    format: &str,
    selected: Option<&[String]>,
    dynamic_capture_bytes: usize,
) -> io::Result<CapturePlan> {
    capture_plan_with_registry(
        category,
        event,
        format,
        selected,
        dynamic_capture_bytes,
        PolicyRegistry::empty(),
    )
}

pub fn capture_plan_with_registry(
    category: &str,
    event: &str,
    format: &str,
    selected: Option<&[String]>,
    dynamic_capture_bytes: usize,
    policies: PolicyRegistry,
) -> io::Result<CapturePlan> {
    validate_identifier(category, "category")?;
    validate_identifier(event, "event")?;
    if dynamic_capture_bytes == 0 {
        return Err(invalid("dynamic capture bound must be nonzero"));
    }
    let available = parse_format(format)?;
    let fields = selected_fields(format, selected)?;
    let mut destination_word = MOLD_METADATA_WORDS;
    let mut captures = Vec::with_capacity(fields.len());
    let mut context_size = 0;
    for mut field in fields {
        let (pointer_capture, length_source) =
            policies.capture_for(category, event, &field, &available)?;
        field.kind = match pointer_capture {
            PointerCapture::UserString { .. } => CaptureKind::UserString,
            PointerCapture::UserBytes { .. } => CaptureKind::UserBytes,
            PointerCapture::KernelString { .. } => CaptureKind::KernelString,
            PointerCapture::KernelBytes { .. } => CaptureKind::KernelBytes,
            PointerCapture::Address => field.kind,
        };
        let capture_size = if let PointerCapture::UserString { max_len }
        | PointerCapture::UserBytes { max_len, .. }
        | PointerCapture::KernelString { max_len }
        | PointerCapture::KernelBytes { max_len, .. } = pointer_capture
        {
            max_len
        } else if matches!(
            field.kind,
            CaptureKind::DataLoc | CaptureKind::RelativeDataLoc
        ) {
            dynamic_capture_bytes
        } else {
            0
        };
        let words = if capture_size == 0 {
            field_words(&field)
        } else {
            1 + capture_size.div_ceil(8)
        };
        context_size = context_size.max(
            field
                .offset
                .checked_add(field.size)
                .ok_or_else(|| invalid("tracepoint field extent overflows usize"))?,
        );
        captures.push(CaptureField {
            name: field.name,
            source_offset: field.offset,
            size: field.size,
            signed: field.signed,
            destination_word,
            words,
            kind: field.kind,
            capture_size,
            length_source,
        });
        destination_word = destination_word
            .checked_add(words)
            .ok_or_else(|| invalid("Mold word count overflows usize"))?;
    }
    validate_record_words(destination_word)?;
    Ok(CapturePlan {
        category: category.to_owned(),
        event: event.to_owned(),
        fields: captures,
        words: destination_word,
        context_size,
    })
}

pub fn parse_format(format: &str) -> io::Result<Vec<TracepointField>> {
    format
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("field:"))
        .map(parse_field)
        .collect()
}

pub fn generate(category: &str, event: &str, format: &str) -> io::Result<GeneratedTracepoint> {
    generate_selected(category, event, format, None)
}

pub fn generate_selected(
    category: &str,
    event: &str,
    format: &str,
    selected: Option<&[String]>,
) -> io::Result<GeneratedTracepoint> {
    validate_identifier(category, "category")?;
    validate_identifier(event, "event")?;
    let fields = fixed_fields(format, selected)?;
    let words = MOLD_METADATA_WORDS + fields.iter().map(field_words).sum::<usize>();
    validate_record_words(words)?;
    let slot_size = 16 + words * 8;
    let per_lane_budget = (64usize << 20) / 8;
    let capacity = previous_power_of_two(per_lane_budget / slot_size).max(1);
    let type_name = pascal_case(&format!("{category}_{event}"));
    let function_name = format!("record_{category}_{event}");

    let mut rust = String::new();
    writeln!(
        rust,
        "// Generated from {category}:{event}; do not edit by hand."
    )
    .unwrap();
    writeln!(rust, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
    writeln!(rust, "pub struct {type_name} {{").unwrap();
    writeln!(rust, "    pub mold_timestamp_ns: u64,").unwrap();
    writeln!(rust, "    pub mold_cpu: u32,").unwrap();
    for field in &fields {
        writeln!(
            rust,
            "    pub {}: {},",
            rust_name(&field.name),
            rust_type(field)
        )
        .unwrap();
    }
    writeln!(rust, "}}\n").unwrap();
    writeln!(rust, "samurai::mold_record!({type_name}, {words} {{").unwrap();
    writeln!(rust, "    mold_timestamp_ns: u64,").unwrap();
    writeln!(rust, "    mold_cpu: u32,").unwrap();
    for field in &fields {
        writeln!(
            rust,
            "    {}: {},",
            rust_name(&field.name),
            rust_type(field)
        )
        .unwrap();
    }
    writeln!(rust, "}});").unwrap();

    let mut bpf_c = String::new();
    writeln!(
        bpf_c,
        "/* Generated from {category}:{event}; do not edit by hand. */"
    )
    .unwrap();
    writeln!(bpf_c, "#define MOLD_WORDS {words}").unwrap();
    writeln!(bpf_c, "#define MOLD_CAPACITY {capacity}").unwrap();
    writeln!(bpf_c, "#include \"mold.h\"\n").unwrap();
    writeln!(bpf_c, "static u64 (*const ktime_get_ns)(void) = (void *)5;").unwrap();
    writeln!(
        bpf_c,
        "static u64 (*const get_smp_processor_id)(void) = (void *)8;\n"
    )
    .unwrap();
    writeln!(
        bpf_c,
        "__attribute__((section(\"tracepoint/{category}/{event}\"), used))"
    )
    .unwrap();
    writeln!(bpf_c, "int {function_name}(void *ctx) {{").unwrap();
    writeln!(bpf_c, "    u32 cpu = (u32)get_smp_processor_id();").unwrap();
    writeln!(bpf_c, "    u64 words[MOLD_WORDS] = {{}};").unwrap();
    writeln!(bpf_c, "    words[0] = ktime_get_ns();").unwrap();
    writeln!(bpf_c, "    words[1] = cpu;").unwrap();
    let mut word = 2;
    for field in &fields {
        writeln!(bpf_c, "    /* {} */", field.declaration).unwrap();
        if matches!(
            field.kind,
            CaptureKind::FixedArray | CaptureKind::FixedStruct
        ) {
            writeln!(
                bpf_c,
                "    __builtin_memcpy(&words[{word}], (const char *)ctx + {}, {});",
                field.offset, field.size
            )
            .unwrap();
        } else {
            writeln!(
                bpf_c,
                "    words[{word}] = (u64)({})*(const {} *)((const char *)ctx + {});",
                if field.signed {
                    "long long"
                } else {
                    "unsigned long long"
                },
                c_type(field),
                field.offset
            )
            .unwrap();
        }
        word += field_words(field);
    }
    writeln!(bpf_c, "    mold_publish(cpu, words);").unwrap();
    writeln!(bpf_c, "    return 0;").unwrap();
    writeln!(bpf_c, "}}\n").unwrap();
    writeln!(bpf_c, "__attribute__((section(\"license\"), used))").unwrap();
    writeln!(bpf_c, "char program_license[] = \"GPL\";").unwrap();

    Ok(GeneratedTracepoint {
        rust,
        bpf_c,
        words,
        capacity,
    })
}

fn fixed_fields(format: &str, selected: Option<&[String]>) -> io::Result<Vec<TracepointField>> {
    let fields = selected_fields(format, selected)?;
    for field in &fields {
        if matches!(
            field.kind,
            CaptureKind::DataLoc | CaptureKind::RelativeDataLoc
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "field {} requires the generic bounded dynamic-data reader ({})",
                    field.name, field.declaration
                ),
            ));
        }
    }
    Ok(fields)
}

fn selected_fields(format: &str, selected: Option<&[String]>) -> io::Result<Vec<TracepointField>> {
    let available: Vec<_> = parse_format(format)?
        .into_iter()
        .filter(|field| !field.name.starts_with("common_"))
        .collect();
    let fields = match selected {
        Some(selected) => select_fields(&available, selected)?,
        None => available,
    };
    if fields.is_empty() {
        return Err(invalid("tracepoint has no event-specific fields"));
    }
    Ok(fields)
}

fn validate_record_words(words: usize) -> io::Result<()> {
    let bytes = words
        .checked_mul(size_of::<u64>())
        .ok_or_else(|| invalid("Mold record size overflows usize"))?;
    if bytes > BPF_STACK_RECORD_BUDGET {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "generated {bytes}-byte record exceeds the {BPF_STACK_RECORD_BUDGET}-byte BPF stack budget"
            ),
        ));
    }
    Ok(())
}

fn select_fields(
    available: &[TracepointField],
    selected: &[String],
) -> io::Result<Vec<TracepointField>> {
    if selected.is_empty() {
        return Err(invalid("field selection cannot be empty"));
    }
    let mut seen = HashSet::new();
    selected
        .iter()
        .map(|name| {
            validate_identifier(name, "selected field")?;
            if !seen.insert(name.as_str()) {
                return Err(invalid(format!("field {name} was selected more than once")));
            }
            available
                .iter()
                .find(|field| field.name == *name)
                .cloned()
                .ok_or_else(|| invalid(format!("tracepoint has no field named {name}")))
        })
        .collect()
}

fn parse_field(line: &str) -> io::Result<TracepointField> {
    let mut parts = line.split(';');
    let declaration = parts
        .next()
        .and_then(|part| part.strip_prefix("field:"))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .ok_or_else(|| invalid("missing field declaration"))?;
    let offset = property(&mut parts, "offset")?;
    let size = property(&mut parts, "size")?;
    let signed = property(&mut parts, "signed")? != 0;
    if size == 0 {
        return Err(invalid("zero-sized tracepoint field"));
    }
    let token = declaration
        .split_whitespace()
        .last()
        .ok_or_else(|| invalid("field has no name"))?;
    let (name, array_len) = match token.split_once('[') {
        Some((name, length)) => {
            let length = length
                .strip_suffix(']')
                .ok_or_else(|| invalid("malformed array field"))?;
            if length.is_empty() {
                (name, None)
            } else {
                let length = length
                    .parse()
                    .map_err(|_| invalid("invalid array length"))?;
                (name, Some(length))
            }
        }
        None => (token.trim_start_matches('*'), None),
    };
    validate_identifier(name, "field name")?;
    Ok(TracepointField {
        declaration: declaration.to_owned(),
        name: name.to_owned(),
        offset,
        size,
        signed,
        array_len,
        kind: classify_field(declaration, array_len, size),
    })
}

fn classify_field(declaration: &str, array_len: Option<usize>, size: usize) -> CaptureKind {
    if declaration.contains("__rel_loc") {
        CaptureKind::RelativeDataLoc
    } else if declaration.contains("__data_loc") || declaration.contains("[]") {
        CaptureKind::DataLoc
    } else if declaration.contains('*') {
        CaptureKind::PointerAddress
    } else if array_len.is_some() {
        CaptureKind::FixedArray
    } else if matches!(size, 1 | 2 | 4 | 8) {
        CaptureKind::Scalar
    } else {
        CaptureKind::FixedStruct
    }
}

fn property<'a>(parts: &mut impl Iterator<Item = &'a str>, name: &str) -> io::Result<usize> {
    let part = parts
        .next()
        .ok_or_else(|| invalid(format!("missing {name}")))?;
    let (actual, value) = part
        .trim()
        .split_once(':')
        .ok_or_else(|| invalid(format!("malformed {name}")))?;
    if actual != name {
        return Err(invalid(format!("expected {name}, found {actual}")));
    }
    value
        .parse()
        .map_err(|_| invalid(format!("invalid {name}")))
}

fn field_words(field: &TracepointField) -> usize {
    if matches!(
        field.kind,
        CaptureKind::FixedArray | CaptureKind::FixedStruct
    ) {
        field.size.div_ceil(8)
    } else {
        1
    }
}

fn rust_type(field: &TracepointField) -> String {
    if matches!(
        field.kind,
        CaptureKind::FixedArray | CaptureKind::FixedStruct
    ) {
        format!("[u8; {}]", field.size)
    } else if field.kind == CaptureKind::PointerAddress {
        "u64".to_owned()
    } else {
        format!("{}{}", if field.signed { 'i' } else { 'u' }, field.size * 8)
    }
}

fn c_type(field: &TracepointField) -> &'static str {
    match (field.signed, field.size) {
        (true, 1) => "signed char",
        (false, 1) => "unsigned char",
        (true, 2) => "signed short",
        (false, 2) => "unsigned short",
        (true, 4) => "signed int",
        (false, 4) => "unsigned int",
        (true, 8) => "signed long long",
        (false, 8) => "unsigned long long",
        _ => unreachable!(),
    }
}

fn rust_name(name: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ];
    if KEYWORDS.contains(&name) {
        format!("field_{name}")
    } else {
        name.to_owned()
    }
}

fn pascal_case(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(char::to_uppercase)
                .into_iter()
                .flatten()
                .chain(chars)
                .collect::<String>()
        })
        .collect()
}

fn previous_power_of_two(value: usize) -> usize {
    if value == 0 {
        0
    } else {
        1usize << (usize::BITS - 1 - value.leading_zeros())
    }
}

fn validate_identifier(value: &str, description: &str) -> io::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || value.as_bytes()[0].is_ascii_digit()
    {
        return Err(invalid(format!("invalid {description}: {value:?}")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        time::SystemTime,
    };

    static SCHEMA_TEST_ID: AtomicU64 = AtomicU64::new(0);

    const SCHED_SWITCH: &str = r#"name: sched_switch
ID: 252
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:char prev_comm[16]; offset:8; size:16; signed:0;
 field:pid_t prev_pid; offset:24; size:4; signed:1;
 field:long prev_state; offset:32; size:8; signed:1;
 field:char next_comm[16]; offset:40; size:16; signed:0;
 field:pid_t next_pid; offset:56; size:4; signed:1;
"#;

    #[test]
    fn parses_and_generates_fixed_sched_fields() {
        let generated = generate("sched", "sched_switch", SCHED_SWITCH).unwrap();
        assert_eq!(generated.words, 9);
        assert!(generated.rust.contains("pub prev_comm: [u8; 16]"));
        assert!(!generated.rust.contains("pub previous_state"));
        assert!(generated.rust.contains("pub prev_state: i64"));
        assert!(generated.bpf_c.contains("tracepoint/sched/sched_switch"));
        assert!(generated.bpf_c.contains("(const char *)ctx + 56"));
        compile_generated_rust(&generated.rust);
    }

    #[test]
    fn selection_reduces_record_and_preserves_requested_order() {
        let selected = ["next_pid".to_owned(), "prev_pid".to_owned()];
        let generated =
            generate_selected("sched", "sched_switch", SCHED_SWITCH, Some(&selected)).unwrap();
        assert_eq!(generated.words, 4);
        assert!(!generated.rust.contains("prev_comm"));
        assert!(
            generated.rust.find("next_pid").unwrap() < generated.rust.find("prev_pid").unwrap()
        );
        assert!(generated.bpf_c.contains("(const char *)ctx + 56"));
        assert!(generated.bpf_c.contains("(const char *)ctx + 24"));
        compile_generated_rust(&generated.rust);
    }

    #[test]
    fn builds_runtime_capture_plan_from_selected_kernel_fields() {
        let selected = [
            "prev_pid".to_owned(),
            "prev_state".to_owned(),
            "next_pid".to_owned(),
        ];
        let plan = capture_plan("sched", "sched_switch", SCHED_SWITCH, Some(&selected)).unwrap();

        assert_eq!(plan.category, "sched");
        assert_eq!(plan.event, "sched_switch");
        assert_eq!(plan.words, 5);
        assert_eq!(plan.context_size, 60);
        assert_eq!(
            plan.fields,
            [
                CaptureField {
                    name: "prev_pid".to_owned(),
                    source_offset: 24,
                    size: 4,
                    signed: true,
                    destination_word: 2,
                    words: 1,
                    kind: CaptureKind::Scalar,
                    capture_size: 0,
                    length_source: None,
                },
                CaptureField {
                    name: "prev_state".to_owned(),
                    source_offset: 32,
                    size: 8,
                    signed: true,
                    destination_word: 3,
                    words: 1,
                    kind: CaptureKind::Scalar,
                    capture_size: 0,
                    length_source: None,
                },
                CaptureField {
                    name: "next_pid".to_owned(),
                    source_offset: 56,
                    size: 4,
                    signed: true,
                    destination_word: 4,
                    words: 1,
                    kind: CaptureKind::Scalar,
                    capture_size: 0,
                    length_source: None,
                },
            ]
        );
        assert_eq!(
            plan.operations().unwrap(),
            [
                CaptureOperation {
                    source_offset: 24,
                    size: 4,
                    destination_word: 2,
                    flags: CAPTURE_SIGNED,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                },
                CaptureOperation {
                    source_offset: 32,
                    size: 8,
                    destination_word: 3,
                    flags: CAPTURE_SIGNED,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                },
                CaptureOperation {
                    source_offset: 56,
                    size: 4,
                    destination_word: 4,
                    flags: CAPTURE_SIGNED,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                },
            ]
        );
    }

    #[test]
    fn selection_rejects_unknown_and_duplicate_fields() {
        for selected in [
            vec!["missing".to_owned()],
            vec!["prev_pid".to_owned(), "prev_pid".to_owned()],
        ] {
            assert_eq!(
                generate_selected("sched", "sched_switch", SCHED_SWITCH, Some(&selected))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn captures_raw_pointers_as_addresses_without_dereferencing() {
        let format = "field:const void * work; offset:16; size:8; signed:0;";
        let plan = capture_plan("workqueue", "execute", format, None).unwrap();

        assert_eq!(plan.fields[0].kind, CaptureKind::PointerAddress);
        assert_eq!(plan.fields[0].words, 1);
        assert_eq!(plan.operations().unwrap()[0].flags, 0);

        let generated = generate("workqueue", "execute", format).unwrap();
        assert!(generated.rust.contains("pub work: u64"));
        assert!(generated.bpf_c.contains("(const char *)ctx + 16"));
        assert!(!generated.bpf_c.contains("probe_read"));
        compile_generated_rust(&generated.rust);
    }

    #[test]
    fn captures_unknown_fixed_structs_as_bytes_across_words() {
        let format = "field:struct example value; offset:16; size:13; signed:0;";
        let plan = capture_plan("example", "fixed_struct", format, None).unwrap();

        assert_eq!(plan.fields[0].kind, CaptureKind::FixedStruct);
        assert_eq!(plan.fields[0].words, 2);
        assert_eq!(
            plan.operations().unwrap(),
            [
                CaptureOperation {
                    source_offset: 16,
                    size: 8,
                    destination_word: 2,
                    flags: 0,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                },
                CaptureOperation {
                    source_offset: 24,
                    size: 5,
                    destination_word: 3,
                    flags: 0,
                    data_offset: 0,
                    auxiliary_offset: 0,
                    pointer_size: 0,
                    auxiliary_size: 0,
                },
            ]
        );

        let generated = generate("example", "fixed_struct", format).unwrap();
        assert!(generated.rust.contains("pub value: [u8; 13]"));
        assert!(generated.bpf_c.contains("__builtin_memcpy(&words[2]"));
        compile_generated_rust(&generated.rust);
    }

    #[test]
    fn still_rejects_dynamic_locations_until_bounded_capture_exists() {
        for declaration in ["__data_loc char[] name", "__rel_loc char[] name"] {
            let format = format!("field:{declaration}; offset:16; size:4; signed:0;");
            assert_eq!(
                generate("x", "y", &format).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn plans_bounded_absolute_and_relative_dynamic_locations() {
        for (declaration, kind, relative_flag) in [
            ("__data_loc char[] name", CaptureKind::DataLoc, 0),
            (
                "__rel_loc unsigned char[] payload",
                CaptureKind::RelativeDataLoc,
                CAPTURE_RELATIVE,
            ),
        ] {
            let format = format!("field:{declaration}; offset:16; size:4; signed:0;");
            let plan = capture_plan_bounded("x", "y", &format, None, 13).unwrap();
            assert_eq!(plan.words, 5);
            assert_eq!(plan.fields[0].kind, kind);
            assert_eq!(plan.fields[0].capture_size, 13);
            assert_eq!(
                plan.operations().unwrap(),
                [
                    CaptureOperation {
                        source_offset: 16,
                        size: 13,
                        destination_word: 2,
                        flags: CAPTURE_DATA_LOC | CAPTURE_DYNAMIC_METADATA | relative_flag,
                        data_offset: 0,
                        auxiliary_offset: 0,
                        pointer_size: 0,
                        auxiliary_size: 0,
                    },
                    CaptureOperation {
                        source_offset: 16,
                        size: 8,
                        destination_word: 3,
                        flags: CAPTURE_DATA_LOC | relative_flag,
                        data_offset: 0,
                        auxiliary_offset: 0,
                        pointer_size: 0,
                        auxiliary_size: 0,
                    },
                    CaptureOperation {
                        source_offset: 16,
                        size: 5,
                        destination_word: 4,
                        flags: CAPTURE_DATA_LOC | relative_flag,
                        data_offset: 8,
                        auxiliary_offset: 0,
                        pointer_size: 0,
                        auxiliary_size: 0,
                    },
                ]
            );
        }
    }

    #[test]
    fn builtin_openat_policy_validates_and_lowers_user_string() {
        let format = r#"
field:unsigned short common_type; offset:0; size:2; signed:0;
field:int common_pid; offset:4; size:4; signed:1;
field:int dfd; offset:16; size:8; signed:1;
field:const char * filename; offset:24; size:8; signed:0;
field:int flags; offset:32; size:8; signed:0;
"#;
        let selected = ["filename".to_owned()];
        let plan = capture_plan_with_registry(
            "syscalls",
            "sys_enter_openat",
            format,
            Some(&selected),
            DEFAULT_DYNAMIC_CAPTURE_BYTES,
            PolicyRegistry::builtin(),
        )
        .unwrap();

        assert_eq!(plan.words, 19);
        assert_eq!(plan.fields[0].kind, CaptureKind::UserString);
        assert_eq!(plan.fields[0].capture_size, 128);
        assert_eq!(
            plan.operations().unwrap()[0],
            CaptureOperation {
                source_offset: 24,
                size: 128,
                destination_word: 2,
                flags: CAPTURE_USER_STRING,
                data_offset: 0,
                auxiliary_offset: 0,
                pointer_size: 8,
                auxiliary_size: 0,
            }
        );
    }

    #[test]
    fn policy_rejects_a_running_kernel_field_that_is_no_longer_a_pointer() {
        let format = "field:char filename[16]; offset:16; size:16; signed:0;";
        let error = capture_plan_with_registry(
            "syscalls",
            "sys_enter_openat",
            format,
            None,
            DEFAULT_DYNAMIC_CAPTURE_BYTES,
            PolicyRegistry::builtin(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("requires a pointer"));
    }

    #[test]
    fn lowers_user_bytes_kernel_string_and_kernel_bytes_policies() {
        static POLICIES: &[CapturePolicy] = &[
            CapturePolicy {
                category: "test",
                event: "memory",
                field: "user_buffer",
                capture: PointerCapture::UserBytes {
                    length_field: "length",
                    max_len: 13,
                },
            },
            CapturePolicy {
                category: "test",
                event: "memory",
                field: "kernel_name",
                capture: PointerCapture::KernelString { max_len: 128 },
            },
            CapturePolicy {
                category: "test",
                event: "memory",
                field: "kernel_buffer",
                capture: PointerCapture::KernelBytes {
                    length_field: "length",
                    max_len: 13,
                },
            },
        ];
        let format = r#"
field:const void * user_buffer; offset:16; size:8; signed:0;
field:const char * kernel_name; offset:24; size:8; signed:0;
field:const void * kernel_buffer; offset:32; size:8; signed:0;
field:unsigned int length; offset:40; size:4; signed:0;
"#;

        for (name, kind, memory_flag) in [
            ("user_buffer", CaptureKind::UserBytes, 0),
            (
                "kernel_name",
                CaptureKind::KernelString,
                CAPTURE_KERNEL_MEMORY,
            ),
            (
                "kernel_buffer",
                CaptureKind::KernelBytes,
                CAPTURE_KERNEL_MEMORY,
            ),
        ] {
            let plan = capture_plan_with_registry(
                "test",
                "memory",
                format,
                Some(&[name.to_owned()]),
                DEFAULT_DYNAMIC_CAPTURE_BYTES,
                PolicyRegistry::from_static(POLICIES),
            )
            .unwrap();
            assert_eq!(plan.fields[0].kind, kind);
            let operations = plan.operations().unwrap();
            if kind == CaptureKind::KernelString {
                assert_eq!(operations.len(), 1);
                assert_eq!(
                    operations[0].flags,
                    CAPTURE_USER_STRING | CAPTURE_KERNEL_MEMORY
                );
                assert_eq!(operations[0].pointer_size, 8);
            } else {
                assert_eq!(operations.len(), 3);
                assert_eq!(operations[0].auxiliary_offset, 40);
                assert_eq!(operations[0].auxiliary_size, 4);
                assert_eq!(
                    operations[0].flags,
                    CAPTURE_POINTER_BYTES | CAPTURE_DYNAMIC_METADATA | memory_flag
                );
                assert_eq!(operations[2].data_offset, 8);
                assert_eq!(operations[2].size, 5);
            }
        }
    }

    #[test]
    fn byte_policy_rejects_missing_or_non_scalar_length_fields() {
        static POLICY: &[CapturePolicy] = &[CapturePolicy {
            category: "test",
            event: "bad_length",
            field: "buffer",
            capture: PointerCapture::UserBytes {
                length_field: "length",
                max_len: 16,
            },
        }];
        for format in [
            "field:const void * buffer; offset:16; size:8; signed:0;",
            "field:const void * buffer; offset:16; size:8; signed:0;\nfield:char length[4]; offset:24; size:4; signed:0;",
        ] {
            assert!(
                capture_plan_with_registry(
                    "test",
                    "bad_length",
                    format,
                    None,
                    DEFAULT_DYNAMIC_CAPTURE_BYTES,
                    PolicyRegistry::from_static(POLICY),
                )
                .is_err()
            );
        }
    }

    fn compile_generated_rust(source: &str) {
        let dependencies = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_owned();
        let rlib = fs::read_dir(&dependencies)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("libsamurai-") && name.ends_with(".rlib")
            })
            .max_by_key(|entry| {
                entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH)
            })
            .expect("Cargo must build the Samurai rlib before its unit tests");
        let test_id = SCHEMA_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let directory = dependencies.join(format!("schema-test-{}-{test_id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("generated.rs");
        let output = directory.join("libgenerated.rlib");
        fs::write(&input, source).unwrap();
        let result = Command::new("rustc")
            .args([
                "--crate-name",
                "generated_schema",
                "--crate-type",
                "lib",
                "--edition=2024",
            ])
            .arg(&input)
            .arg("--extern")
            .arg(format!("samurai={}", rlib.path().display()))
            .arg("-L")
            .arg(format!("dependency={}", dependencies.display()))
            .arg("-o")
            .arg(output)
            .output()
            .expect("generated Rust schema requires rustc");
        assert!(
            result.status.success(),
            "generated Rust failed to compile:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
