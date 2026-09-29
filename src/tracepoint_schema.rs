//! Generate fixed Mold schemas from Linux tracepoint format descriptions.
use std::{collections::HashSet, fmt::Write as _, io};

const MOLD_METADATA_WORDS: usize = 2;
const BPF_STACK_RECORD_BUDGET: usize = 384;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracepointField {
    pub declaration: String,
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub signed: bool,
    pub array_len: Option<usize>,
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
}

impl CapturePlan {
    /// Discover and validate a fixed-field plan from the running kernel.
    pub fn discover(
        resolver: &crate::utils::tracepoint::TracepointResolver,
        category: &str,
        event: &str,
        selected: Option<&[String]>,
    ) -> io::Result<Self> {
        let format = resolver.format(category, event)?;
        capture_plan(category, event, &format, selected)
    }
}

pub fn capture_plan(
    category: &str,
    event: &str,
    format: &str,
    selected: Option<&[String]>,
) -> io::Result<CapturePlan> {
    validate_identifier(category, "category")?;
    validate_identifier(event, "event")?;
    let fields = fixed_fields(format, selected)?;
    let mut destination_word = MOLD_METADATA_WORDS;
    let mut captures = Vec::with_capacity(fields.len());
    let mut context_size = 0;
    for field in fields {
        let words = field_words(&field);
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
        if field.array_len.is_some() {
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
    for field in &fields {
        if field.declaration.contains('*')
            || field.declaration.contains("__data_loc")
            || field.declaration.contains("__rel_loc")
            || field.declaration.contains("[]")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "field {} requires an explicit pointer or dynamic-data policy ({})",
                    field.name, field.declaration
                ),
            ));
        }
        if field.array_len.is_none() && !matches!(field.size, 1 | 2 | 4 | 8) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "field {} has unsupported scalar size {}",
                    field.name, field.size
                ),
            ));
        }
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
    })
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
    if field.array_len.is_some() {
        field.size.div_ceil(8)
    } else {
        1
    }
}

fn rust_type(field: &TracepointField) -> String {
    if field.array_len.is_some() {
        format!("[u8; {}]", field.size)
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
                },
                CaptureField {
                    name: "prev_state".to_owned(),
                    source_offset: 32,
                    size: 8,
                    signed: true,
                    destination_word: 3,
                    words: 1,
                },
                CaptureField {
                    name: "next_pid".to_owned(),
                    source_offset: 56,
                    size: 4,
                    signed: true,
                    destination_word: 4,
                    words: 1,
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
    fn rejects_pointer_and_dynamic_fields() {
        for declaration in ["const char * filename", "__data_loc char[] name"] {
            let format = format!("field:{declaration}; offset:16; size:8; signed:0;");
            assert_eq!(
                generate("x", "y", &format).unwrap_err().kind(),
                io::ErrorKind::Unsupported
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
