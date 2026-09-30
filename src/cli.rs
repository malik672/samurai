//! Command-line entry points for tracing and inspecting Linux tracepoints.

use crate::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, MappedMoldWorker, MoldEntry},
    policy::PolicyRegistry,
    tracepoint_schema::{
        CaptureField, CaptureKind, CapturePlan, DEFAULT_DYNAMIC_CAPTURE_BYTES,
        GENERIC_CAPTURE_WORDS, capture_plan_with_registry, parse_format,
    },
    utils::tracepoint::TracepointResolver,
};
use std::{
    fs, io,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const PREVIEW_RECORDS: usize = 20;

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
    count_limit: Option<u64>,
    duration: Option<Duration>,
    json: bool,
    object_path: Option<&Path>,
) -> io::Result<()> {
    let resolver = TracepointResolver::new();
    let plan = CapturePlan::discover(&resolver, category, event, fields)?;
    let operations = plan.operations()?;

    let loader = match object_path {
        Some(path) => ObjectLoader::from_file(path)?,
        None => ObjectLoader::parse(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/generic-tracepoint.bpf.o"
        )))?,
    };
    let loaded = loader.load()?;
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
    let cpus = resolve_cpus(cpu_spec, mold.lanes())?;
    let program = loaded
        .program("record_generic_tracepoint")
        .ok_or_else(|| missing("record_generic_tracepoint"))?;
    let mut attachments = Vec::with_capacity(cpus.len());
    for cpu in &cpus {
        attachments.push(program.attach_to_cpu(&resolver, category, event, *cpu)?);
    }

    install_stop_handlers()?;
    let deadline = duration
        .map(|duration| {
            Instant::now()
                .checked_add(duration)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "duration is too large"))
        })
        .transpose()?;
    let (mut received, mut dropped) = (0u64, 0u64);
    // Defer output until detach so tracing sys_enter_write cannot recursively
    // capture the CLI's own printing.
    let mut preview = Vec::with_capacity(PREVIEW_RECORDS);
    loop {
        let progressed = drain_workers(&mut workers, &mut received, &mut dropped, &mut preview)?;
        if count_limit.is_some_and(|limit| received >= limit)
            || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || STOP_REQUESTED.load(Ordering::Relaxed)
        {
            break;
        }
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
    drop(attachments);
    loop {
        let progressed = drain_workers(&mut workers, &mut received, &mut dropped, &mut preview)?;
        let mut caught_up = true;
        for worker in &workers {
            caught_up &= worker.is_caught_up()?;
        }
        if !progressed && caught_up {
            break;
        }
    }
    for words in &preview {
        if json {
            print_json_record(category, event, &plan, words);
        } else {
            print_record(&plan, words);
        }
    }
    if json {
        println!(
            "{{\"type\":\"summary\",\"event\":\"{category}:{event}\",\"received\":{received},\"dropped\":{dropped},\"cpus\":{cpus:?},\"words\":{},\"operations\":{}}}",
            plan.words,
            operations.len()
        );
    } else {
        println!(
            "event={category}:{event} received={received} dropped={dropped} cpus={cpus:?} words={} operations={}",
            plan.words,
            operations.len()
        );
    }
    Ok(())
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

fn resolve_cpus(spec: Option<&str>, lanes: usize) -> io::Result<Vec<usize>> {
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
        if *cpu >= lanes {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "BPF object has {lanes} Mold lanes and cannot record CPU {cpu}; rebuild with MOLD_LANES greater than {}",
                    cpu
                ),
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

fn drain_workers(
    workers: &mut [MappedMoldWorker<'_, '_, GENERIC_CAPTURE_WORDS>],
    received: &mut u64,
    dropped: &mut u64,
    preview: &mut Vec<[u64; GENERIC_CAPTURE_WORDS]>,
) -> io::Result<bool> {
    let mut progressed = false;
    for worker in workers {
        match worker.try_next()? {
            Some(MoldEntry::Data(words)) => {
                *received += 1;
                progressed = true;
                if preview.len() < PREVIEW_RECORDS {
                    preview.push(words);
                }
            }
            Some(MoldEntry::Gap(missed)) => {
                *dropped += missed;
                progressed = true;
            }
            Some(MoldEntry::Done) => progressed = true,
            None => {}
        }
    }
    Ok(progressed)
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

fn print_record(plan: &CapturePlan, words: &[u64; GENERIC_CAPTURE_WORDS]) {
    print!(
        "{} CPU {} pid={}",
        words[0],
        words[1] as u32,
        words[1] >> 32
    );
    for field in &plan.fields {
        let values = &words[field.destination_word..field.destination_word + field.words];
        if matches!(
            field.kind,
            CaptureKind::UserString | CaptureKind::KernelString
        ) {
            let length = values[0] as u32 as usize;
            let error = (values[0] >> 32) as u32 as i32;
            print!(" {}=\"", field.name);
            for index in 0..length {
                let byte = values[1 + index / 8].to_ne_bytes()[index % 8];
                for escaped in byte.escape_ascii() {
                    print!("{}", escaped as char);
                }
            }
            print!("\"");
            if error != 0 {
                print!("(error {error})");
            }
        } else if matches!(
            field.kind,
            CaptureKind::DataLoc
                | CaptureKind::RelativeDataLoc
                | CaptureKind::UserBytes
                | CaptureKind::KernelBytes
        ) {
            let captured_length = values[0] as u32 as usize;
            let original_length = (values[0] >> 32) as u32 as usize;
            print!(" {}=0x", field.name);
            for index in 0..captured_length {
                let byte = values[1 + index / 8].to_ne_bytes()[index % 8];
                print!("{byte:02x}");
            }
            if captured_length < original_length {
                print!("(truncated {captured_length}/{original_length})");
            }
        } else if matches!(
            field.kind,
            CaptureKind::PointerAddress | CaptureKind::FunctionPointer
        ) {
            print!(" {}=0x{:x}", field.name, values[0]);
        } else if field.words == 1 {
            if field.signed {
                print!(" {}={}", field.name, values[0] as i64);
            } else {
                print!(" {}={}", field.name, values[0]);
            }
        } else {
            print!(" {}={values:x?}", field.name);
        }
    }
    println!();
}

fn print_json_record(
    category: &str,
    event: &str,
    plan: &CapturePlan,
    words: &[u64; GENERIC_CAPTURE_WORDS],
) {
    print!(
        "{{\"event\":\"{}:{}\",\"timestamp_ns\":{},\"cpu\":{},\"pid\":{},\"fields\":{{",
        category,
        event,
        words[0],
        words[1] as u32,
        words[1] >> 32
    );
    for (index, field) in plan.fields.iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        print!("\"{}\":", field.name);
        let values = &words[field.destination_word..field.destination_word + field.words];
        if matches!(
            field.kind,
            CaptureKind::UserString | CaptureKind::KernelString
        ) {
            let length = (values[0] as u32 as usize).min((field.words - 1) * 8);
            let bytes = (0..length)
                .map(|offset| values[1 + offset / 8].to_ne_bytes()[offset % 8])
                .collect::<Vec<_>>();
            let value = String::from_utf8_lossy(&bytes);
            print!("\"{}\"", json_escape(&value));
        } else if matches!(
            field.kind,
            CaptureKind::DataLoc
                | CaptureKind::RelativeDataLoc
                | CaptureKind::UserBytes
                | CaptureKind::KernelBytes
        ) {
            let length = ((values[0] as u32 as usize).min((field.words - 1) * 8)) as usize;
            print!("\"0x");
            for offset in 0..length {
                print!("{:02x}", values[1 + offset / 8].to_ne_bytes()[offset % 8]);
            }
            print!("\"");
        } else if matches!(
            field.kind,
            CaptureKind::PointerAddress | CaptureKind::FunctionPointer
        ) {
            print!("\"0x{:x}\"", values[0]);
        } else if field.words == 1 {
            if field.signed {
                print!("{}", values[0] as i64);
            } else {
                print!("{}", values[0]);
            }
        } else {
            print!("\"0x");
            for word in values {
                print!("{word:016x}");
            }
            print!("\"");
        }
    }
    println!("}}}}");
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32).unwrap();
            }
            character => escaped.push(character),
        }
    }
    escaped
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
