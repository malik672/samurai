use samurai::{
    policy::PolicyRegistry,
    tracepoint_schema::{
        CaptureField, CaptureKind, DEFAULT_DYNAMIC_CAPTURE_BYTES, capture_plan_with_registry,
        parse_format,
    },
    utils::tracepoint::TracepointResolver,
};
use std::{fs, io, path::Path};

fn main() -> io::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--find-relative"] {
        return find_relative();
    }
    let (category, event, selected) = match args.as_slice() {
        [category, event] => (category.as_str(), event.as_str(), None),
        [category, event, fields] => (
            category.as_str(),
            event.as_str(),
            Some(fields.split(',').map(str::to_owned).collect::<Vec<_>>()),
        ),
        _ => return Err(usage()),
    };
    let resolver = TracepointResolver::new();
    let format = resolver.format(category, event)?;
    let available = parse_format(&format)?;
    let names = selected.unwrap_or_else(|| {
        available
            .iter()
            .filter(|field| !field.name.starts_with("common_"))
            .map(|field| field.name.clone())
            .collect()
    });

    println!("event={category}:{event}");
    for name in names {
        let chosen = [name.clone()];
        match capture_plan_with_registry(
            category,
            event,
            &format,
            Some(&chosen),
            DEFAULT_DYNAMIC_CAPTURE_BYTES,
            PolicyRegistry::builtin(),
        ) {
            Ok(plan) => print_field(&plan.fields[0], plan.operations()?.len()),
            Err(error) => println!("{name}: unsupported ({error})"),
        }
    }
    Ok(())
}

fn find_relative() -> io::Result<()> {
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
        "{}: {} offset={} size={} words={} operations={operations}",
        field.name,
        kind_name(field.kind),
        field.source_offset,
        field.size,
        field.words,
    );
    if field.capture_size != 0 {
        print!(" max_bytes={}", field.capture_size);
    }
    if let Some((offset, size)) = field.length_source {
        print!(" length_offset={offset} length_size={size}");
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

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: inspect_tracepoint <category> <event> [field,...] | inspect_tracepoint --find-relative",
    )
}
