use samurai::{tracepoint_schema, utils::tracepoint::TracepointResolver};
use std::{fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (category, event, output, format) = match args.as_slice() {
        [category, event, output] => (
            category,
            event,
            PathBuf::from(output),
            TracepointResolver::new().format(category, event)?,
        ),
        [flag, file, category, event, output] if flag == "--format-file" => (
            category,
            event,
            PathBuf::from(output),
            fs::read_to_string(file)?,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: generate_tracepoint [--format-file <path>] <category> <event> <output-directory>",
            ));
        }
    };
    let generated = tracepoint_schema::generate(category, event, &format)?;
    fs::create_dir_all(&output)?;
    let stem = format!("{category}_{event}");
    let rust = output.join(format!("{stem}.rs"));
    let bpf = output.join(format!("{stem}.bpf.c"));
    fs::write(&rust, generated.rust)?;
    fs::write(&bpf, generated.bpf_c)?;
    println!(
        "generated={} words={} capacity={} rust={} bpf={}",
        stem,
        generated.words,
        generated.capacity,
        rust.display(),
        bpf.display(),
    );
    Ok(())
}
