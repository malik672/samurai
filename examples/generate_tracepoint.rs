use samurai::{tracepoint_schema, utils::tracepoint::TracepointResolver};
use std::{fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut format_file = None;
    let mut fields = None;
    let mut position = 0;
    while position < args.len() && args[position].starts_with("--") {
        let flag = &args[position];
        let value = args.get(position + 1).ok_or_else(usage)?;
        match flag.as_str() {
            "--format-file" => format_file = Some(value.as_str()),
            "--fields" => {
                let selected: Vec<_> = value.split(',').map(str::to_owned).collect();
                fields = Some(selected);
            }
            _ => return Err(usage()),
        }
        position += 2;
    }
    let [category, event, output] = &args[position..] else {
        return Err(usage());
    };
    let output = PathBuf::from(output);
    let format = match format_file {
        Some(file) => fs::read_to_string(file)?,
        None => TracepointResolver::new().format(category, event)?,
    };
    let generated =
        tracepoint_schema::generate_selected(category, event, &format, fields.as_deref())?;
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

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: generate_tracepoint [--format-file <path>] [--fields <a,b,...>] <category> <event> <output-directory>",
    )
}
