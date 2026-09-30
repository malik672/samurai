use std::{io, path::Path, time::Duration};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [object, category, event, fields, seconds] = args.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generic_tracepoint <bpf-object> <category> <event> <field,...> <seconds>",
        ));
    };
    let seconds = seconds
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let selected = fields.split(',').map(str::to_owned).collect::<Vec<_>>();
    samurai::cli::run_trace(
        category,
        event,
        Some(&selected),
        None,
        None,
        Some(Duration::from_secs(seconds)),
        false,
        Some(Path::new(object)),
    )
}
