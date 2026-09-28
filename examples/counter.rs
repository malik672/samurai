use samurai::{bpf::object::ObjectLoader, utils::tracepoint::TracepointResolver};
use std::{io, thread, time::Duration};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: counter <object.o> [seconds=10]; counter <object.o> --check",
        ));
    }
    let loader = ObjectLoader::from_file(&args[0])?;
    if args.len() == 2 && args[1] == "--check" {
        println!("programs: {:?}", loader.program_names().collect::<Vec<_>>());
        println!("maps: {:?}", loader.map_names().collect::<Vec<_>>());
        return Ok(());
    }
    let seconds: u64 = args
        .get(1)
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .unwrap_or(10);
    if seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seconds must be positive",
        ));
    }
    let loaded = loader.load()?;
    let program = loaded.program("count_switches").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "count_switches program not found")
    })?;
    let _attachment = program.attach(&TracepointResolver::new(), "sched", "sched_switch")?;
    let map = loaded
        .per_cpu_map("switches")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "switches map not found"))?;
    let mut cpu_values = vec![0; map.cpu_count()];
    map.read_u64(0, &mut cpu_values)?;
    let mut previous: u64 = cpu_values.iter().sum();
    for _ in 0..seconds {
        thread::sleep(Duration::from_secs(1));
        map.read_u64(0, &mut cpu_values)?;
        let count: u64 = cpu_values.iter().sum();
        println!(
            "{} context switches since last read (total {count})",
            count.wrapping_sub(previous)
        );
        previous = count;
    }
    Ok(())
}
