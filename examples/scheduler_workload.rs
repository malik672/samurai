use samurai::utils::affinity::{parse_cpu_list, pin_current_thread};
use std::{
    hint::black_box,
    io,
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let yields = args
        .first()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(1_000_000);
    let cpus = parse_cpu_list(args.get(1).map_or("0,1,2,3", String::as_str))?;
    let worker_count = cpus.len();
    let start = Arc::new(Barrier::new(worker_count + 1));
    let workers: Vec<_> = cpus
        .into_iter()
        .map(|cpu| {
            let start = Arc::clone(&start);
            thread::spawn(move || -> io::Result<u64> {
                pin_current_thread(cpu)?;
                start.wait();
                let mut completed = 0u64;
                for _ in 0..yields {
                    let result = unsafe { libc::sched_yield() };
                    if result != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    completed += black_box(1);
                }
                Ok(completed)
            })
        })
        .collect();
    let wall = Instant::now();
    start.wait();
    let mut completed = 0u64;
    for worker in workers {
        completed += worker
            .join()
            .map_err(|_panic| io::Error::other("workload worker panicked"))??;
    }
    println!(
        "workers={} requested={} completed={} elapsed_seconds={:.9}",
        worker_count,
        yields * worker_count as u64,
        completed,
        wall.elapsed().as_secs_f64(),
    );
    Ok(())
}
