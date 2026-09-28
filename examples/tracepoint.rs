use samurai::{perf::event::open_tracepoint, utils::tracepoint::TracepointResolver};

fn main() -> std::io::Result<()> {
    let resolver = TracepointResolver::new();

    let sched_switch = resolver.open("sched", "sched_switch")?;

    println!("sched_switch id = {}", sched_switch.id);

    let perf_fd = open_tracepoint(sched_switch.id)?;

    println!("opened disabled tracepoint perf event: fd = {:?}", perf_fd);

    Ok(())
}
