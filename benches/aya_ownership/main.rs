use aya::{Ebpf, programs::TracePoint};
use std::error::Error;
#[cfg(not(feature = "alloc-stats"))]
use std::{hint::black_box, time::Instant};

// Separate feature/build: timing binaries use the uninstrumented system allocator.
#[cfg(feature = "alloc-stats")]
mod memory {
    use std::{alloc::{GlobalAlloc, Layout, System}, sync::atomic::{AtomicUsize, Ordering::Relaxed}};
    pub static CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static BYTES: AtomicUsize = AtomicUsize::new(0);
    pub static LIVE: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);
    pub struct Counting;
    fn allocated(size: usize) {
        CALLS.fetch_add(1, Relaxed);
        BYTES.fetch_add(size, Relaxed);
        let live = LIVE.fetch_add(size, Relaxed) + size;
        PEAK.fetch_max(live, Relaxed);
    }
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(l) };
            if !p.is_null() { allocated(l.size()); }
            p
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc_zeroed(l) };
            if !p.is_null() { allocated(l.size()); }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            unsafe { System.dealloc(p, l) };
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
            let next = unsafe { System.realloc(p, l, size) };
            if !next.is_null() { LIVE.fetch_sub(l.size(), Relaxed); allocated(size); }
            next
        }
    }
}
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOCATOR: memory::Counting = memory::Counting;

fn load(bytes: &[u8], kernel: bool) -> Result<Ebpf, Box<dyn Error>> {
    let mut bpf = Ebpf::load(bytes)?;
    if kernel {
        for (_, program) in bpf.programs_mut() {
            let program: &mut TracePoint = program.try_into()?;
            program.load()?;
        }
    }
    Ok(bpf)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 { return Err("expected <object.o> <prepare|kernel> <iterations>".into()); }
    let bytes = std::fs::read(&args[1])?;
    let kernel = match args[2].as_str() { "prepare" => false, "kernel" => true, _ => return Err("invalid phase".into()) };
    let iterations: usize = args[3].parse()?;
    if iterations == 0 { return Err("iterations must be positive".into()); }
    // Warm lazy feature probes and per-thread caches before either measurement.
    for _ in 0..5 { drop(load(&bytes, kernel)?); }

    #[cfg(not(feature = "alloc-stats"))]
    {
        let mut load_ns = 0u128;
        let mut total_ns = 0u128;
        let mut programs = 0;
        for _ in 0..iterations {
            let start = Instant::now();
            let bpf = black_box(load(black_box(&bytes), kernel)?);
            load_ns += start.elapsed().as_nanos();
            programs = black_box(bpf.programs().count());
            drop(bpf);
            total_ns += start.elapsed().as_nanos();
        }
        println!("TIME load_ns={:.3} cycle_ns={:.3} programs={programs}",
            load_ns as f64 / iterations as f64, total_ns as f64 / iterations as f64);
    }
    #[cfg(feature = "alloc-stats")]
    {
        use memory::*;
        use std::sync::atomic::Ordering::Relaxed;
        let baseline = LIVE.load(Relaxed);
        let calls = CALLS.load(Relaxed);
        let bytes_before = BYTES.load(Relaxed);
        PEAK.store(baseline, Relaxed);
        let bpf = load(&bytes, kernel)?;
        let allocations = CALLS.load(Relaxed) - calls;
        let allocated_bytes = BYTES.load(Relaxed) - bytes_before;
        let retained_bytes = LIVE.load(Relaxed) - baseline;
        let peak_bytes = PEAK.load(Relaxed) - baseline;
        drop(bpf);
        let after_drop = LIVE.load(Relaxed) as i128 - baseline as i128;
        println!("MEM allocations={allocations} allocated_bytes={allocated_bytes} retained_bytes={retained_bytes} peak_bytes={peak_bytes} after_drop={after_drop}");
    }
    Ok(())
}
