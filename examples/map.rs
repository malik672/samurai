use samurai::bpf::syscall::create_array_map;

fn main() -> std::io::Result<()> {
    let map = create_array_map(
        std::mem::size_of::<u32>() as u32,
        std::mem::size_of::<u64>() as u32,
        1,
    )?;

    println!("map fd = {:?}", map);

    Ok(())
}
