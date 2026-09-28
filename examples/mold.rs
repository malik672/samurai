use samurai::mold::{MoldEntry, marked_mold};

fn main() -> std::io::Result<()> {
    let (mut producer, mut worker) = marked_mold::<1>(512)?;
    for value in 1..=10 {
        producer.produce([value]);
    }
    producer.finish();

    while !worker.is_done() {
        match worker.try_next() {
            Some(MoldEntry::Data([value])) => println!("value={value}"),
            Some(MoldEntry::Gap(missed)) => println!("missed={missed}"),
            Some(MoldEntry::Done) => println!("done"),
            None => std::hint::spin_loop(),
        }
    }
    Ok(())
}
