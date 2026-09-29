use samurai::{
    bpf::object::ObjectLoader,
    mold::{MappedMold, MoldEntry},
    tracepoint_schema::{CaptureKind, CapturePlan, GENERIC_CAPTURE_WORDS},
    utils::tracepoint::TracepointResolver,
};
use std::{
    io, thread,
    time::{Duration, Instant},
};

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
    let selected: Vec<_> = fields.split(',').map(str::to_owned).collect();
    let resolver = TracepointResolver::new();
    let plan = CapturePlan::discover(&resolver, category, event, Some(&selected))?;
    let operations = plan.operations()?;

    let loaded = ObjectLoader::from_file(object)?.load()?;
    loaded
        .map("capture_config")
        .ok_or_else(|| missing("capture_config"))?
        .write(0, &(operations.len() as u64).to_ne_bytes())?;
    let operation_map = loaded
        .map("capture_operations")
        .ok_or_else(|| missing("capture_operations"))?;
    for (index, operation) in operations.iter().enumerate() {
        operation_map.write(index as u32, &operation.to_bytes())?;
    }

    let slots = loaded
        .map("slots")
        .ok_or_else(|| missing("slots"))?
        .mmap()?;
    let frontiers = loaded
        .map("frontiers")
        .ok_or_else(|| missing("frontiers"))?
        .mmap()?;
    let mold = MappedMold::<GENERIC_CAPTURE_WORDS>::new(&slots, &frontiers)?;
    let mut workers = (0..mold.lanes())
        .map(|lane| mold.worker(lane))
        .collect::<io::Result<Vec<_>>>()?;
    let program = loaded
        .program("record_generic_tracepoint")
        .ok_or_else(|| missing("record_generic_tracepoint"))?;
    let attachment = program.attach(&resolver, category, event)?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let (mut received, mut dropped, mut printed) = (0u64, 0u64, 0usize);
    while Instant::now() < deadline {
        let mut progressed = false;
        for worker in &mut workers {
            match worker.try_next()? {
                Some(MoldEntry::Data(words)) => {
                    received += 1;
                    progressed = true;
                    if printed < 20 {
                        print_record(&plan, &words);
                        printed += 1;
                    }
                }
                Some(MoldEntry::Gap(missed)) => {
                    dropped += missed;
                    progressed = true;
                }
                Some(MoldEntry::Done) => progressed = true,
                None => {}
            }
        }
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
    drop(attachment);
    println!(
        "event={category}:{event} received={received} dropped={dropped} words={} operations={}",
        plan.words,
        operations.len()
    );
    Ok(())
}

fn print_record(plan: &CapturePlan, words: &[u64; GENERIC_CAPTURE_WORDS]) {
    print!("{} CPU {}", words[0], words[1]);
    for field in &plan.fields {
        let values = &words[field.destination_word..field.destination_word + field.words];
        if matches!(
            field.kind,
            CaptureKind::DataLoc | CaptureKind::RelativeDataLoc
        ) {
            let captured_length = values[0] as u32 as usize;
            let original_length = (values[0] >> 32) as u32 as usize;
            print!(" {}=0x", field.name);
            for index in 0..captured_length {
                let byte = values[1 + index / 8].to_ne_bytes()[index % 8];
                print!("{byte:02x}");
            }
            if captured_length < original_length {
                print!("(truncated {captured_length}/{original_length})");
            }
        } else if field.words == 1 {
            if field.signed {
                print!(" {}={}", field.name, values[0] as i64);
            } else {
                print!(" {}={}", field.name, values[0]);
            }
        } else {
            print!(" {}={values:x?}", field.name);
        }
    }
    println!();
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}
