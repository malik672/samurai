use std::{io, mem};

pub fn parse_cpu_list(value: &str) -> io::Result<Vec<usize>> {
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU list must not be empty",
        ));
    }

    value
        .split(',')
        .map(|cpu| {
            cpu.parse()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })
        .collect()
}

pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU exceeds cpu_set_t capacity",
        ));
    }

    let mut set = unsafe { mem::zeroed::<libc::cpu_set_t>() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    let result = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_cpu_list;

    #[test]
    fn parses_cpu_list() {
        assert_eq!(parse_cpu_list("0,5,6,7").unwrap(), [0, 5, 6, 7]);
    }

    #[test]
    fn rejects_empty_cpu_list() {
        assert!(parse_cpu_list("").is_err());
    }
}
