//! Privileged pointer-helper compatibility cases adapted from Aya.
//! Source: Aya bpf_probe_read integration tests at
//! 8bcb4e390fde09ffd8d7e8c060e473c03d9b6601 (MIT; LICENSES/aya-MIT.txt).
use samurai::{
    bpf::object::ObjectLoader,
    tracepoint_schema::CapturePlan,
    utils::{affinity::pin_current_thread, tracepoint::TracepointResolver},
};
use std::io;

const BUFFER_LEN: usize = 128;
const RESULT_LEN: usize = 24 + BUFFER_LEN * 3;

fn main() -> io::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: pointer_helpers_test <pointer-helpers-test.bpf.o> [cpu=0]",
        ));
    }
    let cpu = args
        .get(1)
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(0);
    pin_current_thread(cpu)?;

    let resolver = TracepointResolver::new();
    let fields = ["filename".to_owned()];
    let plan = CapturePlan::discover(&resolver, "syscalls", "sys_enter_openat", Some(&fields))?;
    let pathname_offset = plan
        .fields
        .iter()
        .find(|field| field.name == "filename")
        .ok_or_else(|| missing("filename field"))?
        .source_offset;

    let loaded = ObjectLoader::from_file(&args[0])?.load()?;
    let mut config = [0_u8; 8];
    let pathname_offset = u32::try_from(pathname_offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "openat filename offset does not fit the BPF test ABI",
        )
    })?;
    config[..4].copy_from_slice(&std::process::id().to_ne_bytes());
    config[4..].copy_from_slice(&pathname_offset.to_ne_bytes());
    loaded
        .map("test_config")
        .ok_or_else(|| missing("test_config"))?
        .write(0, &config)?;
    let kernel = loaded
        .map("kernel_buffer")
        .ok_or_else(|| missing("kernel_buffer"))?;
    let result = loaded
        .map("test_result")
        .ok_or_else(|| missing("test_result"))?;
    let program = loaded
        .program("test_pointer_helpers")
        .ok_or_else(|| missing("test_pointer_helpers"))?;
    let _attachment = program.attach(&resolver, "syscalls", "sys_enter_openat")?;

    let user = buffer(b"user\0bytes-after-nul");
    let normal_kernel = buffer(b"kernel\0bytes-after-nul");
    kernel.write(0, &normal_kernel)?;
    trigger_openat(user.as_ptr().cast());
    let normal = read_result(result)?;
    assert_eq!(normal.user_error, 0);
    assert_eq!(normal.user_bytes, user);
    assert_eq!(normal.kernel_string_result, 7);
    assert_eq!(&normal.kernel_string[..7], b"kernel\0");
    assert_eq!(normal.kernel_bytes_error, 0);
    assert_eq!(normal.kernel_bytes, normal_kernel);

    let truncated_kernel = [b'a'; BUFFER_LEN];
    kernel.write(0, &truncated_kernel)?;
    trigger_openat(user.as_ptr().cast());
    let truncated = read_result(result)?;
    assert_eq!(truncated.kernel_string_result, BUFFER_LEN as i64);
    assert_eq!(
        &truncated.kernel_string[..BUFFER_LEN - 1],
        &[b'a'; BUFFER_LEN - 1]
    );
    assert_eq!(truncated.kernel_string[BUFFER_LEN - 1], 0);

    let empty_kernel = buffer(b"\0");
    kernel.write(0, &empty_kernel)?;
    trigger_openat(user.as_ptr().cast());
    let empty = read_result(result)?;
    assert_eq!(empty.kernel_string_result, 1);
    assert_eq!(empty.kernel_string[0], 0);

    println!(
        "pointer helper cases passed on CPU {cpu}: user bytes, kernel bytes, kernel string normal/truncated/empty"
    );
    Ok(())
}

struct ResultValue {
    user_error: i64,
    kernel_string_result: i64,
    kernel_bytes_error: i64,
    user_bytes: [u8; BUFFER_LEN],
    kernel_string: [u8; BUFFER_LEN],
    kernel_bytes: [u8; BUFFER_LEN],
}

fn read_result(map: &samurai::bpf::map::ArrayMap) -> io::Result<ResultValue> {
    let mut bytes = [0_u8; RESULT_LEN];
    map.read(0, &mut bytes)?;
    Ok(ResultValue {
        user_error: i64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
        kernel_string_result: i64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        kernel_bytes_error: i64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        user_bytes: bytes[24..152].try_into().unwrap(),
        kernel_string: bytes[152..280].try_into().unwrap(),
        kernel_bytes: bytes[280..408].try_into().unwrap(),
    })
}

fn buffer(prefix: &[u8]) -> [u8; BUFFER_LEN] {
    let mut value = [0_u8; BUFFER_LEN];
    value[..prefix.len()].copy_from_slice(prefix);
    value
}

fn trigger_openat(path: *const libc::c_char) {
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, libc::O_RDONLY, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
    }
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
}
