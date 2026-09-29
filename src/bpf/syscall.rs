use std::{
    io,
    os::fd::{FromRawFd, OwnedFd},
};

use crate::bpf::BpfInsn;
use std::{
    ffi::CStr,
    os::fd::{AsRawFd, BorrowedFd},
};

pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_F_MMAPABLE: u32 = 1 << 10;
pub const BPF_OBJ_NAME_LEN: usize = 16;

#[repr(C)]
#[derive(Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,

    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; BPF_OBJ_NAME_LEN],
    map_ifindex: u32,

    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,

    map_extra: u64,
}

pub fn load_program(insns: &[BpfInsn]) -> io::Result<OwnedFd> {
    // Conversion is only for the small handwritten fixture path. Compiled
    // programs pass aya-obj's native instructions directly to the syscall.
    let instructions: Vec<_> = insns
        .iter()
        .map(|insn| {
            let mut native = aya_obj::generated::bpf_insn {
                code: insn.code,
                off: insn.offset,
                imm: insn.imm,
                _bitfield_align_1: [],
                _bitfield_1: aya_obj::generated::bpf_insn::new_bitfield_1(0, 0),
            };
            native.set_src_reg(insn.reg >> 4);
            native.set_dst_reg(insn.reg & 0xf);
            native
        })
        .collect();
    load_program_with_type(&instructions, BPF_PROG_TYPE_SOCKET_FILTER, c"GPL", 0)
}

pub(crate) fn load_program_with_type(
    insns: &[aya_obj::generated::bpf_insn],
    prog_type: u32,
    license: &CStr,
    kern_version: u32,
) -> io::Result<OwnedFd> {
    let insn_cnt = u32::try_from(insns.len())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let mut attr = BpfProgLoadAttr {
        prog_type,
        kern_version,

        insn_cnt,

        // Address in OUR userspace process.
        insns: insns.as_ptr() as u64,

        // Address of "GPL\0" in OUR process.
        license: license.as_ptr() as u64,

        ..Default::default()
    };

    // A success log can exceed a fixed userspace buffer and make an otherwise
    // valid BPF_PROG_LOAD fail with ENOSPC. Load quietly first, as libbpf does.
    let ret = prog_load(&attr);

    if ret < 0 {
        let original_error = io::Error::last_os_error();
        let mut log = vec![0u8; 1024 * 1024];
        attr.log_level = 1;
        attr.log_size = log.len() as u32;
        attr.log_buf = log.as_mut_ptr() as u64;
        let diagnostic_ret = prog_load(&attr);
        if diagnostic_ret >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(diagnostic_ret as i32) });
        }
        let diagnostic_error = io::Error::last_os_error();

        let end = log.iter().position(|&byte| byte == 0).unwrap_or(log.len());
        let verifier_log = String::from_utf8_lossy(&log[..end]);

        eprintln!("BPF_PROG_LOAD failed: {original_error}");

        if !verifier_log.is_empty() {
            eprintln!("--- verifier log ---");
            eprintln!("{verifier_log}");
        }
        if diagnostic_error.raw_os_error() == Some(libc::ENOSPC) {
            eprintln!("verifier diagnostic log exceeded {} bytes", log.len());
        }
        return Err(original_error);
    }

    // Successful BPF_PROG_LOAD returns a file descriptor.
    let fd = ret as i32;

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn prog_load(attr: &BpfProgLoadAttr) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            attr as *const BpfProgLoadAttr,
            std::mem::size_of::<BpfProgLoadAttr>(),
        )
    }
}

/// The caller must ensure this is a map with a four-byte key and eight-byte value.
pub(crate) unsafe fn lookup_u64(fd: BorrowedFd<'_>, key: u32) -> io::Result<u64> {
    #[repr(C)]
    struct LookupAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let mut value = 0u64;
    let attr = LookupAttr {
        map_fd: fd.as_raw_fd() as u32,
        padding: 0,
        key: (&key as *const u32) as u64,
        value: (&mut value as *mut u64) as u64,
        flags: 0,
    };
    // The caller guarantees buffer sizes; both pointers live through the syscall.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, 1u32, &attr, std::mem::size_of_val(&attr)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

pub(crate) fn update_map_value(fd: BorrowedFd<'_>, key: u32, value: &[u8]) -> io::Result<()> {
    #[repr(C)]
    struct UpdateAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = UpdateAttr {
        map_fd: fd.as_raw_fd() as u32,
        padding: 0,
        key: (&key as *const u32) as u64,
        value: value.as_ptr() as u64,
        flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr,
            std::mem::size_of_val(&attr),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn lookup_map_bytes(
    fd: BorrowedFd<'_>,
    key: &[u8],
    values: &mut [u8],
) -> io::Result<()> {
    #[repr(C)]
    struct LookupAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = LookupAttr {
        map_fd: fd.as_raw_fd() as u32,
        padding: 0,
        key: key.as_ptr() as u64,
        value: values.as_mut_ptr() as u64,
        flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_ELEM,
            &attr,
            std::mem::size_of_val(&attr),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn next_map_key(
    fd: BorrowedFd<'_>,
    key: Option<&[u8]>,
    next_key: &mut [u8],
) -> io::Result<bool> {
    #[repr(C)]
    struct NextKeyAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        next_key: u64,
    }
    let attr = NextKeyAttr {
        map_fd: fd.as_raw_fd() as u32,
        padding: 0,
        key: key.map_or(0, |key| key.as_ptr() as u64),
        next_key: next_key.as_mut_ptr() as u64,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_GET_NEXT_KEY,
            &attr,
            std::mem::size_of_val(&attr),
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Read every CPU-local u64 for one per-CPU array key.
pub(crate) fn lookup_per_cpu_u64(
    fd: BorrowedFd<'_>,
    key: u32,
    values: &mut [u64],
) -> io::Result<()> {
    #[repr(C)]
    struct LookupAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = LookupAttr {
        map_fd: fd.as_raw_fd() as u32,
        padding: 0,
        key: (&key as *const u32) as u64,
        value: values.as_mut_ptr() as u64,
        flags: 0,
    };
    let ret = unsafe { libc::syscall(libc::SYS_bpf, 1u32, &attr, std::mem::size_of_val(&attr)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_map(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> io::Result<OwnedFd> {
    let attr = BpfMapCreateAttr {
        map_type,
        key_size,
        value_size,
        max_entries,
        map_flags,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr,
            std::mem::size_of::<BpfMapCreateAttr>(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

pub fn create_array_map(key_size: u32, value_size: u32, max_entries: u32) -> io::Result<OwnedFd> {
    create_array_map_with_flags(key_size, value_size, max_entries, 0)
}

pub(crate) fn create_array_map_with_flags(
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> io::Result<OwnedFd> {
    create_map(
        BPF_MAP_TYPE_ARRAY,
        key_size,
        value_size,
        max_entries,
        map_flags,
    )
}

pub fn create_per_cpu_array_map(
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> io::Result<OwnedFd> {
    create_map(
        BPF_MAP_TYPE_PERCPU_ARRAY,
        key_size,
        value_size,
        max_entries,
        0,
    )
}

pub fn create_lru_per_cpu_hash_map(
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> io::Result<OwnedFd> {
    create_map(
        BPF_MAP_TYPE_LRU_PERCPU_HASH,
        key_size,
        value_size,
        max_entries,
        0,
    )
}

pub fn create_ring_buffer_map(max_entries: u32) -> io::Result<OwnedFd> {
    create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, max_entries, 0)
}
