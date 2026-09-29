use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub const PERF_TYPE_TRACEPOINT: u32 = 2;
pub const PERF_ATTR_SIZE_VER0: u32 = 64;
const PERF_ATTR_DISABLED: u64 = 1 << 0;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;

#[repr(C)]
#[derive(Debug, Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,

    config: u64,

    // union {
    //     sample_period
    //     sample_freq
    // }
    sample_period: u64,

    sample_type: u64,
    read_format: u64,

    // The giant __u64 bitfield from the kernel header.
    flags: u64,

    // union {
    //     wakeup_events
    //     wakeup_watermark
    // }
    wakeup_events: u32,
    bp_type: u32,

    // union {
    //     bp_addr
    //     kprobe_func
    //     uprobe_path
    //     config1
    // }
    config1: u64,
}

/// Open the perf event for all tasks executing on CPU 0.
pub fn open_tracepoint(tracepoint_id: u64) -> io::Result<OwnedFd> {
    open_tracepoint_for(tracepoint_id, -1, 0)
}

/// Open the perf event for one Linux thread on any CPU.
pub fn open_tracepoint_for_thread(tracepoint_id: u64, tid: u32) -> io::Result<OwnedFd> {
    open_tracepoint_for(tracepoint_id, tid as i32, -1)
}

fn open_tracepoint_for(tracepoint_id: u64, pid: i32, cpu: i32) -> io::Result<OwnedFd> {
    let attr = PerfEventAttr {
        type_: PERF_TYPE_TRACEPOINT,
        size: PERF_ATTR_SIZE_VER0,
        config: tracepoint_id,
        sample_period: 1,
        flags: PERF_ATTR_DISABLED,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            pid,
            cpu,
            -1i32,     // no event group
            1u64 << 3, // PERF_FLAG_FD_CLOEXEC
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

pub fn attach_bpf(perf_fd: &OwnedFd, bpf_fd: &OwnedFd) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(
            perf_fd.as_raw_fd(),
            PERF_EVENT_IOC_SET_BPF,
            bpf_fd.as_raw_fd(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn enable_event(perf_fd: &OwnedFd) -> io::Result<()> {
    let ret = unsafe { libc::ioctl(perf_fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
