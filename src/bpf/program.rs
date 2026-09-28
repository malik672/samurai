//! Typed tracepoint lifecycle adapted from Aya's programs/trace_point.rs.
//! Source revision: 15593549d93cd39decf008f6d859fd054ba40bcf.
//! MIT notice: LICENSES/aya-MIT.txt. Attachment uses Samurai's perf syscalls
//! and returns an owned perf FD rather than Aya's managed link ID.
use super::syscall::{BPF_PROG_TYPE_TRACEPOINT, load_program_with_type};
use crate::{perf::event, utils::tracepoint::TracepointResolver};
use aya_obj::{Function, Program};
use std::{io, os::fd::OwnedFd};

/// A successfully loaded kernel program; no parsed instructions are retained.
pub struct TracePoint {
    fd: OwnedFd,
}
impl TracePoint {
    pub(crate) fn load(obj: &Program, function: &Function) -> io::Result<Self> {
        let fd = load_program_with_type(
            &function.instructions,
            BPF_PROG_TYPE_TRACEPOINT,
            &obj.license,
            obj.kernel_version.unwrap_or(0),
        )?;
        Ok(Self { fd })
    }
    /// Keep the returned FD alive to retain this CPU's attachment.
    pub fn attach(
        &self,
        resolver: &TracepointResolver,
        category: &str,
        name: &str,
    ) -> io::Result<OwnedFd> {
        let tracepoint = resolver.open(category, name)?;
        let perf_fd = event::open_tracepoint(tracepoint.id)?;
        event::attach_bpf(&perf_fd, &self.fd)?;
        event::enable_event(&perf_fd)?;
        Ok(perf_fd)
    }
}
