//! Typed, allocation-free decoding of records produced by Samurai BPF programs.
use crate::bpf::map::RingBufferMap;
use std::{
    io,
    os::fd::AsRawFd,
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
    time::Duration,
};

const CONTEXT_SWITCH_RECORD_SIZE: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextSwitchRecord {
    pub timestamp_ns: u64,
    pub runtime_ns: u64,
    pub previous_pid: u32,
    pub next_pid: u32,
    pub cpu: u32,
    pub previous_state: i64,
}

crate::mold_record!(ContextSwitchRecord, 6 {
    timestamp_ns: u64,
    runtime_ns: u64,
    previous_pid: u32,
    next_pid: u32,
    cpu: u32,
    previous_state: i64,
});

pub struct RingBufferRecorder<'map> {
    map: &'map RingBufferMap,
    consumer_mapping: NonNull<libc::c_void>,
    producer_mapping: NonNull<libc::c_void>,
    consumer_position: NonNull<AtomicU64>,
    producer_position: NonNull<AtomicU64>,
    data: NonNull<u8>,
    consumer: u64,
    capacity: usize,
    mask: usize,
    page_size: usize,
    producer_mapping_len: usize,
}

impl<'map> RingBufferRecorder<'map> {
    pub fn new(map: &'map RingBufferMap) -> io::Result<Self> {
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(io::Error::last_os_error)?;
        let capacity = map.capacity();
        if !capacity.is_power_of_two()
            || capacity < page_size
            || !capacity.is_multiple_of(page_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ring-buffer capacity must be a page-aligned power of two",
            ));
        }
        let producer_mapping_len = page_size
            .checked_add(
                capacity
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("ring-buffer mapping size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("ring-buffer mapping size overflow"))?;

        let consumer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map.fd().as_raw_fd(),
                0,
            )
        };
        let consumer_mapping = NonNull::new(consumer_mapping)
            .filter(|mapping| mapping.as_ptr() != libc::MAP_FAILED)
            .ok_or_else(io::Error::last_os_error)?;

        let producer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                producer_mapping_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                map.fd().as_raw_fd(),
                page_size as libc::off_t,
            )
        };
        let Some(producer_mapping) =
            NonNull::new(producer_mapping).filter(|mapping| mapping.as_ptr() != libc::MAP_FAILED)
        else {
            let error = io::Error::last_os_error();
            unsafe { libc::munmap(consumer_mapping.as_ptr(), page_size) };
            return Err(error);
        };

        let consumer_position = consumer_mapping.cast::<AtomicU64>();
        let producer_position = producer_mapping.cast::<AtomicU64>();
        let data = unsafe { producer_mapping.byte_add(page_size) }.cast::<u8>();
        let consumer = unsafe { consumer_position.as_ref() }.load(Ordering::Relaxed);

        Ok(Self {
            map,
            consumer_mapping,
            producer_mapping,
            consumer_position,
            producer_position,
            data,
            consumer,
            capacity,
            mask: capacity - 1,
            page_size,
            producer_mapping_len,
        })
    }

    pub fn poll(&self, timeout: Duration) -> io::Result<bool> {
        let timeout_ms = timeout.as_millis().max(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: self.map.fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if result > 0 {
                return Ok(true);
            }
            if result == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub fn consume_available(
        &mut self,
        mut consume: impl FnMut(ContextSwitchRecord) -> io::Result<()>,
    ) -> io::Result<u64> {
        const HEADER_SIZE: usize = 8;
        const BUSY_BIT: u32 = 1 << 31;
        const DISCARD_BIT: u32 = 1 << 30;
        const LENGTH_MASK: u32 = !(BUSY_BIT | DISCARD_BIT);

        let mut consumed = 0u64;
        let mut producer = unsafe { self.producer_position.as_ref() }.load(Ordering::Acquire);
        let mut needs_wakeup_fence = false;

        loop {
            while self.consumer != producer {
                let offset = (self.consumer as usize) & self.mask;
                let header = unsafe { self.data.byte_add(offset) }.cast::<AtomicU32>();
                let length_flags = unsafe { header.as_ref() }.load(Ordering::Acquire);
                if length_flags & BUSY_BIT != 0 {
                    if needs_wakeup_fence {
                        std::sync::atomic::fence(Ordering::SeqCst);
                        needs_wakeup_fence = false;
                        continue;
                    }
                    return Ok(consumed);
                }
                let length = (length_flags & LENGTH_MASK) as usize;
                let record_size = (length + HEADER_SIZE + 7) & !7;
                if length != CONTEXT_SWITCH_RECORD_SIZE || record_size > self.capacity {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ring buffer contains an invalid context-switch record",
                    ));
                }
                if length_flags & DISCARD_BIT == 0 {
                    let payload = unsafe {
                        std::slice::from_raw_parts(
                            self.data.byte_add(offset + HEADER_SIZE).as_ptr(),
                            CONTEXT_SWITCH_RECORD_SIZE,
                        )
                    };
                    consume(decode_context_switch(payload)?)?;
                    consumed += 1;
                }
                self.consumer += record_size as u64;
                unsafe { self.consumer_position.as_ref() }.store(self.consumer, Ordering::Release);
                needs_wakeup_fence = true;
            }

            if needs_wakeup_fence {
                // Ensure either this refresh observes the next commit or the
                // producer observes our published cursor and sends a wakeup.
                std::sync::atomic::fence(Ordering::SeqCst);
                needs_wakeup_fence = false;
            }
            let refreshed = unsafe { self.producer_position.as_ref() }.load(Ordering::Acquire);
            if refreshed == producer {
                break;
            }
            producer = refreshed;
        }
        Ok(consumed)
    }
}

impl Drop for RingBufferRecorder<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.producer_mapping.as_ptr(), self.producer_mapping_len);
            libc::munmap(self.consumer_mapping.as_ptr(), self.page_size);
        }
    }
}

fn decode_context_switch(bytes: &[u8]) -> io::Result<ContextSwitchRecord> {
    if bytes.len() != CONTEXT_SWITCH_RECORD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid context-switch record size",
        ));
    }
    let timestamp_ns = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let runtime_ns = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    let previous_pid = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
    let next_pid = u32::from_ne_bytes(bytes[20..24].try_into().unwrap());
    let cpu = u32::from_ne_bytes(bytes[24..28].try_into().unwrap());
    let reserved = u32::from_ne_bytes(bytes[28..32].try_into().unwrap());
    let previous_state = i64::from_ne_bytes(bytes[32..40].try_into().unwrap());
    if reserved != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "context-switch record reserved field is not zero",
        ));
    }
    Ok(ContextSwitchRecord {
        timestamp_ns,
        runtime_ns,
        previous_pid,
        next_pid,
        cpu,
        previous_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_context_switch_record() {
        let mut bytes = [0; CONTEXT_SWITCH_RECORD_SIZE];
        bytes[0..8].copy_from_slice(&123u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&17u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&41u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&42u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&5u32.to_ne_bytes());
        bytes[32..40].copy_from_slice(&1i64.to_ne_bytes());
        assert_eq!(
            decode_context_switch(&bytes).unwrap(),
            ContextSwitchRecord {
                timestamp_ns: 123,
                runtime_ns: 17,
                previous_pid: 41,
                next_pid: 42,
                cpu: 5,
                previous_state: 1,
            }
        );
    }

    #[test]
    fn rejects_nonzero_reserved_field() {
        let mut bytes = [0; CONTEXT_SWITCH_RECORD_SIZE];
        bytes[28] = 1;
        assert_eq!(
            decode_context_switch(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
