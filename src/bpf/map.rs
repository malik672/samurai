//! Array-map ownership, following Aya's MapData/typed-map separation of duties.
use super::syscall;
use aya_obj::Map;
use std::{
    fs, io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    ptr::NonNull,
};

pub struct ArrayMap {
    fd: OwnedFd,
    obj: Map,
}

pub struct MappedArray<'map> {
    _map: &'map ArrayMap,
    mapping: NonNull<libc::c_void>,
    mapping_len: usize,
    values: NonNull<u8>,
    value_size: usize,
    entries: usize,
}

unsafe impl Send for MappedArray<'_> {}
unsafe impl Sync for MappedArray<'_> {}

pub struct RingBufferMap {
    fd: OwnedFd,
    obj: Map,
}

pub struct PerCpuArrayMap {
    fd: OwnedFd,
    obj: Map,
    cpu_count: usize,
}

pub struct LruPerCpuHashMap {
    fd: OwnedFd,
    obj: Map,
    cpu_count: usize,
    value_stride: usize,
}

impl ArrayMap {
    // ObjectLoader validates the supported map definitions before this call.
    pub(crate) fn create(obj: Map) -> io::Result<Self> {
        let fd = syscall::create_array_map_with_flags(
            obj.key_size(),
            obj.value_size(),
            obj.max_entries(),
            obj.map_flags(),
        )?;
        Ok(Self { fd, obj })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub(crate) fn obj(&self) -> &Map {
        &self.obj
    }

    pub fn read_u64(&self, index: u32) -> io::Result<u64> {
        if self.obj.key_size() != 4 || self.obj.value_size() != 8 || index >= self.obj.max_entries()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requires a four-byte key, eight-byte value, and an in-range index",
            ));
        }
        // The private FD owns an array with these immutable key/value sizes.
        unsafe { syscall::lookup_u64(self.fd.as_fd(), index) }
    }

    pub fn write(&self, index: u32, value: &[u8]) -> io::Result<()> {
        if self.obj.key_size() != 4
            || value.len() != self.obj.value_size() as usize
            || index >= self.obj.max_entries()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "array update requires a four-byte key, exact value size, and an in-range index",
            ));
        }
        syscall::update_map_value(self.fd.as_fd(), index, value)
    }

    pub fn mmap(&self) -> io::Result<MappedArray<'_>> {
        if self.obj.map_flags() & syscall::BPF_F_MMAPABLE == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "array is not mmapable",
            ));
        }
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(io::Error::last_os_error)?;
        let values_len = (self.obj.value_size() as usize)
            .checked_mul(self.obj.max_entries() as usize)
            .ok_or_else(|| io::Error::other("mapped array size overflow"))?;
        // BPF array maps keep an internal metadata page before their values,
        // but the map's mmap operation exposes the value region at offset 0.
        // Therefore userspace maps only the page-rounded value storage.
        let mapping_len = values_len.next_multiple_of(page);
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd.as_raw_fd(),
                0,
            )
        };
        let mapping = NonNull::new(mapping)
            .filter(|ptr| ptr.as_ptr() != libc::MAP_FAILED)
            .ok_or_else(io::Error::last_os_error)?;
        let values = mapping.cast();
        Ok(MappedArray {
            _map: self,
            mapping,
            mapping_len,
            values,
            value_size: self.obj.value_size() as usize,
            entries: self.obj.max_entries() as usize,
        })
    }
}

impl MappedArray<'_> {
    pub fn value_ptr(&self, index: usize) -> io::Result<NonNull<u8>> {
        if index >= self.entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mapped array index out of range",
            ));
        }
        Ok(unsafe { self.values.byte_add(index * self.value_size) })
    }
    pub fn value_size(&self) -> usize {
        self.value_size
    }

    pub fn entries(&self) -> usize {
        self.entries
    }
}

impl Drop for MappedArray<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping.as_ptr(), self.mapping_len);
        }
    }
}

impl RingBufferMap {
    pub(crate) fn create(obj: Map) -> io::Result<Self> {
        let fd = syscall::create_ring_buffer_map(obj.max_entries())?;
        Ok(Self { fd, obj })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn obj(&self) -> &Map {
        &self.obj
    }

    pub fn capacity(&self) -> usize {
        self.obj.max_entries() as usize
    }
}

impl PerCpuArrayMap {
    pub(crate) fn create(obj: Map) -> io::Result<Self> {
        let cpu_count = possible_cpu_count()?;
        let fd =
            syscall::create_per_cpu_array_map(obj.key_size(), obj.value_size(), obj.max_entries())?;
        Ok(Self { fd, obj, cpu_count })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn obj(&self) -> &Map {
        &self.obj
    }

    pub fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Read all CPU-local u64 values into storage allocated by the caller.
    pub fn read_u64(&self, index: u32, values: &mut [u64]) -> io::Result<()> {
        if self.obj.key_size() != 4
            || self.obj.value_size() != 8
            || index >= self.obj.max_entries()
            || values.len() != self.cpu_count
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "requires a four-byte key, eight-byte value, in-range index, and {} CPU slots",
                    self.cpu_count
                ),
            ));
        }
        syscall::lookup_per_cpu_u64(self.fd.as_fd(), index, values)
    }
}

impl LruPerCpuHashMap {
    pub(crate) fn create(obj: Map) -> io::Result<Self> {
        let cpu_count = possible_cpu_count()?;
        let value_stride = (obj.value_size() as usize + 7) & !7;
        let fd = syscall::create_lru_per_cpu_hash_map(
            obj.key_size(),
            obj.value_size(),
            obj.max_entries(),
        )?;
        Ok(Self {
            fd,
            obj,
            cpu_count,
            value_stride,
        })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn obj(&self) -> &Map {
        &self.obj
    }

    pub fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    pub fn key_size(&self) -> usize {
        self.obj.key_size() as usize
    }

    pub fn value_size(&self) -> usize {
        self.obj.value_size() as usize
    }

    pub fn max_entries(&self) -> usize {
        self.obj.max_entries() as usize
    }

    pub fn values_len(&self) -> usize {
        self.value_stride * self.cpu_count
    }

    pub fn next_key(&self, key: Option<&[u8]>, next: &mut [u8]) -> io::Result<bool> {
        if key.is_some_and(|key| key.len() != self.key_size()) || next.len() != self.key_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid hash-map key size",
            ));
        }
        syscall::next_map_key(self.fd.as_fd(), key, next)
    }

    pub fn read(&self, key: &[u8], values: &mut [u8]) -> io::Result<()> {
        if key.len() != self.key_size() || values.len() != self.values_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid per-CPU hash lookup buffer size",
            ));
        }
        syscall::lookup_map_bytes(self.fd.as_fd(), key, values)
    }

    pub fn cpu_value<'a>(&self, values: &'a [u8], cpu: usize) -> io::Result<&'a [u8]> {
        if values.len() != self.values_len() || cpu >= self.cpu_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid CPU value buffer",
            ));
        }
        let start = cpu * self.value_stride;
        Ok(&values[start..start + self.value_size()])
    }
}

fn possible_cpu_count() -> io::Result<usize> {
    let list = fs::read_to_string("/sys/devices/system/cpu/possible")?;
    parse_possible_cpu_count(&list)
}

fn parse_possible_cpu_count(list: &str) -> io::Result<usize> {
    let mut count = 0usize;
    for range in list.trim().split(',') {
        let (start, end) = match range.split_once('-') {
            Some((start, end)) => (start, end),
            None => (range, range),
        };
        let start: usize = start
            .parse()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let end: usize = end
            .parse()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let width = end
            .checked_sub(start)
            .and_then(|width| width.checked_add(1))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid possible CPU range")
            })?;
        count = count.checked_add(width).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "possible CPU count overflow")
        })?;
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "possible CPU list is empty",
        ));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_possible_cpu_ranges() {
        assert_eq!(parse_possible_cpu_count("0-7\n").unwrap(), 8);
        assert_eq!(parse_possible_cpu_count("0-3,8,10-11\n").unwrap(), 7);
    }

    #[test]
    fn rejects_invalid_possible_cpu_ranges() {
        for value in ["", "4-2", "x", "0-"] {
            assert_eq!(
                parse_possible_cpu_count(value).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
