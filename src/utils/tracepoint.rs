use std::{
    cell::OnceCell,
    fs,
    io::{self, Read},
    path::Path,
};

#[derive(Debug)]
pub struct Tracepoint {
    pub category: String,
    pub name: String,
    pub id: u64,
}

/// Reuse one resolver to cache tracing-directory discovery without synchronization.
/// Discovery failures are cached too; mount tracing before the first lookup.
#[derive(Debug, Default)]
pub struct TracepointResolver {
    root: OnceCell<io::Result<&'static Path>>,
}

impl TracepointResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&self, category: &str, name: &str) -> io::Result<Tracepoint> {
        let path = self.event_path(category, name)?.join("id");

        let id = fs::File::open(&path)
            .and_then(read_id)
            .map_err(|err| path_error(&path, err))?;

        Ok(Tracepoint {
            category: category.to_owned(),
            name: name.to_owned(),
            id,
        })
    }

    pub fn format(&self, category: &str, name: &str) -> io::Result<String> {
        let path = self.event_path(category, name)?.join("format");
        fs::read_to_string(&path).map_err(|err| path_error(&path, err))
    }

    fn event_path(&self, category: &str, name: &str) -> io::Result<std::path::PathBuf> {
        if !valid_component(category) || !valid_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tracepoint category and name must contain only ASCII letters, digits, or underscores",
            ));
        }
        let tracing_root = self
            .root
            .get_or_init(tracing_root)
            .as_ref()
            .map_err(|err| io::Error::new(err.kind(), err.to_string()))?;
        Ok(tracing_root.join("events").join(category).join(name))
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn read_id(mut reader: impl Read) -> io::Result<u64> {
    // 20 decimal digits for u64, one newline, and one byte to detect overflow.
    let mut buffer = [0u8; 22];
    let mut len = 0;
    while len < buffer.len() {
        match reader.read(&mut buffer[len..]) {
            Ok(0) => break,
            Ok(count) => len += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    if len == buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tracepoint ID is too long",
        ));
    }
    let text = std::str::from_utf8(&buffer[..len])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    text.trim()
        .parse()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

// Adapted from Aya's find_tracefs_path under the MIT license.
// https://github.com/aya-rs/aya/blob/main/aya/src/programs/utils.rs
// See LICENSES/aya-MIT.txt for the copyright and permission notice.
fn tracing_root() -> io::Result<&'static Path> {
    find_tracing_root(|mount| {
        let mut entries = mount.read_dir()?;
        entries.next().transpose().map(|entry| entry.is_some())
    })
}

fn path_error(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("cannot read {}: {err}", path.display()))
}

fn find_tracing_root(
    mut readable: impl FnMut(&'static Path) -> io::Result<bool>,
) -> io::Result<&'static Path> {
    let mut failure = None;
    for mount in [
        Path::new("/sys/kernel/tracing"),
        Path::new("/sys/kernel/debug/tracing"),
    ] {
        match readable(mount) {
            Ok(true) => return Ok(mount),
            Ok(false) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                if failure.is_none() || err.kind() == io::ErrorKind::PermissionDenied {
                    failure = Some(path_error(mount, err));
                }
            }
        }
    }
    Err(failure.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tracefs not found")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_preserves_permission_denied() {
        let err = find_tracing_root(|path| {
            Err(io::Error::from(
                if path == Path::new("/sys/kernel/tracing") {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::NotFound
                },
            ))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("/sys/kernel/tracing"));
    }

    #[test]
    fn discovery_uses_readable_fallback() {
        let root = find_tracing_root(|path| {
            if path == Path::new("/sys/kernel/tracing") {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(true)
            }
        })
        .unwrap();
        assert_eq!(root, Path::new("/sys/kernel/debug/tracing"));
    }

    #[test]
    fn cached_permission_failure_is_preserved() {
        let resolver = TracepointResolver {
            root: OnceCell::from(Err(path_error(
                Path::new("/sys/kernel/tracing"),
                io::ErrorKind::PermissionDenied.into(),
            ))),
        };
        for _ in 0..2 {
            let err = resolver.open("sched", "sched_switch").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("/sys/kernel/tracing"));
        }
    }

    #[test]
    fn reads_id_with_short_reads() {
        struct ByteReader<'a>(&'a [u8]);
        impl Read for ByteReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let len = buffer.len().min(1);
                self.0.read(&mut buffer[..len])
            }
        }
        assert_eq!(
            read_id(ByteReader(b"18446744073709551615\n")).unwrap(),
            u64::MAX
        );
        assert_eq!(read_id(&b"0"[..]).unwrap(), 0);
    }

    #[test]
    fn rejects_invalid_or_oversized_ids() {
        for input in [
            &b""[..],
            &b"abc\n"[..],
            &b"\xff"[..],
            &b"18446744073709551616\n"[..],
            &b"12345678901234567890123"[..],
        ] {
            assert_eq!(
                read_id(input).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn rejects_tracepoint_path_components() {
        let resolver = TracepointResolver::new();
        for value in ["", ".", "..", "sched/x", "sched-switch"] {
            assert_eq!(
                resolver.event_path(value, "event").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
