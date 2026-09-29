//! Semantic overrides for tracepoint pointer fields.
//!
//! Linux's tracepoint format remains authoritative for layout. Policies only
//! opt known pointer fields into bounded memory reads; every other pointer is
//! transported as an address.
use crate::tracepoint_schema::{CaptureKind, TracepointField};
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerCapture {
    Address,
    UserString {
        max_len: usize,
    },
    UserBytes {
        length_field: &'static str,
        max_len: usize,
    },
    KernelString {
        max_len: usize,
    },
    KernelBytes {
        length_field: &'static str,
        max_len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePolicy {
    pub category: &'static str,
    pub event: &'static str,
    pub field: &'static str,
    pub capture: PointerCapture,
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyRegistry {
    policies: &'static [CapturePolicy],
}

const fn user_string(event: &'static str, field: &'static str) -> CapturePolicy {
    CapturePolicy {
        category: "syscalls",
        event,
        field,
        capture: PointerCapture::UserString { max_len: 128 },
    }
}

const BUILTIN_POLICIES: &[CapturePolicy] = &[
    user_string("sys_enter_open", "filename"),
    user_string("sys_enter_openat", "filename"),
    user_string("sys_enter_openat2", "filename"),
    user_string("sys_enter_execve", "filename"),
    user_string("sys_enter_execveat", "filename"),
    user_string("sys_enter_chdir", "filename"),
    user_string("sys_enter_unlink", "pathname"),
    user_string("sys_enter_unlinkat", "pathname"),
    user_string("sys_enter_mkdir", "pathname"),
    user_string("sys_enter_mkdirat", "pathname"),
    user_string("sys_enter_rmdir", "pathname"),
    user_string("sys_enter_rename", "oldname"),
    user_string("sys_enter_rename", "newname"),
    user_string("sys_enter_renameat", "oldname"),
    user_string("sys_enter_renameat", "newname"),
    user_string("sys_enter_renameat2", "oldname"),
    user_string("sys_enter_renameat2", "newname"),
    CapturePolicy {
        category: "syscalls",
        event: "sys_enter_write",
        field: "buf",
        capture: PointerCapture::UserBytes {
            length_field: "count",
            max_len: 128,
        },
    },
    CapturePolicy {
        category: "syscalls",
        event: "sys_enter_pwrite64",
        field: "buf",
        capture: PointerCapture::UserBytes {
            length_field: "count",
            max_len: 128,
        },
    },
];

impl PolicyRegistry {
    pub const fn builtin() -> Self {
        Self {
            policies: BUILTIN_POLICIES,
        }
    }

    pub const fn empty() -> Self {
        Self { policies: &[] }
    }

    pub const fn from_static(policies: &'static [CapturePolicy]) -> Self {
        Self { policies }
    }

    pub(crate) fn capture_for(
        self,
        category: &str,
        event: &str,
        field: &TracepointField,
        available: &[TracepointField],
    ) -> io::Result<(PointerCapture, Option<(usize, usize)>)> {
        let Some(policy) = self.policies.iter().find(|policy| {
            policy.category == category && policy.event == event && policy.field == field.name
        }) else {
            return Ok((PointerCapture::Address, None));
        };
        if field.kind != CaptureKind::PointerAddress {
            return Err(invalid(format!(
                "policy for {category}:{event}.{} requires a pointer, running kernel declares {}",
                field.name, field.declaration
            )));
        }
        if !matches!(field.size, 4 | 8) {
            return Err(invalid(format!(
                "policy for {category}:{event}.{} requires a 4- or 8-byte pointer",
                field.name
            )));
        }
        let length = match policy.capture {
            PointerCapture::UserBytes { length_field, .. }
            | PointerCapture::KernelBytes { length_field, .. } => {
                let source = available
                    .iter()
                    .find(|candidate| candidate.name == length_field)
                    .ok_or_else(|| {
                        invalid(format!(
                            "policy for {category}:{event}.{} requires missing length field {length_field}",
                            field.name
                        ))
                    })?;
                if source.kind != CaptureKind::Scalar
                    || source.signed
                    || !matches!(source.size, 1 | 2 | 4 | 8)
                {
                    return Err(invalid(format!(
                        "policy length field {length_field} must be an unsigned fixed scalar"
                    )));
                }
                Some((source.offset, source.size))
            }
            _ => None,
        };
        Ok((policy.capture, length))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
