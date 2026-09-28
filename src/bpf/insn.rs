/// Kernel-compatible instruction used by the small handwritten fixture path.
/// Compiled programs use `aya_obj::generated::bpf_insn` directly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfInsn {
    pub code: u8,
    // The kernel ABI packs dst_reg into the low nibble and src_reg into the high.
    pub reg: u8,
    pub offset: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, src_reg: u8, dst_reg: u8, offset: i16, imm: i32) -> Self {
        Self {
            code,
            reg: (src_reg << 4) | (dst_reg & 0x0f),
            offset,
            imm,
        }
    }
}

const BPF_K: u8 = 0x00;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;
const BPF_MOV: u8 = 0xb0;
const BPF_EXIT: u8 = 0x90;

const MOV64_IMM: u8 = BPF_ALU64 | BPF_MOV | BPF_K;
const EXIT: u8 = BPF_JMP | BPF_EXIT;

pub fn trivial_program() -> [BpfInsn; 2] {
    [
        BpfInsn::new(MOV64_IMM, 0, 0, 0, 0), // r0 = 0
        BpfInsn::new(EXIT, 0, 0, 0, 0),      // exit
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_matches_kernel_abi_size() {
        assert_eq!(size_of::<BpfInsn>(), 8);
    }

    #[test]
    fn constructor_packs_register_nibbles() {
        let instruction = BpfInsn::new(0, 0x0a, 0x03, 0, 0);
        assert_eq!(instruction.reg, 0xa3);
    }
}
