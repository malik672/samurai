use std::process::ExitCode;

use samurai::bpf::{insn::trivial_program, syscall::load_program};

fn main() -> ExitCode {
    let insns = trivial_program();

    match load_program(&insns) {
        Ok(fd) => {
            println!("loaded eBPF program!");
            println!("fd = {:?}", fd);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("failed: {err}");
            ExitCode::FAILURE
        }
    }
}
