use std::io;

fn main() -> io::Result<()> {
    samurai::cli::run_inspect_args(std::env::args().skip(1).collect())
}
