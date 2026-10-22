use anyhow::Result;

fn main() -> Result<()> {
    pgpcrypt::harden_process()?;
    pgpcrypt::worker::run(std::io::stdin().lock(), std::io::stdout().lock())
}
