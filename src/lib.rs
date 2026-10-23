pub mod duress;
pub mod expiry;
mod kdbx;
#[cfg(feature = "legacy-migration")]
pub mod legacy_vault;
pub mod pgp;
pub mod protection;
pub mod qubes;
pub mod vault;
pub mod worker;

/// Must run before accepting secrets. Prevent ordinary Linux core dumps.
pub fn harden_process() -> anyhow::Result<()> {
    // A crashed/killed desktop must not leave a worker holding unlocked keys.
    // Check the parent again after registration to close the startup race.
    // SAFETY: these calls take only integer arguments and affect this process.
    let parent = unsafe { libc::getppid() };
    anyhow::ensure!(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
        "Could not register parent-death protection"
    );
    anyhow::ensure!(
        unsafe { libc::getppid() } == parent,
        "Parent exited during startup"
    );
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointer; affects only this process.
    anyhow::ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "Could not disable core dumps"
    );
    // SAFETY: PR_SET_DUMPABLE takes an integer argument and no pointers.
    anyhow::ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "Could not disable process dumping"
    );
    Ok(())
}
