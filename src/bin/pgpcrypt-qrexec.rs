//! Narrow transport adapter. Run by Qubes qrexec in the vault user's context.
//! stderr intentionally contains no request, domain, key or library error.
use anyhow::{Context, Result, ensure};
use pgpcrypt::qubes::{Caller, MAX_REMOTE_FRAME, RemoteRequest};
use std::{
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn read_input() -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "Input deadline");
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized poll descriptor; bounded timeout.
        ensure!(
            unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(10000) as i32) } > 0,
            "Input deadline"
        );
        let mut part = [0u8; 4096];
        let count = std::io::stdin().read(&mut part)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&part[..count]);
        ensure!(bytes.len() <= MAX_REMOTE_FRAME, "Oversized request");
    }
    Ok(bytes)
}
fn run() -> Result<()> {
    pgpcrypt::harden_process()?;
    let service = std::env::args().nth(1).context("Missing service")?;
    ensure!(
        std::env::args().count() == 2,
        "Unexpected service arguments"
    );
    ensure!(
        std::env::var("QREXEC_SERVICE_ARGUMENT")
            .unwrap_or_default()
            .is_empty(),
        "Service arguments forbidden"
    );
    let domain = std::env::var("QREXEC_REMOTE_DOMAIN").context("qrexec required")?;
    let bytes = read_input()?;
    let mut fields = if service == "Lock" {
        ensure!(
            domain == "dom0" && bytes.is_empty(),
            "Lock is dom0-only and takes no data"
        );
        serde_json::json!({"version":1,"operation":"lock"})
    } else {
        Caller::from_qrexec_domain(&domain)?;
        let request = RemoteRequest::parse(&bytes)?;
        ensure!(
            matches!(
                (service.as_str(), &request),
                ("Sign", RemoteRequest::Sign { .. }) | ("Decrypt", RemoteRequest::Decrypt { .. })
            ),
            "Service operation mismatch"
        );
        serde_json::from_slice(&bytes)?
    };
    fields["caller"] = serde_json::json!(domain);
    // Derive the location from the effective UID, not caller-controlled paths.
    // SAFETY: geteuid has no arguments or memory requirements.
    let uid = unsafe { libc::geteuid() };
    let directory = PathBuf::from(format!("/run/user/{uid}/pgpcrypt"));
    let metadata = std::fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "Unsafe broker directory"
    );
    let mut socket = UnixStream::connect(directory.join("rpc.sock"))?;
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: correctly sized writable credential buffer and live socket.
    ensure!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credential.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0,
        "Peer credentials unavailable"
    );
    // SAFETY: getsockopt initialized the credential buffer on success.
    ensure!(
        unsafe { credential.assume_init() }.uid == uid,
        "Wrong broker owner"
    );
    socket.set_read_timeout(Some(Duration::from_secs(90)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut encoded = Zeroizing::new(serde_json::to_vec(&fields)?);
    encoded.push(b'\n');
    socket.write_all(&encoded)?;
    let mut response = Zeroizing::new(Vec::new());
    socket
        .take((8 * MAX_REMOTE_FRAME + 1) as u64)
        .read_to_end(&mut response)?;
    ensure!(
        response.len() <= 8 * MAX_REMOTE_FRAME && response.last() == Some(&b'\n'),
        "Invalid response"
    );
    std::io::stdout().write_all(&response)?;
    Ok(())
}
fn main() {
    if run().is_err() {
        let _ = std::io::stdout().write_all(
            b"{\"ok\":false,\"error\":\"Request denied, cancelled, unavailable or timed out\"}\n",
        );
        std::process::exit(1);
    }
}
