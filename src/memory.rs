//! Best-effort Linux memory locking for stable secret allocations.
//! This does not lock every library/GUI copy or establish that swap is encrypted.
use serde::Serialize;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
use zeroize::{Zeroize, Zeroizing};

static LIMITED: AtomicBool = AtomicBool::new(false);
static SWAP: OnceLock<&'static str> = OnceLock::new();

#[derive(Serialize)]
pub struct Status {
    pub selected_buffers_locked: bool,
    pub swap: &'static str,
}

fn swap_state(contents: &str) -> &'static str {
    let mut lines = contents.lines();
    if !lines
        .next()
        .is_some_and(|line| line.starts_with("Filename"))
    {
        return "unknown";
    }
    if lines.any(|line| !line.trim().is_empty()) {
        "active"
    } else {
        "none"
    }
}

pub fn initialize() {
    SWAP.get_or_init(|| {
        // Inspect only whether entries exist; never expose device names/paths.
        let state = std::fs::read_to_string("/proc/swaps")
            .map(|text| swap_state(&text))
            .unwrap_or("unknown");
        let probe = LockedPassword::new("memory-lock capability probe");
        drop(probe);
        state
    });
}

pub fn status() -> Status {
    initialize();
    Status {
        selected_buffers_locked: !LIMITED.load(Ordering::Relaxed),
        swap: SWAP.get().copied().unwrap_or("unknown"),
    }
}

// Dedicated page mappings prevent munlock() on one password from unlocking a
// different allocation sharing the same allocator page.
enum Storage {
    Mapping {
        address: std::ptr::NonNull<u8>,
        length: usize,
        capacity: usize,
        locked: bool,
    },
    Fallback(Zeroizing<Box<[u8]>>),
}
pub struct LockedPassword {
    storage: Storage,
}
impl LockedPassword {
    pub fn new(value: &str) -> Self {
        // SAFETY: sysconf has no memory preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let capacity = if page > 0 {
            value.len().max(1).checked_next_multiple_of(page as usize)
        } else {
            None
        };
        if let Some(capacity) = capacity {
            // SAFETY: anonymous private mapping; no address or file supplied.
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if address != libc::MAP_FAILED {
                let address = std::ptr::NonNull::new(address.cast::<u8>()).expect("non-null mmap");
                // Lock before writing secrets. Failure is reported, not hidden.
                let locked = unsafe { libc::mlock(address.as_ptr().cast(), capacity) } == 0;
                if !locked {
                    LIMITED.store(true, Ordering::Relaxed);
                }
                // Exclude these pages from core dumps independently of process policy.
                unsafe {
                    libc::madvise(address.as_ptr().cast(), capacity, libc::MADV_DONTDUMP);
                }
                // SAFETY: fresh mapping is writable and at least value.len() bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(value.as_ptr(), address.as_ptr(), value.len());
                }
                return Self {
                    storage: Storage::Mapping {
                        address,
                        length: value.len(),
                        capacity,
                        locked,
                    },
                };
            }
        }
        LIMITED.store(true, Ordering::Relaxed);
        Self {
            storage: Storage::Fallback(Zeroizing::new(
                value.as_bytes().to_vec().into_boxed_slice(),
            )),
        }
    }
    pub fn as_str(&self) -> &str {
        let bytes = match &self.storage {
            Storage::Mapping {
                address, length, ..
            } => {
                // SAFETY: mapping is owned by self and remains valid until Drop.
                unsafe { std::slice::from_raw_parts(address.as_ptr(), *length) }
            }
            Storage::Fallback(bytes) => bytes,
        };
        std::str::from_utf8(bytes).expect("locked UTF-8 password")
    }
    pub fn secret_copy(&self) -> age::secrecy::SecretString {
        // age owns/zeroizes its temporary KDF copy; it is not covered by our lock.
        age::secrecy::SecretString::from(self.as_str().to_owned())
    }
}
impl Drop for LockedPassword {
    fn drop(&mut self) {
        if let Storage::Mapping {
            address,
            capacity,
            locked,
            ..
        } = &self.storage
        {
            // SAFETY: wipe the whole owned mapping before unlocking or unmapping.
            unsafe {
                std::slice::from_raw_parts_mut(address.as_ptr(), *capacity).zeroize();
                if *locked {
                    libc::munlock(address.as_ptr().cast(), *capacity);
                }
                libc::munmap(address.as_ptr().cast(), *capacity);
            }
        }
        // Fallback is wiped by Zeroizing before its allocation is freed.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn swap_reporting_does_not_include_devices() {
        assert_eq!(swap_state("Filename\tType\tSize\tUsed\tPriority\n"), "none");
        assert_eq!(
            swap_state("Filename\tType\tSize\tUsed\tPriority\n/private/device partition 32 0 -2\n"),
            "active"
        );
        assert_eq!(swap_state("unexpected"), "unknown");
    }
    #[test]
    fn simultaneous_passwords_have_independent_pages() {
        let first = LockedPassword::new("first");
        let second = LockedPassword::new("second");
        if let (
            Storage::Mapping {
                address: a,
                capacity: ac,
                ..
            },
            Storage::Mapping {
                address: b,
                capacity: bc,
                ..
            },
        ) = (&first.storage, &second.storage)
        {
            let a = a.as_ptr() as usize;
            let b = b.as_ptr() as usize;
            assert!(a + ac <= b || b + bc <= a);
        }
        drop(first);
        assert_eq!(second.as_str(), "second");
    }
    #[test]
    fn locked_password_preserves_exact_utf8_and_empty_values() {
        for value in ["", " secret\n🗝 "] {
            let secret = LockedPassword::new(value);
            assert_eq!(secret.as_str(), value);
        }
    }
}
