#![doc = "Audited platform boundary for atomic replace-with-retained-old semantics."]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fs;
use std::io;
use std::path::Path;

/// Atomically installs `candidate` at `target` and retains the replaced target at `rollback`.
/// All paths must be on the same local filesystem and `rollback` must not exist.
pub fn atomic_replace_preserving_old(
    target: &Path,
    candidate: &Path,
    rollback: &Path,
) -> io::Result<()> {
    validate_paths(target, candidate, rollback)?;
    platform_replace(target, candidate, rollback)
}

/// Applies owner-only vault permissions on Unix and a protected owner/System DACL on Windows.
pub fn harden_private_file(path: &Path) -> io::Result<()> {
    platform_harden_private_file(path)
}

#[cfg(unix)]
fn platform_harden_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn platform_harden_private_file(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };

    let path_w = path
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    let sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)"
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: input is a live NUL-terminated UTF-16 SDDL string; the API initializes descriptor.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor came from the conversion API and path is NUL-terminated and live.
    let applied = unsafe {
        SetFileSecurityW(
            path_w.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    // SAFETY: LocalFree is the required deallocator for the conversion API allocation.
    let _ = unsafe { LocalFree(descriptor) };
    if applied == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_harden_private_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn validate_paths(target: &Path, candidate: &Path, rollback: &Path) -> io::Result<()> {
    if rollback.exists() || target == candidate || target == rollback || candidate == rollback {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "replace paths are not distinct or rollback already exists",
        ));
    }
    for path in [target, candidate] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replace path is not a regular non-link file",
            ));
        }
        reject_windows_reparse_point(&metadata)?;
    }
    Ok(())
}

#[cfg(windows)]
fn reject_windows_reparse_point(metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows reparse points are not accepted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn reject_windows_reparse_point(_metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_replace(target: &Path, candidate: &Path, rollback: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "target contains NUL"))?;
    let candidate_c = CString::new(candidate.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "candidate contains NUL"))?;
    // SAFETY: the C strings are NUL-terminated and live for the call. RENAME_SWAP atomically
    // exchanges two existing same-volume entries and does not retain the pointers.
    let result =
        unsafe { libc::renamex_np(candidate_c.as_ptr(), target_c.as_ptr(), libc::RENAME_SWAP) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = fs::rename(candidate, rollback) {
        // SAFETY: the same pointer and lifetime guarantees apply; this restores original names.
        let _ =
            unsafe { libc::renamex_np(candidate_c.as_ptr(), target_c.as_ptr(), libc::RENAME_SWAP) };
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_replace(target: &Path, candidate: &Path, rollback: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "target contains NUL"))?;
    let candidate_c = CString::new(candidate.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "candidate contains NUL"))?;
    // SAFETY: pointers reference live NUL-terminated paths. renameat2 with RENAME_EXCHANGE
    // atomically swaps the two entries and does not retain pointers.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            candidate_c.as_ptr(),
            libc::AT_FDCWD,
            target_c.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = fs::rename(candidate, rollback) {
        // SAFETY: same valid path arguments; this best-effort swap restores original names.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                candidate_c.as_ptr(),
                libc::AT_FDCWD,
                target_c.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn platform_replace(target: &Path, candidate: &Path, rollback: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain([0])
            .collect::<Vec<_>>()
    };
    let target_w = wide(target);
    let candidate_w = wide(candidate);
    let rollback_w = wide(rollback);
    // SAFETY: all UTF-16 buffers are NUL-terminated and live for the call; optional pointers
    // are null as required. ReplaceFileW installs the candidate and retains a backup atomically.
    let result = unsafe {
        ReplaceFileW(
            target_w.as_ptr(),
            candidate_w.as_ptr(),
            rollback_w.as_ptr(),
            REPLACEFILE_WRITE_THROUGH,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn platform_replace(target: &Path, candidate: &Path, rollback: &Path) -> io::Result<()> {
    fs::hard_link(target, rollback)?;
    fs::rename(candidate, target)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::atomic_replace_preserving_old;

    #[test]
    fn replacement_retains_exact_old_file() {
        let directory = temp_directory();
        let target = directory.join("target");
        let candidate = directory.join("candidate");
        let rollback = directory.join("rollback");
        fs::write(&target, b"old").expect("old file must write");
        fs::write(&candidate, b"new").expect("candidate must write");
        atomic_replace_preserving_old(&target, &candidate, &rollback)
            .expect("platform replace must succeed");
        assert_eq!(fs::read(&target).expect("target exists"), b"new");
        assert_eq!(fs::read(&rollback).expect("rollback exists"), b"old");
        assert!(!candidate.exists());
        fs::remove_dir_all(directory).expect("test directory must clean");
    }

    fn temp_directory() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vaultx-platform-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock must be valid")
                .as_nanos()
        ));
        fs::create_dir(&path).expect("test directory must exist");
        path
    }
}
