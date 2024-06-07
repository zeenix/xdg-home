#![doc = include_str!("../README.md")]
#![doc(test(attr(
    warn(unused),
    deny(warnings),
    // W/o this, we seem to get some bogus warning about `extern crate ..`.
    allow(unused_extern_crates),
)))]

use std::path::PathBuf;

/// Get the path of the current user's home directory.
///
/// See the library documentation for more information.
pub fn home_dir() -> Option<PathBuf> {
    match std::env::var("HOME") {
        Ok(home) => Some(home.into()),
        Err(_) => {
            #[cfg(unix)]
            {
                unix::home_dir()
            }

            #[cfg(windows)]
            {
                win32::home_dir()
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    pub(super) fn home_dir() -> Option<PathBuf> {
        let uid = unsafe { libc::geteuid() };
        let passwd = unsafe { libc::getpwuid(uid) };

        // getpwnam(3):
        // The getpwnam() and getpwuid() functions return a pointer to a passwd structure, or NULL
        // if the matching entry is not found or an error occurs. If an error occurs, errno is set
        // to indicate the error. If one wants to check errno after the call, it should be set to
        // zero before the call. The return value may point to a static area, and may be overwritten
        // by subsequent calls to getpwent(3), getpwnam(), or getpwuid().
        if passwd.is_null() {
            return None;
        }

        // SAFETY: `getpwuid()` returns either NULL or a valid pointer to a `passwd` structure.
        let passwd = unsafe { &*passwd };
        if passwd.pw_dir.is_null() {
            return None;
        }

        // SAFETY: `getpwuid()->pw_dir` is a valid pointer to a c-string.
        let home_dir = unsafe { CStr::from_ptr(passwd.pw_dir) };

        Some(PathBuf::from(OsStr::from_bytes(home_dir.to_bytes())))
    }
}

#[cfg(windows)]
mod win32 {
    use std::{path::PathBuf, ptr};

    use windows_sys::Win32::Foundation::S_OK;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::FOLDERID_Profile;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

    pub(super) fn home_dir() -> Option<PathBuf> {
        let rfid = FOLDERID_Profile;
        let mut psz_path = ptr::null_mut();
        let res = unsafe { SHGetKnownFolderPath(&rfid, 0, 0, &mut psz_path as *mut _) };
        if res != S_OK {
            return None;
        }

        // Determine the length of the UTF-16 string.
        let mut len = 0;
        // SAFETY: `psz_path` guaranteed to be a valid pointer to a null-terminated UTF-16 string.
        while unsafe { *(psz_path as *const u16).offset(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(psz_path, len as usize) };
        let path = String::from_utf16(slice).ok()?;
        unsafe {
            CoTaskMemFree(psz_path as *mut _);
        }

        Some(PathBuf::from(path))
    }
}
