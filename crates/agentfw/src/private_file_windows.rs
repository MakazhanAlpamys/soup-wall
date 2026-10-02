// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Owner-only Windows files for the daemon token and audit log.
//!
//! A new file receives a protected DACL in the `CreateFileW` call, before any
//! secret is written. An existing file is secured through its open handle before
//! its contents are read or appended. Failures are fatal to daemon startup.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Both SDDL conversion functions return LocalAlloc memory.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken returned this owned handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct PrivateAcl {
    descriptor: LocalMemory,
    dacl: *mut ACL,
}

impl PrivateAcl {
    fn new() -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)");
        Self::from_sddl(&sddl)
    }

    fn for_directory() -> io::Result<Self> {
        let sid = current_user_sid()?;
        // OI and CI let files and subdirectories created beneath .agentfw
        // inherit the owner-only ACL too. The directory itself is protected.
        let sddl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)");
        Self::from_sddl(&sddl)
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated and `descriptor` receives an owned
        // LocalAlloc allocation when the conversion succeeds.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalMemory(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        // SAFETY: The returned security descriptor remains alive in `descriptor`.
        if unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private security descriptor has no DACL",
            ));
        }
        Ok(Self { descriptor, dacl })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        }
    }

    fn apply(&self, handle: HANDLE) -> io::Result<()> {
        // SAFETY: The handle is open with WRITE_DAC. `dacl` points into the
        // security descriptor held by `self` for the duration of this call.
        let code = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.dacl,
                null(),
            )
        };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: The process pseudo-handle is valid and `raw_token` is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = TokenHandle(raw_token);
    let mut needed = 0;
    // SAFETY: The first call asks Windows for the required buffer size.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::last_os_error());
    }
    // `Vec<usize>` gives the TOKEN_USER structure pointer-sized alignment.
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    // SAFETY: `buffer` has at least `needed` bytes and remains alive while the
    // returned TOKEN_USER and its embedded SID pointer are used.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation(TokenUser) filled an aligned TOKEN_USER.
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_wide = null_mut();
    // SAFETY: The SID pointer is part of the live TOKEN_USER buffer; the API
    // returns a NUL-terminated string allocated with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _sid_memory = LocalMemory(sid_wide.cast());
    let length = (0..256)
        .find(|&index| unsafe { *sid_wide.add(index) == 0 })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID string too long"))?;
    // SAFETY: The NUL terminator was found within the allocated SID string.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_wide, length) })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(sid)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn check_kind(handle: HANDLE, directory: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is open and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file path is a reparse point",
        ));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private path has the wrong file type",
        ));
    }
    Ok(())
}

fn open_private(path: &Path, access: u32, create: bool) -> io::Result<File> {
    let wide = wide_path(path)?;
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let raw = if create {
        // SAFETY: All pointers remain live for the call. CREATE_NEW never opens
        // or truncates an existing file, including a final-component symlink.
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                share,
                &attributes,
                CREATE_NEW,
                flags,
                null_mut(),
            )
        }
    } else {
        INVALID_HANDLE_VALUE
    };
    let raw = if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if !create
            || matches!(
                error.raw_os_error(),
                Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
            )
        {
            // SAFETY: OPEN_EXISTING does not create or truncate. The reparse
            // flag makes the opened handle refer to the link itself for checks.
            unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    access,
                    share,
                    null(),
                    OPEN_EXISTING,
                    flags,
                    null_mut(),
                )
            }
        } else {
            return Err(error);
        }
    } else {
        raw
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a unique owned file handle. `File` closes it
    // on all subsequent error and success paths.
    let file = unsafe { File::from_raw_handle(raw) };
    check_kind(raw, false)?;
    // Even on a new file, verify that the filesystem accepts a protected DACL
    // before any data is written. A filesystem without ACL support fails closed.
    acl.apply(raw)?;
    Ok(file)
}

pub fn open_token(path: &Path) -> io::Result<File> {
    open_private(
        path,
        FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC,
        true,
    )
}

pub fn open_audit(path: &Path) -> io::Result<File> {
    open_private(path, FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC, true)
}

pub fn restrict_existing(path: &Path) -> io::Result<()> {
    let _file = open_private(path, READ_CONTROL | WRITE_DAC, false)?;
    Ok(())
}

/// Create or tighten the default .agentfw directory before resolving any
/// token, audit, grant, or manifest path beneath it.
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    let wide = wide_path(path)?;
    let acl = PrivateAcl::for_directory()?;
    let attributes = acl.attributes();
    // SAFETY: The path and security descriptor remain live for this call.
    // Existing directories are never replaced or modified here.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        ) {
            return Err(error);
        }
    }
    let raw = open_directory_handle(&wide)?;
    // SAFETY: CreateFileW returned one owned handle, closed with File on every
    // return path. Backup semantics permit opening directories as files.
    let _directory = unsafe { File::from_raw_handle(raw) };
    check_kind(raw, true)?;
    acl.apply(raw)?;
    Ok(())
}

fn open_directory_handle(wide: &[u16]) -> io::Result<HANDLE> {
    // SAFETY: `wide` is a NUL-terminated path. The reparse flag opens the final
    // link itself so the caller can reject it, never the link's target.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    use super::{
        current_user_sid, open_directory_handle, wide_path, LocalMemory, PrivateAcl,
        FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL, WRITE_DAC,
    };

    fn security_sddl(path: &Path) -> String {
        let file = File::open(path).unwrap();
        security_sddl_handle(&file)
    }

    fn directory_sddl(path: &Path) -> String {
        let wide = wide_path(path).unwrap();
        let raw = open_directory_handle(&wide).unwrap();
        // SAFETY: The helper returns an owned directory handle.
        let directory = unsafe { File::from_raw_handle(raw) };
        security_sddl_handle(&directory)
    }

    fn security_sddl_handle(file: &File) -> String {
        let mut descriptor = null_mut();
        // SAFETY: The file handle is live and the requested descriptor is
        // returned as LocalAlloc memory owned by this test.
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(code, 0, "GetSecurityInfo failed: {code}");
        let _descriptor = LocalMemory(descriptor);
        let mut wide = null_mut();
        let mut length = 0;
        // SAFETY: The descriptor is live and output pointers are writable.
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut wide,
                    &mut length,
                )
            },
            0,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed"
        );
        let _wide = LocalMemory(wide.cast());
        // SAFETY: The API returned exactly `length` UTF-16 code units.
        String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length as usize) })
            .unwrap()
            .trim_end_matches('\0')
            .to_string()
    }

    fn assert_private(path: &Path) {
        let sddl = security_sddl(path);
        assert_private_sddl(&sddl);
        assert_eq!(sddl.matches("(A;").count(), 2, "unexpected ACE: {sddl}");
    }

    fn assert_private_directory(path: &Path) {
        let sddl = directory_sddl(path);
        assert_private_sddl(&sddl);
        assert!(
            sddl.matches(";OICI").count() >= 2,
            "directory inheritance missing: {sddl}"
        );
    }

    fn assert_private_sddl(sddl: &str) {
        let user = current_user_sid().unwrap();
        assert!(sddl.starts_with("D:P"), "DACL must be protected: {sddl}");
        assert!(
            sddl.contains(&format!(";;;{user})")),
            "owner missing: {sddl}"
        );
        assert!(sddl.contains(";;;SY)"), "SYSTEM missing: {sddl}");
        for ace in sddl.split('(').skip(1) {
            let ace = ace.split(')').next().unwrap();
            assert!(ace.starts_with("A;"), "unexpected ACE: {sddl}");
            let trustee = ace.rsplit(';').next().unwrap();
            assert!(trustee == user || trustee == "SY", "broad access in {sddl}");
        }
    }

    fn make_world_readable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .access_mode(FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC)
            .open(path)
            .unwrap();
        let loose = PrivateAcl::from_sddl("D:P(A;;GA;;;WD)").unwrap();
        loose.apply(file.as_raw_handle()).unwrap();
        assert!(security_sddl(path).contains(";;;WD)"));
    }

    #[test]
    fn new_token_and_audit_files_have_protected_owner_only_acls() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        let audit = dir.path().join("audit.jsonl");
        crate::token::load_or_create(&token).unwrap();
        let _sink = crate::audit::AuditSink::open(&audit).unwrap();
        assert_private(&token);
        assert_private(&audit);
    }

    #[test]
    fn existing_loose_files_are_secured_without_losing_data() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        let audit = dir.path().join("audit.jsonl");
        make_world_readable(&token, "old-token\n");
        make_world_readable(&audit, "old-audit\n");

        assert_eq!(crate::token::load_or_create(&token).unwrap(), "old-token");
        let _sink = crate::audit::AuditSink::open(&audit).unwrap();
        assert_eq!(fs::read_to_string(&audit).unwrap(), "old-audit\n");
        assert_private(&token);
        assert_private(&audit);
    }

    #[test]
    fn token_path_does_not_follow_a_file_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("token-link");
        fs::write(&target, "target-data").unwrap();
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => {}
            // Creating symlinks requires Developer Mode or SeCreateSymbolicLinkPrivilege
            // on some Windows hosts. The ACL tests above still run there.
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("symlink privilege unavailable; reparse test skipped");
                return;
            }
            Err(error) => panic!("cannot create test symlink: {error}"),
        }
        assert!(crate::token::load_or_create(&link).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "target-data");
    }

    #[test]
    fn inaccessible_existing_token_fails_without_overwriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "keep-me").unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .access_mode(FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        let user = current_user_sid().unwrap();
        let narrow = PrivateAcl::from_sddl(&format!("D:P(A;;RCWD;;;{user})(A;;GA;;;SY)")).unwrap();
        narrow.apply(file.as_raw_handle()).unwrap();

        assert!(crate::token::load_or_create(&path).is_err());

        // The already-open owner handle can restore the ACL for inspection and
        // cleanup; the denied open above must not have rewritten the token.
        PrivateAcl::new()
            .unwrap()
            .apply(file.as_raw_handle())
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep-me");
    }

    #[test]
    fn new_agent_home_has_protected_inheritable_acl() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join(".agentfw");
        super::ensure_private_directory(&home).unwrap();
        assert_private_directory(&home);

        // Files created by other Agent stores inherit a private ACL too.
        let child = home.join("grant.json");
        fs::write(&child, "grant").unwrap();
        let sddl = security_sddl(&child);
        let user = current_user_sid().unwrap();
        assert!(sddl.contains(&format!(";;;{user})")), "{sddl}");
        assert!(sddl.contains(";;;SY)"), "{sddl}");
        assert!(!sddl.contains(";;;WD)"), "{sddl}");
    }

    #[test]
    fn existing_loose_agent_home_is_tightened_before_use() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join(".agentfw");
        fs::create_dir(&home).unwrap();
        fs::write(home.join("existing"), "keep").unwrap();
        let wide = wide_path(&home).unwrap();
        let raw = open_directory_handle(&wide).unwrap();
        // SAFETY: The helper returns an owned directory handle.
        let directory = unsafe { File::from_raw_handle(raw) };
        PrivateAcl::from_sddl("D:P(A;OICI;GA;;;WD)")
            .unwrap()
            .apply(directory.as_raw_handle())
            .unwrap();
        drop(directory);
        assert!(directory_sddl(&home).contains(";;;WD)"));

        super::ensure_private_directory(&home).unwrap();
        assert_private_directory(&home);
        assert_eq!(fs::read_to_string(home.join("existing")).unwrap(), "keep");
    }

    #[test]
    fn agent_home_does_not_follow_a_directory_symlink() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join(".agentfw");
        fs::create_dir(&target).unwrap();
        match std::os::windows::fs::symlink_dir(&target, &link) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("symlink privilege unavailable; reparse test skipped");
                return;
            }
            Err(error) => panic!("cannot create test symlink: {error}"),
        }
        assert!(super::ensure_private_directory(&link).is_err());
        assert!(target.is_dir());
    }
}
