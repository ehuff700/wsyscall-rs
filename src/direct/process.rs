use crate::{
    direct::NTDLL_NAME,
    utils::wintypes::{NTSTATUS, UNICODE_STRING},
    SSN_CACHE,
};
use core::arch::asm;

#[repr(C)]
#[derive(Debug)]
// https://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
pub struct ClientId {
    unique_process: *mut core::ffi::c_void,
    unique_thread: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut core::ffi::c_void,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *const core::ffi::c_void,
    pub SecurityQualityOfService: *const core::ffi::c_void,
}

/// Opens a process object.
///
/// This function uses a direct syscall to call the `NtOpenProcess` function.
///
/// # Safety
/// This function abides by the same safety requirements as the underlying syscall.
pub unsafe fn NtOpenProcess(
    process_handle: *mut core::ffi::c_void,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS {
    let ssn = { SSN_CACHE.lock().get_or_insert(NTDLL_NAME, "NtOpenProcess") };
    let status: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) ssn,
        in("rcx") process_handle,
        in("rdx") desired_access,
        in("r8") object_attributes,
        in("r9") client_id,
        lateout("rax") status,
        options(nostack),
    );
    status
}
