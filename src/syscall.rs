#![allow(non_snake_case, non_camel_case_types)]
pub const STACK_ALLOC: usize = 40;

#[allow(unused)]
macro_rules! count_fields {
    () => (0);
    ($field:expr) => (1);
    ($field:expr, $($rest:expr),+) => (1 + count_fields!($($rest),+));
}

#[allow(unused)]
macro_rules! reverse_and_push {
    // Base case: No more fields to process
    () => {};

    // Recursive case: Split off the last field, push it, and recurse
    ($last:expr) => {
        core::arch::asm!(
            "push {0:r}",
            in(reg) $last,
        );
    };
    ($first:expr, $($rest:expr),+) => {
        reverse_and_push!($($rest),+); // Recurse with the rest of the fields
        core::arch::asm!(
            "push {0:r}",
            in(reg) $first,
        );
    };
}
#[macro_export]
macro_rules! syscall {
    // Base case: no arguments (just SSN)
    ($ssn:ident) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) ssn,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:ident, $field1:expr) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) ssn,
            in("rcx") $field1,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) ssn,
            in("rcx") $field1,
            in("rdx") $field2,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) ssn,
            in("rcx") $field1,
            in("rdx") $field2,
            in("r8") $field3,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        core::arch::asm!(
            #[cfg(feature = "direct")]
            "syscall",
            in("r10") $field1,
            in("rdx") $field2,
            in("r8") $field3,
            in("r9") $field4,
            // `rcx` preserves rip
            out("rcx") _,
            // `r11` preserves rflags
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr, $($extra_fields:expr),+) => {{
        let status: i32;
        #[cfg(feature = "indirect")]
        let (ssn, syscall_address) = ($ssn.ssn, $ssn.syscall_address);
        #[cfg(feature = "direct")]
        let ssn = $ssn.ssn;
        // Reverse the order of extra fields and push them onto the stack
        reverse_and_push!($($extra_fields),+);
        const LEN: usize = count_fields!($($extra_fields),+);
        core::arch::asm!(
            "sub rsp, {stack_alloc}",
            #[cfg(feature = "direct")]
            "syscall",
            "add rsp, {stack_dealloc}",
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            inout("r9") $field4 => _,
            inlateout("rax") ssn => status,
            // `rcx` preserves rip
            out("rcx") _,
            // `r11` preserves rflags
            out("r11") _,
            stack_alloc = const $crate::syscall::STACK_ALLOC,
            stack_dealloc = const $crate::syscall::STACK_ALLOC + (8 * LEN),
            options(preserves_flags),
        );
        status
    }};
}

#[macro_export]
macro_rules! syscall_imp {
    ($syscall:ident, ($($field_name:ident: $field_type:ty),*)) => {
        #[allow(non_snake_case, clippy::too_many_arguments)]
        pub unsafe extern "system" fn $syscall($($field_name: $field_type),*) -> $crate::utils::wintypes::NTSTATUS {
            let syscall = {
                $crate::SSN_CACHE.lock()
                    .get_ssn_for_hash($crate::hash!($syscall))
            };
            $crate::syscall!(syscall, $($field_name),*)
        }
    };

}

#[cfg(test)]
mod tests {
    extern crate std;
    use core::ffi::{c_char, c_ulong};
    use std::{eprintln, println};

    use crate::utils::wintypes::{NTSTATUS, UNICODE_STRING};
    use alloc::vec::Vec;

    #[repr(C)]
    #[derive(Debug)]
    pub struct SYSTEM_BASIC_INFORMATION {
        pub Reserved: c_ulong,
        pub TimerResolution: c_ulong,
        pub PageSize: c_ulong,
        pub NumberOfPhysicalPages: c_ulong,
        pub LowestPhysicalPageNumber: c_ulong,
        pub HighestPhysicalPageNumber: c_ulong,
        pub AllocationGranularity: c_ulong,
        pub MinimumUserModeAddress: usize,
        pub MaximumUserModeAddress: usize,
        pub ActiveProcessorsAffinityMask: usize,
        pub NumberOfProcessors: c_char,
    }

    #[allow(non_upper_case_globals)]
    const SystemBasicInformation: u32 = 0; // Corresponds to the SYSTEM_INFORMATION_CLASS enum.

    #[test]
    fn test_syscall_imp() {
        syscall_imp!(NtQuerySystemInformation,(
            SystemInformationClass: u32,
            SystemInformation: *mut core::ffi::c_void,
            SystemInformationLength: u32,
            ReturnLength: *mut u32
        ));

        unsafe {
            let mut system_info = core::mem::zeroed::<SYSTEM_BASIC_INFORMATION>();

            let status = NtQuerySystemInformation(
                SystemBasicInformation,
                &mut system_info as *mut _ as *mut _,
                core::mem::size_of::<SYSTEM_BASIC_INFORMATION>() as u32,
                core::ptr::null_mut(),
            );

            if status == 0 {
                // STATUS_SUCCESS
                println!("Number of Processors: {}", system_info.NumberOfProcessors);
                println!("return: {:?}", system_info)
            } else {
                eprintln!(
                    "NtQuerySystemInformation failed with status: 0x{:X}",
                    status
                );
            }
            assert_eq!(status, 0);
            assert!(system_info.NumberOfProcessors > 0);
        }
    }

    #[repr(C)]
    pub struct IO_STATUS_BLOCK {
        pub u: IO_STATUS_BLOCK_u,
        pub Information: usize,
    }

    #[repr(C)]
    pub union IO_STATUS_BLOCK_u {
        pub Status: NTSTATUS,
        pub Pointer: *mut core::ffi::c_void,
    }

    #[repr(C)]
    pub struct OBJECT_ATTRIBUTES {
        pub Length: u32,
        pub RootDirectory: *mut core::ffi::c_void,
        pub ObjectName: *mut UNICODE_STRING,
        pub Attributes: u32,
        pub SecurityDescriptor: *mut core::ffi::c_void,
        pub SecurityQualityOfService: *mut core::ffi::c_void,
    }

    pub const FILE_GENERIC_WRITE: u32 = 1_179_926u32;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
    pub const FILE_OVERWRITE_IF: u32 = 0x00000005;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
    pub const DELETE: u32 = 0x00010000;

    extern "system" {
        fn RtlInitUnicodeString(DestinationString: *mut UNICODE_STRING, SourceString: *const u16);
        fn NtClose(Handle: *mut core::ffi::c_void) -> NTSTATUS;
    }

    #[inline]
    pub unsafe fn InitializeObjectAttributes(
        p: *mut OBJECT_ATTRIBUTES,
        n: *mut UNICODE_STRING,
        a: u32,
        r: *mut core::ffi::c_void,
        s: *mut core::ffi::c_void,
    ) {
        (*p).Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        (*p).RootDirectory = r;
        (*p).Attributes = a;
        (*p).ObjectName = n;
        (*p).SecurityDescriptor = s;
        (*p).SecurityQualityOfService = core::ptr::null_mut();
    }
    #[test]
    fn test_nt_create_file() {
        syscall_imp!(NtCreateFile, (
        FileHandle: *mut *mut core::ffi::c_void,
        DesiredAccess: core::ffi::c_ulong,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        AllocationSize: *mut core::ffi::c_void,
        FileAttributes: core::ffi::c_ulong,
        ShareAccess: core::ffi::c_ulong,
        CreateDisposition: core::ffi::c_ulong,
        CreateOptions: core::ffi::c_ulong,
        EaBuffer: *mut core::ffi::c_void,
        EaLength: core::ffi::c_ulong));

        let mut handle = -1isize as *mut core::ffi::c_void;

        unsafe {
            let mut io_status = core::mem::zeroed::<IO_STATUS_BLOCK>();
            let mut oa = core::mem::zeroed::<OBJECT_ATTRIBUTES>();
            let path = "\\??\\E:\\vscodeprojects\\wsyscall-rs\\test.txt\0"
                .encode_utf16()
                .collect::<Vec<u16>>();
            let mut unicode_string = core::mem::zeroed::<UNICODE_STRING>();
            RtlInitUnicodeString(&mut unicode_string, path.as_ptr());

            InitializeObjectAttributes(
                &mut oa,
                &mut unicode_string,
                0x00000040,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );

            let ret: i32 = NtCreateFile(
                &mut handle,
                FILE_GENERIC_WRITE | DELETE,
                &mut oa,
                &mut io_status,
                core::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OVERWRITE_IF,
                FILE_DELETE_ON_CLOSE,
                core::ptr::null_mut(),
                0,
            );
            assert_eq!(ret, 0, "NtCreateFile failed with status: 0x{:X}", ret);
            assert_eq!(NtClose(handle), 0);
        }
    }
}
