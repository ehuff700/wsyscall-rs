#![allow(non_snake_case, non_camel_case_types)]

#[cfg(feature = "indirect")]
use crate::utils::cache::PtrWrapper;

/// 32 bytes of "shadow stack space" per MSDN docs. The 8 bytes for the return address are added manually for direct syscalls.
pub const BASE_STACK_ALLOC: usize = 32;

#[derive(Clone, Copy)]
/// A structure representing a syscall.
///
/// It contains the system service number, and optionally the address of the appropriate syscall instruction for indirect syscalls.
pub struct Syscall {
    pub ssn: u32,
    #[cfg(feature = "indirect")]
    pub syscall_address: PtrWrapper,
}

impl Syscall {
    pub fn new(ssn: u32, #[cfg(feature = "indirect")] syscall_address: *const u8) -> Self {
        Self {
            ssn,
            #[cfg(feature = "indirect")]
            syscall_address: PtrWrapper(syscall_address as *const core::ffi::c_void),
        }
    }
}

#[macro_export]
#[cfg(feature = "direct")]
/// Emits the actual assembly for the system call using the provided SSN and arguments. See `Remarks` for more information.
///
/// # Note:
/// This macro should not be invoked directly. Instead, use the `syscall_impl!` macro to generate the wrapper function instead.
///
/// ## Remarks:
/// For cases of the direct syscall, the generated assembly will generate an actual "syscall" instruction.
///
/// For indirect syscalls, it will jump to the syscall address stored in the [Syscall] struct with a "call" instruction.
///
/// The first four arguments are passed directly to registers r10, rdx, r8, and r9 according to MSDN docs,
/// the rcx and r11 registers are preserved, and the ssn (and eventually the returned status) is passed in the rax register.
///
/// For functions with more than four arguments, the remaining arguments are pushed onto the stack in reverse order, and the stack pointer is adjusted appropriately.
macro_rules! syscall {
    // Base case: no arguments (just SSN)
    ($ssn:ident) => {{
        let status: i32;
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "syscall",
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr) => {{
        let status: i32;
        let ssn = $ssn.ssn;

        core::arch::asm!(
            "syscall",
            inout("r10") $field1 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr) => {{
        let status: i32;
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "syscall",
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr) => {{
        let status: i32;
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "syscall",
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr) => {{
        let status: i32;
        let ssn = $ssn.ssn;
        core::arch::asm!(
            "syscall",
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            inout("r9") $field4 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr, $($extra_fields:expr),+) => {{
        let status: i32;
        let ssn = $ssn.ssn;
        // Reverse the order of extra fields and push them onto the stack
        syscall!(@reverse_and_push $($extra_fields),+);

        core::arch::asm!(
            "sub rsp, {stack_alloc}",
            "syscall",
            "add rsp, {stack_dealloc}",
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            inout("r9") $field4 => _,
            inlateout("rax") ssn => status,
            out("rcx") _,
            out("r11") _,
            stack_alloc = const $crate::syscall::BASE_STACK_ALLOC + 8, // +8 for the ret address
            stack_dealloc = const $crate::syscall::BASE_STACK_ALLOC + 8 + (8 * syscall!(@count_fields $($extra_fields),+)),
            options(preserves_flags),
        );
        status
    }};
    (@reverse_and_push $last:expr) => {
        core::arch::asm!(
            "push {0:r}",
            in(reg) $last,
        );
    };
    (@reverse_and_push $first:expr, $($rest:expr),+) => {
        syscall!(@reverse_and_push $($rest),+); // Recurse with the rest of the fields
        core::arch::asm!(
            "push {0:r}",
            in(reg) $first,
        );
    };

    (@count_fields) => (0);
    (@count_fields $field:expr) => (1);
    (@count_fields $field:expr, $($rest:expr),+) => (1 + syscall!(@count_fields $($rest),+));
}

#[macro_export]
#[cfg(feature = "indirect")]
/// Emits the actual assembly for the system call using the provided SSN and arguments. See `Remarks` for more information.
///
/// # Note:
/// This macro should not be invoked directly. Instead, use the `syscall_impl!` macro to generate the wrapper function instead.
///
/// ## Remarks:
/// For cases of the direct syscall, the generated assembly will generate an actual "syscall" instruction.
///
/// For indirect syscalls, it will jump to the syscall address stored in the [Syscall] struct with a "call" instruction.
///
/// The first four arguments are passed directly to registers r10, rdx, r8, and r9 according to MSDN docs,
/// the rcx and r11 registers are preserved, and the ssn (and eventually the returned status) is passed in the rax register.
///
/// For functions with more than four arguments, the remaining arguments are pushed onto the stack in reverse order, and the stack pointer is adjusted appropriately.
macro_rules! syscall {
    // Base case: no arguments (just SSN)
    ($ssn:ident) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);
        core::arch::asm!(
            "call {}",
            in(reg) syscall_address,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);
        core::arch::asm!(
            "call {}",
            in(reg) syscall_address,
            inout("r10") $field1 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);
        core::arch::asm!(
            "call {}",
            in(reg) syscall_address,
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);

        core::arch::asm!(
            "call {}",
            in(reg) syscall_address,
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);
        core::arch::asm!(
            "call {}",
            in(reg) syscall_address,
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            inout("r9") $field4 => _,
            out("rcx") _,
            out("r11") _,
            inlateout("rax") ssn => status,
            options(nostack, preserves_flags)
        );
        status
    }};
    ($ssn:ident, $field1:expr, $field2:expr, $field3:expr, $field4:expr, $($extra_fields:expr),+) => {{
        let status: i32;
        let (ssn, syscall_address) = ($ssn.ssn, *$ssn.syscall_address);
        // Reverse the order of extra fields and push them onto the stack
        syscall!(@reverse_and_push $($extra_fields),+);

        core::arch::asm!(
            "sub rsp, {stack_alloc}",
            "call {}",
            "add rsp, {stack_dealloc}",
            in(reg) syscall_address,
            inout("r10") $field1 => _,
            inout("rdx") $field2 => _,
            inout("r8") $field3 => _,
            inout("r9") $field4 => _,
            inlateout("rax") ssn => status,
            out("rcx") _,
            out("r11") _,
            stack_alloc = const $crate::syscall::BASE_STACK_ALLOC, // no need to add +8, as call pushes the ret address to the stack
            stack_dealloc = const $crate::syscall::BASE_STACK_ALLOC + (8 * syscall!(@count_fields $($extra_fields),+)),
            options(preserves_flags),
        );
        status
    }};
    (@reverse_and_push $last:expr) => {
        core::arch::asm!(
            "push {0:r}",
            in(reg) $last,
        );
    };
    (@reverse_and_push $first:expr, $($rest:expr),+) => {
        syscall!(@reverse_and_push $($rest),+); // Recurse with the rest of the fields
        core::arch::asm!(
            "push {0:r}",
            in(reg) $first,
        );
    };

    (@count_fields) => (0);
    (@count_fields $field:expr) => (1);
    (@count_fields $field:expr, $($rest:expr),+) => (1 + syscall!(@count_fields $($rest),+));
}

#[macro_export]
/// This macro is what you use to define a new system call.
///
/// The first argument is the name of the system call, and the second argument is a tuple containing the field names and their types.
///
/// ```rust
///    use wsyscall_rs::syscall_imp;
///     
///    // Defines a new system call named NtQuerySystemInformation, with four arguments as shown.
///    syscall_imp!(NtQuerySystemInformation, (
///            SystemInformationClass: u32,
///            SystemInformation: *mut core::ffi::c_void,
///            SystemInformationLength: u32,
///            ReturnLength: *mut u32
///        ));
///   
///   #[allow(non_upper_case_globals)]
///   const SystemBasicInformation: u32 = 0; // Corresponds to the SYSTEM_INFORMATION_CLASS enum.
///   
///   fn test_nt_query_system_information() {
///     const SYSTEM_BASIC_INFORMATION_SIZE: usize = 64usize;
///     let mut system_info = [0u8; SYSTEM_BASIC_INFORMATION_SIZE]; // size of SYSTEM_BASIC_INFORMATION structure.
///       unsafe {
///           let status = NtQuerySystemInformation(
///               SystemBasicInformation,
///               &mut system_info as *mut _ as *mut _,
///               SYSTEM_BASIC_INFORMATION_SIZE as u32,
///               core::ptr::null_mut(),
///           );
///           assert_eq!(status, 0);
///           // offset of NumberOfProcessors field in the SYSTEM_BASIC_INFORMATION structure.
///           let NumberOfProcessors = unsafe { *(system_info.as_ptr().add(0x38) as *const i8) };
///           let Reserved = unsafe { *(system_info.as_ptr() as *const u32) };
///           assert!(NumberOfProcessors > 0);
///           assert_eq!(Reserved, 0);
///       }
///    }
///
/// ```
macro_rules! syscall_imp {
    ($syscall:ident, ($($field_name:ident: $field_type:ty),*)) => {
        #[allow(non_snake_case, clippy::too_many_arguments)]
        pub unsafe extern "system" fn $syscall($($field_name: $field_type),*) -> $crate::wintypes::NTSTATUS {
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
            assert_eq!(system_info.Reserved, 0);
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

        syscall_imp!(NtClose, (Handle: *mut core::ffi::c_void));

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
