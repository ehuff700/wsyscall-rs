#![allow(non_snake_case, non_camel_case_types)]

#[allow(unused)]
macro_rules! direct_syscall {
    // Base case: no arguments (just SSN)
    ($ssn:expr) => {{
        let status: i32;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) $ssn,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:expr, $field1:expr) => {{
        let status: i32;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) $ssn,
            in("rcx") $field1,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:expr, $field1:expr, $field2:expr) => {{
        let status: i32;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) $ssn,
            in("rcx") $field1,
            in("rdx") $field2,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:expr, $field1:expr, $field2:expr, $field3:expr) => {{
        let status: i32;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) $ssn,
            in("rcx") $field1,
            in("rdx") $field2,
            in("r8") $field3,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
    ($ssn:expr, $field1:expr, $field2:expr, $field3:expr, $field4:expr) => {{
        let status: i32;
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            #[cfg(feature = "direct")]
            "syscall",
            in(reg) $ssn,
            in("rcx") $field1,
            in("rdx") $field2,
            in("r8") $field3,
            in("r9") $field4,
            lateout("rax") status,
            options(nostack)
        );
        status
    }};
}

#[macro_export]
macro_rules! syscall_imp {
    ($syscall:ident, ($($field_name:ident: $field_type:ty),*)) => {
        #[allow(non_snake_case)]
        pub unsafe fn $syscall($($field_name: $field_type),*) -> $crate::utils::wintypes::NTSTATUS {
            let ssn = {
                $crate::SSN_CACHE
                    .lock()
                    .get_or_insert($crate::NTDLL_NAME, stringify!($syscall))
            };
            direct_syscall!(ssn, $($field_name),*)
        }
    };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use core::ffi::{c_char, c_ulong};
    use std::{eprintln, println};

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
        syscall_imp!(NtQuerySystemInformation, (
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
}
