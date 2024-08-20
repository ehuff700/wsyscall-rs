#![allow(non_snake_case)]
pub(crate) mod cache;
pub mod wintypes;
use core::arch::asm;

use alloc::string::String;
#[cfg(target_arch = "x86")]
use wintypes::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use wintypes::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

use wintypes::{
    FARPROC, HMODULE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
    LDR_DATA_TABLE_ENTRY, PEB,
};

#[derive(Clone, Copy)]
pub struct Syscall {
    pub ssn: u32,
    #[cfg(feature = "indirect")]
    pub syscall_address: *const u8,
}

impl Syscall {
    pub fn new(ssn: u32, #[cfg(feature = "indirect")] syscall_address: *const u8) -> Self {
        Self {
            ssn,
            #[cfg(feature = "indirect")]
            syscall_address,
        }
    }
}

#[inline]
fn strlen(s: *const u8) -> usize {
    unsafe {
        let mut i: usize = 0;
        if !s.is_null() {
            while *s.add(i) != 0 {
                i += 1;
            }
        }
        i
    }
}
/// Retrieves the current process environment block (PEB) pointer.
pub fn NtCurrentPeb() -> *mut PEB {
    let mut peb: *mut PEB;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("mov {0}, gs:[0x60]", out(reg) peb);

        #[cfg(target_arch = "x86")]
        asm!("mov {0:e}, fs:[0x30]", out(reg) peb);
    }
    peb
}

pub fn SusGetModuleHandle(module: &str) -> Option<HMODULE> {
    let peb = NtCurrentPeb();
    let ldr = unsafe { (*peb).Ldr };

    let mut current_module = unsafe { (*ldr).InLoadOrderModuleList.Flink };
    let last_module = unsafe { (*ldr).InLoadOrderModuleList.Blink };

    while current_module != last_module {
        let current_entry = unsafe { &*(current_module.cast::<LDR_DATA_TABLE_ENTRY>()) };

        let slice = unsafe {
            core::slice::from_raw_parts(
                current_entry.BaseDllName.Buffer,
                (current_entry.BaseDllName.Length as usize) / core::mem::size_of::<u16>(),
            )
        };
        // TODO: make this better by making a direct byte comparison.
        let module_name = String::from_utf16_lossy(slice);
        if module_name.eq_ignore_ascii_case(module) {
            return Some(current_entry.DllBase);
        }
        current_module = unsafe { (*current_module).Flink }
    }
    None
}
/// Retrieves the address of a function within a given module.
///
/// # Safety
/// The safety of this function is not checked at runtime, and depends on the validity of the provided module handle. The passed in handle is assumed to be valid and non null for all reads performed by this function.
pub unsafe fn SusGetProcAddress(module: HMODULE, fn_name: &str) -> FARPROC {
    let dos_header = &*(module.cast::<IMAGE_DOS_HEADER>());
    let nt_header = module
        .add(dos_header.e_lfanew as usize)
        .cast::<IMAGE_NT_HEADERS>();
    let export_data_dir = &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if export_data_dir.Size == 0 || export_data_dir.VirtualAddress == 0 {
        return None;
    }

    let export_dir = module
        .add(export_data_dir.VirtualAddress as usize)
        .cast::<IMAGE_EXPORT_DIRECTORY>();

    let number_of_names = (*export_dir).NumberOfNames as usize;
    let rvas = core::slice::from_raw_parts(
        module
            .add((*export_dir).AddressOfFunctions as _)
            .cast::<u32>(),
        number_of_names,
    );
    let names = core::slice::from_raw_parts(
        module.add((*export_dir).AddressOfNames as _).cast::<u32>(),
        number_of_names,
    );

    let ordinals = core::slice::from_raw_parts(
        module
            .add((*export_dir).AddressOfNameOrdinals as _)
            .cast::<u16>(),
        number_of_names,
    );

    for i in 0..number_of_names {
        let name_ptr = module.add(names[i] as usize).cast::<u8>();
        let len = strlen(name_ptr);
        let name = core::str::from_raw_parts(name_ptr, len);

        if name.eq_ignore_ascii_case(fn_name) {
            let ordinal = ordinals[i] as usize;
            let function_ptr: FARPROC = core::mem::transmute(module.add(rvas[ordinal] as usize));
            return function_ptr;
        }
    }
    None
}

// mov r10, rcx
const SYSCALL_START: (u8, u8, u8) = (0x4C, 0x8B, 0xD1);

/// Retrieves the system service number (SSN) of a given function within a given module.
///
/// # Safety
/// The safety of this function is not checked at runtime, and depends on the validity of the provided module handle. The passed in handle is assumed to be valid and non null for all reads performed by this function.
pub(crate) unsafe fn GetSsn(hmodule: HMODULE, fn_name: &str) -> Option<Syscall> {
    let addr = SusGetProcAddress(hmodule, fn_name);

    /// Given a function's address, make sure that it is valid (no hooks or other shenanigans).
    #[inline(always)]
    fn is_valid_stub(addr: *const u8) -> bool {
        let stub_bytes = unsafe { core::slice::from_raw_parts(addr, 20) };
        // mov r10, rcx & mov eax, empty bytes after SSN, and syscall instruction.
        stub_bytes.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8])
            && stub_bytes[6..8] == [0x00, 0x00]
            && stub_bytes[18..20] == [0x0F, 0x05]
    }

    #[inline(always)]
    /// Determines whether or not a function is hooked.
    ///
    /// TODO: handle false positives
    fn is_hooked(addr: *const u8) -> bool {
        unsafe {
            let slice = core::slice::from_raw_parts(addr, 4);
            slice != [0x4C, 0x8B, 0xD1, 0xB8]
        }
    }

    /// Retrieves the system service number (SSN) of a given function within a given module.
    ///
    /// If the function is hooked, this function attempts to trace forwards and backwards to find the ssn (modified Halo's gate).
    fn retrieve_ssn(addr: *const u8) -> u32 {
        // 1600 bytes = ~50 functions
        if is_hooked(addr) {
            // backwards loop
            let mut backwards_sys_counter = 0;
            for i in 1..1600 {
                let byte3 = unsafe { addr.sub(i) };
                let byte2 = unsafe { addr.sub(i + 1) };
                let byte1 = unsafe { addr.sub(i + 2) };
                if unsafe { (*byte1, *byte2, *byte3) } == SYSCALL_START {
                    backwards_sys_counter += 1;
                    if is_valid_stub(byte1) {
                        return unsafe { *byte1.add(4) as u32 + backwards_sys_counter as u32 };
                    }
                }
            }
            // forwards loop
            let mut forward_sys_counter = 0;
            for i in 1..1600 {
                let byte1 = unsafe { addr.add(i) };
                let byte2 = unsafe { addr.add(i + 1) };
                let byte3 = unsafe { addr.add(i + 2) };
                if unsafe { (*byte1, *byte2, *byte3) } == SYSCALL_START {
                    forward_sys_counter += 1;
                    if is_valid_stub(byte1) {
                        return unsafe { *byte1.add(4) as u32 - forward_sys_counter as u32 };
                    }
                }
            }
        }
        unsafe { *addr.add(4) as u32 }
    }

    #[cfg(feature = "indirect")]
    unsafe fn syscall_address(addr: *const u8) -> *const u8 {
        // this should always be safe to unwrap because we can assume that the syscall instruction will be somewhere in the stub.
        (1..)
            .find_map(|counter| {
                let test_byte = *addr.wrapping_add(counter);
                if test_byte == 0xc3 {
                    None
                } else if test_byte == 0x0F && *addr.wrapping_add(counter + 1) == 0x05 {
                    Some(addr.wrapping_add(counter))
                } else {
                    None
                }
            })
            .unwrap()
    }

    if let Some(addr) = addr {
        let addr: *const u8 = addr as *const u8;
        #[cfg(feature = "indirect")]
        let syscall_addr = syscall_address(addr);

        let ssn = retrieve_ssn(addr);
        return Some(Syscall::new(
            ssn,
            #[cfg(feature = "indirect")]
            syscall_addr,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" {
        fn GetProcAddress(
            hmodule: *mut core::ffi::c_void,
            lpname: *const u8,
        ) -> *mut core::ffi::c_void;
    }
    extern "C" {
        fn GetModuleHandleA(lpModuleName: *const u8) -> *mut core::ffi::c_void;
    }

    #[allow(non_camel_case_types)]
    type GetProcAddress_t = unsafe extern "C" fn(
        hmodule: *mut core::ffi::c_void,
        lpname: *const u8,
    ) -> *mut core::ffi::c_void;

    #[test]
    fn test_sus_functions() {
        let sus_ntdll = SusGetModuleHandle("ntdll.dll");
        let sus_kernel32 = SusGetModuleHandle("kernel32.dll");
        assert_ne!(sus_ntdll, None);
        assert_ne!(sus_kernel32, None);

        let (sus_ntdll, sus_kernel32) = (sus_ntdll.unwrap(), sus_kernel32.unwrap());

        let basic_ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr() as _) };
        let basic_kernel32 = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr() as _) };
        assert_eq!(sus_ntdll, basic_ntdll);
        assert_eq!(sus_kernel32, basic_kernel32);

        unsafe {
            let test_address_basic =
                GetProcAddress(basic_kernel32, c"GetProcAddress".as_ptr() as _);
            let test_address_sus: *mut core::ffi::c_void =
                core::mem::transmute(SusGetProcAddress(basic_kernel32, "GetProcAddress"));

            assert_eq!(test_address_basic, test_address_sus);
            let test_fn: GetProcAddress_t = core::mem::transmute(test_address_sus);
            assert_eq!(
                test_fn(basic_kernel32, c"GetProcAddress".as_ptr() as _),
                test_address_sus
            )
        }
    }

    #[test]
    fn test_get_ssn() {
        let sus_ntdll = SusGetModuleHandle("ntdll.dll");
        assert_ne!(sus_ntdll, None);
        let sus_ntdll = sus_ntdll.unwrap();
        let ssn = unsafe { GetSsn(sus_ntdll, "NtQuerySystemInformation") }.unwrap();
        assert_eq!(ssn.ssn, 54);
    }
}
