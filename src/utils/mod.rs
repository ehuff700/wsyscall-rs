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
        let current_entry = unsafe { &*(current_module as *const LDR_DATA_TABLE_ENTRY) };

        let slice = unsafe {
            core::slice::from_raw_parts(
                current_entry.BaseDllName.Buffer,
                (current_entry.BaseDllName.Length as usize) / core::mem::size_of::<u16>(),
            )
        };
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

    let export_dir: *const IMAGE_EXPORT_DIRECTORY = module
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

/// # Safety
/// The safety of this function is not checked at runtime, and depends on the validity of the provided module handle. The passed in handle is assumed to be valid and non null for all reads performed by this function.
pub unsafe fn GetSsn(hmodule: HMODULE, fn_name: &str) -> Option<u32> {
    let addr = SusGetProcAddress(hmodule, fn_name);

    if let Some(addr) = addr {
        let addr: *const u8 = addr as *const u8;
        let ssn = *addr.add(4) as u32;
        return Some(ssn);
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
}
