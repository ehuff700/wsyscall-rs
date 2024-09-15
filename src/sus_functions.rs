#![allow(non_snake_case)]
use alloc::vec::Vec;
use core::arch::asm;

#[cfg(target_arch = "x86")]
use crate::utils::wintypes::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use crate::utils::wintypes::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

use crate::utils::wintypes::{
    FARPROC, HMODULE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
    LDR_DATA_TABLE_ENTRY, PEB, TEB,
};

use crate::wintypes::WindowsString;
use crate::{
    obf::{hash_with_salt_u16, hash_with_salt_u8, Hash},
    syscall::Syscall,
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
#[inline]
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

/// Retrieves the current thread environment block (TEB) pointer.
#[inline]
pub fn NtCurrentTeb() -> *mut TEB {
    let mut teb: *mut TEB;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("mov {0}, gs:[0x30]", out(reg) teb);
        #[cfg(target_arch = "x86")]
        asm!("mov {0:e}, fs:[0x18]", out(reg) teb);
    }

    teb
}

/// Retrieves the value of the environment variable with the specified key.
///
/// # Note:
/// This function **is case sensitive**.
pub fn SusGetEnvironmentVariable(key: &str) -> Option<WindowsString> {
    let key_bytes = key.encode_utf16().collect::<Vec<u16>>();
    let peb = NtCurrentPeb();
    let rtl_process_parameters = unsafe { (*peb).ProcessParameters };
    // 0x80 is the offset to the ProcessParameters field in the PEB on x64

    let (environment_block_offset, environment_size_offset) = {
        #[cfg(target_arch = "x86_64")]
        {
            (0x80, 0x03F0)
        }
        #[cfg(target_arch = "x86")]
        {
            (0x48, 0x0290)
        }
    };

    // Environment block is a pointer to a Unicode string that contains the environment variables.
    let environment_block =
        unsafe { *(rtl_process_parameters.add(environment_block_offset) as *const *const u16) };
    // Environment size is a pointer to the size of the environment block in bytes.
    let environment_size =
        unsafe { *(rtl_process_parameters.add(environment_size_offset) as *const usize) };

    if environment_block.is_null() || environment_size == 0 {
        return None;
    }

    let environment_slice = unsafe {
        core::slice::from_raw_parts(
            environment_block,
            environment_size / core::mem::size_of::<u16>(),
        )
    };

    let environment_block_str = WindowsString::new(environment_slice);
    for key_value in environment_block_str.bytes.split(|c| *c == 0) {
        if let Some((curr_key, value)) = key_value.split_once(|c| *c == '=' as u16) {
            if curr_key.eq(&key_bytes) {
                return Some(WindowsString::new(value));
            }
        } else {
            continue;
        }
    }
    None
}
/// Retrieves the module handle for the provided module hash.
///
/// This function is semantically equivalent to `GetModuleHandleA/W` from winapi (with minor changes, see `Remarks`), but implemented manually to avoid the function call.
///
/// # Remarks
/// This function is **case sensitive** to what the module appears like in the `InLoadOrderModuleList`.
pub fn SusGetModuleHandle(module_hash: Hash) -> Option<HMODULE> {
    let peb = NtCurrentPeb();
    let ldr = unsafe { (*peb).Ldr };

    let mut current_module = unsafe { (*ldr).InLoadOrderModuleList.Flink };
    let last_module = unsafe { (*ldr).InLoadOrderModuleList.Blink };

    loop {
        let current_entry = unsafe { &*(current_module.cast::<LDR_DATA_TABLE_ENTRY>()) };
        let slice = unsafe {
            core::slice::from_raw_parts(
                current_entry.BaseDllName.Buffer,
                (current_entry.BaseDllName.Length as usize) / core::mem::size_of::<u16>(),
            )
        };
        if hash_with_salt_u16(slice) == *module_hash {
            return Some(current_entry.DllBase);
        }
        if current_module == last_module {
            break;
        }
        current_module = unsafe { (*current_module).Flink }
    }
    None
}

/// Retrieves the address of a function within a given module.
///
/// # Safety
/// The safety of this function is not checked at runtime, and depends on the validity of the provided module handle. The passed in handle is assumed to be valid and non null for all reads performed by this function.
pub unsafe fn SusGetProcAddress(module: HMODULE, fn_name: Hash) -> FARPROC {
    let dos_header = &*(module.cast::<IMAGE_DOS_HEADER>());
    let nt_header = module
        .add(dos_header.e_lfanew as usize)
        .cast::<IMAGE_NT_HEADERS>();
    // Retrieve the IMAGE_EXPORT_DIRECTORY from the module.
    let export_data_dir = &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if export_data_dir.Size == 0 || export_data_dir.VirtualAddress == 0 {
        return None;
    }
    let export_dir = &*(module
        .add(export_data_dir.VirtualAddress as usize)
        .cast::<IMAGE_EXPORT_DIRECTORY>());

    let number_of_names = export_dir.NumberOfNames as usize;

    // Retrieve the base address for the function RVAs, function names, and ordinal numbers.
    let rva_base = module
        .add(export_dir.AddressOfFunctions as usize)
        .cast::<u32>();
    let name_base = module.add(export_dir.AddressOfNames as usize).cast::<u32>();
    let ordinals_base = module
        .add(export_dir.AddressOfNameOrdinals as usize)
        .cast::<u16>();

    for i in 0..number_of_names {
        // Construct a hash of the current function name.
        let name_ptr = module.add(*name_base.add(i) as usize).cast::<u8>();
        let name_bytes = core::slice::from_raw_parts(name_ptr, strlen(name_ptr));

        let hash = hash_with_salt_u8(name_bytes);

        if *fn_name == hash {
            // Use the ordinal number to get the function address by adding the rva to the module base.
            let ordinal = *ordinals_base.add(i) as usize;
            let function_ptr: FARPROC =
                core::mem::transmute(module.add(*rva_base.add(ordinal) as usize));
            return function_ptr;
        }
    }
    None
}

/// Retrieves the system service number (SSN) of a given function within a given module.
///
/// # Safety
/// The safety of this function is not checked at runtime, and depends on the validity of the provided module handle. The passed in handle is assumed to be valid and non null for all reads performed by this function.
pub(crate) unsafe fn GetSsn(hmodule: HMODULE, fn_name: Hash) -> Option<Syscall> {
    // mov r10, rcx
    const SYSCALL_START: (u8, u8, u8) = (0x4C, 0x8B, 0xD1);
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
    extern crate std;
    use crate::hash;

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
    fn test_module_and_proc_address() {
        let sus_ntdll = SusGetModuleHandle(hash!("ntdll.dll"));
        let sus_kernel32 = SusGetModuleHandle(hash!("KERNEL32.DLL"));
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
                core::mem::transmute(SusGetProcAddress(basic_kernel32, hash!("GetProcAddress")));

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
        let sus_ntdll = SusGetModuleHandle(hash!("ntdll.dll"));
        assert_ne!(sus_ntdll, None);
        let sus_ntdll = sus_ntdll.unwrap();
        let ssn = unsafe { GetSsn(sus_ntdll, hash!("NtQuerySystemInformation")) }.unwrap();
        assert_eq!(ssn.ssn, 54);
    }

    #[test]
    fn test_get_environment_variable() {
        let print = SusGetEnvironmentVariable("USERPROFILE");
        assert!(print.is_some());
        let print = print.unwrap();
        assert!(print
            .bytes
            .starts_with(&"C:\\Users".encode_utf16().collect::<Vec<u16>>()));
        std::println!("{}", print);

        let test = SusGetEnvironmentVariable("localappdata");
        assert!(test.is_none());
    }

    #[test]
    fn test_nt_current_teb() {
        dynamic_invoke_imp!("KERNEL32.DLL", SetLastError, (dwerrorcode: u32));
        unsafe { SetLastError(1337) };
        let teb = NtCurrentTeb();
        assert!(!teb.is_null());

        let test = unsafe { &*teb }.ProcessEnvironmentBlock;
        assert_eq!(NtCurrentPeb(), test);

        let last_error = unsafe { &*teb }.LastErrorValue;
        assert_eq!(1337, last_error)
    }

    #[test]
    fn test_gdi32_load() {
        dynamic_invoke_imp!("KERNEL32.DLL", LoadLibraryA, (lplibname: *const u8) -> *mut core::ffi::c_void);
        unsafe { LoadLibraryA(c"user32.dll".as_ptr() as _) };
        let user32 = SusGetModuleHandle(hash!("user32.dll"));
        assert_ne!(user32, None);
        let create_compatible_dc =
            unsafe { SusGetProcAddress(user32.unwrap(), hash!("ReleaseDC")) };
        assert_ne!(create_compatible_dc, None);
    }
}
