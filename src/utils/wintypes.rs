#![allow(non_camel_case_types, non_snake_case, clippy::upper_case_acronyms)]

use core::{
    fmt::UpperHex,
    ops::{ControlFlow, FromResidual},
};

use alloc::{string::String, vec::Vec};

pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;
pub type HMODULE = *const core::ffi::c_void;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const STATUS_SUCCESS: NTSTATUS = NTSTATUS(0x00000000);

#[repr(C)]
#[derive(Debug)]
pub struct UNICODE_STRING {
    pub Length: core::ffi::c_ushort,
    pub MaximumLength: core::ffi::c_ushort,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct TEB {
    pub Reserved1: [*mut core::ffi::c_void; 12],
    pub ProcessEnvironmentBlock: *mut PEB,
    pub LastErrorValue: u32,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut core::ffi::c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut core::ffi::c_void,
    pub SubSystemData: *mut core::ffi::c_void,
    pub ProcessHeap: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: core::ffi::c_ulong,
    pub Initialized: u8,
    pub SsHandle: *mut core::ffi::c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *const core::ffi::c_void,
    pub EntryPoint: *const core::ffi::c_void,
    pub SizeOfImage: core::ffi::c_ulong,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: core::ffi::c_ulong,
    pub LoadCount: core::ffi::c_ushort,
    pub TlsIndex: core::ffi::c_ushort,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: core::ffi::c_ulong,
}

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[repr(C)]

pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct NTSTATUS(pub i32);
impl core::ops::Deref for NTSTATUS {
    type Target = i32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl UpperHex for NTSTATUS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl core::ops::Try for NTSTATUS {
    type Output = ();
    type Residual = NTERROR;

    fn from_output(_output: Self::Output) -> Self {
        NTSTATUS(0)
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        if self.0 == 0 {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(NTERROR(self.0))
        }
    }
}

impl<T, E> FromResidual<NTERROR> for Result<T, E>
where
    E: From<NTERROR>,
{
    fn from_residual(residual: NTERROR) -> Self {
        Err(E::from(residual))
    }
}

impl FromResidual<NTERROR> for NTSTATUS {
    fn from_residual(residual: NTERROR) -> Self {
        NTSTATUS(residual.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Helper struct for all NTSTATUS codes other than STATUS_SUCCESS.
pub struct NTERROR(pub i32);

#[derive(Debug, Clone)]
/// A container for a Windows Unicode string.
///
/// Windows strings are typically represented as Unicode strings.
pub struct WindowsString {
    pub(crate) bytes: Vec<u16>,
}

impl WindowsString {
    pub(crate) fn new(bytes: Vec<u16>) -> Self {
        WindowsString { bytes }
    }

    pub(crate) fn from_slice(bytes: &[u16]) -> Self {
        WindowsString::new(bytes.to_vec())
    }
    /// Creates a WindowsString from a UTF-8 encoded string.
    pub fn from_string(string: &str) -> Self {
        let bytes: Vec<u16> = string.encode_utf16().collect();
        Self::new(bytes)
    }
    /// Pushes a single u16 to the end of the buffer.
    pub fn push_u16(&mut self, b: u16) {
        self.bytes.push(b);
    }

    /// Pushes a string to the end of the buffer.
    pub fn push_str(&mut self, s: &str) {
        self.bytes.extend(s.encode_utf16());
    }

    /// Gets a reference to the underlying buffer contents.
    pub fn as_bytes(&self) -> &[u16] {
        &self.bytes
    }

    /// Returns a pointer to the buffers contents.
    pub fn as_ptr(&self) -> *const u16 {
        self.bytes.as_ptr()
    }

    /// Converts the WindowsString into a null-terminated UTF-16 string.
    pub fn into_nt_pointer(mut self) -> *const u16 {
        self.bytes.push(0); // null-terminate
        self.bytes.as_ptr()
    }
}

impl core::fmt::Display for WindowsString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let string = String::from_utf16_lossy(&self.bytes);
        write!(f, "{}", string)
    }
}

/// A Windows UTF-16 string.
///
/// This struct is a wrapper around a slice of u16 bytes. It is intended to be used for passing around Windows strings as function arguments.
///
/// You can create a WindowsStr from a static slice of u16 using the `from_utf16_lit` function, which is supported in const contexts.
pub struct WindowsStr<'a> {
    buffer: &'a [u16],
}

impl<'a> WindowsStr<'a> {
    /// Constructs a new windows string from a static slice of u16.
    pub const fn from_utf16_lit(buffer: &'static [u16]) -> Self {
        Self { buffer }
    }

    /// Returns a pointer to the underlying buffer contents.
    pub fn as_ptr(&self) -> *const u16 {
        self.buffer.as_ptr()
    }
}

impl core::fmt::Display for WindowsStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let string = String::from_utf16_lossy(self.buffer);
        write!(f, "{}", string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_error() -> Result<(), NTERROR> {
        let nt_error = NTSTATUS(0x000001);
        Ok(nt_error?)
    }

    fn test_ok() -> Result<(), NTERROR> {
        let nt_ok = STATUS_SUCCESS;
        Ok(nt_ok?)
    }

    #[test]
    fn test_nt_error() {
        assert_eq!(test_error(), Err(NTERROR(0x000001)));
        assert_eq!(test_ok(), Ok(()));
    }
}
