#![no_std]
#![feature(str_from_raw_parts)]
include!(concat!(env!("OUT_DIR"), "/salt.rs"));

use once_cell::sync::Lazy;
use utils::cache::{DynamicCache, Ntdll};
extern crate alloc;

pub mod dynamic_invoke;
pub mod obf;
pub mod sus_functions;
pub mod syscall;
pub mod utils;

pub const NTDLL_HASH_LOWER: obf::Hash = hash!("ntdll.dll");
pub const NTDLL_HASH_UPPER: obf::Hash = hash!("NTDLL.DLL");

/// A hash for kernel32.dll, exactly how it appears in the InLoadOrderModuleList.
pub const KERNEL32_HASH: obf::Hash = hash!("KERNEL32.DLL");

/// A global cache for storing system calls from Ntdll and their corresponding SSNs.
pub static SSN_CACHE: Lazy<spin::Mutex<Ntdll>> = Lazy::new(|| spin::Mutex::new(Ntdll::new()));
/// A global cache for storing dynamically loaded functions.
pub static DYNAMIC_CACHE: Lazy<spin::Mutex<DynamicCache>> =
    Lazy::new(|| spin::Mutex::new(DynamicCache::new()));
