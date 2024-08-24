#![no_std]
#![feature(str_from_raw_parts)]
//! # wsyscall_rs
//!
//! `wsyscall_rs` is a Rust library designed to facilitate dynamic invocation, or indirect/direct invocation of Windows system calls.
//!
//! ## Features
//!
//! - **Dynamic Invocation of System Calls:** The `dynamic_invoke_imp` macro allows you to dynamically invoke Windows API functions from loaded modules such as `KERNEL32.DLL`, without needing to statically link against these functions.
//! - **Custom System Call Wrappers:** The `syscall_imp` macro creates a wrapper over an Nt system call using native system call numbers and raw assembly. It supports direct and indirect syscalls with the corresponding feature (direct is default)
//!
//! ## Usage
//!
//! For more usage information, please see the documentation for the macros mentioned above.
//!
//! ## Safety and Best Practices
//!
//! The macros provided by `wsyscall_rs` generate `unsafe` functions due to the nature of system calls. These operations can directly interact with the operating system, which can cause undefined behavior or system instability if used incorrectly. Therefore, it is crucial to:
//! - Validate all inputs and outputs.
//! - Ensure that you have a thorough understanding of the Windows API and system call interfaces you are invoking.
//! - Test thoroughly, especially when dealing with different versions of Windows.
//!
//! ## License
//! This project is licensed under either of
//! * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
//! * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
//!
//! at your option.
include!(concat!(env!("OUT_DIR"), "/salt.rs"));

use once_cell::sync::Lazy;
use utils::cache::{DynamicCache, Ntdll};
extern crate alloc;

#[macro_use]
mod dynamic_invoke;
pub mod obf;
mod sus_functions;
pub use sus_functions::*;
pub mod syscall;
mod utils;
pub use utils::*;

pub const NTDLL_HASH_LOWER: obf::Hash = hash!("ntdll.dll");
pub const NTDLL_HASH_UPPER: obf::Hash = hash!("NTDLL.DLL");

/// A hash for kernel32.dll, exactly how it appears in the InLoadOrderModuleList.
pub const KERNEL32_HASH: obf::Hash = hash!("KERNEL32.DLL");

/// A global cache for storing system calls from Ntdll and their corresponding SSNs.
pub static SSN_CACHE: Lazy<spin::Mutex<Ntdll>> = Lazy::new(|| spin::Mutex::new(Ntdll::new()));
/// A global cache for storing dynamically loaded functions.
pub static DYNAMIC_CACHE: Lazy<spin::Mutex<DynamicCache>> =
    Lazy::new(|| spin::Mutex::new(DynamicCache::new()));

#[cfg(all(feature = "indirect", feature = "direct"))]
compile_error!("indirect and direct syscalls cannot be enabled at the same time. Please enable only one of them.");
