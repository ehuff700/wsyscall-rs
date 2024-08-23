#![no_std]
#![feature(stmt_expr_attributes, str_from_raw_parts)]
include!(concat!(env!("OUT_DIR"), "/salt.rs"));

use once_cell::sync::Lazy;
use utils::cache::Ntdll;
extern crate alloc;

pub mod obf;
pub mod sus_functions;
pub mod syscall;
pub mod utils;

pub const NTDLL_HASH_LOWER: obf::Hash = hash!("ntdll.dll");
pub const NTDLL_HASH_UPPER: obf::Hash = hash!("NTDLL.DLL");

pub static SSN_CACHE: Lazy<spin::Mutex<Ntdll>> = Lazy::new(|| spin::Mutex::new(Ntdll::new()));
