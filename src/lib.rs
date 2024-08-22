#![no_std]
#![feature(str_from_raw_parts, stmt_expr_attributes, const_trait_impl)]
include!(concat!(env!("OUT_DIR"), "/salt.rs"));

#[macro_use]
extern crate lazy_static;

use obf::Hash;
use spin::Mutex;
use utils::cache::Ntdll;
extern crate alloc;
pub const NTDLL_HASH: Hash = hash!("ntdll.dll");

pub mod obf;
pub mod syscall;
pub mod utils;

lazy_static! {
    pub static ref SSN_CACHE: Mutex<Ntdll> = Mutex::new(Ntdll::new());
}
