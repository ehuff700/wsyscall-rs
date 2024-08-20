#![no_std]
#![feature(str_from_raw_parts, stmt_expr_attributes)]

use lazy_static::lazy_static;
use spin::Mutex;
use utils::cache::ModuleCache;
extern crate alloc;
pub const NTDLL_NAME: &str = "ntdll.dll";

pub mod syscall;
pub mod utils;

lazy_static! {
    pub static ref SSN_CACHE: Mutex<ModuleCache> = Mutex::new(ModuleCache::new());
}
