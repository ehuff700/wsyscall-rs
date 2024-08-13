#![no_std]
#![feature(str_from_raw_parts)]

use lazy_static::lazy_static;
use spin::Mutex;
use utils::cache::ModuleCache;
extern crate alloc;

#[cfg(feature = "direct")]
pub mod direct;
#[cfg(feature = "indirect")]
mod indirect;
pub mod utils;

lazy_static! {
    pub static ref SSN_CACHE: Mutex<ModuleCache> = Mutex::new(ModuleCache::new());
}
