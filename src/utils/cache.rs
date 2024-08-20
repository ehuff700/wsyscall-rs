use alloc::{boxed::Box, collections::btree_map::BTreeMap};

use crate::utils::SusGetModuleHandle;

use super::{GetSsn, Syscall};

pub struct PtrWrapper(*const core::ffi::c_void);
unsafe impl Sync for PtrWrapper {}
unsafe impl Send for PtrWrapper {}
impl core::ops::Deref for PtrWrapper {
    type Target = *const core::ffi::c_void;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ModuleCache {
    map: BTreeMap<Box<str>, (PtrWrapper, SsnCache)>,
}

impl ModuleCache {
    pub fn new() -> Self {
        ModuleCache {
            map: BTreeMap::new(),
        }
    }

    /// Gets a SSN for the given module name and fn name, or calculates it + inserts it into the cache if it doesn't exist.
    pub fn get_or_insert(&mut self, module_name: &str, fn_name: &str) -> Syscall {
        match self.map.get_mut(module_name) {
            Some((hmodule, cache_for_module)) => cache_for_module.get_or_insert(**hmodule, fn_name),
            None => {
                //TODO: fix unwrap
                let handle = SusGetModuleHandle(module_name).unwrap();
                let mut cache_for_module = SsnCache::new();
                let ssn = cache_for_module.get_or_insert(handle, fn_name);
                self.map
                    .insert(module_name.into(), (PtrWrapper(handle), cache_for_module));
                ssn
            }
        }
    }
}

/// A simple key value cache for storing SSN values.
pub struct SsnCache {
    map: BTreeMap<Box<str>, Syscall>,
}

impl SsnCache {
    pub fn new() -> Self {
        SsnCache {
            map: BTreeMap::new(),
        }
    }

    /// Gets a SSN for the given hmodule and fn_name, or calculates it + inserts it into the cache if it doesn't exist.
    pub fn get_or_insert(&mut self, hmodule: *const core::ffi::c_void, fn_name: &str) -> Syscall {
        match self.map.get(fn_name) {
            Some(ssn) => *ssn,
            None => {
                let ssn = unsafe { GetSsn(hmodule, fn_name) }.unwrap();
                self.map.insert(fn_name.into(), ssn);
                ssn
            }
        }
    }
}

impl Default for SsnCache {
    fn default() -> Self {
        SsnCache::new()
    }
}

impl Default for ModuleCache {
    fn default() -> Self {
        ModuleCache::new()
    }
}
