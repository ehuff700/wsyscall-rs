use alloc::collections::btree_map::BTreeMap;

use crate::{obf::Hash, utils::SusGetModuleHandle, NTDLL_HASH};

use super::{GetSsn, Syscall};

struct PtrWrapper(*const core::ffi::c_void);
unsafe impl Sync for PtrWrapper {}
unsafe impl Send for PtrWrapper {}
impl core::ops::Deref for PtrWrapper {
    type Target = *const core::ffi::c_void;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Ntdll {
    handle: PtrWrapper,
    ssn_cache: BTreeMap<Hash, Syscall>,
}

impl Ntdll {
    pub fn new() -> Self {
        let handle = SusGetModuleHandle(NTDLL_HASH).expect("failed to get NTDLL handle");
        Ntdll {
            handle: PtrWrapper(handle),
            ssn_cache: BTreeMap::new(),
        }
    }

    pub fn get_ssn_for_hash(&mut self, fn_hash: Hash) -> Syscall {
        match self.ssn_cache.get_mut(&fn_hash) {
            Some(ssn) => *ssn,
            None => {
                // TODO: fix GetSsn
                let ssn = unsafe { GetSsn(*self.handle, fn_hash).expect("failed to get SSN") };
                self.ssn_cache.insert(fn_hash, ssn);
                ssn
            }
        }
    }
}

impl Default for Ntdll {
    fn default() -> Self {
        Self::new()
    }
}
