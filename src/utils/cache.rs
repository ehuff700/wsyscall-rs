use alloc::collections::btree_map::BTreeMap;

use crate::{obf::Hash, utils::SusGetModuleHandle, NTDLL_HASH_LOWER, NTDLL_HASH_UPPER};

use super::{GetSsn, Syscall};

/// Custom struct to wrap a pointer to ensure Sync + Send, since we don't modify these pointers directly.
struct PtrWrapper(*const core::ffi::c_void);
unsafe impl Sync for PtrWrapper {}
unsafe impl Send for PtrWrapper {}
impl core::ops::Deref for PtrWrapper {
    type Target = *const core::ffi::c_void;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A wrapper struct over a handle to `ntdll.dll`.
///
/// A SSN cache is maintained, where the key is a function hash and the value is the syscall number and optionally a syscall address for indirect syscalls.
pub struct Ntdll {
    handle: PtrWrapper,
    ssn_cache: BTreeMap<Hash, Syscall>,
}

impl Ntdll {
    /// Creates a new Ntdll struct.
    pub fn new() -> Self {
        let handle = SusGetModuleHandle(NTDLL_HASH_LOWER).unwrap_or_else(|| {
            SusGetModuleHandle(NTDLL_HASH_UPPER).expect("failed to get NTDLL handle")
        });
        Ntdll {
            handle: PtrWrapper(handle),
            ssn_cache: BTreeMap::new(),
        }
    }

    /// Given a function hash, retrieves the appropriate syscall number.
    pub fn get_ssn_for_hash(&mut self, fn_hash: Hash) -> Syscall {
        match self.ssn_cache.get_mut(&fn_hash) {
            Some(ssn) => *ssn,
            None => {
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
