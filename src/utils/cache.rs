use alloc::collections::btree_map::BTreeMap;

use crate::{
    obf::Hash,
    sus_functions::{GetSsn, SusGetModuleHandle, SusGetProcAddress},
    syscall::Syscall,
    NTDLL_HASH_LOWER, NTDLL_HASH_UPPER,
};

/// Custom struct to wrap a pointer to ensure Sync + Send, since we don't modify these pointers directly, and only read from them.
#[derive(Clone, Copy)]
pub struct PtrWrapper(pub(crate) *const core::ffi::c_void);
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
    pub(crate) fn new() -> Self {
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

/// A cache for dynamically resolved function addresses.
///
/// The use case of this structure is dynamically resolving function addresses from a module by hash, preventing them from appearing in the `IAT`.
pub struct DynamicCache {
    /// A cache for dynamically resolved fn addresses, where the key is the module hash and the value is a tuple containing the module pointer and a cache for function addresses.
    cache: BTreeMap<
        Hash,
        (
            PtrWrapper,
            BTreeMap<Hash, unsafe extern "system" fn() -> isize>,
        ),
    >,
}

impl DynamicCache {
    pub(crate) fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
        }
    }

    /// Retrieves the function address for a given module and function hash.
    pub fn get_function_address(
        &mut self,
        module_hash: Hash,
        fn_hash: Hash,
    ) -> unsafe extern "system" fn() -> isize {
        let (module_ptr, module_cache) = self.cache.entry(module_hash).or_insert_with(|| {
            (
                PtrWrapper(SusGetModuleHandle(module_hash).unwrap()),
                BTreeMap::new(),
            )
        });
        let function_address = module_cache
            .entry(fn_hash)
            .or_insert_with(|| unsafe { SusGetProcAddress(**module_ptr, fn_hash).unwrap() });
        *function_address
    }
}
