#[macro_export]
/// This macro generates a function that dynamically invokes the associated system call.
///
/// The first parameter is a string literal of the module name, exactly how it appears in the PEB's InLoadOrderModuleList.
/// The second parameter is the function name, exactly how it appears in the module's export table.
/// The third parameter is a tuple containing the function arguments, and types, and it optionally includes a return type.
///
/// ```rust
/// use wsyscall_rs::dynamic_invoke_imp;
/// fn test_dynamic_invoke() {
///     // example of no return type
///     dynamic_invoke_imp!("KERNEL32.DLL", SetLastError, (dwerrorcode: u32));
///     // example of including return type
///     dynamic_invoke_imp!("KERNEL32.DLL", GetLastError, () -> u32);
///     // Reset the error code to 0 for testing purposes
///     unsafe { SetLastError(0) };
///     // Check if the error code was reset correctly
///     assert_eq!(unsafe { GetLastError() }, 0);
/// }
/// ```
macro_rules! dynamic_invoke_imp {
    ($module_name:literal, $fnname:ident, ($($field_name:ident: $field_type:ty),*) -> $ret:ty) => {
        #[allow(non_snake_case)]
        pub unsafe fn $fnname($($field_name: $field_type),*) -> $ret {
            type InternalType = unsafe extern "system" fn($($field_name: $field_type),*) -> $ret;
            let fn_ptr = $crate::DYNAMIC_CACHE.lock().get_function_address($crate::hash!($module_name), $crate::hash!($fnname));
            let transmuted_fn: InternalType = unsafe { core::mem::transmute(fn_ptr) };
            transmuted_fn($($field_name),*)
        }
    };
    ($module_name:literal, $fnname:ident, ($($field_name:ident: $field_type:ty),*)) => {
        #[allow(non_snake_case)]
        pub unsafe fn $fnname($($field_name: $field_type),*) {
            type InternalType = unsafe extern "system" fn($($field_name: $field_type),*);
            let fn_ptr = $crate::DYNAMIC_CACHE.lock().get_function_address($crate::hash!($module_name), $crate::hash!($fnname));
            let transmuted_fn: InternalType = unsafe { core::mem::transmute(fn_ptr) };
            transmuted_fn($($field_name),*);
        }
    };
}

#[macro_export]
/// This macro is exactly the same as `dynamic_invoke_imp!` but does not use `alloc` for the dynamic cache.
///
/// This macro generates a function that dynamically invokes the associated system call.
///
/// The first parameter is a string literal of the module name, exactly how it appears in the PEB's InLoadOrderModuleList.
/// The second parameter is the function name, exactly how it appears in the module's export table.
/// The third parameter is a tuple containing the function arguments, and types, and it optionally includes a return type.
///
/// ```rust
/// use wsyscall_rs::dynamic_invoke_imp;
/// fn test_dynamic_invoke() {
///     // example of no return type
///     dynamic_invoke_imp!("KERNEL32.DLL", SetLastError, (dwerrorcode: u32));
///     // example of including return type
///     dynamic_invoke_imp!("KERNEL32.DLL", GetLastError, () -> u32);
///     // Reset the error code to 0 for testing purposes
///     unsafe { SetLastError(0) };
///     // Check if the error code was reset correctly
///     assert_eq!(unsafe { GetLastError() }, 0);
/// }
/// ```
macro_rules! dynamic_invoke_imp_no_alloc {
    ($module_name:literal, $fnname:ident, ($($field_name:ident: $field_type:ty),*) -> $ret:ty) => {
        #[allow(non_snake_case)]
        pub unsafe fn $fnname($($field_name: $field_type),*) -> $ret {
            type InternalType = unsafe extern "system" fn($($field_name: $field_type),*) -> $ret;
            let fn_ptr = $crate::cache::GetFunctionAddress($crate::hash!($module_name), $crate::hash!($fnname));
            let transmuted_fn: InternalType = unsafe { core::mem::transmute(fn_ptr) };
            transmuted_fn($($field_name),*)
        }
    };
    ($module_name:literal, $fnname:ident, ($($field_name:ident: $field_type:ty),*)) => {
        #[allow(non_snake_case)]
        pub unsafe fn $fnname($($field_name: $field_type),*) {
            type InternalType = unsafe extern "system" fn($($field_name: $field_type),*);
            let fn_ptr = $crate::cache::GetFunctionAddress($crate::hash!($module_name), $crate::hash!($fnname));
            let transmuted_fn: InternalType = unsafe { core::mem::transmute(fn_ptr) };
            transmuted_fn($($field_name),*);
        }
    };
}

#[cfg(test)]
mod tests {
    extern crate std;

    #[test]
    fn test_dynamic_invoke_imp() {
        dynamic_invoke_imp!("KERNEL32.DLL", SetLastError, (dwerrorcode: u32));
        dynamic_invoke_imp!("KERNEL32.DLL", GetLastError, () -> u32);
        unsafe { SetLastError(1337) };
        let ret = unsafe { GetLastError() };
        assert_eq!(ret, 1337);
        std::println!("GetLastError returned: {}", ret);
    }

    #[test]
    fn test_dynamic_invoke_imp_no_alloc() {
        dynamic_invoke_imp_no_alloc!("KERNEL32.DLL", SetLastError, (dwerrorcode: u32));
        dynamic_invoke_imp_no_alloc!("KERNEL32.DLL", GetLastError, () -> u32);
        unsafe { SetLastError(1337) };
        let ret = unsafe { GetLastError() };
        assert_eq!(ret, 1337);
        std::println!("GetLastError returned: {}", ret);
    }
}
