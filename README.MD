# wsyscall_rs
`wsyscall_rs` is a Rust library designed to facilitate dynamic invocation, or indirect/direct invocation of Windows systems.
## Features
- **Dynamic Invocation of System Calls:** The `dynamic_invoke_imp` macro allows you to dynamically invoke Windows API tions from loaded modules such as `KERNEL32.DLL`, without needing to statically link against these functions.
- **Custom System Call Wrappers:** The `syscall_imp` macro creates a wrapper over an Nt system call using native system callers and raw assembly. It supports direct and indirect syscalls with the corresponding feature (direct is default).
## Usage
For more usage information, please see the documentation for the macros mentioned above.
## Safety and Best Practices
The macros provided by `wsyscall_rs` generate `unsafe` functions due to the nature of system calls and the use of raw assembly. These operations can directly interact with the operating system, which can cause undefined behavior or system ability if used incorrectly. Therefore, it is crucial to:
- Validate all inputs and outputs.
- Ensure that you have a thorough understanding of the Windows API and system call interfaces you are invoking.
- Test thoroughly, especially when dealing with different versions of Windows.
## License
This project is licensed under either of
* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.