fn main() {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    compile_error!("This crate only supports x86 and x86_64 architectures.");
}
