use std::{fs, path::Path};

use rand::Rng;

fn main() {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    compile_error!("This crate only supports x86 and x86_64 architectures.");
    let mut rng = rand::thread_rng();
    let random_number: u16 = rng.gen_range(1000..=9999);
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("salt.rs");
    fs::write(
        dest_path,
        format!("pub const SALT: u32 = {};", random_number),
    )
    .expect("Failed to write salt.rs");
}
