cfg_if::cfg_if! {
    if #[cfg(features = "static_lib")]  {
        extern crate alloc;

        mod libsmt_static;
        pub use libsmt_static::*;
    } else if #[cfg(features = "dynamic_lib")]  {
        extern crate alloc;

        mod code_hashes;
        pub use code_hashes::CODE_HASH_CKB_SMT;

        mod libsmt_dynamic;
        pub use libsmt_dynamic::*;
    } else {
        pub fn get_libsmt_bin() -> &'static [u8] {
            include_bytes!("../lib/ckb_smt")
        }
    }
}
