cfg_if::cfg_if! {
    if #[cfg(feature(no_std, static_lib))]  {
        extern crate alloc;

        mod libsecp256k1_static;
        pub use libsecp256k1_static::*;
    } else if #[cfg(feature(no_std, dynamic_lib))]  {
        extern crate alloc;
        
        mod code_hashes;
            pub use code_hashes::CODE_HASH_SECP256K1;

            mod libsecp256k1_dynamic;
            pub use libsecp256k1_dynamic::*;
    } else {
        pub fn get_libsecp256k1_bin() -> &'static [u8] {
            include_bytes!("../lib/secp256k1_blake2b_sighash_all_dual")
        }
    }
}


