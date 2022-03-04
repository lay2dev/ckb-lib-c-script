/*
 * @Author: your name
 * @Date: 2021-08-31 19:57:42
 * @LastEditTime: 2021-09-01 22:00:25
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: /ckb-lib-c-script/ckb-lib-rsa/src/lib.rs
 */
pub mod email_rs {
    pub use email_rs::*;
}

cfg_if::cfg_if! {
    if #[cfg(feature(no_std, static_lib))]  {
        extern crate alloc;

        mod librsa_static;
        pub use librsa_static::*;
    } else if #[cfg(feature(no_std, dynamic_lib))]  {
        extern crate alloc;
        
        mod code_hashes;
        pub use code_hashes::CODE_HASH_RSA;

        mod librsa_dynamic;
        pub use librsa_dynamic::*;
    } else {
        pub fn get_librsa_bin() -> &'static [u8] {
            include_bytes!("../lib/rsa_sighash_all")
        }
    }
}
