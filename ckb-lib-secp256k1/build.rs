use std::path::Path;

cfg_if::cfg_if! {
    if #[cfg(feature="static_lib")] {
        fn build_fn() {
            let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            println!(
                "cargo:rustc-link-search=native={}",
                Path::new(&dir).join("lib").display()
            );
            println!("cargo:rustc-link-lib=static=rsa_secp256k1");
        }
    } else {
        use std::{
            fs::File,
            io::{BufWriter, Read, Write},
        };

        const BUF_SIZE: usize = 8 * 1024;
        fn build_fn() {
            let path = Path::new("./lib/secp256k1_blake2b_sighash_all_dual");

            if !path.exists() {
                // do nothing if binary is not exists
                return;
            }

            let out_path = Path::new("src").join("code_hashes.rs");
            let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

            let mut buf = [0u8; BUF_SIZE];

            // build hash
            let mut blake2b = new_blake2b();
            let mut fd = File::open(path).expect("open file");
            loop {
                let read_bytes = fd.read(&mut buf).expect("read file");
                if read_bytes > 0 {
                    blake2b.update(&buf[..read_bytes]);
                } else {
                    break;
                }
            }

            let mut hash = [0u8; 32];
            blake2b.finalize(&mut hash);

            write!(
                &mut out_file,
                "pub const CODE_HASH_SECP256K1: [u8; 32] = {:?};\n",
                hash
            )
            .expect("write to code_hashes.rs");
        }

        pub use blake2b_rs::{Blake2b, Blake2bBuilder};

        const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

        pub fn new_blake2b() -> Blake2b {
            Blake2bBuilder::new(32)
                .personal(CKB_HASH_PERSONALIZATION)
                .build()
        }
    }
}

fn main() {
    build_fn()
}
