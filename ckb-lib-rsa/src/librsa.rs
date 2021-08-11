use crate::alloc::{
    alloc::{alloc, Layout},
    boxed::Box,
    vec::*,
};
use crate::code_hashes::CODE_HASH_RSA;
use ckb_std::{
    debug,
    dynamic_loading_c_impl::{CKBDLContext, Symbol},
};
use email_rs::Email;
use sha2::{Digest, Sha256};

const CKB_VERIFY_RSA: u32 = 1;
/// function signature of validate_secp256k1_blake2b_sighash_all
type ValidateRSASighashAll = unsafe extern "C" fn(pubkey_hash: *const u8) -> i32;
/// function signature of validate_signature
type ValidateSignature = unsafe extern "C" fn(
    prefilled_data: *const u8,
    signature_buffer: *const u8,
    signature_size: u64,
    message_buffer: *const u8,
    message_size: u64,
    output: *mut u8,
    output_len: *mut u64,
) -> i32;

/// Symbol name
const VALIDATE_RSA_SIGHASH_ALL: &[u8; 24] = b"validate_rsa_sighash_all";
const VALIDATE_SIGNATURE: &[u8; 18] = b"validate_signature";

const SECP256K1_DATA_SIZE: usize = 256; //1048576;
pub struct PrefilledData(Box<[u8; SECP256K1_DATA_SIZE]>);
pub struct PubkeyHash([u8; 20]);

impl PubkeyHash {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for PubkeyHash {
    fn default() -> Self {
        let inner = [0u8; 20];
        PubkeyHash(inner)
    }
}

impl Into<[u8; 20]> for PubkeyHash {
    fn into(self) -> [u8; 20] {
        self.0
    }
}
pub struct LibRSA {
    validate_rsa_sighash_all: Symbol<ValidateRSASighashAll>,
    validate_signature: Symbol<ValidateSignature>,
}

impl LibRSA {
    pub fn load<T>(context: &mut CKBDLContext<T>) -> Self {
        // load library
        let lib = context.load(&CODE_HASH_RSA).expect("load rsa");

        // find symbols
        let validate_rsa_sighash_all: Symbol<ValidateRSASighashAll> =
            unsafe { lib.get(VALIDATE_RSA_SIGHASH_ALL).expect("load function") };
        let validate_signature: Symbol<ValidateSignature> =
            unsafe { lib.get(VALIDATE_SIGNATURE).expect("load function") };
        LibRSA {
            validate_rsa_sighash_all,
            validate_signature,
        }
    }

    pub fn load_prefilled_data(&self) -> Result<PrefilledData, i32> {
        let data = unsafe {
            let layout = Layout::new::<[u8; 256]>();
            let raw_allocation = alloc(layout) as *mut [u8; 256];
            Box::from_raw(raw_allocation)
        };
        Ok(PrefilledData(data))
    }

    pub fn validate_rsa_sighash_all(&self, pubkey_hash: &mut [u8; 20]) -> Result<(), i32> {
        let f = &self.validate_rsa_sighash_all;
        let error_code = unsafe { f(pubkey_hash.as_mut_ptr()) };
        if error_code != 0 {
            return Err(error_code);
        }
        Ok(())
    }

    pub fn validate_signature(
        &self,
        prefilled_data: &PrefilledData,
        signature: &[u8],
        message: &[u8],
    ) -> Result<PubkeyHash, i32> {
        let mut pubkeyhash = PubkeyHash::default();
        let mut len: u64 = pubkeyhash.0.len() as u64;

        let f = &self.validate_signature;
        let error_code = unsafe {
            f(
                prefilled_data.0.as_ptr(),
                signature.as_ptr(),
                signature.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                pubkeyhash.0.as_mut_ptr(),
                &mut len as *mut u64,
            )
        };

        if error_code != 0 {
            return Err(error_code);
        }
        debug_assert_eq!(pubkeyhash.0.len() as u64, len);
        Ok(pubkeyhash)
    }

    pub fn verify_dkim_signature(&self, email: &Email, e: u32, n: Vec<u8>) -> Result<(), i32> {
        let dkim_msg = email.get_dkim_message();
        let dkim_header = &email.dkim_header.as_ref().unwrap();

        // verify body hash
        let mut sha256_context = Sha256::default();
        sha256_context.update(email.get_canonicalized_body().as_bytes());
        let dup_body_hash = sha256_context.finalize();

        if !dup_body_hash
            .as_slice()
            .eq(dkim_header.body_hash.as_slice())
        {
            debug!("email body hash verify error");
            return Err(1);
        }

        let sig = &dkim_header.signature;
        let rsa_info = LibRSA::get_rsa_info(&n, e, &sig).map_err(|_err| 8)?;

        let prefilled_data = self.load_prefilled_data().unwrap();
        let _pub_key_hash = self
            .validate_signature(&prefilled_data, rsa_info.as_ref(), &dkim_msg.as_bytes())
            .map_err(|_err| {
                debug!("dkim verify error: {}", _err);
                1
            })?;

        Ok(())
    }

    pub fn get_rsa_info(n: &[u8], e: u32, sig: &[u8]) -> Result<Vec<u8>, i32> {
        if n.len() != sig.len() {
            return Err(8);
        }
        let pub_key_size: u32 = (n.len() as u32) * 8;
        let rsa_info_len = pub_key_size / 4 + 12;

        let mut rsa_info = Vec::new();
        for _ in 0..rsa_info_len {
            rsa_info.push(0u8);
        }

        rsa_info[0..4].copy_from_slice(&CKB_VERIFY_RSA.to_le_bytes());
        rsa_info[4..8].copy_from_slice(&pub_key_size.to_le_bytes());
        rsa_info[8..12].copy_from_slice(&e.to_le_bytes());
        rsa_info[12..(12 + n.len())].copy_from_slice(&n);
        rsa_info[(12 + n.len())..(12 + n.len() * 2)].copy_from_slice(sig);

        Ok(rsa_info)
    }
}
