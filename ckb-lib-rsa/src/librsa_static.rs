use core::ptr::null;

use crate::alloc::vec::*;
use ckb_std::dynamic_loading_c_impl::CKBDLContext;
use email_rs::Email;

const CKB_VERIFY_RSA: u32 = 1;

pub struct PrefilledData;
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

extern "C" {
    // fn load_prefilled_data(data: *mut u8, len: *mut u64) -> i32;
    fn validate_signature_rsa(
        prefilled_data: *const u8,
        signature_buffer: *const u8,
        signature_size: u64,
        msg_buf: *const u8,
        msg_size: u64,
        output: *mut u8,
        output_len: *mut u64,
    ) -> isize;
}

pub struct LibRSA;

impl LibRSA {
    pub fn load<T>(_context: &mut CKBDLContext<T>) -> Self {
        LibRSA
    }

    pub fn load_prefilled_data(&self) -> Result<PrefilledData, i32> {
        Ok(PrefilledData)
    }

    pub fn validate_signature(
        &self,
        _prefilled_data: &PrefilledData,
        signature: &[u8],
        message: &[u8],
    ) -> Result<PubkeyHash, i32> {
        let mut pubkeyhash = PubkeyHash::default();
        let mut len: u64 = pubkeyhash.0.len() as u64;

        let error_code = unsafe {
            validate_signature_rsa(
                null(),
                signature.as_ptr(),
                signature.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                pubkeyhash.0.as_mut_ptr(),
                &mut len as *mut u64,
            )
        };

        if error_code != 0 {
            return Err(error_code as i32);
        }
        debug_assert_eq!(pubkeyhash.0.len() as u64, len);
        Ok(pubkeyhash)
    }

    pub fn verify_dkim_signature(&self, email: &Email, e: u32, n: Vec<u8>) -> Result<(), i32> {
        if email
            .get_dkim_message()
            .into_iter()
            .zip(email.dkim_headers.iter())
            .find(|(dkim_msg, dkim_header)| {
                let handle = || {
                    let sig = &dkim_header.signature;
                    let rsa_info = LibRSA::get_rsa_info(&n, e, &sig)?;

                    let prefilled_data = self.load_prefilled_data().unwrap();
                    self.validate_signature(
                        &prefilled_data,
                        rsa_info.as_ref(),
                        &dkim_msg.as_bytes(),
                    )
                };
                handle().is_ok()
            })
            .is_none()
        {
            return Err(1);
        }

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
