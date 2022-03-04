use crate::alloc::{
    alloc::{alloc, Layout},
    boxed::Box,
};
use ckb_std::dynamic_loading_c_impl::CKBDLContext;

const SECP256K1_DATA_SIZE: usize = 1048576;
pub struct PrefilledData(Box<[u8; SECP256K1_DATA_SIZE]>);
pub struct Pubkey([u8; 65]);

impl Pubkey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        let inner = [0u8; 65];
        Pubkey(inner)
    }
}

impl Into<[u8; 65]> for Pubkey {
    fn into(self) -> [u8; 65] {
        self.0
    }
}
pub struct LibSecp256k1;

extern "C" {
    fn load_prefilled_data(data: *mut u8, len: *mut u64) -> isize;

    fn validate_signature_secp256k1(
        prefilled_data: *const u8,
        signature_buffer: *const u8,
        signature_size: u64,
        msg_buf: *const u8,
        msg_size: u64,
        output: *mut u8,
        output_len: *mut u64,
    ) -> isize;
    fn validate_secp256k1_blake2b_sighash_all(output_public_key_hash: *mut u8) -> isize;

}

impl LibSecp256k1 {
    pub fn load<T>(_context: &mut CKBDLContext<T>) -> Self {
        LibSecp256k1
    }

    pub fn validate_blake2b_sighash_all(&self, pubkey_hash: &mut [u8; 20]) -> Result<(), i32> {
        let error_code =
            unsafe { validate_secp256k1_blake2b_sighash_all(pubkey_hash.as_mut_ptr()) };
        if error_code != 0 {
            return Err(error_code as i32);
        }
        Ok(())
    }

    pub fn load_prefilled_data(&self) -> Result<PrefilledData, i32> {
        let mut data = unsafe {
            let layout = Layout::new::<[u8; SECP256K1_DATA_SIZE]>();
            let raw_allocation = alloc(layout) as *mut [u8; SECP256K1_DATA_SIZE];
            Box::from_raw(raw_allocation)
        };
        let mut len: u64 = SECP256K1_DATA_SIZE as u64;

        let error_code = unsafe { load_prefilled_data(data.as_mut_ptr(), &mut len as *mut u64) };
        if error_code != 0 {
            return Err(error_code as i32);
        }
        Ok(PrefilledData(data))
    }

    pub fn recover_pubkey(
        &self,
        prefilled_data: &PrefilledData,
        signature: &[u8],
        message: &[u8],
    ) -> Result<Pubkey, i32> {
        let mut pubkey = Pubkey::default();
        let mut len: u64 = pubkey.0.len() as u64;

        let error_code = unsafe {
            validate_signature_secp256k1(
                prefilled_data.0.as_ptr(),
                signature.as_ptr(),
                signature.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                pubkey.0.as_mut_ptr(),
                &mut len as *mut u64,
            )
        };

        if error_code != 0 {
            return Err(error_code as i32);
        }
        debug_assert_eq!(pubkey.0.len() as u64, len);
        Ok(pubkey)
    }
}
