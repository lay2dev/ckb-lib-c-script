use alloc::vec::Vec;
use ckb_std::dynamic_loading_c_impl::{CKBDLContext, Symbol};

const CKB_SMT_VEIRFY: &[u8; 14] = b"ckb_smt_verify";
type CKBSmtVerify = unsafe extern "C" fn(
    old_root: *const u8,
    smt_pair_len: u32,
    keys: *const u8,
    values: *const u8,
    proof: *const u8,
    proof_length: u32,
) -> i32;

pub struct LibCKBSmt {
    smt_verify: Symbol<CKBSmtVerify>,
}

impl LibCKBSmt {
    pub fn load<T>(context: &mut CKBDLContext<T>) -> Self {
        let lib = context
            .load(&crate::code_hashes::CODE_HASH_CKB_SMT)
            .expect("load ckb_smt");

        let smt_verify = unsafe { lib.get(CKB_SMT_VEIRFY).expect("load function") };
        LibCKBSmt { smt_verify }
    }

    pub fn smt_verify(
        &self,
        root: &[u8],
        keys: &[u8],
        values: &[u8],
        proof: &[u8],
    ) -> Result<(), i32> {
        let f = &self.smt_verify;

        if keys.len() != values.len() || root.len() != 32 {
            return Err(-1);
        }
        let keys = keys.chunks(32).collect::<Vec<_>>();
        let values = values.chunks(32).collect::<Vec<_>>();

        if keys.last().ok_or(-1)?.len() != 32 || values.last().ok_or(-1)?.len() != 32 {
            return Err(-2);
        }

        let res = unsafe {
            f(
                root.as_ptr(),
                keys.len() as u32,
                keys.get(0)
                    .map(|x| x.as_ptr())
                    .unwrap_or(keys.as_ptr() as _),
                values
                    .get(0)
                    .map(|x| x.as_ptr())
                    .unwrap_or(values.as_ptr() as _),
                proof.as_ptr(),
                proof.len() as u32,
            )
        };
        if res != 0 {
            Err(res)
        } else {
            Ok(())
        }
    }
}
