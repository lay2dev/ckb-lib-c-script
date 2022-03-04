use alloc::vec::Vec;
use ckb_std::dynamic_loading_c_impl::CKBDLContext;

pub struct LibCKBSmt;

extern "C" {
    fn ckb_smt_verify(
        root: *const u8,
        smt_pair_len: u32,
        keys: *const u8,
        values: *const u8,
        proof: *const u8,
        proof_length: u32,
    ) -> isize;
}

impl LibCKBSmt {
    pub fn load<T>(_context: &mut CKBDLContext<T>) -> Self {
        LibCKBSmt
    }

    pub fn smt_verify(
        &self,
        root: &[u8],
        keys: &[u8],
        values: &[u8],
        proof: &[u8],
    ) -> Result<(), i32> {
        if keys.len() != values.len() || root.len() != 32 {
            return Err(-1);
        }
        let keys = keys.chunks(32).collect::<Vec<_>>();
        let values = values.chunks(32).collect::<Vec<_>>();

        if keys.last().ok_or(-1)?.len() != 32 || values.last().ok_or(-1)?.len() != 32 {
            return Err(-2);
        }

        let res = unsafe {
            ckb_smt_verify(
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
            Err(res as i32)
        } else {
            Ok(())
        }
    }
}
