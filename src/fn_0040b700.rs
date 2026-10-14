//! Original procedure `0x0040b700` (16 bytes, `0x0040b700–0x0040b70f`).
//! Evidence: `evidence/0040b700_fn_0040b700.md`.

unsafe extern "C" fn default_probe(_obj: *mut u8) -> u32 {
    0
}

/// Probe `0x0040b698` (`FUN_0040b698`). Observed `void`, but this
/// caller uses EAX after the call, so the hook models the EAX
/// residue as its return.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040b698` once EAX-residue semantics are proven.
pub static mut HOOK_0040b698: unsafe extern "C" fn(*mut u8) -> u32 = default_probe;

/// `r=probe(param)+1; (r&~0xff)|(r!=0)`. `param_1` arrives in
/// EAX per Ghidra `__register` observation; the original keeps
/// it across the call in EBX (no observable effect). `INC`
/// wraps like EAX; `SETNZ` sets only the low byte.
pub unsafe fn fn_0040b700(param_1: *mut u8) -> u32 {
    let r = HOOK_0040b698(param_1).wrapping_add(1);
    (r & 0xffff_ff00) | ((r != 0) as u32)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040b698, fn_0040b700};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PROBE_ARG: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn probe(obj: *mut u8) -> u32 {
        PROBE_ARG.store(obj as usize, Ordering::SeqCst);
        PROBE_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn inc_setnz_lanes() {
        unsafe { HOOK_0040b698 = probe };
        let obj = 0x9abc as *mut u8;
        for (ret, want) in [
            (0xffff_ffffu32, 0u32),
            (0x0000_0000, 1),
            (0x0000_00fe, 1),
            (0x0000_00ff, 0x0000_0101),
            (0x1234_5678, 0x1234_5601),
            (0x1234_00ff, 0x1234_0101),
        ] {
            PROBE_RET.store(ret as usize, Ordering::SeqCst);
            assert_eq!(unsafe { fn_0040b700(obj) }, want);
        }
        assert_eq!(PROBE_ARG.load(Ordering::SeqCst), obj as usize);
    }
}
