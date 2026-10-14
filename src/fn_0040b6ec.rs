//! Original procedure `0x0040b6ec` (20 bytes, `0x0040b6ec–0x0040b6ff`).
//! Evidence: `evidence/0040b6ec_fn_0040b6ec.md`.

unsafe extern "C" fn default_probe(_obj: *mut u8) -> u32 {
    0
}

/// Probe `0x0040b698` (`FUN_0040b698`). Observed `void`, but this
/// caller reads EAX after the call, so the hook models the EAX
/// residue as its return.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040b698` once EAX-residue semantics are proven.
pub static mut HOOK_0040b698: unsafe extern "C" fn(*mut u8) -> u32 = default_probe;

/// `r=probe(param); r==-1 → 0; (r&0x10)==0 → 0; else
/// (r&~0xff)|1`. `param_1` arrives in EAX per Ghidra
/// `__register` observation. Mask verified by hand against
/// `TEST AL,0x10` / `MOV AL,1`.
pub unsafe fn fn_0040b6ec(param_1: *mut u8) -> u32 {
    let r = HOOK_0040b698(param_1);
    if r == 0xffff_ffff {
        return 0;
    }
    if ((r as u8) & 0x10) == 0 {
        return 0;
    }
    (r & 0xffff_ff00) | 1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040b698, fn_0040b6ec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PROBE_ARG: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn probe(obj: *mut u8) -> u32 {
        PROBE_ARG.store(obj as usize, Ordering::SeqCst);
        PROBE_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn flag_lanes() {
        unsafe { HOOK_0040b698 = probe };
        let obj = 0x5678 as *mut u8;
        for (ret, want) in [
            (0xffff_ffffu32, 0u32),
            (0x0000_0000, 0),
            (0x0000_000f, 0),
            (0x0000_0010, 1),
            (0x0000_001f, 1),
            (0x1234_5610, 0x1234_5601),
            (0xffff_ff10, 0xffff_ff01),
        ] {
            PROBE_RET.store(ret as usize, Ordering::SeqCst);
            assert_eq!(unsafe { fn_0040b6ec(obj) }, want);
        }
        assert_eq!(PROBE_ARG.load(Ordering::SeqCst), obj as usize);
    }
}
