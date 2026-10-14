//! Original procedure `0x00405530` (24 bytes, `0x405530–0x405547`).
//! Evidence: `evidence/00405530_fn_00405530.md`.

unsafe extern "C" fn default_slot() {}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect cell observed as `dword ptr [0x412010]` (`DAT_00412010`);
/// the branch tests cell *content* against 0.
///
/// ponytail: absolute-address cell modeled as optional hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_00412010: Option<unsafe extern "C" fn()> = None;

/// Tail target `0x402f60` (`FUN_00402f60`), called on the null lane
/// with `(param & ~0xff) | 0x10` (`MOV AL,0x10` over live EAX).
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-arg call once cross-module test serialization exists.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) = default_tail;

/// `if slot { slot() } else { 02f60((param & ~0xff)|0x10) }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00405530(param_1: u32) {
    match PTR_00412010 {
        Some(f) => f(),
        None => HOOK_00402f60((param_1 & 0xffffff00) | 0x10),
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402f60, PTR_00412010, fn_00405530};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SLOT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn slot() {
        SLOT_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn slot_or_masked_tail() {
        unsafe {
            HOOK_00402f60 = tail;
        }
        // Slot set: indirect fires, tail silent (EAX passthrough unproven).
        unsafe {
            PTR_00412010 = Some(slot);
        }
        SLOT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405530(0xABCDEF12) };
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Slot null: tail fires with (param & ~0xff)|0x10.
        unsafe {
            PTR_00412010 = None;
        }
        unsafe { fn_00405530(0xABCDEF12) };
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0xABCDEF10);

        unsafe { fn_00405530(0x000000FF) };
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x00000010);
    }
}
