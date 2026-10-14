//! Original procedure `0x00405664` (24 bytes, `0x00405664–0x0040567b`).
//! Evidence: `evidence/00405664_fn_00405664.md`.

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Slot observed as `dword ptr [0x00412014]` (`DAT_00412014`); non-null
/// arm is `CALL [slot]` with registers passed through.
///
/// ponytail: absolute-address cell modeled as optional hook (`None` =
/// null slot), upgrade to real image-relative import once data layout
/// proven.
pub static mut HOOK_00412014: Option<unsafe extern "C" fn()> = None;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `CALL` with
/// `AL=0x10` over the entry EAX.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// `if [slot]!=0 { [slot]() } else { tail((param & ~0xff) | 0x10) }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation; unlike
/// its `0x00402e20` sibling there is no `param==0` early exit.
pub unsafe fn fn_00405664(param_1: u32) {
    match HOOK_00412014 {
        Some(f) => f(),
        None => TAIL_00402F60((param_1 & 0xffffff00) | 0x10),
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00412014, TAIL_00402F60, fn_00405664};
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
            HOOK_00412014 = Some(slot);
            TAIL_00402F60 = tail;
        }
        SLOT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405664(0x12345678) };
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        unsafe { HOOK_00412014 = None };
        // Assembly: MOV AL,0x10 over EAX=0x12345678 -> 0x12345610.
        unsafe { fn_00405664(0x12345678) };
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x12345610);
        // Low byte fully replaced: 0xAB -> 0x10.
        unsafe { fn_00405664(0x000000ab) };
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x00000010);
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 1);
    }
}
