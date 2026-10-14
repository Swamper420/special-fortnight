//! Original procedure `0x00403f88` (108 bytes, `0x00403f88–0x00403ff3`).
//! Evidence: `evidence/00403f88_fn_00403f88.md`.

unsafe extern "C" fn default_raise(_code: u32, _flags: u32, _extra: u32) {}

unsafe extern "C" fn default_tail14() {}

/// Indirect slot `dword ptr [0x0041301c]` (`DAT_0041301c`), null-checked at
/// `0x00403fb1`; when set it is called with `(0xeedfade, 1, extra)` where
/// `extra` is 0 or `[fn_00402efc()+0xC]` per `0x00403fd4–0x00403fe9`.
///
/// ponytail: `Option` models the observed null check (a plain hook cannot),
/// upgrade to real image-relative import once data layout proven.
pub static mut HOOK_0041301C: Option<unsafe extern "C" fn(u32, u32, u32)> = None;

/// Terminal `JMP dword ptr [0x00413014]` at `0x00403fee` (no null check).
/// The cell is owned as a 4-arg raise hook by `fn_00403b0c`, but this site
/// passes no clean args (stack holds leftover struct words), so a hermetic
/// nullary tail hook is used and the jump is modeled as call+return.
///
/// ponytail: alias of `crate::fn_00403b0c::HOOK_00413014`; unify once a
/// shared call-site convention is proven.
pub static mut TAIL_00413014: unsafe extern "C" fn() = default_tail14;

/// Conditional raise-tail: `param_1==0` allocates via `fn_004046b8(0xd8)`
/// (its `POP` source is the return-address slot, `0x00403f96` on target);
/// when the `0x0041301c` slot is set, resolve `fn_00402efc()` and raise
/// `(0xeedfade, 1, extra)`; always tail through `[0x00413014]`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00403f88(param_1: u32) {
    if param_1 == 0 {
        crate::fn_004046b8::fn_004046b8(0xd8, 0x00403f96);
    }
    if let Some(raise) = HOOK_0041301C {
        let r = crate::fn_00402efc::fn_00402efc();
        // Double deref: `r` is itself `*ctx()`; nonzero reads `[r+0xC]`.
        // `r as *const u32` zero-extends the 32-bit address (exact); the
        // `+3` is `usize` (never truncated).
        let extra: u32 = if r == 0 {
            0
        } else {
            core::ptr::read_unaligned((r as *const u32).wrapping_add(3))
        };
        raise(0xeedfade, 1, extra);
    }
    TAIL_00413014();
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0041301C, TAIL_00413014, fn_00403f88};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RAISE_HITS: AtomicUsize = AtomicUsize::new(0);
    static RAISE_CODE: AtomicUsize = AtomicUsize::new(0);
    static RAISE_FLAGS: AtomicUsize = AtomicUsize::new(0);
    static RAISE_EXTRA: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);

    static mut WORDS: [u32; 2] = [0, 0];

    unsafe extern "C" fn raise(code: u32, flags: u32, extra: u32) {
        RAISE_HITS.fetch_add(1, Ordering::SeqCst);
        RAISE_CODE.store(code as usize, Ordering::SeqCst);
        RAISE_FLAGS.store(flags as usize, Ordering::SeqCst);
        RAISE_EXTRA.store(extra as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail14() {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Stands in for the OS import behind real `fn_00406588`
    /// (reached via real `fn_00402efc`).
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    unsafe extern "C" fn alloc_tail(arg: u32) {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn alloc_raise_tail_lanes() {
        // Foreign hooks/cells (no shared locks exist): save, use in a
        // tight window, restore. Asserts run after restore.
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_hook, old_tail, old_cell, old_alloc);
        let (old_flag, old_tls_hook, old_index);
        unsafe {
            old_hook = HOOK_0041301C;
            old_tail = TAIL_00413014;
            old_cell = crate::fn_004046b8::CELL_00412004;
            old_alloc = crate::fn_004046b8::HOOK_004046ac;
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_tls_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            HOOK_0041301C = None;
            TAIL_00413014 = tail14;
            crate::fn_004046b8::HOOK_004046ac = alloc_tail;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            WORDS = [0, 0x99];
        }
        // Nonzero param: no alloc, null slot: no raise, tail fires.
        RAISE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00403f88(0x5a) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(RAISE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        // Zero param: alloc via 0x004046b8(0xd8) with the retaddr-slot word.
        RAISE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00403f88(0) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0xd8);
        assert_eq!(unsafe { crate::fn_004046b8::CELL_00412004 }, 0x00403f96);
        assert_eq!(RAISE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        // Set slot, ctx head zero → raise(eedfade, 1, 0), tail fires.
        unsafe { HOOK_0041301C = Some(raise) };
        RAISE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00403f88(0x5a) };
        assert_eq!(RAISE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RAISE_CODE.load(Ordering::SeqCst), 0xeedfade);
        assert_eq!(RAISE_FLAGS.load(Ordering::SeqCst), 1);
        assert_eq!(RAISE_EXTRA.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { WORDS[1] }, 0x99);
        unsafe {
            HOOK_0041301C = old_hook;
            TAIL_00413014 = old_tail;
            crate::fn_004046b8::CELL_00412004 = old_cell;
            crate::fn_004046b8::HOOK_004046ac = old_alloc;
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
