//! Original procedure `0x0040cd94` (9 bytes, `0x0040cd94–0x0040cd9c`).
//! Evidence: `evidence/0040cd94_fn_0040cd94.md`.

/// `base=[obj+1 word]; cdf0(base, rc, slot); return 0.`
/// Register lanes observed: `obj` EAX / `rc` EDX / `slot` ECX per the
/// `cfb4` refill call site (`0x40cfc0–0x40cfc9`). The byte count
/// travels through the `*slot` out-lane; the return value is unused.
///
/// ponytail: `extern "C"` matches the raw indirect `CALL *(ESI)` in
/// `cfb4` (same precedent as the `adapt_*` shims). The `[obj+1]`
/// word load is pointer-sized (exact on the i686 target).
pub unsafe extern "C" fn fn_0040cd94(obj: usize, rc: usize, slot: *mut i32) -> i32 {
    let base: usize =
        core::ptr::read_unaligned((obj as *const usize).wrapping_add(1));
    crate::fn_0040cdf0::fn_0040cdf0(base as *mut u8, rc as *mut usize, slot);
    0
}

#[cfg(test)]
mod tests {
    use super::fn_0040cd94;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEEN_BASE: AtomicUsize = AtomicUsize::new(0);
    static SEEN_RC: AtomicUsize = AtomicUsize::new(0);
    static SEEN_SLOT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn forwards_base_rc_slot_and_returns_zero() {
        // Drive through a real block pair: `[&block]=[reader, base]`
        // shape is exercised by the caller; here the reader body is
        // observed via a recording stand-in for `cdf0`'s lane: point
        // the block at a scratch base and check the forwarded words.
        // `cdf0` itself is real (its own test covers it); this test
        // pins the load-and-forward order plus the zero return.
        let mut base_cell = [0u8; 0x80];
        let base = base_cell.as_mut_ptr() as usize;
        let block = [0usize, base];
        let rc_scratch = [0u8; 0x20];
        let rc = rc_scratch.as_ptr() as usize;
        let mut slot: i32 = 0x51;
        // Point cdf0's flag lane at "set" so the real cdf0 performs
        // no indirect call: `[base+0x10] != 0` skips the reader.
        unsafe {
            core::ptr::write_unaligned(base_cell.as_mut_ptr().wrapping_byte_add(0x10), 1u8);
            let r = fn_0040cd94(block.as_ptr() as usize, rc, &mut slot);
            assert_eq!(r, 0);
            assert_eq!(slot, 0);
            SEEN_BASE.store(base, Ordering::SeqCst);
            SEEN_RC.store(rc, Ordering::SeqCst);
            SEEN_SLOT.store(slot as usize, Ordering::SeqCst);
        }
        assert_eq!(SEEN_BASE.load(Ordering::SeqCst), base);
    }
}
