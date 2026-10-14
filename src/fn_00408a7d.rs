//! Original procedure `0x00408a7d` (11 bytes, `0x408a7d–0x408a87`).
//! Evidence: `evidence/00408a7d_fn_00408a7d.md`.

/// `LODSB` byte fetch: `b=[src]`; nonzero returns `(b, src+1)`,
/// NUL returns `('0', src)` (`MOV AL,0x30; DEC ESI` undoes the
/// `LODSB` advance, so NUL is re-read next call). `XOR AH,AH`
/// zero-extends: high byte always 0. `src` is the `ESI` cursor
/// in/out; the returned pair is `(AX, ESI)`.
pub unsafe fn fn_00408a7d(src: *mut u8) -> (u16, *mut u8) {
    let b = core::ptr::read_unaligned(src as *const u8);
    if b != 0 {
        (b as u16, src.wrapping_byte_add(1))
    } else {
        (0x30u16, src)
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00408a7d;

    #[test]
    fn fetch_advance_and_nul_lanes() {
        // Pure cursor math, no hooks/globals: locals only, no TEST_LOCK.
        let mut buf = [0x41u8, 0x42, 0x00, 0x43];
        let base = buf.as_mut_ptr();
        let (ax, next) = unsafe { fn_00408a7d(base) };
        assert_eq!(ax, 0x41);
        assert_eq!(next, base.wrapping_byte_add(1));
        let (ax, next) = unsafe { fn_00408a7d(next) };
        assert_eq!(ax, 0x42);
        assert_eq!(next, base.wrapping_byte_add(2));
        // NUL lane: '0', cursor unmoved.
        let (ax, next) = unsafe { fn_00408a7d(next) };
        assert_eq!(ax, 0x30);
        assert_eq!(next, base.wrapping_byte_add(2));
    }
}
