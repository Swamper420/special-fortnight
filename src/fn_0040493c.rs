//! Original procedure `0x0040493c` (15 bytes, `0x0040493c–0x0040494a`).
//! Evidence: `evidence/0040493c_fn_0040493c.md`.

/// Refcount AddRef guard: `if p { count=[p-8]; next=count+1;
/// if next>0 signed { LOCK INC [p-8] } }`. Guards isomorphic: `TEST/JZ`
/// null exit, plain-read `INC; JLE` signed exit (store only for
/// `count` in `[0, 0x7FFFFFFE]`), then locked increment. Count cell
/// stays `u32` per observed width; pointer link pointer-sized.
///
/// ponytail: non-atomic host model of `LOCK INC`, AtomicU32 once
/// threading proven (same ceiling as `fn_004046c4`).
pub unsafe fn fn_0040493c(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let count = core::ptr::read_unaligned(p.wrapping_byte_sub(8) as *const u32);
    if (count.wrapping_add(1) as i32) <= 0 {
        return;
    }
    let next = count.wrapping_add(1);
    core::ptr::write_unaligned(p.wrapping_byte_sub(8) as *mut u32, next);
}

#[cfg(test)]
mod tests {
    use super::fn_0040493c;

    #[test]
    fn addref_lanes() {
        // No shared globals, no FPU: locals only, no TEST_LOCK.
        unsafe fn run_with(count: u32) -> u32 {
            let mut arena = [0u32; 4];
            *arena.as_mut_ptr().wrapping_add(1) = count;
            let base = arena.as_mut_ptr() as *mut u8;
            let obj = base.wrapping_byte_add(12);
            fn_0040493c(obj);
            *arena.as_mut_ptr().wrapping_add(1)
        }
        unsafe {
            // Null lane: no-op, must not fault.
            fn_0040493c(core::ptr::null_mut());
            assert_eq!(run_with(0), 1);
            assert_eq!(run_with(5), 6);
            assert_eq!(run_with(0x7fff_fffe), 0x7fff_ffff);
            // Negative counts unchanged.
            assert_eq!(run_with(0xffff_ffff), 0xffff_ffff);
            assert_eq!(run_with(0x8000_0000), 0x8000_0000);
            // Overflow edge: assembly JLE skips, pseudo would store.
            assert_eq!(run_with(0x7fff_ffff), 0x7fff_ffff);
        }
    }
}
