//! Original procedure `0x00404414` (36 bytes, `0x00404414–0x00404438`).
//! Evidence: `evidence/00404414_fn_00404414.md`.

/// Add-reduce loop: `count = param_1[0]`; per 3-word entry
/// `[dest, src, add]` do `*(u32 *)dest = *(u32 *)src + add` (wrapping).
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: entry words are `usize` (pointer-sized slots) vs `u32` on
/// the i686 target, so host pointers survive with no `as u32`
/// truncation; on i686 `usize == u32` and the `+3-word` stride is the
/// observed `ADD ESI, 0xc`. `EBX` is `0` for the whole body, so the
/// `+EBX` scale terms are omitted as `+0` no-ops.
pub unsafe fn fn_00404414(param_1: *mut usize) {
    let mut count: usize = core::ptr::read_unaligned(param_1 as *const usize);
    let mut entry = param_1.wrapping_add(1);
    loop {
        let dest: *mut u32 =
            core::ptr::read_unaligned(entry as *const *mut u32);
        let src: *const u32 =
            core::ptr::read_unaligned(entry.wrapping_add(1) as *const *const u32);
        let add: u32 =
            core::ptr::read_unaligned(entry.wrapping_add(2) as *const usize) as u32;
        let v: u32 = core::ptr::read_unaligned(src);
        core::ptr::write_unaligned(dest, v.wrapping_add(add));
        entry = entry.wrapping_add(3);
        count = count.wrapping_sub(1);
        if count == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00404414;

    static mut DEST0: u32 = 0;
    static mut DEST1: u32 = 0;
    static mut SRC: u32 = 0;

    #[test]
    fn add_reduce_wrap_and_stride() {
        unsafe {
            SRC = 10;
            let d0 = core::ptr::addr_of_mut!(DEST0) as *mut u32 as usize;
            let s = core::ptr::addr_of_mut!(SRC) as *const u32 as usize;
            let mut table: [usize; 4] = [1, d0, s, 5];
            fn_00404414(table.as_mut_ptr());
            assert_eq!(DEST0, 15);

            // Wrapping ADD: 0xFFFFFFFF + 1 -> 0.
            SRC = 0xffffffff;
            let mut table: [usize; 4] = [1, d0, s, 1];
            fn_00404414(table.as_mut_ptr());
            assert_eq!(DEST0, 0);

            // Two entries: stride is 3 words.
            SRC = 100;
            DEST0 = 0;
            DEST1 = 0;
            let d1 = core::ptr::addr_of_mut!(DEST1) as *mut u32 as usize;
            let mut table: [usize; 7] = [2, d0, s, 1, d1, s, 2];
            fn_00404414(table.as_mut_ptr());
            assert_eq!(DEST0, 101);
            assert_eq!(DEST1, 102);
        }
    }
}
