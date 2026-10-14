//! Original procedure `0x004038a0` (86 bytes, `0x004038a0–0x004038f5`).
//! Evidence: `evidence/004038a0_fn_004038a0.md`.

/// Init `dest` from `obj`, then apply chained patch blocks.
///
/// `*dest = obj (low 32);` zero remaining `N=[obj-0x34]` bytes; walk
/// chain pushing each nonzero `[obj-0x54]` block, following double
/// link at `[obj-0x30]`; drain LIFO writing each nonzero
/// `[entry+0x10]` value to `dest + [entry+0x14]` (stride `0x1c`).
///
/// ponytail: `Vec` mirrors hardware-stack push/pop (strict LIFO,
/// same order); `for _ in 1..(N>>2)` equals `DEC; REP STOSD` for
/// `N>=4`, no-ops for `N<4` where original wraps ECX and trashes
/// memory — upgrade only if sub-4 sizes ever observed.
///
/// Returns `dest` (`mov %edx,%eax` before the patch walk; no later
/// EAX write on the return path): callers thread it as the object.
pub unsafe fn fn_004038a0(obj: *const u8, dest: *mut u8) -> *mut u8 {
    let base = dest;
    core::ptr::write_unaligned(base as *mut u32, obj as u32);
    let size = core::ptr::read_unaligned(obj.wrapping_byte_sub(0x34) as *const u32);
    let mut d = base.wrapping_add(4);
    // ponytail: see doc comment for N<4 ceiling.
    for _ in 1..(size >> 2) {
        core::ptr::write_unaligned(d as *mut u32, 0);
        d = d.wrapping_add(4);
    }
    for _ in 0..(size & 3) {
        core::ptr::write_unaligned(d, 0);
        d = d.wrapping_add(1);
    }
    let mut cur = obj;
    // ponytail: Vec used as explicit stack, LIFO only.
    let mut stack: Vec<*const u8> = Vec::new();
    loop {
        let blk = core::ptr::read_unaligned(cur.wrapping_byte_sub(0x54) as *const *const u8);
        if !blk.is_null() {
            stack.push(blk);
        }
        let link = core::ptr::read_unaligned(cur.wrapping_byte_sub(0x30) as *const *const u8);
        if link.is_null() {
            break;
        }
        cur = core::ptr::read_unaligned(link as *const *const u8);
    }
    while let Some(blk) = stack.pop() {
        let mut count = core::ptr::read_unaligned(blk as *const u32);
        let mut ent = blk.wrapping_add(4);
        while count != 0 {
            let val = core::ptr::read_unaligned(ent.wrapping_add(0x10) as *const u32);
            if val != 0 {
                let off = core::ptr::read_unaligned(ent.wrapping_add(0x14) as *const u32);
                core::ptr::write_unaligned(base.wrapping_add(off as usize) as *mut u32, val);
            }
            ent = ent.wrapping_add(0x1c);
            count = count.wrapping_sub(1);
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::fn_004038a0;

    const OBJ_LEN: usize = 0x60;
    const OBJ_OFF: usize = 0x54;

    unsafe fn set_size(obj: *mut u8, n: u32) {
        core::ptr::write_unaligned(obj.wrapping_byte_sub(0x34) as *mut u32, n);
    }

    unsafe fn set_link(obj: *mut u8, slot: *const *const u8) {
        core::ptr::write_unaligned(obj.wrapping_byte_sub(0x30) as *mut *const *const u8, slot);
    }

    unsafe fn set_block(obj: *mut u8, blk: *const u8) {
        core::ptr::write_unaligned(obj.wrapping_byte_sub(0x54) as *mut *const u8, blk);
    }

    #[test]
    fn init_zeroes_then_applies_block() {
        // Block: count=1, value at +0x10, dest offset at +0x14.
        let mut blk = [0u8; 4 + 0x1c];
        let mut dest = [0xFFu8; 12];
        unsafe {
            core::ptr::write_unaligned(blk.as_mut_ptr() as *mut u32, 1);
            core::ptr::write_unaligned(blk.as_mut_ptr().add(4 + 0x10) as *mut u32, 0xAABBCCDD);
            core::ptr::write_unaligned(blk.as_mut_ptr().add(4 + 0x14) as *mut u32, 8);
            let mut o = [0u8; OBJ_LEN];
            let obj = o.as_mut_ptr().add(OBJ_OFF);
            set_size(obj, 12);
            set_link(obj, core::ptr::null());
            set_block(obj, blk.as_ptr());
            fn_004038a0(obj, dest.as_mut_ptr());
            assert_eq!(
                u32::from_le_bytes([dest[0], dest[1], dest[2], dest[3]]),
                obj as u32
            );
            assert_eq!(&dest[4..8], &[0, 0, 0, 0]);
            assert_eq!(
                u32::from_le_bytes([dest[8], dest[9], dest[10], dest[11]]),
                0xAABBCCDD
            );
            // Zero-valued entry skips store: pre-seed target, expect kept.
            core::ptr::write_unaligned(blk.as_mut_ptr().add(4 + 0x10) as *mut u32, 0);
            dest = [0xFFu8; 12];
            fn_004038a0(obj, dest.as_mut_ptr());
            assert_eq!(&dest[4..8], &[0, 0, 0, 0]);
            assert_eq!(&dest[8..12], &[0, 0, 0, 0]);
            // Null block lane: pure init, no entries.
            set_block(obj, core::ptr::null());
            dest = [0xFFu8; 12];
            fn_004038a0(obj, dest.as_mut_ptr());
            assert_eq!(&dest[4..12], &[0; 8]);
        }
    }
}
