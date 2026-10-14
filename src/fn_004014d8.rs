//! Original procedure `0x004014d8` (61 bytes, ranges
//! `0x4014d8–0x4014e6` + `0x4014e8–0x401515`).
//! Evidence: `evidence/004014d8_fn_004014d8.md`.

/// Word table observed as `dword ptr [EDX*4 + 0x413a44]`, indexed by
/// `(bucket_off>>8)&0xff`.
///
/// ponytail: absolute-address cells modeled as mutable statics, merge
/// into shared image-relative data (with `fn_00401518`'s tables) once
/// layout proven.
pub static mut DAT_00413a40: u32 = 0;
/// See [`DAT_00413a40`].
pub static mut DAT_00413a44: [u32; 256] = [0; 256];

/// Bucket-base constant from `SUB ECX, 0x413ac4`.
///
/// ponytail: absolute address folded to `usize` index math, restore
/// absolute form once data layout proven.
const BUCKET_BASE: usize = 0x413ac4;

/// Two-pointer unlink; clears bitmap bits only when the bucket drains.
/// `param_1` holds two pointer-sized links in EAX per Ghidra
/// `__register` observation (pointer-sized per host-testability
/// precedent; on target these are 32-bit `u32` links).
pub unsafe fn fn_004014d8(param_1: *mut *mut u8) {
    let next = core::ptr::read_unaligned(param_1.wrapping_add(1));
    let prev = core::ptr::read_unaligned(param_1);
    core::ptr::write_unaligned(next as *mut *mut u8, prev);
    core::ptr::write_unaligned((prev as *mut *mut u8).wrapping_add(1), next);
    if next == prev {
        let off = (next as usize).wrapping_sub(BUCKET_BASE);
        let word = &mut DAT_00413a44[((off >> 8) & 0xff) as usize];
        *word &= 0xfffffffeu32.rotate_left(((off >> 3) & 0x1f) as u32);
        if *word == 0 {
            DAT_00413a40 &= 0xfffffffeu32.rotate_left(((off >> 8) & 0x1f) as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_00413a40, DAT_00413a44, fn_004014d8};

    /// Test-only serialization for tests sharing DAT globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn word_bit(p: *mut u8) -> (usize, u32, u32) {
        let off = (p as usize).wrapping_sub(super::BUCKET_BASE);
        (
            ((off >> 8) & 0xff) as usize,
            ((off >> 3) & 0x1f) as u32,
            ((off >> 8) & 0x1f) as u32,
        )
    }

    #[test]
    fn unlink_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Non-draining lane: splice runs, bitmap untouched.
        // Note: list nodes carry two pointer slots (16 bytes on host).
        let mut target = [0u64; 2];
        let mut filler = [0u64; 2];
        let mut node: [*mut u8; 2] = [target.as_mut_ptr() as *mut u8, filler.as_mut_ptr() as *mut u8];
        unsafe {
            DAT_00413a40 = 0x1234_5678;
            DAT_00413a44 = [0x9abcdef0; 256];
            fn_004014d8(node.as_mut_ptr());
            assert_eq!(
                *(filler.as_ptr() as *const *mut u8),
                target.as_mut_ptr() as *mut u8
            );
            assert_eq!(
                *((target.as_ptr() as *const *mut u8).wrapping_add(1)),
                filler.as_mut_ptr() as *mut u8
            );
            assert_eq!(DAT_00413a40, 0x1234_5678);
            assert_eq!(DAT_00413a44, [0x9abcdef0; 256]);
        }
        // Draining lane, word stays nonzero: root kept.
        let mut bkt = [0u64; 2];
        let b = bkt.as_mut_ptr() as *mut u8;
        let (w, bit, _) = word_bit(b);
        let other = (bit + 7) & 31;
        let mut n2: [*mut u8; 2] = [b, b];
        unsafe {
            DAT_00413a40 = 0xffff_ffff;
            DAT_00413a44 = [0; 256];
            DAT_00413a44[w] = (1 << bit) | (1 << other);
            fn_004014d8(n2.as_mut_ptr());
            assert_eq!(DAT_00413a44[w], 1 << other);
            assert_eq!(DAT_00413a40, 0xffff_ffff);
        }
        // Draining lane, word hits zero: root bit cleared too.
        let (w2, bit2, root2) = word_bit(b);
        let mut n3: [*mut u8; 2] = [b, b];
        unsafe {
            DAT_00413a40 = 0xffff_ffff;
            DAT_00413a44 = [0; 256];
            DAT_00413a44[w2] = 1 << bit2;
            fn_004014d8(n3.as_mut_ptr());
            assert_eq!(DAT_00413a44[w2], 0);
            assert_eq!(DAT_00413a40, 0xffff_ffff & !(1 << root2));
        }
    }
}
