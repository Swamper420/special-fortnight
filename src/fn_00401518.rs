//! Original procedure `0x00401518` (94 bytes, ranges
//! `0x00401518–0x00401549` + `0x0040154c–0x00401577`).
//! Evidence: `evidence/00401518_fn_00401518.md`.

/// Bucket table: 1024 buckets × 2 pointers at `0x00413ac4`+`u*8`
/// (`DAT_00413ac8` is the second-word lane at `base+4`).
///
/// ponytail: absolute-address cells modeled as mutable statics, merge
/// into shared image-relative data (with `fn_004014d8`'s tables) once
/// layout proven.
pub static mut BUCKETS_00413ac4: [[*mut u8; 2]; 1024] =
    [[core::ptr::null_mut(); 2]; 1024];
/// See [`BUCKETS_00413ac4`].
pub static mut DAT_00413a40: u32 = 0;
/// See [`BUCKETS_00413ac4`].
pub static mut DAT_00413a44: [u32; 256] = [0; 256];

/// `u = min((param_2-0xb30)>>8, 0x3ff)`; insert node into bucket `u`;
/// set bitmap bits only when the bucket was empty. Params arrive in
/// EAX/EDX per Ghidra `__register` observation (links pointer-sized
/// per host-testability precedent; on target these are 32-bit `u32`).
pub unsafe fn fn_00401518(param_1: *mut *mut u8, param_2: u32) {
    let u = param_2
        .wrapping_sub(0xb30)
        .wrapping_shr(8)
        .min(0x3ff);
    let bucket = core::ptr::addr_of_mut!(BUCKETS_00413ac4)
        .cast::<[*mut u8; 2]>()
        .wrapping_add(u as usize) as *mut *mut u8;
    let old = core::ptr::read_unaligned(bucket.wrapping_add(1));
    core::ptr::write_unaligned(param_1, bucket as *mut u8);
    core::ptr::write_unaligned(param_1.wrapping_add(1), old);
    core::ptr::write_unaligned(old as *mut *mut u8, param_1 as *mut u8);
    core::ptr::write_unaligned(bucket.wrapping_add(1), param_1 as *mut u8);
    if old == bucket as *mut u8 {
        DAT_00413a44[((u >> 5) & 0xff) as usize] |= 1 << (u & 0x1f);
        DAT_00413a40 |= 1 << ((u.wrapping_mul(8).wrapping_shr(8)) & 0x1f);
    }
}

#[cfg(test)]
mod tests {
    use super::{BUCKETS_00413ac4, DAT_00413a40, DAT_00413a44, fn_00401518};

    /// Test-only serialization for tests sharing bucket/DAT globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe fn bucket_self_link(u: usize) {
        let b = core::ptr::addr_of_mut!(BUCKETS_00413ac4).cast::<[*mut u8; 2]>().wrapping_add(u)
            as *mut *mut u8;
        core::ptr::write_unaligned(b, b as *mut u8);
        core::ptr::write_unaligned(b.wrapping_add(1), b as *mut u8);
    }

    unsafe fn bucket_ptr(u: usize) -> *mut u8 {
        core::ptr::addr_of_mut!(BUCKETS_00413ac4).cast::<[*mut u8; 2]>().wrapping_add(u)
            as *mut u8
    }

    #[test]
    fn clamp_and_insert_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe fn reset(link: &[usize]) {
            BUCKETS_00413ac4 = [[core::ptr::null_mut(); 2]; 1024];
            DAT_00413a40 = 0;
            DAT_00413a44 = [0; 256];
            for u in link {
                bucket_self_link(*u);
            }
        }
        // param_2 = 0xb30 → u = 0, empty lane sets bits.
        let mut n0: [*mut u8; 2] = [core::ptr::null_mut(); 2];
        unsafe {
            reset(&[0]);
            fn_00401518(n0.as_mut_ptr(), 0xb30);
            assert_eq!(n0[0], bucket_ptr(0));
            assert_eq!(n0[1], bucket_ptr(0));
            assert_eq!(DAT_00413a44[0], 1 << 0);
            assert_eq!(DAT_00413a40, 1 << 0);
        }
        // param_2 = 0 wraps (0-0xb30 huge) and clamps to bucket 1023
        // (observed SUB/SHR/SBB/AND/ADD clamp).
        let mut nwrap: [*mut u8; 2] = [core::ptr::null_mut(); 2];
        unsafe {
            reset(&[1023]);
            fn_00401518(nwrap.as_mut_ptr(), 0);
            assert_eq!(nwrap[0], bucket_ptr(1023));
            assert_eq!(nwrap[1], bucket_ptr(1023));
            assert_eq!(DAT_00413a44[31], 1 << 31);
        }
        // Huge param_2 clamps to bucket 1023 (word 31, bit 31).
        let mut nmax: [*mut u8; 2] = [core::ptr::null_mut(); 2];
        unsafe {
            reset(&[1023]);
            fn_00401518(nmax.as_mut_ptr(), 0xffff_ffff);
            assert_eq!(nmax[0], bucket_ptr(1023));
            assert_eq!(DAT_00413a44[31], 1 << 31);
            assert_eq!(DAT_00413a40, 1 << 31);
        }
        // Nonempty lane: no bitmap touch, linkage spliced.
        let mut n1: [*mut u8; 2] = [core::ptr::null_mut(); 2];
        let mut n2: [*mut u8; 2] = [core::ptr::null_mut(); 2];
        unsafe {
            reset(&[5]);
            // param_2 = 0xb30 + 5<<8 → u = 5.
            fn_00401518(n1.as_mut_ptr(), 0xb30 + (5 << 8));
            assert_eq!(DAT_00413a44[0], 1 << 5);
            DAT_00413a44 = [0; 256];
            DAT_00413a40 = 0;
            fn_00401518(n2.as_mut_ptr(), 0xb30 + (5 << 8));
            assert_eq!(DAT_00413a44, [0; 256]);
            assert_eq!(DAT_00413a40, 0);
            assert_eq!(n2[0], bucket_ptr(5));
            assert_eq!(n2[1], n1.as_mut_ptr() as *mut u8);
            assert_eq!(n1[0], n2.as_mut_ptr() as *mut u8);
        }
    }
}
