//! Original procedure `0x00401578` (102 bytes, `0x00401578–0x004015e1`).
//! Evidence: `evidence/00401578_fn_00401578.md`.

unsafe extern "C" fn default_callee(_cursor: *mut u8) {}

unsafe extern "C" fn default_tail(_block: *mut u32, _size: u32) {}

/// Callee `0x004014d8` (`FUN_004014d8`), cursor arrives in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004014d8` once it exists.
pub static mut CALLEE_004014d8: unsafe extern "C" fn(*mut u8) = default_callee;

/// Shared large-block tail at `0x00401518` (`FUN_00401518` body).
///
/// ponytail: hook standing in for shared tail code outside this body,
/// rewire to real `fn_00401518` once it exists.
pub static mut TAIL_00401518: unsafe extern "C" fn(*mut u32, u32) = default_tail;

/// Cursor cell `DAT_00413a38`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a38: *mut u8 = core::ptr::null_mut();

/// Remaining-size cell `DAT_00413a3c`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a3c: u32 = 0;

/// Seal current heap block: write `size+3` header and `size` sentinel, tail
/// to the shared large-block bucket when `size >= 0xb30`.
pub unsafe fn fn_00401578() {
    if DAT_00413a3c == 0 {
        return;
    }
    let mut cursor = DAT_00413a38;
    let flags =
        core::ptr::read_unaligned(cursor.wrapping_byte_sub(4) as *const u32);
    let (block, size) = if (flags & 1) == 0 {
        core::ptr::write_unaligned(
            cursor.wrapping_byte_sub(4) as *mut u32,
            flags | 8,
        );
        let rem = DAT_00413a3c;
        let block =
            cursor.wrapping_byte_sub(rem as usize) as *mut u32;
        core::ptr::write_unaligned(
            (block as *mut u8).wrapping_byte_sub(4) as *mut u32,
            rem.wrapping_add(3),
        );
        core::ptr::write_unaligned(
            (block as *mut u8)
                .wrapping_byte_add(rem.wrapping_sub(8) as usize)
                as *mut u32,
            rem,
        );
        (block, rem)
    } else {
        let mut masked = flags & 0xfffffff0;
        if masked > 0xb2f {
            CALLEE_004014d8(cursor);
            cursor = DAT_00413a38;
            masked = core::ptr::read_unaligned(
                cursor.wrapping_byte_sub(4) as *const u32,
            ) & 0xfffffff0;
        }
        let rem = DAT_00413a3c;
        let block =
            (cursor as *mut u8).wrapping_byte_sub(rem as usize) as *mut u32;
        let size = masked.wrapping_add(rem);
        core::ptr::write_unaligned(
            (block as *mut u8).wrapping_byte_sub(4) as *mut u32,
            size.wrapping_add(3),
        );
        core::ptr::write_unaligned(
            (block as *mut u8)
                .wrapping_byte_add(size.wrapping_sub(8) as usize)
                as *mut u32,
            size,
        );
        (block, size)
    };
    if size < 0xb30 {
        return;
    }
    TAIL_00401518(block, size);
}

#[cfg(test)]
mod tests {
    use super::{
        CALLEE_004014d8, DAT_00413a38, DAT_00413a3c, TAIL_00401518,
        fn_00401578,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLEE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_SIZE: AtomicUsize = AtomicUsize::new(0);
    static TAIL_BLOCK: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(_cursor: *mut u8) {
        CALLEE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(block: *mut u32, size: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_BLOCK.store(block as usize, Ordering::SeqCst);
        TAIL_SIZE.store(size as usize, Ordering::SeqCst);
    }

    unsafe fn header_at(cursor: *mut u8) -> u32 {
        core::ptr::read_unaligned(cursor.wrapping_byte_sub(4) as *const u32)
    }

    #[test]
    fn seal_lanes() {
        unsafe {
            CALLEE_004014d8 = callee;
            TAIL_00401518 = tail;
        }
        // Empty: remaining==0 returns before touching cursor.
        unsafe {
            DAT_00413a3c = 0;
            DAT_00413a38 = core::ptr::null_mut();
            fn_00401578();
        }
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Clear-bit small block: headers written, no tail.
        let mut buf = [0u8; 64];
        let cursor = buf.as_mut_ptr().wrapping_byte_add(32);
        unsafe {
            core::ptr::write_unaligned(
                cursor.wrapping_byte_sub(4) as *mut u32,
                0x10,
            );
            DAT_00413a38 = cursor;
            DAT_00413a3c = 8;
            fn_00401578();
        }
        let block = cursor.wrapping_byte_sub(8);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        unsafe {
            assert_eq!(header_at(cursor), 0x10 | 8);
            assert_eq!(
                core::ptr::read_unaligned(
                    block.wrapping_byte_sub(4) as *const u32
                ),
                11
            );
            assert_eq!(
                core::ptr::read_unaligned(block as *const u32),
                8
            );
        }

        // Set-bit large block: callee fires, tail fires with masked size.
        let mut big = [0u8; 0x2000];
        let cursor2 = big.as_mut_ptr().wrapping_byte_add(0x1000);
        unsafe {
            core::ptr::write_unaligned(
                cursor2.wrapping_byte_sub(4) as *mut u32,
                0xc01,
            );
            DAT_00413a38 = cursor2;
            DAT_00413a3c = 0x100;
            fn_00401578();
        }
        let block2 = cursor2.wrapping_byte_sub(0x100);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_BLOCK.load(Ordering::SeqCst), block2 as usize);
        assert_eq!(TAIL_SIZE.load(Ordering::SeqCst), 0xd00);
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(
                    block2.wrapping_byte_sub(4) as *const u32
                ),
                0xd03
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    block2.wrapping_byte_add(0xd00 - 8) as *const u32
                ),
                0xd00
            );
        }
    }
}
