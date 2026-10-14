//! Original procedure `0x004054f8` (53 bytes, `0x004054f8–0x0040552c`).
//! Evidence: `evidence/004054f8_fn_004054f8.md`.

use core::ptr::read_unaligned;

unsafe extern "C" fn default_dispatch(_dest: *mut u8, _src: *mut u8, _n: u32) {}

/// Target `0x00405548` (`FUN_00405548`), called per entry as
/// `(add+base, **entry_ptr, 1)`; result ignored.
///
/// ponytail: hook standing in for same-batch `fn_00405548`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_00405548: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
    default_dispatch;

/// Walk the `count` 2-slot entries at `desc+off+10` (`off=u8[desc+1]`,
/// `count=u32[desc+off+6]`), dispatching each; returns base.
/// Params arrive in EAX/EDX per Ghidra `__register` observation.
///
/// ponytail: entry words are `usize` (pointer-sized slots) vs `u32`
/// on the i686 target, so host pointers survive with no `as u32`
/// truncation; on i686 `usize == u32` and the 2-word stride is the
/// observed `ADD ESI, 0x8` (per `fn_00404414` precedent).
pub unsafe fn fn_004054f8(param_1: *mut u8, param_2: *mut u8) -> *mut u8 {
    let off = read_unaligned(param_2.wrapping_add(1)) as usize;
    let mut entry = param_2.wrapping_add(off).wrapping_add(10) as *mut usize;
    let mut count: u32 = read_unaligned(
        param_2.wrapping_add(off).wrapping_add(6) as *const u32,
    );
    if count != 0 {
        loop {
            let mid: *mut u8 =
                read_unaligned(entry as *const *mut u8);
            let add: usize = read_unaligned(entry.wrapping_add(1));
            let dest = param_1.wrapping_add(add);
            let src: *mut u8 =
                read_unaligned(mid as *const *mut u8);
            HOOK_00405548(dest, src, 1);
            entry = entry.wrapping_add(2);
            count = count.wrapping_sub(1);
            if (count as i32) <= 0 {
                break;
            }
        }
    }
    param_1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405548, fn_004054f8};
    use core::ptr::write_unaligned;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARGS: AtomicUsize = AtomicUsize::new(0);

    static mut GOT: [(usize, usize, u32); 2] = [(0, 0, 0); 2];

    unsafe extern "C" fn dispatch(dest: *mut u8, src: *mut u8, n: u32) {
        let i = HITS.fetch_add(1, Ordering::SeqCst);
        if i < 2 {
            GOT[i] = (dest as usize, src as usize, n);
        }
        ARGS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn entry_walk_threads_dest_src() {
        unsafe {
            HOOK_00405548 = dispatch;
        }
        let mut base_arena = [0u8; 8];
        let base = base_arena.as_mut_ptr();
        let mut src0: u8 = 0xA1;
        let mut src1: u8 = 0xB2;
        // Double deref: entry[0] points at a cell holding src.
        let mut p0: *mut u8 = &mut src0 as *mut u8;
        let mut p1: *mut u8 = &mut src1 as *mut u8;
        // desc: off=0 at [1], count=2 at [6], entries at [10]:
        // each 2 pointer-sized slots [cell_ptr, add].
        let mut desc = [0usize; 8];
        let db = desc.as_mut_ptr() as *mut u8;
        unsafe {
            write_unaligned(db.wrapping_add(1), 0u8);
            write_unaligned(db.wrapping_add(6) as *mut u32, 2u32);
            let e0 = db.wrapping_add(10) as *mut usize;
            write_unaligned(e0 as *mut *mut u8, &mut p0 as *mut *mut u8 as *mut u8);
            write_unaligned(e0.wrapping_add(1), 0x100usize);
            let e1 = e0.wrapping_add(2);
            write_unaligned(e1 as *mut *mut u8, &mut p1 as *mut *mut u8 as *mut u8);
            write_unaligned(e1.wrapping_add(1), 0x200usize);
        }
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004054f8(base, db) };
        assert_eq!(ret, base);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        unsafe {
            assert_eq!(GOT[0], (base.wrapping_add(0x100) as usize, p0 as usize, 1));
            assert_eq!(GOT[1], (base.wrapping_add(0x200) as usize, p1 as usize, 1));
        }

        // Count 0: no calls, returns base.
        unsafe {
            write_unaligned(db.wrapping_add(6) as *mut u32, 0u32);
        }
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004054f8(base, db) };
        assert_eq!(ret, base);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
    }
}
