//! Original procedure `0x00408f2c` (59 bytes, `0x408f2c–0x408f66`).
//! Evidence: `evidence/00408f2c_fn_00408f2c.md`.

use crate::fn_004063e4::fn_004063e4;
use crate::fn_00408eb4::fn_00408eb4;

/// `8eb4(*(p6-4), p1, 0, p4); if *p4==0 { 63e4(table[p2], p4) }`.
/// `p1/p2/table` arrive in EAX/EDX/ECX (ECX spilled across the first
/// call), `p4` is the first stack arg, `p5` is never read, `p6`
/// carries the caller frame whose `[p6-4]` word is the LCID.
/// `RET 0x8` (caller pops the remaining word). The `p6-4` offset is
/// sign-extended (`wrapping_byte_offset`); slot links read
/// pointer-sized; addresses form on `usize` (never `as u32` on
/// pointers). Direct calls to done `fn_00408eb4`/`fn_004063e4`.
///
/// ponytail: on the i686 target the table is a dword array read as
/// `[p3+p2*4]`; host elements are pointer-sized so the index scales
/// by `size_of::<usize>()` — same lane, same wrap class. Upgrade to
/// image-relative tables once data layout proven.
pub unsafe fn fn_00408f2c(
    param_1: u32,
    param_2: i32,
    param_3: *const u8,
    param_4: *mut u8,
    _param_5: u32,
    param_6: *const u8,
) {
    let lcid: u32 = core::ptr::read_unaligned(param_6.wrapping_byte_offset(-4) as *const u32);
    fn_00408eb4(lcid, param_1, core::ptr::null_mut(), param_4);
    let cur: *mut u8 = core::ptr::read_unaligned(param_4 as *const *mut u8);
    if !cur.is_null() {
        return;
    }
    let rec: *const u8 = core::ptr::read_unaligned(
        (param_3 as usize)
            .wrapping_add((param_2 as u32).wrapping_mul(core::mem::size_of::<usize>() as u32) as usize)
            as *const *const u8,
    );
    fn_004063e4(rec, param_4);
}

#[cfg(test)]
mod tests {
    use super::fn_00408f2c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GLI_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLI_A: AtomicUsize = AtomicUsize::new(0);
    static GLI_B: AtomicUsize = AtomicUsize::new(0);
    static GLI_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_SLOT: AtomicUsize = AtomicUsize::new(0);
    static STORE_SRC: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn gli(loc: u32, typ: u32, _buf: *mut u16, _n: i32) -> i32 {
        GLI_HITS.fetch_add(1, Ordering::SeqCst);
        GLI_A.store(loc as usize, Ordering::SeqCst);
        GLI_B.store(typ as usize, Ordering::SeqCst);
        GLI_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn store_wide(slot: *mut u8, s: *mut u16) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_SLOT.store(slot as usize, Ordering::SeqCst);
        STORE_SRC.store(s as usize, Ordering::SeqCst);
    }

    #[test]
    fn resolve_then_fallback_lanes() {
        // Foreign hooks (owners hold no lock): hold the common one first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00408eb4::HOOK_GetLocaleInfoW = gli;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            crate::fn_004063e4::HOOK_00404e14 = store_wide;
        }
        // Frame anchor: [p6-4] must read back the LCID.
        let frame = [0x409u32, 0u32];
        let p6 = core::ptr::addr_of!(frame[1]) as *const u8;
        // One-entry table -> {ptr, id} record with a direct-lane id.
        let mut mid: *mut u8 = core::ptr::null_mut();
        let rec = [&mut mid as *mut *mut u8 as usize, 0x1_0000usize];
        let table = [rec.as_ptr() as *const u8];
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Fail lane: locale resolves nothing -> table fallback fires.
        GLI_RET.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408f2c(0x44, 0, table.as_ptr() as *const u8, slot_ptr, 0xb, p6) };
        assert_eq!(GLI_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLI_A.load(Ordering::SeqCst), 0x409);
        assert_eq!(GLI_B.load(Ordering::SeqCst), 0x44);
        assert!(slot.is_null());
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_SLOT.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(STORE_SRC.load(Ordering::SeqCst), 0x1_0000);

        // Success lane: slot set -> fallback skipped.
        GLI_RET.store(2, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408f2c(0x44, 0, table.as_ptr() as *const u8, slot_ptr, 0xb, p6) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot as usize, CANNED as usize);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);
    }
}
