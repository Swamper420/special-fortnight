//! Original procedure `0x00404850` (130 bytes, `0x00404850–0x004048d1`).
//! Evidence: `evidence/00404850_fn_00404850.md`.

unsafe extern "C" fn default_release(_a: *mut u32) {}

unsafe extern "C" fn default_convert(
    _a: *mut u8,
    _b: u32,
    _c: *mut u16,
    _d: u32,
    _e: i32,
) -> u32 {
    0
}

unsafe extern "C" fn default_alloc(_a: *mut u32, _b: u32, _c: u32) {}

/// Release `0x004046c4` (`FUN_004046c4`); return discarded by body:
/// direct intra-reconstruction call (rewired; `fn_004046c4` verified
/// `fn(*mut u8) -> *mut u8`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004046c4(a: *mut u32) {
    crate::fn_004046c4::fn_004046c4(a as *mut u8);
}
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u32) = adapt_004046c4;

/// Convert `0x004047c0` (`FUN_004047c0`); probe `(NULL,0,src,tag,count)`
/// returns size, fill `(*slot,size,src,tag,count)`: direct
/// intra-reconstruction call with a host size probe (rewired;
/// `fn_004047c0` verified `fn(*mut u8, i32, *const u16, u32, i32)`,
/// result discarded per its contract — the count comes from the host
/// `WideCharToMultiByte` shim, exact on i686).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004047c0(
    a: *mut u8,
    b: u32,
    c: *mut u16,
    d: u32,
    e: i32,
) -> u32 {
    let n = crate::fn_004047c0::W2M_00401170(d, 0, c, e, core::ptr::null_mut(), 0, 0, 0);
    crate::fn_004047c0::fn_004047c0(a, b as i32, c, d, e);
    n
}
pub static mut HOOK_004047C0: unsafe extern "C" fn(*mut u8, u32, *mut u16, u32, i32) -> u32 =
    adapt_004047c0;

/// Alloc `0x004049c4` (`FUN_004049c4`); args `(slot,size,0)`: direct
/// intra-reconstruction call (rewired; `fn_004049c4` verified
/// `fn(*mut *mut u8, u32, i32)`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004049c4(a: *mut u32, b: u32, c: u32) {
    crate::fn_004049c4::fn_004049c4(a as *mut *mut u8, b, c as i32)
}
pub static mut HOOK_004049C4: unsafe extern "C" fn(*mut u32, u32, u32) = adapt_004049c4;

/// Global word `DAT_004138c8`, default tag when `param_4 == 0`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004138C8: u16 = 0;

/// `if count<1 { release } else { tag?=DAT; size=probe(NULL,0);
/// alloc(slot,size,0); if size<1 signed { release } else {
/// fill(*slot,size); [reloaded *slot-12]=tag } }`. Guards signed
/// (`JG`/`JLE`); `*param_1` read twice (fill arg, write base), never
/// cached. Frame spills and `RET 0x4` are calling-convention mechanics;
/// unmodeled.
pub unsafe fn fn_00404850(
    param_1: *mut u32,
    param_2: *mut u16,
    param_3: i32,
    param_4: u16,
) {
    if param_3 < 1 {
        HOOK_004046C4(param_1);
        return;
    }
    let tag = if param_4 == 0 { DAT_004138C8 } else { param_4 };
    let size = HOOK_004047C0(core::ptr::null_mut(), 0, param_2, tag as u32, param_3);
    HOOK_004049C4(param_1, size, 0);
    if (size as i32) < 1 {
        HOOK_004046C4(param_1);
    } else {
        let base: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        HOOK_004047C0(base, size, param_2, tag as u32, param_3);
        let wbase: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        core::ptr::write_unaligned(wbase.wrapping_byte_offset(-12) as *mut u16, tag);
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138C8, HOOK_004046C4, HOOK_004047C0, HOOK_004049C4, fn_00404850};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_SIZE: AtomicUsize = AtomicUsize::new(0);
    static CVT_A0_NULL: AtomicUsize = AtomicUsize::new(0);
    static CVT_TAG: AtomicUsize = AtomicUsize::new(0);
    static CVT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(_a: *mut u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn convert(a: *mut u8, b: u32, _c: *mut u16, d: u32, e: i32) -> u32 {
        let n = CVT_HITS.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            CVT_A0_NULL.store(a.is_null() as usize, Ordering::SeqCst);
            assert_eq!(b, 0);
        }
        CVT_TAG.store(d as usize, Ordering::SeqCst);
        CVT_COUNT.store(e as usize, Ordering::SeqCst);
        CVT_SIZE.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn alloc(_a: *mut u32, b: u32, c: u32) {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_SIZE.store(b as usize, Ordering::SeqCst);
        assert_eq!(c, 0);
    }

    fn reset() {
        REL_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn lanes() {
        unsafe {
            HOOK_004046C4 = release;
            HOOK_004047C0 = convert;
            HOOK_004049C4 = alloc;
            DAT_004138C8 = 9;
        }
        let mut wide = [0u16; 4];
        let src = wide.as_mut_ptr();

        // count<1 lane: release only.
        let mut dead: *mut u8 = core::ptr::null_mut();
        let dead_ptr = &mut dead as *mut *mut u8 as *mut u32;
        reset();
        unsafe { fn_00404850(dead_ptr, src, 0, 5) };
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Zero-size lane: probe(NULL,0)+alloc, then release; tag defaults to DAT.
        let mut zbuf = [0u8; 32];
        let mut zinner: *mut u8 = zbuf.as_mut_ptr().wrapping_byte_add(16);
        let zptr = &mut zinner as *mut *mut u8 as *mut u32;
        CVT_SIZE.store(0, Ordering::SeqCst);
        reset();
        unsafe { fn_00404850(zptr, src, 2, 0) };
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_A0_NULL.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_TAG.load(Ordering::SeqCst), 9);
        assert_eq!(CVT_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Positive-size lane: fill + tag word at (*slot)-12; no second release.
        let mut fbuf = [0u8; 32];
        let base = fbuf.as_mut_ptr().wrapping_byte_add(16);
        let mut finner: *mut u8 = base;
        let fptr = &mut finner as *mut *mut u8 as *mut u32;
        CVT_SIZE.store(4, Ordering::SeqCst);
        reset();
        unsafe { fn_00404850(fptr, src, 2, 0) };
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(base.wrapping_byte_offset(-12) as *const u16) },
            9
        );
    }
}
