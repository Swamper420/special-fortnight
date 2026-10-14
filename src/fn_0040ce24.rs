//! Original procedure `0x0040ce24` (195 bytes, `0x0040ce24–0x0040cee6`).
//! Evidence: `evidence/0040ce24_fn_0040ce24.md`.

unsafe extern "C" fn default_parse(
    _s: *mut u8,
    _n: u32,
    _h: *const u8,
    _o1: *mut u32,
    _o2: *mut i32,
    _c: u32,
) -> i32 {
    0
}
unsafe extern "C" fn default_alloc(_a: u32, _s: u32, _t: u32, _p: u32) -> u32 {
    0
}
unsafe extern "C" fn default_emit(_s: *mut u8, _d: usize, _o: usize) {}

/// `0x0040cc3c` reporter (codes 1/3/7): direct intra-cluster call
/// (rewired; signatures verified `fn(u32)`).

/// `0x00403250` fill `(state,0x50,0)`: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*mut u8, u32, u8)`).

/// `0x0040d9d8` header parse `(state,0x50,hdr,&sz,&off,5)`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut HOOK_0040D9D8: unsafe extern "C" fn(*mut u8, u32, *const u8, *mut u32, *mut i32, u32) -> i32 =
    default_parse;

/// `0x0040cdcc` free lane: direct intra-cluster call
/// (rewired; signatures verified `fn(*mut u8)`).

/// Thunk `0x0040684c` (`KERNEL32.DLL::VirtualAlloc`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_VirtualAlloc: unsafe extern "C" fn(u32, u32, u32, u32) -> u32 = default_alloc;

/// `0x0040da28` emit `(state,dst,dst+off)`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut HOOK_0040DA28: unsafe extern "C" fn(*mut u8, usize, usize) = default_emit;

/// `0x00409818` OOM lane: direct intra-reconstruction call
/// (rewired; signatures verified `fn()`).

/// Header-read → fill → parse → size-gated realloc → emit → ready=1.
/// First call is raw indirect `[param_1+8]`; `ADD` wraps.
pub unsafe fn fn_0040ce24(param_1: *mut u8) {
    let target: usize = core::ptr::read_unaligned(param_1.wrapping_byte_add(8) as *const usize);
    let arg0: u32 = core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32);
    let read: unsafe extern "C" fn(u32, *mut u8, u32) -> i32 = core::mem::transmute(target);
    let mut hdr = [0u8; 8];
    if read(arg0, hdr.as_mut_ptr(), 5) != 5 {
        crate::fn_0040cc3c::fn_0040cc3c(1);
    }
    crate::fn_00403250::fn_00403250(param_1.wrapping_byte_add(0x14), 0x50, 0);
    let mut out_sz: u32 = 0;
    let mut out_off: i32 = 0;
    if HOOK_0040D9D8(
        param_1.wrapping_byte_add(0x14),
        0x50,
        hdr.as_ptr(),
        &mut out_sz,
        &mut out_off,
        5,
    ) != 0
    {
        crate::fn_0040cc3c::fn_0040cc3c(3);
    }
    if out_sz > 0x4000000 {
        crate::fn_0040cc3c::fn_0040cc3c(7);
    }
    // ponytail: `ADD ESI,[ESP+0xc]` wraps on target; `wrapping_add` here.
    let total: u32 = (out_off as u32).wrapping_add(out_sz);
    if total != core::ptr::read_unaligned(param_1.wrapping_byte_add(0x68) as *const u32) {
        crate::fn_0040cdcc::fn_0040cdcc(param_1);
        let p = HOOK_VirtualAlloc(0, total, 0x1000, 4);
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0x64) as *mut u32, p);
        if p == 0 {
            crate::fn_00409818::fn_00409818();
        }
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0x68) as *mut u32, total);
    }
    let base: usize =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(0x64) as *const u32) as usize;
    HOOK_0040DA28(
        param_1.wrapping_byte_add(0x14),
        base,
        base.wrapping_add(out_off as usize),
    );
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x11), 1u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_0040D9D8, HOOK_0040DA28, HOOK_VirtualAlloc, fn_0040ce24,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FAIL: AtomicUsize = AtomicUsize::new(0);
    static PARSE_RET: AtomicUsize = AtomicUsize::new(0);
    static SZ: AtomicUsize = AtomicUsize::new(0);
    static OFF: AtomicUsize = AtomicUsize::new(0);
    static FREE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC: AtomicUsize = AtomicUsize::new(0);
    static EMIT: AtomicUsize = AtomicUsize::new(0);
    static READ_RET: AtomicUsize = AtomicUsize::new(0);

    // Fail codes observed through the real `fn_0040cc3c`: it forwards
    // `[code, 0]` to its format hook and the format result to the real
    // die (pinned to its null-raise lane here), so record at the format
    // hook — same code, same call count.
    unsafe extern "C" fn fmt_fail(
        _p1: usize,
        _p2: u8,
        _p3: *const u16,
        _p4: u32,
        blk: *mut u8,
    ) -> u32 {
        let c = core::ptr::read_unaligned(blk as *const u32);
        FAIL.store(c as usize, Ordering::SeqCst);
        c
    }
    unsafe extern "C" fn parse(
        _s: *mut u8,
        _n: u32,
        _h: *const u8,
        o1: *mut u32,
        o2: *mut i32,
        _c: u32,
    ) -> i32 {
        *o1 = SZ.load(Ordering::SeqCst) as u32;
        *o2 = OFF.load(Ordering::SeqCst) as i32;
        PARSE_RET.load(Ordering::SeqCst) as i32
    }
    // Frees observed through the real `fn_0040cdcc`'s `VirtualFree` hook.
    unsafe extern "C" fn vfree(_p: u32, _s: u32, _t: u32) -> u32 {
        FREE.fetch_add(1, Ordering::SeqCst);
        1
    }
    unsafe extern "C" fn alloc(_a: u32, _s: u32, _t: u32, _p: u32) -> u32 {
        ALLOC.fetch_add(1, Ordering::SeqCst);
        0x7000
    }
    unsafe extern "C" fn emit(_s: *mut u8, d: usize, o: usize) {
        EMIT.store(d.wrapping_sub(o), Ordering::SeqCst);
    }
    unsafe extern "C" fn read5(_a: u32, _b: *mut u8, _c: u32) -> i32 {
        READ_RET.load(Ordering::SeqCst) as i32
    }

    fn rec_with(read_ret: i32) -> [u8; 0x80] {
        let mut rec = [0u8; 0x80];
        let base = rec.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut usize, read5 as usize);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x64) as *mut u32, 0x7000);
        }
        READ_RET.store(read_ret as isize as usize, Ordering::SeqCst);
        rec
    }

    #[test]
    fn lanes() {
        // Real `fn_00403f88` behind the fail reporter (nonzero codes
        // skip its alloc lane): hold its lock set, pin the null raise
        // slot.
        let _b8 = crate::fn_004046b8::TEST_LOCK.lock().unwrap();
        let _ac = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_hook, old_tail);
        unsafe {
            old_hook = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_0040cc3c::HOOK_00409860 = fmt_fail;
            HOOK_0040D9D8 = parse;
            crate::fn_0040cdcc::HOOK_VirtualFree = vfree;
            HOOK_VirtualAlloc = alloc;
            HOOK_0040DA28 = emit;
        }
        // Short-read lane: fail(1), then equal-size lane skips alloc.
        SZ.store(0x10, Ordering::SeqCst);
        OFF.store(0x4, Ordering::SeqCst);
        PARSE_RET.store(0, Ordering::SeqCst);
        let mut rec = rec_with(5);
        let base = rec.as_mut_ptr();
        unsafe {
            // Real `fn_00403250` zeroes the 0x50-byte state window.
            core::ptr::write_unaligned(base.wrapping_byte_add(0x14), 0xAAu8);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x68) as *mut u32, 0x14);
            fn_0040ce24(base);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x14)), 0u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x63)), 0u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x11) as *const u8), 1);
        }
        assert_eq!(FAIL.load(Ordering::SeqCst), 0);
        assert_eq!(FREE.load(Ordering::SeqCst), 0);
        // Short read hits fail(1).
        let mut rec = rec_with(3);
        FAIL.store(0, Ordering::SeqCst);
        SZ.store(0x10, Ordering::SeqCst);
        OFF.store(0x4, Ordering::SeqCst);
        unsafe {
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(0x68) as *mut u32, 0x14);
            fn_0040ce24(rec.as_mut_ptr());
        }
        assert_eq!(FAIL.load(Ordering::SeqCst), 1);
        // Parse-fail hits fail(3); resize lane frees+allocs.
        PARSE_RET.store(2, Ordering::SeqCst);
        SZ.store(0x20, Ordering::SeqCst);
        OFF.store(0x4, Ordering::SeqCst);
        FREE.store(0, Ordering::SeqCst);
        ALLOC.store(0, Ordering::SeqCst);
        let mut rec = rec_with(5);
        unsafe {
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(0x68) as *mut u32, 0x10);
            fn_0040ce24(rec.as_mut_ptr());
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(0x68) as *const u32),
                0x24
            );
        }
        assert_eq!(FAIL.load(Ordering::SeqCst), 3);
        assert_eq!(FREE.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00403f88::HOOK_0041301C = old_hook;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
