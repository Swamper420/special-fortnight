//! Original procedure `0x00408480` (112 bytes, `0x00408480–0x004084ef`).
//! Evidence: `evidence/00408480_fn_00408480.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404a8c::fn_00404a8c;
use crate::fn_00404b9c::fn_00404b9c;
use crate::fn_00404c2c::fn_00404c2c;
use crate::fn_00404d24::fn_00404d24;
use crate::fn_00404eb8::fn_00404eb8;
use crate::fn_0040822c::fn_0040822c;

/// Straight-line BSTR pipeline over two zeroed locals: `local_8`
/// (BSTR slot) runs `4c2c → 4b9c → 4a8c`; `local_c` runs
/// `4eb8 → 4d24 → (thunk 464c4) → 822c`. `param_1` (EAX) forwards
/// only to `822c`, `param_2` (EDX) only to `4b9c`, `param_3` (ECX)
/// to `4c2c`/`4b9c`/`822c`. Callee results are ignored exactly where
/// the assembly overwrites `EAX`. The `thunk_FUN_004046c4` (5 bytes)
/// is a transparent jump: done `fn_004046c4` is called directly.
/// FS install/teardown and the `0x004084f0`/`0x004084f7` handler labels
/// have no host effect.
///
/// ponytail: locals are host `usize` slots (4B `u32` cells on the
/// i686 target, identical there); a `u32` local next to stack pad
/// makes the downstream pointer-sized slot read pick up pad garbage
/// on 64-bit hosts. Revisit with image-relative data layout.
pub unsafe fn fn_00408480(param_1: i32, param_2: *const u16, param_3: u32) {
    let mut local_8: usize = 0;
    let mut local_c: usize = 0;
    fn_00404c2c(&mut local_8 as *mut usize as *mut u8, param_3);
    fn_00404b9c(&mut local_8 as *mut usize as *mut u32, param_2, param_3);
    fn_00404eb8(&mut local_c as *mut usize as *mut u8, local_8 as *mut u8);
    let pl = fn_00404d24(local_c as *const u8);
    fn_0040822c(param_1 as u32, pl as *mut u8, param_3);
    fn_004046c4(&mut local_c as *mut usize as *mut u8);
    fn_00404a8c(&mut local_8 as *mut usize as *mut u32);
}

#[cfg(test)]
mod tests {
    use super::fn_00408480;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_SYS_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SYS_A: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SYS_B: AtomicUsize = AtomicUsize::new(0);
    static TAIL_A64_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_DD4_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_DD4_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_COUNT: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static CALLEE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static GOT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1: AtomicUsize = AtomicUsize::new(0);
    static TAIL14_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut CELL: u8 = 0;
    static mut T0: u8 = 0;
    static mut T1: u8 = 0;
    static mut TBL: [*mut u8; 2] = [core::ptr::null_mut(); 2];

    unsafe extern "C" fn alloc_sys(psz: u32, cch: u32) -> u32 {
        let n = ALLOC_SYS_HITS.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            ALLOC_SYS_A.store(psz as usize, Ordering::SeqCst);
            ALLOC_SYS_B.store(cch as usize, Ordering::SeqCst);
        }
        0
    }

    unsafe extern "C" fn tail_a64(_arg: u32) {
        TAIL_A64_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn free_hook(_bstr: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc_dd4(n: u32) -> u32 {
        ALLOC_DD4_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_DD4_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill_dd4(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn copy_hook(dst: *mut u8, src: *mut u8, count: u32) -> *mut u8 {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_COUNT.store(count as usize, Ordering::SeqCst);
        COPY_SRC.store(src as usize, Ordering::SeqCst);
        dst
    }

    unsafe extern "C" fn callee_7bb8(obj: *mut u8, flag: u8, p1: u32, _p4: u32, _p5: u32) -> u32 {
        CALLEE_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
        GOT_FLAG.store(flag as usize, Ordering::SeqCst);
        GOT_P1.store(p1 as usize, Ordering::SeqCst);
        // Nonzero: downstream `fn_00403f88` takes the no-alloc lane.
        0x5a
    }

    unsafe extern "C" fn tail14() {
        TAIL14_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn pipeline_order_oom_lanes() {
        // Foreign hooks/cells: hold the common owner lock first, then
        // the owner locks where they exist. Save/restore everything.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _a64 = crate::fn_00404a64::TEST_LOCK.lock().unwrap();
        let _a7c = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let (s_sys, s_tail, s_free, s_alloc, s_fill, s_copy, s_tbl);
        let (s_callee, s_cell, s_raise, s_tail14);
        unsafe {
            s_sys = crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180;
            s_tail = crate::fn_00404a64::TAIL_00402F60;
            s_free = crate::fn_00404a7c::SYS_FREE_STRING_00401190;
            s_alloc = crate::fn_00404dd4::HOOK_004054b4;
            s_fill = crate::fn_00404dd4::HOOK_00402fbc;
            s_copy = crate::fn_0040822c::HOOK_00408118;
            s_tbl = crate::fn_0040822c::TABLE_0041281C;
            s_callee = crate::fn_00407bb8::HOOK_0040991C;
            s_cell = crate::fn_00407bb8::DAT_0040751C;
            s_raise = crate::fn_00403f88::HOOK_0041301C;
            s_tail14 = crate::fn_00403f88::TAIL_00413014;
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = alloc_sys;
            crate::fn_00404a64::TAIL_00402F60 = tail_a64;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook;
            crate::fn_00404dd4::HOOK_004054b4 = alloc_dd4;
            crate::fn_00404dd4::HOOK_00402fbc = fill_dd4;
            crate::fn_0040822c::HOOK_00408118 = copy_hook;
            TBL[0] = core::ptr::addr_of_mut!(T0);
            TBL[1] = core::ptr::addr_of_mut!(T1);
            crate::fn_0040822c::TABLE_0041281C = core::ptr::addr_of!(TBL) as *const *mut u8;
            crate::fn_00407bb8::HOOK_0040991C = callee_7bb8;
            crate::fn_00407bb8::DAT_0040751C = core::ptr::addr_of_mut!(CELL);
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_00403f88::TAIL_00413014 = tail14;
        }
        let wide = [0x41u16, 0x42, 0];
        ALLOC_SYS_HITS.store(0, Ordering::SeqCst);
        TAIL_A64_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        ALLOC_DD4_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        CALLEE_HITS.store(0, Ordering::SeqCst);
        TAIL14_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408480(1, wide.as_ptr(), 3) };
        // Both BSTR allocs fail: (0,3) then (src,3), two tail(1)s.
        assert_eq!(ALLOC_SYS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_SYS_A.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_SYS_B.load(Ordering::SeqCst), 3);
        assert_eq!(TAIL_A64_HITS.load(Ordering::SeqCst), 2);
        // Null-old lanes: no free anywhere in the chain.
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        // Null-BSTR lane through 4eb8/4dd4: alloc(0), no fill.
        assert_eq!(ALLOC_DD4_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_DD4_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        // Null local_c takes the 4d24 default-cell path into 822c.
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(
            COPY_SRC.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of!(crate::fn_00404d24::CELL_004127A8) } as usize
        );
        // Table object + cell forwarded into 7bb8, tail raised.
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_OBJ.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(CELL) } as usize
        );
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_P1.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(T1) } as usize as u32 as usize
        );
        assert_eq!(TAIL14_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = s_sys;
            crate::fn_00404a64::TAIL_00402F60 = s_tail;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = s_free;
            crate::fn_00404dd4::HOOK_004054b4 = s_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = s_fill;
            crate::fn_0040822c::HOOK_00408118 = s_copy;
            crate::fn_0040822c::TABLE_0041281C = s_tbl;
            crate::fn_00407bb8::HOOK_0040991C = s_callee;
            crate::fn_00407bb8::DAT_0040751C = s_cell;
            crate::fn_00403f88::HOOK_0041301C = s_raise;
            crate::fn_00403f88::TAIL_00413014 = s_tail14;
        }
    }
}
