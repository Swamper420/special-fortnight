//! Original procedure `0x0040822c` (69 bytes, `0x40822c–0x408270`).
//! Evidence: `evidence/0040822c_fn_0040822c.md`.

unsafe extern "C" fn default_00408118(dst: *mut u8, src: *mut u8, count: u32) -> *mut u8 {
    crate::fn_00402fbc::fn_00402fbc(src, dst, count.wrapping_shl(1));
    dst
}

/// Copy target `0x408118` (`FUN_00408118`), called with
/// `(buf, param_2, count)`; observed body copies `count*2` bytes via
/// `FUN_00402fbc(src, dst, count<<1)` and returns `dst`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408118` once it exists. Default performs the observed
/// copy through done `fn_00402fbc` (pure, no globals).
pub static mut HOOK_00408118: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8 =
    default_00408118;

/// Table observed as `dword ptr [ESI*4+0x41281c]`
/// (`PTR_PTR_0041281c`): base of a pointer table indexed by
/// `param_1` (stride 4, no bounds check observed).
///
/// ponytail: absolute-address table as mutable base pointer, upgrade
/// to real image-relative import once data layout proven.
pub static mut TABLE_0041281C: *const *mut u8 = core::ptr::null();

/// Stack struct at `[ESP+0x40]`: buffer pointer, then the `0xa`
/// flag byte. Second slot addressed pointer-sized on host (see
/// evidence for the 32-bit `+4` original).
#[repr(C)]
struct Local10 {
    buf: *mut u16,
    flag: u8,
}

/// Clamp `param_3` to `0x1f` (unsigned), copy `param_2` into a
/// 32-`u16` stack buffer, NUL-terminate at the clamped count, then
/// `fn_00407bb8(table[param_1], &struct{buf, 10}, 0)`.
/// `param_1/param_2/param_3` arrive in EAX/EDX/ECX per Ghidra
/// `__register` observation.
pub unsafe fn fn_0040822c(param_1: u32, param_2: *mut u8, param_3: u32) {
    let mut count = param_3;
    if count > 0x1f {
        count = 0x1f;
    }
    let mut buf = [0u16; 32];
    HOOK_00408118(buf.as_mut_ptr() as *mut u8, param_2, count);
    core::ptr::write_unaligned(buf.as_mut_ptr().wrapping_add(count as usize), 0);
    let local = Local10 {
        buf: buf.as_mut_ptr(),
        flag: 10,
    };
    let obj: *mut u8 = core::ptr::read_unaligned(TABLE_0041281C.add(param_1 as usize));
    // `fn_00407bb8` takes `u32`: host pointers truncate at this
    // boundary (same ceiling as `fn_00404c98:57`).
    crate::fn_00407bb8::fn_00407bb8(obj as u32, &local as *const Local10 as u32, 0);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00408118, TABLE_0041281C, fn_0040822c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_COUNT: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static CALLEE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_CELL: AtomicUsize = AtomicUsize::new(0);
    static GOT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1: AtomicUsize = AtomicUsize::new(0);
    static GOT_P4: AtomicUsize = AtomicUsize::new(0);
    static GOT_P5: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut CAP: [u16; 32] = [0; 32];
    static mut CAP_N: usize = 0;

    static mut CELL: u8 = 0;
    static mut T0: u8 = 0;
    static mut T1: u8 = 0;
    static mut TBL: [*mut u8; 2] = [core::ptr::null_mut(); 2];

    unsafe extern "C" fn copy_hook(dst: *mut u8, src: *mut u8, count: u32) -> *mut u8 {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_COUNT.store(count as usize, Ordering::SeqCst);
        COPY_SRC.store(src as usize, Ordering::SeqCst);
        let nbytes = (count as usize).wrapping_mul(2);
        core::ptr::copy_nonoverlapping(src, dst, nbytes);
        CAP_N = count as usize;
        core::ptr::copy_nonoverlapping(dst as *const u16, CAP.as_mut_ptr(), count as usize);
        dst
    }

    unsafe extern "C" fn callee_hook(
        obj: *mut u8,
        flag: u8,
        p1: u32,
        p4: u32,
        p5: u32,
    ) -> u32 {
        CALLEE_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_CELL.store(obj as usize, Ordering::SeqCst);
        GOT_FLAG.store(flag as usize, Ordering::SeqCst);
        GOT_P1.store(p1 as usize, Ordering::SeqCst);
        GOT_P4.store(p4 as usize, Ordering::SeqCst);
        GOT_P5.store(p5 as usize, Ordering::SeqCst);
        // Nonzero: downstream `fn_00403f88` takes the tail lane
        // (no alloc), firing the tail stub below.
        0x5a
    }

    unsafe extern "C" fn tail_hook() {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn clamp_copy_and_downstream_call() {
        // Foreign hooks/cells (no owner locks exist): hold the
        // common lock first, save, use in a tight window, restore.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let (old_hook, old_cell, old_raise, old_tail);
        unsafe {
            old_hook = crate::fn_00407bb8::HOOK_0040991C;
            old_cell = crate::fn_00407bb8::DAT_0040751C;
            old_raise = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            HOOK_00408118 = copy_hook;
            TBL[0] = core::ptr::addr_of_mut!(T0);
            TBL[1] = core::ptr::addr_of_mut!(T1);
            TABLE_0041281C = core::ptr::addr_of!(TBL) as *const *mut u8;
            crate::fn_00407bb8::HOOK_0040991C = callee_hook;
            crate::fn_00407bb8::DAT_0040751C = core::ptr::addr_of_mut!(CELL);
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_00403f88::TAIL_00413014 = tail_hook;
        }
        let mut src = [0u16; 32];
        for (i, w) in src.iter_mut().enumerate() {
            *w = (i as u16).wrapping_add(1);
        }

        // Small lane: exact count, table[1], downstream args.
        COPY_HITS.store(0, Ordering::SeqCst);
        CALLEE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040822c(1, src.as_mut_ptr() as *mut u8, 3) };
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), src.as_mut_ptr() as usize);
        assert_eq!(unsafe { CAP_N }, 3);
        assert_eq!(unsafe { CAP[0] }, 1);
        assert_eq!(unsafe { CAP[2] }, 3);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_CELL.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(CELL) } as usize
        );
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_P1.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(T1) } as usize as u32 as usize
        );
        assert_eq!(GOT_P4.load(Ordering::SeqCst), 0);
        assert_ne!(GOT_P5.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);

        // Clamp lane: 0x100 -> 0x1f, table[0].
        COPY_HITS.store(0, Ordering::SeqCst);
        CALLEE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040822c(0, src.as_mut_ptr() as *mut u8, 0x100) };
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_COUNT.load(Ordering::SeqCst), 0x1f);
        assert_eq!(unsafe { CAP_N }, 0x1f);
        assert_eq!(unsafe { CAP[0x1e] }, 0x1f);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_P1.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(T0) } as usize as u32 as usize
        );

        unsafe {
            crate::fn_00407bb8::HOOK_0040991C = old_hook;
            crate::fn_00407bb8::DAT_0040751C = old_cell;
            crate::fn_00403f88::HOOK_0041301C = old_raise;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
