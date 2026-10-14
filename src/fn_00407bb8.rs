//! Original procedure `0x00407bb8` (34 bytes, `0x00407bb8–0x00407bd9`).
//! Evidence: `evidence/00407bb8_fn_00407bb8.md`.

unsafe extern "C" fn default_40991c(
    _obj: *mut u8,
    _flag: u8,
    _p1: u32,
    _p4: u32,
    _p5: u32,
) -> u32 {
    0
}

/// Cell observed as `dword ptr [0x0040751c]` (reference manager renders
/// its content as `&PTR_LAB_00407574`).
///
/// ponytail: absolute-address cell as mutable `*mut u8` (pointer-sized
/// on host, never truncated to `u32`), upgrade to real image-relative
/// data once layout proven.
pub static mut DAT_0040751C: *mut u8 = core::ptr::null_mut();

/// Callee `0x0040991c` (`FUN_0040991c`), set up with `EAX=[0x0040751c]`,
/// `DL=1`, `ECX=orig EAX`, stack `orig ECX` then `orig EDX` (first
/// pushed = deepest = 5th param).
///
/// ponytail: hook standing in for the unreconstructed callee, rewire to
/// real `fn_0040991c` once it exists. Return threads the leftover-EAX
/// slot into `fn_00403f88`.
pub static mut HOOK_0040991C: unsafe extern "C" fn(*mut u8, u8, u32, u32, u32) -> u32 =
    default_40991c;

/// `HOOK(cell, 1, p1, p3, p2)` then `fn_00403f88(result)`.
/// `(param_1, param_2, param_3)` arrive in `(EAX, EDX, ECX)` per Ghidra
/// `__register` observation. Direct call to done `fn_00403f88` (no hook).
pub unsafe fn fn_00407bb8(param_1: u32, param_2: u32, param_3: u32) {
    let r = HOOK_0040991C(DAT_0040751C, 1, param_1, param_3, param_2);
    crate::fn_00403f88::fn_00403f88(r);
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040751C, HOOK_0040991C, fn_00407bb8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static GOT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1: AtomicUsize = AtomicUsize::new(0);
    static GOT_P4: AtomicUsize = AtomicUsize::new(0);
    static GOT_P5: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut OBJ: u8 = 0;

    unsafe extern "C" fn callee(obj: *mut u8, flag: u8, p1: u32, p4: u32, p5: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
        GOT_FLAG.store(flag as usize, Ordering::SeqCst);
        GOT_P1.store(p1 as usize, Ordering::SeqCst);
        GOT_P4.store(p4 as usize, Ordering::SeqCst);
        GOT_P5.store(p5 as usize, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn tail() {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn arg_order_and_raise_tail() {
        // Foreign hooks/cells (no shared locks exist): save, use in a
        // tight window, restore.
        let (old_hook, old_cell, old_raise, old_tail);
        unsafe {
            old_hook = HOOK_0040991C;
            old_cell = DAT_0040751C;
            old_raise = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            HOOK_0040991C = callee;
            DAT_0040751C = core::ptr::addr_of_mut!(OBJ);
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_00403f88::TAIL_00413014 = tail;
        }
        // Nonzero leftover EAX: no alloc lane, raise slot empty, tail fires.
        RET.store(0x5a, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00407bb8(0x11, 0x22, 0x33) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_OBJ.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(OBJ) } as usize
        );
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_P1.load(Ordering::SeqCst), 0x11);
        assert_eq!(GOT_P4.load(Ordering::SeqCst), 0x33);
        assert_eq!(GOT_P5.load(Ordering::SeqCst), 0x22);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            HOOK_0040991C = old_hook;
            DAT_0040751C = old_cell;
            crate::fn_00403f88::HOOK_0041301C = old_raise;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
