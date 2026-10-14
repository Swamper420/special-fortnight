//! Original procedure `0x004065c8` (11 bytes, `0x004065c8–0x004065d2`).
//! Evidence: `evidence/004065c8_fn_004065c8.md`.

unsafe extern "C" fn default_push(_node: *mut usize) {}

/// Node cell observed at `0x004127b4`, address-taken as the push arg.
///
/// ponytail: absolute-address cell widened to host `usize` (never
/// `as u32` on pointers), upgrade to real image-relative data once
/// data layout proven.
pub static mut DAT_004127b4: usize = 0;

/// Target `0x004061f4` (`FUN_004061f4`), called with `&DAT_004127b4`.
///
/// ponytail: hook standing in for done `fn_004061f4`, rewire to the
/// real call once both modules are linked.
pub static mut CALLEE_004061f4: unsafe extern "C" fn(*mut usize) = default_push;

/// Push `DAT_004127b4` onto the head list. No params, void return
/// per Ghidra `__register` observation.
pub unsafe fn fn_004065c8() {
    CALLEE_004061f4(core::ptr::addr_of_mut!(DAT_004127b4));
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_004061f4, DAT_004127b4, fn_004065c8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn push(node: *mut usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT.store(node as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(node, 0x7777);
    }

    #[test]
    fn pushes_cell_address() {
        unsafe {
            CALLEE_004061f4 = push;
            DAT_004127b4 = 0;
        }
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004065c8() };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT.load(Ordering::SeqCst),
            core::ptr::addr_of!(DAT_004127b4) as usize
        );
        assert_eq!(unsafe { DAT_004127b4 }, 0x7777);
    }
}
