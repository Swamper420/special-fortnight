//! Original procedure `0x0040a00c` (141 bytes, `0x0040a00c–0x0040a098`).
//! Evidence: `evidence/0040a00c_fn_0040a00c.md`.

unsafe extern "C" fn default_make(
    _p1: *mut u8,
    _p2: u8,
    _p3: *const u8,
) -> usize {
    0
}

/// Maker target `0x004098e0` (`FUN_004098e0`), `(EAX, 1, ECX)`;
/// result is a DATA pointer.
///
/// ponytail: hook standing in for done `fn_004098e0`, rewire to
/// the real call once cross-module linkage proven. Result
/// widened to pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004098E0: unsafe extern "C" fn(*mut u8, u8, *const u8) -> usize =
    default_make;

/// Result cell `DAT_00415c9c`.
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut DAT_00415C9C: usize = 0;

/// Result cell `DAT_00415ca0`.
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut DAT_00415CA0: usize = 0;

/// Call-arg source `0x00406eb0` (first-call `EAX`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_00406EB0: usize = 0;

/// Call-arg source `0x00412b4c` (first-call `ECX`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_00412B4C: usize = 0;

/// Call-arg source `0x0040743c` (second-call `EAX`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_0040743C: usize = 0;

/// Call-arg source `0x00412bec` (second-call `ECX`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_00412BEC: usize = 0;

/// Value source `0x00406d5c` (stored through the `0x00412b40` slot).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_00406D5C: usize = 0;

/// Pointer slot `0x00412b20` (cell takes `0x00409b64`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B20: usize = 0;

/// Pointer slot `0x00412b7c` (cell takes `0x00409ffc`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B7C: usize = 0;

/// Pointer slot `0x00412b40` (cell takes `[0x00406d5c]`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B40: usize = 0;

/// Pointer slot `0x00412b70` (cell takes `0x00409d24`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B70: usize = 0;

/// Pointer slot `0x00412b80` (cell takes `0x00409f08`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B80: usize = 0;

/// Pointer slot `0x00412b84` (cell takes `0x00409fd8`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B84: usize = 0;

/// Pointer slot `0x00412bfc` (cell takes `0x00409c70`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412BFC: usize = 0;

/// Pointer slot `0x00412b14` (cell takes `0x00409c8c`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412B14: usize = 0;

/// Table initializer: two maker calls into `DAT_00415c9c/a0`,
/// then 8 double-deref slot stores. Operand direction kept per
/// site (slot-first ×6, immediate-first ×2). Addresses form on
/// `usize` (never `as u32` on pointers).
pub unsafe fn fn_0040a00c() {
    DAT_00415C9C = HOOK_004098E0(
        SRC_00406EB0 as *mut u8,
        1,
        SRC_00412B4C as *const u8,
    );
    DAT_00415CA0 = HOOK_004098E0(
        SRC_0040743C as *mut u8,
        1,
        SRC_00412BEC as *const u8,
    );
    core::ptr::write(SLOT_00412B20 as *mut usize, 0x00409b64);
    core::ptr::write(SLOT_00412B7C as *mut usize, 0x00409ffc);
    core::ptr::write(SLOT_00412B40 as *mut usize, SRC_00406D5C);
    core::ptr::write(SLOT_00412B70 as *mut usize, 0x00409d24);
    core::ptr::write(SLOT_00412B80 as *mut usize, 0x00409f08);
    core::ptr::write(SLOT_00412B84 as *mut usize, 0x00409fd8);
    core::ptr::write(SLOT_00412BFC as *mut usize, 0x00409c70);
    core::ptr::write(SLOT_00412B14 as *mut usize, 0x00409c8c);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415C9C, DAT_00415CA0, HOOK_004098E0, SLOT_00412B14, SLOT_00412B20, SLOT_00412B40,
        SLOT_00412B70, SLOT_00412B7C, SLOT_00412B80, SLOT_00412B84, SLOT_00412BFC,
        SRC_00406D5C, SRC_00406EB0, SRC_0040743C, SRC_00412B4C, SRC_00412BEC, fn_0040a00c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static B0: AtomicUsize = AtomicUsize::new(0);
    static C0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static B1: AtomicUsize = AtomicUsize::new(0);
    static C1: AtomicUsize = AtomicUsize::new(0);
    static R0: AtomicUsize = AtomicUsize::new(0xaaaa);
    static R1: AtomicUsize = AtomicUsize::new(0xbbbb);

    unsafe extern "C" fn make(p1: *mut u8, p2: u8, p3: *const u8) -> usize {
        let h = HITS.fetch_add(1, Ordering::SeqCst);
        if h == 0 {
            A0.store(p1 as usize, Ordering::SeqCst);
            B0.store(p2 as usize, Ordering::SeqCst);
            C0.store(p3 as usize, Ordering::SeqCst);
            R0.load(Ordering::SeqCst)
        } else {
            A1.store(p1 as usize, Ordering::SeqCst);
            B1.store(p2 as usize, Ordering::SeqCst);
            C1.store(p3 as usize, Ordering::SeqCst);
            R1.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn calls_then_slot_stores() {
        // Own hooks/slots only: no foreign globals, no TEST_LOCK.
        unsafe { HOOK_004098E0 = make };
        let mut s1 = 0u8;
        let mut s2 = 0u8;
        let mut s3 = 0u8;
        let mut s4 = 0u8;
        let (e1, e2, e3, e4) = (
            &mut s1 as *mut u8 as usize,
            &mut s2 as *mut u8 as usize,
            &mut s3 as *mut u8 as usize,
            &mut s4 as *mut u8 as usize,
        );
        let mut c: [usize; 8] = [0; 8];
        let cp = c.as_mut_ptr();
        unsafe {
            SRC_00406EB0 = e1;
            SRC_00412B4C = e2;
            SRC_0040743C = e3;
            SRC_00412BEC = e4;
            SRC_00406D5C = 0x51;
            SLOT_00412B20 = cp.wrapping_add(0) as usize;
            SLOT_00412B7C = cp.wrapping_add(1) as usize;
            SLOT_00412B40 = cp.wrapping_add(2) as usize;
            SLOT_00412B70 = cp.wrapping_add(3) as usize;
            SLOT_00412B80 = cp.wrapping_add(4) as usize;
            SLOT_00412B84 = cp.wrapping_add(5) as usize;
            SLOT_00412BFC = cp.wrapping_add(6) as usize;
            SLOT_00412B14 = cp.wrapping_add(7) as usize;
            fn_0040a00c();
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(A0.load(Ordering::SeqCst), e1);
            assert_eq!(B0.load(Ordering::SeqCst), 1);
            assert_eq!(C0.load(Ordering::SeqCst), e2);
            assert_eq!(A1.load(Ordering::SeqCst), e3);
            assert_eq!(B1.load(Ordering::SeqCst), 1);
            assert_eq!(C1.load(Ordering::SeqCst), e4);
            assert_eq!(DAT_00415C9C, 0xaaaa);
            assert_eq!(DAT_00415CA0, 0xbbbb);
            assert_eq!(
                c,
                [0x00409b64, 0x00409ffc, 0x51, 0x00409d24, 0x00409f08, 0x00409fd8, 0x00409c70, 0x00409c8c]
            );
        }
    }
}
