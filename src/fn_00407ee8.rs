//! Original procedure `0x00407ee8` (38 bytes, `0x00407ee8–0x00407f0d`).
//! Evidence: `evidence/00407ee8_fn_00407ee8.md`.

use crate::fn_00404dc4::fn_00404dc4;
use crate::fn_00407e1c::fn_00407e1c;

/// Format the stacked `u64` as decimal into a 32-byte scratch
/// buffer, then store it through `4dc4(dst, start, count)`.
/// `param_1` arrives in EAX (destination slot, kept across the
/// first call via `PUSH`/`POP`); `val` is the 8-byte stack
/// argument at `[EBP+8]` (both observed call sites push
/// value-low then 0-high; callee cleans it via `RET 0x8`).
/// `ESI` is callee-saved, so nothing returns in registers:
/// `void`. Direct calls to done siblings (no hooks).
pub unsafe fn fn_00407ee8(param_1: *mut u8, val: u64) {
    // `MOV ESI,ESP` snapshot (exclusive end) before `SUB ESP,0x20`.
    let mut buf = [0u8; 32];
    let end = buf.as_mut_ptr().wrapping_add(32);
    // `(value, width 0, base 0)` per `XOR ECX,ECX` / `XOR EDX,EDX`.
    let v = val;
    let (start, n) = fn_00407e1c(&v, 0, 0, end);
    // `MOV EDX,ESI` (start) with `ECX` (count) left over.
    fn_00404dc4(param_1, start as *const u8, n);
}

#[cfg(test)]
mod tests {
    use super::fn_00407ee8;
    use crate::fn_00404d30::{HOOK_004047ec, HOOK_00404f00};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_N: AtomicUsize = AtomicUsize::new(0);
    static CONV_R0: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    // Bytes captured inside the hook: the scratch buffer dies with
    // the call, so the test must not deref the src pointer after.
    static mut CAPTURED: [u8; 8] = [0; 8];
    static mut CAPTURED_N: usize = 0;

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn convert(
        _dst: *mut u16,
        _cap: u32,
        src: *const u8,
        p4: u32,
        n: u32,
    ) -> i32 {
        CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        CONV_N.store(n as usize, Ordering::SeqCst);
        CAPTURED_N = n as usize;
        core::ptr::copy_nonoverlapping(src, CAPTURED.as_mut_ptr(), n as usize);
        CONV_R0.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn size(_slot: *mut u8, _n: u32) {}

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_arg: u32) {}

    #[test]
    fn decimal_value_reaches_convert_and_slot() {
        // Foreign fn_00404d30/fn_00404dc4/fn_00404dd4/fn_004046c4
        // hooks and cell: hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00404dc4::DAT_004138c8 = 0x51;
            HOOK_004047ec = convert;
            HOOK_00404f00 = size;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            crate::fn_004046c4::HOOK_00402E20 = release;
        }
        // Arena mirroring fn_00404d30's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        CONV_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        CONV_R0.store(3, Ordering::SeqCst);
        unsafe { fn_00407ee8(slot_ptr, 12345) };
        // Stack lane: convert saw the 5 decimal digits, the
        // global as p4, and the slot was allocated.
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_N.load(Ordering::SeqCst), 5);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), 0x51);
        assert_eq!(unsafe { (CAPTURED_N, *CAPTURED.as_ptr().cast::<[u8; 5]>()) }, (5, *b"12345"));
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 6);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
