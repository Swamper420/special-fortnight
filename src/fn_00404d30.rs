//! Original procedure `0x00404d30` (148 bytes, `0x404d30–0x404dc3`).
//! Evidence: `evidence/00404d30_fn_00404d30.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404dd4::fn_00404dd4;

unsafe extern "C" fn default_convert(
    _dst: *mut u16,
    _cap: u32,
    _src: *const u8,
    _p4: u32,
    _n: u32,
) -> i32 {
    0
}

unsafe extern "C" fn default_size(_slot: *mut u8, _n: u32) {}

/// Target `0x4047ec` (`FUN_004047ec`): converts the counted source
/// into the WCHAR dst (cap in WCHARs), returns the converted length
/// (signed int in EAX; stack lane needs `> 0`, heap lane clamps
/// `< 0` to 0).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004047ec` once it exists.
pub static mut HOOK_004047ec: unsafe extern "C" fn(*mut u16, u32, *const u8, u32, u32) -> i32 =
    default_convert;

/// Target `0x404f00` (`FUN_00404f00`): sizes `*param_1`, first with
/// `param_3+1`, then with the converted length.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00404f00` once it exists.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_size;

/// `p3<=0 → 46c4(p1); else if p3+1<0x7ff && convert(stack)>0 →
/// 4dd4(p1,stack,r); else { 4f00(p1,p3+1); r=convert(*p1);
/// clamp; 4f00(p1,r) }`. `param_1` arrives in EAX (slot, kept in
/// EDI), `param_2` in EDX (saved to a local, reloaded for both
/// convert calls), `param_3` in ECX, `param_4` on the stack
/// (`[EBP+8]`, pushed for both convert calls). Guards isomorphic:
/// signed `JG` on the count, signed `JGE` on `p3+1` vs `0x7ff`
/// (`LEA` is `wrapping_add`), signed `JLE` on the stack length,
/// signed `JGE` on the heap clamp. Stack buffer is `[0u16; 0x7ff]`,
/// matching the observed `EDX=0x7ff` cap. Direct calls to done
/// `fn_004046c4`/`fn_00404dd4` (no hooks).
pub unsafe fn fn_00404d30(param_1: *mut u8, param_2: *const u8, param_3: u32, param_4: u32) {
    if (param_3 as i32) > 0 {
        if (param_3.wrapping_add(1) as i32) < 0x7ff {
            let mut buf = [0u16; 0x7ff];
            let r = HOOK_004047ec(buf.as_mut_ptr(), 0x7ff, param_2, param_4, param_3);
            if r > 0 {
                fn_00404dd4(param_1, buf.as_mut_ptr() as *mut u8, r as u32);
                return;
            }
        }
        HOOK_00404f00(param_1, param_3.wrapping_add(1));
        let dst: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        let mut r = HOOK_004047ec(
            dst as *mut u16,
            param_3.wrapping_add(1),
            param_2,
            param_4,
            param_3,
        );
        if r < 0 {
            r = 0;
        }
        HOOK_00404f00(param_1, r as u32);
    } else {
        fn_004046c4(param_1);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004047ec, HOOK_00404f00, fn_00404d30};
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_DST: AtomicUsize = AtomicUsize::new(0);
    static CONV_CAP: AtomicUsize = AtomicUsize::new(0);
    static CONV_SRC: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_N: AtomicUsize = AtomicUsize::new(0);
    static CONV_R0: AtomicUsize = AtomicUsize::new(0);
    static CONV_R1: AtomicUsize = AtomicUsize::new(0);
    static SIZE_HITS: AtomicUsize = AtomicUsize::new(0);
    static SIZE_A: AtomicUsize = AtomicUsize::new(0);
    static SIZE_FIRST_B: AtomicUsize = AtomicUsize::new(0);
    static SIZE_LAST_B: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;
    const P4: u32 = 0x51;

    unsafe extern "C" fn convert(dst: *mut u16, cap: u32, src: *const u8, p4: u32, n: u32) -> i32 {
        let hits = CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_DST.store(dst as usize, Ordering::SeqCst);
        CONV_CAP.store(cap as usize, Ordering::SeqCst);
        CONV_SRC.store(src as usize, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        CONV_N.store(n as usize, Ordering::SeqCst);
        if hits == 0 {
            CONV_R0.load(Ordering::SeqCst) as i32
        } else {
            CONV_R1.load(Ordering::SeqCst) as i32
        }
    }

    unsafe extern "C" fn size(slot: *mut u8, n: u32) {
        let hits = SIZE_HITS.fetch_add(1, Ordering::SeqCst);
        if hits == 0 {
            SIZE_A.store(slot as usize, Ordering::SeqCst);
            SIZE_FIRST_B.store(n as usize, Ordering::SeqCst);
        }
        SIZE_LAST_B.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_arg: u32) {
        RELEASE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        CONV_HITS.store(0, Ordering::SeqCst);
        SIZE_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        RELEASE_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn count_cap_length_clamp_lanes() {
        // Done callees read their hook globals: hold the release
        // owner lock so its writer test can't race us.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004047ec = convert;
            HOOK_00404f00 = size;
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
            crate::fn_004046c4::HOOK_00402E20 = release;
        }
        let src = b"abc\0".as_ptr();

        // Arena mirroring fn_004046c4's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Free lane: p3=0 → release, no convert/size.
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        reset();
        unsafe { fn_00404d30(slot_ptr, src, 0, P4) };
        assert_eq!(RELEASE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);

        // Stack lane: p3=5 (5+1 < 0x7ff), conv 3 → alloc 3,
        // fill bytes 3<<1=6, no size calls.
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        reset();
        CONV_R0.store(3, Ordering::SeqCst);
        unsafe { fn_00404d30(slot_ptr, src, 5, P4) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_CAP.load(Ordering::SeqCst), 0x7ff);
        assert_eq!(CONV_SRC.load(Ordering::SeqCst), src as usize);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), P4 as usize);
        assert_eq!(CONV_N.load(Ordering::SeqCst), 5);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 6);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);

        // Heap lane: conv 0 then 7 → size(6), size(7); the heap
        // convert reads dst=*p1 (still obj: size hook is a stub).
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        reset();
        CONV_R0.store(0, Ordering::SeqCst);
        CONV_R1.store(7, Ordering::SeqCst);
        unsafe { fn_00404d30(slot_ptr, src, 5, P4) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_FIRST_B.load(Ordering::SeqCst), 6);
        assert_eq!(SIZE_LAST_B.load(Ordering::SeqCst), 7);
        assert_eq!(SIZE_A.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(CONV_DST.load(Ordering::SeqCst), obj as usize);

        // Clamp lane: conv 0 then −3 → size(6), size(0).
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        reset();
        CONV_R0.store(0, Ordering::SeqCst);
        CONV_R1.store((-3i32) as u32 as usize, Ordering::SeqCst);
        unsafe { fn_00404d30(slot_ptr, src, 5, P4) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_FIRST_B.load(Ordering::SeqCst), 6);
        assert_eq!(SIZE_LAST_B.load(Ordering::SeqCst), 0);

        // Cap-skip lane: p3=0x7fe (0x7fe+1 >= 0x7ff) → one
        // convert call, straight to the heap path.
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        reset();
        CONV_R0.store(4, Ordering::SeqCst);
        unsafe { fn_00404d30(slot_ptr, src, 0x7fe, P4) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_CAP.load(Ordering::SeqCst), 0x7ff);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_FIRST_B.load(Ordering::SeqCst), 0x7ff);
        assert_eq!(SIZE_LAST_B.load(Ordering::SeqCst), 4);
    }
}
