//! Original procedure `0x0040bb10` (34 bytes, `0x0040bb10–0x0040bb31`).
//! Evidence: `evidence/0040bb10_fn_0040bb10.md`.

unsafe extern "C" fn default_grow(_slot: *mut u8, _n: u32) {}

/// Grow `0x00404f00` (`FUN_00404f00`), called as `(param_1, param_2)`
/// with the original registers untouched.
///
/// ponytail: hook standing in for done `fn_00404f00`, rewire to the
/// real call once cross-module test serialization exists (kept a
/// hook so the test stays hermetic).
pub static mut HOOK_00404F00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// `v = *p1 ? *(u32*)(*p1-4) : 0; gt = v > p2 (signed);
/// grow(p1, p2); return gt`. `param_1` arrives in EAX, `param_2`
/// in EDX per Ghidra `__register` observation. The compare runs
/// before the call per assembly (`SETG BL` precedes `CALL`).
/// Return is `u8`: only AL is set, upper EAX keeps stale EBX
/// (`MOV EAX,EBX` with no EBX restore), matching the existing
/// `HOOK_0040bb10` shape in `fn_0040b710`.
pub unsafe fn fn_0040bb10(param_1: *mut u8, param_2: u32) -> u8 {
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    let mut v: u32 = 0;
    if !cur.is_null() {
        v = core::ptr::read_unaligned(cur.wrapping_byte_offset(-4) as *const u32);
    }
    let gt = (v as i32) > (param_2 as i32);
    HOOK_00404F00(param_1, param_2);
    gt as u8
}

/// Test-only serialization for tests sharing the lane hook.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{HOOK_00404F00, fn_0040bb10};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_A: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn grow(slot: *mut u8, n: u32) {
        GROW_HITS.fetch_add(1, Ordering::SeqCst);
        GROW_A.store(slot as usize, Ordering::SeqCst);
        GROW_N.store(n as usize, Ordering::SeqCst);
    }

    /// Arena: obj = base+12; length cell = base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn len_compare_lanes() {
        // Own hook only: hold the owner lock so the rewired
        // `fn_0040b710` test (which pins this hook behind the real
        // call) can't race us.
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00404F00 = grow };
        let mut arena = [0u32; 4];
        let mut cell: *mut u8 = core::ptr::null_mut();
        let slot = &mut cell as *mut *mut u8 as *mut u8;

        // Null lane: v=0; 0>0 false, grow still runs.
        GROW_HITS.store(0, Ordering::SeqCst);
        cell = core::ptr::null_mut();
        assert_eq!(unsafe { fn_0040bb10(slot, 0) }, 0);
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GROW_A.load(Ordering::SeqCst), slot as usize);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 0);

        // Null vs nonzero: 0>5 false.
        assert_eq!(unsafe { fn_0040bb10(slot, 5) }, 0);

        // Above / equal / below lanes with [obj-4]=9.
        let obj = unsafe { hdr(&mut arena, 9) };
        cell = obj;
        assert_eq!(unsafe { fn_0040bb10(slot, 4) }, 1);
        assert_eq!(unsafe { fn_0040bb10(slot, 9) }, 0);
        assert_eq!(unsafe { fn_0040bb10(slot, 10) }, 0);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 10);

        // Signed lanes: v=0 vs p2=-1 → 0>-1 true.
        cell = core::ptr::null_mut();
        assert_eq!(unsafe { fn_0040bb10(slot, 0xffff_ffff) }, 1);
        // v=-1 ([obj-4]=0xffffffff) vs p2=0 → -1>0 false.
        let neg = unsafe { hdr(&mut arena, 0xffff_ffff) };
        cell = neg;
        assert_eq!(unsafe { fn_0040bb10(slot, 0) }, 0);
    }
}
