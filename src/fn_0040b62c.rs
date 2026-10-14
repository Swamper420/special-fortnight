//! Original procedure `0x0040b62c` (107 bytes, `0x0040b62c–0x0040b696`).
//! Evidence: `evidence/0040b62c_fn_0040b62c.md`.

unsafe extern "C" fn default_scan(_obj: *mut u8, _one: u8) -> i32 {
    0
}

unsafe extern "C" fn default_at(_obj: *mut u8, _addr: *mut u8) -> *mut u16 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_slice(_obj: *mut u8, _one: i32, _n: i32, _dest: *mut u8) {}

/// Scanner `0x0040b3cc` (`FUN_0040b3cc`), `(obj, 1)`.
/// Only the low byte of EDX is forced to 1 (`MOV DL,1`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040b3cc` once it exists.
pub static mut HOOK_0040b3cc: unsafe extern "C" fn(*mut u8, u8) -> i32 = default_scan;

/// Indexer `0x0040b620` (`FUN_0040b620`), `(obj, obj+n*2)`.
/// Returns a DATA pointer (deref'd by the caller).
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040b620` once it exists.
pub static mut HOOK_0040b620: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u16 = default_at;

/// Class test `0x0040b334` (`FUN_0040b334`), `(MOVZX ch)`.
/// Only `AL` is observed (`TEST AL,AL`): direct intra-reconstruction
/// call (rewired; signatures verified `fn(u16) -> u32`).

/// Store `0x00404c98` (`FUN_00404c98`), `(dest_slot, src)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Slicer `0x0040525c` (`FUN_0040525c`), `(obj, 1, n, dest)`.
///
/// ponytail: hook mirroring done `fn_0040525c`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_0040525c: unsafe extern "C" fn(*mut u8, i32, i32, *mut u8) = default_slice;

/// Scan `param_1` from the searched start down while the class
/// test holds, then store (length unchanged) or slice (shrunk).
/// `param_1` arrives in EAX, `param_2` (dest slot) in EDX per
/// Ghidra `__register` observation. Header length is the `u32`
/// at `obj-4`, null-guarded to 0 and compared signed; the
/// counter wraps (`DEC`); addresses form on `usize`.
pub unsafe fn fn_0040b62c(param_1: *mut u8, param_2: *mut u8) {
    let start = HOOK_0040b3cc(param_1, 1);
    let mut n: i32 = if param_1.is_null() {
        0
    } else {
        core::ptr::read_unaligned(param_1.wrapping_byte_offset(-4) as *const i32)
    };
    while start < n {
        let addr =
            (param_1 as usize).wrapping_add((n as u32).wrapping_mul(2) as usize) as *mut u8;
        let p = HOOK_0040b620(param_1, addr);
        let r = crate::fn_0040b334::fn_0040b334(core::ptr::read_unaligned(p as *const u16));
        if (r as u8) == 0 {
            break;
        }
        n = n.wrapping_sub(1);
    }
    let len: i32 = if param_1.is_null() {
        0
    } else {
        core::ptr::read_unaligned(param_1.wrapping_byte_offset(-4) as *const i32)
    };
    if len == n {
        crate::fn_00404c98::fn_00404c98(param_2, param_1);
    } else {
        HOOK_0040525c(param_1, 1, n, param_2);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040525c, HOOK_0040b3cc, HOOK_0040b620, fn_0040b62c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static SCAN_ONE: AtomicUsize = AtomicUsize::new(0);
    static SCAN_RET: AtomicUsize = AtomicUsize::new(0);
    static AT_ADDR: AtomicUsize = AtomicUsize::new(0);
    static AT_SEQ: AtomicUsize = AtomicUsize::new(0);
    static SLICE_HITS: AtomicUsize = AtomicUsize::new(0);
    static SLICE_B: AtomicUsize = AtomicUsize::new(0);
    static SLICE_C: AtomicUsize = AtomicUsize::new(0);
    static SLICE_D: AtomicUsize = AtomicUsize::new(0);

    static mut PROBE: u16 = 0x41;
    static mut SLASH: u16 = 0x5c;

    unsafe extern "C" fn scan(_obj: *mut u8, one: u8) -> i32 {
        SCAN_HITS.fetch_add(1, Ordering::SeqCst);
        SCAN_ONE.store(one as usize, Ordering::SeqCst);
        SCAN_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn at(_obj: *mut u8, addr: *mut u8) -> *mut u16 {
        AT_ADDR.store(addr as usize, Ordering::SeqCst);
        // First call of a lane serves the slash cell (real class
        // holds, 0x5c→1); later calls serve the probe (real class
        // releases, 0x41→0). Lanes preset AT_SEQ to select.
        if AT_SEQ.fetch_add(1, Ordering::SeqCst) == 0 {
            core::ptr::addr_of_mut!(SLASH)
        } else {
            core::ptr::addr_of_mut!(PROBE)
        }
    }

    unsafe extern "C" fn slice(_o: *mut u8, b: i32, c: i32, d: *mut u8) {
        SLICE_HITS.fetch_add(1, Ordering::SeqCst);
        SLICE_B.store(b as usize, Ordering::SeqCst);
        SLICE_C.store(c as usize, Ordering::SeqCst);
        SLICE_D.store(d as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag 2 at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    #[test]
    fn scan_store_slice_lanes() {
        // Real `fn_00404c98` behind the store lane (null old → no
        // dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040b3cc = scan;
            HOOK_0040b620 = at;
            HOOK_0040525c = slice;
        }
        let mut dest: *mut u8 = core::ptr::null_mut();
        let dest_ptr = &mut dest as *mut *mut u8 as *mut u8;

        // Null lane: scan(?,1), no loop, real store(dest, null)
        // no-op (dest stays null).
        SCAN_RET.store(5, Ordering::SeqCst);
        SLICE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b62c(core::ptr::null_mut(), dest_ptr) };
        assert_eq!(SCAN_ONE.load(Ordering::SeqCst), 1);
        assert!(dest.is_null());
        assert_eq!(SLICE_HITS.load(Ordering::SeqCst), 0);

        // Equal lane: len 3, scan→0, real class(0x41)==0 releases
        // at once → break at n=3 → 3==3 → real store lane;
        // at-addr = obj+6. Headed obj taken (rc 5→6).
        let mut a_eq = [0u32; 4];
        let obj = unsafe { hdr(&mut a_eq, 3) };
        SCAN_RET.store(0, Ordering::SeqCst);
        AT_SEQ.store(1, Ordering::SeqCst);
        SLICE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b62c(obj, dest_ptr) };
        assert_eq!(AT_ADDR.load(Ordering::SeqCst), (obj as usize).wrapping_add(6));
        assert_eq!(dest, obj);
        assert_eq!(unsafe { rc_of(obj) }, 6);
        assert_eq!(SLICE_HITS.load(Ordering::SeqCst), 0);

        // Shrink lane: first at-call serves 0x5c (real class holds,
        // n 3→2) then 0x41 (releases) → break at 2 → 3!=2 →
        // slice(obj,1,2,dest).
        AT_SEQ.store(0, Ordering::SeqCst);
        SLICE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b62c(obj, dest_ptr) };
        assert_eq!(SLICE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SLICE_B.load(Ordering::SeqCst), 1);
        assert_eq!(SLICE_C.load(Ordering::SeqCst), 2);
        assert_eq!(SLICE_D.load(Ordering::SeqCst), dest_ptr as usize);
    }
}
