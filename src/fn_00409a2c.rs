//! Original procedure `0x00409a2c` (39 bytes, `0x00409a2c–0x00409a52`).
//! Evidence: `evidence/00409a2c_fn_00409a2c.md`.

unsafe extern "C" fn default_query() -> *const u8 {
    core::ptr::null()
}

/// Target `0x00402e88` (`FUN_00402e88`), no args; result feeds the
/// match call as its object.
///
/// ponytail: hook standing in for done `fn_00402e88` (which
/// returns the DATA pointer), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00402e88: unsafe extern "C" fn() -> *const u8 = default_query;

/// Target `0x0040392c` (`FUN_0040392c`): rewired to
/// `crate::fn_0040392c::fn_0040392c` (signatures match exactly).
use crate::fn_0040392c::fn_0040392c;

/// Target `0x00402ec8` (`FUN_00402ec8`), no args; result stored to
/// `[param_1+0xc]`: direct intra-reconstruction call (rewired;
/// signatures verified `fn() -> u32`).

/// Dword VALUE at absolute `0x00406d5c` (`PTR_PTR_00406d5c`,
/// nominally `PTR_LAB_00406db4`), passed by value as the match
/// key (no dereference at this site).
///
/// ponytail: absolute-address cell modeled as mutable seed
/// static, upgrade to real image-relative import once data layout
/// proven.
pub static mut DATA_00406D5C: u32 = 0;

/// `if [p+0x14]!=0 { r=match(query(), [0x00406d5c]);
/// if (r&0xff)!=0 { [p+0xc]=take() } }`. `p1` arrives in EAX
/// (saved to EBX, the store base) per Ghidra `__register`
/// observation. Flag is one byte, slot one dword per observed
/// widths.
pub unsafe fn fn_00409a2c(param_1: *mut u8) {
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0x14) as *const u8) == 0 {
        return;
    }
    let q = HOOK_00402e88();
    let r = fn_0040392c(q, DATA_00406D5C);
    if r & 0xff == 0 {
        return;
    }
    let v = crate::fn_00402ec8::fn_00402ec8();
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, v);
}

#[cfg(test)]
mod tests {
    use super::{DATA_00406D5C, HOOK_00402e88, fn_00409a2c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static Q_HITS: AtomicUsize = AtomicUsize::new(0);
    static Q_RET: AtomicUsize = AtomicUsize::new(0);

    static mut TAKE_INNER: [u32; 3] = [0; 3];
    static mut TAKE_CTX: *const u8 = core::ptr::null();

    unsafe extern "C" fn query() -> *const u8 {
        Q_HITS.fetch_add(1, Ordering::SeqCst);
        Q_RET.load(Ordering::SeqCst) as *const u8
    }

    /// TLS slot behind real `fn_00402ec8` → real `fn_00406588`:
    /// returns the take-slot address.
    unsafe extern "C" fn tls_get_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(TAKE_CTX) as *const u8
    }

    const NODE_OFF: usize = 0x30;

    unsafe fn set_link(node: *mut u8, cell: *const *const u8) {
        core::ptr::write_unaligned(node.wrapping_byte_sub(NODE_OFF) as *mut *const *const u8, cell);
    }

    unsafe fn obj_holding(inner: *const u8) -> [u8; 8] {
        let mut obj = [0u8; 8];
        core::ptr::write_unaligned(obj.as_mut_ptr() as *mut *const u8, inner);
        obj
    }

    fn reset() {
        Q_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn flag_miss_and_hit_lanes() {
        // Real `fn_00402ec8` → real `fn_00406588` chain: hold both
        // owner locks while programming the TLS slot.
        let _take = crate::fn_00402ec8::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index, old_cb);
        unsafe {
            HOOK_00402e88 = query;
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            old_cb = crate::fn_00402ec8::HOOK_00413020;
            // Take lane observed through the real chain.
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_get_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            crate::fn_00402ec8::HOOK_00413020 = None;
        }
        // Feasible buffer: flag at +0x14, slot at +0xc.
        let mut buf = [0u8; 0x18];
        let p = buf.as_mut_ptr();
        // Flag-zero lane: nothing fires, slot kept.
        reset();
        unsafe {
            *p.wrapping_byte_add(0x14) = 0;
            *p.wrapping_byte_add(0xc).cast::<u32>() = 0x1111_1111;
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x1111_1111);
        }
        assert_eq!(Q_HITS.load(Ordering::SeqCst), 0);
        // Miss lane: real 0040392c on a null-linked node returns 0 →
        // low byte zero, no take, slot kept.
        let mut b0 = [0u8; 0x40];
        let (obj0, key0) = unsafe {
            let n0 = b0.as_mut_ptr().add(NODE_OFF);
            set_link(n0, core::ptr::null());
            (obj_holding(n0), 0x12345678u32)
        };
        Q_RET.store(obj0.as_ptr() as usize, Ordering::SeqCst);
        reset();
        unsafe {
            DATA_00406D5C = key0;
            *p.wrapping_byte_add(0x14) = 1;
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x1111_1111);
        }
        assert_eq!(Q_HITS.load(Ordering::SeqCst), 1);
        // Hit lane: key == inner node address → low byte forced 1 →
        // real take stored (and its slot cleared).
        let mut b1 = [0u8; 0x40];
        let obj1 = unsafe {
            let n1 = b1.as_mut_ptr().add(NODE_OFF);
            DATA_00406D5C = n1 as u32;
            obj_holding(n1)
        };
        Q_RET.store(obj1.as_ptr() as usize, Ordering::SeqCst);
        reset();
        unsafe {
            TAKE_INNER = [0, 0, 0x9e37_79b9];
            TAKE_CTX = TAKE_INNER.as_ptr() as *const u8;
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x9e37_79b9);
            assert_eq!(TAKE_INNER[2], 0);
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
            crate::fn_00402ec8::HOOK_00413020 = old_cb;
        }
    }
}
