//! Original procedure `0x00406274` (21 bytes, `0x00406274–0x00406288`).
//! Evidence: `evidence/00406274_fn_00406274.md`.

/// Release slot: `obj = *p; if obj { *p = 0; vtbl_call(*(obj)+8)(obj);
/// return obj } else return p`. `param_1` arrives in EAX per Ghidra
/// `__register` observation. Image byte offset `+8` is u32-slot index 2;
/// host reads pointer slot 2 (addresses stay `usize`, never `as u32`).
pub unsafe fn fn_00406274(param_1: *mut usize) -> *mut usize {
    let obj: usize = *(param_1 as *const usize);
    if obj == 0 {
        return param_1;
    }
    *(param_1 as *mut usize) = 0;
    let vtbl: usize = *(obj as *const usize);
    let target: usize = *((vtbl as *const usize).wrapping_add(2));
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(target);
    f(obj as *mut u8);
    obj as *mut usize
}

#[cfg(test)]
mod tests {
    use super::fn_00406274;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(obj: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
    }

    #[test]
    fn clears_slot_and_returns_old_object() {
        // Null slot: no fire, returns slot itself.
        let mut empty: usize = 0;
        HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00406274(&mut empty) };
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        assert_eq!(r as usize, &mut empty as *mut usize as usize);
        assert_eq!(empty, 0);
        // Live object: slot cleared, hook fires once with object,
        // old object returned.
        let vtbl: [usize; 3] = [0, 0, hook as usize];
        let mut obj: [usize; 1] = [vtbl.as_ptr() as usize];
        let mut slot: usize = obj.as_mut_ptr() as usize;
        let r = unsafe { fn_00406274(&mut slot) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_OBJ.load(Ordering::SeqCst), obj.as_ptr() as usize);
        assert_eq!(slot, 0);
        assert_eq!(r as usize, obj.as_ptr() as usize);
    }
}
