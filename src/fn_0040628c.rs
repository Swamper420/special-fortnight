//! Original procedure `0x0040628c` (44 bytes, `0x40628c–0x4062b7`).
//! Evidence: `evidence/0040628c_fn_0040628c.md`.

/// Slot assign with release: `param_1` in EAX, `param_2` in EDX per
/// Ghidra `__register` observation. Null `param_2` takes path A
/// (`old=*p1; *p1=0; if old fire [+8]`); else path B (`fire [+4]` on
/// `*p2`; re-read `old2=*p2`; `*p2=p1`; `if old2 fire [+8]`).
/// Image byte offsets `+4`/`+8` are u32-slot indexes 1/2; host reads
/// pointer slots 1/2 (addresses stay `usize`, never `as u32`).
pub unsafe fn fn_0040628c(param_1: *mut usize, param_2: *mut usize) {
    if (param_2 as usize) == 0 {
        let old: usize = *(param_1 as *const usize);
        *(param_1 as *mut usize) = 0;
        if old != 0 {
            let vtbl: usize = *(old as *const usize);
            let target: usize = *((vtbl as *const usize).wrapping_add(2));
            let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(target);
            f(old as *mut u8);
        }
        return;
    }
    let o2: usize = *(param_2 as *const usize);
    let vtbl2: usize = *(o2 as *const usize);
    let target4: usize = *((vtbl2 as *const usize).wrapping_add(1));
    let f4: unsafe extern "C" fn(*mut u8) = core::mem::transmute(target4);
    f4(o2 as *mut u8);
    let old2: usize = *(param_2 as *const usize);
    *(param_2 as *mut usize) = param_1 as usize;
    if old2 == 0 {
        return;
    }
    let vtbl: usize = *(old2 as *const usize);
    let target: usize = *((vtbl as *const usize).wrapping_add(2));
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(target);
    f(old2 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::fn_0040628c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS4: AtomicUsize = AtomicUsize::new(0);
    static HITS8: AtomicUsize = AtomicUsize::new(0);
    static GOT4: AtomicUsize = AtomicUsize::new(0);
    static GOT8: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook4(obj: *mut u8) {
        HITS4.fetch_add(1, Ordering::SeqCst);
        GOT4.store(obj as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn hook8(obj: *mut u8) {
        HITS8.fetch_add(1, Ordering::SeqCst);
        GOT8.store(obj as usize, Ordering::SeqCst);
    }

    #[test]
    fn assign_paths() {
        HITS4.store(0, Ordering::SeqCst);
        HITS8.store(0, Ordering::SeqCst);
        // Path A, null old: slot stays 0, nothing fires.
        let mut p1: usize = 0;
        unsafe { fn_0040628c(&mut p1, core::ptr::null_mut()) };
        assert_eq!(HITS8.load(Ordering::SeqCst), 0);
        assert_eq!(p1, 0);
        // Path A, live old: slot cleared, [+8] fires once with old.
        let vtbl_a: [usize; 3] = [0, hook4 as usize, hook8 as usize];
        let mut obj_a: [usize; 1] = [vtbl_a.as_ptr() as usize];
        p1 = obj_a.as_mut_ptr() as usize;
        unsafe { fn_0040628c(&mut p1, core::ptr::null_mut()) };
        assert_eq!(p1, 0);
        assert_eq!(HITS8.load(Ordering::SeqCst), 1);
        assert_eq!(GOT8.load(Ordering::SeqCst), obj_a.as_ptr() as usize);
        // Path B: [+4] fires on old *p2, slot takes p1, [+8] fires on old.
        let vtbl_b: [usize; 3] = [0, hook4 as usize, hook8 as usize];
        let mut obj_b: [usize; 1] = [vtbl_b.as_ptr() as usize];
        let mut p1b: usize = 0x1111;
        let mut p2b: usize = obj_b.as_mut_ptr() as usize;
        unsafe { fn_0040628c(&mut p1b, &mut p2b) };
        assert_eq!(HITS4.load(Ordering::SeqCst), 1);
        assert_eq!(GOT4.load(Ordering::SeqCst), obj_b.as_ptr() as usize);
        assert_eq!(HITS8.load(Ordering::SeqCst), 2);
        assert_eq!(GOT8.load(Ordering::SeqCst), obj_b.as_ptr() as usize);
        assert_eq!(p2b, &mut p1b as *mut usize as usize);
        assert_eq!(p1b, 0x1111);
    }
}
