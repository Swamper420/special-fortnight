//! Original procedure `0x0040b2e0` (58 bytes, `0x0040b2e0–0x0040b319`).
//! Evidence: `evidence/0040b2e0_fn_0040b2e0.md`.

unsafe extern "C" fn default_tag(_obj: usize) -> *mut u16 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_class(_w: u16) -> u32 {
    0
}

unsafe extern "C" fn default_take(_a: *mut u8, _b: *mut u8, _c: *mut u8) {}

unsafe extern "C" fn default_store(_slot: *mut u8, _src: *mut u8) {}

/// Tag lookup `0x0040b5fc` (`FUN_0040b5fc`), called with the object
/// address; returns the tag-word pointer (`short *`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b5fc` once it exists.
pub static mut HOOK_0040B5FC: unsafe extern "C" fn(usize) -> *mut u16 = default_tag;

/// Classifier `0x0040b334` (`FUN_0040b334`), called with the tag word;
/// only its low byte is tested (`TEST AL,AL`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b334` once it exists.
pub static mut HOOK_0040B334: unsafe extern "C" fn(u16) -> u32 = default_class;

/// Target `0x00405058` (`FUN_00405058`), zero-tag lane with
/// `(param_2, param_1, &DAT_0040b328)`.
///
/// ponytail: hook mirroring done `fn_00405058`'s shape, rewire to
/// the real call once cross-module test serialization exists (its
/// own test mutates its hook globals lockless).
pub static mut HOOK_00405058: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_take;

/// Target `0x00404c98` (`FUN_00404c98`), null/tagged lane with
/// `(param_2, param_1)`.
///
/// ponytail: hook mirroring done `fn_00404c98`'s shape, rewire to
/// the real call once cross-module test serialization exists (its
/// own test mutates shared hook globals under its own locks).
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u8, *mut u8) = default_store;

/// Cell observed as `DAT_0040b328`; image bytes are `u32 0x5c`
/// followed by code, so one 4-byte word traveling by address as
/// the third arg where the callee compares it against `*p1`
/// (sentinel tag, not a string).
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_0040b328: u32 = 0x5c;

/// `if p1 { if class(*tag(p1))&0xff==0 { take(p2,p1,&DAT); ret } }
/// store(p2,p1)`. `param_1` arrives in EAX, `param_2` in EDX per
/// Ghidra `__register` observation. EBX/ESI saves and the
/// `MOV EAX,EBX` shuffle have no Rust equivalent.
pub unsafe fn fn_0040b2e0(param_1: *mut u8, param_2: *mut u8) {
    if !param_1.is_null() {
        let tagged: *mut u16 = HOOK_0040B5FC(param_1 as usize);
        let w: u16 = core::ptr::read_unaligned(tagged as *const u16);
        if (HOOK_0040B334(w) & 0xff) == 0 {
            HOOK_00405058(
                param_2,
                param_1,
                core::ptr::addr_of_mut!(DAT_0040b328) as *mut u8,
            );
            return;
        }
    }
    HOOK_00404C98(param_2, param_1);
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040b328, HOOK_00405058, HOOK_00404C98, HOOK_0040B334, HOOK_0040B5FC, fn_0040b2e0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAG_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAG_ARG: AtomicUsize = AtomicUsize::new(0);
    static CLASS_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLASS_ARG: AtomicUsize = AtomicUsize::new(0);
    static CLASS_RET: AtomicUsize = AtomicUsize::new(0);
    static TAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAKE_A: AtomicUsize = AtomicUsize::new(0);
    static TAKE_B: AtomicUsize = AtomicUsize::new(0);
    static TAKE_C: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_A: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);

    static mut WORD: u16 = 0;

    unsafe extern "C" fn tag(obj: usize) -> *mut u16 {
        TAG_HITS.fetch_add(1, Ordering::SeqCst);
        TAG_ARG.store(obj, Ordering::SeqCst);
        core::ptr::addr_of_mut!(WORD)
    }

    unsafe extern "C" fn class(w: u16) -> u32 {
        CLASS_HITS.fetch_add(1, Ordering::SeqCst);
        CLASS_ARG.store(w as usize, Ordering::SeqCst);
        CLASS_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn take(a: *mut u8, b: *mut u8, c: *mut u8) {
        TAKE_HITS.fetch_add(1, Ordering::SeqCst);
        TAKE_A.store(a as usize, Ordering::SeqCst);
        TAKE_B.store(b as usize, Ordering::SeqCst);
        TAKE_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn store(a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_A.store(a as usize, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    fn clear() {
        TAG_HITS.store(0, Ordering::SeqCst);
        CLASS_HITS.store(0, Ordering::SeqCst);
        TAKE_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn null_tagged_zero_tag_lanes() {
        // Own hooks/cell only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_0040B5FC = tag;
            HOOK_0040B334 = class;
            HOOK_00405058 = take;
            HOOK_00404C98 = store;
        }
        let mut o = 0u8;
        let mut s = 0u8;
        let p1 = &mut o as *mut u8;
        let p2 = &mut s as *mut u8;
        // Null lane: no tag/class/take, store(p2, p1).
        clear();
        unsafe { fn_0040b2e0(core::ptr::null_mut(), p2) };
        assert_eq!(TAG_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(STORE_B.load(Ordering::SeqCst), 0);
        // Tagged lane: class low byte nonzero → store(p2, p1).
        unsafe { WORD = 0x25c };
        CLASS_RET.store(0x101, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b2e0(p1, p2) };
        assert_eq!(TAG_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAG_ARG.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLASS_ARG.load(Ordering::SeqCst), 0x25c);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(STORE_B.load(Ordering::SeqCst), p1 as usize);
        // Zero-tag lane: take(p2, p1, &DAT), no store.
        CLASS_RET.store(0x500, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b2e0(p1, p2) };
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(TAKE_B.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(
            TAKE_C.load(Ordering::SeqCst),
            core::ptr::addr_of!(DAT_0040b328) as usize
        );
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);
    }
}
