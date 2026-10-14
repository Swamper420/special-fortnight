//! Original procedure `0x00404318` (72 bytes, `0x404318–0x40435f`).
//! Evidence: `evidence/00404318_fn_00404318.md`.

unsafe extern "C" fn default_resolve(_a: u32, _b: *mut *mut u8) {}

/// First callee `0x4063e4` (`FUN_004063e4`): `(EAX=param_1, EDX=&local)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004063e4` once it exists.
pub static mut HOOK_004063E4: unsafe extern "C" fn(u32, *mut *mut u8) = default_resolve;

unsafe extern "C" fn default_attach(_a: *mut u8, _b: *mut u8, _c: u32) {}

/// Second callee `0x404e94` (`FUN_00404e94`):
/// `(EAX=param_2, EDX=local, ECX=0)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00404e94` once it exists.
pub static mut HOOK_00404E94: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_attach;

/// Handler pushed at `0x404326` for the unwind window.
pub const HANDLER_00404360: u32 = 0x00404360;

/// Inline SEH record: `prev/handler/ebp` at `+0/+4/+8`
/// (`PUSH EBP; PUSH handler; PUSH FS:[0]; FS:[0]=ESP`).
#[repr(C)]
pub struct SehRecord00404318 {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record (`PUSH EBP` at `0x404325`).
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_00404318: u32 = 0;

/// Resolve-attach-release: `local=0; resolve(param_1,&local);
/// attach(param_2,local,0); release(&local)`. `param_1` (EAX) is an
/// opaque passthrough value; `param_2` (EDX) an opaque handle. Head
/// links through owner `crate::fn_004039e4::SEH_HEAD_FS0` (no duplicate
/// cell); release is the reconstructed `fn_004046c4` (via thunk
/// `0x404c88`), called after the SEH unlink per assembly.
///
/// ponytail: the `PUSH 0x404367` before the release call has no
/// decompiler counterpart and no stack-arg reader in the callee;
/// left unmodeled.
pub unsafe fn fn_00404318(param_1: u32, param_2: *mut u8) {
    let mut local: *mut u8 = core::ptr::null_mut();
    let mut record = SehRecord00404318 {
        prev: crate::fn_004039e4::SEH_HEAD_FS0,
        handler: HANDLER_00404360,
        ebp: EBP_00404318,
    };
    crate::fn_004039e4::SEH_HEAD_FS0 = &mut record as *mut _ as *mut u8;
    HOOK_004063E4(param_1, &mut local as *mut *mut u8);
    let attached = local;
    HOOK_00404E94(param_2, attached, 0);
    crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    crate::fn_004046c4::fn_004046c4(&mut local as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404E94, HOOK_004063E4, fn_00404318};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_AT: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_A1: AtomicUsize = AtomicUsize::new(0);
    static PLANT: AtomicUsize = AtomicUsize::new(0);
    static ATTACH_AT: AtomicUsize = AtomicUsize::new(0);
    static ATTACH_A1: AtomicUsize = AtomicUsize::new(0);
    static ATTACH_A2: AtomicUsize = AtomicUsize::new(0);
    static ATTACH_A3: AtomicUsize = AtomicUsize::new(0);
    static HEAD_SEEN: AtomicUsize = AtomicUsize::new(0);
    static PREV_SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn resolve(a1: u32, out: *mut *mut u8) {
        RESOLVE_A1.store(a1 as usize, Ordering::SeqCst);
        RESOLVE_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        core::ptr::write_unaligned(out, PLANT.load(Ordering::SeqCst) as *mut u8);
    }

    unsafe extern "C" fn attach(a1: *mut u8, a2: *mut u8, a3: u32) {
        ATTACH_A1.store(a1 as usize, Ordering::SeqCst);
        ATTACH_A2.store(a2 as usize, Ordering::SeqCst);
        ATTACH_A3.store(a3 as usize, Ordering::SeqCst);
        ATTACH_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        let head = crate::fn_004039e4::SEH_HEAD_FS0;
        HEAD_SEEN.store(head as usize, Ordering::SeqCst);
        PREV_SEEN.store(
            core::ptr::read_unaligned(head as *const *mut u8) as usize,
            Ordering::SeqCst,
        );
    }

    #[test]
    fn resolve_attach_release_lanes() {
        let _seh = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004063E4 = resolve;
            HOOK_00404E94 = attach;
            let mut tag = [0u8; 4];

            // Null-out lane: attach observes (param_2, null, 0),
            // release no-ops on the null slot.
            PLANT.store(0, Ordering::SeqCst);
            SEQ.store(0, Ordering::SeqCst);
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404318(0x1234, tag.as_mut_ptr());
            assert_eq!(RESOLVE_A1.load(Ordering::SeqCst), 0x1234);
            assert_eq!(RESOLVE_AT.load(Ordering::SeqCst), 0);
            assert_eq!(ATTACH_A1.load(Ordering::SeqCst), tag.as_mut_ptr() as usize);
            assert_eq!(ATTACH_A2.load(Ordering::SeqCst), 0);
            assert_eq!(ATTACH_A3.load(Ordering::SeqCst), 0);
            assert_eq!(ATTACH_AT.load(Ordering::SeqCst), 1);
            assert_ne!(HEAD_SEEN.load(Ordering::SeqCst), 0x777);
            assert_eq!(PREV_SEEN.load(Ordering::SeqCst), 0x777);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);

            // Live-object lane: count-0 arena object is observed by
            // attach, then cleared by release without destructor fire.
            let mut arena = [0u32; 4];
            let obj = arena.as_mut_ptr() as *mut u8;
            let obj12 = obj.wrapping_byte_add(12);
            PLANT.store(obj12 as usize, Ordering::SeqCst);
            SEQ.store(0, Ordering::SeqCst);
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404318(0x9, tag.as_mut_ptr());
            assert_eq!(ATTACH_A2.load(Ordering::SeqCst), obj12 as usize);
            assert_eq!(RESOLVE_AT.load(Ordering::SeqCst), 0);
            assert_eq!(ATTACH_AT.load(Ordering::SeqCst), 1);
            assert_eq!(arena[1], 0);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);
        }
    }
}
