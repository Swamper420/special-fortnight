//! Original procedure `0x004097f0` (27 bytes, `0x004097f0–0x0040980a`).
//! Evidence: `evidence/004097f0_fn_004097f0.md`.

unsafe extern "C" fn default_make(_slot: usize, _flag: u8, _ctx: usize, _arg: usize) -> usize {
    0
}

unsafe extern "C" fn default_consume(_p: usize) {}

/// Target `0x004098e0` (`FUN_004098e0`); lanes per ASSEMBLY:
/// `EAX=[0x00406dd8]`, `DL=1`, `ECX=[0x00412bb8]`, stack=`entry EAX`.
/// Returns the DATA pointer the tail consumes.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004098e0` once it exists.
pub static mut HOOK_004098E0: unsafe extern "C" fn(usize, u8, usize, usize) -> usize = default_make;

/// Tail target `0x00403f88` (`FUN_00403f88`), reached by `JMP` with the
/// maker result in `EAX`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00403f88` once it exists.
pub static mut TAIL_00403F88: unsafe extern "C" fn(usize) = default_consume;

/// Data cell `0x00406dd8`, read as an address (`MOV EAX,[0x00406dd8]`).
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_00406DD8: usize = 0;

/// Data cell `0x00412bb8`, read as an address (`MOV ECX,[0x00412bb8]`).
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_00412BB8: usize = 0;

/// `tail(make(*0x00406dd8, 1, *0x00412bb8, entry_eax))`. No params per
/// Ghidra `__register` observation, but ASSEMBLY consumes entry `EAX`,
/// so it is an explicit lane.
pub unsafe fn fn_004097f0(entry_eax: usize) {
    let p = HOOK_004098E0(DAT_00406DD8, 1, DAT_00412BB8, entry_eax);
    TAIL_00403F88(p);
}

/// Test-only serialization for tests sharing the maker/tail hooks.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{DAT_00406DD8, DAT_00412BB8, HOOK_004098E0, TAIL_00403F88, fn_004097f0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static MAKE_A: AtomicUsize = AtomicUsize::new(0);
    static MAKE_B: AtomicUsize = AtomicUsize::new(0);
    static MAKE_C: AtomicUsize = AtomicUsize::new(0);
    static MAKE_D: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn make(slot: usize, flag: u8, ctx: usize, arg: usize) -> usize {
        MAKE_HITS.fetch_add(1, Ordering::SeqCst);
        MAKE_A.store(slot, Ordering::SeqCst);
        MAKE_B.store(flag as usize, Ordering::SeqCst);
        MAKE_C.store(ctx, Ordering::SeqCst);
        MAKE_D.store(arg, Ordering::SeqCst);
        0xd004
    }

    unsafe extern "C" fn consume(p: usize) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(p, Ordering::SeqCst);
    }

    #[test]
    fn maker_lanes_and_tail() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004098E0 = make;
            TAIL_00403F88 = consume;
            DAT_00406DD8 = 0xa001;
            DAT_00412BB8 = 0xb002;
        }
        unsafe { fn_004097f0(0xc003) };
        assert_eq!(MAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MAKE_A.load(Ordering::SeqCst), 0xa001);
        assert_eq!(MAKE_B.load(Ordering::SeqCst), 1);
        assert_eq!(MAKE_C.load(Ordering::SeqCst), 0xb002);
        assert_eq!(MAKE_D.load(Ordering::SeqCst), 0xc003);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0xd004);
    }
}
