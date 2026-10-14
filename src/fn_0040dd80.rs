//! Original procedure `0x0040dd80` (303 bytes, `0x40dd80–0x40deae`).
//! Evidence: `evidence/0040dd80_fn_0040dd80.md`.

unsafe extern "C" fn default_init(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_push(_d: *mut u8, _s: u32) {}
unsafe extern "C" fn default_mkprefix(_d: *mut u32, _s: *mut u8, _n: i32) {}
unsafe extern "C" fn default_tail(_d: *mut u32, _s: *mut u8) {}
unsafe extern "C" fn default_scan(_s: *mut u8, _ch: u16) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_free(_s: *mut u32) {}

/// ponytail: hook for `fn_00404c98` (init).
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_init;
/// ponytail: hook for `fn_00404f98` (token push).
pub static mut HOOK_00404F98: unsafe extern "C" fn(*mut u8, u32) = default_push;
/// ponytail: hook for `fn_00404dd4` (prefix slice).
pub static mut HOOK_00404DD4: unsafe extern "C" fn(*mut u32, *mut u8, i32) = default_mkprefix;
/// ponytail: hook for `fn_00404e14` (tail convert).
pub static mut HOOK_00404E14: unsafe extern "C" fn(*mut u32, *mut u8) = default_tail;
/// ponytail: hook for `thunk 0x4081d0` (`strchr(s,0x25)`-shaped scan).
pub static mut HOOK_004081D0: unsafe extern "C" fn(*mut u8, u16) -> *mut u8 = default_scan;
/// ponytail: hook for `thunk 0x404c88` (cleanup).
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u32) = default_free;

/// Format-scan decoder: init, null-guard, `%`-scan loop, tail convert, dual cleanup.
/// `param_1` EAX / `param_2` EDX (table base) / `param_3` ECX (max index) per observation.
pub unsafe fn fn_0040dd80(param_1: *mut u8, param_2: u32, param_3: i32, param_4: *mut u8) {
    HOOK_00404C98(param_4 as *mut u32, 0);
    if param_1.is_null() {
        goto_cleanup();
        return;
    }
    let mut cur = param_1;
    loop {
        let hit = HOOK_004081D0(cur, 0x25);
        if hit.is_null() {
            break;
        }
        let mut pre: u32 = 0;
        if cur != hit {
            // ponytail: `(hit-cur)>>1` with `JNS/ADC` round-up; byte diff assumed even.
            let diff = (hit as usize).wrapping_sub(cur as usize) as i32;
            let mut n = diff >> 1;
            if n < 0 {
                n += ((diff & 1) != 0) as i32;
            }
            HOOK_00404DD4(&mut pre, cur, n);
            HOOK_00404F98(param_4, pre);
            cur = hit;
        }
        let code = core::ptr::read_unaligned(hit.wrapping_byte_add(2) as *const u16);
        // ponytail: `DAT_0040dec0` bit-table not dumped; hook stands in for the BT+range gate.
        let known = HOOK_0040DEC0_GATE(code, param_3);
        if !known {
            HOOK_00404F98(param_4, DAT_0040DEEC);
            cur = hit.wrapping_byte_add(2);
            if code == 0x25 {
                cur = hit.wrapping_byte_add(4);
            }
        } else {
            let entry = core::ptr::read_unaligned(
                (param_2.wrapping_sub(0xc4).wrapping_add((code as u32).wrapping_mul(4))) as *const u32,
            );
            HOOK_00404F98(param_4, entry);
            cur = hit.wrapping_byte_add(4);
        }
    }
    let mut tail: u32 = 0;
    HOOK_00404E14(&mut tail, cur);
    HOOK_00404F98(param_4, tail);
    goto_cleanup();

    unsafe fn goto_cleanup() {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        HOOK_00404C88(&mut a);
        HOOK_00404C88(&mut b);
    }
}

/// Bit/range gate over `DAT_0040dec0` + `code-0x31 <= max`.
///
/// ponytail: table bytes not dumped; default hook models "unknown code" (false).
/// Override in tests to model a known code.
pub static mut HOOK_0040DEC0_GATE: unsafe extern "C" fn(u16, i32) -> bool = default_gate;
unsafe extern "C" fn default_gate(_c: u16, _m: i32) -> bool {
    false
}

/// Default token `DAT_0040deec` value slot.
///
/// ponytail: address-named static; bytes unproven, default 0.
pub static mut DAT_0040DEEC: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INITS: AtomicUsize = AtomicUsize::new(0);
    static PUSHES: AtomicUsize = AtomicUsize::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static TAILS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn init(_d: *mut u32, _s: u32) {
        INITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn push(_d: *mut u8, _s: u32) {
        PUSHES.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn tail(d: *mut u32, _s: *mut u8) {
        TAILS.fetch_add(1, Ordering::SeqCst);
        *d = 0x9;
    }
    unsafe extern "C" fn scan(_s: *mut u8, _c: u16) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn free(_s: *mut u32) {
        FREES.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        INITS.store(0, Ordering::SeqCst);
        PUSHES.store(0, Ordering::SeqCst);
        FREES.store(0, Ordering::SeqCst);
        TAILS.store(0, Ordering::SeqCst);
        unsafe {
            HOOK_00404C98 = init;
            HOOK_00404F98 = push;
            HOOK_00404E14 = tail;
            HOOK_004081D0 = scan;
            HOOK_00404C88 = free;
        }
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn null_input_inits_and_frees() {
        let _lock = LOCK.lock().unwrap();
        reset();
        unsafe { fn_0040dd80(core::ptr::null_mut(), 0, 0, core::ptr::null_mut()) };
        assert_eq!(INITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREES.load(Ordering::SeqCst), 2);
        assert_eq!(TAILS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_escape_tail_push() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let mut buf = [0x41u8; 8];
        unsafe { fn_0040dd80(buf.as_mut_ptr(), 0, 0, core::ptr::null_mut()) };
        assert_eq!(TAILS.load(Ordering::SeqCst), 1);
        assert_eq!(PUSHES.load(Ordering::SeqCst), 1); // tail token only
        assert_eq!(FREES.load(Ordering::SeqCst), 2);
    }
}
