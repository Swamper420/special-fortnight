//! Original procedure `0x0040e2f8` (247 bytes, `0x40e2f8–0x40e3ee`).
//! Evidence: `evidence/0040e2f8_fn_0040e2f8.md`.

unsafe extern "C" fn default_retain(_p: i32) {}
unsafe extern "C" fn default_mkname(_d: *mut u8, _s: *mut u32) {}
unsafe extern "C" fn default_take(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_seed(_n: u32) -> u32 {
    0
}
unsafe extern "C" fn default_stat(_s: u32, _o: *mut i32) -> u32 {
    0
}
unsafe extern "C" fn default_msg(_id: u32, _v: u32, _o: *mut u8) {}
unsafe extern "C" fn default_mkmsg(_e: *mut u32, _f: u8, _s: u32) -> *mut u32 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_fatal(_m: *mut u32) {}
unsafe extern "C" fn default_name(_id: u32, _d: *mut u32) {}
unsafe extern "C" fn default_alloc(_d: *mut u32, _n: u32) {}
unsafe extern "C" fn default_gate(_f: u8, _s: u32) -> u8 {
    0
}
unsafe extern "C" fn default_store(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_free(_s: *mut u32, _n: u32) {}

/// ponytail: hook for `thunk 0x404c80` (retain).
pub static mut HOOK_0040493C: unsafe extern "C" fn(i32) = default_retain;
/// ponytail: hook for `fn_0040b2e0`.
pub static mut HOOK_0040B2E0: unsafe extern "C" fn(*mut u8, *mut u32) = default_mkname;
/// ponytail: hook for `fn_00404cec`.
pub static mut HOOK_00404CEC: unsafe extern "C" fn(*mut u32, u32) = default_take;
/// ponytail: hook for `fn_004030e4` (seed).
pub static mut HOOK_004030E4: unsafe extern "C" fn(u32) -> u32 = default_seed;
/// ponytail: hook for `fn_0040b62c`.
pub static mut HOOK_0040B62C: unsafe extern "C" fn(u32, *mut i32) -> u32 = default_stat;
/// Target `0x40df20` cycle-fatal message.
///
/// ponytail: hook standing in for same-batch `fn_0040df20`.
pub static mut HOOK_0040DF20: unsafe extern "C" fn(u32, u32, *mut u8) = default_msg;
/// ponytail: hook for `fn_00409824`.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u32, u8, u32) -> *mut u32 = default_mkmsg;
/// ponytail: hook for `fn_00403f88`.
pub static mut HOOK_00403F88: unsafe extern "C" fn(*mut u32) = default_fatal;
/// Target `0x40e280` name encoder.
///
/// ponytail: hook standing in for same-batch `fn_0040e280`.
pub static mut HOOK_0040E280: unsafe extern "C" fn(u32, *mut u32) = default_name;
/// ponytail: hook for `fn_0040513c`.
pub static mut HOOK_0040513C: unsafe extern "C" fn(*mut u32, u32) = default_alloc;
/// Target `0x40e1e0` gate.
///
/// ponytail: hook standing in for same-batch `fn_0040e1e0`.
pub static mut HOOK_0040E1E0: unsafe extern "C" fn(u8, u32) -> u8 = default_gate;
/// ponytail: hook for `fn_00404c98`.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_store;
/// ponytail: hook for `thunk 0x404c90` (sized free).
pub static mut HOOK_004046E8: unsafe extern "C" fn(*mut u32, u32) = default_free;

/// Temp-name hunt loop; stores found token to `*param_4`.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040e2f8(param_1: u8, param_2: *mut u8, param_3: u32, param_4: *mut u32) {
    HOOK_0040493C(param_2 as i32);
    let mut cur: u32 = 0;
    let mut tmp: u32 = 0;
    HOOK_0040B2E0(param_2, &mut tmp);
    HOOK_00404CEC(&mut cur, tmp);
    let seed = HOOK_004030E4(0x2000000);
    // ponytail: `INC; CMP 0x1ffffff; JLE / XOR` wrap + `CMP seed; JNZ` cycle-fatal order matches.
    let mut ctr = seed;
    loop {
        ctr = ctr.wrapping_add(1);
        if (ctr as i32) > 0x1ffffff {
            ctr = 0;
        }
        if seed == ctr {
            let mut v: i32 = 0;
            let st = HOOK_0040B62C(cur, &mut v);
            // ponytail: `CONCAT31(st>>8, 0x4c)` id shape preserved.
            let id = (st & 0xffffff00) | 0x4c;
            let mut tok: u32 = 0;
            HOOK_0040DF20(id, v as u32, (&mut tok as *mut u32) as *mut u8);
            let m = HOOK_00409824(&mut 0u32, 1, tok);
            HOOK_00403F88(m);
        }
        let mut name: u32 = 0;
        HOOK_0040E280(ctr, &mut name);
        let _saved = param_3;
        let mut tok: u32 = 0;
        HOOK_0040513C(&mut tok, 4);
        let g = HOOK_0040E1E0(param_1, tok);
        if g == 0 {
            break;
        }
    }
    HOOK_00404C98(param_4, tmp);
    // ponytail: SEH frame not modeled — test-platform init detail.
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    HOOK_004046E8(&mut a, 4);
    HOOK_004046E8(&mut b, 2);
    let _ = cur;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GATE: AtomicUsize = AtomicUsize::new(0);
    static FATALS: AtomicUsize = AtomicUsize::new(0);
    static STORED: AtomicUsize = AtomicUsize::new(0);
    static NAMES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn seed(_n: u32) -> u32 {
        0x100
    }
    unsafe extern "C" fn name(_id: u32, _d: *mut u32) {
        NAMES.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn alloc(d: *mut u32, _n: u32) {
        *d = 0x61;
    }
    unsafe extern "C" fn gate(_f: u8, _s: u32) -> u8 {
        GATE.load(Ordering::SeqCst) as u8
    }
    unsafe extern "C" fn store(d: *mut u32, s: u32) {
        STORED.store(s as usize, Ordering::SeqCst);
        *d = s;
    }
    unsafe extern "C" fn fatal(_m: *mut u32) {
        FATALS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        unsafe {
            HOOK_004030E4 = seed;
            HOOK_0040E280 = name;
            HOOK_0040513C = alloc;
            HOOK_0040E1E0 = gate;
            HOOK_00404C98 = store;
            HOOK_00403F88 = fatal;
        }
    }

    #[test]
    fn exits_first_iter_and_stores() {
        reset();
        GATE.store(0, Ordering::SeqCst);
        NAMES.store(0, Ordering::SeqCst);
        FATALS.store(0, Ordering::SeqCst);
        let mut out = 0u32;
        unsafe { fn_0040e2f8(0, core::ptr::null_mut(), 0, &mut out) };
        assert_eq!(NAMES.load(Ordering::SeqCst), 1);
        assert_eq!(FATALS.load(Ordering::SeqCst), 0);
        assert_eq!(STORED.load(Ordering::SeqCst), 0); // tmp from null mkname hook
    }
}
