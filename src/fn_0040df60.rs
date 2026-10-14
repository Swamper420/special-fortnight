//! Original procedure `0x0040df60` (23 bytes, `0x40df60–0x40df76`).
//! Evidence: `evidence/0040df60_fn_0040df60.md`.

unsafe extern "C" fn default_mkmsg(_e: *mut u32, _f: u8, _s: *const u8) -> *mut u32 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_fatal(_m: *mut u32) {}

/// Target `0x409824` message-record builder.
///
/// ponytail: hook standing in for out-of-batch `fn_00409824`.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u32, u8, *const u8) -> *mut u32 =
    default_mkmsg;
/// Target `0x403f88` fatal raise.
///
/// ponytail: hook standing in for out-of-batch `fn_00403f88`.
pub static mut HOOK_00403F88: unsafe extern "C" fn(*mut u32) = default_fatal;

/// Format-handle slot `PTR_LAB_00406db4` (`[0x406d5c]`).
///
/// ponytail: address-named static; handle value unknown, default 0.
pub static mut PTR_LAB_00406DB4: u32 = 0;

/// Corrupt-setup abort: build message, raise. No args.
pub unsafe fn fn_0040df60() {
    // ponytail: `MOV ECX,str; MOV DL,1; MOV EAX,[ptr]` setup order matches.
    let msg = HOOK_00409824(
        (&mut PTR_LAB_00406DB4 as *mut u32) as *mut u32,
        1,
        MSG_CORRUPT.as_ptr(),
    );
    HOOK_00403F88(msg);
}

/// NUL-terminated message at `0x40df84` (observed bytes).
pub static MSG_CORRUPT: &[u8] =
    b"The setup files are corrupted. Please obtain a new copy of the program.\0";

#[cfg(test)]
mod tests {
    use super::{HOOK_00403F88, HOOK_00409824, MSG_CORRUPT, fn_0040df60};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MK: AtomicUsize = AtomicUsize::new(0);
    static FATAL: AtomicUsize = AtomicUsize::new(0);
    static FLAG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mkmsg(_e: *mut u32, f: u8, s: *const u8) -> *mut u32 {
        MK.fetch_add(1, Ordering::SeqCst);
        FLAG.store(f as usize, Ordering::SeqCst);
        assert_eq!(s, MSG_CORRUPT.as_ptr());
        0x55 as *mut u32
    }
    unsafe extern "C" fn fatal(m: *mut u32) {
        FATAL.fetch_add(1, Ordering::SeqCst);
        assert_eq!(m as usize, 0x55);
    }

    #[test]
    fn builds_then_raises() {
        unsafe {
            HOOK_00409824 = mkmsg;
            HOOK_00403F88 = fatal;
        }
        MK.store(0, Ordering::SeqCst);
        FATAL.store(0, Ordering::SeqCst);
        unsafe { fn_0040df60() };
        assert_eq!(MK.load(Ordering::SeqCst), 1);
        assert_eq!(FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(FATAL.load(Ordering::SeqCst), 1);
    }
}
