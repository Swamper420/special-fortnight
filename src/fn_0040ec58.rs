//! Original procedure `0x0040ec58` (67 bytes, `0x0040ec58–0x0040ec9a`).
//! Evidence: `evidence/0040ec58_fn_0040ec58.md`.

unsafe extern "C" fn default_format(
    _ctx: *mut u32,
    _flag: u8,
    _msg: *const u8,
) -> u32 {
    0
}

unsafe extern "C" fn default_raise(_msg: u32) {}

/// Image-absolute dword cell (`mov addr,%reg` in the original).
/// Reads 32 bits and zero-extends: image addresses fit either way,
/// and a 64-bit host must not swallow adjacent stack bytes.
unsafe fn img_ptr(addr: u32) -> *const u8 {
    core::ptr::read_unaligned(addr as *const u32) as usize as *const u8
}

/// Context observed at `[0x00406d5c]`, EAX lane of `0x00409824` both branches.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CTX_00406d5c: *mut u32 = core::ptr::null_mut();

/// Literal at `0x0040eca8`, ECX lane of `0x00409824` on the null-slot path.
///
/// ponytail: NUL-terminated `u8` ceiling; encoding/terminator unproven,
/// rewire to proven bytes once string bytes proven.
pub static FALLBACK_MSG_0040eca8: &[u8] =
    b"The setup files are corrupted. Please obtain a new copy of the program.\0";

/// Target `0x00409824` (`FUN_00409824`), lanes `(EAX=ctx, DL=flag, ECX=msg)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00409824` once it exists.
pub static mut FORMAT_00409824: unsafe extern "C" fn(*mut u32, u8, *const u8) -> u32 =
    default_format;

/// Target `0x00403f88` (`FUN_00403f88`), EAX lane = `0x00409824` return.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00403f88` once it exists.
pub static mut RAISE_00403f88: unsafe extern "C" fn(u32) = default_raise;

/// Fatal helper: slot `!= 0` formats stored message, else formats fallback;
/// then raises formatted value. No params, void return.
pub unsafe fn fn_0040ec58() {
    let base = img_ptr(0x00412c08);
    let slot = core::ptr::read_unaligned(base.wrapping_byte_add(0x278) as *const u32);
    if slot != 0 {
        let msg = core::ptr::read_unaligned(
            base.wrapping_byte_add(0x278) as *const u32
        ) as *const u8;
        let ctx = CTX_00406d5c;
        let out = FORMAT_00409824(ctx, 1, msg);
        RAISE_00403f88(out);
        return;
    }
    let ctx = CTX_00406d5c;
    let out = FORMAT_00409824(ctx, 1, FALLBACK_MSG_0040eca8.as_ptr());
    RAISE_00403f88(out);
}

#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{
        CTX_00406d5c, FALLBACK_MSG_0040eca8, FORMAT_00409824,
        RAISE_00403f88, TEST_LOCK, fn_0040ec58,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FMT_CTX: AtomicUsize = AtomicUsize::new(0);
    static FMT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static FMT_MSG: AtomicUsize = AtomicUsize::new(0);
    static FMT_HITS: AtomicUsize = AtomicUsize::new(0);
    static FMT_RET: AtomicUsize = AtomicUsize::new(0);
    static RAISE_ARG: AtomicUsize = AtomicUsize::new(0);
    static RAISE_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn format(
        ctx: *mut u32,
        flag: u8,
        msg: *const u8,
    ) -> u32 {
        FMT_CTX.store(ctx as usize, Ordering::SeqCst);
        FMT_FLAG.store(flag as usize, Ordering::SeqCst);
        FMT_MSG.store(msg as usize, Ordering::SeqCst);
        FMT_HITS.fetch_add(1, Ordering::SeqCst);
        FMT_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn raise(msg: u32) {
        RAISE_ARG.store(msg as usize, Ordering::SeqCst);
        RAISE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn slot_selects_stored_or_fallback_message() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Body reads the image cell `[0x00412c08]+0x278`: map the image
        // on Linux, drive the slot through the private mapping.
        #[cfg(target_os = "linux")]
        crate::host_image::map_original_image();
        static mut CTX_CELL: u32 = 0;
        // Slot address: [0x00412c08] -> base, +0x278 (u32 cell,
        // zero-extended: a 64-bit host must not read adjacent bytes).
        let slot_ptr = unsafe {
            let base =
                core::ptr::read_unaligned(0x00412c08 as *const u32) as usize as *const u8;
            base.wrapping_byte_add(0x278) as *mut u32
        };
        let saved = unsafe { core::ptr::read_unaligned(slot_ptr) };
        unsafe {
            CTX_00406d5c = core::ptr::addr_of_mut!(CTX_CELL);
            FORMAT_00409824 = format;
            RAISE_00403f88 = raise;
            FMT_RET.store(0x77, Ordering::SeqCst);
            // Null slot: fallback literal lane, DL=1, raise passthrough.
            core::ptr::write_unaligned(slot_ptr, 0);
            FMT_HITS.store(0, Ordering::SeqCst);
            RAISE_HITS.store(0, Ordering::SeqCst);
            fn_0040ec58();
            assert_eq!(FMT_CTX.load(Ordering::SeqCst), CTX_00406d5c as usize);
            assert_eq!(FMT_FLAG.load(Ordering::SeqCst), 1);
            assert_eq!(
                FMT_MSG.load(Ordering::SeqCst),
                FALLBACK_MSG_0040eca8.as_ptr() as usize
            );
            assert_eq!(FMT_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(RAISE_ARG.load(Ordering::SeqCst), 0x77);
            assert_eq!(RAISE_HITS.load(Ordering::SeqCst), 1);
            // Nonzero slot: stored u32 value becomes message pointer.
            core::ptr::write_unaligned(slot_ptr, 0x1234);
            FMT_HITS.store(0, Ordering::SeqCst);
            RAISE_HITS.store(0, Ordering::SeqCst);
            fn_0040ec58();
            assert_eq!(FMT_MSG.load(Ordering::SeqCst), 0x1234);
            assert_eq!(FMT_FLAG.load(Ordering::SeqCst), 1);
            assert_eq!(FMT_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(RAISE_HITS.load(Ordering::SeqCst), 1);
            core::ptr::write_unaligned(slot_ptr, saved);
        }
    }
}
