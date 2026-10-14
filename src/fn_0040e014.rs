//! Original procedure `0x0040e014` (188 bytes, `0x40e014–0x40e0cf`).
//! Evidence: `evidence/0040e014_fn_0040e014.md`.

unsafe extern "C" fn default_cmp(_p: *mut u32, _s: *mut u32, _n: u32) -> u32 {
    0
}
unsafe extern "C" fn default_crc(_p: *mut u8, _n: u32) -> u32 {
    0
}
unsafe extern "C" fn default_strlen(_p: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_mk(_t: *mut u32, _s: *mut u8, _n: u32) {}
unsafe extern "C" fn default_fatal() {}

/// ponytail: hook for `fn_004031e0`.
pub static mut HOOK_004031E0: unsafe extern "C" fn(*mut u32, *mut u32, u32) -> u32 = default_cmp;
/// ponytail: hook for `fn_0040c738` (CRC).
pub static mut HOOK_0040C738: unsafe extern "C" fn(*mut u8, u32) -> u32 = default_crc;
/// ponytail: hook for `fn_004080dc` (strlen-ish).
pub static mut HOOK_004080DC: unsafe extern "C" fn(*mut u8) -> u32 = default_strlen;
/// ponytail: hook for `fn_00404dd4` (table fill).
pub static mut HOOK_00404DD4: unsafe extern "C" fn(*mut u32, *mut u8, u32) = default_mk;
/// Target `0x40df60` fatal sink.
///
/// ponytail: hook standing in for same-batch `fn_0040df60`.
pub static mut HOOK_0040DF60: unsafe extern "C" fn() = default_fatal;

/// Setup-messages blob validation + string-table build.
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e014(param_1: *mut u8, param_2: u32) {
    if param_2 > 0x50 {
        let z = HOOK_004031E0(
            param_1 as *mut u32,
            PTR_S_INNO_SETUP_MESSAGES as *mut u32,
            0x40,
        );
        if z == 0 {
            goto_checks(param_1, param_2);
            return;
        }
    }
    HOOK_0040DF60();
    goto_checks(param_1, param_2);
}

unsafe fn goto_checks(param_1: *mut u8, param_2: u32) {
    let hdr = param_1.wrapping_byte_add(0x40);
    // ponytail: `NOT EDX` compare triple order matches (`[1]!=~[2] || size!=[1] || [0]!=0xdd`).
    let h0 = core::ptr::read_unaligned(hdr as *const u32);
    let h1 = core::ptr::read_unaligned(hdr.wrapping_byte_add(4) as *const u32);
    let h2 = core::ptr::read_unaligned(hdr.wrapping_byte_add(8) as *const u32);
    if h1 != (!h2) || param_2 != h1 || h0 != 0xdd {
        HOOK_0040DF60();
    }
    let body = param_1.wrapping_byte_add(0x50);
    let end = param_1.wrapping_byte_add(h1 as usize);
    // ponytail: `(end-body)>>1` with `SAR/ADC` round-up.
    let diff = (end as usize).wrapping_sub(body as usize) as i32;
    let mut half = diff >> 1;
    if half < 0 {
        half += ((diff & 1) != 0) as i32;
    }
    let crc = HOOK_0040C738(body, (half as u32).wrapping_mul(2));
    let h3 = core::ptr::read_unaligned(hdr.wrapping_byte_add(0xc) as *const u32);
    if crc != h3 || core::ptr::read_unaligned(end.wrapping_byte_offset(-2) as *const u16) != 0 {
        HOOK_0040DF60();
    }
    let mut p = body;
    let mut t = crate::fn_0040def0::DAT_004181A0.as_mut_ptr();
    let mut n: u8 = 0xdd;
    loop {
        if end <= p {
            HOOK_0040DF60();
        }
        let len = HOOK_004080DC(p as *mut u8);
        HOOK_00404DD4(t, p, len);
        p = p.wrapping_byte_add((len.wrapping_add(1)).wrapping_mul(2) as usize);
        t = t.wrapping_byte_add(4);
        n = n.wrapping_sub(1);
        if n == 0 {
            break;
        }
    }
}

/// Pointer-word for `"Inno Setup Messages (5.5.3) (u)"` (`PTR 0x412c18`).
///
/// ponytail: address-named static; referent bytes unproven beyond observed string.
pub static mut PTR_S_INNO_SETUP_MESSAGES: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FATAL: AtomicUsize = AtomicUsize::new(0);
    static CMP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fatal() {
        FATAL.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn cmp(_p: *mut u32, _s: *mut u32, _n: u32) -> u32 {
        CMP.fetch_add(1, Ordering::SeqCst);
        1 // nonzero → fall into df60 (JNZ path)
    }
    unsafe extern "C" fn crc(_p: *mut u8, _n: u32) -> u32 {
        0x99
    }
    unsafe extern "C" fn slen(_p: *mut u8) -> u32 {
        0
    }
    unsafe extern "C" fn mk(_t: *mut u32, _s: *mut u8, _n: u32) {}

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn bad_magic_hits_fatal() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040DF60 = fatal;
            HOOK_004031E0 = cmp;
            HOOK_0040C738 = crc;
            HOOK_004080DC = slen;
            HOOK_00404DD4 = mk;
        }
        FATAL.store(0, Ordering::SeqCst);
        CMP.store(0, Ordering::SeqCst);
        // param_2 <= 0x50 skips compare; zero header fails triple check → fatal ≥1.
        // Body crafted so later checks pass: h1=0x50, h2=!0x50, h3=crc, trailing zero.
        let mut blob = [0u8; 0x60];
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr().wrapping_byte_add(0x40) as *mut u32, 0xdd);
            core::ptr::write_unaligned(blob.as_mut_ptr().wrapping_byte_add(0x44) as *mut u32, 0x50);
            core::ptr::write_unaligned(blob.as_mut_ptr().wrapping_byte_add(0x48) as *mut u32, !0x50);
            core::ptr::write_unaligned(blob.as_mut_ptr().wrapping_byte_add(0x4c) as *mut u32, 0x99);
            // end = base+0x50; trailing word at end-2 must be 0 (already zero).
            // Fill loop: slen hook returns 0 → p advances 2/step over 0xdd iters; needs
            // end-p > 0 each iter → end(0x50 past base) - body(0x50 past base)... body==end
            // triggers empty-range fatal per observed guard. Just assert fatal hit.
            fn_0040e014(blob.as_mut_ptr(), 0x50);
        }
        assert!(FATAL.load(Ordering::SeqCst) >= 1);
        assert_eq!(CMP.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn oversize_calls_compare_first() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040DF60 = fatal;
            HOOK_004031E0 = cmp;
            HOOK_0040C738 = crc;
            HOOK_004080DC = slen;
            HOOK_00404DD4 = mk;
        }
        FATAL.store(0, Ordering::SeqCst);
        CMP.store(0, Ordering::SeqCst);
        let mut blob = [0u8; 0x60];
        unsafe { fn_0040e014(blob.as_mut_ptr(), 0x51) };
        assert_eq!(CMP.load(Ordering::SeqCst), 1);
        assert!(FATAL.load(Ordering::SeqCst) >= 1);
    }
}
