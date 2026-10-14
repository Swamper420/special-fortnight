//! Process entry point `0x004117dc` (522 bytes, `0x4117dc–0x4119e5`).
//! Entry-region note: OS-invoked; no callers. Semantics kept, but this
//! function is NOT called from `fn main()` yet (main stays as-is).
//! Evidence: `evidence/004117dc_fn_004117dc.md`.

unsafe extern "C" fn default_u32arg(_a: u32) {}
unsafe extern "C" fn default_none() {}
unsafe extern "C" fn default_argv(_i: i32, _o: *mut u32) {}
unsafe extern "C" fn default_pair(_a: u32, _b: u32) {}
unsafe extern "C" fn default_c238(_a: u32, _b: u8, _c: u32, _d: u32, _e: u32, _f: u32) -> u32 {
    0
}
unsafe extern "C" fn default_ee14() -> u32 {
    0
}
unsafe extern "C" fn default_c738(_a: u32, _b: u32) -> u32 {
    0
}
unsafe extern "C" fn default_read(_s: u32, _o: *mut u32, _n: u32) -> i32 {
    0
}
unsafe extern "C" fn default_c1f8(_a: u32, _b: u32, _c: u32) {}
unsafe extern "C" fn default_31e0(_a: u32, _b: u32, _c: u32) -> i32 {
    1
}
unsafe extern "C" fn default_c854(_a: u32, _b: u8, _c: u32, _d: u32) -> u32 {
    0
}
unsafe extern "C" fn default_da38(_a: u32, _b: u32, _c: u32, _d: u32, _e: u32) {}
unsafe extern "C" fn default_alloc(_n: u32) -> u32 {
    0
}

/// Image-flag cells observed on entry path.
pub static mut DAT_00412ADC_ENTRY: u8 = 0;
/// Stream-object / setup-data slots.
pub static mut DAT_00418658: u32 = 0;
pub static mut DAT_0041865C: u32 = 0;
pub static mut DAT_00418664: u32 = 0;
pub static mut DAT_004186B8: u32 = 0;
pub static mut DAT_00418650: u32 = 0;
pub static mut DAT_0041864C: u32 = 0;

/// Callee hooks in spine order (defaults no-op / zero).
pub static mut HOOK_004065D4: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_0040ED40: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_0040E894: unsafe extern "C" fn() = default_none;
pub static mut HOOK_0040EE68: unsafe extern "C" fn() = default_none;
/// Process-exit (original `FUN_004046ac(0)`); default no-op so tests survive.
pub static mut HOOK_004046AC: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_0040B8FC: unsafe extern "C" fn(i32, *mut u32) = default_argv;
pub static mut HOOK_00404C98: unsafe extern "C" fn(u32, u32) = default_pair;
pub static mut HOOK_0040C238: unsafe extern "C" fn(u32, u8, u32, u32, u32, u32) -> u32 =
    default_c238;
pub static mut HOOK_0040EE14: unsafe extern "C" fn() -> u32 = default_ee14;
pub static mut HOOK_0040C738: unsafe extern "C" fn(u32, u32) -> u32 = default_c738;
/// Vtable `+4` stream readers (two sites).
pub static mut HOOK_STREAMREAD: unsafe extern "C" fn(u32, *mut u32, u32) -> i32 = default_read;
pub static mut HOOK_0040EC58: unsafe extern "C" fn() = default_none;
pub static mut HOOK_0040C220: unsafe extern "C" fn(u32, u32) = default_pair;
pub static mut HOOK_0040C1F8: unsafe extern "C" fn(u32, u32, u32) = default_c1f8;
pub static mut HOOK_004031E0: unsafe extern "C" fn(u32, u32, u32) -> i32 = default_31e0;
pub static mut HOOK_0040C854: unsafe extern "C" fn(u32, u8, u32, u32) -> u32 = default_c854;
pub static mut HOOK_0040DA38: unsafe extern "C" fn(u32, u32, u32, u32, u32) = default_da38;
pub static mut HOOK_00402DEC: unsafe extern "C" fn(u32) -> u32 = default_alloc;
pub static mut HOOK_00403894: unsafe extern "C" fn(u32) = default_u32arg;
/// Fake backing for `DAT_00418664` fields (+0xc/+0x10/+0x20/+0x28).
pub static mut FAKE_SETUP: [u32; 12] = [0; 12];

/// Entry spine. `ok` mirrors `uVar4` (version/stream gate).
/// Skips nothing: both `ec58` conditional sites kept in order.
pub unsafe fn fn_004117dc() {
    HOOK_004065D4(0x410144);
    HOOK_0040ED40(0);
    HOOK_0040E894();
    if DAT_00412ADC_ENTRY != 0 {
        HOOK_0040EE68();
        HOOK_004046AC(0);
    }
    let mut arg0: u32 = 0;
    HOOK_0040B8FC(0, &mut arg0);
    HOOK_00404C98(0x418658, arg0);
    DAT_0041865C = HOOK_0040C238(0x40c04c, 1, DAT_00418658, 1, 0, 2);
    DAT_00418664 = HOOK_0040EE14();
    let mut ok = false;
    let mut skip_first_ec58 = false;
    let base = DAT_00418664;
    // ponytail: guarded reads; null base → setup-missing path (ec58).
    let plus_c: u32 = if base == 0 { 0xffff } else { FAKE_SETUP[3] };
    if plus_c == 1 {
        let got = HOOK_0040C738(base, 0x28);
        if got == FAKE_SETUP[10] {
            let mut w0 = [0u32; 2];
            HOOK_STREAMREAD(DAT_0041865C, w0.as_mut_ptr(), 8);
            // ponytail: `local_1c` is second dword; nonzero → goto c220 (skip ec58 #1).
            ok = w0[1] == 0;
            if !ok {
                skip_first_ec58 = true;
            } else {
                let mut w1 = [0u32; 2];
                HOOK_STREAMREAD(DAT_0041865C, w1.as_mut_ptr(), 8);
                ok = w1[0] == FAKE_SETUP[4];
                // ponytail: `JNC` (w1 >= expected) → goto c220 (skip ec58 #1, ok keeps equality).
                if FAKE_SETUP[4] <= w1[0] {
                    skip_first_ec58 = true;
                }
            }
        }
    }
    if !skip_first_ec58 {
        HOOK_0040EC58();
    }
    HOOK_0040C220(DAT_0041865C, FAKE_SETUP[8]);
    HOOK_0040C1F8(DAT_0041865C, 0x418674, 0x40);
    // ponytail: decompiler lifts trailing `JZ` as `if (!uVar4)`; return value unused.
    let _ = HOOK_004031E0(0x418674, 0x412b2c, 0x40);
    if !ok {
        HOOK_0040EC58();
    }
    DAT_004186B8 = HOOK_0040C854(0x40c698, 1, DAT_0041865C, 0x40cc18);
    HOOK_0040DA38(DAT_004186B8, 0x41852c, 0x11d, 4, 0x1c);
    let count = FAKE_SETUP[11];
    DAT_00418650 = count;
    // ponytail: `IMUL count,0x3d` alloc size exact.
    DAT_0041864C = HOOK_00402DEC(count.wrapping_mul(0x3d));
    if (count as i32).wrapping_sub(1) >= 0 {
        let mut i: u32 = 0;
        let mut left: i32 = count as i32;
        while left != 0 {
            HOOK_0040DA38(
                DAT_004186B8,
                DAT_0041864C.wrapping_add(i.wrapping_mul(0x3d)),
                0x3d,
                4,
                6,
            );
            i = i.wrapping_add(1);
            left -= 1;
        }
    }
    HOOK_00403894(DAT_004186B8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static EC58: AtomicU32 = AtomicU32::new(0);
    static EXITS: AtomicU32 = AtomicU32::new(0);
    static DA38: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn ec58() {
        EC58.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn exit_(c: u32) {
        assert_eq!(c, 0);
        EXITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn da38(_a: u32, _b: u32, _c: u32, _d: u32, _e: u32) {
        DA38.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn argv0(_i: i32, _o: *mut u32) {}
    unsafe extern "C" fn pair0(_a: u32, _b: u32) {}
    unsafe extern "C" fn c1f8_0(_a: u32, _b: u32, _c: u32) {}
    unsafe extern "C" fn s31e0(_a: u32, _b: u32, _c: u32) -> i32 {
        1
    }

    #[test]
    fn missing_setup_calls_ec58_and_help_exits() {
        unsafe {
            HOOK_0040EC58 = ec58;
            HOOK_004046AC = exit_;
            HOOK_0040B8FC = argv0;
            HOOK_00404C98 = pair0;
            HOOK_0040C1F8 = c1f8_0;
            HOOK_004031E0 = s31e0;
            HOOK_0040DA38 = da38;
            FAKE_SETUP = [0; 12];
            EC58.store(0, Ordering::SeqCst);
            EXITS.store(0, Ordering::SeqCst);
            DA38.store(0, Ordering::SeqCst);
            DAT_00412ADC_ENTRY = 0;
            fn_004117dc();
            assert_eq!(EC58.load(Ordering::SeqCst), 2); // both ec58 sites
            // help path: fires ee68 + exit hook, host survives.
            DAT_00412ADC_ENTRY = 1;
            EC58.store(0, Ordering::SeqCst);
            EXITS.store(0, Ordering::SeqCst);
            fn_004117dc();
            assert_eq!(EXITS.load(Ordering::SeqCst), 1);
        }
    }
}
