//! Process entry point `0x004117dc` (522 bytes, `0x004117dc–0x004119e5`).
//! Entry-region note: OS-invoked; no callers. Wired into `fn main()`.
//! Evidence: `evidence/004117dc_fn_004117dc.md`.

// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_004065d4(a: u32) {
    crate::fn_004065d4::fn_004065d4(a as *mut u8)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040ed40(a: u32) {
    crate::fn_0040ed40::fn_0040ed40(a)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040e894() {
    crate::fn_0040e894::fn_0040e894()
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040ee68() {
    crate::fn_0040ee68::fn_0040ee68()
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_004046ac(a: u32) {
    crate::fn_004046ac::fn_004046ac(a)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040b8fc(i: i32, o: *mut u32) {
    crate::fn_0040b8fc::fn_0040b8fc(i as u32, o as *mut u8)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_00404c98(a: u32, b: u32) {
    crate::fn_00404c98::fn_00404c98(a as *mut u8, b as *mut u8)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040c238(a: u32, b: u8, c: u32, d: u32, e: u32, f: u32) -> u32 {
    crate::fn_0040c238::fn_0040c238(a as *mut *const u8, b, c, d as u8, e as u8, f as u8)
        as u32
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040ee14() -> u32 {
    crate::fn_0040ee14::fn_0040ee14() as u32
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040c738(a: u32, b: u32) -> u32 {
    crate::fn_0040c738::fn_0040c738(a as *const u8, b as i32)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040ec58() {
    crate::fn_0040ec58::fn_0040ec58()
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040c220(a: u32, b: u32) {
    crate::fn_0040c220::fn_0040c220(a as *mut *const u8, b)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040c1f8(a: u32, b: u32, c: u32) {
    crate::fn_0040c1f8::fn_0040c1f8(a as *mut *const u8, b, c as i32)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_004031e0(a: u32, b: u32, c: u32) -> i32 {
    // Real fn returns `(ptr, zf)`; spine discards it. 1 preserves old stub value.
    let _ = crate::fn_004031e0::fn_004031e0(a as *const u8, b as *const u8, c);
    1
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040c854(a: u32, b: u8, c: u32, d: u32) -> u32 {
    crate::fn_0040c854::fn_0040c854(a as *mut u8, b, c as *mut *const u8, d as *mut *const u8)
        as u32
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_0040da38(a: u32, b: u32, c: u32, d: u32, e: u32) {
    crate::fn_0040da38::fn_0040da38(a as *mut u8, b as *mut u32, c as i32, d as i32, e as i32)
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_00402dec(n: u32) -> u32 {
    // Real fn is a void guard (not the allocator); 0 preserves old stub value.
    crate::fn_00402dec::fn_00402dec(n);
    0
}
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapter_00403894(a: u32) {
    crate::fn_00403894::fn_00403894(a as *mut *const u8)
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

/// Callee hooks in spine order (wired to real reconstructed fns via adapters).
pub static mut HOOK_004065D4: unsafe extern "C" fn(u32) = adapter_004065d4;
pub static mut HOOK_0040ED40: unsafe extern "C" fn(u32) = adapter_0040ed40;
pub static mut HOOK_0040E894: unsafe extern "C" fn() = adapter_0040e894;
pub static mut HOOK_0040EE68: unsafe extern "C" fn() = adapter_0040ee68;
/// Process-exit (original `FUN_004046ac(0)`); wired real, tests override with no-op.
pub static mut HOOK_004046AC: unsafe extern "C" fn(u32) = adapter_004046ac;
pub static mut HOOK_0040B8FC: unsafe extern "C" fn(i32, *mut u32) = adapter_0040b8fc;
pub static mut HOOK_00404C98: unsafe extern "C" fn(u32, u32) = adapter_00404c98;
pub static mut HOOK_0040C238: unsafe extern "C" fn(u32, u8, u32, u32, u32, u32) -> u32 =
    adapter_0040c238;
pub static mut HOOK_0040EE14: unsafe extern "C" fn() -> u32 = adapter_0040ee14;
pub static mut HOOK_0040C738: unsafe extern "C" fn(u32, u32) -> u32 = adapter_0040c738;
/// Vtable `+4` stream readers (two sites): rewired to the real
/// `crate::fn_0040c360::fn_0040c360` (GetFileSize lane) via a minimal
/// ABI adapter. The entry's `n` lane is unread by the body; the
/// adapter drops it exactly as the original does.
use crate::fn_0040c360::fn_0040c360;
unsafe extern "C" fn adapter_streamread(s: u32, o: *mut u32, _n: u32) -> i32 {
    fn_0040c360(s as *const u8, o);
    0
}
pub static mut HOOK_STREAMREAD: unsafe extern "C" fn(u32, *mut u32, u32) -> i32 =
    adapter_streamread;
pub static mut HOOK_0040EC58: unsafe extern "C" fn() = adapter_0040ec58;
pub static mut HOOK_0040C220: unsafe extern "C" fn(u32, u32) = adapter_0040c220;
pub static mut HOOK_0040C1F8: unsafe extern "C" fn(u32, u32, u32) = adapter_0040c1f8;
pub static mut HOOK_004031E0: unsafe extern "C" fn(u32, u32, u32) -> i32 = adapter_004031e0;
pub static mut HOOK_0040C854: unsafe extern "C" fn(u32, u8, u32, u32) -> u32 = adapter_0040c854;
pub static mut HOOK_0040DA38: unsafe extern "C" fn(u32, u32, u32, u32, u32) = adapter_0040da38;
pub static mut HOOK_00402DEC: unsafe extern "C" fn(u32) -> u32 = adapter_00402dec;
pub static mut HOOK_00403894: unsafe extern "C" fn(u32) = adapter_00403894;
/// Fake backing for `DAT_00418664` fields (+0xc/+0x10/+0x20/+0x28).
pub static mut FAKE_SETUP: [u32; 12] = [0; 12];

/// Image-absolute dword cell (`mov addr,%reg` in the original).
/// Valid on Windows (linked image) and on a Linux host after
/// `host_image::map_original_image()`. Exact on i686; on a 64-bit
/// test host the value is still the true 32-bit cell.
unsafe fn img_u32(addr: u32) -> u32 {
    core::ptr::read_unaligned(addr as *const u32)
}

/// Entry spine. `ok` mirrors `uVar4` (version/stream gate).
/// Skips nothing: both `ec58` conditional sites kept in order.
pub unsafe fn fn_004117dc() {
    HOOK_004065D4(0x00410144);
    HOOK_0040ED40(0);
    HOOK_0040E894();
    if DAT_00412ADC_ENTRY != 0 {
        HOOK_0040EE68();
        HOOK_004046AC(0);
    }
    let mut arg0: u32 = 0;
    HOOK_0040B8FC(0, &mut arg0);
    HOOK_00404C98(0x00418658, arg0);
    DAT_0041865C = HOOK_0040C238(img_u32(0x0040c04c), 1, img_u32(0x00418658), 1, 0, 2);
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
    HOOK_0040C1F8(DAT_0041865C, 0x00418674, 0x40);
    // ponytail: decompiler lifts trailing `JZ` as `if (!uVar4)`; return value unused.
    let _ = HOOK_004031E0(0x00418674, img_u32(0x00412b2c), 0x40);
    if !ok {
        HOOK_0040EC58();
    }
    DAT_004186B8 = HOOK_0040C854(img_u32(0x0040c640), 1, DAT_0041865C, img_u32(0x0040cbc0));
    HOOK_0040DA38(DAT_004186B8, 0x0041852c, 0x11d, 4, 0x1c);
    let count = img_u32(0x004185ac);
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

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static EC58: AtomicU32 = AtomicU32::new(0);
    static EXITS: AtomicU32 = AtomicU32::new(0);
    static DA38: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn stub_u32arg(_a: u32) {}
    unsafe extern "C" fn stub_none() {}
    unsafe extern "C" fn stub_argv(_i: i32, _o: *mut u32) {}
    unsafe extern "C" fn stub_pair(_a: u32, _b: u32) {}
    unsafe extern "C" fn stub_c238(_a: u32, _b: u8, _c: u32, _d: u32, _e: u32, _f: u32) -> u32 {
        0
    }
    unsafe extern "C" fn stub_ee14() -> u32 {
        0
    }
    unsafe extern "C" fn stub_c738(_a: u32, _b: u32) -> u32 {
        0
    }
    unsafe extern "C" fn stub_read(_s: u32, _o: *mut u32, _n: u32) -> i32 {
        0
    }
    unsafe extern "C" fn stub_c1f8(_a: u32, _b: u32, _c: u32) {}
    unsafe extern "C" fn stub_31e0(_a: u32, _b: u32, _c: u32) -> i32 {
        1
    }
    unsafe extern "C" fn stub_c854(_a: u32, _b: u8, _c: u32, _d: u32) -> u32 {
        0
    }
    unsafe extern "C" fn stub_alloc(_n: u32) -> u32 {
        0
    }
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

    /// Save every hook/DAT this module's tests mutate; returns the snapshot.
    #[allow(clippy::type_complexity)]
    unsafe fn save() -> (
        unsafe extern "C" fn(u32),
        unsafe extern "C" fn(u32),
        unsafe extern "C" fn(),
        unsafe extern "C" fn(),
        unsafe extern "C" fn(u32),
        unsafe extern "C" fn(i32, *mut u32),
        unsafe extern "C" fn(u32, u32),
        unsafe extern "C" fn(u32, u8, u32, u32, u32, u32) -> u32,
        unsafe extern "C" fn() -> u32,
        unsafe extern "C" fn(u32, u32) -> u32,
        unsafe extern "C" fn(u32, *mut u32, u32) -> i32,
        unsafe extern "C" fn(),
        unsafe extern "C" fn(u32, u32),
        unsafe extern "C" fn(u32, u32, u32),
        unsafe extern "C" fn(u32, u32, u32) -> i32,
        unsafe extern "C" fn(u32, u8, u32, u32) -> u32,
        unsafe extern "C" fn(u32, u32, u32, u32, u32),
        unsafe extern "C" fn(u32) -> u32,
        unsafe extern "C" fn(u32),
        u8,
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        [u32; 12],
        u8,
        u8,
        u32,
        u32,
    ) {
        (
            HOOK_004065D4,
            HOOK_0040ED40,
            HOOK_0040E894,
            HOOK_0040EE68,
            HOOK_004046AC,
            HOOK_0040B8FC,
            HOOK_00404C98,
            HOOK_0040C238,
            HOOK_0040EE14,
            HOOK_0040C738,
            HOOK_STREAMREAD,
            HOOK_0040EC58,
            HOOK_0040C220,
            HOOK_0040C1F8,
            HOOK_004031E0,
            HOOK_0040C854,
            HOOK_0040DA38,
            HOOK_00402DEC,
            HOOK_00403894,
            DAT_00412ADC_ENTRY,
            DAT_00418658,
            DAT_0041865C,
            DAT_00418664,
            DAT_004186B8,
            DAT_00418650,
            DAT_0041864C,
            FAKE_SETUP,
            crate::fn_0040e894::DAT_00412AE0,
            crate::fn_0040e894::DAT_00412ADC,
            crate::fn_0040e894::DAT_00418528,
            crate::fn_004046ac::CELL_00412000,
        )
    }

    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn restore(
        s: (
            unsafe extern "C" fn(u32),
            unsafe extern "C" fn(u32),
            unsafe extern "C" fn(),
            unsafe extern "C" fn(),
            unsafe extern "C" fn(u32),
            unsafe extern "C" fn(i32, *mut u32),
            unsafe extern "C" fn(u32, u32),
            unsafe extern "C" fn(u32, u8, u32, u32, u32, u32) -> u32,
            unsafe extern "C" fn() -> u32,
            unsafe extern "C" fn(u32, u32) -> u32,
            unsafe extern "C" fn(u32, *mut u32, u32) -> i32,
            unsafe extern "C" fn(),
            unsafe extern "C" fn(u32, u32),
            unsafe extern "C" fn(u32, u32, u32),
            unsafe extern "C" fn(u32, u32, u32) -> i32,
            unsafe extern "C" fn(u32, u8, u32, u32) -> u32,
            unsafe extern "C" fn(u32, u32, u32, u32, u32),
            unsafe extern "C" fn(u32) -> u32,
            unsafe extern "C" fn(u32),
            u8,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            [u32; 12],
            u8,
            u8,
            u32,
            u32,
        ),
    ) {
        HOOK_004065D4 = s.0;
        HOOK_0040ED40 = s.1;
        HOOK_0040E894 = s.2;
        HOOK_0040EE68 = s.3;
        HOOK_004046AC = s.4;
        HOOK_0040B8FC = s.5;
        HOOK_00404C98 = s.6;
        HOOK_0040C238 = s.7;
        HOOK_0040EE14 = s.8;
        HOOK_0040C738 = s.9;
        HOOK_STREAMREAD = s.10;
        HOOK_0040EC58 = s.11;
        HOOK_0040C220 = s.12;
        HOOK_0040C1F8 = s.13;
        HOOK_004031E0 = s.14;
        HOOK_0040C854 = s.15;
        HOOK_0040DA38 = s.16;
        HOOK_00402DEC = s.17;
        HOOK_00403894 = s.18;
        DAT_00412ADC_ENTRY = s.19;
        DAT_00418658 = s.20;
        DAT_0041865C = s.21;
        DAT_00418664 = s.22;
        DAT_004186B8 = s.23;
        DAT_00418650 = s.24;
        DAT_0041864C = s.25;
        FAKE_SETUP = s.26;
        crate::fn_0040e894::DAT_00412AE0 = s.27;
        crate::fn_0040e894::DAT_00412ADC = s.28;
        crate::fn_0040e894::DAT_00418528 = s.29;
        crate::fn_004046ac::CELL_00412000 = s.30;
    }

    unsafe fn install_stubs() {
        HOOK_004065D4 = stub_u32arg;
        HOOK_0040ED40 = stub_u32arg;
        HOOK_0040E894 = stub_none;
        HOOK_0040EE68 = stub_none;
        HOOK_004046AC = exit_;
        HOOK_0040B8FC = stub_argv;
        HOOK_00404C98 = stub_pair;
        HOOK_0040C238 = stub_c238;
        HOOK_0040EE14 = stub_ee14;
        HOOK_0040C738 = stub_c738;
        HOOK_STREAMREAD = stub_read;
        HOOK_0040EC58 = ec58;
        HOOK_0040C220 = stub_pair;
        HOOK_0040C1F8 = stub_c1f8;
        HOOK_004031E0 = stub_31e0;
        HOOK_0040C854 = stub_c854;
        HOOK_0040DA38 = da38;
        HOOK_00402DEC = stub_alloc;
        HOOK_00403894 = stub_u32arg;
    }

    #[test]
    fn missing_setup_calls_ec58_and_help_exits() {
        let _guard = LOCK.lock().unwrap();
        // Entry now reads image-absolute cells: map the image on Linux.
        #[cfg(target_os = "linux")]
        crate::host_image::map_original_image();
        let snap = unsafe { save() };
        unsafe {
            install_stubs();
            FAKE_SETUP = [0; 12];
            EC58.store(0, Ordering::SeqCst);
            EXITS.store(0, Ordering::SeqCst);
            DA38.store(0, Ordering::SeqCst);
            DAT_00412ADC_ENTRY = 0;
            DAT_00418658 = 0;
            DAT_0041865C = 0;
            DAT_00418664 = 0;
            DAT_004186B8 = 0;
            DAT_00418650 = 0;
            DAT_0041864C = 0;
            fn_004117dc();
            assert_eq!(EC58.load(Ordering::SeqCst), 2); // both ec58 sites
            // help path: fires ee68 + exit hook, host survives.
            DAT_00412ADC_ENTRY = 1;
            EC58.store(0, Ordering::SeqCst);
            EXITS.store(0, Ordering::SeqCst);
            fn_004117dc();
            assert_eq!(EXITS.load(Ordering::SeqCst), 1);
            restore(snap);
        }
    }

    #[test]
    fn wired_spine_runs_without_panic() {
        // Real adapters for host-safe callees (safe under default sub-hooks);
        // stubs for wild-pointer lanes (65d4/b8fc/4c98/c238/c220/c1f8/31e0/
        // c854/da38), vtable stream reads, and the fatal-format ec58 path.
        let _guard = LOCK.lock().unwrap();
        // Entry now reads image-absolute cells: map the image on Linux.
        #[cfg(target_os = "linux")]
        crate::host_image::map_original_image();
        let snap = unsafe { save() };
        unsafe {
            HOOK_004065D4 = stub_u32arg;
            HOOK_0040ED40 = adapter_0040ed40;
            HOOK_0040E894 = adapter_0040e894;
            HOOK_0040EE68 = adapter_0040ee68;
            HOOK_004046AC = adapter_004046ac;
            HOOK_0040B8FC = stub_argv;
            HOOK_00404C98 = stub_pair;
            HOOK_0040C238 = stub_c238;
            HOOK_0040EE14 = adapter_0040ee14;
            HOOK_0040C738 = adapter_0040c738;
            HOOK_STREAMREAD = stub_read;
            HOOK_0040EC58 = ec58;
            HOOK_0040C220 = stub_pair;
            HOOK_0040C1F8 = stub_c1f8;
            HOOK_004031E0 = stub_31e0;
            HOOK_0040C854 = stub_c854;
            HOOK_0040DA38 = da38;
            HOOK_00402DEC = adapter_00402dec;
            HOOK_00403894 = adapter_00403894;
            FAKE_SETUP = [0; 12];
            EC58.store(0, Ordering::SeqCst);
            EXITS.store(0, Ordering::SeqCst);
            DA38.store(0, Ordering::SeqCst);
            DAT_00412ADC_ENTRY = 0;
            DAT_00418658 = 0;
            DAT_0041865C = 0;
            DAT_00418664 = 0;
            DAT_004186B8 = 0;
            DAT_00418650 = 0;
            DAT_0041864C = 0;
            fn_004117dc();
            // Real ee14 finds no host resource → null → setup-missing path.
            assert_eq!(DAT_00418664, 0);
            assert_eq!(EC58.load(Ordering::SeqCst), 2);
            assert_eq!(DAT_00418650, 0);
            assert_eq!(DAT_0041864C, 0);
            // stub da38 once (0x11d site); count 0 skips the 0x3d loop.
            assert_eq!(DA38.load(Ordering::SeqCst), 1);
            // Help gate skipped: real exit never fired.
            assert_eq!(EXITS.load(Ordering::SeqCst), 0);
            restore(snap);
        }
    }
}
