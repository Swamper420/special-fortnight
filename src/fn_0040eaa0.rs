//! Original procedure `0x0040eaa0` (35 bytes, `0x40eaa0–0x40eac2`).
//! Evidence: `evidence/0040eaa0_fn_0040eaa0.md`.

unsafe extern "C" fn default_match(_cb: u32, _f: u8, _w: u32, _out: *mut i32) -> u8 {
    0
}
unsafe extern "C" fn default_sink(_i: i32) {}

/// `DAT_00418528` wanted-name cell (ECX lane).
pub static mut DAT_00418528_EAA0: u32 = 0;
/// `DAT_00418635` preference flag byte (DL lane).
pub static mut DAT_00418635_EAA0: u8 = 0;

/// Target `0x40e66c` (locale matcher).
pub static mut HOOK_0040E66C: unsafe extern "C" fn(u32, u8, u32, *mut i32) -> u8 =
    default_match;
/// Target `0x40ea2c` (index consumer).
pub static mut HOOK_0040EA2C: unsafe extern "C" fn(i32) = default_sink;

/// Adapter: seeds out-index from `param_3`, runs matcher on stored globals,
/// forwards result to `0x40ea2c`.
pub unsafe fn fn_0040eaa0(param_3: i32) {
    let mut local: i32 = param_3;
    // ponytail: EAX=0x40ea80 callback, ECX=DAT_00418528, DL=DAT_00418635.
    HOOK_0040E66C(0x40ea80, DAT_00418635_EAA0, DAT_00418528_EAA0, &mut local);
    let idx = core::ptr::read_unaligned(&local);
    HOOK_0040EA2C(idx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    static GOT: AtomicI32 = AtomicI32::new(-1);

    unsafe extern "C" fn match_(_cb: u32, _f: u8, _w: u32, out: *mut i32) -> u8 {
        unsafe { *out = 5 };
        2
    }
    unsafe extern "C" fn sink(i: i32) {
        GOT.store(i, Ordering::SeqCst);
    }

    #[test]
    fn forwards_index() {
        unsafe {
            HOOK_0040E66C = match_;
            HOOK_0040EA2C = sink;
            fn_0040eaa0(9);
            assert_eq!(GOT.load(Ordering::SeqCst), 5);
        }
    }
}
