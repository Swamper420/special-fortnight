//! Original procedure `0x00407f10` (22 bytes, `0x407f10–0x407f25`).
//! Evidence: `evidence/00407f10_fn_00407f10.md`.

use crate::fn_004032ec::fn_004032ec;

/// Wide-char parse with fallback: `r = 32ec(text, &slot)`
/// where `slot` is seeded with `param_3` (`PUSH ECX`); return
/// `r` iff the slot came back 0, else the saved `param_2`
/// (`MOV EBX,EDX` / `MOV EAX,EBX`). `(param_1, param_2,
/// param_3)` arrive in `(EAX, EDX, ECX)` per Ghidra
/// `__register` observation; result returns in `EAX` as
/// `uint`. Direct call to done `fn_004032ec` (no hook).
pub unsafe fn fn_00407f10(param_1: *const u16, param_2: u32, param_3: u32) -> u32 {
    let mut slot = param_3;
    let r = fn_004032ec(param_1, &mut slot);
    if slot != 0 {
        return param_2;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::fn_00407f10;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0, 0]).collect()
    }

    fn run(s: &str, fallback: u32, seed: u32) -> u32 {
        let v = wide(s);
        unsafe { fn_00407f10(v.as_ptr(), fallback, seed) }
    }

    #[test]
    fn parse_or_fallback_lanes() {
        // Clean parse: fallback ignored.
        assert_eq!(run("123", 7, 0), 123);
        // Bad first char: consumed=1, fallback wins.
        assert_eq!(run("q", 7, 0), 7);
        // Empty string: consumed=1, fallback wins.
        assert_eq!(run("", 7, 0), 7);
        // Trailing bad char: partial value discarded, fallback wins.
        assert_eq!(run("12q", 7, 0), 7);
        // Hex parse through the shared callee.
        assert_eq!(run("0x10", 7, 0), 16);
    }
}
