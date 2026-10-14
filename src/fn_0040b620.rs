//! Original procedure `0x0040b620` (10 bytes, `0x0040b620–0x0040b629`).
//! Evidence: `evidence/0040b620_fn_0040b620.md`.

/// `if p1 < p2 { p2 -= 2 }; return p2`. Unsigned compare (`JNC`
/// skips the subtract iff `EAX >= EDX` unsigned). Both lanes carry
/// addresses at every observed caller, so pointer-sized (`usize`)
/// per the never-`as u32`-on-pointers rule; `SUB` wraps.
pub unsafe fn fn_0040b620(param_1: usize, param_2: usize) -> usize {
    if param_1 < param_2 {
        param_2.wrapping_sub(2)
    } else {
        param_2
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040b620;

    #[test]
    fn clamp_lanes() {
        // No hooks/globals: locals only, no TEST_LOCK.
        unsafe {
            assert_eq!(fn_0040b620(5, 10), 8);
            assert_eq!(fn_0040b620(10, 5), 5);
            assert_eq!(fn_0040b620(7, 7), 7);
            assert_eq!(fn_0040b620(0, 0), 0);
            assert_eq!(fn_0040b620(0, 1), usize::MAX);
        }
    }
}
