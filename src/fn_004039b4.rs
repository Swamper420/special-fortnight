//! Original procedure `0x004039b4` (1 byte, `0x004039b4`; followed by
//! 5-byte `lea` padding).
//! Evidence: `evidence/004039b4_fn_004039b4.md`.
//!
//! Alignment `ret` slot reached as the `[vtbl-0x1c]` dispatch from
//! `fn_00403a3c` on the entry's TCustomFile object. No direct
//! `call 0x4039b4` site exists, which is why call-dest enumeration
//! missed it.

/// Single `ret`: no reads, no writes, no result. Kept as a real
/// function (not a stub) so vtable links resolve 1:1.
pub unsafe fn fn_004039b4() {}

#[cfg(test)]
mod tests {
    use super::fn_004039b4;

    #[test]
    fn bare_ret() {
        unsafe { fn_004039b4() };
    }
}
