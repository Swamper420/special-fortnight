//! Original procedure `0x004039b8` (1 byte, `ret`; followed by
//! 5-byte `lea` padding).
//! Evidence: `evidence/004039b8_fn_004039b8.md`.

/// Single `ret`: no reads, no writes, no result. Same alignment-slot
/// shape as `fn_004039b4`; reached as the `[vtbl-0x18]` dispatch from
/// `fn_00403a8c` (e.g. `[0x40c680]`, `[0x40cc00]` on the entry path).
pub unsafe fn fn_004039b8() {}

#[cfg(test)]
mod tests {
    use super::fn_004039b8;

    #[test]
    fn bare_ret() {
        unsafe { fn_004039b8() };
    }
}
