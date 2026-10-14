//! Original procedure `0x00408c82` (6 bytes, `0x408c82–0x408c87`).
//! Evidence: `evidence/00408c82_fn_00408c82.md`.

/// Shared stdcall epilogue (`MOV ESP,EBP; POP EBP; RET 0xc`):
/// no reads, no writes, returns void. Reached by tail-`JMP`
/// from `FUN_00408988` (`0x408a58`); the three popped dwords
/// are the caller's stack args, modeled as dummy params with
/// no host effect (same precedent as `fn_00408274`).
pub unsafe fn fn_00408c82(_a: u32, _b: u32, _c: u32) {}

#[cfg(test)]
mod tests {
    use super::fn_00408c82;

    #[test]
    fn epilogue_returns() {
        // No hooks/globals: locals only, no TEST_LOCK.
        unsafe { fn_00408c82(1, 2, 3) };
    }
}
