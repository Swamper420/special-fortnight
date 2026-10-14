//! Original procedure `0x00408eab` (9 bytes, `0x00408eab–0x00408eb3`).
//! Evidence: `evidence/00408eab_fn_00408eab.md`.

/// Shared epilogue of `fn_00408c88`: `POP EBX / POP ESI / POP EDI /
/// MOV ESP,EBP / POP EBP / RET 0x8`. Reached only by the two terminal
/// `JMP`s from `0x00408ca6`/`0x00408cb0`; returns to `0x00408c88`'s caller
/// on its behalf, popping its two stack args. Register restores and
/// the callee-pops cleanup are host-implicit with no observable
/// state change, so the body is empty.
pub unsafe fn fn_00408eab() {}

#[cfg(test)]
mod tests {
    use super::fn_00408eab;

    #[test]
    fn returns() {
        unsafe { fn_00408eab() };
    }
}
