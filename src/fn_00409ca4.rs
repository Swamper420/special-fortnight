//! Original procedure `0x00409ca4` (127 bytes, `0x409ca4–0x409d22`).
//! Evidence: `evidence/00409ca4_fn_00409ca4.md`.

/// Status-word map: `*param_1` dispatches through signed bounds and
/// wrapping SUB/ADD/DEC chains; each exit sets only AL, preserving
/// the running upper bytes (`(eax & ~0xFF) | imm`). `JG` bounds use
/// signed `i32` compares; all arithmetic uses `wrapping_*` per
/// observed wrap. `param_1` arrives in EAX per Ghidra `__register`
/// observation.
pub unsafe fn fn_00409ca4(param_1: *const u32) -> u32 {
    let mut eax: u32 = core::ptr::read_unaligned(param_1);
    // 0x409ca6: CMP EAX, 0xc0000092; JG HIGH.
    if (eax as i32) > (0xC0000092u32 as i32) {
        // 0x409cd9: CMP EAX, 0xc0000096; JG TOP.
        if (eax as i32) > (0xC0000096u32 as i32) {
            // 0x409cf1: SUB EAX, 0xc00000fd; JZ RETE.
            eax = eax.wrapping_sub(0xC00000FD);
            if eax == 0 {
                return (eax & 0xFFFF_FF00) | 0x0E;
            }
            // 0x409cf8: SUB EAX, 0x3d; JZ RETD.
            eax = eax.wrapping_sub(0x3D);
            if eax == 0 {
                return (eax & 0xFFFF_FF00) | 0x0D;
            }
            // 0x409cfd: JMP default.
            return (eax & 0xFFFF_FF00) | 0x16;
        }
        // 0x409ce0: JZ RETC.
        if eax == 0xC0000096 {
            return (eax & 0xFFFF_FF00) | 0x0C;
        }
        // 0x409ce2: SUB EAX, 0xc0000093; JZ RET9.
        eax = eax.wrapping_sub(0xC0000093);
        if eax == 0 {
            return (eax & 0xFFFF_FF00) | 0x09;
        }
        // 0x409ce9: DEC EAX; JZ RET3.
        eax = eax.wrapping_sub(1);
        if eax == 0 {
            return (eax & 0xFFFF_FF00) | 0x03;
        }
        // 0x409cec: DEC EAX; JZ RET5.
        eax = eax.wrapping_sub(1);
        if eax == 0 {
            return (eax & 0xFFFF_FF00) | 0x05;
        }
        // 0x409cef: JMP default.
        return (eax & 0xFFFF_FF00) | 0x16;
    }
    // 0x409cad: JZ RET6.
    if eax == 0xC0000092 {
        return (eax & 0xFFFF_FF00) | 0x06;
    }
    // 0x409caf: CMP EAX, 0xc000008e; JG MID1.
    if (eax as i32) > (0xC000008Eu32 as i32) {
        // 0x409ccb: ADD EAX, 0x3fffff71.
        eax = eax.wrapping_add(0x3FFF_FF71);
        // 0x409cd0: SUB EAX, 0x2; JC RET6 (borrow iff pre-sub < 2).
        let pre = eax;
        eax = eax.wrapping_sub(2);
        if pre < 2 {
            return (eax & 0xFFFF_FF00) | 0x06;
        }
        // 0x409cd5: JZ RET8.
        if eax == 0 {
            return (eax & 0xFFFF_FF00) | 0x08;
        }
        // 0x409cd7: JMP default.
        return (eax & 0xFFFF_FF00) | 0x16;
    }
    // 0x409cb6: JZ RET7.
    if eax == 0xC000008E {
        return (eax & 0xFFFF_FF00) | 0x07;
    }
    // 0x409cb8: SUB EAX, 0xc0000005; JZ RETB.
    eax = eax.wrapping_sub(0xC0000005);
    if eax == 0 {
        return (eax & 0xFFFF_FF00) | 0x0B;
    }
    // 0x409cbf: SUB EAX, 0x87; JZ RET4.
    eax = eax.wrapping_sub(0x87);
    if eax == 0 {
        return (eax & 0xFFFF_FF00) | 0x04;
    }
    // 0x409cc6: DEC EAX; JZ RET9.
    eax = eax.wrapping_sub(1);
    if eax == 0 {
        return (eax & 0xFFFF_FF00) | 0x09;
    }
    // 0x409cc9: JMP default.
    (eax & 0xFFFF_FF00) | 0x16
}

#[cfg(test)]
mod tests {
    use super::fn_00409ca4;

    #[test]
    fn status_word_lanes() {
        // (input, expected), derived from assembly EAX tracking
        // (see evidence); covers all 14 constant leaves + defaults.
        for (input, expected) in [
            (0xC0000092u32, 0xC0000006u32),
            (0xC000008Eu32, 0xC0000007u32),
            (0xC0000005u32, 0x0000000Bu32),
            (0xC000008Cu32, 0x00000004u32),
            (0xC000008Du32, 0x00000009u32),
            (0xC000008Fu32, 0xFFFFFF06u32),
            (0xC0000090u32, 0xFFFFFF06u32),
            (0xC0000091u32, 0x00000008u32),
            (0xC0000096u32, 0xC000000Cu32),
            (0xC0000093u32, 0x00000009u32),
            (0xC0000094u32, 0x00000003u32),
            (0xC0000095u32, 0x00000005u32),
            (0xC00000FDu32, 0x0000000Eu32),
            (0xC000013Au32, 0x0000000Du32),
            (0x00000000u32, 0x3FFFFE16u32),
            (0xC0000000u32, 0xFFFFFF16u32),
        ] {
            let cell = input;
            assert_eq!(
                unsafe { fn_00409ca4(&cell as *const u32) },
                expected,
                "input {input:#x}"
            );
        }
    }
}
