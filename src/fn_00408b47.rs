//! Original procedure `0x00408b47` (115 bytes, `0x00408b47–0x00408bb9`).
//! Evidence: `evidence/00408b47_fn_00408b47.md`.

use crate::fn_00408a7d::fn_00408a7d;

/// Grouped digit writer: `precision` chars fetched via
/// `fn_00408a7d` into `dst` words with a `sep` word every 3
/// (group `((precision-1) mod 3)+1`, skipped when `mode==2`),
/// then up to `width` (clamped to `0x12`) tail slots: optional
/// `frac` word, `'0'` pad while `precision<0`, then digits.
/// `width` is `[EBP+8]`, `precision` the `MOVSX` word at
/// `[EBP-0x26]`, `mode` the byte at `[EBP+0x10]`, `sep` the
/// word at `[EBP-0xC]`, `frac` the word at `[EBP-0xA]`;
/// `src`/`dst` are the `ESI`/`EDI` cursors, returned updated.
///
/// ponytail: direct call to done pure `fn_00408a7d` (no hook) —
/// same precedent as `fn_00408118` over pure `fn_00402fbc`.
pub unsafe fn fn_00408b47(
    width: u32,
    precision: i16,
    mode: u8,
    sep: u16,
    frac: u16,
    src: *mut u8,
    dst: *mut u16,
) -> (*mut u8, *mut u16) {
    let mut src = src;
    let mut dst = dst;
    // `MOV EDX,[EBP+8]; CMP EDX,0x12; JC skip; MOV EDX,0x12`.
    let mut edx = width;
    if edx >= 0x12 {
        edx = 0x12;
    }
    // `MOVSX ECX,[EBP-0x26]; OR ECX,ECX; JG long`.
    let mut ecx = precision as i32;
    if ecx <= 0 {
        // `MOV AX,0x30; STOSW; JMP phase2`.
        core::ptr::write_unaligned(dst, 0x30u16);
        dst = dst.wrapping_byte_add(2);
    } else {
        // `XOR EBX,EBX`.
        let mut ebx: u32 = 0;
        // `CMP [EBP+0x10],2; JZ digits`.
        if mode != 2 {
            // `MOV EAX,ECX; DEC EAX; MOV BL,3; DIV BL` (unsigned
            // `AX/3`); `MOV BL,AH; INC EBX`. Quotient lane
            // discarded.
            let ax = (ecx as u32).wrapping_sub(1) as u16;
            ebx = (ax as u32).wrapping_rem(3).wrapping_add(1);
        }
        loop {
            // `CALL 408a7d; STOSW`.
            let (ax, next) = fn_00408a7d(src);
            src = next;
            core::ptr::write_unaligned(dst, ax);
            dst = dst.wrapping_byte_add(2);
            // `DEC ECX; JZ phase2`.
            ecx = ecx.wrapping_sub(1);
            if ecx == 0 {
                break;
            }
            // `DEC EBX; JNZ digits`.
            ebx = ebx.wrapping_sub(1);
            if ebx != 0 {
                continue;
            }
            // `MOV AX,[EBP-0xC]; TEST AX,AX; JZ digits`.
            if sep == 0 {
                continue;
            }
            // `STOSW; MOV BL,3` (`EBX==0` here, so plain `=3`).
            core::ptr::write_unaligned(dst, sep);
            dst = dst.wrapping_byte_add(2);
            ebx = 3;
        }
    }
    // Phase 2: `OR EDX,EDX; JZ ret`.
    if edx == 0 {
        return (src, dst);
    }
    // `MOV AX,[EBP-0xA]; TEST AX,AX; JZ skip; STOSW`.
    if frac != 0 {
        core::ptr::write_unaligned(dst, frac);
        dst = dst.wrapping_byte_add(2);
    }
    // `JECXZ tail`.
    if ecx != 0 {
        // Pad loop: `STOSW '0'; DEC EDX; JZ ret; INC ECX; JNZ`.
        loop {
            core::ptr::write_unaligned(dst, 0x30u16);
            dst = dst.wrapping_byte_add(2);
            edx = edx.wrapping_sub(1);
            if edx == 0 {
                return (src, dst);
            }
            ecx = ecx.wrapping_add(1);
            if ecx == 0 {
                break;
            }
        }
    }
    // Tail loop: `CALL 408a7d; STOSW; DEC EDX; JNZ` (do-while).
    loop {
        let (ax, next) = fn_00408a7d(src);
        src = next;
        core::ptr::write_unaligned(dst, ax);
        dst = dst.wrapping_byte_add(2);
        edx = edx.wrapping_sub(1);
        if edx == 0 {
            break;
        }
    }
    (src, dst)
}

#[cfg(test)]
mod tests {
    use super::fn_00408b47;

    #[test]
    fn grouped_pad_and_tail_lanes() {
        // Pure callee, no hooks/globals: locals only, no TEST_LOCK.
        // Short lane: precision<=0 stores one '0', width 0 returns.
        let mut d0 = [0u16; 2];
        let src0 = b"q".as_ptr() as *mut u8;
        let (s, d) = unsafe { fn_00408b47(0, 0, 2, 0, 0, src0, d0.as_mut_ptr()) };
        assert_eq!(s, src0);
        assert_eq!(d, d0.as_mut_ptr().wrapping_byte_add(2));
        assert_eq!(d0[0], 0x30);
        // Separator lane: precision 4, group ((4-1)%3)+1=1 → sep
        // after first digit, reload 3, then 3 digits, ECX exhausts.
        let mut d1 = [0u16; 8];
        let src1 = b"1234".as_ptr() as *mut u8;
        let (s, _) = unsafe { fn_00408b47(0, 4, 0, 0x2c, 0, src1, d1.as_mut_ptr()) };
        assert_eq!(s, src1.wrapping_byte_add(4));
        assert_eq!(&d1[..5], &[0x31u16, 0x2c, 0x32, 0x33, 0x34]);
        // Mode==2 lane: no separators, 2 digits.
        let mut d2 = [0u16; 4];
        let src2 = b"56".as_ptr() as *mut u8;
        unsafe { fn_00408b47(0, 2, 2, 0x2c, 0, src2, d2.as_mut_ptr()) };
        assert_eq!(&d2[..2], &[0x35u16, 0x36]);
        // Frac+tail lane: 1 digit, width 2, '.' word (free — EDX
        // only decrements in pad/tail loops), then 2 tail digits.
        let mut d3 = [0u16; 8];
        let src3 = b"7ab".as_ptr() as *mut u8;
        let (s, _) = unsafe { fn_00408b47(2, 1, 2, 0, 0x2e, src3, d3.as_mut_ptr()) };
        assert_eq!(s, src3.wrapping_byte_add(3));
        assert_eq!(&d3[..4], &[0x37u16, 0x2e, 0x61, 0x62]);
        // Pad lane: precision -2, width 5 → '0' + 2 pads + 3 digits.
        let mut d4 = [0u16; 8];
        let src4 = b"xyz".as_ptr() as *mut u8;
        unsafe { fn_00408b47(5, -2, 2, 0, 0, src4, d4.as_mut_ptr()) };
        assert_eq!(
            &d4[..6],
            &[0x30u16, 0x30, 0x30, 0x78, 0x79, 0x7a]
        );
        // Pad-exhaustion lane: width 1 dies in the pad loop.
        let mut d5 = [0u16; 4];
        let src5 = b"q".as_ptr() as *mut u8;
        let (s, _) = unsafe { fn_00408b47(1, -1, 2, 0, 0, src5, d5.as_mut_ptr()) };
        assert_eq!(s, src5);
        assert_eq!(&d5[..2], &[0x30u16, 0x30]);
    }
}
