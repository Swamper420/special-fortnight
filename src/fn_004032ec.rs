//! Original procedure `0x004032ec` (258 bytes, `0x004032ec–0x004033ed`).
//! Evidence: `evidence/004032ec_fn_004032ec.md`.

/// Wide-char integer parse: skip spaces, optional sign, `$`/`0x`
/// hex or decimal digits with pre-multiply overflow guards.
/// Returns the accumulator; `*param_2` is wchar units consumed on
/// the error lane, `0` on success. `param_1` EAX / `param_2` EDX
/// per Ghidra `__register` observation. All arithmetic wraps
/// (`wrapping_*`); char subtracts use unsigned 16-bit wrap so
/// `JA`/`JBE` Chel alike match.
pub unsafe fn fn_004032ec(param_1: *const u16, param_2: *mut u32) -> u32 {
    unsafe {
        if param_1.is_null() {
            // 0x004032f4→0x0040337d→0x00403388: ESI=0+2, (2-0)>>1.
            core::ptr::write_unaligned(param_2, 1);
            return 0;
        }
        let mut esi = param_1;
        let mut eax: u32 = 0;
        // Space skip (0x00403303): read, advance, loop while 0x20.
        let mut w: u16;
        loop {
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
            if w != 0x20 {
                break;
            }
        }
        // Sign into CH (0x0040330f–0x00403395).
        let mut neg = false;
        if w == 0x2d {
            neg = true;
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
        } else if w == 0x2b {
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
        }
        // Prefix dispatch (0x0040331d): hex select, or decimal loop
        // entered with the already-read char in `w`.
        let hex: bool;
        if w == 0x24 || w == 0x78 || w == 0x58 {
            hex = true;
        } else if w == 0x30 {
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
            if w == 0x78 || w == 0x58 {
                hex = true;
            } else if w == 0 {
                // 0x00403347→0x00403373 end lane with EAX==0.
                if neg {
                    // NEG 0; JLE takes it.
                    core::ptr::write_unaligned(param_2, 0);
                    return 0;
                }
                core::ptr::write_unaligned(param_2, 0);
                return 0;
            } else {
                hex = false;
            }
        } else if w == 0 {
            // 0x0040334e→0x00403388.
            let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
            core::ptr::write_unaligned(param_2, used);
            return eax;
        } else {
            hex = false;
        }
        if hex {
            // Hex lane (0x00403397).
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
            if w == 0 {
                // 0x0040337d: one more wchar past NUL, then error.
                esi = esi.wrapping_add(1);
                let used =
                    ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
                core::ptr::write_unaligned(param_2, used);
                return eax;
            }
            loop {
                if w > 0x60 {
                    w = w.wrapping_sub(0x20);
                }
                let mut d = w.wrapping_sub(0x30);
                if d > 9 {
                    let e = w.wrapping_sub(0x41);
                    if e > 5 {
                        let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1)
                            as u32;
                        core::ptr::write_unaligned(param_2, used);
                        return eax;
                    }
                    d = e.wrapping_add(0xa);
                }
                if eax > 0xfffffff {
                    let used =
                        ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
                    core::ptr::write_unaligned(param_2, used);
                    return eax;
                }
                eax = eax.wrapping_shl(4).wrapping_add(d as u32);
                w = core::ptr::read_unaligned(esi);
                esi = esi.wrapping_add(1);
                if w == 0 {
                    break;
                }
            }
            // Hex end (0x004033dd): DEC CH; JNZ ok; else NEG then ok.
            if neg {
                eax = eax.wrapping_neg();
            }
            core::ptr::write_unaligned(param_2, 0);
            return eax;
        }
        // Decimal loop (0x00403353) starting at `w`.
        loop {
            let d = w.wrapping_sub(0x30);
            if d > 9 {
                let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
                core::ptr::write_unaligned(param_2, used);
                return eax;
            }
            if eax > 0xccccccc {
                let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
                core::ptr::write_unaligned(param_2, used);
                return eax;
            }
            // LEA+ADD+ADD = ×10, wrapping.
            eax = eax.wrapping_mul(10).wrapping_add(d as u32);
            w = core::ptr::read_unaligned(esi);
            esi = esi.wrapping_add(1);
            if w == 0 {
                break;
            }
        }
        // Decimal end (0x00403373): DEC CH; JZ negate lane.
        if neg {
            // 0x00403382: NEG then JLE/JS; union is exactly r <= 0.
            let r = (eax as i32).wrapping_neg();
            eax = r as u32;
            if r <= 0 {
                core::ptr::write_unaligned(param_2, 0);
                return eax;
            }
            let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
            core::ptr::write_unaligned(param_2, used);
            return eax;
        }
        if (eax as i32) >= 0 {
            core::ptr::write_unaligned(param_2, 0);
            return eax;
        }
        let used = ((esi as usize).wrapping_sub(param_1 as usize) >> 1) as u32;
        core::ptr::write_unaligned(param_2, used);
        eax
    }
}

#[cfg(test)]
mod tests {
    use super::fn_004032ec;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0, 0]).collect()
    }

    fn run(s: &str) -> (u32, u32) {
        let v = wide(s);
        let mut used = 0xdead_u32;
        let r = unsafe { fn_004032ec(v.as_ptr(), &mut used) };
        (r, used)
    }

    #[test]
    fn lanes() {
        unsafe {
            let mut used = 0xdead_u32;
            assert_eq!(
                (fn_004032ec(core::ptr::null(), &mut used), used),
                (0, 1)
            );
        }
        assert_eq!(run("123"), (123, 0));
        assert_eq!(run("-123"), (0xffffff85, 0));
        assert_eq!(run("+123"), (123, 0));
        assert_eq!(run("   42"), (42, 0));
        assert_eq!(run("0"), (0, 0));
        assert_eq!(run("-0"), (0, 0));
        assert_eq!(run("012"), (12, 0));
        assert_eq!(run("2147483647"), (0x7fffffff, 0));
        assert_eq!(run("0x10"), (16, 0));
        assert_eq!(run("$FF"), (255, 0));
        assert_eq!(run("0X1a"), (26, 0));
        assert_eq!(run("-0x10"), (0xfffffff0, 0));
        assert_eq!(run(""), (0, 1));
        assert_eq!(run("q"), (0, 1));
        assert_eq!(run("12q"), (12, 3));
        assert_eq!(run("9999999999"), (999999999, 10));
        assert_eq!(run("2147483648"), (0x80000000, 11));
        assert_eq!(run("-2147483648"), (0x80000000, 0));
        assert_eq!(run("-2147483649"), (0x7fffffff, 12));
        assert_eq!(run("0x100000000"), (0x10000000, 11));
    }
}
