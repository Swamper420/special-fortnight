//! Original procedure `0x0040c750` (188 bytes, `0x0040c750–0x0040c80b`).
//! Evidence: `evidence/0040c750_fn_0040c750.md`.

/// In-place marker transform over `buf[0..len)`: for each `0xe8`/`0xe9`
/// byte at `i` with guard `[i+4] ∈ {0x00, 0xff}`, rebuild the 24-bit
/// LE value at `[i+1..i+4]`, subtract (`param_3==0`) or add
/// (`param_3!=0`) `(param_4 + i + 5) & 0xffffff`, complement the guard
/// when bit 23 lands set, store the value back. `param_1` in EAX,
/// `param_2` in EDX, `param_3` in CL, `param_4` on the stack
/// (`RET 0x4`, host-invisible). All `CMP/JL/JGE` stay signed; `SUB/ADD`
/// wrap. Returns void.
pub unsafe fn fn_0040c750(param_1: *mut u8, param_2: i32, param_3: u8, param_4: i32) {
    if param_2 <= 4 {
        return;
    }
    let limit = param_2.wrapping_sub(4);
    if limit <= 0 {
        return;
    }
    let mut i: i32 = 0;
    loop {
        let b: u8 = *param_1.wrapping_byte_add(i as usize);
        if b == 0xe8 || b == 0xe9 {
            let i2 = i.wrapping_add(1);
            let guard: u8 = *param_1.wrapping_byte_add((i2 as usize).wrapping_add(3));
            if guard == 0x00 || guard == 0xff {
                let uvar3: u32 =
                    (param_4 as u32).wrapping_add(i2 as u32).wrapping_add(4) & 0xffffff;
                let mut uvar4: u32 = *param_1.wrapping_byte_add(i2 as usize) as u32
                    | ((*param_1.wrapping_byte_add((i2 as usize).wrapping_add(1)) as u32) << 8)
                    | ((*param_1.wrapping_byte_add((i2 as usize).wrapping_add(2)) as u32) << 16);
                if param_3 == 0 {
                    uvar4 = uvar4.wrapping_sub(uvar3);
                }
                if uvar4 & 0x800000 != 0 {
                    let slot = param_1.wrapping_byte_add((i2 as usize).wrapping_add(3));
                    *slot = !*slot;
                }
                if param_3 != 0 {
                    uvar4 = uvar4.wrapping_add(uvar3);
                }
                *param_1.wrapping_byte_add(i2 as usize) = uvar4 as u8;
                *param_1.wrapping_byte_add((i2 as usize).wrapping_add(1)) = (uvar4 >> 8) as u8;
                *param_1.wrapping_byte_add((i2 as usize).wrapping_add(2)) = (uvar4 >> 16) as u8;
            }
            i = i2.wrapping_add(4);
        } else {
            i = i.wrapping_add(1);
        }
        if i >= limit {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040c750;

    #[test]
    fn marker_lanes() {
        // Decode lane: 0x030201 - 0x105 = 0x0300fc, no NOT (bit 23 clear).
        let mut a = [0xe8u8, 0x01, 0x02, 0x03, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45];
        unsafe { fn_0040c750(a.as_mut_ptr(), 10, 0, 0x100) };
        assert_eq!(a, [0xe8, 0xfc, 0x00, 0x03, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45]);
        // Encode+NOT lane: 0x800000 + 5 = 0x800005, guard 0xff -> 0x00.
        let mut b = [0xe9u8, 0x00, 0x00, 0x80, 0xff, 0x41, 0x42, 0x43, 0x44];
        unsafe { fn_0040c750(b.as_mut_ptr(), 9, 1, 0) };
        assert_eq!(b, [0xe9, 0x05, 0x00, 0x80, 0x00, 0x41, 0x42, 0x43, 0x44]);
        // Guard-skip lane: marker with guard 0x42, stride +5, untouched.
        let mut c = [0xe8u8, 0x11, 0x22, 0x33, 0x42, 0xe8, 0x00, 0x00, 0x00];
        unsafe { fn_0040c750(c.as_mut_ptr(), 9, 0, 0) };
        assert_eq!(c, [0xe8, 0x11, 0x22, 0x33, 0x42, 0xe8, 0x00, 0x00, 0x00]);
        // Short-len early out.
        let mut d = [0xe8u8, 0x01, 0x02, 0x03];
        unsafe { fn_0040c750(d.as_mut_ptr(), 4, 0, 0x100) };
        assert_eq!(d, [0xe8, 0x01, 0x02, 0x03]);
    }
}
