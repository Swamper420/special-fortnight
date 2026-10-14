//! Original procedure `0x00408924` (98 bytes, `0x408924–0x408985`).
//! Evidence: `evidence/00408924_fn_00408924.md`.

/// Divisor observed as `dword ptr [ESI+0x412830]` with `ESI=0`
/// (`DAT_00412830`).
///
/// ponytail: absolute-address cell as mutable hook, upgrade to real
/// image-relative import once data layout proven. Default 10 is an
/// inference (decimal digit loop); unproven.
pub static mut DAT_00412830: u32 = 10;

/// Number writer. `EAX` packs `(AL=c1, AH=c2, BL=mode, BH=wide)`,
/// `EDX` is the value, `ECX` the minimum digit count, `EDI` (`dest`)
/// the cursor. Stores `c1`, the `wide`/`mode`/`AH` lanes, then the
/// magnitude in `DAT_00412830`-base with at least `min_digits`
/// digits. Returns `(magnitude, cursor)` (`EAX` + advanced `EDI`
/// pair, same precedent as `fn_00407cd8`).
pub unsafe fn fn_00408924(
    dest: *mut u8,
    eax_pack: u32,
    value: u32,
    min_digits: i32,
) -> (u32, *mut u8) {
    let b = eax_pack.to_le_bytes();
    let (c1, c2, mode, wide) = (b[0], b[1], b[2], b[3]);
    let mut out = dest;
    let mut al = c1;
    core::ptr::write_unaligned(out, al);
    out = out.wrapping_byte_add(1);
    if wide != 0 {
        al = 0;
        core::ptr::write_unaligned(out, 0);
        out = out.wrapping_byte_add(1);
    }
    let mut mag = value;
    let mut store_ah = false;
    if mode == 0 {
        mag = 0;
        if c2 != 0 {
            al = c2;
            store_ah = true;
        }
    } else if (value as i32) < 0 {
        al = 0x2d;
        mag = value.wrapping_neg();
        store_ah = true;
    } else if c2 != 0 {
        al = c2;
        store_ah = true;
    }
    if store_ah {
        core::ptr::write_unaligned(out, al);
        out = out.wrapping_byte_add(1);
        if wide != 0 {
            core::ptr::write_unaligned(out, 0);
            out = out.wrapping_byte_add(1);
        }
    }
    let div = DAT_00412830;
    // ponytail: 36-byte temp covers binary widths plus slack;
    // unbounded min_digits truncates (original smashes its frame).
    let mut tmp = [0u8; 36];
    let mut n = 0usize;
    let mut v = mag;
    let mut w = min_digits;
    loop {
        let q = v / div;
        let r = v % div;
        if n < tmp.len() {
            tmp[n] = (r as u8).wrapping_add(0x30);
            n += 1;
        }
        w = w.wrapping_sub(1);
        v = q;
        if v != 0 {
            continue;
        }
        if w > 0 {
            continue;
        }
        break;
    }
    // Assembly reads the interleave flag as `CH` of the popped
    // magnitude (byte 2), not pack `BH` (see evidence).
    let interleave = ((mag >> 16) as u8) != 0;
    let mut i = n;
    loop {
        i -= 1;
        core::ptr::write_unaligned(out, tmp[i]);
        out = out.wrapping_byte_add(1);
        if interleave {
            core::ptr::write_unaligned(out, 0);
            out = out.wrapping_byte_add(1);
        }
        if i != 0 {
            continue;
        }
        break;
    }
    (mag, out)
}

#[cfg(test)]
mod tests {
    use super::{DAT_00412830, fn_00408924};

    fn run(pack: u32, value: u32, min: i32) -> (Vec<u8>, u32, usize) {
        let mut buf = [0xccu8; 40];
        let (mag, end) = unsafe { fn_00408924(buf.as_mut_ptr(), pack, value, min) };
        let n = (end as usize).wrapping_sub(buf.as_ptr() as usize);
        (buf[..n].to_vec(), mag, n)
    }

    const fn pack(c1: u8, c2: u8, mode: u8, wide: u8) -> u32 {
        (c1 as u32) | ((c2 as u32) << 8) | ((mode as u32) << 16) | ((wide as u32) << 24)
    }

    #[test]
    fn lanes() {
        unsafe { DAT_00412830 = 10 };
        // Mode 0 forces magnitude 0; single prefix, one digit.
        let (s, mag, n) = run(pack(b'A', 0, 0, 0), 0xdead, 1);
        assert_eq!((s.as_slice(), mag, n), (b"A0".as_slice(), 0, 2));
        // Negative with AH set: sign lane stores only '-', AH never
        // stores on this path (JMP straight to STOSB).
        let (s, mag, n) = run(pack(b'A', b'.', 1, 0), (-5i32) as u32, 1);
        assert_eq!((s.as_slice(), mag, n), (b"A-5".as_slice(), 5, 3));
        // Wide lane with mag > 0xffff: NUL after every stored byte.
        let (s, mag, n) = run(pack(b'W', 0, 1, 1), 0x12345, 1);
        assert_eq!(
            (s.as_slice(), mag, n),
            (
                [0x57, 0, 0x37, 0, 0x34, 0, 0x35, 0, 0x36, 0, 0x35, 0].as_slice(),
                0x12345,
                12
            )
        );
        // Wide lane with AH set but small magnitude: prefix, NUL, AH,
        // NUL, then plain digits (interleave keys off mag byte 2).
        let (s, mag, n) = run(pack(b'A', b'.', 0, 1), 0, 1);
        assert_eq!((s.as_slice(), mag, n), ([b'A', 0, b'.', 0, b'0'].as_slice(), 0, 5));
    }
}
