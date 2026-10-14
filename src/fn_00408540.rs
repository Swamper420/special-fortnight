//! Original procedure `0x00408540` (238 bytes, `0x00408540–0x0040862d`).
//! Evidence: `evidence/00408540_fn_00408540.md`.

use crate::fn_0040862e::fn_0040862e;

unsafe extern "C" fn default_0040867d(_c: u32, _n: usize, _end: *mut u16) {}

unsafe extern "C" fn default_00408914(_n: u32) -> u32 {
    0
}

/// Callee `0x0040867d` (`FUN_0040867d`), called with the current char in
/// `EAX`, remaining capacity in `EDX`, end bound in `ECX`. The
/// `PUSH ECX/PUSH EDX … POP EDX/POP ECX` pair is a save area (both
/// restored values are consumed afterwards), not stack args, so the
/// hook takes only the three register lanes. `ECX` is modeled as
/// preserved across the call (host locals persist).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040867d` once it exists.
pub static mut HOOK_0040867D: unsafe extern "C" fn(u32, usize, *mut u16) = default_0040867d;

/// Terminal tail target `0x00408914` (`FUN_00408914`), reached by `JMP`
/// with `EAX=(dst-base)>>1`; the leftover `EAX` is this procedure's
/// result (as consumed by done callers `fn_00408274`/`fn_00408290`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408914` once it exists.
pub static mut HOOK_00408914: unsafe extern "C" fn(u32) -> u32 = default_00408914;

/// Test-only serialization for tests sharing this module's hooks.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `u16` format scanner. `param_1` is the dst cursor (also the base
/// for the exit count), `param_2` the remaining capacity (pointer-typed
/// on target, pure count in this body — carried pointer-sized),
/// `param_3` the format cursor, `end = param_3 + param_6*2`,
/// `param_4`/`param_5` opaque args forwarded to `fn_0040862e`.
/// Literal/`%%` lanes store and consume capacity; `%` specs run the
/// `0x00408599/59f` shape (optional `-`, `fn_0040862e`, `:` re-entry,
/// optional `.` + second call, `HOOK_0040867D`, three saturating
/// copy/fill phases); every lane converges on the exit block.
/// `param_5` travels as `u32` bits (zero-extended to a table pointer
/// exactly like the target's 32-bit move).
pub unsafe fn fn_00408540(
    param_1: *mut u16,
    param_2: *mut u16,
    param_3: *mut u16,
    param_4: u32,
    param_5: u32,
    param_6: i32,
) -> u32 {
    let base = param_1;
    let mut dst = param_1;
    let mut cursor = param_3;
    // `LEA ECX,[ESI+ECX*2]`: signed count, sign-extended, wrapping.
    let end = param_3.wrapping_byte_offset((param_6 as isize).wrapping_mul(2));
    let mut count: usize = param_2 as usize;
    let mut star: u32 = 0;
    // Dead stores on target (`[EBP-0x4]`, `[EBP-0x10]`, spec-start
    // `[EBP-0x14]`, `[EBP-0x20]`) omitted: write-only, never read.
    'main: loop {
        if count == 0 {
            break;
        }
        if cursor == end {
            break;
        }
        let ch: u16 = core::ptr::read_unaligned(cursor);
        cursor = cursor.wrapping_add(1);
        if ch != 0x25 {
            core::ptr::write_unaligned(dst, ch);
            dst = dst.wrapping_add(1);
            count = count.wrapping_sub(1);
            if count == 0 {
                break;
            }
            continue;
        }
        if cursor == end {
            break;
        }
        let ch2: u16 = core::ptr::read_unaligned(cursor);
        cursor = cursor.wrapping_add(1);
        if ch2 == 0x25 {
            core::ptr::write_unaligned(dst, ch2);
            dst = dst.wrapping_add(1);
            count = count.wrapping_sub(1);
            if count == 0 {
                break;
            }
            continue;
        }
        let mut eax = ch2 as u32;
        loop {
            let save16 = (eax & 0xffff) as u16;
            if save16 == 0x2d {
                if cursor == end {
                    break 'main;
                }
                let w: u16 = core::ptr::read_unaligned(cursor);
                cursor = cursor.wrapping_add(1);
                eax = (eax & 0xffff0000) | (w as u32);
            }
            let ebx: u32 = match fn_0040862e(
                eax,
                &mut cursor as *mut *mut u16,
                end,
                &mut star,
                param_4,
                param_5 as *const u8,
            ) {
                Ok((e, b)) => {
                    eax = e;
                    b
                }
                Err(_) => break 'main,
            };
            if (eax & 0xffff) as u16 == 0x3a {
                star = ebx;
                if cursor == end {
                    break 'main;
                }
                let w: u16 = core::ptr::read_unaligned(cursor);
                cursor = cursor.wrapping_add(1);
                eax = (eax & 0xffff0000) | (w as u32);
                continue;
            }
            let save1c = ebx;
            if (eax & 0xffff) as u16 == 0x2e {
                if cursor == end {
                    break 'main;
                }
                let w: u16 = core::ptr::read_unaligned(cursor);
                cursor = cursor.wrapping_add(1);
                eax = (eax & 0xffff0000) | (w as u32);
                match fn_0040862e(
                    eax,
                    &mut cursor as *mut *mut u16,
                    end,
                    &mut star,
                    param_4,
                    param_5 as *const u8,
                ) {
                    Ok((e, _)) => {
                        eax = e;
                    }
                    Err(_) => break 'main,
                }
            }
            let save24 = cursor;
            HOOK_0040867D(eax, count, end);
            // `SUB/JNC/ADD/XOR` groups: `used = min(req, count)`.
            let end_us = end as usize;
            let mut ebx_w: usize = if (save1c as usize) >= end_us {
                (save1c as usize).wrapping_sub(end_us)
            } else {
                0
            };
            let mut ecx: usize = end_us;
            if save16 == 0x2d {
                let sub = count.wrapping_sub(ecx);
                if count >= ecx {
                    count = sub;
                } else {
                    ecx = ecx.wrapping_add(sub);
                    count = 0;
                }
                let mut t = cursor;
                for _ in 0..ecx {
                    core::ptr::write_unaligned(dst, core::ptr::read_unaligned(t));
                    dst = dst.wrapping_add(1);
                    t = t.wrapping_add(1);
                }
                ecx = 0;
            }
            core::mem::swap(&mut ecx, &mut ebx_w);
            let sub = count.wrapping_sub(ecx);
            if count >= ecx {
                count = sub;
            } else {
                ecx = ecx.wrapping_add(sub);
                count = 0;
            }
            for _ in 0..ecx {
                core::ptr::write_unaligned(dst, 0x20);
                dst = dst.wrapping_add(1);
            }
            ecx = 0;
            core::mem::swap(&mut ecx, &mut ebx_w);
            let sub = count.wrapping_sub(ecx);
            if count >= ecx {
                count = sub;
            } else {
                ecx = ecx.wrapping_add(sub);
                count = 0;
            }
            let mut t = cursor;
            for _ in 0..ecx {
                core::ptr::write_unaligned(dst, core::ptr::read_unaligned(t));
                dst = dst.wrapping_add(1);
                t = t.wrapping_add(1);
            }
            cursor = save24;
            continue 'main;
        }
    }
    // `0x00408581`: byte difference `>> 1` (u16 count), tail call.
    // ponytail: `as u32` narrows a small element count (never a
    // pointer); exact while output stays under 2G units, as on target.
    let n = ((dst as usize).wrapping_sub(base as usize) >> 1) as u32;
    HOOK_00408914(n)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040867D, HOOK_00408914, TEST_LOCK, fn_00408540};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLEE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_C: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: u32, b: usize, c: *mut u16) {
        CALLEE_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b, Ordering::SeqCst);
        GOT_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(n: u32) -> u32 {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(n as usize, Ordering::SeqCst);
        TAIL_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn scan_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040867D = callee;
            HOOK_00408914 = tail;
        }
        TAIL_RET.store(0x51, Ordering::SeqCst);
        // Capacity travels pointer-typed (target EDX dual-use).
        let cap = 8 as *mut u16;
        let mut dst = [0u16; 16];

        // Literal lane: "AB" stores 2, exits at end.
        let fmt_a = [0x41u16, 0x42];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_a.as_ptr() as *mut u16, 0, 0, 2) };
        assert_eq!(r, 0x51);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(dst[0], 0x41);
        assert_eq!(dst[1], 0x42);

        // "%%" lane: one literal '%', exits at end.
        dst.fill(0);
        let fmt_b = [0x25u16, 0x25];
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_b.as_ptr() as *mut u16, 0, 0, 2) };
        assert_eq!(r, 0x51);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(dst[0], 0x25);

        // Plain-spec lane: "%d" + 8 literal words; callee fires once,
        // final phase fills remaining capacity from the cursor.
        dst.fill(0);
        let fmt_c = [0x25u16, 0x64, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        let end_c = unsafe { fmt_c.as_ptr().wrapping_add(10) } as usize;
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_c.as_ptr() as *mut u16, 0, 0, 10) };
        assert_eq!(r, 0x51);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), 0x64);
        assert_eq!(GOT_B.load(Ordering::SeqCst), 8);
        assert_eq!(GOT_C.load(Ordering::SeqCst), end_c);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(&dst[..8], &[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48][..]);

        // '-'-spec lane: "%-x" copies the pending chunk first.
        dst.fill(0);
        let fmt_d = [0x25u16, 0x2d, 0x78, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_d.as_ptr() as *mut u16, 0, 0, 11) };
        assert_eq!(r, 0x51);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), 0x78);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(&dst[..8], &[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68][..]);
        // End-in-spec lane: "%5" hits the terminal lane inside the
        // digit loop — no callee, zero output.
        dst.fill(0);
        let fmt_e = [0x25u16, 0x35];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_e.as_ptr() as *mut u16, 0, 0, 2) };
        assert_eq!(r, 0x51);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0);

        // ':'-re-entry lane: "%5:Y" parses width, re-processes 'Y'.
        dst.fill(0);
        let fmt_f = [
            0x25u16, 0x35, 0x3a, 0x59, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        ];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408540(dst.as_mut_ptr(), cap, fmt_f.as_ptr() as *mut u16, 0, 0, 12) };
        assert_eq!(r, 0x51);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), 0x59);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(&dst[..8], &[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68][..]);
    }
}
