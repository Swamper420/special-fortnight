//! Original procedure `0x0040867d` (575 bytes, `0x0040867d–0x004086a3` +
//! `0x004086ec–0x00408903`, non-contiguous; gap is the jump table).
//! Evidence: `evidence/0040867d_fn_0040867d.md`.

unsafe extern "C" fn default_8480(
    _v: u32,
    _start: *mut u8,
    _count: u32,
    _ebx: u32,
    _out: *mut *mut u8,
) -> u32 {
    0
}
unsafe extern "C" fn default_8500(_slot: *mut u8) {}
unsafe extern "C" fn default_8524(
    _buf: *mut u8,
    _val: u32,
    _mode: u32,
    _b: u32,
    _a: u32,
    _pack: u32,
) -> u32 {
    0
}
unsafe extern "C" fn default_4b9c(_slot: *mut u32, _src: *const u16, _len: u32) {}
unsafe extern "C" fn default_7cd8(_val: u32, _width: u32, _base: u32, _cursor: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_indirect(
    _base: u32,
    _off: u32,
    _slot: *mut u8,
    _val: *mut u8,
    _count: u32,
) {
}
unsafe extern "C" fn default_tail(_val: *mut u8, _width: u32, _base: u32, _cursor: *mut u8) -> u32 {
    0
}

/// Fallback-loop head `0x00408904` (`FUN_00408904`), always called
/// with 0 from the loop: direct intra-reconstruction call (rewired;
/// signatures verified `fn(u32) -> u32`). Its scratch hook stays,
/// pinned by the test under the callee lock.

/// Callee `0x00408480` (`FUN_00408480`): `(v, start, count, ebx)`,
/// returns the class char in `ECX` and the pointer in `EAX`
/// (split via `out`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408480` once it exists.
pub static mut HOOK_00408480: unsafe extern "C" fn(u32, *mut u8, u32, u32, *mut *mut u8) -> u32 =
    default_8480;

/// Callee `0x00408500` (`FUN_00408500`) with the `EBP-0x10` slot.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408500` once it exists.
pub static mut HOOK_00408500: unsafe extern "C" fn(*mut u8) = default_8500;

/// Callee `0x00408524` (`FUN_00408524`): `(buf:EAX, val:EDX,
/// mode:ECX=bh, b:EDX-push, a:EAX-push, pack:EBX-push)` from the
/// observed reg/push order.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408524` once it exists.
pub static mut HOOK_00408524: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32) -> u32 =
    default_8524;

/// Callee `0x00404b9c` (`FUN_00404b9c`): `(slot, wide_src, len)`.
///
/// ponytail: hook standing in for reconstructed `fn_00404b9c`,
/// rewire to real call once cross-module linkage proven.
pub static mut HOOK_00404B9C: unsafe extern "C" fn(*mut u32, *const u16, u32) = default_4b9c;

/// Tail target `0x00407cd8` (`FUN_00407cd8`): `(value, width, base,
/// cursor)`.
///
/// ponytail: hook standing in for reconstructed `fn_00407cd8`,
/// rewire to real call once cross-module linkage proven.
pub static mut HOOK_00407CD8: unsafe extern "C" fn(u32, u32, u32, *mut u8) -> u32 = default_7cd8;

/// Indirect `CALL ESI` (`0x004087ee`): `(base, frame_off, slot, val,
/// count)`; base is one of `0x00404b8c/0x00404bc0/0x00404bf0` per arm.
///
/// ponytail: hook standing in for unreconstructed indirect targets.
pub static mut HOOK_INDIRECT: unsafe extern "C" fn(u32, u32, *mut u8, *mut u8, u32) =
    default_indirect;

/// Tail target `0x00407d38` (`LAB_00407d38`, out-of-body float/int
/// tail): `(value:EAX, width:EDX, base:ECX, cursor:ESI)`.
///
/// ponytail: hook standing in for code outside this procedure.
pub static mut TAIL_00407D38: unsafe extern "C" fn(*mut u8, u32, u32, *mut u8) -> u32 = default_tail;

/// Data byte `0x00415b76` (`DAT_00415b76`), `M`-lane precision.
///
/// ponytail: absolute-address cell as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_00415B76: u8 = 0;

unsafe fn rd32(f: *mut u8, off: isize) -> u32 {
    let p = if off < 0 {
        f.wrapping_byte_sub(off.wrapping_neg() as usize)
    } else {
        f.wrapping_byte_add(off as usize)
    };
    core::ptr::read_unaligned(p as *const u32)
}

unsafe fn wr32(f: *mut u8, off: isize, v: u32) {
    let p = if off < 0 {
        f.wrapping_byte_sub(off.wrapping_neg() as usize)
    } else {
        f.wrapping_byte_add(off as usize)
    };
    core::ptr::write_unaligned(p as *mut u32, v);
}

/// Pointer link `+0xc` (entry-table base): pointer-sized on host
/// (same precedent as `fn_004046c4`).
unsafe fn rd_base(f: *mut u8) -> *mut u8 {
    core::ptr::read_unaligned(f.wrapping_byte_add(0xc) as *const *mut u8)
}

/// Shared `0x00408815/0x0040881e` tail: null → 0, else
/// `[esi-4]>>1` clamped (unsigned `JA`) to `[EBP-0x20]`.
unsafe fn len_tail(frame: *mut u8, esi: *mut u8) -> u32 {
    if esi.is_null() {
        return 0;
    }
    let len: u32 = core::ptr::read_unaligned(esi.wrapping_byte_sub(4) as *const u32);
    let len = len.wrapping_shr(1);
    let lim = rd32(frame, -0x20);
    if len > lim { lim } else { len }
}

unsafe fn indirect(frame: *mut u8, ecx: u32, slot: *mut u8, val: u32, base: u32) -> u32 {
    if (ecx as u8) != 0x53 {
        return fallback(frame);
    }
    HOOK_INDIRECT(base, rd32(frame, -4), slot, val as *mut u8, ecx);
    len_tail(frame, core::ptr::read_unaligned(slot as *const *mut u8))
}

unsafe fn case_c(frame: *mut u8, val: u32, ecx: u32, bh: u8) -> u32 {
    let bl = ecx as u8;
    let (pack, a, b);
    if bl == 0x47 || bl == 0x45 {
        let mut lim = rd32(frame, -0x20);
        if lim > 0x12 {
            lim = 0xf;
        }
        pack = (bh as u32).wrapping_shl(8);
        a = lim;
        b = 3;
    } else {
        let bl2 = if bl == 0x46 {
            2
        } else if bl == 0x4e {
            3
        } else if bl == 0x4d {
            4
        } else {
            return fallback(frame);
        };
        let prec = rd32(frame, -0x20);
        let mut b_out = prec;
        if prec > 0x12 {
            b_out = if bl == 0x4d { DAT_00415B76 as u32 } else { 2 };
        }
        pack = (bl2 as u32) | (bh as u32).wrapping_shl(8);
        a = 0x12;
        b = b_out;
    }
    let buf = frame.wrapping_byte_sub(0xa6);
    let len = HOOK_00408524(buf, val, bh as u32, b, a, pack);
    let slot = frame.wrapping_byte_sub(0x10);
    HOOK_00404B9C(slot as *mut u32, buf as *const u16, len);
    len_tail(frame, core::ptr::read_unaligned(slot as *const *mut u8))
}

/// Fallback/default loop at `0x004086ec`: `8904(0)`, `8480`, clamp
/// width to `0x20`, classify raw `D/X/U` (no case mask here) else
/// repeat.
unsafe fn fallback(frame: *mut u8) -> u32 {
    loop {
        let v = crate::fn_00408904::fn_00408904(0);
        let start = rd32(frame, -0x14) as *mut u8;
        let end = rd32(frame, -0x24);
        let count = end.wrapping_sub(start as u32).wrapping_shr(1);
        let ebx = rd32(frame, -0x4);
        let mut outp: *mut u8 = core::ptr::null_mut();
        let cls = HOOK_00408480(v, start, count, ebx, &mut outp as *mut *mut u8);
        let mut w = rd32(frame, -0x20);
        if w > 0x20 {
            w = 0;
        }
        let bl = cls as u8;
        let cursor = frame.wrapping_byte_sub(0x66);
        if bl == 0x44 {
            return TAIL_00407D38(outp, w, cls & 0xffffff00, cursor);
        } else if bl == 0x58 {
            return TAIL_00407D38(outp, w, 0x10, cursor);
        } else if bl == 0x55 {
            return TAIL_00407D38(outp, w, 0x0a, cursor);
        }
    }
}

/// Format dispatcher over the caller frame (`EBP` value).
/// `param_1` arrives in `AL` (masked `& 0xdf`); `param_3` is the
/// entry `ECX` (low byte overwritten by the mask, high bytes feed
/// the `D`-lane base); `EDX` is dead on entry. Returns the observed
/// `ECX` lane value.
pub unsafe fn fn_0040867d(frame: *mut u8, param_1: u8, param_3: u32) -> u32 {
    let masked = param_1 & 0xdf;
    let ix = rd32(frame, -0xC);
    let bound = rd32(frame, 8);
    if (ix as i32) > (bound as i32) {
        return fallback(frame);
    }
    wr32(frame, -0xC, ix.wrapping_add(1));
    let ent = rd_base(frame).wrapping_byte_add((ix as usize).wrapping_mul(8));
    let val: u32 = core::ptr::read_unaligned(ent as *const u32);
    let disp: u8 = core::ptr::read_unaligned(ent.wrapping_byte_add(4) as *const u8);
    let ecx = (param_3 & 0xffffff00) | masked as u32;
    let slot = frame.wrapping_byte_sub(0x10);
    match disp {
        0 => {
            let mut w = rd32(frame, -0x20);
            if w > 0x10 {
                w = 0;
            }
            let bl = ecx as u8;
            let base_arg = if bl == 0x44 {
                ecx & 0xffffff00
            } else if bl == 0x58 {
                0x10
            } else if bl == 0x55 {
                0x0a
            } else {
                return fallback(frame);
            };
            HOOK_00407CD8(val, w, base_arg, frame.wrapping_byte_sub(0x86))
        }
        2 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            HOOK_INDIRECT(0x00404b8c, rd32(frame, -4), slot, ent, 1);
            len_tail(frame, core::ptr::read_unaligned(slot as *const *mut u8))
        }
        3 => case_c(frame, val, ecx, 0),
        4 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            let n: u8 = core::ptr::read_unaligned(val as *const u8);
            HOOK_INDIRECT(
                0x00404b8c,
                rd32(frame, -4),
                slot,
                val.wrapping_add(1) as *mut u8,
                n as u32,
            );
            len_tail(frame, core::ptr::read_unaligned(slot as *const *mut u8))
        }
        5 => {
            if (ecx as u8) != 0x50 {
                return fallback(frame);
            }
            HOOK_00407CD8(val, 8, 0x10, frame.wrapping_byte_sub(0x86))
        }
        6 => indirect(frame, ecx, slot, val, 0x00404bc0),
        9 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            1
        }
        10 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            let n = rd32(frame, -0x20) as usize;
            let mut p = val as *const u16;
            let mut k = 0usize;
            while k < n {
                if core::ptr::read_unaligned(p) == 0 {
                    break;
                }
                p = p.wrapping_add(1);
                k += 1;
            }
            k as u32
        }
        11 => indirect(frame, ecx, slot, val, 0x00404bf0),
        12 => case_c(frame, val, ecx, 1),
        13 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            let w: u16 = core::ptr::read_unaligned(val as *const u16);
            if w < 2 {
                return 0;
            }
            HOOK_00408500(slot);
            len_tail(frame, core::ptr::read_unaligned(slot as *const *mut u8))
        }
        15 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            len_tail(frame, val as *mut u8)
        }
        16 => {
            let mut w = rd32(frame, -0x20);
            if w > 0x20 {
                w = 0;
            }
            let bl = ecx as u8;
            let base_arg = if bl == 0x44 {
                ecx & 0xffffff00
            } else if bl == 0x58 {
                0x10
            } else if bl == 0x55 {
                0x0a
            } else {
                return fallback(frame);
            };
            TAIL_00407D38(val as *mut u8, w, base_arg, frame.wrapping_byte_sub(0x66))
        }
        17 => {
            if (ecx as u8) != 0x53 {
                return fallback(frame);
            }
            let esi = val as *mut u8;
            if esi.is_null() {
                return 0;
            }
            let len: u32 = core::ptr::read_unaligned(esi.wrapping_byte_sub(4) as *const u32);
            let lim = rd32(frame, -0x20);
            if len > lim { lim } else { len }
        }
        _ => fallback(frame),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415B76, HOOK_00407CD8, HOOK_00408480, HOOK_INDIRECT, TAIL_00407D38, fn_0040867d,
        rd32, wr32,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CD_V: AtomicUsize = AtomicUsize::new(0);
    static CD_W: AtomicUsize = AtomicUsize::new(0);
    static CD_B: AtomicUsize = AtomicUsize::new(0);
    static CD_C: AtomicUsize = AtomicUsize::new(0);
    static IN_BASE: AtomicUsize = AtomicUsize::new(0);
    static IN_COUNT: AtomicUsize = AtomicUsize::new(0);
    static IN_VAL: AtomicUsize = AtomicUsize::new(0);
    static INNER_HITS: AtomicUsize = AtomicUsize::new(0);
    static C8480_CLS: AtomicUsize = AtomicUsize::new(0x44);
    static TAIL_W: AtomicUsize = AtomicUsize::new(0);
    static TAIL_B: AtomicUsize = AtomicUsize::new(0);

    static mut ENTRY: [u32; 2] = [0; 2];
    static mut ARENA: [u8; 128] = [0; 128];

    unsafe extern "C" fn h7cd8(val: u32, w: u32, b: u32, cursor: *mut u8) -> u32 {
        CD_V.store(val as usize, Ordering::SeqCst);
        CD_W.store(w as usize, Ordering::SeqCst);
        CD_B.store(b as usize, Ordering::SeqCst);
        CD_C.store(cursor as usize, Ordering::SeqCst);
        0x77
    }

    unsafe extern "C" fn hind(base: u32, _off: u32, slot: *mut u8, val: *mut u8, count: u32) {
        IN_BASE.store(base as usize, Ordering::SeqCst);
        IN_VAL.store(val as usize, Ordering::SeqCst);
        IN_COUNT.store(count as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(slot as *mut *mut u8, core::ptr::null_mut());
    }

    /// Real `fn_00408904` scratch hook behind the fallback head
    /// (passthrough 0, fires once per fallback).
    unsafe extern "C" fn inner(_slot: *mut u32) {
        INNER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn h8480(
        _v: u32,
        _s: *mut u8,
        _c: u32,
        _b: u32,
        out: *mut *mut u8,
    ) -> u32 {
        core::ptr::write_unaligned(out, 0x1234 as *mut u8);
        C8480_CLS.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn ttail(val: *mut u8, w: u32, b: u32, _c: *mut u8) -> u32 {
        CD_V.store(val as usize, Ordering::SeqCst);
        TAIL_W.store(w as usize, Ordering::SeqCst);
        TAIL_B.store(b as usize, Ordering::SeqCst);
        0x99
    }

    unsafe fn frame() -> *mut u8 {
        core::ptr::addr_of_mut!(ARENA).wrapping_byte_add(64) as *mut u8
    }

    unsafe fn setup(disp: u32, val: u32) -> *mut u8 {
        ENTRY = [val, disp];
        let f = frame();
        wr32(f, -0xC, 0);
        wr32(f, 8, 5);
        core::ptr::write_unaligned(
            f.wrapping_byte_add(0xc) as *mut *mut u8,
            core::ptr::addr_of_mut!(ENTRY) as *mut u8,
        );
        f
    }

    #[test]
    fn dispatch_lanes() {
        // Real `fn_00408904` behind the fallback head: hold its
        // lock, pin the scratch hook, save/restore.
        let _head = crate::fn_00408904::TEST_LOCK.lock().unwrap();
        let old_inner;
        unsafe {
            HOOK_00407CD8 = h7cd8;
            HOOK_INDIRECT = hind;
            old_inner = crate::fn_00408904::HOOK_00404A8C;
            crate::fn_00408904::HOOK_00404A8C = inner;
            HOOK_00408480 = h8480;
            TAIL_00407D38 = ttail;
        }
        // Case 9, 's' masked to 'S' → return 1, index bumped.
        let f = unsafe { setup(9, 0x9999) };
        assert_eq!(unsafe { fn_0040867d(f, b's', 0) }, 1);
        assert_eq!(unsafe { rd32(f, -0xC) }, 1);
        // Case 0, 'd' → 7cd8 tail (value, width, base keeps param_3
        // high bytes with low byte zeroed). Width > 0x10 zeroes.
        let f = unsafe { setup(0, 0x1234) };
        unsafe { wr32(f, -0x20, 5) };
        assert_eq!(unsafe { fn_0040867d(f, b'd', 0x1234_5600) }, 0x77);
        assert_eq!(CD_V.load(Ordering::SeqCst), 0x1234);
        assert_eq!(CD_W.load(Ordering::SeqCst), 5);
        assert_eq!(CD_B.load(Ordering::SeqCst), 0x1234_5600);
        assert_eq!(CD_C.load(Ordering::SeqCst), f.wrapping_byte_sub(0x86) as usize);
        unsafe { wr32(f, -0x20, 0x100) };
        assert_eq!(unsafe { fn_0040867d(f, b'd', 0) }, 0x77);
        assert_eq!(CD_W.load(Ordering::SeqCst), 0);
        // Case 5, 'P' → 7cd8 tail (value, 8, 0x10).
        let f = unsafe { setup(5, 0x55) };
        assert_eq!(unsafe { fn_0040867d(f, b'P', 0) }, 0x77);
        assert_eq!(CD_V.load(Ordering::SeqCst), 0x55);
        assert_eq!(CD_W.load(Ordering::SeqCst), 8);
        assert_eq!(CD_B.load(Ordering::SeqCst), 0x10);
        // Case 2, 'S' → indirect via 0x00404b8c with entry ptr and
        // count 1; hook nulls the slot → length 0.
        let f = unsafe { setup(2, 0) };
        assert_eq!(unsafe { fn_0040867d(f, b'S', 0) }, 0);
        assert_eq!(IN_BASE.load(Ordering::SeqCst), 0x00404b8c);
        assert_eq!(IN_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(
            IN_VAL.load(Ordering::SeqCst),
            core::ptr::addr_of_mut!(ENTRY) as usize
        );
        // Fallback: index > bound → 8904(0), classify D → tail with
        // clamped width, zeroed-low base, cursor at frame-0x66.
        let f = unsafe { setup(0, 0) };
        unsafe {
            wr32(f, -0xC, 9);
            wr32(f, -0x20, 7);
            wr32(f, -0x14, 0x1_0000);
            wr32(f, -0x24, 0x1_0008);
            wr32(f, -0x4, 0x77);
        }
        INNER_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040867d(f, b'Q', 0) }, 0x99);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CD_V.load(Ordering::SeqCst), 0x1234);
        assert_eq!(TAIL_W.load(Ordering::SeqCst), 7);
        assert_eq!(TAIL_B.load(Ordering::SeqCst), 0);
        let _ = unsafe { DAT_00415B76 };
        unsafe {
            crate::fn_00408904::HOOK_00404A8C = old_inner;
        }
    }
}
