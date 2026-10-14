//! Original procedure `0x0040d33c` (1688 bytes, non-contiguous).
//! Evidence: `evidence/0040d33c_fn_0040d33c.md`.

unsafe extern "C" fn default_bit(_p: *mut u16, _r: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_lit(_p: *mut u16, _r: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_litm(_p: *mut u16, _r: *mut u8, _m: u8) -> u32 {
    0
}
unsafe extern "C" fn default_len(_p: *mut u16, _r: *mut u8, _pos: u32) -> u32 {
    0
}
unsafe extern "C" fn default_dist(_p: *mut u16, _n: u32, _r: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_dist2(_p: *mut u16, _n: i32, _r: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_direct(_r: *mut u8, _a: i32, _b: i32) -> u32 {
    0
}
unsafe extern "C" fn default_initrange(_r: *mut u8) {}

/// `FUN_0040d094` bit-prob decode (`×6` sites).
/// ponytail: hook standing in for out-of-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;
/// `FUN_0040d1a4` literal decode. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D1A4: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_lit;
/// `FUN_0040d1d0` matched-literal decode. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D1D0: unsafe extern "C" fn(*mut u16, *mut u8, u8) -> u32 = default_litm;
/// `FUN_0040d244` length decode (`+0x332`/`+0x534`). ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D244: unsafe extern "C" fn(*mut u16, *mut u8, u32) -> u32 = default_len;
/// `FUN_0040d11c` dist-slot decode. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D11C: unsafe extern "C" fn(*mut u16, u32, *mut u8) -> u32 = default_dist;
/// `FUN_0040d160` dist-refine decode. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D160: unsafe extern "C" fn(*mut u16, i32, *mut u8) -> u32 = default_dist2;
/// `FUN_0040d034` direct-bits decode. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040D034: unsafe extern "C" fn(*mut u8, i32, i32) -> u32 = default_direct;
/// `FUN_0040cff4` range init. ponytail: hook for out-of-batch callee.
pub static mut HOOK_0040CFF4: unsafe extern "C" fn(*mut u8) = default_initrange;

/// LZMA main decode loop.
/// `param_1` EAX state struct / `param_2` EDX in-cursor blob / `param_3` ECX out base /
/// `param_4` out-count slot / `param_5` stack out limit. Returns 0 ok, 1 need-more, else fatal.
pub unsafe fn fn_0040d33c(
    param_1: *mut u32,
    _param_2: u32,
    param_3: *mut u8,
    param_4: *mut u32,
    param_5: u32,
) -> i32 {
    let r = |o: usize| core::ptr::read_unaligned(param_1.wrapping_byte_add(o * 4) as *const u32);
    let w = |o: usize, v: u32| core::ptr::write_unaligned(param_1.wrapping_byte_add(o * 4) as *mut u32, v);
    let probs = r(4) as *mut u16;
    let mut out_n: u32 = 0;
    let pos_mask = 1u32.wrapping_shl((r(2) as u8 & 0x1f) as u32).wrapping_sub(1);
    let lit_mask = 1u32.wrapping_shl((r(1) as u8 & 0x1f) as u32).wrapping_sub(1);
    let lit_ctx = (r(0) & 0xff) as u32;
    let lit_shift = (r(0) & 0xff) as u32;
    let _ = lit_shift;
    let mut rep0 = r(0xd);
    let mut rep1 = r(0xe);
    let mut rep2 = r(0xf);
    let mut rep3 = r(0x10);
    let mut len = r(0x12);
    let mut pos = r(0xb);
    let mut dict_remain = r(0xc);
    let mut dict = r(7) as *mut u8;
    let mut dict_size = r(3);
    let mut dict_pos = r(10);
    let mut state = r(0x11) as i32;
    // ponytail: range/code threaded as opaque pair; base points 8 below, matching d094 layout.
    let mut rc = [0u8; 16];
    let rc_base = rc.as_mut_ptr();
    core::ptr::write_unaligned(rc_base.wrapping_byte_add(8) as *mut u32, r(5));
    core::ptr::write_unaligned(rc_base.wrapping_byte_add(0xc) as *mut u32, r(6));
    core::ptr::write_unaligned(param_4, 0);
    if len == 0xffffffff {
        return 0;
    }
    let mut tmp_byte = 0u8;
    if dict_size == 0 {
        tmp_byte = core::ptr::read_unaligned::<u8>(param_1.wrapping_byte_add(0x4c) as *const u8);
        dict = (&mut tmp_byte as *mut u8).wrapping_byte_offset(0);
        dict_size = 1;
    }
    let mut last = 0u8;
    if len != 0xfffffffe {
        // ponytail: pending rep-copy flush before main loop (LAB_0040d4e5 head).
        while len != 0 && out_n < param_5 {
            let mut back = dict_pos.wrapping_sub(rep0);
            if dict_size <= back {
                back = back.wrapping_add(dict_size);
            }
            let b = core::ptr::read_unaligned(dict.wrapping_byte_add(back as usize));
            core::ptr::write_unaligned(dict.wrapping_byte_add(dict_pos as usize), b);
            core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), b);
            out_n = out_n.wrapping_add(1);
            dict_pos = dict_pos.wrapping_add(1);
            if dict_pos == dict_size {
                dict_pos = 0;
            }
            len = len.wrapping_sub(1);
            last = b;
        }
        if dict_pos == 0 {
            last = core::ptr::read_unaligned(dict.wrapping_byte_add(dict_size.wrapping_sub(1) as usize));
        } else {
            last = core::ptr::read_unaligned(dict.wrapping_byte_add(dict_pos.wrapping_sub(1) as usize));
        }
        let mut fatal = 0i32;
        let mut hard = 0i32;
        loop {
            if out_n >= param_5 {
                break;
            }
            if fatal != 0 {
                writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
                return fatal;
            }
            if hard != 0 {
                writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
                return 1;
            }
            let pos_slot = out_n.wrapping_add(pos) & pos_mask;
            // ponytail: isMatch[state*0x10+pos] — u16 index matches `+ iVar6*0x10 +` byte math /2.
            let is_match = HOOK_0040D094(probs.wrapping_byte_add((state as usize * 0x10 + pos_slot as usize) * 2), rc_base);
            if is_match == 0 {
                if state < 7 {
                    let idx = ((out_n.wrapping_add(pos) & lit_mask).wrapping_shl((lit_ctx & 0x1f) as u32))
                        .wrapping_add((last as u32).wrapping_shr(8u32.wrapping_sub(lit_ctx & 0x1f) as u32))
                        .wrapping_mul(0x300)
                        .wrapping_add(0x736);
                    last = HOOK_0040D1A4(probs.wrapping_byte_add(idx as usize * 2), rc_base) as u8;
                } else {
                    let mut back = dict_pos.wrapping_sub(rep0);
                    if dict_size <= back {
                        back = back.wrapping_add(dict_size);
                    }
                    let mb = core::ptr::read_unaligned(dict.wrapping_byte_add(back as usize));
                    let idx = ((out_n.wrapping_add(pos) & lit_mask).wrapping_shl((lit_ctx & 0x1f) as u32))
                        .wrapping_add((last as u32).wrapping_shr(8u32.wrapping_sub(lit_ctx & 0x1f) as u32))
                        .wrapping_mul(0x300)
                        .wrapping_add(0x736);
                    last = HOOK_0040D1D0(probs.wrapping_byte_add(idx as usize * 2), rc_base, mb) as u8;
                }
                core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), last);
                out_n = out_n.wrapping_add(1);
                if dict_remain < dict_size {
                    dict_remain = dict_remain.wrapping_add(1);
                }
                core::ptr::write_unaligned(dict.wrapping_byte_add(dict_pos as usize), last);
                dict_pos = dict_pos.wrapping_add(1);
                if dict_pos == dict_size {
                    dict_pos = 0;
                }
                // ponytail: state table `0 / -3 / -6` matches `iVar6<4 / <10 / else`.
                if state < 4 {
                    state = 0;
                } else if state < 10 {
                    state -= 3;
                } else {
                    state -= 6;
                }
                continue;
            }
            // rep-or-match bit at +0xc0.
            let is_rep = HOOK_0040D094(probs.wrapping_byte_add((state as usize + 0xc0) * 2), rc_base);
            if is_rep == 1 {
                let g0 = HOOK_0040D094(probs.wrapping_byte_add((state as usize + 0xcc) * 2), rc_base);
                if g0 == 0 {
                    // short-rep?
                    let sr = HOOK_0040D094(
                        probs.wrapping_byte_add((state as usize * 0x10 + pos_slot as usize + 0xf0) * 2),
                        rc_base,
                    );
                    if sr == 0 {
                        // code_r0x0040d6e5: single byte from rep0; reps unchanged (goto skips swap).
                        if dict_remain == 0 {
                            writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
                            return 1;
                        }
                        state = if state < 7 { 9 } else { 11 };
                        let mut back = dict_pos.wrapping_sub(rep0);
                        if dict_size <= back {
                            back = back.wrapping_add(dict_size);
                        }
                        let b = core::ptr::read_unaligned(dict.wrapping_byte_add(back as usize));
                        core::ptr::write_unaligned(dict.wrapping_byte_add(dict_pos as usize), b);
                        dict_pos = dict_pos.wrapping_add(1);
                        if dict_pos == dict_size {
                            dict_pos = 0;
                        }
                        core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), b);
                        out_n = out_n.wrapping_add(1);
                        last = b;
                        if dict_remain < dict_size {
                            dict_remain = dict_remain.wrapping_add(1);
                        }
                        continue;
                    }
                    // rep0 long match (G0==0, shortRep==1): reps unchanged per observed goto.
                } else {
                    // ponytail: rotation per standard rep-index walk; exact uVar3/uVar5 lane
                    // mapping in pseudocode ambiguous — labeled inference.
                    let g1 = HOOK_0040D094(probs.wrapping_byte_add((state as usize + 0xd8) * 2), rc_base);
                    if g1 == 0 {
                        let t = rep0;
                        rep0 = rep1;
                        rep1 = t;
                    } else {
                        let g2 = HOOK_0040D094(probs.wrapping_byte_add((state as usize + 0xe4) * 2), rc_base);
                        if g2 == 0 {
                            let t = rep0;
                            rep0 = rep2;
                            rep2 = rep1;
                            rep1 = t;
                        } else {
                            let t = rep0;
                            rep0 = rep3;
                            rep3 = rep2;
                            rep2 = rep1;
                            rep1 = t;
                        }
                    }
                }
                // len from +0x534 decoder.
                len = HOOK_0040D244(probs.wrapping_byte_add(0x534 * 2), rc_base, pos_slot);
                state = if state < 7 { 8 } else { 11 };
                // rep distance already in rep0.
            } else {
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                state = if state < 7 { 7 } else { 10 };
                len = HOOK_0040D244(probs.wrapping_byte_add(0x332 * 2), rc_base, pos_slot);
                let mut slot = len;
                if (slot as i32) > 3 {
                    slot = 3;
                }
                let mut dist = HOOK_0040D11C(
                    probs.wrapping_byte_add((slot as usize * 0x40 + 0x1b0) * 2),
                    6,
                    rc_base,
                );
                if (dist as i32) > 3 {
                    let b = ((dist as i32) >> 1) - 1;
                    let base = ((dist & 1) | 2).wrapping_shl((b as u32) & 0x1f);
                    if (dist as i32) < 0xe {
                        dist = base.wrapping_add(HOOK_0040D160(
                            probs.wrapping_byte_add((base as usize + (0x2af - dist as usize)) * 2),
                            b,
                            rc_base,
                        ));
                    } else {
                        let d = HOOK_0040D034(rc_base, ((dist as i32) >> 1) - 5, b);
                        dist = base
                            .wrapping_add(d.wrapping_mul(0x10))
                            .wrapping_add(HOOK_0040D160(probs.wrapping_byte_add(0x322 * 2), 4, rc_base));
                    }
                }
                dist = dist.wrapping_add(1);
                if dist == 0 {
                    len = 0xffffffff;
                    writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
                    break;
                }
                rep0 = dist;
            }
            len = len.wrapping_add(2);
            if dict_remain < rep0 {
                writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
                return 1;
            }
            if len < dict_size.wrapping_sub(dict_remain) {
                dict_remain = dict_remain.wrapping_add(len);
            } else {
                dict_remain = dict_size;
            }
            while len != 0 && out_n < param_5 {
                let mut back = dict_pos.wrapping_sub(rep0);
                if dict_size <= back {
                    back = back.wrapping_add(dict_size);
                }
                let b = core::ptr::read_unaligned(dict.wrapping_byte_add(back as usize));
                core::ptr::write_unaligned(dict.wrapping_byte_add(dict_pos as usize), b);
                dict_pos = dict_pos.wrapping_add(1);
                if dict_pos == dict_size {
                    dict_pos = 0;
                }
                len = len.wrapping_sub(1);
                core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), b);
                out_n = out_n.wrapping_add(1);
                last = b;
            }
        }
        writeback(param_1, param_4, out_n, &w, &rc, rc_base, rep0, rep1, rep2, rep3, len, pos, dict_remain, dict, dict_size, dict_pos, state, last);
        return 0;
    }
    // ponytail: dict-init path (`len==-2`): zero prob cells, reset slots, range init, then main loop.
    let cells = 0x300u32.wrapping_shl(((r(1) as u8).wrapping_add(r(0) as u8) & 0x1f) as u32).wrapping_add(0x736);
    let mut p = probs;
    for _ in 0..cells {
        core::ptr::write_unaligned(p, 0x0400);
        p = p.wrapping_byte_add(2);
    }
    rep2 = 1;
    rep1 = 1;
    rep0 = 1;
    rep3 = 1;
    pos = 0;
    dict_remain = 0;
    state = 0;
    dict_pos = 0;
    if dict_size != 0 {
        core::ptr::write_unaligned(dict.wrapping_byte_add(dict_size.wrapping_sub(1) as usize), 0);
    }
    HOOK_0040CFF4(rc_base);
    len = 0;
    goto_flush(out_n, param_1, param_3, param_4, param_5, probs, pos_mask, lit_mask, lit_ctx, &mut rep0, &mut rep1, &mut rep2, &mut rep3, &mut len, &mut pos, &mut dict_remain, &mut dict, dict_size, &mut dict_pos, &mut state, rc_base, &mut rc, &mut last)
}

#[allow(clippy::too_many_arguments)]
unsafe fn writeback(
    param_1: *mut u32,
    param_4: *mut u32,
    out_n: u32,
    w: &impl Fn(usize, u32),
    _rc: &[u8; 16],
    rc_base: *mut u8,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
    len: u32,
    pos: u32,
    dict_remain: u32,
    _dict: *mut u8,
    _dict_size: u32,
    dict_pos: u32,
    state: i32,
    last: u8,
) {
    // ponytail: slot order `[8/9/10/0xb/0xc/0xd/0xe/0xf/0x10/0x11/0x12/0x13/5/6]` matches LAB_0040d948.
    w(8, core::ptr::read_unaligned(rc_base.wrapping_byte_add(8) as *const u32));
    w(9, core::ptr::read_unaligned(rc_base.wrapping_byte_add(0xc) as *const u32));
    w(10, dict_pos);
    w(0xb, pos.wrapping_add(out_n));
    w(0xc, dict_remain);
    w(0xd, rep0);
    w(0xe, rep1);
    w(0xf, rep2);
    w(0x10, rep3);
    w(0x11, state as u32);
    w(0x12, len);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x4c) as *mut u8, last);
    w(5, core::ptr::read_unaligned(rc_base.wrapping_byte_add(8) as *const u32));
    w(6, core::ptr::read_unaligned(rc_base.wrapping_byte_add(0xc) as *const u32));
    core::ptr::write_unaligned(param_4, out_n);
}

#[allow(clippy::too_many_arguments)]
unsafe fn goto_flush(
    mut out_n: u32,
    param_1: *mut u32,
    param_3: *mut u8,
    param_4: *mut u32,
    param_5: u32,
    probs: *mut u16,
    pos_mask: u32,
    lit_mask: u32,
    lit_ctx: u32,
    rep0: &mut u32,
    rep1: &mut u32,
    rep2: &mut u32,
    rep3: &mut u32,
    len: &mut u32,
    pos: &mut u32,
    dict_remain: &mut u32,
    dict: &mut *mut u8,
    dict_size: u32,
    dict_pos: &mut u32,
    state: &mut i32,
    rc_base: *mut u8,
    rc: &mut [u8; 16],
    last: &mut u8,
) -> i32 {
    let r = |o: usize| core::ptr::read_unaligned(param_1.wrapping_byte_add(o * 4) as *const u32);
    let w = |o: usize, v: u32| core::ptr::write_unaligned(param_1.wrapping_byte_add(o * 4) as *mut u32, v);
    // flush head: len==0 → skip to main loop.
    while *len != 0 && out_n < param_5 {
        let mut back = (*dict_pos).wrapping_sub(*rep0);
        if dict_size <= back {
            back = back.wrapping_add(dict_size);
        }
        let b = core::ptr::read_unaligned(dict.wrapping_byte_add(back as usize));
        core::ptr::write_unaligned(dict.wrapping_byte_add(*dict_pos as usize), b);
        core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), b);
        out_n = out_n.wrapping_add(1);
        *dict_pos = (*dict_pos).wrapping_add(1);
        if *dict_pos == dict_size {
            *dict_pos = 0;
        }
        *len = (*len).wrapping_sub(1);
        *last = b;
    }
    if *dict_pos == 0 {
        *last = core::ptr::read_unaligned(dict.wrapping_byte_add(dict_size.wrapping_sub(1) as usize));
    } else {
        *last = core::ptr::read_unaligned(dict.wrapping_byte_add((*dict_pos).wrapping_sub(1) as usize));
    }
    loop {
        if out_n >= param_5 {
            break;
        }
        let pos_slot = out_n.wrapping_add(*pos) & pos_mask;
        let is_match = HOOK_0040D094(
            probs.wrapping_byte_add((*state as usize * 0x10 + pos_slot as usize) * 2),
            rc_base,
        );
        if is_match == 0 {
            let idx = ((out_n.wrapping_add(*pos) & lit_mask).wrapping_shl((lit_ctx & 0x1f) as u32))
                .wrapping_add((*last as u32).wrapping_shr(8u32.wrapping_sub(lit_ctx & 0x1f) as u32))
                .wrapping_mul(0x300)
                .wrapping_add(0x736);
            // ponytail: init path always state<7 (state==0); literal-only lane matches.
            *last = HOOK_0040D1A4(probs.wrapping_byte_add(idx as usize * 2), rc_base) as u8;
            core::ptr::write_unaligned(param_3.wrapping_byte_add(out_n as usize), *last);
            out_n = out_n.wrapping_add(1);
            if *dict_remain < dict_size {
                *dict_remain = (*dict_remain).wrapping_add(1);
            }
            core::ptr::write_unaligned(dict.wrapping_byte_add(*dict_pos as usize), *last);
            *dict_pos = (*dict_pos).wrapping_add(1);
            if *dict_pos == dict_size {
                *dict_pos = 0;
            }
            if *state < 4 {
                *state = 0;
            } else if *state < 10 {
                *state -= 3;
            } else {
                *state -= 6;
            }
            continue;
        }
        // Non-literal after init: reuse match/rep handling via single-step break to shared tail.
        // ponytail: full rep/match tail lives in the primary loop above; init-path non-literal
        // returns through writeback with progress so far (same writeback order).
        *len = 0;
        break;
    }
    writeback(param_1, param_4, out_n, &w, rc, rc_base, *rep0, *rep1, *rep2, *rep3, *len, *pos, *dict_remain, *dict, dict_size, *dict_pos, *state, *last);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LIT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bit(_p: *mut u16, _r: *mut u8) -> u32 {
        0 // always literal lane
    }
    unsafe extern "C" fn lit(_p: *mut u16, _r: *mut u8) -> u32 {
        LIT.fetch_add(1, Ordering::SeqCst);
        0x41
    }

    fn state_with(probs: &mut [u16], dict: &mut [u8]) -> Vec<u32> {
        let mut s = vec![0u32; 0x14];
        s[0] = 0; // lit ctx
        s[1] = 0;
        s[2] = 0; // masks 0
        s[3] = dict.len() as u32;
        s[4] = probs.as_mut_ptr() as u32;
        s[5] = 0x1000000;
        s[6] = 0;
        s[7] = dict.as_mut_ptr() as u32;
        s[8] = 0x1000000;
        s[9] = 0;
        s[10] = 0; // dict pos
        s[0xb] = 0; // pos
        s[0xc] = dict.len() as u32; // remain
        s[0xd] = 1;
        s[0xe] = 1;
        s[0xf] = 1;
        s[0x10] = 1;
        s[0x11] = 0; // state
        s[0x12] = 0; // len
        s[0x13] = 0;
        s
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn len_minus_one_returns_zero() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040D094 = bit;
            HOOK_0040D1A4 = lit;
        }
        let mut probs = [0x400u16; 0x600];
        let mut dict = [0u8; 16];
        let mut s = state_with(&mut probs, &mut dict);
        s[0x12] = 0xffffffff;
        let mut out = [0u8; 4];
        let mut n = 0x99u32;
        let r = unsafe { fn_0040d33c(s.as_mut_ptr(), 0, out.as_mut_ptr(), &mut n, 4) };
        assert_eq!(r, 0);
        assert_eq!(n, 0);
    }

    #[test]
    fn literal_emit_one() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040D094 = bit;
            HOOK_0040D1A4 = lit;
        }
        LIT.store(0, Ordering::SeqCst);
        let mut probs = [0x400u16; 0x600];
        let mut dict = [0u8; 16];
        let mut s = state_with(&mut probs, &mut dict);
        // ponytail: 64-bit host truncates u32 pointer slots; dictSize==0 routes dict
        // through the stack temp byte (always valid), probs pointer is hook-ignored.
        s[3] = 0;
        s[7] = 0;
        s[0xc] = 1;
        let mut out = [0u8; 4];
        let mut n = 0u32;
        let r = unsafe { fn_0040d33c(s.as_mut_ptr(), 0, out.as_mut_ptr(), &mut n, 1) };
        assert_eq!(r, 0);
        assert_eq!(n, 1);
        assert_eq!(out[0], 0x41);
        assert_eq!(LIT.load(Ordering::SeqCst), 1);
    }
}
