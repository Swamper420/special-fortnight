//! Inline hill-scenery stores (evidence-backed, no alloc, no vector).
//!
//! Family sweep: `evidence/scenery_family.md` §§2–3. Only 3 of 10 sections
//! follow the allocate-store-append skeleton; the other 7 write inline
//! into fixed hill-object slots via tiny pure stores/getters:
//!
//! | Section | Hill slot | Store | Keys |
//! |---|---|---|
//! | railing | `+0xc4` | `00436150` 2-word (`d,h` floats) | `d,h` + strings via `004682a0(+8)`/`00436160(+0x2c)` → `00435e70` |
//! | frame | `+0x114` | `004361f0` 1-word (`h` float) | `h` + strings via `0046efb0(+4)`/`00436530(+0x28)` → `00435e70`, dead `00436540(+0x4c)` |
//! | startgate | `+0x9c` | strings only (`00436590` identity → `00435e70`) | `c,m,t` |
//! | startbanner | `+0xc0` | `004361f0` 1-word (`z` float) | `z` |
//! | flag | `+0x1b8` | `00436320` 12 params: 7 float words `[+0x0..+0x18]` + 4 guarded wide-string tails | `rt,rb,hp,hf,wf,z,x` + `cp/mp,tp,mf,tf` |
//! | fence | `+0x184` | strings only (`00436590` identity → `00435e70`) | `c,m,t` |
//! | judgetower | `+0x1a8` | `00436020` 4-word direct call, mixed string-ptr/float dwords (U6) | `c2,c1` strings + `z,d` floats |
//!
//! Transcribed here: only the proven-pure word stores, bit-exact as
//! `u32` (floats pass through `to_bits`; judgetower stays untyped per
//! U6 — which dwords are pointers vs floats is untraced). String tails
//! (`00435e70`, `00436320` wide-copy loops, `00402d50/00402e80/`
//! `00403280` runtime) are opaque — not transcribed.
//! Reuse point: `crate::fn_00436020::store_float_quad` for typed f32
//! quads; `store_quad_words` below is its untyped twin for U6 slots.
//!
//! Evidence (reused sweep IDs + fresh confirmatory reads, Ghidra 12.1.2,
//! document `target-3619dcbde2bc.exe` = `/tmp/dsj3-wrap/DSJ3.exe`):
//! - `00436150` 2-word: sweep `ev_ab75e7882ce29c5a5887316d494c9823a779e9c2f31cc77c49fc3c21dcd8cebc`;
//!   fresh `ev_25725a2ae6f3706e4f73ccf221bb2b01451e0672093aed1ed34f7c87179aab29`
//!   (`MOV [ECX],EAX=[ESP+4]; MOV [ECX+4],EDX=[ESP+8]; RET 8`).
//! - `004361f0` 1-word: sweep `ev_d54bde73662912766226e4af5de59c8e8d2d1fc4575882e830216e1604ff9394`;
//!   fresh `ev_3cdde2d185bb123130c280a268e00d8ce7938b12cb52cf2376623d2c40722bb9`
//!   (`MOV [ECX],EAX=[ESP+4]; RET 4`).
//! - `00436020` 4-word: `ev_e9caa85d2791ff3be17cdefbeae0d7a73778b0026e51738b8ced1d3d0925cde5`;
//!   fresh `ev_aa84685a1484da5d34180d1f8ff4749ce08d79d6405c4e4e8ec89ebd03ba32dd`
//!   (`[ECX+0/4/8/c]=[ESP+4/8/c/10]; RET 0x10`).
//! - `00436320` flag: sweep `ev_6ff4acb73457b907b0698b7d5f9dfa7a5c91bc65c8bbe1d27c7893eac82c4c35` (+tail
//!   `ev_a5062f6f00bf3053e7998cdec7db37fba20de59273ce3b226384fdab2d92ed05`);
//!   fresh `ev_8c8e789a72c82ea3115483c3f58a4b11ce0c6a1e5b3262bff53db0b6a9173d64`
//!   (pseudocode: `*ECX=p1; ECX[1..6]=p2..p7`, then `0059ce28`+`00402d50`-gated
//!   wide copies at `[8]/[9]`, `[0xc]/[0xd]`, `[0x10]/[0x11]`, `.../[0x17]`).
//! - Getters (§3c, pure LEA/identity, untranscribed address math — offsets
//!   below only): `00436160`+0x2c `ev_f8a0c64102a99ade4e77c9b87815f5081ffe93b3ed5ea2abd72e9921cded45a6`,
//!   `00436530`+0x28 `ev_cc4a06b06ada19fd90d51694d9d590ab585fae3c41f14644349bda21b54c57e4`,
//!   `00436540`+0x4c `ev_6cfbfa9709a7dfbc2c399b35b2d0a558cbad1fb0ec84cb7bf8964d5f0f5e73a0`,
//!   `00436590` identity `ev_880065b078eac7c644bd57b20c4787d1fb52655678b19cdb76b7f61035153018`,
//!   `004682a0`+8 `ev_19d659723bc8303054285534ab1489e091fee494f9d14d9fb018da562a6b9c69`,
//!   `0046efb0`+4 `ev_e0bfb77172cd1a12349059393721715f15b4a727b6b7c73810f53ac1de53a84d`.
//!
//! Unknowns (carried from sweep U1/U5–U7, not resolved here):
//! - U1: stack-push → param mapping per leaf (counts proven by `RET`
//!   widths; which key lands in which slot is inference).
//! - U5: `00435e70` dest-object/string-refcount semantics; p3 meaning.
//! - U6: judgetower slot typing at hill+0x1a8 (modeled `u32` deliberately).
//! - U7: three dead pure calls (`00436160` railing tail, `00436540`
//!   frame tail, `00502610` stairs tail) — real `CALL`s, results discarded.

/// Hill-object slot bases for the 7 inline sections (§2 dispatch table).
pub const HILL_OFF_RAILING: usize = 0xc4;
/// Hill-object slot base: frame head (`004361f0` 1-word `h`).
pub const HILL_OFF_FRAME: usize = 0x114;
/// Hill-object slot base: startgate strings (`00436590` identity → `00435e70`).
pub const HILL_OFF_STARTGATE: usize = 0x9c;
/// Hill-object slot base: startbanner (`004361f0` 1-word `z`).
pub const HILL_OFF_STARTBANNER: usize = 0xc0;
/// Hill-object slot base: flag struct (`00436320`, size ≥ 0x60).
pub const HILL_OFF_FLAG: usize = 0x1b8;
/// Hill-object slot base: fence strings (`00436590` identity → `00435e70`).
pub const HILL_OFF_FENCE: usize = 0x184;
/// Hill-object slot base: judgetower mixed 4-word (`00436020` direct).
pub const HILL_OFF_JUDGETOWER: usize = 0x1a8;

/// Sub-object getter adds (§3c) for inline-section string feeds.
pub const ADD_RAILING_STR: usize = 0x08; // `004682a0`
/// Sub-object getter add: railing second string block (dead call, U7).
pub const ADD_RAILING_SUB: usize = 0x2c; // `00436160`
/// Sub-object getter add: frame first string block.
pub const ADD_FRAME_STR: usize = 0x04; // `0046efb0`
/// Sub-object getter add: frame second string block.
pub const ADD_FRAME_SUB0: usize = 0x28; // `00436530`
/// Sub-object getter add: frame dead call (U7).
pub const ADD_FRAME_SUB1: usize = 0x4c; // `00436540`

/// `FUN_00436150`: bit-exact 2-word store (`*ECX=p1; ECX[1]=p2`).
pub fn store_pair(dst: &mut [u32; 2], p1: u32, p2: u32) {
    dst[0] = p1;
    dst[1] = p2;
}

/// `FUN_004361f0`: bit-exact 1-word store (`*ECX=p1`).
pub fn store_single(dst: &mut u32, p1: u32) {
    *dst = p1;
}

/// `FUN_00436320` float prefix: 7 words at `[ECX+0x0..+0x18]`
/// (`*ECX=p1; ECX[1..6]=p2..p7`). String tails (`[8]/[9]`,
/// `[0xc]/[0xd]`, `[0x10]/[0x11]`, `.../[0x17]`) stay opaque.
pub fn store_flag_floats(dst: &mut [u32; 7], p: [u32; 7]) {
    *dst = p;
}

/// `FUN_00436020` untyped twin for judgetower's mixed slots (U6):
/// same 4-word shape as `crate::fn_00436020::store_float_quad`,
/// `u32` so string-pointer dwords pass through bit-exact.
pub fn store_quad_words(dst: &mut [u32; 4], p1: u32, p2: u32, p3: u32, p4: u32) {
    dst[0] = p1;
    dst[1] = p2;
    dst[2] = p3;
    dst[3] = p4;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the inline stores (generated fixtures — no original
    /// bytes): order preserved, bit-exact incl. NaN payload and -0.0;
    /// hill-slot bases distinct per §2 table.
    #[test]
    fn inline_stores_bit_exact() {
        let f = |v: f32| v.to_bits();
        // 00436150 pair (railing d,h).
        let mut pair = [0u32; 2];
        store_pair(&mut pair, f(1.5), f(-0.0));
        assert_eq!(pair, [f(1.5), f(-0.0)]);
        // 004361f0 single (frame h / startbanner z).
        let mut one = 0u32;
        store_single(&mut one, f(f32::NAN));
        assert_eq!(one, f(f32::NAN));
        // 00436320 7-float prefix (flag rt,rb,hp,hf,wf,z,x in some order, U1).
        let mut flag = [0u32; 7];
        let p = [f(1.0), f(2.0), f(-0.0), f(f32::NAN), 0xdead_beef, f(47.75), 0];
        store_flag_floats(&mut flag, p);
        assert_eq!(flag, p);
        assert!(f32::from_bits(flag[3]).is_nan());
        // 00436020 untyped twin (judgetower mixed slots, U6).
        let mut q = [0u32; 4];
        store_quad_words(&mut q, f(3.25), 0x1234_5678, f(f32::NAN), f(-0.0));
        assert_eq!(q[0], f(3.25));
        assert_eq!(q[1], 0x1234_5678);
        // Slot bases from the §2 dispatch table.
        assert_eq!(
            [HILL_OFF_RAILING, HILL_OFF_FRAME, HILL_OFF_STARTGATE, HILL_OFF_STARTBANNER, HILL_OFF_FLAG, HILL_OFF_FENCE, HILL_OFF_JUDGETOWER],
            [0xc4, 0x114, 0x9c, 0xc0, 0x1b8, 0x184, 0x1a8]
        );
    }
}
