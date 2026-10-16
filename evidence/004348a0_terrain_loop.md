# FUN_004348a0 — terrain heightfield loop (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE, NOT the installer stub),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Procedure `0x4348a0`–`0x434fe9`, 1866 B, contiguous, `RET 0x30`
(12 float stack params + ECX=this hill object).

Called from `FUN_00436620` composition dispatcher (call site `0x437702`).
Base `FUN_00434ff0` already transcribed (`evidence/00434ff0_terrain_base.md`,
`TerrainBase::eval` in `engine/src/mesh.rs`).

## Pseudocode (REA decompiler, `ev_6d8bdd4d...`; per-vertex core only)

```text
// Setup (0x434941-0x434b29): 8-tap tables from params + RNG
for uVar12 in 0..8 {
  t = uVar12 * (param_11 - param_10) * 0.125 + param_10;
  ampA[uVar12] = t; ampB[uVar12] = t;                    // afStack_29c/25c
  s = (param_9 - param_8) * uVar12 * 0.125 + param_8;
  divA[uVar12] = (|RNG()| + 1.0) * s;                    // afStack_27c, 004df9a0
  divB[uVar12] = (|RNG()| + 1.0) * s;                    // afStack_2dc
  phA[uVar12] = RNG(0, 4*pi); phB[uVar12] = RNG(0, 4*pi); // afStack_23c/2bc, 004df960
}
// Grid setup: [this+0x90] = 10.0; [this+0x94] = range/step;
// [this+0x80] = ftol(...) + 40 (cols); [this+0x84] = 61 (rows, 0x3d);
// [this+0x8c] = base_x; [this+0x88] = 10.0 * -30.0 = -300.0;
// [this+0x98] = fVar2 - cos(pi*param_3*0.0055555557) * param_4.
for row in 0..61 {                                       // local_31c < [this+0x84]
  for col in 0..[this+0x80] {                            // local_310 < [this+0x80]
    fVar4 = (double)col * [this+0x94] + [this+0x8c];      // FILD/FMUL/FADD, FSTP float
    fVar5 = (double)row * [this+0x90] + [this+0x88];
    f = FUN_00434ff0(fVar4, fVar5);                       // 0x434b99, ECX=this
    t1 = max2(?, fVar4); t2 = min2(?, ?); h = xform(t2);  // 468360/468340/4de3e0, order open (U3)
    if !(fVar4 >= fVar1) { h += (xform(...) - xform(...)) * param_1; }  // 0x434bd6, NaN enters
    if !(fVar4 >= fVar2) { h += sin(-0.0055555557*pi*param_3) * (max2(fVar4,?)-fVar2) * param_1; }
    noise = 0.0;                                          // FLD [0x5cd378]=0.0
    for k in 0..8 {                                       // EAX = 0,4,...,28; JC on CMP EAX,0x20
      a = fVar4 / divA[k] * pi; noise += cos(a + a + phA[k]) * ampA[k];
      b = fVar5 / divB[k] * pi; noise += cos(b + b + phB[k]) * ampB[k];
    }
    v = min2(...) * noise + clamp3(lo, hi);               // sin(param_6/7)+param_2 weights, order open (U3)
    push v to float vector [this+0x74/0x78/0x7c];         // std::vector-like growth, 00475330/0059c120
  }
}
```

## Assembly summary (hand-verified from `ev_6d8bdd4d...` listing)

- Setup loop `0x434949`–`0x434a0e`: `FILD` counter, `×(p11−p10)×0.125+p10`
  (`[0x5ce074]`=0.125), tables at `ESP+ESI*4+{0xa4,0xe4,0xc4,0x68,0x104,0x84}`;
  `FABS`+`FADD [0x5cd2d0]`(dbl 1.0) after `004df9a0`; `004df960(0, 4*pi)`
  with `[0x61b880]` file-zero (pi at runtime) × `[0x5cd2c8]`(f32 4.0).
- `[EBP+0x90]=0x41200000` (10.0f) `0x434a6a`; `[0x88]=10.0×[0x5ce064]`(−30.0)
  → −300.0; `[0x84]=0x3d` (61) `0x434aac`; `[0x80]=__ftol+0x28` (+40).
- `[0x98]=fVar2−cos([0x61b880]×param_3×[0x5ce060])×param_4`
  (`[0x5ce060]`=0.0055555557=1/180, FCOS) `0x434b09`–`0x434b29`.
- Inner head `0x434b51`–`0x434b99`: `FILD qword` col/row (int→x87, exact),
  `FMUL` step / `FADD` base / `FSTP` float; `PUSH fVar5; PUSH fVar4;
  CALL 00434ff0` — arg order matches base evidence (fVar4,fVar5).
- Guards `0x434bd6`/`0x434c24`: `FCOMP; FNSTSW; TEST AH,1; JZ skip` —
  skip iff C0=0 (ordered ≥); less OR unordered (NaN) enters body.
- Noise `0x434c75`–`0x434cd4`: `FLD [0x5cd378]`(0.0); per tap
  `FDIV div; FMUL [0x61b880]; FADD ST0; FADD phase; FCOS; FMUL amp;
  FADDP`; `CMP EAX,0x20; JC loop` (CF survives FPU ops; 8 taps).
- Tail `0x434cd8`–`0x434dcb`: `FSIN param_6/param_7`,
  `468360(param_2)`, `468340(1−param_2)`, `468310(lo,hi)` with
  `[0x5ce054]`=0.3/`[0x5ce058]`=0.0033333334/`[0x5ce05c]`=−0.0055555557,
  `468340()` then `v = f18*noise + f16`; vector push with capacity
  growth (`operator_new`, `00475330` per-element copy, `0059c120` free).
- No strings referenced in body (numeric code + calls only).

## Callers / callees

- Callers: `FUN_00436620` (`0x437702`, composition dispatcher).
- Callee
...[truncated 1583 chars]

## U3 wiring closure — max/min-arg order (2026-10-16, no new Evidence IDs)

Wired from evidence, no REA call: `evidence/00435740_strip_minmax.md` §3
maps the reader-internal arg order authoritatively from asm (stack at
`CALL 00468340/00468360` is `[second=b50][first=b60]`), so the `004348a0`
call-site order is not ambiguous for the combine itself.

- `FUN_00435740` = `min2(a = lo_b50, b = lo_b60)` (checked `strip_lo` /
  `FUN_004de320` pair + `min2` / `FUN_00468340`); NaN either side → b
  (b60-side lo value).
- `FUN_00435770` = `max2(a = hi_b50, b = hi_b60)` (checked `strip_hi` /
  `FUN_004de350` pair + `max2` / `FUN_00468360`); NaN either side → a
  (b50-side: NaN `hi_b50` survives, NaN `hi_b60` falls back to `hi_b50`).
  (Dossier §4 summary line says "NaN → b60-side" for max; its cited asm +
  `max2` mapping give a-side. Transcription follows the asm.)
- Transcribed as `engine/src/mesh.rs` `strip_lo_min` / `strip_hi_max`,
  reusing `crate::fn_004de320::{strip_lo, strip_hi, StripRange}`,
  `crate::fn_00435740::min2`, `crate::mesh::max2` — no duplication.
  Covered by the extended `terrain_loop_core` test (generated fixtures).

Sin-weight wiring CLOSED by `evidence/004348a0_sin_tail.md`
(`terrain_sin_tail` in `engine/src/mesh.rs`).
Still open (not this wave): RNG tables, vector growth, exact `004348a0`
call-site addresses of the 2+1 reader sites (strip-minmax dossier U2),
downstream use of the min/max results.

## U-status 2026-10-16: entry/setup/grid/tail driver wired (this wave)

REA: `analyze_function FUN_004348a0` re-ran against
`/tmp/dsj3-wrap/DSJ3.exe` — same dossier, no new Evidence IDs
(`ev_6aa12cdd56427e2cd5c7cc4e87752d27985c3bf515442de3b43e3c416a697016`:
body `0x4348a0`–`0x434fe9`, 1866 B contiguous, `RET 0x30`; 20 callees
incl `0059e643`/`0055b490`/`__ftol`/`operator_new`). Pseudocode confirms
the per-vertex order wired below (coords → `00434ff0` → `468360/468340`
+ `004de3e0` guard accum with `terrain_adjust_enter` predicates →
noise → sin tail → `[+0x74/0x78/0x7c]` push) and the fixed slot map
(`p1=in p2=dh p3=a0 p4=l0 p5=y0 p6=az p7=ax p8=l1 p9=l2 p10=d1
p11=d2 p12=rs`-seed; caller converts only `ax`/`az`).

Transcription (`engine/src/mesh.rs`, no duplication — reuses
`terrain_coords`, `TerrainBase::eval`, `terrain_adjust_enter` (predicate
only), `terrain_noise`, `terrain_sin_tail`, `strip_lo_min`/`strip_hi_max`
shapes): `Terrain` (12-key profile + `from_map`), `TERRAIN_STEP_Y=10.0`
/ `TERRAIN_BASE_Y=-300.0`, pure setup taps `terrain_amp_tap`
(`k×(d2−d1)×0.125+d1`) / `terrain_div_span` (`(l2−l1)×k×0.125+l1`,
unit RNG factor), `TerrainTables` (shared `amp`, `div`/`ph` open),
`TerrainGrid` (`cols`/`step_x`/`base_x` open), `terrain_vertex`
(asm order), `terrain_build` (61×cols row-major `Vec::push`).
Covered by `terrain_build_driver`: generated tap fixtures exact +
live Hill01 profile (`in=0.87 dh=0.4 a0=40 l0=70 y0=-46 rs=529572`,
`ax`/`az` deg→rad) → 61×41 grid all finite, bit-identical re-run,
sample `[233.0819, 230.89233, 228.76059, 226.73271]` (fixture
tables/xform/`h`=base/`lo_b60`=0, not original outputs).

CLOSED: entry slot/param map, setup pure taps, grid axes, per-vertex
wiring order. Still open: RNG tables (`004df960/004df9a0` outputs),
vector-growth impurity (`operator_new`/`00475330`/`0059c120` path —
`Vec::push` is std equivalent, not 1:1), `cols`/`step_x`/`base_x`
(`0059e643` + `__ftol` semantics unmapped, driver inputs), guard `h`
(`004de3e0` virtual targets + combine order, `height` closure),
`thr`/`off` writers (`[+0x260/+0x264]`), `lo_b60` strip object,
reader call-site addresses (U2), downstream min/max use,
`U-host-sin`/`U-tie-sign` (carried).