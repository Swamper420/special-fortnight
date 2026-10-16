# FUN_004348a0 grid setup — cols/step_x/base_x (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope strictly: `[this+0x80]` cols, `[this+0x94]` step_x, `[this+0x8c]`
base_x (`0x434a14`–`0x434af1`). Fixed axes (`[+0x90]=10.0`,
`[+0x88]=-300.0`, `[+0x84]=61`) already covered by parent
(`evidence/004348a0_terrain_loop.md`); per-vertex use
(`terrain_coords`, `TerrainGrid`) unchanged.

## Pseudocode (observed assembly order, float ops verbatim)

```text
// Strip slots (thiscall ECX, no stack args):
lo_b60 = FUN_004de320([this+0x60])   // [ESP+0x28], parked dbl [ESP+0x48]
hi_b60 = FUN_004de350([this+0x60])   // [ESP+0x50]
lo_b50 = FUN_004de320([this+0x50])   // via 00435740 chain
hi_b50 = FUN_004de350([this+0x50])   // via 00435770 chain
min_lo = FUN_00435740(this)          // min2(lo_b50, lo_b60)
max_hi = FUN_00435770(this)          // max2(hi_b50, hi_b60)

// step_x [this+0x94] (0x434a44-0x434a74):
range = hi_b60 - lo_b60              // FLD [ESP+0x50]; FSUB [ESP+0x28]
n = FUN_0059e643((double)(range * 0.1f))  // FST dbl range; FMUL [0x5ce070]
step_x = range / n                   // FDIVR [ESP+0x50]; FSTP [EBP+0x94]

// cols [this+0x80] (0x434a7a-0x434aa6):
span = max_hi - min_lo               // max parked [ESP+0x24]; FSUBR; FDIV step
cols = __ftol((float)(span / step_x)) + 40   // 0x59d46c; ADD EAX,0x28

// base_x [this+0x8c] (0x434ab6-0x434af1):
q = FUN_0059e643((double)((lo_b60 - min_lo) / step_x))  // FSUBR; FDIV; FSTP dbl
base_x = lo_b60 - (q + 20.0) * step_x  // FADD [0x5ce068]; FMUL step; FSUBR [ESP+0x48]
```

Constants (observed via `read_bytes`, LE decode):
`[0x5ce070]` f32 `0x3DCCCCCD` = 0.1 (`ev_6537d381...`, first 4 B);
`[0x5ce068]` f64 `0x4034000000000000` = 20.0 (`ev_8b3a9824...`,
first 8 B); `+0x28` = 40 cols margin.

## Assembly (verbatim subset, `ev_94f24797...`)

```text
0x434a44: FLD float ptr [ESP + 0x50]
0x434a48: FSUB float ptr [ESP + 0x28]
0x434a4c: SUB ESP, 0x8
0x434a4f: FST double ptr [ESP + 0x50]
0x434a53: FMUL float ptr [0x005ce070]
0x434a59: FSTP double ptr [ESP]
0x434a5c: CALL 0x0059e643
0x434a61: FDIVR double ptr [ESP + 0x50]
0x434a65: ADD ESP, 0x8
0x434a6a: MOV dword ptr [EBP + 0x90], 0x41200000
0x434a74: FSTP float ptr [EBP + 0x94]
0x434a7a: CALL 0x00435770
0x434a7f: FSTP float ptr [ESP + 0x24]
0x434a83: MOV ECX, EBP
0x434a85: CALL 0x00435740
0x434a8a: FSUBR float ptr [ESP + 0x24]
0x434a8e: FDIV float ptr [EBP + 0x94]
0x434a94: CALL 0x0059d46c
0x434a99: FLD float ptr [ESP + 0x28]
0x434a9d: ADD EAX, 0x28
0x434aa0: MOV ECX, EBP
0x434aa2: FSTP double ptr [ESP + 0x48]
0x434aa6: MOV dword ptr [EBP + 0x80], EAX
0x434aac: MOV dword ptr [EBP + 0x84], 0x3d
0x434ab6: CALL 0x00435740
0x434abb: FSUBR float ptr [ESP + 0x28]
0x434abf: SUB ESP, 0x8
0x434ac2: FDIV float ptr [EBP + 0x94]
0x434ac8: FSTP double ptr [ESP]
0x434acb: CALL 0x0059e643
0x434ad0: FADD double ptr [0x005ce068]
0x434ad6: FMUL float ptr [EBP + 0x94]
0x434adc: MOV EAX, dword ptr [EBP + 0x84]
0x434ae2: ADD ESP, 0x8
0x434ae9: FSUBR double ptr [ESP + 0x48]
0x434af1: FSTP float ptr [EBP + 0x8c]
```

FDIVR/FDIV/FSUBR direction checked against Intel semantics:
`FDIVR m` = `m / ST0`; `FDIV m` = `ST0 / m`;
`FSUBR m` = `m - ST0`. Matches equations above.

## Callers / callees

- Container: `FUN_004348a0` (`0x4348a0`–`0x434fe9`, 1866 B).
- Callees here: `FUN_0059e643` (round, `ev_234fb768...`),
  `__ftol` trunc (`0x59d46c`, `ev_8535a65a...` dossier /
  `ev_ef14753a...` instr), `FUN_00435770` (max2 reader),
  `FUN_00435740` (min2 reader), `FUN_004de320/004de350`
  (strip lo/hi getters). Outgoing edges incl `0x434a5c→0x59e643`,
  `0x434a94→0x59d46c(__ftol)`, `0x434acb→0x59e643`
  (`ev_1cfb5247...`).
- `FUN_0059e643` pseudocode (`ev_234fb768...`): finite fast path
  `__frnd` (FRNDINT, current RC) → return if already integral or
  FPU status bit `0x20` set; else `FUN_005a4e2d` FP-exception
  plumbing; NaN/Inf branch via `FUN_005a5571/005a4d79`.
- `__ftol` (`ev_ef14753a...`): `FSTCW; OR AH,0xC` (RC=truncate);
  `FLDCW; FISTP qword; FLDCW restore`; returns `EDX:EAX`.
  Caller keeps `EAX`. Ghidra labels VS library `__ftol`
  (`ev_8535a65a...`).
- `00435740` = min of two `+0x28` lo slots,
  `00435770` = max of two `+0x2c` hi slots
  (`evidence/00435740_strip_minmax.md` §§1–3); getters take
  `ECX` only. Which strip is b50 vs b60 inside the readers is
  per that dossier (`[EAX+0x60]` first, `[EAX+0x50]` second);
  grid inputs used here are only the reader *results*
  (`min_lo`, `max_hi`) plus direct `[this+0x60]` slots.
- Strings referenced in this range: none (numeric + calls only).

## Inference (transcribed)

- `FUN_0059e643` on finite inputs = x87 `FRNDINT` = round-half-to-even
  under default RC (observed `__frnd` + equality fast path; exact
  non-default-RC / exception behavior not modeled).
  Transcribed as `f64::round_ties_even` (Rust ≥1.77).
- `__ftol` = truncation toward zero, 64-bit; caller uses low dword
  with x86 wrap (`ADD EAX,0x28`). Transcribed for finite in-`i32`
  range inputs via trunc; out-of-range/invalid (`0x8000...`) open.
- x87 80-bit intermediates vs `f64` transcription: magnitudes here
  (hill extents, ÷0.1/×20) are exactly representable enough that
  `f64` rint/trunc agree; bit-identity vs FPU not claimed —
  equations + order are the transcription, tested on fixtures.
- `TerrainGrid { cols, step_x, base_x }` stays caller-supplied
  struct; new pure constructors compute each field from strip
  values (`lo_b60/hi_b60/min_lo/max_hi`).

## Unknowns

- U-grid-1: `0059e643` non-finite inputs (NaN/Inf → `005a5571`
  status/`005a4d79`/`005a4e2d` paths) unmapped; transcription
  covers finite inputs only.
- U-grid-2: `__ftol` out-of-range (FISTP invalid → `0x8000000000000000`,
  low dword `0x80000000`) vs Rust `as` saturation; open, in-range only.
- U-grid-3: non-default FPU rounding-control word (FRNDINT follows
  RC; transcription assumes default round-nearest-even).
- U-grid-4: strip slot provenance (`[this+0x50/+0x60]` = which hill
  strips) — reader dossier U1 carried, not re-proven here.
- U-grid-5: live strip values (no execution per AGENTS.md); grid
  fields stay caller-supplied, fixtures only.
