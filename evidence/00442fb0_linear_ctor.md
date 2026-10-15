# Linear element ctor `0x442fb0` input-to-slot wiring (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: this ctor ONLY. Closes linear half of the recommended wiring
(`evidence/xform_list_setup.md` §Recommended via `00443030` evidence §2;
cubic analog `evidence/00443060_cubic_ctor.md`).

Prior (cited, not re-pulled): `evidence/xform_list_setup.md` §§1-3
(linear layout `0x14`, vtable `005ce0e8`, sole caller `0x4ddae0`,
emitter arg order `(prev_x, prev_y, p, param_2)`);
`evidence/00443030_linear_xform.md` §§1-2 (slot-0 `slope*x+intercept`
read of `+12/+16`).

## Evidence IDs (new, this sweep)

- `ev_28b987cc86c1ef2008908f440f417e8a0e770cbd19af10782f82056f170cea1b`
  (`analyze_function FUN_00442fb0`: pseudocode + full asm + callers/
  callees/refs; body `0x442fb0-0x443022`, 115 B, contiguous; 3 basic
  blocks; strings none).
- `ev_331e892376db5a4d0bc3e54099af29bd19fa21345df80c89f9cd701bc2241ef3`
  (`read_bytes 0x005ce0e0`, 8 B complete: `0000000000000000` = `0.0`
  double — the `FCOMP` threshold).

## 1. Observation: signature, callees, constants

thiscall, `ECX` = new element, four `f32` stack params (`RET 0x10`):

```c
void FUN_00442fb0(float param_1, float param_2, float param_3, float param_4)
```

Callees (observation, `ev_28b987cc...`): `0x442f30` (base: vtable
`005ce0d0` then overwritten, `lo`/`hi` from `(param_1, param_3)`).
Callers: `0x4ddae0` ONLY (`UNCONDITIONAL_CALL` at `0x4ddba3`).
Strings: none. Data refs: `0x5ce0e8` (linear vtable, stored at `[ESI]`),
`0x5ce0e0` (`0.0` double, degenerate compare).

## 2. Observation: pseudocode at `0x442fb0` (verbatim, `ev_28b987cc...`)

```c
void FUN_00442fb0(float param_1,float param_2,float param_3,float param_4)
{
  undefined4 *in_ECX;

  FUN_00442f30(param_1,param_3);
  *in_ECX = &PTR_LAB_005ce0e8;
  if (0.0 < ABS(param_3 - param_1)) {
    in_ECX[3] = (param_4 - param_2) / (param_3 - param_1);
    in_ECX[4] = param_2 - param_1 * (float)in_ECX[3];
    return;
  }
  in_ECX[3] = 0;
  in_ECX[4] = param_2 - param_1 * (float)in_ECX[3];
  return;
}
```

Assembly (verbatim, `ev_28b987cc...`):

```text
0x442fb0: MOV EAX, dword ptr [ESP + 0xc]
0x442fb4: PUSH ESI
0x442fb5: MOV ESI, ECX
0x442fb7: PUSH EAX
0x442fb8: MOV ECX, dword ptr [ESP + 0xc]
0x442fbc: PUSH ECX
0x442fbd: MOV ECX, ESI
0x442fbf: CALL 0x00442f30
0x442fc4: FLD float ptr [ESP + 0x10]
0x442fc8: FSUB float ptr [ESP + 0x8]
0x442fcc: MOV dword ptr [ESI], 0x5ce0e8
0x442fd2: FLD ST0
0x442fd4: FABS
0x442fd6: FCOMP double ptr [0x005ce0e0]
0x442fdc: FNSTSW AX
0x442fde: TEST AH, 0x41
0x442fe1: JNZ 0x00443006
0x442fe3: FLD float ptr [ESP + 0x14]
0x442fe7: FSUB float ptr [ESP + 0xc]
0x442feb: MOV EAX, ESI
0x442fed: FDIV ST0, ST1
0x442fef: FSTP float ptr [ESI + 0xc]
0x442ff2: FSTP ST0
0x442ff4: FLD float ptr [ESP + 0x8]
0x442ff8: FMUL float ptr [ESI + 0xc]
0x442ffb: FSUBR float ptr [ESP + 0xc]
0x442fff: FSTP float ptr [ESI + 0x10]
0x443002: POP ESI
0x443003: RET 0x10
0x443006: FSTP ST0
0x443008: FLD float ptr [ESP + 0x8]
0x44300c: MOV dword ptr [ESI + 0xc], 0x0
0x443013: MOV EAX, ESI
0x443015: FMUL float ptr [ESI + 0xc]
0x443018: FSUBR float ptr [ESP + 0xc]
0x44301c: FSTP float ptr [ESI + 0x10]
0x44301f: POP ESI
0x443020: RET 0x10
```

Stack-arg map (observation, derivation from prologue pushes): on entry
`[ESP+4/+8/+12/+16] = p1/p2/p3/p4`; after `PUSH ESI` all shift `+4`, so
gap `FLD [ESP+0x10]; FSUB [ESP+0x8]` = `p3 - p1`, slope numerator
`FLD [ESP+0x14]; FSUB [ESP+0xC]` = `p4 - p2`, intercept
`FLD [ESP+0x8](p1); FMUL slope; FSUBR [ESP+0xC](p2)` = `p2 - p1*slope`.
Degenerate arm writes `[+12] = 0` then the SAME intercept shape with
the stored `0.0` reloaded (`FMUL [ESI+0xC]`), i.e. `p2 - p1*0`.

Branch (observation): `FLD gap; FLD ST0; FABS; FCOMP [0.0 double];
FNSTSW; TEST AH,0x41; JNZ 0x443006`. Bit mask `0x41` = C3 (bit 6, set
on equal OR unordered) + C0 (bit 0, set on below OR unordered). Normal
path requires neither set, i.e. `0.0 < ABS(gap)` ordered-above. Taken
(degenerate) when gap `== 0.0` (incl. `-0.0`) OR gap is NaN. Basic
blocks (`ev_28b987cc...`): `442fb0-442fe3` header,
`442fe3-443006` main, `443006-443023` degenerate.

## 3. Wiring map (all observation)

Notation: `x0=param_1`, `y0=param_2`, `x1=param_3`, `y1=param_4`,
`gap = x1 - x0` (`FSUB` order).

- `+4/+8` (via base `0x442f30(param_1, param_3)`): `lo`/`hi` of
  `(x0, x1)` — observation (same convention as cubic `0x443060`).
- `+0`: vtable `005ce0e8` — observation.
- `+12` (`in_ECX[3]`, slope): normal `s = (y1-y0)/(x1-x0)` (`FDIV`
  `ST0,ST1` order); degenerate `0.0`.
- `+16` (`in_ECX[4]`, intercept): BOTH arms `y0 - x0*s` with the
  just-stored `s` reloaded (`FSUBR` reversed-subtract order), so the
  line passes through `(x0,y0)`; degenerate arm is `y0 - x0*0`,
  which equals `y0` for finite `x0` but NaN when `x0` is inf/NaN
  (`inf*0` invalid → NaN) — observation from the `FMUL`/`FSUBR`
  shape, transcribed isomorphically (no simplification to `y0`).
- Caller arg order (prior, `xform_list_setup.md` §1): emitter
  `0x4ddae0` passes `([ECX+0x20], [ECX+0x24], p, param_2)`, i.e.
  `(prev_x, prev_y, new_x, new_y)` straight into `(x0,y0,x1,y1)`.

## 4. Callers / callees / strings

- Callees: `0x442f30` only. No `00443280`/`00443290` use (unlike cubic).
- Callers: `0x4ddae0` only (`0x4ddba3 UNCONDITIONAL_CALL`).
- Referenced strings: none (observation, empty list).
- Referenced names: `FUN_00442f30` (call), `LAB_00443006`
  (degenerate target), `DAT_005ce0e0` (`0.0` double),
  `PTR_LAB_005ce0e8` (vtable).

## Unknowns

- U1 (carried): base `00442f30` NaN edge on `lo`/`hi`
  (`xform_list_setup.md` §5 U3) applies to `(x0,x1)` here too.
- U2 (carried): 80-bit `ST0` intermediates (divide + mul/sub chains,
  single `FSTP m32` rounding per slot) vs `f64` stand-in — last-ulp
  caveat in module docs, same class as `004432a0`/`00443060` U4.
- U3 (carried): runtime slope/intercept VALUES are data, unmapped.

## Transcribed

`engine/src/fn_00442fb0.rs` (`pub mod fn_00442fb0` in `lib.rs`,
alphabetical; `mesh.rs` untouched) as slope/intercept core
`fn_00442fb0(x0,y0,x1,y1) -> (slope, intercept)` with `f64`
intermediates (nearest portable stand-in for single-rounded 80-bit
`ST0`; last-ulp caveat in module docs), isomorphic
`0.0 < |gap| → divide` else `slope 0.0` arm and shared
`intercept = y0 - x0*slope` in both arms (degenerate NaN/inf edge
preserved). Base call `0x442f30` and element write-back (vtable,
`lo`/`hi`, slot stores) stay out — separate procedure units /
`mesh.rs` integration. One test `linear_ctor_endpoints`: slot-0
endpoint reproduction via `linear_xform` + exact degenerate arms.
