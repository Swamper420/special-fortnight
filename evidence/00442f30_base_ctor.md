# Base element ctor `0x442f30` lo/hi core (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: lo/hi core ONLY. Vtable store (`[ECX] = 0x5ce0d0`) is data,
noted only. Closes the carried NaN-edge unknown in
`evidence/00442fb0_linear_ctor.md` (U1),
`evidence/00443060_cubic_ctor.md` (U3),
`evidence/00443370_arc_ctor.md` (U3), all citing
`evidence/xform_list_setup.md` §5 U3.

Prior (cited, not re-pulled): the three caller dossiers for base-call
sections — linear `0x442fb0` (base `(param_1, param_3)`),
cubic `0x443060` (base `(param_1, param_3)`),
arc `0x443370` (base `(param_3, param_5)`); each stores its own vtable
over the base value after the call.

## Evidence IDs (new, this sweep)

- `ev_7655649bba8c7a6ed73f8a56e67ac732693d1dc0b3e5caa0655689e74e7c7d01`
  (`analyze_function FUN_00442f30`: pseudocode + full asm + callers/
  callees/refs; body `0x442f30-0x442f78`, 73 B, contiguous; 6 basic
  blocks; strings none; data ref `0x5ce0d0`; callees none; callers
  `0x442fb0`/`0x443060`/`0x443370` only).

## 1. Observation: signature, body, callees

thiscall, `ECX` = new element, two `f32` stack params (`RET 0x8` ×2):

```c
void FUN_00442f30(float param_1, float param_2)
```

Callees: none. Callers: `0x442fb0`, `0x443060`, `0x443370`
(all `UNCONDITIONAL_CALL`). Strings: none. Data refs: `0x5ce0d0`
(base vtable, stored at `[ECX]`).

## 2. Observation: pseudocode (verbatim, `ev_7655...`)

```c
void FUN_00442f30(float param_1,float param_2)
{
  float fVar1;
  undefined4 *in_ECX;

  *in_ECX = &PTR_LAB_005ce0d0;
  fVar1 = param_2;
  if (param_1 < param_2) {
    fVar1 = param_1;
  }
  in_ECX[1] = fVar1;
  if (param_1 <= param_2) {
    in_ECX[2] = param_2;
    return;
  }
  in_ECX[2] = param_1;
  return;
}
```

Assembly (verbatim, `ev_7655...`):

```text
0x442f30: FLD float ptr [ESP + 0x4]
0x442f34: FCOMP float ptr [ESP + 0x8]
0x442f38: MOV dword ptr [ECX], 0x5ce0d0
0x442f3e: FNSTSW AX
0x442f40: TEST AH, 0x1
0x442f43: JZ 0x00442f4b
0x442f45: FLD float ptr [ESP + 0x4]
0x442f49: JMP 0x00442f4f
0x442f4b: FLD float ptr [ESP + 0x8]
0x442f4f: FSTP float ptr [ECX + 0x4]
0x442f52: FLD float ptr [ESP + 0x4]
0x442f56: FCOMP float ptr [ESP + 0x8]
0x442f5a: FNSTSW AX
0x442f5c: TEST AH, 0x41
0x442f5f: JNZ 0x00442f6d
0x442f61: FLD float ptr [ESP + 0x4]
0x442f65: MOV EAX, ECX
0x442f67: FSTP float ptr [ECX + 0x8]
0x442f6a: RET 0x8
0x442f6d: FLD float ptr [ESP + 0x8]
0x442f71: MOV EAX, ECX
0x442f73: FSTP float ptr [ECX + 0x8]
0x442f76: RET 0x8
```

## 3. Observation: branch shape + NaN edge (closes carried U-NaN)

x87 `FCOMP` flag map: C3/C2/C0 = unordered `111`, greater `000`,
less `001`, equal `100`. `FNSTSW AX` puts C0 at `AH` bit 0,
C3 at `AH` bit 6.

- Gate 1 (`lo`, `[ECX+4]`): `TEST AH,0x1` (C0 only), `JZ 0x442f4b`.
  Fall-through (C0=1: ordered-less OR unordered) loads `param_1`;
  jump (C0=0: ordered `>=`) loads `param_2`. So `lo = param_1`
  iff `p1 < p2` ordered OR either is NaN — i.e. `!(p1 >= p2)`.
- Gate 2 (`hi`, `[ECX+8]`): `TEST AH,0x41` (C0|C3), `JNZ 0x442f6d`.
  Taken (C0 or C3: ordered `<=` OR unordered) loads `param_2`;
  fall-through (ordered `>`) loads `param_1`. So `hi = param_2`
  iff `!(p1 > p2)`.

Combined: ordered inputs give `(min, max)`. Any NaN input gives
`(lo, hi) = (p1, p2)` as-is, no swap. The decompiler's `<` / `<=`
spellings differ on NaN (both false in C, both taken in asm);
the transcription encodes them as `!(p1 >= p2)` / `!(p1 > p2)`,
which match on all ordered inputs AND on NaN.

## 4. Callers / callees / strings

- Callees: none (observation, empty list).
- Callers: `0x442fb0` (`0x442fbf`), `0x443060` (`0x443072`),
  `0x443370` (`0x443382`) — all `UNCONDITIONAL_CALL`.
- Referenced strings: none (observation, empty list).
- Referenced names: `LAB_00442f4b`, `LAB_00442f4f`, `LAB_00442f6d`,
  `PTR_LAB_005ce0d0`.

## Transcribed

`engine/src/fn_00442f30.rs` (`pub mod fn_00442f30` in `lib.rs`,
alphabetical; `mesh.rs` untouched) as pure lo/hi core
`fn_00442f30(p1, p2) -> (lo, hi)` with the asm predicates
`!(p1 >= p2)` / `!(p1 > p2)` (NaN edge preserved). Vtable store
and element write-back stay out — data / `mesh.rs` integration.
One test `base_ctor_lo_hi`: ordered min/max both orders, equal,
`-0.0`, NaN-either-leg pins `(p1, p2)` passthrough.

## Unknowns

- None open on the lo/hi core. Carried U-NaN (linear U1, cubic U3,
  arc U3) CLOSED by §3.
- Out of scope (not unknowns of this unit): vtable `0x5ce0d0`
  semantics and per-caller arg identities — caller dossiers own them.
