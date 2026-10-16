# Quaternion composer `FUN_004df660` — Euler→quaternion (closes `rotation_writer.md` U1)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`.
Parent: `evidence/rotation_writer.md` §4/U1 (trig + normalization source
for `0046fa90` via `00502220`).

## 1. Claim

- `FUN_004df660` (`0x4df660`–`0x4df6fd`, 158 B) is an Euler→quaternion
  composer, cdecl `(dest: float[4]*, a, b, c: float) -> dest`.
- `a` rotates about **Y**, `b` about **X**, `c` about **Z** (axis↔param
  verified from asm push order, §2, not just pseudocode).
- Output: `*dest = (qY(a) ⊗ qX(b)) ⊗ qZ(c)` (Hamilton product,
  left-associated; order from REA entry-canonical refs, §2).
- Trig lives HERE (`FCOS`/`FSIN` x87 insns, 3× half-angle). No
  normalization anywhere on this path (unit in → unit out assumed).
- Helper `FUN_004df510` is the Hamilton product
  (`dest = ECX ⊗ stack-src`); all four component formulas verified
  term-by-term from asm (§3). `CRect::CRect` is a verbatim 4-dword store.

## 2. Observation: `FUN_004df660` (57 insns)

Evidence: `ev_248242f90ea3ce67516444d5f8f8b78cfeb26ec115c16a73883cc235907f539e`
(`analyze_function`); duplicate run
`ev_dce5fb678f8712932a89a39965ae6758950b70480251963baff6a923ef5c7de8`
(same dossier: locals, outgoing refs, caller list); raw instructions:
`ev_fd26eba0e1985b0bf24eb576e76d45a30cbea7311c74caf09bc179d19bc41559`
(`read_function_instructions`, 57 insns).

Pseudocode (verbatim):

```c
undefined4 FUN_004df660(undefined4 param_1,float param_2,float param_3,float param_4)
{
  float10 fVar1;
  float10 fVar2;
  undefined4 uVar3;
  CRect *pCVar4;
  CRect local_40 [16];
  CRect local_30 [16];
  CRect local_20 [16];
  undefined1 local_10 [16];

  fVar1 = (float10)fcos((float10)param_2 * (float10)0.5);
  fVar2 = (float10)fsin((float10)param_2 * (float10)0.5);
  CRect::CRect(local_20,0,(int)(float)fVar2,0,(int)(float)fVar1);
  fVar1 = (float10)fcos((float10)param_3 * (float10)0.5);
  fVar2 = (float10)fsin((float10)param_3 * (float10)0.5);
  CRect::CRect(local_30,(int)(float)fVar2,0,0,(int)(float)fVar1);
  fVar1 = (float10)fcos((float10)param_4 * (float10)0.5);
  fVar2 = (float10)fsin((float10)param_4 * (float10)0.5);
  CRect::CRect(local_40,0,0,(int)(float)fVar2,(int)(float)fVar1);
  pCVar4 = local_40;
  uVar3 = param_1;
  FUN_004df510(local_10,local_30);
  FUN_004df510(uVar3,pCVar4);
  return param_1;
}
```

(`(int)` casts are float-bit stores: `CRect::CRect` writes 4 dwords
verbatim, see §3. `float10` = x87 80-bit intermediate.)

Calling convention (observed): entry `FLD [ESP+0x8]` before any push =
`a` (first float); canonical refs `0x4df660->stack:0x8`,
`0x4df689->stack:0xc` (= `b`), `0x4df6ae->stack:0x10` (= `c`),
`0x4df6d3->stack:0x4` (= `dest`). Tail `MOV EAX,ESI; RET` (bare `RET` =
cdecl, caller cleans). Returns `dest`.

Axis↔param (observed, from asm push order — top-of-stack at each
`CALL 0x004df350` is `p1`, params read `[ESP+4..+10]` above `RET`):
- quat1 (`a`): pushes `0, sin, 0, cos` → `(0, sin(a/2), 0, cos(a/2))` = Y.
- quat2 (`b`): pushes `sin, 0, 0, cos` → `(sin(b/2), 0, 0, cos(b/2))` = X.
- quat3 (`c`): pushes `0, 0, sin, cos` → `(0, 0, sin(c/2), cos(c/2))` = Z.
Each angle halved via `FMUL double ptr [0x005cdaf8]`; file bytes at
`0x5cdaf8` (`.rdata`, file offset `0x1cdaf8`, obs.) =
`000000000000e03f` = **double 0.5**. `FCOS`/`FSIN` are inline x87.

Multiply order (observed): REA entry-canonical LEA refs
`0x4df6d7->entry-0x40` (= `local_40`), `0x4df6dc->entry-0x30`
(= `local_30`), `0x4df6e1->entry-0x10` (= `local_10`),
`0x4df6e7->entry-0x20` (= `local_20`, final `ECX`).
Callee `004df510` reads src-B from `[entry+8]`, dest from
`[entry+4]` (after its own 2 pushes), `ECX` = src-A, `RET 0x8`.
Push sequence `EAX(l40), ESI(dest), ECX(l30), EDX(l10)` ⇒ call#1:
dest=`local_10`, src-B=`local_30`(qX), src-A=`ECX`=`local_20`(qY):
`tmp = qY ⊗ qX`. Call#2 (stack leftovers `ESI, EAX`; `ECX`=call#1
result): dest=`param_1`, src-B=`local_40`(qZ), src-A=`tmp`:
`*dest = tmp ⊗ qZ`. Full: `*dest = (qY(a) ⊗ qX(b)) ⊗ qZ(c)`.

Callers (9): `00450ab0` (×10 sites), `00453110`, `0045b130`,
`0045dce0`, `00502220`, `005026f0`, `00502780`, `00502820`,
`005028b0`. Only `00502220` args observed: `(local,0,0,0)` → identity
(see rotation_writer.md §4). Callees: `004df350`, `004df510` only.
Strings: none. Names: `CRect::CRect`, `FUN_004df510`, `DAT_005cdaf8`.

## 3. Helper observations (firm)

- `FUN_004df510` (`0x4df510`–`0x4df5a5`, 150 B,
  `ev_6dd1846ce81abe8385fe1a3e38687b78510ba0b54f356ab56eff1f73b04a7050`):
  `dest([entry+4]) = ECX ⊗ [entry+8]`, Hamilton product, x87 FPU,
  `RET 0x8`. All four groups verified term-by-term from asm
  (A = `ECX`, B = stack src):
  - `w = ((B.w·A.w − B.x·A.x) − B.y·A.y) − B.z·A.z`
  - `z = ((B.y·A.x + A.w·B.z) − B.x·A.y) + B.w·A.z`
  - `y = ((A.w·B.y − B.z·A.x) + B.x·A.z) + B.w·A.y`
  - `x = ((B.z·A.y + A.w·B.x) + A.x·B.w) − B.y·A.z`
  Standard `(A⊗B)` in each slot. No normalization.
- `CRect::CRect` (`0x4df350`, 32 B, library match VS2005/2008,
  `ev_f2b11b7ef4177aae987fbec0c86cacdf67b339b05121c5c61667c00e5c11933c`):
  verbatim 4-dword store (`[this+0,+4,+8,+0xc] ← p1..p4`).

## 4. Inference

- U1 closed: trig lives in `004df660` (inline x87 `FCOS`/`FSIN` on
  half-angles), NOT in `0046fa90` (pure polynomial, as recorded).
- Normalization: none on this path — neither `004df660`, `004df510`,
  nor `0046fa90` normalizes. Unit output relies on unit axis-quats
  (`sin²+cos²=1`); multi-axis products preserve norm algebraically.
  Caller responsibility, end to end.
- Precision: original evaluates angle-halving in x87 extended
  (`float→double` load × `double 0.5`, `FSIN`/`FCOS` 80-bit, narrow to
  `f32` on store) and multiplies in x87; Rust transcription uses `f32`
  per-op. Bit-exact for `(0,0,0)` (exact `sin0/cos0` both sides);
  general inputs may differ ~1 ulp/slot. Recorded in doc comment.

## 5. Transcription (`engine/src/matrix.rs`)

- `quat_multiply(a, b)`: §3 formulas with original association order
  (`w` first … `x` last is computation order; slots stored `(x,y,z,w)`).
  `a` = original `ECX`, `b` = original stack src.
- `euler_to_quaternion(a, b, c)`: `qY=(0,sin(a/2),0,cos(a/2))`,
  `qX=(sin(b/2),0,0,cos(b/2))`, `qZ=(0,0,sin(c/2),cos(c/2))`,
  `quat_multiply(quat_multiply(qY, qX), qZ)`.
- Test (generated fixtures, no original bytes): `I⊗q`/`q⊗I` identity,
  `i⊗j=k` bit-exact, `euler(0,0,0)=(0,0,0,1)` bit-exact (matches
  observed `00502220` call), single-axis Y-90° structure
  (`x==z==0`, `y≈w≈√2/2`, unit norm). Multi-axis combined values NOT
  asserted (would enshrine the §2 order reading beyond the tests).

## Unknowns

- U1 (new, minor): two `analyze_function` runs returned different
  Evidence IDs (`ev_2482…` vs `ev_dce5…`) for identical dossier content;
  both recorded; no content divergence observed.
- U2 (carried): x87-vs-`f32` rounding — association matched, extended
  intermediates not modeled (doc comment).
- U3 (carried): remaining 8 callers' angle args untraced; only
  `00502220`'s `(0,0,0)` is observed.
