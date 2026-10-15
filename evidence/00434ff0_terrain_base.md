# FUN_00434ff0 — terrain base (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE, NOT the installer stub),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Procedure `0x434ff0`–`0x4350cd`, 222 B, contiguous, `__stdcall`-ish
(ECX=this + 2 float stack args, callee pops 8 via `RET 0x8`).
Called from terrain builder `FUN_004348a0` (`ev_ae091b9c...`, call site
`0x434b99`: ECX=EBP(this), PUSH fVar5(lateral), PUSH fVar4(longitudinal)).

## Pseudocode (REA decompiler, `ev_0433699b...` / `ev_a9f53ba9...`)

```text
float10 FUN_00434ff0(float param_1, float param_2)  // ECX = this
{
  if (param_1 < *(float *)(this + 0x260)) {
    f = FUN_004de350(param_1);        // actually thiscall on [this+0x60], stack arg ignored
    f = FUN_004de320((float)f);       // same object
    f = FUN_00468310((float)f);       // 3-arg clamp, decompiler drops args
    f = FUN_004de3e0((float)f);       // ECX=[this+0x68] virtual transform
    f = FUN_00468360(0, ABS(param_2) - f);   // max(0, ...)
    g = (*(float *)(this + 0x98) <= param_1) ? 0.0 : param_1 - [this+0x98];
    return SQRT(f*f + g*g);
  }
  param_1 = param_1 - *(float *)(this + 0x260);
  return FUN_00468360(0, SQRT(param_2*param_2 + param_1*param_1) - *(float *)(this + 0x264));
}
```

## Assembly summary (hand-verified incl. CALL/RET stack shifts + callee cleanups)

- `0x434ff0`: FLD p1; FCOMP `[ESI+0x260]` (ESI=ECX=this); JZ→B when C0=0
  (p1 >= thr; NaN is unordered → C0=1 → A-path).
- Branch A (`0x43500b`–`0x435096`): FABS p2 → FSTP double scratch;
  A=`[obj60+0x2c]` (`004de350`, EBX=`[this+0x68]`, EDI=`[this+0x60]`);
  B=`[obj60+0x28]` (`004de320`); C=`clamp(B,A,p1)` (`00468310`,
  stack slots `[ESP+4]=B,[ESP+8]=A,[ESP+12]=p1` post-CALL-shift, verified by
  concrete emulation); D=`xform(obj68,C)` (`004de3e0`, `RET 0x4` — the +4
  shift confirmed by FSUBR hitting the `|p2|` scratch exactly);
  E=`|p2|-D` (FSUBR double); E32=FSTP float; F=`max(E32,0.0)` (`00468360`);
  G=(p1<x0||NaN) ? p1-x0 : 0.0 (`DAT_005cd378`=0.0, `ev_3d1f761d...`);
  return `sqrt(F²+G²)` (FSTP ST2/FSTP ST0 leave ST0).
- Branch B (`0x435099`–`0x4350cb`): dx=p1-thr; H=`sqrt(p2²+dx²)-[this+0x264]`;
  return `max(H32,0.0)`. Full push/pop balance verified (40 = 36 + RET4).

## Callers / callees

- Callers: `FUN_004348a0` (terrain builder, `ev_ae091b9c...`, `0x434b99`,
  per-vertex `(fVar4,fVar5)` in the 61-row heightfield loop);
  `FUN_00455ba0` (`ev_008854d7...`, 3081 B, render-ish — role unmapped, out of scope).
- Callees:
  - `FUN_004de350` (`ev_d009b3dd...`): checked getter → `*(ECX+0x2c)`,
    throws (via `00406b90`+`59ccce`) if `*(ECX+0x30)==0`.
  - `FUN_004de320` (`ev_04a8515c...`): same → `*(ECX+0x28)`.
  - `FUN_00468310` (`ev_d6c4e9f3...`, raw bytes `ev_40163b13...`, all-`C3`
    RETs): median-clamp, `if v<lo→lo; if hi<v→hi; else v` (C0-bit exact).
  - `FUN_00468360` (`ev_ec2bdf6f...`, raw `ev_679ea9ce...`): max,
    `if b<a→a else b` (C0-bit exact).
  - `FUN_004de3e0` (`ev_78cbb32b...`, `RET 0x4`): virtual transform —
    target = `FUN_004de2a0` (`ev_4f35bbfc...`) list-search selected by
    predicate `FUN_00442f80`, then `CALL [EDX]`. Target unmapped.

## Transcription (`engine/src/mesh.rs`: `TerrainBase::eval`)

`thr=[this+0x260]`, `off=[this+0x264]`, `x0=[this+0x98]`,
`lo=[obj60+0x28]`, `hi=[obj60+0x2c]`, `xform` = opaque `004de3e0` closure.
f64 intermediates (≈ x87 extended), explicit f32 round-trips where the asm
stores float (C→xform arg, E32, H32, final return rounded by caller).

## Observation vs inference vs unknown

- Observation: all branch structure, callee roles, slot contents, NaN→C0=1
  mappings, `0.0` constant bytes, caller arg order, both caller addresses.
- Inference (from asm, high confidence): clamp bound order lo=B(+0x28),
  hi=A(+0x2c) — positional from verified stack layout, NOT from value ranges;
  `x0` set in `004348a0` as `fVar2 - cos(pi*param_3*0.00555…)*param_4`.
- Unknown:
  - U1: identities of `this+0x60`/`+0x68` sub-objects and of
    `thr/off` (`+0x260`/`+0x264` never written in `004348a0`; set elsewhere).
  - U2: `xform` virtual target(s) (`004de2a0` selection + `00442f80`
    predicate unmapped) — closure in transcription.
  - U3: `FUN_00455ba0` caller role.
  - U4: residual x87-80-bit vs f64 intermediate precision (≤ ~1 ulp).
  - U5: absent-range (`+0x30==0`) throws C++ exception in original;
    transcription panics (no C++ EH in engine) — deliberate, documented.
