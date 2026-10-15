# Sibling slot wrappers `FUN_004de480` / `FUN_004de430` / `FUN_004de4d0` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: guard + dispatch shape ONLY (same selector family as `FUN_004de3e0`,
see `evidence/004de3e0_xform.md`). No slot-target deep dives.
`engine/src/mesh.rs` untouched. Pure guard+dispatch fragments transcribed in
`engine/src/fn_004de480.rs`; selector (`004de2a0`) and slot targets stay
caller-side (opaque closures), same split as
`crate::fn_004357a0::strip_range_predicate`.

Evidence IDs (new, this sweep):

- `ev_adf190fda8a254946ace41e67146f85a77cd44ae8e623ca9e66c0fdaf19c8e3c`
  (`analyze_function FUN_004de480`: pseudocode + asm + callers/callees;
  body `0x4de480-0x4de4c2`, 67 bytes, contiguous).
- `ev_6c1bccad7533941b87cab1990c509400ac2d3b34a1981c05187537d41768e23d`
  (`analyze_function FUN_004de430`: pseudocode + asm + callers/callees;
  body `0x4de430-0x4de476`, 71 bytes, contiguous).
- `ev_0832a867b90748fc2d1ba7cbf94770865f6d971e96137e11c2542fc2857a6885`
  (`analyze_function FUN_004de4d0`: pseudocode + asm + callers/callees;
  body `0x4de4d0-0x4de512`, 67 bytes, contiguous).

Prior (cited): `ev_9e23653e...` (`de480` first analysis) and
`ev_a0bc5893...` (`de430` first analysis) per `evidence/004de3e0_xform.md`
§4 — same slot offsets (`+4`, `+4`+`FPATAN`), consistent with this sweep.

## 1. Observation: `FUN_004de480` (verbatim, `ev_adf190fd...`)

Pseudocode (verbatim):

```c
void FUN_004de480(undefined4 param_1)
{
  int *piVar1;
  int in_ECX;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
  }
  piVar1 = (int *)FUN_004de2a0(param_1);
  (**(code **)(*piVar1 + 4))(param_1);
  return;
}
```

Assembly (verbatim):

```text
0x4de480: MOV AL, byte ptr [ECX + 0x30]
0x4de483: SUB ESP, 0x28
0x4de486: TEST AL, AL
0x4de488: JNZ 0x004de4a9
0x4de48a: PUSH 0x0
0x4de48c: PUSH 0x5d09d4
0x4de491: LEA ECX, [ESP + 0x8]
0x4de495: CALL 0x00406b90
0x4de49a: LEA EAX, [ESP]
0x4de49e: PUSH 0x5e6210
0x4de4a3: PUSH EAX
0x4de4a4: CALL 0x0059ccce
0x4de4a9: PUSH ESI
0x4de4aa: MOV ESI, dword ptr [ESP + 0x30]
0x4de4ae: PUSH ESI
0x4de4af: CALL 0x004de2a0
0x4de4b4: MOV EDX, dword ptr [EAX]
0x4de4b6: PUSH ESI
0x4de4b7: MOV ECX, EAX
0x4de4b9: CALL dword ptr [EDX + 0x4]
0x4de4bc: POP ESI
0x4de4bd: ADD ESP, 0x28
0x4de4c0: RET 0x4
```

Shape: byte-identical prologue to `de3e0` (guard `[ECX+0x30]==0` →
`00406b90` + `__CxxThrowException@8`, same immediates), same selector call
`FUN_004de2a0(arg)` with `ESI` = the one `f32` stack arg re-pushed for the
slot call, `ECX` = selected element, indirect `CALL [EDX+4]` (vtable
slot 1). Only difference from `de3e0` is the slot offset (`+4` vs `+0`).

## 2. Observation: `FUN_004de430` (verbatim, `ev_6c1bccad...`)

Pseudocode (verbatim):

```c
unkbyte10 FUN_004de430(undefined4 param_1)
{
  int *piVar1;
  int in_ECX;
  unkbyte10 Var2;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
  }
  piVar1 = (int *)FUN_004de2a0(param_1);
  Var2 = (**(code **)(*piVar1 + 4))(param_1);
  Var2 = fpatan(Var2,(float10)1);
  return Var2;
}
```

Assembly (verbatim):

```text
0x4de430: MOV AL, byte ptr [ECX + 0x30]
0x4de433: SUB ESP, 0x28
0x4de436: TEST AL, AL
0x4de438: JNZ 0x004de459
0x4de43a: PUSH 0x0
0x4de43c: PUSH 0x5d09d4
0x4de441: LEA ECX, [ESP + 0x8]
0x4de445: CALL 0x00406b90
0x4de44a: LEA EAX, [ESP]
0x4de44e: PUSH 0x5e6210
0x4de453: PUSH EAX
0x4de454: CALL 0x0059ccce
0x4de459: PUSH ESI
0x4de45a: MOV ESI, dword ptr [ESP + 0x30]
0x4de45e: PUSH ESI
0x4de45f: CALL 0x004de2a0
0x4de464: MOV EDX, dword ptr [EAX]
0x4de466: PUSH ESI
0x4de467: MOV ECX, EAX
0x4de469: CALL dword ptr [EDX + 0x4]
0x4de46c: FLD1
0x4de46e: POP ESI
0x4de46f: FPATAN
0x4de471: ADD ESP, 0x28
0x4de474: RET 0x4
```

Shape: same guard + selector + slot-`+4` call as `de480`, then `FLD1;
FPATAN` on the slot result. INFERENCE (asm-exact, high confidence): at
`FPATAN`, `ST0`=1.0, `ST1`=slot-`+4` result `y` (x87 `FPATAN` computes
`ST1=atan(ST1/ST0)` and pops) → net `atan(y/1)=atan(y)`, `f32` in, `ST0`
out. This CONFIRMS slot `+4` returns a float in `ST0` (same float
discipline as slot 0 in `de3e0`). 4 bytes longer than its siblings
(`FLD1`+`FPATAN`, 71 vs 67 bytes).

## 3. Observation: `FUN_004de4d0` (verbatim, `ev_0832a867...`)

Pseudocode (verbatim):

```c
void FUN_004de4d0(undefined4 param_1)
{
  int *piVar1;
  int in_ECX;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
  }
  piVar1 = (int *)FUN_004de2a0(param_1);
  (**(code **)(*piVar1 + 8))(param_1);
  return;
}
```

Assembly (verbatim):

```text
0x4de4d0: MOV AL, byte ptr [ECX + 0x30]
0x4de4d3: SUB ESP, 0x28
0x4de4d6: TEST AL, AL
0x4de4d8: JNZ 0x004de4f9
0x4de4da: PUSH 0x0
0x4de4dc: PUSH 0x5d09d4
0x4de4e1: LEA ECX, [ESP + 0x8]
0x4de4e5: CALL 0x00406b90
0x4de4ea: LEA EAX, [ESP]
0x4de4ee: PUSH 0x5e6210
0x4de4f3: PUSH EAX
0x4de4f4: CALL 0x0059ccce
0x4de4f9: PUSH ESI
0x4de4fa: MOV ESI, dword ptr [ESP + 0x30]
0x4de4fe: PUSH ESI
0x4de4ff: CALL 0x004de2a0
0x4de504: MOV EDX, dword ptr [EAX]
0x4de506: PUSH ESI
0x4de507: MOV ECX, EAX
0x4de509: CALL dword ptr [EDX + 0x8]
0x4de50d: ADD ESP, 0x28
0x4de510: RET 0x4
```

Shape: same program as `de480` with slot `+8` (vtable slot 2).

## 4. Observation: callers / callees / strings

- Callees (all three, static): `0x406b90`, `__CxxThrowException@8`
  (`0x59ccce`), `0x4de2a0`. Slot targets are runtime-indirect, not static
  callees.
- Callers: `de480` ← `0x45dce0`, `0x4de7c0`; `de430` ← `0x43ecf0`,
  `0x457110`, `0x45b130`, `0x45dce0`; `de4d0` ← `0x45b130`. Note `0x45dce0`
  calls `de3e0` (slot 0), `de430` AND `de480` — one caller using three
  slots of the same element family. `0x4de7c0` calls only `de480`
  (did not appear in the 19 `de3e0` callers). Call-site arg shapes
  unmapped — out of scope.
- Referenced strings: none in any body (observation: asm contains only
  immediates `0x0` / `0x5d09d4` / `0x5e6210`, same throw immediates as
  `de3e0`/`de320`/`de350`).

## Unknowns

- U1 (open): concrete slot-`+4`/`+8` target sets — same gap as slot-0 U1
  in `004de3e0_xform.md` (list writers unmapped; closes nothing new).
- U2 (open): whether slot-`+4` targets taking the `f32` arg return `f32`
  in all cases — confirmed for the `de430` path only (FPATAN consumes
  `ST0` as float); `de480`/`de4d0` result types inferred from family
  shape, not directly observed (their callers' `ST0` use unmapped).
- U3 (method): `ST0` extended-precision caveat — `FPATAN` runs on the
  80-bit slot result; Rust `f32::atan` on the rounded `f32` may differ on
  sub-`f32`-precision borderlines (same caveat class as `00443030`).
- U4 (carried): exact exception object (`DAT_005d09d4` payload,
  `DAT_005e6210` throw info) unmapped; transcription panics per the
  deliberate convention in `engine/src/fn_004de320.rs`.
