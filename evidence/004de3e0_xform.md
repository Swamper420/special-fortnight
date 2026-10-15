# Virtual xform dispatch `FUN_004de3e0` / `FUN_004de2a0` / `FUN_00442f80` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: dispatch mechanism ONLY. No target-function deep dives.
`engine/src/mesh.rs` untouched. Evidence-only (no pure fragment maps cleanly;
prior transcriptions keep `de3e0` as opaque closure — unchanged).

Evidence IDs (new, this sweep):

- `ev_229ed5be2ae285842080cfa07fb67565fe3c7eccc35b4cc0f0207b6775d62d89`
  (`analyze_function FUN_004de3e0`: pseudocode + asm + callers/callees;
  body `0x4de3e0-0x4de421`, 66 bytes, contiguous).
- `ev_4206caa69468ae9969b834fc36776b1d8c7eb8399c2fb1c0f7c2a69d38663f31`
  (`procedure_assembly FUN_004de3e0`, verbatim asm below).
- `ev_65e2689c9c78f72d007fa30a4c1ffe176a07bb23157411322f55d500bec42ab5`
  (`procedure_callers FUN_004de3e0`: 19 callers, listed below).
- `ev_7bc6e3f10b625a0011732a3e8779e5b5fba2cb20ab9540bd2a36959f42d9d9a7`
  (`procedure_callees FUN_004de3e0`: `0x406b90`, `0x4de2a0`, `0x59ccce`;
  also `procedure_assembly FUN_004de4d0`, cited §4).
- `ev_4f35bbfc87422049cb687bbe4beec606f13394831de317c08cc019b752408ea3`
  (`analyze_function FUN_004de2a0`: list-search selector;
  body `0x4de2a0-0x4de316`, 119 bytes, contiguous).
- `ev_e4df3062665a22466f09129918cc2c8984fba4064d3747ecd2e0d441a5a391cc`
  (`procedure_callers FUN_004de2a0`: `de3e0`, `de430`, `de480`, `de4d0` only).
- `ev_a0bc5893af2d1d4d390f4a736caebed522ddd9710801965d34abff1ac6f5d178`
  (`analyze_function FUN_004de430`: sibling wrapper, vtable slot +4 + `FPATAN`).
- `ev_9e23653e2be2aaa72f4e0cde5b46af36f4f8387fb872f4dd6aff3758412850bf`
  (`analyze_function FUN_004de480`: sibling wrapper, vtable slot +4).
- `ev_ff6c9550d5437619917e01973378db23ab544de42b9edd8b11228abaa26e610d`
  (`analyze_function FUN_00442f80`: range predicate;
  body `0x442f80-0x442fa8`, 41 bytes, contiguous).

Prior (cited): `ev_78cbb32b...` (`de3e0` first analysis, per
`evidence/004357a0_predicates.md` §5); `ev_4f35bbfc...` selector +
`FUN_00442f80` predicate role per `evidence/00434ff0_terrain_base.md` §5 —
same `4f35bbfc` analysis re-pulled above, consistent.

## 1. Observation: `FUN_004de3e0` assembly (verbatim, `ev_4206caa6...`)

```text
0x4de3e0: MOV AL, byte ptr [ECX + 0x30]
0x4de3e3: SUB ESP, 0x28
0x4de3e6: TEST AL, AL
0x4de3e8: JNZ 0x004de409
0x4de3ea: PUSH 0x0
0x4de3ec: PUSH 0x5d09d4
0x4de3f1: LEA ECX, [ESP + 0x8]
0x4de3f5: CALL 0x00406b90
0x4de3fa: LEA EAX, [ESP]
0x4de3fe: PUSH 0x5e6210
0x4de403: PUSH EAX
0x4de404: CALL 0x0059ccce
0x4de409: PUSH ESI
0x4de40a: MOV ESI, dword ptr [ESP + 0x30]
0x4de40e: PUSH ESI
0x4de40f: CALL 0x004de2a0
0x4de414: MOV EDX, dword ptr [EAX]
0x4de416: PUSH ESI
0x4de417: MOV ECX, EAX
0x4de419: CALL dword ptr [EDX]
0x4de41b: POP ESI
0x4de41c: ADD ESP, 0x28
0x4de41f: RET 0x4
```

Pseudocode (verbatim, `ev_229ed5be...`):

```c
void FUN_004de3e0(undefined4 param_1)
{
  undefined4 *puVar1;
  int in_ECX;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
  }
  puVar1 = (undefined4 *)FUN_004de2a0(param_1);
  (**(code **)*puVar1)(param_1);
  return;
}
```

Mechanism: thiscall (`ECX`=strip, one `f32` stack arg, `RET 0x4`).
`[ECX+0x30]==0` → `00406b90` + `__CxxThrowException@8` (same throw family as
the `de320`/`de350` getters). Else `ECX` passes through untouched to
`FUN_004de2a0(arg)`; its return `EAX`=element object; `EDX=[EAX]`=vtable;
indirect `CALL [EDX+0]` with `ECX`=element, stack arg=`f32`. Float result
returns in `ST0` (both predicate call sites `FCOMP` it with no store between;
`de430` applies `FPATAN` to it — confirms `ST0` float discipline).

## 2. Observation: `FUN_004de2a0` selector (verbatim pseudocode + asm)

Pseudocode (verbatim, `ev_4f35bbfc...`):

```c
undefined4 FUN_004de2a0(undefined4 param_1)
{
  undefined4 *puVar1;
  undefined4 *puVar2;
  char cVar3;
  int in_ECX;
  int extraout_ECX;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
    in_ECX = extraout_ECX;
  }
  puVar1 = *(undefined4 **)(in_ECX + 8);
  for (puVar2 = (undefined4 *)*puVar1; puVar2 != puVar1; puVar2 = (undefined4 *)*puVar2) {
    cVar3 = FUN_00442f80(param_1);
    if (cVar3 != '\0') goto LAB_004de30b;
  }
  FUN_00406b90(&DAT_005d09d4,0);
  __CxxThrowException_8(local_28,&DAT_005e6210);
LAB_004de30b:
  return puVar2[2];
}
```

Key asm (verbatim excerpt):

```text
0x4de2cc: MOV EDI, dword ptr [ECX + 0x8]
0x4de2cf: MOV ESI, dword ptr [EDI]
0x4de2d1: CMP ESI, EDI
0x4de2d3: JZ 0x004de2ec
0x4de2d5: MOV EBX, dword ptr [ESP + 0x38]
0x4de2d9: MOV ECX, dword ptr [ESI + 0x8]
0x4de2dc: PUSH EBX
0x4de2dd: CALL 0x00442f80
0x4de2e2: TEST AL, AL
0x4de2e4: JNZ 0x004de30b
0x4de2e6: MOV ESI, dword ptr [ESI]
0x4de2e8: CMP ESI, EDI
0x4de2ea: JNZ 0x004de2d9
0x4de2ec: (throw path: 00406b90 + 0059ccce, same immediates)
0x4de30b: MOV EAX, dword ptr [ESI + 0x8]
```

Selection rule: intrusive list with sentinel `EDI=[strip+8]`, first node
`ESI=[EDI]`, next at `[node+0]`, loop while `ESI != EDI`. Each node tested
via `ECX=[node+8]`, `FUN_00442f80(arg)`; first hit wins, returns
`[node+8]` (the SAME pointer tested — `0x4de2d9` loads it, `0x4de30b`
returns it). Empty list or no hit → `00406b90` + `__CxxThrowException@8`
(never returns; NOT a default value).

## 3. Observation: `FUN_00442f80` predicate (verbatim asm, `ev_ff6c9550...`)

```text
0x442f80: FLD float ptr [ESP + 0x4]
0x442f84: FCOMP float ptr [ECX + 0x4]
0x442f87: FNSTSW AX
0x442f89: TEST AH, 0x1
0x442f8c: JNZ 0x00442fa4
0x442f8e: FLD float ptr [ESP + 0x4]
0x442f92: FCOMP float ptr [ECX + 0x8]
0x442f95: FNSTSW AX
0x442f97: TEST AH, 0x41
0x442f9a: JZ 0x00442fa4
0x442f9c: MOV EAX, 0x1
0x442fa1: RET 0x4
0x442fa4: XOR EAX, EAX
0x442fa6: RET 0x4
```

Gate 1 (`TEST AH,0x1`, C0 only, `JNZ fail`): `FLD p; FCOMP [ECX+4]` fails if
`p < lo` OR unordered → pass iff `p >= lo` ordered. NaN `p` or NaN `lo` → FAIL.
Gate 2 (`TEST AH,0x41`, C0|C3, `JZ fail`): `FLD p; FCOMP [ECX+8]` passes if
`p < hi`, `p == hi`, OR unordered → pass iff `!(p > hi)`. NaN `p` or NaN
`hi` → PASS (gate 1 already rejected NaN `p`, so net NaN `p` → 0; NaN `hi`
selects iff gate 1 passed).
INFERENCE (asm-exact, high confidence): element layout `+0`=vtable ptr,
`+4`=range lo, `+8`=range hi — `ECX` is the same `[node+8]` pointer the
predicate reads (`+4`/`+8`) and `de3e0` dereferences (`[EAX]`=vtable).
NOTE: decompiler pseudocode (`lo <= p && p <= hi`) is WRONG for NaN `hi`
(C++ `<=` is false on unordered; asm gate 2 passes unordered). Trust asm.

## 4. Observation: callers / callees / strings

- `FUN_004de3e0` callees (`ev_7bc6e3f1...`): `0x406b90`,
  `__CxxThrowException@8` (`0x59ccce`), `0x4de2a0`. Indirect target
  `CALL [EDX]` is runtime-resolved, not a static callee.
- `FUN_004de3e0` callers, 19 (`ev_65e2689c...`): `0x4348a0`, `0x434ff0`,
  `0x435140`, `0x4357a0`, `0x435810`, `0x438a80`, `0x439370`, `0x43a420`,
  `0x43bce0`, `0x43c120`, `0x43d230`, `0x43e4a0`, `0x43ecf0`, `0x440690`,
  `0x441f80`, `0x455ba0`, `0x457110`, `0x45b130`, `0x45dce0`. All pass a
  strip object as `ECX` with one `f32` stack arg (spot shape matches the
  `00434ff0`/`004357a0`/`00435810` sites already mapped; remaining 16
  call-site arg shapes unmapped — out of scope).
- `FUN_004de2a0` callers, exactly 4 (`ev_e4df3062...`): `0x4de3e0`
  (slot `[EDX+0]`), `0x4de480` (slot `[EDX+4]`), `0x4de430` (slot `[EDX+4]`
  + `FLD1; FPATAN`, i.e. `atan(y/1)`), `0x4de4d0` (slot `[EDX+8]`).
  So the element vtable has ≥3 slots; xform = slot 0.
- Referenced strings: none in any of the three bodies (observation: asm
  contains only immediates `0x0` / `0x5d09d4` / `0x5e6210` — data addresses,
  not string loads; same throw immediates as the `de320`/`de350` getters).

## 5. Candidates (inference, explicitly bounded)

Candidate slot-0 targets = first vtable entries of whatever element objects
get linked into `[strip+8]` lists at runtime. That set is NOT recoverable
from the dispatch bodies alone — no vtable addresses, constructors, or list
writers appear in them. Sibling-slot evidence bounds the shape (slots
`+0/+4/+8` all selected by the same predicate, so candidates share the
element class family), but no concrete target address is claimed.

## Unknowns

- U1 (open): concrete slot-0 target set — which vtables get linked into
  `[strip+8]` lists, who writes the list heads/nodes (constructors /
  registration unmapped). Closes U2 in `00434ff0_terrain_base.md`,
  `004357a0_predicates.md`, `004de320_getters.md` context.
- U2 (open): whether overlapping ranges can occur (first-hit-wins makes
  order load-bearing if they can); list order source = insertion order (U1).
- U3 (method): `ST0` extended-precision caveat — target returns `f32` in
  `ST0`, consumed directly by callers (`FCOMP`/`FPATAN` with no `FSTP`
  between); a Rust `f32` re-type is exact only if the target rounds to
  `f32` before return (unverified per target).
- U4 (carried): exact exception object (`DAT_005d09d4` payload,
  `DAT_005e6210` throw info) and catch-side handlers unmapped; same
  deliberate panic-stands-in convention as prior files if ever transcribed.
- U5 (minor): 16 of 19 `de3e0` call-site arg shapes unverified (only
  `00434ff0`/`004357a0`/`00435810` sites mapped).

## Recommended next target (ONE)

`FUN_004348a0` (terrain builder, 1866 B): map where it (or its callees)
builds the `[strip+8]` list heads and links element nodes — the single
upstream point that names concrete slot-0 candidate vtables and closes U1.
Do NOT chase individual vtable targets before the writer set is known.
