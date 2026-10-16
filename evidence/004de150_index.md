# Index insert `FUN_004de150` + key `FUN_00538460` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Parent context: `evidence/004ddae0_emit_check.md` §1 (every builder emit feeds
`de150(x, y)`). Scope here is strictly `de150` + key computation; the segment
builders, curve objects, and strip composition stay untouched.
`engine/src/fn_00538460.rs` transcribed (`key_build`/`key_copy` only);
`de150`/`def20`/`df1d0` are impure (heap alloc, tree mutation, C++ throw) and
stay evidence-only.

Evidence IDs (new, this task):

- `ev_4a972653aa3af3a10b000c0efd012078566df638345258f3bed487588c02e558`
  (`analyze_function FUN_004de150`: pseudocode + full asm + callers/callees;
  body `0x4de150-0x4de23e`, 239 bytes, contiguous).
- `ev_9bf4c9b621749c3e8d58c998b03c8b88a67aa5ae7c46432c2e208d8bd0817f2e`
  (`analyze_function FUN_00538460`: body `0x538460-0x538471`, 18 bytes).
- `ev_42c37f514ff27301c42f4f000d1ecb55a094c808365b79266bd9e0707097b82d`
  (`analyze_function FUN_004def20`: insert + rebalance; body
  `0x4def20-0x4df187`, 616 bytes; sole caller `0x4de150`).
- `ev_7680bea141a2c8b64ddc1809a51dd392a0d3bcadbee1aebe4118123ab5237f3b`
  (`analyze_function FUN_004df1d0`: hint-adjust helper; body
  `0x4df1d0-0x4df220`, 81 bytes; callers `0x4de150`, `0x4de6b0`).
- `ev_5185915dbb6526eb4471d4ebbaa92874ccaa051efdc452e5ab378ebd25aaecb6`
  (`analyze_function FUN_004df280`: key-store wrapper; calls `0x538480`).
- `ev_17dc5684df4322cb6bb5e1908841c9c5990036f8ccf17bc2b35f3263fb556803`
  (`analyze_function FUN_00538480`: 8-byte key copy; 7 insns).
- `ev_70978c7b1b48d528c7586e3a775b06402a9f6f28ccaaf5a1ddf4a6bc6e9eafeb`
  (`read_function_instructions FUN_004ddae0`, filtered: `de150` call site
  `0x4ddc6b-0x4ddc77` + arg shuffle).
- `ev_a89c16f9d3df125647730afb43bcdb4f7b447db5282a83bf32cf83dcd79aad09`
  (`read_function_instructions FUN_004dda60`, filtered: `de150` call site
  `0x4ddab2-0x4ddabe`).

Prior (cited): `ev_4a972653...` is the same dossier already referenced by
`evidence/004ddae0_emit_check.md` §1 (`de150` guard/tree summary) — re-read
here with full asm instead of the summary.

## 1. Observation: `FUN_004de150` assembly (verbatim, `ev_4a972653...`)

```text
0x4de150: SUB ESP, 0x30
0x4de153: PUSH EBX
0x4de154: PUSH EBP
0x4de155: MOV EBP, ECX
0x4de157: PUSH ESI
0x4de158: PUSH EDI
0x4de159: MOV AL, byte ptr [EBP + 0x30]
0x4de15c: TEST AL, AL
0x4de15e: JZ 0x004de17f
0x4de160: PUSH 0x0
0x4de162: PUSH 0x5d09d4
0x4de167: LEA ECX, [ESP + 0x20]
0x4de16b: CALL 0x00406b90
0x4de170: LEA EAX, [ESP + 0x18]
0x4de174: PUSH 0x5e6210
0x4de179: PUSH EAX
0x4de17a: CALL 0x0059ccce
0x4de17f: MOV ECX, dword ptr [ESP + 0x48]
0x4de183: MOV EDX, dword ptr [ESP + 0x44]
0x4de187: PUSH ECX
0x4de188: PUSH EDX
0x4de189: LEA ECX, [ESP + 0x18]
0x4de18d: CALL 0x00538460
0x4de192: MOV ECX, dword ptr [EBP + 0x14]
0x4de195: MOV EDX, dword ptr [0x0061bb58]
0x4de19b: ADD EBP, 0x10
0x4de19e: MOV EBX, EAX
0x4de1a0: MOV ESI, dword ptr [ECX + 0x4]
0x4de1a3: MOV EDI, ECX
0x4de1a5: CMP ESI, EDX
0x4de1a7: MOV AL, 0x1
0x4de1a9: JZ 0x004de1c8
0x4de1ab: FLD float ptr [EBX]
0x4de1ad: FCOMP float ptr [ESI + 0xc]
0x4de1b0: MOV EDI, ESI
0x4de1b2: FNSTSW AX
0x4de1b4: TEST AH, 0x1
0x4de1b7: JZ 0x004de1bf
0x4de1b9: MOV ESI, dword ptr [ESI]
0x4de1bb: MOV AL, 0x1
0x4de1bd: JMP 0x004de1c4
0x4de1bf: MOV ESI, dword ptr [ESI + 0x8]
0x4de1c2: XOR AL, AL
0x4de1c4: CMP ESI, EDX
0x4de1c6: JNZ 0x004de1ab
0x4de1c8: MOV DL, byte ptr [EBP + 0x8]
0x4de1cb: TEST DL, DL
0x4de1cd: JZ 0x004de1e8
0x4de1cf: PUSH EBX
0x4de1d0: PUSH EDI
0x4de1d1: LEA EAX, [ESP + 0x4c]
0x4de1d5: PUSH ESI
0x4de1d6: PUSH EAX
0x4de1d7: MOV ECX, EBP
0x4de1d9: CALL 0x004def20
0x4de1de: POP EDI
0x4de1df: POP ESI
0x4de1e0: POP EBP
0x4de1e1: POP EBX
0x4de1e2: ADD ESP, 0x30
0x4de1e5: RET 0x8
0x4de1e8: TEST AL, AL
0x4de1ea: MOV dword ptr [ESP + 0x48], EDI
0x4de1ee: JZ 0x004de216
0x4de1f0: CMP EDI, dword ptr [ECX]
0x4de1f2: JNZ 0x004de20d
0x4de1f4: PUSH EBX
0x4de1f5: PUSH EDI
0x4de1f6: LEA ECX, [ESP + 0x4c]
0x4de1fa: PUSH ESI
0x4de1fb: PUSH ECX
0x4de1fc: MOV ECX, EBP
0x4de1fe: CALL 0x004def20
0x4de203: POP EDI
0x4de204: POP ESI
0x4de205: POP EBP
0x4de206: POP EBX
0x4de207: ADD ESP, 0x30
0x4de20a: RET 0x8
0x4de20d: LEA ECX, [ESP + 0x48]
0x4de211: CALL 0x004df1d0
0x4de216: MOV EDX, dword ptr [ESP + 0x48]
0x4de21a: FLD float ptr [EDX + 0xc]
0x4de21d: FCOMP float ptr [EBX]
0x4de21f: FNSTSW AX
0x4de221: TEST AH, 0x1
0x4de224: JZ 0x004de235
0x4de226: PUSH EBX
0x4de227: PUSH EDI
0x4de228: LEA EAX, [ESP + 0x4c]
0x4de22c: PUSH ESI
0x4de22d: PUSH EAX
0x4de22e: MOV ECX, EBP
0x4de230: CALL 0x004def20
0x4de235: POP EDI
0x4de236: POP ESI
0x4de237: POP EBP
0x4de238: POP EBX
0x4de239: ADD ESP, 0x30
0x4de23c: RET 0x8
```

Pseudocode (verbatim, `ev_4a972653...`):

```c
void FUN_004de150(undefined4 param_1,int *param_2)
{
  int *piVar1;
  bool bVar2;
  int *piVar3;
  int *piVar4;
  float *pfVar5;
  int in_ECX;
  int *piVar6;
  undefined1 local_28 [40];

  if (*(char *)(in_ECX + 0x30) != '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
  }
  pfVar5 = (float *)FUN_00538460(param_1,param_2);
  piVar1 = *(int **)(in_ECX + 0x14);
  bVar2 = true;
  piVar3 = piVar1;
  piVar4 = (int *)piVar1[1];
  while (piVar4 != DAT_0061bb58) {
    if ((float)piVar4[3] <= *pfVar5) {
      piVar6 = (int *)piVar4[2];
    }
    else {
      piVar6 = (int *)*piVar4;
    }
    bVar2 = (float)piVar4[3] > *pfVar5;
    piVar3 = piVar4;
    piVar4 = piVar6;
  }
  if (*(char *)(in_ECX + 0x18) == '\0') {
    param_2 = piVar3;
    if (bVar2) {
      if (piVar3 == (int *)*piVar1) {
        FUN_004def20(&param_1,piVar4,piVar3,pfVar5);
        return;
      }
      FUN_004df1d0();
    }
    if ((float)param_2[3] < *pfVar5) {
      FUN_004def20(&param_1,piVar4,piVar3,pfVar5);
    }
    return;
  }
  FUN_004def20(&param_1,piVar4,piVar3,pfVar5);
  return;
}
```

Callers (observation, `ev_4a972653...`): `0x434390` (`FUN_00434390`
landing direct-insert loop), `0x4dda60`, `0x4ddae0`, `0x4ddcb0`,
`0x4ddf10`. Callees: `0x406b90`, `0x4def20`, `0x4df1d0`, `0x538460`,
`__CxxThrowException@8` (`0x59ccce`). Referenced strings: none in body
(throw payload is the `DAT_005d09d4` object address, same family as the
emit guards).

## 2. Observation: key computation `FUN_00538460` (verbatim, `ev_9bf4c9b6...`)

```text
0x538460: MOV EDX, dword ptr [ESP + 0x8]
0x538464: MOV EAX, ECX
0x538466: MOV ECX, dword ptr [ESP + 0x4]
0x53846a: MOV dword ptr [EAX], ECX
0x53846c: MOV dword ptr [EAX + 0x4], EDX
0x53846f: RET 0x8
```

Pseudocode (verbatim):

```c
void FUN_00538460(undefined4 param_1,undefined4 param_2)
{
  undefined4 *in_ECX;

  *in_ECX = param_1;
  in_ECX[1] = param_2;
  return;
}
```

No callees, no strings, 15 other callers (`0x43c120`, `0x45a7e0`,
`0x45dce0`, `0x4de5a0`, `0x4de6b0`, `0x4de7c0`, `0x4de7f0`, `0x4de8c0`,
`0x5384c0`, `0x538530`, `0x538560`, `0x538590`, `0x5385c0`, `0x5385f0`
besides `0x4de150`) — a shared 8-byte pair-store helper, not `de150`
specific.

Inference (proven by register tracing, pure fragment): `ECX` = out
pointer (returned in `EAX`: `de150` keeps it in `EBX` as `pfVar5`);
`[ESP+4]` = first stack arg → `[out+0]`; `[ESP+8]` = second stack arg →
`[out+4]`. Raw dword moves — bit copy, no float conversion, NaN passes
through. Zero side effects beyond the 8-byte store.

## 3. Observation: call sites prove key slot 0 = x

`FUN_004ddae0` tail (`ev_70978c7b...`):

```text
0x4ddc6b: MOV EAX, dword ptr [ESP + 0x4c]
0x4ddc6f: MOV ECX, dword ptr [ESP + 0x48]
0x4ddc73: PUSH EAX
0x4ddc74: PUSH ECX
0x4ddc75: MOV ECX, ESI
0x4ddc77: CALL 0x004de150
```

`[ESP+0x48]` is the same slot `FLD`/`FCOMP`-compared against cursor
`[ESI+0x20]` at `0x4ddb2e`/`0x4ddb67` (the emit x), so it is x;
`[ESP+0x4c]` is y. Last push = x = `de150` `param_1`.
Inside `de150`, `param_1` lands in the key buffer slot 0
(`[ESP+0x44]` → `FUN_00538460` `param_1` → `[EAX+0]`; traced in §2),
and the walk compares only `*pfVar5` = buffer slot 0 against
`node[3]` (`0x4de1ab-0x4de1ad`). Therefore the tree is keyed by x;
y rides along in slot 1 and is stored into the node (§5) but never
compared during descent.

`FUN_004dda60` (`ev_a89c16f9...`) uses the same shape
(`EAX=[ESP+0x30]`, `EDX=[ESP+0x34]`, `PUSH EDX/PUSH EAX`,
`param_1` = `[ESP+0x30]`), consistent with `(x, y)` order; the
`dda60` slot names are inherited from the caller convention, not
re-proven here.

## 4. Observation: tree walk shape (`0x4de192-0x4de1c6`)

- Header pointer: `[this+0x14]` (`0x4de192`); root = `[header+0x4]`
  (`0x4de1a0`); walk ends at sentinel `DAT_0061bb58` (`0x4de195`).
- Per node: `+0x0` = left child, `+0x8` = right child (observed branch
  targets: `MOV ESI,[ESI]` vs `MOV ESI,[ESI+0x8]`), `+0xc` (`node[3]`)
  = key x (compared field).
- Direction: `FLD [EBX]` (key x) / `FCOMP [ESI+0xc]` /
  `TEST AH,1` (x87 C0). `JZ` (C0=0: key >= nodekey, ordered) → right
  (`+0x8`, `AL=0`); else (key < nodekey OR unordered/NaN) → left
  (`+0x0`, `AL=1`). Equal keys go right. NaN key always goes left
  (unordered sets C0) — observation from the opcode, not a replay
  (binary never executed per workflow rules).
- `EDI` tracks the parent (last non-sentinel node; header itself when
  the tree is empty), `AL` tracks the last direction
  (`1` = left-or-empty, `0` = right).

## 5. Observation: insert dispatch on `[this+0x18]` (`0x4de1c8-0x4de235`)

`EBP` was bumped by `0x10` (`0x4de19b`), so `[EBP+0x8]` =
`[this+0x18]`:

- Nonzero → unconditional `FUN_004def20(&args, parent=EDI,
  nil=ESI, key=EBX)` with `ECX=this+0x10` (`0x4de1cf-0x4de1d9`).
- Zero → dedup path:
  1. `AL!=0` (last step left, or empty tree): if parent == header's
     leftmost/begin (`CMP EDI,[ECX]`, `ECX` still the header) →
     `def20`; else `FUN_004df1d0` over the parent slot
     (`LEA ECX,[ESP+0x48]; CALL`, parent was stored there at
     `0x4de1ea`), then fall through to step 2.
  2. `AL==0` skips step 1. Then: if `parent[3] < key`
     (`FLD [EDX+0xc]` / `FCOMP [EBX]` / `TEST AH,1` / `JNZ→def20`,
     `0x4de216-0x4de224`) → `def20`; else return without inserting
     (duplicate-x drop, same shape as the emit equal-x drop).

Inference: `[this+0x18]!=0` = multi-insert mode (every emit inserts,
duplicates allowed); `==0` = unique-insert mode (equal-x suppressed).
The exact flag writer is unmapped (Unknowns U2). The branch structure
above is observation; the "multi vs unique" naming is inference from
that structure.

## 6. Observation: node insert `FUN_004def20` (dossier `ev_42c37f51...`)

- `operator_new(0x18)` node; `node[1]=parent`,
  `*node=node[2]=DAT_0061bb58` (both children nil), `node[5]=0`.
- `FUN_004df280(node+3, keyptr)` (`ev_5185915d...`) forwards to
  `FUN_00538480` (`ev_17dc5684...`), which copies 8 bytes verbatim:

```text
0x538480: MOV EAX, ECX
0x538482: MOV ECX, dword ptr [ESP + 0x4]
0x538486: MOV EDX, dword ptr [ECX]
0x538488: MOV dword ptr [EAX], EDX
0x53848a: MOV ECX, dword ptr [ECX + 0x4]
0x53848d: MOV dword ptr [EAX + 0x4], ECX
0x538490: RET 0x4
```

  i.e. `node[3]=key.x`, `node[4]=key.y` (both f32 bit patterns).
- Remainder of `def20` (after the link-in at `0x4def6d-0x4defb1`,
  `[this+0xc]++` count): color flips + rotations keyed on
  `node[5]` (`!=0 break`, `+0x14` flag words) — red-black rebalance
  shape (inference; full rotation mapping out of scope, U4).
- Sole caller is `0x4de150`; callees `0x4df280`, `operator_new`.
- `FUN_004df1d0` (`ev_7680bea1...`, 81 bytes, no callees) rewrites
  `*ECX` (the parent slot) by walking `+0x0`/`+0x8` links against the
  same sentinel — hint-adjust before the step-2 compare. Exact STL
  role (increment/lower-bound detail) unmapped (U3).

Full node layout (observed): `0x18` bytes —
`[+0x0]` left, `[+0x4]` parent, `[+0x8]` right, `[+0xc]` key.x,
`[+0x10]` key.y, `[+0x14]` color/flag. Link fields from `def20`
stores + `df1d0` walks; key slots from the `538480` copy;
`+0x14` role from rebalance flag traffic (exact values open, U4).

## 7. Transcription

`engine/src/fn_00538460.rs`: `key_build(x_bits, y_bits)` =
`FUN_00538460` (buffer slot order `[x, y]`, returns pair) and
`key_copy(dst, src)` = `FUN_00538480` (8-byte verbatim copy). Both are
call-free straight-line dword moves — the only fragments in this scope
proven pure. `de150` (throw + tree walk + conditional `def20`/`df1d0`
mutation), `def20` (`operator_new` + rebalance stores), and `df1d0`
(tree-link rewrite) stay evidence-only. One test `key_pair_roundtrip`
over generated fixtures (incl. NaN bit patterns, which the `MOV`
semantics preserve).

## Unknowns

- U1: `[this+0x18]` writer/meaning beyond §5 inference (who sets
  multi vs unique per builder; landing vs inrun values unmapped).
- U2: header object at `[this+0x14]` full layout (`[header+0x0]` read
  as begin/leftmost at `0x4de1f0`, `[header+0x4]` root, `+0x8`/`+0xc`
  traffic inside `def20`/`df1d0` unmapped).
- U3: `FUN_004df1d0` exact role (hint increment vs lower-bound step —
  body walks both `+0x0` and `+0x8` links; not matched to an STL
  primitive).
- U4: `FUN_004def20` rebalance after `0x4defb1` (color values at
  `node[5]`/`+0x14`, rotation sequence) — plausibly red-black
  (inference only), unmapped instruction-by-instruction.
- U5: float compare exactness: x87 80-bit `FCOMP` vs f32 compare —
  same boundary caveat as `004ddae0_emit_check.md` U4; near-equal x
  values could diverge at the equal-goes-right boundary.
- U6: duplicate-x records in multi mode (`[+0x18]!=0`): payload beyond
  the key (does the consumer read `node[4]`=y, or something else at the
  call site?) unmapped — consumer side untouched.
- U7: `FUN_00406b90` exception-object role and `DAT_005d09d4` /
  `DAT_005e6210` / `DAT_0061bb58` values — cited, not examined.
