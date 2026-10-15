# Consumer check: `FUN_00466a20` is wide-string assign plumbing, not a hill-strip combiner

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), Ghidra 12.1.2. Parent dossiers:
`evidence/00436620_composition.md` (U4),
`evidence/00436620_placement_recon.md` (recommends this target).

## 1. Claim

`FUN_00466a20` does NOT combine hill strips and does NO placement
transform. It is a thiscall wide-string assign to a string member at
`ECX+0xAC` (buffer `[+0xB0]`, length `[+0xB4]`, capacity `[+0xB8]`
relative to object base in `ECX`; code uses `EDI=ECX+0xAC`).
Body `0x466a20-0x466b47`, 296 bytes, 27 blocks, 119 instructions,
ZERO x87/SSE float ops. `FUN_00470db0` (second choice) is a 5-byte
tail-call wrapper over it — also plumbing.

No Rust code transcribed (per task: plumbing = evidence only).
`engine/src/mesh.rs` untouched.

## 2. Observation: pseudocode (full, Ghidra decompiler)

Evidence: `ev_91014c0159057779db0f771085dbb23fd175471ecb90bd40c592fa1181e86cd7`.

```c
void FUN_00466a20(ushort *param_1)
{
  char cVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int in_ECX;
  ushort *puVar6;
  ushort *puVar7;
  uint uVar8;

  uVar4 = FUN_0059ce28(param_1);
  uVar5 = *(uint *)(in_ECX + 0xb4);
  uVar8 = uVar5;
  if (uVar4 <= uVar5) {
    uVar8 = uVar4;
  }
  puVar6 = *(ushort **)(in_ECX + 0xb0);
  puVar7 = param_1;
  for (; uVar8 != 0; uVar8 = uVar8 - 1) {
    if (*puVar6 != *puVar7) {
      if ((-(uint)(*puVar6 < *puVar7) & 0xfffffffe) != 0xffffffff) goto LAB_00466a86;
      break;
    }
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  if ((uVar4 <= uVar5) && (uVar5 == uVar4)) {
    return;
  }
LAB_00466a86:
  uVar5 = FUN_0059ce28(param_1);
  if (0x7ffffffd < uVar5) {
    FUN_0059c12b();
  }
  iVar3 = *(int *)(in_ECX + 0xb0);
  if (((iVar3 == 0) || (cVar1 = *(char *)(iVar3 + -1), cVar1 == '\0')) || (cVar1 == -1)) {
    if (uVar5 == 0) {
      FUN_00402e80(1);
      FUN_004668f0();
      return;
    }
    if ((*(uint *)(in_ECX + 0xb8) < 0x20) && (uVar5 <= *(uint *)(in_ECX + 0xb8))) goto LAB_00466b11;
    FUN_00402e80(1);
  }
  else if (uVar5 == 0) {
    *(char *)(iVar3 + -1) = cVar1 + -1;
    FUN_00402e80(0);
    FUN_004668f0();
    return;
  }
  FUN_00403280(uVar5);
LAB_00466b11:
  puVar6 = *(ushort **)(in_ECX + 0xb0);
  for (uVar8 = uVar5; uVar8 != 0; uVar8 = uVar8 - 1) {
    uVar2 = *param_1;
    param_1 = param_1 + 1;
    *puVar6 = uVar2;
    puVar6 = puVar6 + 1;
  }
  *(uint *)(in_ECX + 0xb4) = uVar5;
  *(undefined2 *)(*(int *)(in_ECX + 0xb0) + uVar5 * 2) = 0;
  FUN_004668f0();
  return;
}
```

Reading (observation): early compare loop = equality/ordering check
against current buffer (early return when identical); then
length via `0059ce28`, clear via `00402e80`, realloc via `00403280`,
u16 copy loop + NUL terminator, tail `004668f0` notify. Shape =
assign-to-UnicodeString-member. Offsets below are relative to `ECX`
as passed at entry; disassembly shows `LEA EDI,[ECX+0xAC]` then
`[EDI+0x4]` buffer / `[EDI+0x8]` length / `[EDI+0xC]` capacity, i.e.
object+0xB0/0xB4/0xB8.

`FUN_00470db0` (observation, `ev_857c4515c9d8d4fcd98c287d8da6fe1789153da3a17ef281de423bd60954c9bf`):

```c
void FUN_00470db0(undefined4 param_1)
{
  FUN_00466a20(param_1);
  return;
}
```

5 instructions, 0 float ops (`ev_10a7293138c7ff4c457e2d22ee02496c84a2d7caa6ab0d497bdea0d5fb47f1b8`).

## 3. Observation: assembly (full, 119 insns)

Evidence: `ev_3c127da4ee298aec3ef8b022f1d18d4fac8da1778d5f7b89e4f5d7b65c9ffef0`.

```asm
0x466a20: PUSH ECX
0x466a21: PUSH EBX
0x466a22: PUSH EBP
0x466a23: MOV EBP, dword ptr [ESP + 0x10]
0x466a27: PUSH ESI
0x466a28: PUSH EDI
0x466a29: PUSH EBP
0x466a2a: MOV dword ptr [ESP + 0x14], ECX
0x466a2e: LEA EDI, [ECX + 0xac]
0x466a34: CALL 0x0059ce28
0x466a39: MOV EBX, dword ptr [EDI + 0x8]
0x466a3c: ADD ESP, 0x4
0x466a3f: CMP EBX, EAX
0x466a41: MOV ESI, EBX
0x466a43: JC 0x00466a47
0x466a45: MOV ESI, EAX
0x466a47: MOV ECX, dword ptr [EDI + 0x4]
0x466a4a: MOV EDX, EBP
0x466a4c: TEST ESI, ESI
0x466a4e: JBE 0x00466a73
0x466a50: MOV BP, word ptr [ECX]
0x466a53: CMP BP, word ptr [EDX]
0x466a56: JNZ 0x00466a63
0x466a58: ADD ECX, 0x2
0x466a5b: ADD EDX, 0x2
0x466a5e: DEC ESI
0x466a5f: JNZ 0x00466a50
0x466a61: JMP 0x00466a73
0x466a63: MOV CX, word ptr [ECX]
0x466a66: CMP CX, word ptr [EDX]
0x466a69: SBB ECX, ECX
0x466a6b: AND ECX, 0xfffffffe
0x466a6e: INC ECX
0x466a6f: TEST ECX, ECX
0x466a71: JNZ 0x00466a86
0x466a73: CMP EBX, EAX
0x466a75: JC 0x00466a86
0x466a77: XOR ECX, ECX
0x466a79: CMP EBX, EAX
0x466a7b: SETNZ CL
0x466a7e: TEST ECX, ECX
0x466a80: JZ 0x00466b40
0x466a86: MOV EBX, dword ptr [ESP + 0x18]
0x466a8a: PUSH EBX
0x466a8b: CALL 0x0059ce28
0x466a90: MOV ESI, EAX
0x466a92: ADD ESP, 0x4
0x466a95: CMP ESI, 0x7ffffffd
0x466a9b: JBE 0x00466aa2
0x466a9d: CALL 0x0059c12b
0x466aa2: MOV ECX, dword ptr [EDI + 0x4]
0x466aa5: TEST ECX, ECX
0x466aa7: JZ 0x00466ad6
0x466aa9: MOV AL, byte ptr [ECX + -0x1]
0x466aac: TEST AL, AL
0x466aae: JZ 0x00466ad6
0x466ab0: CMP AL, 0xff
0x466ab2: JZ 0x00466ad6
0x466ab4: TEST ESI, ESI
0x466ab6: JNZ 0x00466b09
0x466ab8: DEC AL
0x466aba: PUSH ESI
0x466abb: MOV byte ptr [ECX + -0x1], AL
0x466abe: MOV ECX, EDI
0x466ac0: CALL 0x00402e80
0x466ac5: MOV ECX, dword ptr [ESP + 0x10]
0x466ac9: CALL 0x004668f0
0x466ace: POP EDI
0x466acf: POP ESI
0x466ad0: POP EBP
0x466ad1: POP EBX
0x466ad2: POP ECX
0x466ad3: RET 0x4
0x466ad6: TEST ESI, ESI
0x466ad8: JNZ 0x00466af4
0x466ada: PUSH 0x1
0x466adc: MOV ECX, EDI
0x466ade: CALL 0x00402e80
0x466ae3: MOV ECX, dword ptr [ESP + 0x10]
0x466ae7: CALL 0x004668f0
0x466aec: POP EDI
0x466aed: POP ESI
0x466aee: POP EBP
0x466aef: POP EBX
0x466af0: POP ECX
0x466af1: RET 0x4
0x466af4: MOV EAX, dword ptr [EDI + 0xc]
0x466af7: CMP EAX, 0x1f
0x466afa: JA 0x00466b00
0x466afc: CMP EAX, ESI
0x466afe: JNC 0x00466b11
0x466b00: PUSH 0x1
0x466b02: MOV ECX, EDI
0x466b04: CALL 0x00402e80
0x466b09: PUSH ESI
0x466b0a: MOV ECX, EDI
0x466b0c: CALL 0x00403280
0x466b11: MOV EAX, dword ptr [EDI + 0x4]
0x466b14: MOV ECX, EBX
0x466b16: TEST ESI, ESI
0x466b18: JBE 0x00466b2b
0x466b1a: MOV EDX, ESI
0x466b1c: MOV BX, word ptr [ECX]
0x466b1f: ADD ECX, 0x2
0x466b22: MOV word ptr [EAX], BX
0x466b25: ADD EAX, 0x2
0x466b28: DEC EDX
0x466b29: JNZ 0x00466b1c
0x466b2b: MOV EDX, dword ptr [EDI + 0x4]
0x466b2e: MOV ECX, dword ptr [ESP + 0x10]
0x466b32: MOV dword ptr [EDI + 0x8], ESI
0x466b35: MOV word ptr [EDX + ESI*0x2], 0x0
0x466b3b: CALL 0x004668f0
0x466b40: POP EDI
0x466b41: POP ESI
0x466b42: POP EBP
0x466b43: POP EBX
0x466b44: POP ECX
0x466b45: RET 0x4
```

Float scan (observation): `read_function_instructions`
filtered for `FLD/FST/FMUL/FADD/FSUB/FDIV/FCOM/MULSS/ADDSS/SUBSS/
DIVSS/MOVSS/UCOMISS` over 119 insns = 0 hits
(`ev_af8fef7049d92222eaa85bc066731be0a3e8ce8c730abcf93b920cb7f9c2686c`).
Only word-size `MOV/CMP` + `SBB/AND/INC` compare idiom; widest
memory access is `dword ptr` for len/capacity and `word ptr`
for character copy (`0x466b1c-0x466b35`). No float constant,
no float callee in body.

## 4. Observation: callers / callees / strings

- Body/signature (`ev_88bdd8052590b528c5b7d66540811d6f811a0124ffb1fba53287d79fb29fbf4c`):
  `undefined FUN_00466a20()`, range `0x466a20-0x466b47`, 296 bytes,
  contiguous, 27 blocks (`ev_ca2b1de5e3fa544b4fd25f6fc55577f8c74a93edfd201a5eb1d264e5ce284c13`).
- Callees (5, `ev_58483cab92c29ac84f1e81316d3619d140930625955b57207b0d98aff45ccbe8`):
  `0x402e80 / 0x403280 / 0x4668f0 / 0x59c12b / 0x59ce28`.
  Roles (observation from own pseudocode dossiers):
  `0059ce28` = wide-string length (`ev_1821ccc52629feec655fb6a5e508b46b3e921236e26bb5ff57ad4bfa6b8569aa`);
  `00402e80` = string clear (zeroes +0x4/+0x8/+0xC,
  `ev_b27238e2b375f5de002a06c69dcc838251368e98066056307e7d507fb5a1f0bf`);
  `00403280` = grow/alloc (`operator_new`, small-string `0x1f`
  threshold, `ev_e1acb75796b6fe9935c5dae82f99d66acbd58990a5aaa261bf9b26227530228e`);
  `004668f0` = change-notify tail call (head shows virtual calls,
  `ev_edc9a88c40955d73abf922d216fca1c87574a4b41cdbfbaef8346c22a11997af`);
  `0059c12b` = length-error throw guard. None is a mesh builder
  (`00434020/00434390/004348a0` absent).
- Callers (65, `ev_9b715819fd12f45b7c147603b1668f9132eb681413a72b2475eb5dc011cb099e`):
  includes `0x4444a0` (the hill-load wrapper from the recon
  dossier) plus `0x41e770/0x44de90/0x4521a0/0x463840/0x463ef0/
  0x4649b0/0x46b170/0x470db0/0x474400/...` (65 total; generic
  string-setter fan-in, not hill-specific). `FUN_00470db0` is both
  caller (wrapper) and itself called from elsewhere.
- Outgoing refs (`ev_b426f3e94ed8d546b4577a39260bd7da786ec4aa7adcb1acb3be84bea08c6f71`):
  data READ/WRITE to stack slots + `UNCONDITIONAL_CALL` to
  `0x59ce28` at `0x466a34/0x466a8b`, internal conditional jumps,
  no data xref to hill slots `+0x50/+0x58/+0x60/+0x68`.
- Referenced strings: none in body (observation; string work is
  via buffer contents, and callees carry no hill-section names —
  contrast `hill/version/inrun/dhill/terrain` in `FUN_00436620`).

## 5. Inference

Generic wide-string property setter. The four `FUN_004444a0`
call sites (`0x4447b6/0x4447eb/0x444832/0x444859` per parent
dossier) therefore write text fields (names/paths), not mesh
frames. Placement is NOT here and NOT in `00470db0` either.

## 6. Recommendation

Per parent dossier: escalate to data-xref sweep for readers of
hill-object slots `+0x50/+0x58/+0x60/+0x68` (object created by
`FUN_00433a60`); render-side reader is where the 29 m anchor gap
must resolve. Do not spend further time on `00466a20/00470db0`.

## Unknowns

- U1 (open): which text field lives at object+0xAC (name? path?
  hill-tag?). Call-site buffers in `FUN_004444a0` not traced to
  their string sources; needs per-call-site `param_1` provenance.
- U2 (open): exact string class layout (small-string `0x1f`
  threshold and `-1` refcount/flag byte idiom at `[buf-1]`
  observed but not named; Borland/RTL flavor unconfirmed).
  No claim beyond offsets.
- U3 (open): `FUN_004668f0` notify target semantics (virtual
  calls incl. float getters in its head) untouched; irrelevant to
  placement but unmapped.
- U4 (carried): relative frame placement of
  b50/b58/b60/b68/terrain still unmapped (excluded now from
  `FUN_00436620`, its 6 caller wrappers, `00466a20`, `00470db0`).
- U5 (method): float scan covers x87 + basic SSE mnemonics over
  `read_function_instructions`; integer/DirectX-side transform
  inside callees excluded only by callee identity (string
  helpers), not by exhaustive callee-body scan.
