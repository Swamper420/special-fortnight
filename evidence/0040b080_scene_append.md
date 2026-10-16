# FUN_0040b080 — ordered scene-list insert (submit tail callee)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`. Parent:
`evidence/00409060_submit.md` §6/U1 (attach loop). Method: `analyze_function`
× 4 (`0040b080`, `0040b370`, `00408f10`, `0040b930`, `0040bd10` — five
dossiers, four callees) + `read_function_instructions` × 2 (`0040b080`,
`0040b370`, plus `00409060` tail window for the call site). No Rust
transcribed; no engine edits.

## 1. Claim

- `FUN_0040b080` (`0x40b080`–`0x40b144`, 197 B,
  `ev_84b6d250de84d775af5c120f7dd2a2801eb76d1058cf4a978e68ffee2ca77f5e`;
  instr `ev_8e22c8c5512267baaf161cd472c9d999114c685059d8a988335a330cb93f4ef4`)
  is an ORDERED insert into a comparator-governed container, not a plain
  tail append. Correction to parent §6 wording ("append"): submission order
  (snapshot loop) ≠ storage order (comparator decides position).
- `FUN_0040b370` (`0x40b370`–`0x40b3d2`, 99 B,
  `ev_6c9978a1e5e33d63d6b9afc23ff3fa83bc1a915cead556fd8722caa67d7fa5a8`;
  instr `ev_bd63ae26c71b7687ae376fa07bf53a513c712a95eb963da13892b06959be8034`)
  is a 0x10-node doubly-linked insert with refcounted payload
  (shape-proven from pseudocode + instruction scan below).
- Container node layout (observation): walked entries expose
  `[entry+0x0]` / `[entry+0x8]` links and `[entry+0xC]` key; insert node is
  `0x14` bytes with color-ish flag at `[+0x10]` (red-black fixup idiom,
  proof incomplete — Unknown U3).

## 2. Observation: FUN_0040b080 body

Pseudocode (verbatim, trimmed to structure):

```c
undefined4 * FUN_0040b080(undefined4 *param_1,undefined4 *param_2)
{
  ...
  puVar2 = *(undefined4 **)(in_ECX + 4);
  puVar3 = (undefined4 *)puVar2[1];
  if (puVar3 != DAT_0061b838) {
    do {
      puVar2 = puVar3;
      cVar1 = FUN_00408f10(*param_2,puVar2[3]);
      if (cVar1 == '\0') puVar3 = (undefined4 *)puVar2[2];
      else puVar3 = (undefined4 *)*puVar2;
    } while (puVar3 != DAT_0061b838);
  }
  if (*(char *)(in_ECX + 8) == '\0') {
    if (cVar1 != '\0') {
      if (puVar2 == (undefined4 *)**(int **)(in_ECX + 4)) { ...goto insert; }
      FUN_0040bd10();
    }
    cVar1 = FUN_00408f10(puVar2[3],*param_2);
    if (cVar1 == '\0') { *param_1 = puVar2; return param_1; }  // found: return existing
    ...insert...
  } else { ...insert... }
insert:
  puVar2 = (undefined4 *)FUN_0040b930(...);
  *param_1 = *puVar2;
  return param_1;
}
```

Assembly (key lines, verbatim):

```
0x40b087: MOV EBX,ECX                    // ECX = container (thiscall)
0x40b095: MOV EDI,[EBX+0x4]              // list/tree root holder
0x40b098: MOV ESI,[EDI+0x4]
0x40b09b: CMP ESI,ECX                    // ECX=[0x61b838] sentinel
0x40b09f: MOV EAX,[ESI+0xc]              // key at entry+0xC
0x40b0a2: MOV ECX,[EBP]                  // *param_2 (new node key ptr)
0x40b0a7: LEA ECX,[EBX+0x1]              // comparator obj = container+1
0x40b0ac: CALL 0x00408f10
0x40b0b5: MOV ESI,[ESI]                  // comparator true-branch link
0x40b0b9: MOV ESI,[ESI+0x8]              // comparator false-branch link
0x40b0c4: MOV CL,[EBX+0x8]               // mode flag
0x40b0f1: CALL 0x0040bd10                // unlink/advance path
0x40b105: CALL 0x00408f10                // second compare (reverse arg order)
0x40b118: CALL 0x0040b930                // ordered insert
0x40b12e: RET 0x8                        // 2 stack params (observation)
```

- Walk is comparator-steered (`00408f10` result picks `[ESI]` vs
  `[ESI+8]`), terminating at sentinel `DAT_0061b838` (observation).
- `[EBX+8] != 0` skips the find-or-unlink preamble and goes straight to
  `0040b930` insert (observation). `[EBX+8] == 0` path can return the
  EXISTING entry (`*param_1 = puVar2`, `0x40b131` block) without inserting
  (observation: dedup/find branch).
- `RET 0x8` proves 2 stack params (observation). `ECX` = container object;
  `LEA ECX,[EBX+1]` passes a sub-object at byte offset +1 to the comparator
  (observation; +1 semantics untraced — Unknown U1).
- Callers (1, from analysis): `00409060`. Callees (3): `00408f10`,
  `0040b930`, `0040bd10`. Strings: none (observation).

## 3. Observation: caller wiring in FUN_00409060 tail

Call-site window (`ev_8d2ec6097501a130e60fa507ffb63e8f1666eab69ee80f7750bb46cc4c5254f6`,
verbatim asm):

```
0x4092db: LEA EDI,[EBX+0x8]
0x4092de: ADD EBX,0x14
0x4092ea: PUSH 0xc
0x4092ec: CALL operator_new            // 0xC attach node
0x409353: MOV [ECX+0x8],ESI            // [node+8] = matrix object
0x40935e: MOV EAX,[EDX+0x1c]           // type tag from snapshot+0x1C
0x409361: MOV [ECX],EAX                // [node+0] = tag
0x40937b: MOV [EAX+0x4],ECX            // [node+4] = param_2 (gated)
0x409384: MOV [EDX+0x4],0x0            // [node+4] = 0 (else branch)
0x40938b: LEA EAX,[ESP+0x74]           // node-slot ptr
0x40938f: LEA ECX,[ESP+0x14]           // snapshot-iter ptr
0x409393: PUSH EAX
0x409394: PUSH ECX
0x409395: MOV ECX,[ESP+0x84]           // advanced EBX (stride base)
0x40939c: CALL 0x0040b080
0x4093b3: JNZ 0x004092ea               // per-snapshot loop
```

- 0xC node layout (observation): `[+0]` = tag (`[snap+0x1C]`),
  `[+4]` = `param_2`-or-0, `[+8]` = matrix object (`ESI`).
- Container base advances `0x14` per outer iteration (`ADD EBX,0x14`);
  `EDI = EBX+8` snapshot pre-loop (observation). Exact container array
  element semantics untraced (Unknown U1).
- Which pushed slot maps to `param_1` (out) vs `param_2` (key) follows the
  in-callee `EBP=[ESP+0x20]`/out-slot reads, but the cross-boundary slot
  naming is recorded as inference, not quoted proof (Unknown U4).

## 4. Observation: FUN_0040b370 — 0x10 link insert + refcount

Pseudocode (verbatim):

```c
undefined4 * FUN_0040b370(undefined4 *param_1,void *param_2,undefined4 *param_3)
{
  puVar4 = *(undefined4 **)((int)param_2 + 4);
  puVar2 = operator_new(0x10);
  ...
  *puVar2 = puVar3;                    // [+0] anchor (null-guarded)
  puVar2[1] = puVar4;                  // [+4] next (null-guarded)
  *(undefined4 **)((int)param_2 + 4) = puVar2;
  *(undefined4 **)puVar2[1] = puVar2;   // back-link
  if (puVar2 + 2 != (undefined4 *)0x0) {
    puVar2[2] = *param_3;              // [+8] payload key
    piVar1 = (int *)param_3[1];
    puVar2[3] = piVar1;                // [+0xC] payload ref
    if (piVar1 != (int *)0x0) *piVar1 = *piVar1 + 1;  // refcount INC
  }
  *(int *)(in_ECX + 8) = *(int *)(in_ECX + 8) + 1;   // owner count++
  *param_1 = puVar2;
  return param_1;
}
```

- `RET 0xc` proves 3 stack params (observation). `ECX` = owner (count at
  `[ECX+8]`, observation from `0x40b3be`–`0x40b3c4`: `INC ECX` /
  `MOV [EBX+8],ECX`).
- Doubly-linked insert at `[param_2+4]` head with null-guarded
  anchor/next + back-link store (observation). Payload words at
  `[+8]/[+0xC]` with conditional refcount increment (observation).
- Callers (4): `00409060`, `004093d0`, `0047dd30`, `0047e100`. Callees (1):
  `operator_new`. Strings: none (observation).
- Role in submit: the two pre-copy merge calls (`[EBX+0x28]`/`[EBX+0x34]`
  slots per parent §6) — merge VALUE semantics still untraced (Unknown U2
  carried over).

## 5. Observation: comparator + insert + unlink helpers

- `FUN_00408f10` (336 B,
  `ev_28e53070bfe440e49e694dee48343708e8dee4ce106d78781d5ca8953bc93cb7`):
  strict multi-key comparator returning 1/0 over getter pairs
  `00407200` → `004071f0` → `00435530`+`00435540`+`0059d435` →
  `00407210` → `00407220` → `00407230` → `00407240`
  (verbatim pseudocode chain; observation). No strings. Callers:
  `004093d0`, `0040b080`, `0040b930`. Key SEMANTICS unknown (Unknown U2).
- `FUN_0040b930` (623 B,
  `ev_911bed6e47231b1c4e8831438c4dea58efd6d7d26aa9db12bcb4134c2b82f407`):
  allocates `0x14` node (`operator_new(0x14)`), sets `[1]=param_3`,
  `[4]=0`, key-copies `param_4` via `FUN_00475330(piVar4+3, param_4)`
  (i.e. key at `+0xC`), `*(in_ECX+0xC)++`, comparator-gated link splice,
  then a color-flag (`[+0x10]` 1/0) fixup loop with rotations
  (red-black idiom — INFERENCE, proof incomplete, Unknown U3). Sole
  caller: `0040b080`. Callees: `00408f10`, `00475330`, `operator_new`.
  No strings.
- `FUN_0040bd10` (81 B,
  `ev_4ee8cf2386f8f54452de1c52a0c27895e9dbad71ea61b536538d404d04442df5`):
  unlink/iterator-advance over `*ECX` walking `[+8]` chains to sentinel
  `DAT_0061b838` (observation from pseudocode). Sole caller: `0040b080`.
  No callees, no strings.

## Unknowns

- U1 (open): container object layout. `ECX`/`EBX` base, `+1` comparator
  sub-object (`LEA ECX,[EBX+1]`), `[EBX+4]` root holder, `[EBX+8]` mode
  flag, `0x14` per-iteration stride (`ADD EBX,0x14`), snapshot compare
  `snap != [EBP+4]` — element type and which field is the tree root vs
  list head untraced. `0040b930` full splice/rotation proof needed.
- U2 (open): comparator key semantics. Getter chain (`00407200`,
  `004071f0`, `00435530/00435540`, `00407210/20407220/230/240`) return
  values and the `[entry+0xC]` vs `*param_2` key types untraced; the two
  `0040b370` merge-slot roles (`[EBX+0x28]`/`[EBX+0x34]`) still untraced
  from parent.
- U3 (open): `0040b930` balanced-tree proof. Color-flag/rotation blocks
  match red-black idiom by shape only (inference); no invariant proof,
  no height/balance verification.
- U4 (method): `0040b080` stack-slot → `param_1`/`param_2` role naming
  across the `00409060` call boundary recorded as inference; in-callee
  uses (`EBP=[ESP+0x20]` key reads, `[ESP+0x20]`/`[ESP+0x24]` out writes)
  are asm-observed but the cross-boundary label assignment needs a
  prologue-offset audit. Ghidra text/ordering assumed faithful.

## Recommendation: ONE next target

`FUN_0040b930` (623 B) — ordered-insert + fixup loop that owns the
container layout (U1) and tree-balance proof (U3). Directly closes the
scene-graph role. Not the comparator getters (key semantics second-order)
and not `0040b370` callers (larger, off-scope).
