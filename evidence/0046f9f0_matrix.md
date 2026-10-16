# Matrix composers `FUN_0046f9f0` / `FUN_0046fa40` over 4x4 ctor `FUN_0046ef20`

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`.
Parent: `evidence/00455ba0_render_assets.md` §§4–5 (per-object world-frame
placement from strip-derived scalars; corrects placement-recon U4 for scenery).
Method: `analyze_function` × 3 (snapshot-backed dossiers). No mesh.rs edits.

## 1. Claim

- `FUN_0046ef20` is a 16-dword matrix-object ctor: stores 16 stack dwords
  verbatim at `[ECX+0x4..ECX+0x40]`, writes vtable `0x5cf270` at `[ECX]`,
  callee-cleans `0x40`, returns nothing. Pure word-copy; no arithmetic.
- `FUN_0046f9f0` is a translation-matrix composer: `ECX` = dest object,
  3 stack floats `(tx,ty,tz)`; forwards
  `(1,0,0,0, 0,1,0,0, 0,0,1,0, tx,ty,tz, 1)` to `0046ef20`; returns dest.
- `FUN_0046fa40` is a scale-matrix composer: `ECX` = dest object,
  3 stack floats `(sx,sy,sz)`; forwards
  `(sx,0,0,0, 0,sy,0,0, 0,0,sz,0, 0,0,0, 1)` to `0046ef20`; returns dest.
- No multiply/compose-order inside these three: each builds ONE matrix.
  `00455ba0` submits translation and scale buffers as separate
  `00409060` args (tree loop `0x4560bd`); any `T*S` product (if any)
  happens downstream, not here.

## 2. Observation: `FUN_0046ef20` (123 B, `0x46ef20`–`0x46ef9a`)

Evidence: `ev_6bbc77cfa05bdefe606e31b61bfd0a798ff4389e3f8968fe9bd1ac1a69033f7c`.

Pseudocode (verbatim):

```c
void FUN_0046ef20(p1..p16) {
  in_ECX[1]=p1;  in_ECX[2]=p2;  in_ECX[3]=p3;  in_ECX[4]=p4;
  in_ECX[5]=p5;  in_ECX[6]=p6;  in_ECX[7]=p7;  in_ECX[8]=p8;
  in_ECX[9]=p9;  in_ECX[10]=p10; in_ECX[0xb]=p11; in_ECX[0xc]=p12;
  in_ECX[0xd]=p13; in_ECX[0xe]=p14;
  *in_ECX = &PTR_FUN_005cf270;
  in_ECX[0xf]=p15; in_ECX[0x10]=p16;
}
```

Assembly (verbatim, 33 insns): `MOV EDX,[ESP+0x8]; MOV EAX,ECX;
MOV ECX,[ESP+0x4]; MOV [EAX+0x4],ECX; MOV ECX,[ESP+0xc]; MOV [EAX+0x8],EDX;
MOV EDX,[ESP+0x10]; MOV [EAX+0xc],ECX; ...` — alternating
`ECX`/`EDX` scratch, sequential stores `[EAX+0x4]` … `[EAX+0x40]`
(`p1`→`+0x4`, …, `p16`→`+0x40`), then `MOV [EAX],0x5cf270`,
`RET 0x40` (callee cleans 16 dwords; thiscall, `ECX`/`EAX` = this).

Exact element writes (offset ← stack slot):

| offset | +0x4 | +0x8 | +0xc | +0x10 | +0x14 | +0x18 | +0x1c | +0x20 |
|---|---|---|---|---|---|---|---|
| stack | +0x4 | +0x8 | +0xc | +0x10 | +0x14 | +0x18 | +0x1c | +0x20 |

| offset | +0x24 | +0x28 | +0x2c | +0x30 | +0x34 | +0x38 | +0x3c | +0x40 |
|---|---|---|---|---|---|---|---|
| stack | +0x24 | +0x28 | +0x2c | +0x30 | +0x34 | +0x38 | +0x3c | +0x40 |

plus `[ECX+0x0]` ← `0x5cf270`. Object size `0x44` (68 B).
Callers (16, sampled): `0040cca0`, `0040cf10`, `00424610`, `0046efc0`,
`0046f200`, `0046f8a0`, `0046f910`, `0046f980`, `0046f9f0`, `0046fa40`,
`0046fa90`, `0046fba0`, `0046fbf0`, `004f26f0`, `00501ed0`, `0053c100`.
Callees: none. Referenced strings: none.
Referenced names: `PTR_FUN_005cf270` @ `0x46ef8c`. Single block, no branches.

## 3. Observation: `FUN_0046f9f0` (79 B, `0x46f9f0`–`0x46fa3e`)

Evidence: `ev_6d6c49c17f2160c988dbc3a2d32eeb384d0f1c8397353d156c3d1ef30aad42ba`.

Pseudocode (verbatim):

```c
undefined4 FUN_0046f9f0(p1,p2,p3,p4) {
  FUN_0046ef20(0x3f800000,0,0,0, 0,0x3f800000,0,0,
               0,0,0x3f800000,0, p2,p3,p4,0x3f800000);
  return p1;
}
```

(`0x3f800000` = 1.0f bits; `p1` = spilled `ECX`/dest, `p2..p4` =
stack `(tx,ty,tz)` — read asm: `EDX=[ESP+0xc]`, `ECX=[ESP+0x10]`,
`EAX=[ESP+0x14]` after `PUSH ECX`; `ESI=[ESP+0x24]` = dest;
`MOV ECX,ESI` before `CALL 0x0046ef20`; `MOV EAX,ESI` return.)
Push order (asm `0x46f9fd`–`0x46fa2b`): `1.0, tz, ty, tx, 0, 1.0,
0,0,0,0, 1.0, 0,0,0,0, 1.0` with `MOV [ESP+0x44],0` slot-fill
before CALL. Linear matrix (params 1–16):

```text
1,0,0,0,  0,1,0,0,  0,0,1,0,  tx,ty,tz,1
```

Callers: `00424610`, `00455ba0`, `0045ad80`, `0045dce0`, `00504540`.
Callee: `0046ef20` only. Strings: none. Single block.

## 4. Observation: `FUN_0046fa40` (70 B, `0x46fa40`–`0x46fa85`)

Evidence: `ev_116fab1840f10fd9ff7353e31d54f234925ddd879d99d0434a58f8c168f602a7`.

Pseudocode (verbatim):

```c
undefined4 FUN_0046fa40(p1,p2,p3,p4) {
  FUN_0046ef20(p2,0,0,0, 0,p3,0,0, 0,0,p4,0, 0,0,0,0x3f800000);
  return p1;
}
```

(`p2..p4` = stack `(sx,sy,sz)`, passed verbatim as diagonal words;
same `PUSH ECX/PUSH ESI` frame, `MOV ECX,ESI; MOV [ESP+0x44],0;
CALL 0x0046ef20; MOV EAX,ESI`.) Linear matrix:

```text
sx,0,0,0,  0,sy,0,0,  0,0,sz,0,  0,0,0,1
```

Caller: `00455ba0` only (tree-loop scale path `0x4560bd`).
Callee: `0046ef20` only. Strings: none. Single block.

## 5. Inference: layout (row- vs column-major)

Observed (firm): linear word order above; translation occupies linear
slots 12,13,14 (0-based) at object offsets `+0x34,+0x38,+0x3c`;
all constants bit-exact (`1.0` = `0x3f800000`, `0` = `0x0`).
Inference (not decided by these three): row-major reading = last-row
translation (`_41,_42,_43`, D3D `D3DMATRIX` convention); column-major
reading = last-column translation (transpose). Diagonal + translation
matrices are transpose-symmetric in shape, so rotation-free scenery
frames cannot disambiguate. Row-major assumed for docs (DirectX game);
Rust transcription keeps neutral linear `[f32; 16]` order, so the
assumption affects naming only, not bits.

## 6. Transcription (`engine/src/matrix.rs`, `pub mod matrix`)

- `fn_0046ef20([f32;16]) -> [f32;16]`: verbatim 16-word store
  (vtable/`ECX`/object layout not modeled in portable core — no
  allocation there by design; offsets documented in doc comment).
- `translation(tx,ty,tz)`, `scale(sx,sy,sz)`: exact push-order words.
- Scalars pass through as raw `f32` (no conversion in asm — observation).
- One test: bit-exact (`to_bits`) translation/scale/ctor vectors.

## Unknowns

- U1 (open): `[ESP+0x44] ← 0` dword before CALL in both composers
  (`0x46fa2d`, `0x46fa74`) — spill-slot zeroing or stale local?
  Decompiler shows `local_4 @ Stack[-0x4]` (`PUSH ECX`). Purpose untraced;
  not modeled (stack frame, no semantic effect on matrix words).
- U2 (open): row- vs column-major (§5) — needs a rotation writer or
  downstream multiply (`0046fa90` 263 B? `0046fbf0`? `00423a20` copy
  order?) — explicitly out of scope for this task.
- U3 (open): whether `00455ba0` tree loop multiplies `T*S` downstream
  or submits both frames independently to `00409060` — `00409060`
  internals unmapped (parent U1). Placement-recon U4 closed only for
  per-object frame *construction*, not submission order.
- U4 (method): parent `00455ba0` dossier cites truncated stub IDs
  (`ev_76dee726...`, `ev_60348d98...`, `ev_3ff5fe4d...`); full fresh
  IDs in §§2–4 supersede them for these three functions.
- U5 (carried): vtable `0x5cf270` target semantics, object size `0x44`
  vs `operator_new(0xb8)` scene-node size at `00455ba0` — different
  objects (matrix `0x44` vs node `0xb8`); node copy order in `00423a20`
  untraced.
