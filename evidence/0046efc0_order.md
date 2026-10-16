# `FUN_0046efc0` operand order → composition-map U1 verdict

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2. Static only. No engine changes.
Parents: `evidence/00455ba0_composition_map.md` §2/§9-U1,
`evidence/0046efc0_multiply.md` §2, `engine/src/matrix.rs` `matrix_multiply` +
`multiply_yrot_order` test (lines 334-395; probe lines 355-358).
Fresh Evidence: analyze `ev_7789d9b928a2061554cda0c466334e3f078c1a0f60dff19ac2f191303801e9d9`
(`FUN_0046efc0`, 576 B `0x46efc0`–`0x46f1ff`, 219 insns);
instr `ev_ba3dbe082593dd364c43d139301103bd63d5df89124d90a08a4bcad056d07044`
(same body); call-site window instr
`ev_b6c83121d7aacb859dc888def7addd2d8ce672d623da471955ad3544649fe30c`
(`FUN_00455ba0`, 868 insns; §2 window `0x456000`–`0x456070` re-observed here).
Prior: `ev_0a37f00d21e1cb35dc310acf64b28af43a611a65b38ee33a146ec8cb3e70463e`
(multiply.md order proof; this dossier's pseudocode text identical term-for-term).

## 1. Pseudocode (verbatim, fresh `ev_7789...`; `in_ECX` = ECX object, `param_2` = pushed src; slot `n` at base `+0x4+4n`)

Signature: `undefined4 FUN_0046efc0(undefined4 param_1,int param_2)`; returns `param_1` (dest; tail `MOV EAX,ESI`).

Slot15 arg (computed FIRST) and slot0 arg:

```c
/* slot15 = row3(C).col3(P): */ *(float *)(param_2 + 0x34) * *(float *)(in_ECX + 0x40)  /* P[12]*C[15] */
  /* full sum: */ *(float *)(in_ECX + 0x34) * *(float *)(param_2 + 4)      /* C[12]*P[0]  — slot12 arg head */
                + *(float *)(param_2 + 0x24) * *(float *)(in_ECX + 0x3c)   /* P[8]*C[14] */
                + *(float *)(in_ECX + 0x38) * *(float *)(param_2 + 0x14)  /* C[13]*P[4] */
                + *(float *)(param_2 + 0x34) * *(float *)(in_ECX + 0x40); /* P[12]*C[15] — slot15 */
/* slot0 = row0(C).col0(P): */ *(float *)(param_2 + 0x14) * *(float *)(in_ECX + 8)    /* P[4]*C[1] */
             + *(float *)(param_2 + 0x24) * *(float *)(in_ECX + 0xc)  /* P[8]*C[2] */
             + *(float *)(param_2 + 0x34) * *(float *)(in_ECX + 0x10) /* P[12]*C[3] */
             + *(float *)(param_2 + 4) * *(float *)(in_ECX + 4);      /* P[0]*C[0] */
```

All 16 forwarded args follow `dest[i][j] = SUM_k C[i][k]*P[k][j]` (full 4635-char text in dossier; every term pairs one `in_ECX` word with one `param_2` word, ECX-words sharing row index `i`, param_2-words sharing column index `j`).

## 2. Deciding instruction sequence (verbatim, fresh `ev_ba3d...`; EAX = `param_2` src, ECX = `in_ECX`)

```
0x46efc0: PUSH ECX
0x46efc1: MOV EAX, dword ptr [ESP + 0xc]
0x46efc5: PUSH ESI
0x46efc6: PUSH ECX
0x46efc7: MOV dword ptr [ESP + 0x8], 0x0
0x46efcf: FLD float ptr [EAX + 0x30]    ; P slot11 (0x30-4)/4
0x46efd2: FMUL float ptr [ECX + 0x3c]   ; C slot14
0x46efd5: FLD float ptr [ECX + 0x38]    ; C slot13
0x46efd8: FMUL float ptr [EAX + 0x20]   ; P slot7
0x46efdb: FADDP
0x46efdd: FLD float ptr [ECX + 0x34]    ; C slot12
0x46efe0: FMUL float ptr [EAX + 0x10]   ; P slot3
0x46efe3: FADDP
0x46efe5: FLD float ptr [ECX + 0x40]    ; C slot15
0x46efe8: FMUL float ptr [EAX + 0x40]   ; P slot15
0x46efeb: FADDP
0x46efed: FSTP float ptr [ESP]          ; slot15 result pushed first
```

Reading: `slot15 = P[11]*C[14] + C[13]*P[7] + C[12]*P[3] + C[15]*P[15]` = `row3(C).col3(P)`.
Reverse reading (`P x C`) would need `P`-rows dotted with `C`-columns, i.e. head term `P[12]*C[0]`-family; observed head is `P[11]*C[14]` (C-row family). QED: **`dest = ECX x param_2`** (ECX LEFT).

## 3. Asymmetric probe (observation + inference, labeled)

- Observation (engine test lines 355-358, generated fixtures): `T x S` last row `[2,6,12]` (scaled translation), `S x T` last row `[1,2,3]` (unscaled).
- Observation (asm): dest last-row args are `row3(C).col j(P)` (slot12 arg head `C[12]*P[0] + P[8]*C[14] + C[13]*P[4] + P[12]*C[15]`, §1).
- Inference: with `C=T` (last row `[tx,ty,tz,1]`), `P=S` (`diag(sx,sy,sz,1)`), asm yields last row `[tx*sx, ty*sy, tz*sz, 1]` = `T x S` pattern `[2,6,12]`. Flipped reading would yield `[1,2,3]` for the same inputs. Asm matches ECX-left.
- Inference: engine `matrix_multiply(a,b)` computes `a[i][k]*b[k][j]` (matrix.rs lines 154-160), i.e. `a x b`; matches asm `C x P` with `a=ECX, b=param_2`.

## 4. Call sites (verbatim window, fresh `ev_b6c8...`; matches composition-map §2)

```
0x45602e: LEA EDX, [ESP + 0x120]   ; mul#1 dest
0x456035: PUSH EBP                 ; mul#1 src = S (EBP = 0046fa40 result per 0x45600f MOV EBP,EAX)
0x456036: PUSH EDX                ; dest param_1
0x456037: MOV ECX, EAX             ; ECX = R (EAX = 0046f910 result per 0x456026 CALL)
0x456041: CALL 0x0046efc0          ; mul#1: tmp = R x S, returned in EAX, stored [ESP+0x120]
0x456046: LEA ECX, [ESP + 0x54]    ; mul#2 dest
0x45604a: PUSH EBX                 ; mul#2 src = T (EBX = tree T buf per 0x455fec site)
0x45604b: PUSH ECX                ; dest param_1
0x45604c: MOV ECX, EAX             ; ECX = tmp (EAX = mul#1 dest)
0x456056: CALL 0x0046efc0          ; mul#2: final = tmp x T = (R x S) x T, stored [ESP+0x54]
```

Callers of `0046efc0` (14, fresh dossier): `0040a680, 0040d0f0, 00424610, 00455ba0, 00457110, 0045ad80, 0045af50, 0045b010, 0045dce0, 00461fc0, 004621e0, 00502340, 00502530, 00504540`. Strings: none. Sole callee: `0046ef20`.

## 5. Verdict (one line per site)

- mul#1 (`0x456041`): engine `matrix_multiply(R, S)` arg order CORRECT (`ECX=R` left, `param_2=S` right → `tmp = R x S`).
- mul#2 (`0x456056`): engine `matrix_multiply(tmp, T)` arg order CORRECT (`ECX=tmp` left, `param_2=T` right → `final = (R x S) x T`).

## 6. Unknowns

- U1 (this dossier's method ceiling): order proven from slot-index pairing in decompiler pseudocode + targeted asm window (slot15 computed first, tail `MOV ECX,ESI; CALL 0046ef20; RET 0x8`); no per-block audit of all 219 insns beyond cited slot0/slot12/slot15 args. Ghidra text assumed faithful.
- U2 (carried): x87 80-bit intermediates + per-slot accumulation order vary (multiply.md §2); Rust `f32` canonical `k=0..3` bit-exact only on exact inputs.
- U3 (carried, composition-map U1 now closed on order; remainder stays): row-vector reading (`v.M`, translation last row) is inference; tree-loop angle source `[ESP+0x44]` untraced; downstream frame use unchanged.
