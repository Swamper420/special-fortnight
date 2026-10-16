# Rotation writer `FUN_0046fa90` — row-major disambiguation (closes `0046f9f0_matrix.md` U2)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`.
Parent: `evidence/0046f9f0_matrix.md` §5/U2 (translation+scale are
transpose-symmetric; only off-diagonal nonzeros disambiguate).

## 1. Claim

- `FUN_0046fa90` is a quaternion-to-rotation composer: `ECX` = dest object,
  stack `float[4] (x,y,z,w)`; forwards a 16-word rotation matrix to
  `FUN_0046ef20`; returns dest.
- Slot assignment matches **row-major** (D3D `D3DMATRIX` convention):
  off-diagonal transpose pair slots 1/4 carry `+wz`/`-wz` respectively.
  A column-major reading would swap them. U2 closed: **row-major**.
- Sibling `FUN_0046fba0` is the identity composer (all-diagonal 1.0).
  `FUN_0046fbf0` is NOT a rotation writer (outer-product form, see §4).

## 2. Observation: `FUN_0046fa90` (263 B, `0x46fa90`–`0x46fb96`)

Evidence: `ev_32ec9bd707265a141b3d51c4aad917023e6427dddf5ecc686598118ad4709af9`
(`analyze_function`); raw instructions:
`ev_f54d1627955f588d0c788f13c53911f6724d4780a2c1a634e776cc1860c66a44`
(`read_function_instructions`, 98 insns).

Pseudocode (verbatim):

```c
undefined4 FUN_0046fa90(undefined4 param_1,float *param_2)
{
  fVar1 = param_2[3] * param_2[3];          // w*w
  fVar3 = *param_2 * *param_2;              // x*x
  fVar2 = fVar1 - fVar3;                    // w*w - x*x
  fVar4 = param_2[1] * param_2[1];          // y*y
  fVar5 = param_2[2] * param_2[2];          // z*z
  fVar7 = param_2[2]*param_2[1] - *param_2*param_2[3];  // zy - xw
  fVar8 = param_2[2]**param_2 + param_2[1]*param_2[3];  // zx + yw
  fVar6 = *param_2*param_2[3] + param_2[2]*param_2[1];   // xw + zy
  fVar9 = param_2[1]**param_2 - param_2[2]*param_2[3];   // yx - zw
  fVar10 = param_2[2]**param_2 - param_2[1]*param_2[3];  // zx - yw
  fVar11 = param_2[2]*param_2[3] + param_2[1]**param_2;  // zw + yx
  FUN_0046ef20(((fVar3+fVar1)-fVar4)-fVar5, fVar11+fVar11, fVar10+fVar10, 0,
               fVar9+fVar9, (fVar4+fVar2)-fVar5, fVar6+fVar6, 0,
               fVar8+fVar8, fVar7+fVar7, (fVar2-fVar4)+fVar5, 0,
               0, 0, 0, 0x3f800000);
  return param_1;
}
```

Input convention (observed): `param_2[0]=x, [1]=y, [2]=z, [3]=w`
(asm reads `[EAX+0x0,0x4,0x8,0xc]`; `0x46faa5`–`0x46fb03`).
x87 FPU throughout (`FLD/FMUL/FSUB/FADD/FSTP/FADDP`); tail
`0x46fb62 MOV ESI,[ESP+0x54]` = dest, `0x46fb7a MOV ECX,ESI`,
`0x46fb8b CALL 0x0046ef20`, `MOV EAX,ESI` return (same frame as siblings).
Slots 3,7,11,12,13,14 pushed as `0`; slot 15 pushed as `0x3f800000` (1.0).

Linear slot formulas (0-based, `q=(x,y,z,w)`):

| slot | value | standard term |
|---|---|---|
| 0 | `(x²+w²)−y²−z²` | `1−2(y²+z²)` |
| 1 | `2(yx+zw)` | `m01 = 2(xy+wz)` |
| 2 | `2(zx−yw)` | `m02 = 2(xz−wy)` |
| 4 | `2(yx−zw)` | `m10 = 2(xy−wz)` |
| 5 | `(y²+(w²−x²))−z²` | `1−2(x²+z²)` |
| 6 | `2(xw+zy)` | `m12 = 2(yz+wx)` |
| 8 | `2(zx+yw)` | `m20 = 2(xz+wy)` |
| 9 | `2(zy−xw)` | `m21 = 2(yz−wx)` |
| 10 | `((w²−x²)−y²)+z²` | `1−2(x²+y²)` |

Callers (2): `00502220`, `00502340`. Callee: `0046ef20` only.
Strings: none. Names: `FUN_0046ef20 @ 0x46fb8b` only.

## 3. Inference: layout decided (row-major)

Observed (firm): slot pairs `(1,4) = (2(yx+zw), 2(yx−zw))`,
`(2,8) = (2(zx−yw), 2(zx+yw))`, `(6,9) = (2(xw+zy), 2(zy−xw))` —
each transpose pair differs in exactly one sign. A transposed
(column-major) reading would put `2(xy−wz)` in slot 1; the binary puts
`2(xy+wz)` there. Matches textbook row-major quaternion matrix
(`m00 = 1−2(yy+zz)`, `m01 = 2(xy+wz)`, `m02 = 2(xz−wy)`, …) verbatim.
No trig inside: quaternion arrives pre-formed; sin/cos live upstream
(`004df660`, see Unknowns). No normalization inside: raw polynomial
of the input words (caller responsibility).

Spot check (inference, verified by unit test): `q=(0,s,0,c)`,
`s=c=√2/2` → slots `[0,0,−2sc,0, 0,1,0,0, 2sc,0,0,0, 0,0,0,1]`,
i.e. ±90° rotation about Y with `slot2 = −slot8 ≠ 0`. Transpose would
flip that sign pair; observed order is row-major.

## 4. Siblings (firm, one-line each)

- `FUN_0046fba0` (26 B): identity composer —
  `FUN_0046ef20(1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1)`.
  Evidence: `ev_307834669a073a12c669a0bedf0f8bf9107fe8dd412127aa20ed7fe4579d05e5`.
  Callers: `004089a0`, `00409060`, `004ff980`.
- `FUN_0046fbf0` (122 insns): NOT rotation — outer-product form
  `(fVar1 − p_i·p_j)` diagonal with `−(p_i·p_j)` off-diagonals, plus
  `SQRT`-norm calls (`00538b60`) and `004df630` dot-product helper.
  Evidence: `ev_489f29f15e6b91f5952ad5b5d8d8cc4816525a4035d9643fd1c3c862404cd713`.
  Caller: `00458160` only. Semantics untraced; out of scope.
- Caller `FUN_00502220`: builds quaternion via `FUN_004df660(local,0,0,0)`,
  stores at `[ECX+0x144..0x150]`, calls `0046fa90`, copies 16 result words
  to `[ECX+0x104..0x140]`, then `0046efa0`.
  Evidence: `ev_3acf2b4c6377730ac3802ea11fd7d5ac8a7c526b1e85e3e6f1d6f5e0b49f3fd5`.

## 5. Transcription (`engine/src/matrix.rs`)

- `rotation_from_quaternion(x,y,z,w)`: slot formulas §2 with the same
  association order as the pseudocode (`((x²+w²)−y²)−z²`,
  `(zw+yx)+(zw+yx)`, …). No normalization (none observed).
- Precision note: original evaluates on x87 (80-bit intermediate);
  Rust `f32` rounds per-op. Bit-exactness holds for exact inputs
  (identity, axis-aligned); general inputs may differ ≤1 ulp per slot.
- Test: identity-quaternion bit-exact + Y-90° sign-pair asymmetry
  (`slot2 == −slot8 ≠ 0`, `slot0/slot10 ≈ 0`, diagonal `slot5 == 1`).

## Unknowns

- U1 (next, single): `FUN_004df660` quaternion composer — likely
  axis-angle→quaternion (expected sin/cos site feeding `0046fa90`
  via `00502220`). Unanalyzed; confirms where trig lives and whether
  inputs are unit-normalized at the source.
- U2 (carried): x87-vs-SSE rounding — transcription matches association,
  not intermediate precision; recorded in doc comment, not modeled.
- U3 (carried, parent U3): downstream `T*S*R` multiply site still unmapped;
  layout now fixed row-major, so the multiply search has its ground truth.
