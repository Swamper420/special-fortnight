# Matrix multiply `FUN_0046efc0` + Y-rotation `FUN_0046f910` over ctor `FUN_0046ef20`

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`.
Parent: `evidence/00409060_submit.md` §4 (tree loop composes via `0046f910`
+ `0046efc0` × 2, submits one buffer). Closes submit-doc U3 (operand order).
Method: `analyze_function` × 2 (snapshot-backed dossiers). No mesh.rs edits.

## 1. Claim

- `FUN_0046efc0` is a 4x4 matrix MULTIPLY: thiscall-ish, `ECX` = left-operand
  object, stack `(param_1 = dest, param_2 = right-operand)`, `RET 0x8`,
  returns dest. Product order is **`dest = ECX × param_2`** (ECX left;
  proven §2, load-bearing for row-major). Forwards 16 sums to `0046ef20`.
- `FUN_0046f910` is a Y-rotation composer: `ECX` = dest object, one stack
  float (angle, radians for x87 `FCOS`/`FSIN`), forwards
  `(cos,0,sin,0, 0,1,0,0, -sin,0,cos,0, 0,0,0,1)` to `0046ef20`,
  returns dest. Sign layout is OBSERVED (slot2 `+sin`, slot8 `−sin`).
- Tree-loop net effect (§4 of parent): `tmp = R×S`, then
  `final = tmp×T`, i.e. `(R×S)×T`. Under row-vector reading
  (`v·M`, translation in last row) the object transform applies R, then S,
  then T — standard rotate→scale→translate order (inference from order proof
  + row-vector layout; angle source `[ESP+0x44]` still untraced).

## 2. Observation: `FUN_0046efc0` operand order (576 B, `0x46efc0`–`0x46f1ff`)

Evidence: `ev_0a37f00d21e1cb35dc310acf64b28af43a611a65b38ee33a146ec8cb3e70463e`
(supersedes submit-doc `ev_7789d9b928a2061554cda0c466334e3f078c1a0f60dff19ac2f191303801e9d9`).

Calling-shape proof (asm-observed, 219 insns, 18 × `PUSH ECX`):

- Entry `PUSH ECX` (saved `in_ECX`); `0x46efc1: MOV EAX,[ESP+0xc]`
  (= caller `[ESP+0x8]` = `param_2`, right operand).
- `0x46f173: MOV ESI,[ESP+0x40]` at 15 pushes outstanding (`0x3c` B) lands on
  caller `[ESP+0x4]` = `param_1` = dest. Tail `MOV ECX,ESI; CALL 0046ef20;
  MOV EAX,ESI; RET 0x8`: dest object → `0046ef20`, returned in `EAX`.

Order proof (pseudocode verbatim, offsets relative to object base;
slot `n` at `+0x4+4n`):

- `p1` (dest slot0) = `P[0]*C[0] + P[4]*C[1] + P[8]*C[2] + P[12]*C[3]`
  where `P` = `param_2`, `C` = `in_ECX`
  = `row0(C)·col0(P)`.
- `p2` (dest slot1) = `C[0]*P[1] + C[1]*P[5] + C[2]*P[9] + C[3]*P[13]`
  = `row0(C)·col1(P)`.
- Slot15 (asm head `0x46efcf`–`0x46efeb`, computed FIRST, pushed first):
  `P[11]*C[14] + C[13]*P[7] + C[12]*P[3] + C[15]*P[15]`
  = `row3(C)·col3(P)`.
- All 16 slots follow `dest[i][j] = Σ_k C[i][k]·P[k][j]`.
  **Therefore `dest = ECX × param_2`.** The reverse reading
  (`param_2 × ECX`) would need `P`-rows dotted with `C`-columns;
  observed products are `C`-rows dotted with `P`-columns. QED.

Per-slot FPU term order varies (e.g. slot15 accumulates `k = 2,1,0,3`;
slot0 accumulates `k = 0,3,2,1` per pseudocode listing order) and all
intermediates are x87 80-bit (`FLD`/`FMUL`/`FADDP` chains, one `FSTP`
per slot into the 16 outgoing arg slots). So Rust `f32` is bit-exact only
on exact inputs (0/1 arithmetic), ~1 ulp/slot otherwise (same ceiling as
the quaternion path in `matrix.rs`).

Callees (1): `0046ef20`. Callers (14): `0040a680`, `0040d0f0`, `00424610`,
`00455ba0` (tree loop × 2 sites `0x456041`/`0x456056`), `00457110`,
`0045ad80`, `0045af50`, `0045b010`, `0045dce0`, `00461fc0`, `004621e0`,
`00502340`, `00502530`, `00504540`. Referenced strings: none.

Caller-site direction (parent §4 + order proof): site 1
(`ECX` = R result, pushed src = S) yields `tmp = R×S`; site 2
(`ECX` = `tmp`, pushed src = T) yields `final = (R×S)×T`.

## 3. Observation: `FUN_0046f910` (97 B, `0x46f910`–`0x46f970`)

Evidence: `ev_b0ab3e0a67912c5ff0eaff4e4479aeede5ff43e93ba06f9d78daa1c9258fa1b1`
(supersedes submit-doc `ev_e124dca02437803642c9353b7e74cd9b5d3864dcb226646452dfeb5d04e944d8`).

Pseudocode (verbatim):

```c
undefined4 FUN_0046f910(undefined4 param_1,float param_2)
{
  fVar1 = (float10)fcos((float10)param_2);
  fVar2 = (float10)fsin((float10)param_2);
  FUN_0046ef20((float)fVar1,0,(float)fVar2,0,0,0x3f800000,0,0,
               -(float)fVar2,0,(float)fVar1,0,0,0,0,0x3f800000);
  return param_1;
}
```

Assembly shape (44 insns, observed): `FLD [ESP+0xc]; FCOS` → stash cos;
`FLD; FSIN` → sin bits to `ECX` (`0x46f94b: MOV ECX,[ESP+0x30]`);
`FCHS` → `FSTP [ESP]` overwrites a `PUSH ECX` placeholder with `−sin`;
16 pushes in reverse (`p16..p1 = 1,0,0,0,0,cos,0,−sin,0,0,1,0,0,sin,0,cos`);
`MOV ECX,ESI` (dest = saved `in_ECX`); `CALL 0046ef20`; bare `RET`
(angle is the single thiscall stack param; no callee cleanup).

Forwarded words (observation): row0 `(cos,0,sin,0)`, row1 `(0,1,0,0)`,
row2 `(−sin,0,cos,0)`, row3 `(0,0,0,1)`. Slot2 = `+sin`, slot8 = `−sin`.

Callees (1): `0046ef20`. Callers (2): `00455ba0` (tree loop `0x456026`,
angle `[ESP+0x44]`), `00504540`. Referenced strings: none.

## Unknowns

- U1 (open): angle source/convention at tree-loop `[ESP+0x44]` (units proven
  radians only by `FCOS`/`FSIN` use; value path untraced). Sign convention
  vs the quaternion path (`FUN_0046fa90` Y-90° yields slot2 `−1`, slot8 `+1`;
  `f910(+π/2)` yields slot2 `+1`, slot8 `−1` — opposite handedness under a
  common row-vector reading). Either the Y-rot callers pass negated angles
  or the two rotation producers genuinely disagree; BOTH transcriptions keep
  observed signs (no normalization). Needs a caller-angle trace, not a sign
  "fix".
- U2 (method): per-slot FPU accumulation order transcribed canonically
  (`k = 0..3`) in Rust; original varies per slot (§2) and uses 80-bit
  intermediates, so only exact-input bit-exactness is claimed.
- U3 (open, narrowed from parent): `00455ba0` `param_1`/angle producers
  (`[ESP+0x44]`, model-handle slots) still untraced; composition shape
  `(R×S)×T` no longer depends on them.
