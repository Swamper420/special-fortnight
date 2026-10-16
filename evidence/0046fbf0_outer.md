# `FUN_0046fbf0` — outer-product form (`d·I − v⊗u`), NOT a rotation writer

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2. Parent: `evidence/rotation_writer.md` §4 (one-line note).

## 1. Claim

- `FUN_0046fbf0` (`0x46fbf0`–`0x46fd52`, 355 B, 122 insns, single basic block)
  is a thiscall matrix composer: `ECX` = dest, stack = two `float[4]`
  vectors `(u0..u3, v0..v3)`; forwards a 16-word outer-product form to
  `FUN_0046ef20`; returns dest (`MOV EAX,ESI` tail, same frame as siblings).
- Math: both vectors normalized in place by their **xyz-norm**
  (`sqrt(x²+y²+z²)`, 3 terms — `w` is scaled by the same norm);
  `d` = 4D dot of normalized vectors; slot `(i,j)` = `d·δij − u_j·v_i`
  (diagonals `d − u_i·v_i` via `FSUBR`, off-diagonals `−(u_j·v_i)` via `FCHS`).
- Output layout = linear push order into `ef20` (row `i` = slots `4i..4i+3`).

## 2. Observation

Dossier: `ev_a2d5b6110e02823e58525a264684adf3a412e3185b6c8038693b7a47b48d9929`
(`analyze_function`); raw instructions (122):
`ev_a1dffa04820cc797cb0d53c9e97e53281eb4d7eb2a76cb8df3219e6408180aac`
(`read_function_instructions`).

Pseudocode (verbatim):

```c
undefined4 FUN_0046fbf0(undefined4 param_1,float param_2,float param_3,
  float param_4,float param_5,float param_6,float param_7,float param_8,
  float param_9)
{
  float10 fVar1;
  FUN_00538b60(SQRT(param_6 * param_6 + param_7 * param_7 + param_8 * param_8));
  FUN_00538b60(SQRT(param_2 * param_2 + param_3 * param_3 + param_4 * param_4));
  fVar1 = (float10)FUN_004df630(&param_6,&param_2);
  FUN_0046ef20((float)(fVar1 - (float10)param_2 * (float10)param_6),-(param_3 * param_6),
               -(param_4 * param_6),-(param_5 * param_6),-(param_2 * param_7),
               (float)(fVar1 - (float10)param_3 * (float10)param_7),-(param_4 * param_7),
               -(param_5 * param_7),-(param_2 * param_8),-(param_3 * param_8),
               (float)(fVar1 - (float10)param_4 * (float10)param_8),-(param_5 * param_8),
               -(param_9 * param_2),-(param_9 * param_3),-(param_9 * param_4),
               (float)(fVar1 - (float10)param_5 * (float10)param_9));
  return param_1;
}
```

With `u = (param_2..param_5)`, `v = (param_6..param_9)`, `d = fVar1`:

| slot | value | form |
|---|---|---|
| 0 | `d − u0·v0` | diag |
| 1 | `−(u1·v0)` | off-diag |
| 2 | `−(u2·v0)` | off-diag |
| 3 | `−(u3·v0)` | off-diag |
| 4 | `−(u0·v1)` | off-diag |
| 5 | `d − u1·v1` | diag |
| 6 | `−(u2·v1)` | off-diag |
| 7 | `−(u3·v1)` | off-diag |
| 8 | `−(u0·v2)` | off-diag |
| 9 | `−(u1·v2)` | off-diag |
| 10 | `d − u2·v2` | diag |
| 11 | `−(u3·v2)` | off-diag |
| 12 | `−(v3·u0)` | off-diag |
| 13 | `−(v3·u1)` | off-diag |
| 14 | `−(v3·u2)` | off-diag |
| 15 | `d − u3·v3` | diag |

i.e. `M[i][j] = d·δij − u_j·v_i` = `d·I − v⊗u` (equivalently `d·I − (u⊗v)ᵀ`).

Callees (firm):
- `FUN_00538b60` (`0x538b60`, 43 B; dossier
  `ev_bb78733d6fe41f1dc54f8b14aecff9e653e48cda0aab5833c702ded1efbac9f1`,
  insns `ev_a02890f6bffa623869058f2141616876d2ea941c646e303fa7ca83ad9c03ee59`):
  `ECX` = `float[4]` ptr, stack scalar `s` → divides all 4 words by `s`
  (`FLD/FDIV/FSTP` ×4, `RET 0x4`). In-place normalize-by-given-norm.
- `FUN_004df630` (`0x4df630`, 37 B; dossier
  `ev_a30c7c83d556e662fba3b6d136427d3c708bf753e7b0259e6e05287d3e0cc7a1`,
  insns `ev_188d433acddc0337b6fdb3467fce40f57ba04ada9946967dcc99aaa838bb59f9`):
  cdecl 4D dot, association `((w·w' + z·z') + y·y') + x·x'`
  (loads `+0xc,+0x8,+0x4,+0x0` order). Callers: `0045b130`, `0046fbf0`,
  `004df700`, `00502960`.
- `FUN_0046ef20` (`0x46ef20`): 16-word ctor, same as all siblings.

Callers (1): `FUN_00458160` (dossier
`ev_3dc66013efceee344a2090e7741b5e325ddc6e0132bfa86ffd2820064cca7ad7`,
insns `ev_54088adcfcf05d5a49971714c699aa60e3028f06ded07810a86fdc7c503906d1`).
Call site `0x45836d`: two `float[4]` scratch vectors built on the stack via
`FUN_004df370` (`SUB ESP,0x10` ×2), then `LEA ECX,[ESP+0x74]; PUSH ECX;
CALL 0046fbf0; ADD ESP,0x24` (`0x24` = 32 scratch + 4 pushed).
Frame tail (observed): `MOV ESI,[ESP+..]` dest reload, `MOV ECX,ESI`,
`CALL 0046ef20`, `MOV EAX,ESI` return, `POP ESI/POP ECX/RET`.

Norm term count (firm): exactly 3 `FLD/FMUL` pairs precede each `FSQRT`
(`0x46fbf1`–`0x46fc1b`, `0x46fc25`–`0x46fc46`); decompiler resolves them to
the first three words of each vector. `w` takes part in the dot and the
divide but not the norm.
Diagonal association (firm): `FSUBR ST0,ST1` = `d − prod` per diagonal slot.
Off-diagonal (firm): `FMUL` then `FCHS` = exact negation of product.

Strings: none. Names: `FUN_0046ef20 @ 0x46fd49`, `FUN_004df630 @ 0x46fc5a`,
`FUN_00538b60 @ 0x46fc20,0x46fc4b` only.

## 3. Inference

- Pure fragment of 8 input floats: normalization targets the two stack
  vectors in place (scratch copies — caller rebuilt them per call), so the
  Rust transcription as `fn([f32;4],[f32;4]) -> Mat4` is faithful.
- Zero-norm input: no guard in asm (`FDIV` by zero → inf/nan propagates);
  transcription keeps no guard (no "improvement").
- x87 80-bit intermediates vs `f32` per-op rounding: bit-exact on exact
  inputs (unit basis vectors), ~1 ulp/slot otherwise. Test uses exact cases
  plus one `sqrt(2)` case under tolerance.

## 4. Transcription (`engine/src/matrix.rs`)

- `outer_product_form(u, v)`: xyz-norms `sqrt((x²+y²)+z²)`, divide all 4,
  dot `((u3·v3+u2·v2)+u1·v1)+u0·v0`, slots per §2 (`d − u·v` diagonals,
  `−(u·v)` off-diagonals) via `fn_0046ef20`.
- Test `outer_product_exact`: `u=v=(1,0,0,0)` → `diag(0,1,1,1)` bit-exact;
  `u=(0,1,0,0),v=(0,0,1,0)` → only slot9 `= −1` bit-exact;
  `u=v=(1,1,0,0)` → `[[0.5,−0.5,..],..]` under `1e-6`.

## Unknowns

- U1: exact caller stack plumbing (single pushed ptr + 32 scratch bytes vs
  decompiler 8-float signature) — transcription value-semantics unaffected,
  but a byte-level arg-layout claim is not made here.
- U2: semantic role in `00458160` render path (what `u`,`v` represent —
  plane/projection terms?) — out of scope; matrix family only.
- U3: x87-vs-SSE rounding — association matched, precision not modeled
  (same standing note as sibling composers).
