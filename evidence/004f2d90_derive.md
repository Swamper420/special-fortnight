# `FUN_004f2d90` — dword deriver feeding pad `004f26f0` params 13-15

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2. Parent: `evidence/004f26f0_consumer.md` NEXT TARGET (ONE):
closes what the pad's params 13-15 (`local_c`) carry.

Evidence IDs:

- `ev_197d1ce0b0ec9eef93cdd18801ac67a3beeb3869c730db236d9d923be4a4acfb`
  (`analyze_function FUN_004f2d90`: body `0x4f2d90-0x4f2dd3`, 68 bytes,
  contiguous; pseudocode; assembly; 2 callers, 3 callees).
- `ev_bfe6757f6075002d2644323a109da59d5d6c02df652af2507575be2daae418f9`
  (`analyze_function FUN_005388f0`: `0x5388f0-0x538921`, 50 bytes,
  contiguous; vec3-sub via `00538660`; 20 callers).
- `ev_10984e65b804a9e467c6b604da1de8ec90dbd5f1edd75bcdc3e86a99d465f078`
  (`analyze_function FUN_00538970`: `0x538970-0x5389d0`, 97 bytes,
  contiguous; matvec via `00538660`; 8 callers).
- `ev_b2e7b71e9fd038a2b44215898ce72b36a9c75f81b8cdf75ebaa9a7b62aa0d72f`
  (`analyze_function FUN_005388b0`: `0x5388b0-0x5388e1`, 50 bytes,
  contiguous; vec3-add via `00538660`; 12 callers).
- `ev_adcf68b43fbc33cd42e36cff5aa6f3ded8fa4da7d942f803efaacae8860c0797`
  (prior `analyze_function FUN_004f2d90` from parent dossier: same
  `0x4f2d90-0x4f2dd3` range, same 3-callee chain).

## 1. Claim

- `FUN_004f2d90` is a thiscall (`ECX` = this; Ghidra labels `__stdcall`
  by default but both call sites load `ECX` before `CALL`, and the body
  opens with `MOV ESI,ECX`). One stack param is the out pointer
  (`RET 0x10` — see U1); returns the out pointer (`MOV EAX,EDI`).
- Net effect, in order: (a) `local_c = minuend − (this+0x84)`
  via `005388f0`, where `minuend` = the 3 dwords at the caller's
  `[entryESP+8]` (in the `004f26f0` chain provably the zeroed temp,
  so `local_c = −(this+0x84)` there — §4); (b) `local_18 =
  columns(this+0x44 matrix) · local_c` via `00538970` (`[base]`
  unread, §3); (c) `*out = (this+0x38) + local_18` via `005388b0`.
- The three leaves are genuinely new pure fragments (no existing
  transcription in `engine/src`; `matrix::fn_0046ef20` is the 16-word
  store, `mesh.rs` only documents the `00538660` 3-word store, neither
  duplicates sub/add/matvec). Transcribed in
  `engine/src/fn_004f2d90.rs` with one test (generated fixtures).
- Strings: none (all four analyses report zero referenced strings).

## 2. Observation: `004f2d90` body (verbatim assembly)

```text
0x4f2d90: SUB ESP, 0x18
0x4f2d93: PUSH ESI
0x4f2d94: MOV ESI, ECX
0x4f2d96: PUSH EDI
0x4f2d97: LEA ECX, [ESP + 0x8]
0x4f2d9b: LEA EAX, [ESI + 0x44]
0x4f2d9e: LEA EDX, [ESI + 0x84]
0x4f2da4: PUSH EAX
0x4f2da5: PUSH ECX
0x4f2da6: LEA EAX, [ESP + 0x1c]
0x4f2daa: PUSH EDX
0x4f2dab: PUSH EAX
0x4f2dac: LEA ECX, [ESP + 0x38]
0x4f2db0: CALL 0x005388f0
0x4f2db5: MOV ECX, EAX
0x4f2db7: CALL 0x00538970
0x4f2dbc: MOV EDI, dword ptr [ESP + 0x24]
0x4f2dc0: PUSH EAX
0x4f2dc1: PUSH EDI
0x4f2dc2: LEA ECX, [ESI + 0x38]
0x4f2dc5: CALL 0x005388b0
0x4f2dca: MOV EAX, EDI
0x4f2dcc: POP EDI
0x4f2dcd: POP ESI
0x4f2dce: ADD ESP, 0x18
0x4f2dd1: RET 0x10
```

Pseudocode (decompiler, `in_ECX` = this):

```text
FUN_005388f0(local_c, in_ECX + 0x84);
uVar1 = FUN_00538970(local_18, this + 0x44);
FUN_005388b0(param_1, uVar1);
return param_1;
```

(`ECX` inputs elided by the decompiler; resolved by hand ESP trace
in §4. Locals: `local_18` @ frame `-0x18`, `local_c` @ `-0xc`.)

Callers (2): `FUN_004f26f0` (`0x4f2719`), `FUN_004f6400` (`0x4f641a`).
Callees (3): `005388f0`, `00538970`, `005388b0` — all terminal into
`FUN_00538660` (3-dword store, `RET 0xc`).

## 3. Observation: leaf semantics (verbatim assembly + formulas)

`base` = matrix pointer (`this+0x44` at the `004f2d90` site);
`v` = `ECX` vector; `w[i]` = `[base+i*4]` (`w0 = [base]` never read).

`FUN_005388f0` (`0x5388f0`, dest = stack p1, subtrahend = stack p2,
minuend = `ECX`; `RET 0x8`; returns dest):

```text
0x5388f0: MOV EAX, [ESP+0x8]      ; p2
... FLD [ECX+8]; FSUB [EAX+8] ... ; per-slot x87, FSTP float ×3
... CALL 0x00538660               ; (dest, d0, d1, d2)
```

`dest[i] = ECX[i] − p2[i]`, `i = 0..2`. Single x87 op per slot +
single `FSTP` rounding = bit-exact under `f32` (one rounding).

`FUN_005388b0` (`0x5388b0`, same shape, `FADD` instead of `FSUB`):
`dest[i] = p2[i] + ECX[i]`. Bit-exact under `f32`.

`FUN_00538970` (`0x538970`, dest = stack p1, matrix = stack p2,
vector = `ECX`; `RET 0x8`; returns dest). x87 association order
verbatim (each slot: two `FADDP`s, one `FSTP`):

```text
dest0 = ((w7*v2 + w1*v0) + w4*v1)   ; offs +0x1c,+0x04,+0x10
dest1 = ((w8*v2 + w2*v0) + w5*v1)   ; offs +0x20,+0x08,+0x14
dest2 = ((w9*v2 + w3*v0) + w6*v1)   ; offs +0x24,+0x0c,+0x18
```

i.e. `dest[j] = col_j · v` with `col_0 = (w1,w4,w7)`,
`col_1 = (w2,w5,w8)`, `col_2 = (w3,w6,w9)` — columns of the 3x3
starting at `[base+4]` (= `Mᵀ·v` for row-major `M`). Extended-precision
accumulation + single final rounding per slot: `f32` transcription
matches to ~1 ulp/slot, bit-exact on exact inputs. Inference: the
`[base]` skip / row-vs-column reading is observed addressing, not a
named matrix convention (see U3).

## 4. Derivation: stack-trace resolution (hand trace, derived)

Conventions: `S` = `ESP` after `SUB`+2 pushes (`= entryESP−0x20`);
locals `local_18` @ `entryESP−0x18`, `local_c` @ `entryESP−0x0c`;
callee `p1`/`p2` account for the return-address push.

- First call: `p1` = 4th push = `LEA [ESP+0x1c]` = `local_c`;
  `p2` = 3rd push = `this+0x84`; `ECX` = `LEA [ESP+0x38]` =
  `entryESP+8`. So `local_c = [entryESP+8] − (this+0x84)`.
- In the `004f26f0` chain: `entryESP+8` = caller's `[ESP+0x10]`-slot
  region = the `00538660`-zeroed temp `(0,0,0)` (traced in parent §2:
  `ECX`=caller-`ESP` at zero time; pushes don't move `ECX`). Hence
  there `local_c = −(this+0x84)` exactly (`0.0 − x` is one rounding,
  same op in the transcription, so signs match bit-for-bit).
- `MOV ECX,EAX` forwards `local_c` (return = dest = `local_c`);
  second call passes zero pushes: `p1` = `local_18`, `p2` =
  `this+0x44`. So `local_18 = matvec(this+0x44, local_c)`.
- `MOV EDI,[ESP+0x24]` = incoming out pointer; third call
  `p1` = out, `p2` = `local_18` (return), `ECX` = `this+0x38`.
  So `*out = (this+0x38) + local_18`; `RET 0x10`; returns out.

Confidence: hand ESP arithmetic (checked twice against the
decompiler's dest/subtrahend assignment, which agrees). The
`entryESP+8` alias is caller-dependent by construction — the Rust
transcription takes the minuend as an explicit 4th input so both
callers are served without baking in the `004f26f0` zero-temp fact.

## 5. Inference

- Pad params 13-15 (`local_c`) in the tick chain = `−(this+0x84)`
  (this = `[tick-this+0x84]` sub-object via forwarder `0045af20`),
  then rotated by the `(this+0x44)` columns and added to
  `(this+0x38)` into the caller's out buffer — which the pad then
  forwards as `0046ef20` params 13-15. Parent U2 (slot-base tracing)
  is closed for the `004f26f0` path by §4.
- `005388f0` has 20 callers, `005388b0` 12, `00538970` 8 — shared
  vec3 helpers, transcribed once here, reused by later procedures.

## Unknowns

- U1: `RET 0x10` vs one observed `PUSH` at `0x4f2718` (parent U2
  inherited): the extra 12 bytes popped are caller-frame temps the
  callee never names (its only stack read is `p1`). No imbalance
  accumulates (caller `ESP` lands on its out buffer, which it then
  reads). Second caller `004f6400` (38 bytes) not analyzed — the
  minuend identity there is untraced; transcription keeps it explicit.
- U2: float-vs-int slot types at `this+0x38/44/84`: all three leaves
  use `FLD/FST` (float); no integer path observed. Kept `f32`.
- U3: matrix convention at `this+0x44` (`[base]` unread — count,
  flag, or padding unknown; 3x3-at-`+4` vs 4x4-column reading
  undecided). Transcription indexes the 9 observed words verbatim;
  no layout claim.
- U4: `FUN_004f6400` behavior/out-of-scope; recorded only as caller.
