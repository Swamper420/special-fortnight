# Tree-loop RNG instance init at `0x455eeb` (closes `tree_angle_source.md` U1)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`).
Parents: `evidence/tree_angle_source.md` U1, `evidence/004df840_seed.md`
(terrain mirror: ctor/seed/divisor pattern). No code, no engine edits.

Evidence IDs (new this wave):

- `ev_ca6cf25e203caaa2c4d3b9b2e57ceb9683d0ea5be5a65d31820260657d928efe`
  (`read_function_instructions FUN_00455ba0`: 868 insns; init window
  `0x455dc4`–`0x45602e` + head `0x455ba0`–`0x455dc4` quoted below).
- `ev_368f1e4237d3a1d42a363cc6ba7b2dfd3a5bd36dab03111b51b801b2eef544ea`
  (`analyze_function FUN_0040e520`: `return *(ECX+0x1c)`, body
  `0x40e520`–`0x40e523`, 4 bytes).
- `ev_50aa55957ddb97d41559d2ec5d6dbdc106ecb36e4c43fe9bb7890bdecc2c8235`
  (`analyze_function FUN_00435c40`: `return *(*(ECX+0x23c)+param_1*8)`).
- `ev_1d2b64ed23690d1bc6561109b1ab550838af2c1870286fd5eba0635fff2aaf8b`
  (`analyze_function FUN_00435c00`: count
  `([ECX+0x240]-[ECX+0x23c])>>3`, 0 when `[ECX+0x23c]==0`).

Reused (prior wave, `evidence/004df840_seed.md`):

- `ev_bac87991...` (`analyze_function FUN_004df7e0`: ctor pseudo; asm
  `0x4df7e0`–`0x4df80a`: vtable `0x5d09dc` @ `[+0x0]`, mode byte
  `[ESI+0x20C]=AL`, divisor `(f32)sqrt(dbl[0x5d09e0])` @ `[ESI+0x8]`,
  `seed(obj,0)`, `RET 0x4`).
- `ev_d47b172c...` (`read_bytes 0x5d09e0`: divisor-source double
  `5.333333492279053`; sqrt -> f32 `0x4013CD3A`).
- `ev_d30266c7...` (`FUN_004df840` body `0x4df840`–`0x4df872`:
  stores seed dword to `[ECX+4]`, skips 128-entry table fill when
  mode flag `[ECX+0x20C]==0`, `RET 0x4`).

## 1. Observation: init sequence (asm-observed, `ev_ca6cf25e...`)

```text
0x455bc0: XOR EBX, EBX                      ; EBX=0 at head
... no write to EBX before 0x455ee0 (all interim PUSH EBX are reads) ...
0x455eb5: MOV ECX, [ESP+0x40c]              ; outer object
0x455ebc: CALL 00435c00                     ; count -> EAX
0x455ec1: MOV EBP, EAX
0x455ec9: ... JBE 0x0045610b                ; skip when count==0
0x455ed3: MOV ECX, [ESP+0x40c]
0x455eda: PUSH EBX                          ; param_1 = EBX = 0 (observed)
0x455edb: CALL 00435c40                     ; first-record ptr -> EAX
0x455ee0: PUSH 0x0                          ; ctor mode arg, literal 0
0x455ee2: LEA ECX, [ESP+0x1f0]
0x455ee9: MOV EDI, EAX                      ; EDI = first-record ptr
0x455eeb: CALL 004df7e0                     ; ctor(mode=0), RET 0x4
0x455ef0: MOV ECX, EDI
0x455efa: CALL 0040e520                     ; EAX = *(EDI+0x1c)
0x455eff: PUSH EAX                          ; seed dword
0x455f00: LEA ECX, [ESP+0x1f0]
0x455f07: CALL 004df840                     ; seed(obj, seed), RET 0x4
```

Ctor arg: literal `PUSH 0x0` (`0x455ee0`), independent of EBX.
`param_1` to `00435c40`: `PUSH EBX` with EBX provably 0
(`0x455bc0 XOR EBX,EBX`, no intervening write in either quoted
window), so index 0 = first element.

## 2. Observation: seed source chain

- `0x455edb`: `EDI = 00435c40(outer, 0) = *([outer+0x23c] + 0*8)`
  = first record pointer of the array at `[outer+0x23c]`
  (`ev_50aa5595...` asm verbatim).
- `0x455efa`: `EAX = 0040e520(EDI) = *(EDI+0x1c)`
  (`ev_368f1e42...` pseudo+asm verbatim, 4-byte body).
- `0x455f07`: `004df840(obj, EAX)` stores the dword to `[ECX+4]`
  (reused `ev_d30266c7...`).
- Gate: `0x455ebc 00435c00` count
  (`ev_1d2b64ed...`); whole init + tree loop skipped when count==0
  (`0x455ecd JBE`, `0x455f15 JBE`).

So seed = dword at offset `+0x1c` of the first record. Record struct
layout and field `+0x1c` semantics untraced (Unknowns).

## 3. Observation: mode flag + divisor (mirror of terrain)

- Mode: ctor stores its byte param to `[ESI+0x20C]`
  (reused `ev_bac87991...` asm `MOV [ESI+0x20C],AL`); param here is
  literal 0 -> `[+0x20C]=0` = RAW LCG path in `004df8c0`
  (returns `004df900()` directly, no 128-entry shuffle).
  Both the ctor-internal `004df840(0)` and the explicit `0x455f07`
  reseed therefore skip the table fill (`TEST AL,AL / JZ`).
- Divisor: ctor writes `(f32)sqrt(dbl[0x5d09e0])` = `0x4013CD3A`
  to `[+0x8]` (reused `ev_bac87991...` + `ev_d47b172c...`). Same
  constant as terrain; irrelevant to `004df960` draws (that path
  uses `2^-32` scale at `0x5d09e8`, not `[+0x8]`).

## 4. Observation/inference: one stack object, seeded once

- Observed (RET-balance bookkeeping): ctor `LEA [ESP+0x1f0]` runs
  with one dword pushed (`0x455ee0`); seeder `LEA [ESP+0x1f0]`
  runs with one dword pushed (`0x455eff`); between them
  `004df7e0`'s `RET 0x4` rebalances. Same absolute slot: one
  stack object, size `0x210` per terrain mirror.
- Inference (compiler pattern, same as terrain doc): draw sites
  `LEA ECX,[ESP+0x1f4]` (`0x455f32/0x455f58/0x455fa7/0x455fca`)
  compensate one extra outstanding push (+4 each), aliasing the
  same object. Per-callee `RET`-convention accounting for the
  float helpers (`00436610/00454070/004351a0`) not verified here;
  identity of draw object with init object rests on this pattern,
  not a full ESP audit.
- Observed position: init (`0x455eeb/0x455f07`) sits BEFORE the
  per-count inner loop (`0x455f1f`) and the tree branch
  (`0x455f88 JNZ` skips); draws sit INSIDE both. One instance,
  seeded once per `00455ba0` invocation, sequential draws per tree.

## Unknowns:

- U1-CLOSED (this file): ctor args (mode literal 0), seeder call
  (`0x455f07` <- `0040e520` getter), seed derivation chain to
  first-record `+0x1c`, divisor (`0x4013CD3A`), shuffle flag = 0
  (raw path), single stack instance seeded once.
- Open (semantic, non-load-bearing for angle math): record-struct
  layout at `[outer+0x23c]` (element = 8-byte slots holding
  pointers? stride 8 with `param_1*8`); meaning of field `+0x1c`
  (runtime seed VALUE provenance — which config/scene field feeds
  it); identity of outer object (`[ESP+0x40c]` = caller-SP arg,
  unmapped); whether seed persists across frames (stack temp dies
  at return; determinism given same first-record contents only).
- Carried (`tree_angle_source.md` U2/U3): `0x40490FD8` vs float-pi;
  Ghidra-pseudo method caveat.

## ONE next target

`FUN_00435c40` caller-context / record struct: `analyze_function`
on the allocator of the `[outer+0x23c]` array (or `read_bytes`
around a live `+0x23c` table) to name field `+0x1c`. Single entry
point: cross-refs to `0x435c40` writers of `[+0x23c]`.
NOT `0046f910` sign, NOT banner/frame/tower submits.
