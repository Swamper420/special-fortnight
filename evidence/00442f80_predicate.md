# Selector predicate `FUN_00442f80` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Role: range predicate called by list-search selector `FUN_004de2a0`
(`0x4de2dd`, sole caller); element `ECX` = `[node+8]` pointer tested by
`de2a0`, layout `+0`=vtable ptr, `+4`=range lo, `+8`=range hi.
Parent dispatch detail: `evidence/004de3e0_xform.md` §3.
`engine/src/mesh.rs` untouched. Transcribed:
`engine/src/fn_00442f80.rs::range_contains(lo, hi, p)`.

Evidence IDs (new, this sweep):

- `ev_cc2cb91fd243d3a12c7f1c5f994b2a061e6f283aa13f71ae45012ef96b42e3cc`
  (`analyze_function FUN_00442f80`: pseudocode + asm + callers/callees;
  body `0x442f80-0x442fa8`, 41 bytes, contiguous).
- `ev_737a6c7430b01d76d9f75edc0a799df37cb77c419dd594b9e80fd475836e92a7`
  (`procedure_assembly FUN_00442f80`, verbatim asm below).
- `ev_d8a0f205e780ae5177cec4ac1dccb770266ed293779392e1f87202f937f839a4`
  (`procedure_pseudo_code FUN_00442f80`, verbatim below).
- `ev_15188a0fe2270a328b4ef67e915819bddcff0a2625b5a8d63f535d5cbb779651`
  (`procedure_callers`: exactly [`0x4de2a0`]).
- `ev_82034daf8c6f9683478143b0217ab9f7406cf52a210d52ec2f73859c0822e18c`
  (`procedure_callees`: none — pure compare, `RET 0x4` both exits).

Prior (cited): `ev_ff6c9550...` (same asm re-pulled above, consistent);
selector role + NaN map per `evidence/004de3e0_xform.md` §3.

## 1. Observation: assembly (verbatim, `ev_737a6c74...`)

```text
0x442f80: FLD float ptr [ESP + 0x4]
0x442f84: FCOMP float ptr [ECX + 0x4]
0x442f87: FNSTSW AX
0x442f89: TEST AH, 0x1
0x442f8c: JNZ 0x00442fa4
0x442f8e: FLD float ptr [ESP + 0x4]
0x442f92: FCOMP float ptr [ECX + 0x8]
0x442f95: FNSTSW AX
0x442f97: TEST AH, 0x41
0x442f9a: JZ 0x00442fa4
0x442f9c: MOV EAX, 0x1
0x442fa1: RET 0x4
0x442fa4: XOR EAX, EAX
0x442fa6: RET 0x4
```

Pseudocode (verbatim, `ev_d8a0f205...`):

```c
undefined4 FUN_00442f80(float param_1)
{
  int in_ECX;
  if ((*(float *)(in_ECX + 4) <= param_1) && (param_1 <= *(float *)(in_ECX + 8))) {
    return 1;
  }
  return 0;
}
```

## 2. Inference: gate map (asm-exact)

- Gate 1 (`TEST AH,0x1`, C0 only, `JNZ fail`): `FLD p; FCOMP [ECX+4]`
  fails on `p < lo` OR unordered → pass iff `p >= lo` ordered.
  NaN `p` or NaN `lo` → FAIL.
- Gate 2 (`TEST AH,0x41`, C0|C3, `JZ fail`): `FLD p; FCOMP [ECX+8]`
  passes on `p < hi`, `p == hi`, OR unordered → pass iff `!(p > hi)`.
  NaN `p` or NaN `hi` → PASS at this gate (gate 1 already rejected
  NaN `p`, so net NaN `p` → 0; NaN `hi` selects iff gate 1 passed).
- NOTE: decompiler `p <= hi` is WRONG for NaN `hi` (C++ `<=` is false
  on unordered; asm gate 2 passes unordered). Trust asm.
- Rust: gate 1 `if !(p >= lo) return false` (not `p < lo`, NaN-exact);
  gate 2 `if p > hi return false` (NaN passes, asm-exact).

## 3. Observation: callers / callees / strings

- Callers (`ev_15188a0f...`): `0x4de2a0` only (selector `0x4de2dd` site,
  `ECX=[node+8]`, stack arg `f32`, `TEST AL,AL` on return).
- Callees (`ev_82034daf...`): none.
- Referenced strings: none (observation: asm has no data loads —
  only `[ESP+0x4]` / `[ECX+0x4]` / `[ECX+0x8]` compares).

## 4. Transcription

`engine/src/fn_00442f80.rs::range_contains(lo, hi, p)`: two gates
op-for-op with the NaN map above. One test `range_gates` over
generated fixtures (incl. NaN-`hi` divergence where decompiler
reading differs).

## Unknowns

- U1 (carried): element class / vtable set linked into `[strip+8]`
  lists and list writers — see `evidence/004de3e0_xform.md` U1.
- U2 (carried): overlapping-range order load-bearing (first-hit-wins)
  — see `004de3e0_xform.md` U2.
