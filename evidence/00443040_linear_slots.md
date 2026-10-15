# Linear vtable slots +4/+8: `0x443040` + `0x443050` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: these two addresses ONLY. Slot-0 (`0x443030`) done in
`evidence/00443030_linear_xform.md`; cubic/arc targets untouched.
`engine/src/mesh.rs` untouched.

Closes U2 in `evidence/00443030_linear_xform.md` (sibling-slot semantics).

## Evidence IDs (new, this sweep)

- `ev_b178c3b9339f17c5a62f1315611ddca8a2e83acf0f6c5193de7d3b150651d2f6`
  (`read_bytes 0x00443040`, 64 B complete).
- `ev_80db3ea4493bbe84375b472aba3a260ea4e247f7f8d77e318f0224d82093d4e`
  (`read_bytes 0x00443050`, 64 B complete).
- `ev_dee5090660081c7119856222818b75b25901aceeb3c8d14d1d85bf44bde1cda`
  (`resolve_containing_procedure 0x00443040` → `not_in_procedure`).
- `ev_3d2302a59ddb4f211956b0fcb25d2af11bb237acc6e5af61d6bb3433010e4d1f`
  (`resolve_containing_procedure 0x00443050` → `not_in_procedure`).
- `ev_ff523dabe7b39909784ecb29b57f7cb2889cd181d8b2d97ab80f5c1f19dca125`
  (insn decode `0x443040`: `FLD float ptr [ECX+0xc]`, fallthrough).
- `ev_9b09504c14ad229ecb36cb339e26b387090f059590eea05f9ba0af8017679df5`
  (insn decode `0x443043`: `RET 0x4`, terminator).
- `ev_632a8697531cb88621bda60dd4186d457893bafc86d7cebcf95c458b7d9158f0`
  (insn decode `0x443050`: `FLD float ptr [0x005ce0f4]` + READ ref
  `0x443050 → 0x5ce0f4`).
- `ev_d7bad1d77ab22234d9eb1d0d9e4ab036db51865a9a550556f512e45f512ed522`
  (insn decode `0x443056`: `RET 0x4`, terminator).
- `ev_d95b9849daeffb9a95cb1cb1df2ed1b08dfefea58ef26d948be033e304e5cd5b`
  (`read_bytes 0x005ce0f4`, 16 B complete: `ffff7f7f 00004040 ...`).
- `ev_2bacc9713fe523b9e5559f5982870464243b38f1fef6fa6fd98ffa497019e099`
  (xrefs → `0x443040`: exactly [`0x5ce0ec`], i.e. vtable+4 data ref).
- `ev_890e9ac14e11eed5e63f7380e1c7928c1ee0412f5ea8f45689b29c126977a895`
  (xrefs → `0x00443050`: exactly [`0x5ce0f0`], i.e. vtable+8 data ref).

Prior (cited, not re-pulled): `ev_5e9d537d...` (`read_bytes 0x005ce0e8`:
slots `30304400 40304400 50304400`); `ev_f5a89aaf...` (`00442fb0` ctor:
`+12` slope, `+16` intercept); `ev_adf190fd...` / `ev_6c1bccad...` /
`ev_0832a867...` (`de480`/`de430`/`de4d0` slot+4/+4+atan/+8 dispatch).

## 1. Observation: bytes

`0x443040` (16 B span `0x443040-0x44304f`, decoder-verified):

```text
0x443040: FLD  float ptr [ECX+0xC] ; d9 41 0c (element slope, +12)
0x443043: RET  0x4                 ; c2 04 00 (callee pops 1 f32 arg)
0x443046: NOP x10                 ; pad to 0x443050
```

`0x443050` (16 B span `0x443050-0x44305f`, decoder-verified; next code
`0x443060` is the cubic ctor):

```text
0x443050: FLD  float ptr [0x005ce0f4] ; d9 05 f4 e0 5c 00 (global, .rdata)
0x443056: RET  0x4                   ; c2 04 00 (callee pops 1 f32 arg)
0x443059: NOP x7                    ; pad to 0x443060
```

Global at `0x005ce0f4` (`.rdata`, read-only): bytes `ff ff 7f 7f` =
`0x7F7FFFFF` = `FLT_MAX` (`3.4028234663852886e+38`). Neighbor bytes
(`ev_d95b9849...`): `[5ce0f8] = 0x40400000` (`3.0`), then cubic vtable
`5ce0fc = {0x4432a0, 0x4432c0, ...}` — constant pool directly abutting
the cubic vtable, same `.rdata` neighborhood as the linear vtable.

Calling convention (observation from bytes + dispatch context): thiscall,
`ECX` = linear element, one `f32` stack arg popped unread by both
(`RET 4` with no `[ESP]` read), `f32` result in `ST0`.

## 2. Pseudocode (inference, asm-exact, no branches to lose)

```c
float __thiscall slot1_443040(LinearElem *ECX, float x)
{
  (void)x;
  return ECX->slope /* +12 */;
}

float __thiscall slot2_443050(LinearElem *ECX, float x)
{
  (void)ECX; (void)x;
  return *(float *)0x005ce0f4; /* FLT_MAX, .rdata constant */
}
```

Family reading (inference, one step): slot-0 evaluates the line
(`slope*x+intercept`), slot+4 returns the slope (`dy/dx` — the `de430`
wrapper takes `atan()` of it, i.e. segment angle), slot+8 returns the
constant `FLT_MAX`. Range gating stays in the selector, same split as
slot-0.

## 3. NaN paths (observation: loads only, no compare/branch/ALU)

`FLD` loads bits exactly (no mapping, no trap). Net rules:

- `0x443040`: output bit-identical to `ECX->slope`. NaN slope (quiet or
  signaling — no conversion happens on load) → identical NaN out; never
  maps NaN away. Infinities/zeros pass through unchanged.
- `0x443050`: output is always `FLT_MAX` — never NaN, regardless of `x`
  or element contents (both unread).

No ST0-precision caveat here (unlike slot-0): `f32`→80-bit loads are
exact widenings, so Rust `f32` identity/constant matches bit-for-bit.

## 4. Callers / callees / strings

- Callees: none (each body: 1 x87 load + `RET`; no `CALL`).
- Callers: no STATIC direct caller (both `not_in_procedure`, same
  indirectly-reached-only gap as slot-0). Dynamic callers via vtable
  `0x5ce0e8` slots (`ev_5e9d537d...` + slot xrefs above): slot+4 ←
  `FUN_004de480` / `FUN_004de430` (`CALL [EDX+4]`, same `f32` arg
  re-pushed); slot+8 ← `FUN_004de4d0` (`CALL [EDX+8]`). INFERENCE, one step.
- Referenced strings: none (no string loads; slot+8's only load is the
  `FLT_MAX` constant — observation via the READ ref in `ev_632a8697...`).

## Unknowns

- U1 (closed here): sibling-slot semantics — was open U2 in
  `00443030_linear_xform.md`.
- U2 (open, out of scope): WHY slot+8 returns `FLT_MAX` (sentinel for
  "no curvature"? second-derivative N/A marker? `de4d0` caller `0x45b130`'s
  use of `ST0` unmapped) — value transcribed, purpose unclaimed.
- U3 (open, carried): `00442f30` NaN edge on `lo`/`hi`
  (`xform_list_setup.md` §5 U3) — orthogonal to these pure fragments.
- U4 (method): hand transcription cross-checked by Ghidra insn decoder
  (`ev_ff523dab...`, `ev_632a8697...`); the decoder's absolute operand
  (`0x005ce0f4`) overruled a first-pass hand misread — recorded so a
  future reader does not "re-correct" it back.
