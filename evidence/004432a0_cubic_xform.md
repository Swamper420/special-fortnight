# Cubic slot-0 xform `0x4432a0` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: this address ONLY. Sibling slots (`0x4432c0`/`0x4432e0`),
cubic ctor `0x443060` internals, arc targets untouched (boundary
bytes cited §1 only to delimit extent).

Sibling of linear `0x443030` (`engine/src/fn_00443030.rs`,
`evidence/00443030_linear_xform.md` — pattern followed here).
Element layout (`0x1c`: `+0` vtable `005ce0fc`, `+4` lo, `+8` hi,
`+12..+24` coeffs) and range gating (`00442f80` + `004de2a0`
selector) per `evidence/xform_list_setup.md` §§2-3 and
`evidence/004de3e0_xform.md` §§1-3 (cited, not re-pulled).

## Evidence IDs (new, this sweep)

- `ev_70bd7da47321fa2de97e5bac3dc278c5e59b3f6869056b76766705c806da9d52`
  (`analyze_function FUN_004432a0`: pseudocode + asm + callers/callees;
  body `0x4432a0-0x4432ba`, 27 B, contiguous; callees none;
  referenced strings none; single basic block).
- `ev_be94019d9d0c9fcfdebaf3c20dbb03e1c29cca0e3e8b7718557bf35be9a34cd6`
  (`procedure_assembly FUN_004432a0`, verbatim asm below).
- `ev_e350d247f20ad956136d6ad9a10de309af0e256c27fd97cd01121ce8309848ca`
  (`read_bytes 0x004432a0`, 64 B complete; raw hex below).
- `ev_59842dfde4edf8b81b81d9cda474d2d10b7ee017b1a3669baacede62d1c8b43b`
  (`read_bytes 0x005ce0fc`, 12 B complete: vtable slots
  `a0324400 c0324400 e0324400` = `0x4432a0`, `0x4432c0`, `0x4432e0`).
- `ev_ef7bed3e017940b16b34ccac73de1eed72032369a54dc5878d1a93ec7cb6109e`
  (`procedure_callers FUN_004432a0`: static caller `0x434390` only;
  indirect vtable callers unresolved by construction).
- `ev_ac3ab0eb6e67d53ac67537f4e50248ed8cc56d3100203cce654d43f8e4608265`
  (`resolve_containing_procedure 0x004432a0` — procedure found,
  unlike linear `0x443030` `not_in_procedure`; body IS a known
  Ghidra function `FUN_004432a0`).

Prior (cited, not re-pulled): `evidence/xform_list_setup.md` §§1-3
(cubic ctor `FUN_00443060` `ev_df0ea221...`: calls base `0x442f30`,
sets vtable `005ce0fc`, four coeff words at `+12..+24`, alloc `0x1c`;
callers `0x434390`, `0x4ddcb0`; slot-0 set table).

## 1. Observation: assembly at `0x4432a0` (verbatim, `ev_be94019d...`)

```text
0x4432a0: FLD float ptr [ESP + 0x4]
0x4432a4: FMUL float ptr [ECX + 0xc]
0x4432a7: FADD float ptr [ECX + 0x10]
0x4432aa: FMUL float ptr [ESP + 0x4]
0x4432ae: FADD float ptr [ECX + 0x14]
0x4432b1: FMUL float ptr [ESP + 0x4]
0x4432b5: FADD float ptr [ECX + 0x18]
0x4432b8: RET 0x4
```

Pseudocode (verbatim decompiler output, `ev_70bd7da4...`):

```c
float10 FUN_004432a0(float param_1)
{
  int in_ECX;
  return (((float10)param_1 * (float10)*(float *)(in_ECX + 0xc) + (float10)*(float *)(in_ECX + 0x10)
          ) * (float10)param_1 + (float10)*(float *)(in_ECX + 0x14)) * (float10)param_1 +
         (float10)*(float *)(in_ECX + 0x18);
}
```

`read_bytes` hex (`ev_e350d247...`, 64 B complete):

```text
d9442404 d8490c d84110 d84c2404 d84114 d84c2404 d84118 c20400 9090909090
d9442404 d8490c d80df8e05c00 d94110 dcc0de c1d84c2404 d84114 c20400 9090
```

First 27 B hand-decode matches the assembly line-for-line
(`FLD/FMUL/FADD` x87 encodings identical in shape to linear `0x443030`
head, extended to three multiply-add rounds). Body extent: code
`0x4432a0-0x4432ba` (27 B) + 5 B pad (`90` x5) = 32 B span ending at
`0x4432c0`. Second row is the `0x4432c0` slot-+4 entry (boundary
observation ONLY, not transcribed).

Calling convention (observation from bytes + dispatch context): thiscall,
`ECX` = cubic element (`+0` vtable, `+4` lo, `+8` hi per cited layout),
one `f32` stack arg (`RET 4`), `f32` result in `ST0` (consumed by `de3e0`
callers via `FCOMP` with no store between — `004de3e0` evidence §1).
Single basic block (`0x4432a0-0x4432bb`, no successors), no branches,
no `CALL`, no loads other than the arg and the four coeff slots.

## 2. Pseudocode (inference, asm-exact, no branches to lose)

```c
float __thiscall xform_4432a0(CubicElem *ECX, float x)
{
  return (((x * ECX->c3 /* +12 */ + ECX->c2 /* +16 */) * x + ECX->c1 /* +20 */) * x + ECX->c0 /* +24 */);
}
```

Horner-form cubic, evaluation order fixed by the instruction sequence:
`((c3*x + c2)*x + c1)*x + c0` where `c3=[ECX+12]`, `c2=[ECX+16]`,
`c1=[ECX+20]`, `c0=[ECX+24]`. Coeff-slot ORDER (which multiplier is
`+12` vs `+24`) is observation from this body; what the ctor `0x443060`
STORES into each slot (which ctor param maps to which power) is NOT
claimed here — ctor internals out of scope, prior dossier records stores
only. Naming `c3..c0` is positional shorthand for that observed order,
not a proven ctor contract.

Range gating is the selector's job (`00442f80` predicate + `004de2a0`
first-hit-wins), not this function's — same split as linear.

## 3. NaN paths (observation: no compare, no branch in body)

`FLD` loads NaN bit-exact (no mapping). x87 `FMUL`/`FADD` propagate:
QNaN in → QNaN out; SNaN in → invalid-operation → QNaN out. Net rule:
NaN in any of `{x, c3, c2, c1, c0}` → NaN in `ST0`; NaN NEVER maps to
a non-NaN here (contrast the `00442f80` predicate gates, which DO map
unordered). Same for infinities: `inf*0` → invalid → NaN; overflow →
±inf; no traps (no `FNSTSW`/`TEST` present to observe status).
Intermediate NaN poisons all downstream rounds (single linear chain).

## 4. Callers / callees / strings

- Callees: none (27 B body: 7 x87 ALU ops + `RET`; no `CALL` —
  observation, `ev_70bd7da4...` callees `[]`).
- Callers: static caller `0x434390` (landing builder; direct
  `UNCONDITIONAL_CALL` at `0x43471d`, observation) PLUS vtable DATA ref
  at `0x5ce0fc` slot 0 (observation, `ev_70bd7da4...`
  incoming_references). Dynamic caller is `FUN_004de3e0` via
  `CALL dword ptr [EDX]` (`ev_229ed5be...` in `004de3e0` evidence §1)
  after `FUN_004de2a0` selects a cubic element; slot wiring
  `0x5ce0fc+0 → 0x4432a0` observed in `ev_59842dfd...`. INFERENCE, one
  step. (Differs from linear `0x443030`, which has NO static caller —
  linear is `not_in_procedure`; cubic IS a analyzed procedure with a
  direct probe-style caller, consistent with `xform_list_setup.md` §5
  U2: builder `0x434390` calls cubic ctor `0x443060` directly too.)
- Referenced strings: none (no loads of any kind in body except
  arg/coeffs — observation, `referenced_strings: []`).

## Unknowns

- U1 (carried ST0-precision caveat, same as linear U1): result stays
  80-bit extended in `ST0` — no `FSTP m32` before `RET`, and `de3e0`
  callers `FCOMP` it directly. Rust `f32` transcription rounds each
  mul-then-add to `f32`; last-ulp borderlines can differ. Same
  convention as `strip_range_predicate` (`fn_004357a0.rs` caveat); NOT
  fixed here.
- U2 (open, out of scope): sibling-slot (`0x4432c0`/`0x4432e0`)
  semantics — bytes read for extent only, bodies not decoded.
- U3 (open, carried): `00442f30` NaN edge on `lo`/`hi` selection
  (`xform_list_setup.md` §5 U3) — orthogonal to this pure fragment.
- U4 (open): ctor-to-slot coeff mapping — which `0x443060` input lands
  in `+12` vs `+16` vs `+20` vs `+24` (needs `0x443060` + helpers
  `0x443280`/`0x443290` deep dive, explicitly out of scope). The
  transcription preserves evaluation ORDER; if the ctor stores e.g.
  reversed or scaled coeffs, the wiring goes in the ctor transcription,
  not here.
- U5 (open, carried `xform_list_setup.md` §5 U2): purpose of the direct
  static call `0x434390 → 0x4432a0` (temp/probe evaluation vs inline
  emit unmapped).
