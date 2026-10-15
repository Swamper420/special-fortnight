# Linear slot-0 xform `0x443030` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: this address ONLY. Sibling slots (`0x443040`/`0x443050`),
cubic/arc targets untouched (boundary bytes cited §1 only to delimit extent).

Closes recommended-next-target in `evidence/xform_list_setup.md` §Recommended.

## Evidence IDs (new, this sweep)

- `ev_2894cc260e5bfbe1c299f63d74c9874c6ef178f07b35fb7b2ab09a442d7427d3`
  (`read_bytes 0x00443030`, 64 B complete; raw hex below).
- `ev_6b5fcd28e576ca07a4e3b8cc304eef726a66cf1ddfeb43dfe0f9e627a2877cda`
  (`resolve_containing_procedure 0x00443030` → `not_in_procedure`).
- `ev_5e9d537d503d1fd781793eb63b727d2f16b3439a310e98036e8fafb7b141bbb0`
  (`read_bytes 0x005ce0e8`, 12 B complete: vtable slots).
- `ev_f5a89aaf63ce94afb5f5a922058c03d17482afe0b5672e087ece582dfdaed9d7`
  (`analyze_function 0x00442fb0`: linear ctor dossier, body
  `0x442fb0-0x443022`, 115 B contiguous; sole caller `0x4ddae0`).

Prior (cited, not re-pulled): `evidence/xform_list_setup.md` §§2-3
(element layout, slot-0 set); `evidence/004de3e0_xform.md` §§1-2
(`de3e0` dispatch + `de2a0` selector, ST0 float discipline).

## 1. Observation: bytes at `0x443030` (verbatim, `ev_2894cc26...`)

Requested 64 B at `0x00443030`, all 64 returned complete:

```text
d9442404 d8490c d84110 c20400 909090 d9410c c20400 909090909090909090
d905f4e05c00 c20400 90909090909090 83ec1c 558b6c242c 56578b7c242c 558b...
```

Hand decode of the first 16 B (DERIVATION from the hex above, not
decompiler output — no procedure exists here, §5):

```text
0x443030: FLD  float ptr [ESP+4]   ; d9 44 24 04  (stack f32 arg x)
0x443034: FMUL float ptr [ECX+0xc] ; d8 49 0c     (element slope)
0x443037: FADD float ptr [ECX+0x10]; d8 41 10     (element intercept)
0x44303a: RET  0x4                 ; c2 04 00      (callee pops 1 arg)
0x44303d: NOP x3                  ; 90 90 90      (pad to 0x443040)
```

Body extent: code `0x443030-0x44303c` (13 B) + 3 B pad = 16 B span ending
at `0x443040`. Next word at `+16` decodes `d9 41 0c` (`FLD [ECX+0xC]`)
+ `RET 4` — the `0x443040` slot-+4 entry (boundary observation ONLY, not
transcribed); next code at `+32` (`0x443050`, `FLD [0x005c4e5f]; RET 4`)
likewise boundary-only.

Calling convention (observation from bytes + dispatch context): thiscall,
`ECX` = linear element (`+0` vtable, `+4` lo, `+8` hi per
`004de3e0` evidence §3 and `xform_list_setup.md` §2), one `f32` stack arg
(`RET 4`), `f32` result in `ST0` (consumed by `de3e0` callers via `FCOMP`
with no store between — `004de3e0` evidence §1).

## 2. Pseudocode (inference, asm-exact, no branches to lose)

```c
float __thiscall xform_443030(LinearElem *ECX, float x)
{
  return ECX->slope /* +12 */ * x + ECX->intercept /* +16 */;
}
```

Slope/intercept use (observation, ctor dossier `ev_f5a89aa...` asm +
pseudocode): `FUN_00442fb0` stores vtable `0x5ce0e8` at `[ESI+0]`, then

- normal path: `[ESI+0xC] = (p4-p2)/(p3-p1)` (slope),
  `[ESI+0x10] = p2 - p1*slope` (`FSUBR`, i.e. intercept), so the line
  passes through `(p1,p2)`, `(p3,p4)`;
- degenerate path (`0x443006`, taken when `!(0.0 < ABS(p3-p1))` under
  `TEST AH,0x41`, i.e. zero gap OR unordered/NaN gap): `[ESI+0xC] = 0`,
  `[ESI+0x10] = p2 - p1*0 = p2` — constant function `y = p2`.

So `0x443030` evaluates the segment line; range gating is the selector's
job (`00442f80` predicate), not this function's.

## 3. NaN paths (observation: no compare, no branch in body)

`FLD` loads NaN bit-exact (no mapping). x87 `FMUL`/`FADD` propagate:
QNaN in → QNaN out; SNaN in → invalid-operation → QNaN out. Net rule:
NaN in any of `{x, slope, intercept}` → NaN in `ST0`; NaN NEVER maps to
a non-NaN here (contrast the `00442f80` predicate gates, which DO map
unordered). Same for infinities: `inf*0` → invalid → NaN; overflow →
±inf; no traps (no `FNSTSW`/`TEST` present to observe status).

## 4. Callers / callees / strings

- Callees: none (13 B body: 3 x87 ALU ops + `RET`; no `CALL`).
- Callers: no STATIC direct caller exists (address not in any analyzed
  procedure, §5 — Ghidra records no call edge). Dynamic caller is
  `FUN_004de3e0` via `CALL dword ptr [EDX]` (`ev_229ed5be...` in
  `004de3e0` evidence §1) after `FUN_004de2a0` selects a linear element;
  slot wiring `0x5ce0e8+0 → 0x443030` observed in `ev_5e9d537d...`
  bytes `30304400 40304400 50304400` (= `0x443030`, `0x443040`,
  `0x443050`, matching `xform_list_setup.md` §3). INFERENCE, one step.
- Referenced strings: none (no loads of any kind in body — observation).

## 5. Method note: `not_in_procedure`

`analyze_function FUN_00443030` and `procedure_assembly 0x00443030` both
fail (`Unknown procedure` / `No procedure exists`); `ev_6b5fcd28...`
records `found: false, reason: not_in_procedure`. Same indirectly-
reached-only gap as `xform_list_setup.md` §3 predicted for `0x443030`
(and `0x443450`): reachable only through the vtable slot, never by
direct static call. Body above comes from `read_bytes`, not the
decompiler — pseudocode §2 is hand transcription, labeled inference.

## Unknowns

- U1 (carried ST0-precision caveat, now VERIFIED present for this
  target): result stays 80-bit extended in `ST0` — no `FSTP m32` before
  `RET`, and `de3e0` callers `FCOMP` it directly. Rust `f32`
  transcription rounds mul-then-add to `f32`; last-ulp borderlines
  against `f32` range edges can differ. Same convention as
  `strip_range_predicate` (`fn_004357a0.rs` caveat); NOT fixed here.
- U2 (open, out of scope): sibling-slot (`0x443040`/`0x443050`)
  semantics — bytes read for extent only, bodies not decoded.
- U3 (open, carried): `00442f30` NaN edge on `lo`/`hi` selection
  (`xform_list_setup.md` §5 U3) — orthogonal to this pure fragment.
- U4 (open): which emitter paths feed linear elements at runtime is
  known (`4ddae0` ← both builders, per `xform_list_setup.md` §1); exact
  runtime slope/intercept VALUES are data, unmapped — no claim.
