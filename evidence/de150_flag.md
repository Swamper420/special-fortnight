# de150 mode flag `[strip+0x18]` provenance (U1 of `004de150_index.md`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: strictly who writes the byte at `[strip+0x18]`, where `strip` is the
`ECX` object on entry to `FUN_004de150`. No engine code touched.

Dispatch recap (observation, from `evidence/004de150_index.md` §5):
`0x4de1c8` reads `[EBP+0x8]` with `EBP = ECX+0x10`, i.e. `[this+0x18]`.
Nonzero → unconditional `FUN_004def20` insert. Zero → unique path
(`df1d0` hint + conditional insert). Reader location is settled;
only the writer was open (U1).

## 1. Observation: ctor `FUN_004dd5c0` zeroes `[strip+0x18]`

`ev_7183008684e7945dfb0e3b8d36c82a6b17c0eeb86865944f3db3af9bb2ae3ca0`
(`analyze_function 0x004dd5c0`, body `0x4dd5c0-0x4dd6b1`, 242 bytes);
`ev_ac0b6b48507976a8d00bf3cd4fc73110f741e9f556e2e549ffbc9062462a0bb1`
(`read_function_instructions 0x004dd5c0`, 75 insns). Verbatim:

```text
0x4dd5f0: XOR EBX, EBX
...
0x4dd611: MOV byte ptr [ESI + 0x18], BL
```

`ESI` is `ECX` on entry (`0x4dd5df: MOV ESI, ECX`), `EBX` is 0.
Decompiler agrees (`*(undefined1 *)(in_ECX + 6) = 0`; `in_ECX` is
dword-based, `+6` = `+0x18`). Same ctor also sets `[ESI+0x14]` (index
header), `[ESI+0x1c]`, and guard `[ESI+0x30] = 0` (`0x4dd69e`).
Callers of the ctor: `0x434020`, `0x434390` only.

## 2. Observation: ctor object == de150 object (ECX chain)

- `0x434390` (landing builder, `ev_4df37b1c319d306969f9dba79cedeb46e8ac969e41c3dbeaa6fafbc9e5cb797a`):
  `operator_new(0x34)` → `ECX=EAX; CALL 0x004dd5c0` (`0x4343ae-0x4343c8`),
  result kept in `EDI` → stored at parent `[ESI+0x60]`. Size `0x34`
  covers de150's highest access (`+0x30` guard).
- `FUN_004dda60` head (`ev_ad8a0e5d36fcd0f954fe9cefb6f504c2697abaeddd56b945dd219322d661bf0d`):
  `0x4dda64: MOV ESI, ECX`; tail: `0x4ddabc: MOV ECX, ESI` /
  `0x4ddabe: CALL 0x004de150`. So de150's `ECX` == emitter's `ECX`.
  Both read the same `+0x30` guard (`0x4dda66`, `0x4de159`).
- Therefore `[strip+0x18]` in §5 == `[ESI+0x18]` zeroed at `0x4dd611`.

Per-strip values at construction: `0x434020` builds two strips
(parent `+0x50`/`+0x58`), `0x434390` one strip (parent `+0x60`);
all three go through `004dd5c0`, so all start with flag = 0.
(`ev_17130156cc8288bbe7c626ab3ea19df173d101f974eaa59da3f8b20413929a6a`
for `0x434020`.)

## 3. Observation: negative sweep — no other `+0x18` object store found

`read_function_instructions` over each procedure, filtering for
`0x18]` with a non-`ESP` base (all `ESP+0x18` hits are stack spills/
locals, cited inline where relevant):

- Emitters (de150 callers): `0x4dda60` (41 insns, none),
  `0x4ddae0` (144, only `ESP`), `0x4ddcb0` (200, only `ESP`),
  `0x4ddf10` (185, only `ESP`).
  (`ev_ad8a0e5d...`, `ev_eeb43c1ab866483d85c91e06745b276b6c9f095b801636c5e42310915dee65ff`,
  `ev_540a2b55378fdcfc6f4b252824fcf1781ba1c5c0f7eb60b35752e18689edca04`,
  `ev_6febe684e81373d2eefcf5eb313c2183689f595f64e734a9e2357675bd0d3c50`.)
- Builders: `0x434390` (385 insns, only `ESP`; all non-`ESP` stores
  are parent-relative `[ESI+0x44..0x264]`, none target the strip in
  `EDI`), `0x434020` (282 insns, only `ESP`).
- Sibling methods `0x4dd6c0-0x4e1b50` (~70 procedures incl. `0x4dd980`
  clear, `0x4dd6e0` dtor, `0x4dfb30`/`0x4e0c20`/`0x4e1b50` large fns):
  no non-`ESP` `+0x18` access, except two different-class hits below.
- `0x4dd980` (clear, `ev_bfa3d4f6f917e12057aabcb2af8fb5ec43da6a7fb5406995980a945eeb973eee`,
  caller `0x4dd6e0`): touches `[ECX+0x1c]` and `[ECX+0x30]`, never
  `+0x18`. Dtor `0x4dd6e0`
  (`ev_fbeeeb7d00e9271a4c128b562d8d76067ae100a81790e4f1f8a6ff9763790ecb`)
  never writes `+0x18` either.

Different-class hits (ruled out by vtable): `0x4dfa10`
(`ev_cc3fac920f777fbd24cfb39d6aa6e2f80c7160df580c4ea4d65189c6b8f5b50b`,
`[EAX+0x18]` store) and `0x4dfa80`
(`ev_7377fbe8fc878e049484b90bf858c4fc6de7b492e59aef8cde7b3fed357db2f7`,
`[ECX+0x18]` load) both install/read vtable `0x5d09ec`, not the
strip vtable `0x5d09d8` written by `0x4dd5c0` (`0x4dd698`).

## 4. Inference (labeled)

Ctor zero-init + no setter in any examined path suggests all observed
strips run the unique-insert path, and the nonzero `def20`-always arm
may serve an unobserved caller or a subclass override. This is
inference: absence from the swept set does not prove no writer exists
(see Unknowns).

## Unknowns

- U1 (still open): writer setting `[strip+0x18]` nonzero. No store
  found in ctor, 5 de150 callers, 2 parent builders, or ~70 sibling
  procedures. Unexamined mechanisms: virtual setter via vtable
  `0x5d09d8`, `rep movs`/block copy covering `+0x18` without a literal
  offset, writer outside `0x4dd5c0-0x4e1b50`.
- U2: ctor stack reads (`0x4dd5d8: MOV AL,[ESP+0x3]`,
  `0x4dd5fd/0x4dd601: ...[ESP+0x17]`) feed `[ESI+0x4/0x10/0x11]`;
  callers pass no stack args — provenance of those bytes unmapped
  (not flag-related; recorded so nobody re-trips on it).

## Next target (ONE)

Enumerate vtable `0x5d09d8` entries with a wide `read_bytes`
(`0x005d09d8`, ≥64 bytes; current 64-byte read shows entries
`0x004dd6c0`, `0x004df810`, then `0` — extent unclear) and analyze
each entry for a `[ECX+0x18]` store: a virtual setter is the remaining
plausible writer mechanism on the strip class.
