# Xform element-list setup: writers feeding `FUN_004de2a0` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: list writers ONLY (who allocates nodes, sets vtable slot 0, lo/hi).
No target-function semantics. `engine/src/mesh.rs` untouched. Evidence-only:
list machinery is `std::list` + `shared_ptr` (stdlib rung, nothing pure to
transcribe); element-ctor math is target semantics, out of scope.

Closes U1 in `evidence/004de3e0_xform.md` (concrete slot-0 target set).

## 1. Writer list (all observation, `analyze_function` dossiers)

- Strip ctor `FUN_004dd5c0` (`ev_a1a25e5b26d242659ad9f5fc737336a82bbd38a35c41cdb6ba1dfff60c59ca21`;
  body `0x4dd5c0-0x4dd6b1`, 242 B, contiguous; callers `0x434020`, `0x434390`;
  callees `0x59c120`, `0x59c314`, `0x59c3b0`, `0x59c8e9`; no strings):
  allocates `0x10` sentinel (`operator_new`), self-links `[0]`/`[4]`,
  stores at `ECX+8` (`in_ECX[2] = pvVar1`) — the `[strip+8]` list head the
  selector walks. Count `ECX+0xC = 0`. Strip vtable `&PTR_FUN_005d09d8`
  at `[ECX+0]`. Also inits `[ECX+0x14]` tree + `[ECX+5]` chain (see §4).
- Seal `FUN_004dd970` (`ev_dd3ad81ff80eeb1a33ed6387ef78d3a956c76decc2ea583dabf4b75aee49a7e7`;
  5 B): sets `[ECX+0x30] = 1`. Same flag byte `de3e0`/`de2a0` throw on when
  0. Callers `0x434020`, `0x434390`.
- Base element ctor `FUN_00442f30` (`ev_c221341ac63a64924b73135f72f52540ca9a59d15956d75318f4b18f62ddd104`;
  73 B; callees none; callers `0x442fb0`, `0x443060`, `0x443370`): sets
  vtable `&PTR_LAB_005ce0d0` at `+0`, `lo = min(p1,p2)` at `+4`,
  `hi = max(p1,p2)` at `+8` (branch shape, x87 compare per twin
  `FCOMP/FNSTSW/TEST` idiom elsewhere; NaN edge behavior NOT verified —
  unknown, §5).
- Linear element ctor `FUN_00442fb0` (`ev_13c5fd2d119f41844e123f4708a0f0380eea8e3d84bf4e71cf621beeccd815e1`;
  115 B; callee `0x442f30`; sole caller `0x4ddae0`): calls base
  `(param_1, param_3)`, then vtable `&PTR_LAB_005ce0e8` at `+0`,
  slope at `+12`, intercept at `+16`. Allocation size `0x14`.
- Cubic element ctor `FUN_00443060` (`ev_df0ea221b93e1474c3885e1a82b1f2a4a3d8d8d359be42aee2294abc920e4695ca`;
  529 B; callees `0x442f30`, `0x443280`, `0x443290`; callers `0x434390`,
  `0x4ddcb0`): calls base `(param_1, param_3)`, then vtable
  `&PTR_FUN_005ce0fc` at `+0`, four coeff words at `+12..+24`
  (`in_ECX[3..6]`). Allocation size `0x1c`. Shape (poly coeffs) is
  inference from store pattern only — no semantics claimed.
- Arc element ctor `FUN_00443370` (`ev_b404a8b902c2d04d0331f263931274429c03f57afabe78e08f87b225fb29eb3e`;
  220 B; callees `0x406b90`, `0x442f30`, `0x443290`; sole caller
  `0x4ddf10`): calls base `(param_3, param_5)`, then vtable
  `&PTR_LAB_005ce110` at `+0`, fields at `+12..+24` (`in_ECX[3..6]`).
  Allocation size `0x1c`.
- Linear emitter `FUN_004ddae0` (`ev_d6f345594e071d7b861cbbb399211923cf3fa5fbe0ff4f744608a68535b88974`;
  450 B; callers `0x434020`, `0x434390`; strings `Invalid data exception`
  x2): guards (`[ECX+0x30]` sealed? throw; `p < [ECX+0x20]`? throw;
  `p == [ECX+0x20]`? early return), `new(0x14)` → `00442fb0` with
  `([ECX+0x20], [ECX+0x24], p, param_2)`, `new(0x10)` node, manual
  insert-before-sentinel into `[ECX+8]` (verbatim asm,
  `ev_80f9d7aa2fb739de332591c85dff6f351b97a2604e0410d0dbde3dfb65feb874`:
  `0x4ddbe0 MOV EDI,[ESI+8]` head; `0x4ddc00 [EAX]=link`;
  `0x4ddc0d [EDI+4]=EAX`; `0x4ddc15 [ECX]=EAX`;
  `0x4ddc17 LEA ECX,[EAX+8]`; `0x4ddc23 CALL 004306e0` element copy
  into `node+8`), count `[ECX+0xC]++`, `004de150` tree insert, then
  `[ECX+0x20]=p`, `[ECX+0x24]=param_2`, `[ECX+0x2c]=p`.
- Cubic/arc emitters `FUN_004ddf10` (`ev_36d3bc70a16ee2d4f88a8e096a8f668ec488200801099146718b90d591c1baf0`;
  564 B; callers `0x434020`, `0x434390`; → `00443370`, `new(0x1c)`)
  and `FUN_004ddcb0` (`ev_b3185efdff4421fdc0e286832fbe6191661ebead62f0e844f1361d517f5bd493`;
  606 B; caller `0x434390` ONLY; → `00443060`, `new(0x1c)`): same guard
  shape, but list insert via `00477450` + `00517ca0(node+8, &shared)`
  (allocator-aware push-back), count++. `4ddf10` additionally walks
  `[*elem+4]` (`atan`) / `[*elem+8]` slots in a fill loop — slot use
  observed, semantics out of scope.
- Head-set emitter `FUN_004dda60` (`ev_6e25eaf52377aefd1f67b839172045190d41df0ca546edd807c28098ac63a957`;
  128 B; callers `0x434020`, `0x434390`): NO list insert — sets
  `+0x20/+0x24/+0x28/+0x2c` scalars after `004de150`. First-point init.

## 2. Element layouts (observation: ctor stores + predicate offsets)

Node `0x10` B: `+0`/`+4` doubly-linked links, `+8` element holder
(`shared_ptr`, 8 B: raw ptr + control; `LEA ECX,[EAX+8]` +
`CALL 004306e0` at `0x4ddc17-0x4ddc23`). Selector reads `[node+8]` as
element — consistent with `de2a0` (`ECX=[ESI+8]` → predicate
`[ECX+4]`/`[ECX+8]` → return `[ESI+8]`).

- Linear `0x14`: `+0` vtable(`005ce0e8`), `+4` lo, `+8` hi, `+12` slope,
  `+16` intercept. Emitter `4ddae0` ← both builders.
- Cubic `0x1c`: `+0` vtable(`005ce0fc`), `+4` lo, `+8` hi, `+12..+24`
  coeffs. Emitter `4ddcb0` ← landing builder only.
- Arc `0x1c`: `+0` vtable(`005ce110`), `+4` lo, `+8` hi, `+12..+24`
  fields. Emitter `4ddf10` ← both builders.

## 3. Concrete slot-0 target set (observation: `read_bytes`, complete)

| vtable | bytes (LE) | slot+0 (xform) | slot+4 | slot+8 |
|---|---|---|---|---|
| `005ce0d0` (base) | `93d45900 x3` (`ev_5d0729a1...`) | `0x59d493` | same | same |
| `005ce0e8` (linear) | `30304400/40304400/50304400` (`ev_0d22650e...`) | `0x443030` | `0x443040` | `0x443050` |
| `005ce0fc` (cubic) | `a0324400/c0324400/e0324400` (`ev_fe59a23e...`) | `0x4432a0` | `0x4432c0` | `0x4432e0` |
| `005ce110` (arc) | `50344400/d0344400/50354400` (`ev_786456c5...`) | `0x443450` | `0x4434d0` | `0x443550` |

Slot-0 set = {`0x443030`, `0x4432a0`, `0x443450`}. All three are real code:
`0x443030` decodes `FLD float ptr [ESP+4]` (`ev_8426e6e9...`, xform arg-load
signature); `0x443450` decodes `PUSH ECX...` (`ev_85e1059f...`);
`0x4432a0` is a 27-B analyzed procedure (`ev_8cf8cf7863a0b2a680b4df9c944a021df88e6ab3627e451326c782519c2e67fa`).
`0x443030`/`0x443450` (and sibling slots) report `not_in_procedure` in the
DB (`ev_c09762b7...`, `ev_801e5ccb...`, +6 more) — indirectly-reached-only
analysis gap, NOT absence of code. Sibling-slot shape matches the
`de480`/`de430` (slot +4) / `de4d0` (slot +8) callers exactly (3 slots).

## 4. Adjacent (explicitly NOT xform-list writers)

- `FUN_004de150` (`ev_089722c6f0272481cb7164829e61644ec966a3dde94a68dbcee298dffec39477`;
  239 B; callers `0x434390`, `0x4dda60`, `0x4ddae0`, `0x4ddcb0`,
  `0x4ddf10`): red-black-style tree insert keyed on float `[node+3]`
  into `[ECX+0x14]` (sentinel `DAT_0061bb58`), via `00538460` key-probe
  and `004def20`/`004df1d0` rotators. Separate index — out of scope.
- `FUN_004306e0` (element copy into `node+8`), `00477450`/`00517ca0`
  (allocator push-back), `00442f80` predicate — cited, not analyzed here.

## 5. Unknowns

- U1 (THIS FILE closes the set, not the semantics): slot-0 bodies
  `0x443030`/`0x443450` unanalyzed (`not_in_procedure`); per-target math
  unmapped by scope. Base slot `0x59d493` likewise unresolved (data? thunk?
  pure-virtual stub? — unknown).
- U2 (open): why landing builder `0x434390` calls element ctor `0x443060`
  directly (caller list `ev_df0ea221...`) outside emitter `4ddcb0` —
  temp/probe construction vs inline emit unmapped.
- U3 (open): `00442f30` NaN edge (`lo`/`hi` selection under unordered
  compare) unverified; affects NaN-`hi`-selects nuance in `004de3e0`
  evidence §2.
- U4 (open): `node+12` second holder word role (refcount — inference from
  `004306e0`/`00517ca0` shared-ownership shape, not observed).
- U5 (carried): `evidence/004348a0_terrain_loop.md` callees section still
  truncated in-file (placeholder text); vector-growth `00475330`/`0059c120`
  roles per that file's tail notes, unverified here.

## Recommended next target (ONE)

`FUN_00443030` (linear slot-0 xform, `FLD`-head, smallest): analyze +
transcribe as pure fragment (`slope*x+intercept` shape to verify against
`442fb0` `+12/+16` stores) with one unit test. Do NOT touch sibling slots
or cubic/arc targets before this lands.
