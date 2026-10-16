# World-frame composition map: `FUN_00455ba0` matrices → `FUN_00409060` submit; terrain-vertex writes in `FUN_004348a0`

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`, SHA-256 `3619dcbd...`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`. Static analysis only.
No Rust transcribed; `engine/` untouched. Parents: `evidence/00455ba0_render_assets.md`,
`evidence/00436620_composition.md`, `evidence/00436620_placement_recon.md`,
`evidence/00409060_submit.md`, `evidence/00466a20_consumer.md`, ROADMAP Phase 2 OPEN item.

## 1. Claim

- Scenery frames ARE placed in `FUN_00455ba0`: per-object 4x4 matrices built by
  `0046f9f0` (T) / `0046fa40` (S) / `0046f910` (Ry) over `0046ef20`, composed by
  `0046efc0` x2 in the tree loop only, consumed by scene node `00423a20`
  (matrix word-copy) and submitted by `00409060` (single-matrix copy + list attach).
- Terrain-mesh vertices are written in `FUN_004348a0` into the `[EBP+0x74/0x78/0x7c]`
  vector with NO placement transform at the write; meshes stay in separate local
  frames. World-frame composition of b50/b58/b60/b68/terrain meshes remains OPEN.

## 2. Observation: `FUN_00455ba0` matrix call sites (868 insns)

Fresh: analyze `ev_008854d7aa6bf3d37d4da9b9e91e2eefc7fd77889e049e92c49ab9e2815e889c`;
instr `ev_b6c83121d7aacb859dc888def7addd2d8ce672d623da471955ad3544649fe30c` (this dossier).

| site | op | operands (asm-observed this dossier) |
|---|---|---|
| `0x455fec` | `0046f9f0` T | tree T buf `ESP+0x16c` → `EBX` |
| `0x45600a` | `0046fa40` S | tree S buf `ESP+0xec` → `EBP` |
| `0x456026` | `0046f910` Ry | angle `[ESP+0x44]` (= `df960(0,pi)` output), dest `ESP+0x1c8` |
| `0x456041` | `0046efc0` mul#1 | `ECX`=Ry result, push `EBP`=S, dest `ESP+0x120` |
| `0x456056` | `0046efc0` mul#2 | `ECX`=mul#1 result, push `EBX`=T, dest `ESP+0x54` |
| `0x45606a-0x4560a6` | `0046efa0` x4 | temp-buf teardown |
| `0x4560bd` | `00409060` | `(EAX=[ESP+0x30] model, 0, EDX=[ESP+0x54] composed buf)` |
| `0x456168` | `0046f9f0` T | startbanner: `(xform(FLD[EAX]-0.8), 00436610, EBX)`; submit `0x45618e` |
| `0x4561f5` | `0046f9f0` T | frame block: `(f+g, m, h)` (see §3); node `0x456269`, submit `0x456404` |
| `0x4565a2` | `0046f9f0` T | judgetower loop (5x): `004351a0` min-select feeds T; submit `0x4565c4` |
| `0x455eb0` | `00409060` | `(EBP handle, 0, NULL)` — identity path |

Pseudocode head (verbatim, `ev_008854d7...`): `void FUN_00455ba0(param_1, param_2, param_3)`;
`*(in_ECX+0x58) = param_1` (hill ptr); season selects lighting + tree/tower strings;
`param_3` gates the `0x4561a4` block. Full text 15102 chars, not reproduced.

## 3. Observation: frame-block placement math (`0x4561a4-0x456269`)

Instr window (this dossier, verbatim sequence):

```
0x4561b2 FSTP [ESP+0x14]            ; f = *EDI via 00436610 (EDI = hill+0x1b8 via 00435cb0)
0x4561b8 CALL 00435740              ; g = min2-combine(hill), ECX=EBP=hill
0x4561bd FADD [ESP+0x14]            ; f+g
0x4561c3 FSTP [ESP+0x10]
0x4561c7 CALL 00408860              ; h = *(EDI+4) = [hill+0x1bc], ECX=EDI
0x4561dc CALL 00435140              ; m = 00435140(hill, f+g, h)
0x4561f5 CALL 0046f9f0              ; T(f+g, m, h) into [ESP+0x5c]-buf
0x4561fa PUSH 0xb8 / CALL operator_new
0x456269 CALL 00423a20              ; scene node (copies 16 words, §4)
```

Submit `0x456404`: `00409060(EBP, 00408960(buf)=[buf+0x8c], [ESP+0x54]-T-buf)`.
Only site with nonzero `param_2` (cf. `evidence/00409060_submit.md` §3).

## 4. Observation: consumers copy, never transform

- `FUN_00423a20` (1973 B, `ev_22ecfe6b...`): copies 16 dwords
  `[param_5+4..0x40]` → `[ECX+2..0x11]`, then `in_ECX[0xf] = param_1 + in_ECX[0xf]`
  (one scalar add of a stack float onto slot 15/translation-x slot); `root` string;
  callees incl. `0046eec0/0046efa0/0046f200`. Callers: `00455ba0` only. No rotation/scale.
- `FUN_00409060` (878 B, `ev_9de90fef...`): copies at most ONE 16-dword matrix
  `[param_3+0x4..0x40]` → fresh `0x44` object (redundant double-copy loop), then
  `0xC`-node attach carrying matrix + optional tag. Zero float ALU in 270 insns
  (see `evidence/00409060_submit.md` §5). Callers (7): `0040c970, 00455ba0,
  00456c70, 00456d80, 00456e90, 00456fa0, 00507710`. So composition happens in
  `00455ba0` BEFORE submit; submit only transports.
- Sole caller of `00455ba0` is `FUN_00463840` (643 B, `ev_9c894e64...`):
  `FUN_00455ba0(param_1,param_3,param_4)` first, then string/UI plumbing
  (`00437a20/00437b40/0045ad30/0053cc70/00467380`), `00466a20` string assign,
  `0045a780/0045a7c0/0045a7a0` stores. No float combine of meshes.

## 5. Observation: terrain-vertex writes (`FUN_004348a0`, 522 insns)

Fresh: analyze `ev_ae091b9c03fd91e90073d67c22156016d593e35263a1ff3d96c9ebe0458daad6`;
instr `ev_94f24797617f7e2d155cf2a6de1b2b898ad4d4cad08ecb799f335d901343720a`.
Body `0x4348a0-0x434fe9`, 1866 B, sole caller `00436620`.

- Setup: `004df840` RNG seed; 8-tap tables (`004df9a0/004df960` per tap);
  grid via `0059e643` x2 + `__ftol` (cols/step/base); rows fixed 61.
- Per-vertex (`0x434b51-0x434dcb`): coords (FILD col/row FMUL step FADD base) →
  `CALL 00434ff0` base → guard adjusts (`004de3e0` xforms, `00468310/00468340/
  00468360` clamp/min/max) → cosine noise → sin-tail weight → scalar height `v`.
- Write: vector at `[EBP+0x74]` (begin) / `[0x78]` (end) / `[0x7c]` (cap):
  `00475330` growth at `0x434e21/0x434e39/0x434e53/0x434ecd/0x434ef8/0x434f31`,
  `0059c120` free at `0x434e71`, pointer rotation `0x434e84-0x434eae`,
  `ADD [EBP+0x78],0x4` at `0x434f1c`. No matrix call in callee set; no
  `0046f9f0/0046fa40/0046f910/0046efc0` anywhere in body. Transform at write: NONE.
- Callees (19): `00434ff0/00435740/00435770/00468310/00468340/00468360/
  00475330/004de320/004de350/004de3e0/004df7e0/004df830/004df840/004df960/
  004df9a0/0055b490/0059c120/operator_new/__ftol/0059e643`. Strings: none.

## 6. Observation: `FUN_00457110` is not mesh placement

Fresh: analyze `ev_22c4ae8986fd71006a2e78006c30efaae9d6e87e29e01686266cb5fbd5e90e90`
(4003 B, `0x457110-0x4580b2`, sole caller `004570b0`). Head: float lerp on
`[ECX+0x1b4]` toward `[ECX+0x1b8+DAT_0061b8a8*4]` (`fVar3 = fVar2*param_1*10.0`,
ABS-compare branch), then `switch(DAT_0061b8a8)` storing `00538660` takeoff-marker
triples at `[ECX+0x190..0x1b0]`. Callees incl. `0046efc0/0046f8a0/004de3e0/
004351a0/00538660/00538680/005386a0/005388f0`. Inference: per-frame animation/marker
consumer, not a strip-frame combiner. Full role untraced.

## 7. Callers / callees / strings (consolidated)

- `00455ba0` callees (61, `ev_008854d7...`): matrix `0046f9f0/0046fa40/0046f910/
  0046efc0/0046efa0`, strips `00435740/00435140/004351a0/00434ff0/00435600/
  00436610/00435c00/00435c40/00435c60/00435ca0/00435cb0`, submit `00409060`,
  node `00423a20`, getters `00408860/00408870/00408880/00408890/004088a0/
  00454070/00408960`, models `00406450`, misc `0046e2e0/0046e300/0047dbd0/
  004de3e0/004df960/...`. Callers: `00463840` only.
- Strings in `00455ba0` (14): `Materials\material1.txt`, `Textures\sky-winter/
  summer.png`, `3DModels\tree-summer/winter-model.txt`, `startbanner-model.txt`,
  `judgetower-summer/winter-model.txt`. Frame-block path carries NO asset string
  (variant/child model — carried U4).
- `004348a0` strings: none. `00423a20` strings: `root`. `00409060` strings:
  `Invalid data exception` x2.

## 8. Inference (labeled)

- I1: scenery world position = strip-derived scalars through T (frame block) or
  R×S×T chain (tree loop); `00409060`/`00423a20` only transport. Firm: call-site
  push order + zero-ALU submit scan.
- I2: terrain vertices live in builder-local frame; cross-mesh (29 m anchor gap)
  resolution is downstream of `004348a0` (render or an unmapped reader of the
  `[0x74/0x78/0x7c]` vector / hill slots `+0x50/+0x58/+0x60/+0x68`). The vector
  object identity (which hill slot owns `[EBP+0x74]`) is by slot convention, not
  proven in this dossier.
- I3: `00457110` consumes takeoff markers (`00538660` stores); not the combiner.

## 9. Unknowns

- U1: `0046efc0` operand order (which of ECX/param_2 is left) → tree-loop product
  order (`R×S×T` vs permutation) unproven. Blocks exact tree-frame reimplementation.
- U2: `00409060 param_1` producers (`[ESP+0x30/0x44/0x3c]`, `EBP`) — model vs node
  handle untraced; `ECX=[ESI+0xac]` context type untraced.
- U3: frame-block placed object identity (model chain `00463ed0…00422b50`, no asset
  string on path) — which visible object the `(f+g,m,h)` frame positions.
- U4: terrain-vector owner slot + downstream readers of hill slots
  `+0x50/+0x58/+0x60/+0x68` and of the `[0x74/0x78/0x7c]` heightfield — the actual
  world-frame composition site. Data-xref sweep not done.
- U5: `00457110` full role (switch arms beyond head, `0046f8a0/0046efc0` use inside);
  only head pseudocode transcribed here.
- U6 (method): conclusions from `analyze_function` pseudocode + targeted
  instruction windows (868/522/270-insn bodies); no per-block audit beyond cited
  sites. Ghidra text assumed faithful.

## 10. Next step (ONE)

- Reimplement FIRST: frame-block translation composer — pure
  `place_frame(f, g, m, h) -> Mat4 = translation(f+g, m, h)` (single `0046f9f0`
  call, no multiply-order ambiguity unlike the tree loop).
- Test that proves it: drive with observed strip-reader outputs (stub
  `f=*hill+0x1b8`, `g=00435740(hill)`, `m=00435140(hill,f+g,h)`, `h=[hill+0x1bc]`);
  assert submitted buffer words equal `translation(f+g, m, h)` bit-exact
  (slots 12/13/14 = `f+g`/`m`/`h`, rest identity words) and that `00409060`
  receives exactly that buffer as `param_3` at `0x456404`. Fails if any hidden
  scale/rotation contaminates the frame-block path.
- Do NOT start with the tree-loop `R×S×T` chain (blocked on U1) or terrain-vertex
  placement (blocked on U4).
