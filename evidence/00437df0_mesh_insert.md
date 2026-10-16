# Mesh insert `FUN_00437df0` → hill vector `+0x21c/+0x220/+0x224`

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
x86 PE, Ghidra 12.1.2. Parent: `evidence/heightfield_consumer.md` §4–5
(U1: suspected insert) and `evidence/00435880_scenery.md` (leaf wrapper).
Dossiers below are Ghidra representations, not original source.

Primary dossier: `analyze_function(FUN_00437df0)`
(`ev_c7ea47d0fc574ab5ff47b9f6e8afff2569367eabfe29b80bc9a8a26096300784`).
Body: single range `0x437df0–0x438069`, 634 bytes, non-contiguous=false,
contains_entry=true.

## 1. Claim

`FUN_00437df0` is the insert (append at observed call site) for the
first of the three hill-object mesh-output vectors: triple
`hill+0x21c` (begin) / `+0x220` (end) / `+0x224` (cap), addressed as
`ECX+0x4/+0x8/+0xc` with `ECX=hill+0x218`. Elements are 8 bytes:
`{+0x0: u32 word0 (node/object ptr), +0x4: u32 word1 (refcount-block
ptr)}` with shared-ownership copy/release semantics (copy
`FUN_004306e0`, destroy `FUN_00438570`, assign `FUN_00438780`). Sole
caller is the `stairs` leaf wrapper `FUN_00435880`, itself called only
from composer `FUN_00436620` at `0x4370ac`. Sibling inserts
`FUN_00438070` / `FUN_004382f0` serve vectors `+0x22c/+0x230/+0x234`
and `+0x23c/+0x240/+0x244` via sibling leaves `FUN_00435990` /
`FUN_00435aa0` (same composer). This confirms the suspected insert
mapping; the `+0x21c`-family (not `+0x74`) is the true mesh path.

No engine code edits: mapping only, evidence first. No new pure
fragment transcribed (insert body is allocator/branchy; element
copy `FUN_004306e0` is 25 bytes but transcription deferred — see U4).

## 2. Observation: slot (caller side, proven)

Wrapper `FUN_00435880` (`ev_1c431808c9c2e304a8e360a94c5e9082bf34f771bb6236613de8b50d7b9f832a`,
instructions `ev_fb8138c89f7cb3791a90906544f1af9cfbd6a87cb3d13f63da3c9d980ee96e4a`):

- `0x43590f: MOV EAX,[EDI+0x220]` — insert position = current end.
- `0x435915: LEA ECX,[EDI+0x218]` — vector container (`EDI` = hill
  object, saved from `in_ECX` at `0x43589b: MOV EDI,ECX`).
- `0x435927 PUSH EDX(&local_14) / 0x435928 PUSH 0x1 / 0x43592a PUSH EAX /
  0x43592b CALL 0x00437df0` — `insert(pos, count=1, value)`.
- Decompiler renders `FUN_00437df0(*(in_ECX+0x220),1,&local_14)` where
  `in_ECX` is the *caller's* hill pointer (`EDI`); inside the insert,
  `in_ECX = EDI+0x218`, so `*(ECX+0x8) = [EDI+0x220]` = end.

Insert body slot usage (`ev_c7ea47d0...` assembly):

- `0x437dfd: MOV ESI,[ECX+0x8]` (end), `0x437df3: MOV EDX,[ECX+0xc]`
  (cap), `0x437e12: MOV EDX,[ECX+0x4]` (begin, realloc path),
  `0x437f13: MOV [ECX+0xc],EAX` / `0x437f22–0x437f2b` /
  `0x437f38–0x437f4c` (begin/end/cap rewrite after realloc),
  `0x43805d: ADD [ECX+0x8],EAX` (end += count*8, fast path).
- Hence container `ECX=hill+0x218`; triple at `ECX+0x4/+0x8/+0xc` =
  `hill+0x21c/+0x220/+0x224`.

Sibling slots (same shape, observed same session):

| Insert | Wrapper (sole caller of insert) | Vector ECX | Triple (begin/end/cap) | Composer site |
|---|---|---|---|---|
| `00437df0` (`ev_c7ea47d0...`) | `00435880` (`ev_1c431808...`) | `EDI+0x218` (`0x435915`) | `+0x21c/+0x220/+0x224` | `0x4370ac` |
| `00438070` (`ev_4a79a6716c9a162d3280111e39dd0213aedc798978c4d5d9b80c0be131c74b68`) | `00435990` (`ev_51c3e80a82908ea9d6f5db095926d2cb5ad5b522baf0906d6c2817b1ad942684`: `LEA ECX,[EDI+0x228]`, pos `[EDI+0x230]`) | `EDI+0x228` (`0x435a25`) | `+0x22c/+0x230/+0x234` | `0x4371d2` |
| `004382f0` (`ev_5f299a6416f0aafdc9380c686f267e9dd0c77354ff284f5354408fa42f01e330`) | `00435aa0` (`ev_da4cb9b60a0c0900981d1482bc1519708c151ab504f696576ee51970df348f62`: `LEA ECX,[EDI+0x238]`, pos `[EDI+0x240]`) | `EDI+0x238` (`0x435b49`) | `+0x23c/+0x240/+0x244` | `0x4377fd` |

Composer `FUN_00436620` call sites
(`read_function_instructions`, `ev_4d2c6e0a3e93bb4f34a7825be0f3937b0580707b71ff04f121db95aaf8f0724f`):
`0x4370ac: CALL 00435880`, `0x4371d2: CALL 00435990`,
`0x4377fd: CALL 00435aa0`. Each wrapper's sole caller is `FUN_00436620`
(per wrapper dossiers); `FUN_00437df0` incoming ref is exactly one:
`0x43592b` from `FUN_00435880` (same `ev_c7ea47d0...` dossier).

## 3. Observation: element shape/size (8 bytes, shared-ownership pair)

Stride/size evidence inside `FUN_00437df0` (`ev_c7ea47d0...`):

- `0x437e03: SAR EDX,0x3` (cap-end `>>3`), `0x437e3f: SHL EAX,0x3`
  (`count<<3` for `operator_new`), `ADD EDI/ESI,0x8` stepping
  (`0x437e73`, `0x437e94`, `0x437ecb`, `0x437f92`, `0x438005`, ...),
  `0x437f65: LEA EDX,[EAX*0x8]` — element size 8, count↔byte scaling
  throughout. Realloc path frees old buffer via `FUN_0059c120`.
- Element ops (all 8-byte `{dword,dword}`):
  - Copy `FUN_004306e0`
    (`ev_de3fa310209521f45049b116689cb758dcc2ff701b6a7bcc4510f15fa7721880`,
    25 bytes): `*ECX=*src; ECX[1]=src[1]; if (ECX[1]) INC [ECX[1]]`
    (`0x4306e8/0x4306ef/0x4306f4`). Observation: releasing-copy of a
    `{ptr, refcount*}` pair. 29 further callers (generic helper).
  - Destroy `FUN_00438570`
    (`ev_986b5721251de52fcab475b059bb6ba1376df411a59bf957caec2e5578d149b6`,
    74 bytes): `if (ECX[1] && --[ECX[1]]==0) { if (*ECX)
    {FUN_004360b0(); free(*ECX); } *ECX=0; free(ECX[1]); ECX[1]=0; }`.
    Called from `00437df0` (realloc cleanup) and unwind `005b222b`.
  - Assign `FUN_00438780`
    (`ev_826d7b368a3c6b0142e9625855e4915c3be9726274ba6153e8f257412b4eefd1`,
    134 bytes): same release as `00438570`, then if `src[1]!=0`
    `{ECX[1]=src[1]; *ECX=*src; INC [ECX[1]]}` else zero. Sole caller
    `00437df0`.
- Siblings use the same copy `FUN_004306e0` but their own
  destroy/assign pairs (`00438070`: `004385c0/00438810`;
  `004382f0`: `00438610/004388a0` — pseudocode-identical shape,
  different callees), i.e. three distinct element types sharing the
  8-byte `{ptr, refcount*}` layout but different payload dtors
  (`004360b0` vs `00436570` vs `00458de0` observed at wrapper unwind;
  payload-ctor variance `0x58/0x34/0x20` node sizes).

Dtor cross-check — hill dtor `FUN_00433d70`
(`read_function_instructions`,
`ev_acbadb342874e65970c183ef8946c2ef3c6997dfa770bffe705c72d5f21a5d9a`):

- `+0x23c` family: `0x433d98: MOV EBP,[ESI+0x240]` (end),
  `0x433d9e: MOV EDI,[ESI+0x23c]` (begin), loop `0x433db2–0x433dbf`:
  `CALL 00438720; ADD EDI,0x8`, then `0x433dc1–0x433dd9` free buffer,
  zero `+0x23c/+0x240/+0x244`.
- `+0x22c` family: `0x433ddf: MOV EBP,[ESI+0x230]`,
  `0x433de5: MOV EDI,[ESI+0x22c]`, loop `0x433df7–0x433e04`:
  `CALL 004386c0; ADD EDI,0x8`, then `0x433e06–0x433e1e` free, zero
  `+0x22c/+0x230/+0x234`.
- `+0x21c` family: `0x433e24: MOV EBP,[ESI+0x220]`,
  `0x433e2a: MOV EDI,[ESI+0x21c]`, loop `0x433e3c–0x433e49`:
  `CALL 00438660; ADD EDI,0x8`, then `0x433e4b–0x433e6c` free, zero
  `+0x21c/+0x220/+0x224`.
- Scalar-deleting variants `00438660`
  (`ev_e0ffa5e15c8c310c872bc519e5fcb42fd23f4c74a2894bf81612977c78b2cdc7`)
  and `00438720`
  (`ev_076cb910432e714dd6a4baedce99268c3d3cfcc596f3f6dac5085d67bc3ba576`)
  are body-identical to `00438570` plus a `param_1 & 1 → operator
  delete` tail; each called only from `00433d70`. Correction to
  parent trio label: the middle dtor entry is `FUN_004386c0` (called at
  `0x433dfa`); `0x438690` resolves to `FUN_00438660`
  (`ev_2c986fcca3ffa1e3d49acf88ab4a22ffbaacce9d9b13f2b6ee8b2644187414b9`),
  i.e. interior address, not an entry — `00438690` is not a function.
- Contrast `+0x74` vector (parent §2): freed with NO per-element
  dtors (`0x433ecc–0x433edf`), POD floats — structurally distinct from
  this family.

Pseudocode (insert fast/slow paths, `ev_c7ea47d0...`): capacity check
`(cap-end>>3) >= count` → in-place insert (memmove via `00517ca0`
when shifting within capacity, else copy-construct gap with
`004306e0` + assign with `00438780`) → `end += count*8`; else
`operator_new((old_count+max(count,old_count))<<3)`, copy-construct
prefix/gap/suffix with `004306e0`, destroy olds with `00438570`,
free, rewrite `begin/end/cap`. Standard vector-insert shape.
No strings referenced by `00437df0`.

## 4. Inference

`FUN_00437df0` confirmed as the `+0x21c`-family insert; the composer
feeds all three mesh-output vectors through the leaf wrappers, so any
heightfield-derived mesh data reaching render/file must cross one of
these three inserts (or the heightfield stays write-only scratch as
parent claims). Element payload type beyond `{ptr, refcount*}` (node
`0x58` bytes, ctor `FUN_00436050`
(`ev_841e8b010ff92bde6197a46cd04b51bfb88d80e4c773889da60ee2ef45af91df`))
remains unexamined — inference only.

## Unknowns

- U1 (open): payload layout of the `+0x21c` element node (`0x58`
  bytes; ctor `00436050` calls `00435cc0` twice unexamined; 4 floats
  at `+0x0..+0xc` via `00436020` per `00435880_scenery.md`).
- U2 (open): section tags / node sizes / payload dtors of the two
  sibling vectors (`00435990`: node `0x34`, ctor `00436550`, dtor
  `00436570`; `00435aa0`: node `0x20`, ctor `004365a0`, dtor
  `00458de0`) — tags not read here.
- U3 (open): whether `FUN_00437df0` is ever called with
  `pos != end` (splice) — sole observed call passes `end`; no other
  caller exists, so currently append-only in practice, not proven in
  general.
- U4 (method): no Rust transcription (insert + element helpers touch
  allocator/exception unwinding; only pure-fragment policy applies).
  `FUN_004306e0` (25-byte `{ptr,ref}` copy+INC) is the smallest proven-
  pure candidate if a future task needs it.
- U5 (carried): parent U2–U5 unchanged (other-wrapper `+0x74`
  coverage, 8-byte element payload types, indirect-read sweep,
  placement-U4 unknowns).

## NEXT TARGET (ONE)

`FUN_00436050` (node ctor for the `+0x21c` element, via `00435cc0` ×2)
— analyze it and `FUN_00435cc0` to recover the `0x58`-byte payload
layout, which is the remaining gap between this proven insert shell
and a transcribable mesh element.
