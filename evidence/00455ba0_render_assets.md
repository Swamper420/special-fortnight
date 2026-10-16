# FUN_00455ba0 — render-asset loader + scenery frame placement

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Parent dossiers:
`evidence/strip_slot_readers.md` (00455ba0 role: render-asset loading),
`evidence/00436620_placement_recon.md` U4 (placement downstream),
`evidence/00434ff0_terrain_base.md` (00434ff0 semantics, 00455ba0 caller).
Method: `analyze_function` + `read_function_instructions` (868 insns).
No Rust transcribed; `engine/src/mesh.rs` untouched.

## 1. Claim

`FUN_00455ba0` (3081 B, `0x455ba0`–`0x4567a8`,
`ev_a6d83c30d189d7b64683ac44027665ea10683bee1884f5f6a1964e6890c070f8`;
instr `ev_b6c83121d7aacb859dc888def7addd2d8ce672d623da471955ad3544649fe30c`)
loads render assets (models/materials/textures) AND composes world-frame
placement matrices from strip-derived scalars. Correction to
strip_slot_readers §3 ("not frame placement"): no strip *vertex iteration*,
but per-object 4x4 frame composition IS here — translation/scale matrices
built by `0046f9f0`/`0046fa40` over `0046ef20`, fed by strip-reader outputs
(`00435740`, `00435140`, `00434ff0`), submitted via `00409060` / scene node
`00423a20`. Relative frame placement (placement-recon U4) is thus PARTLY
closed for scenery objects; terrain-mesh vertex placement still unmapped.

## 2. Observation: entry convention

- `in_ECX` = owner object (`ESI` = ECX after prologue, `0x455bbe`).
- `EBP = [ESP+0x40c]` = param_1 = hill object (observation: first stack
  arg; stored `MOV [ESI+0x58],EBP` at `0x455be7`).
- `[ESP+0x410]` = param_2 = season flag (`TEST AL,AL`; 0 = winter strings,
  nonzero = summer strings; also picks lighting constants).
- `[ESP+0x414]` = param_3 = gate for the `0x4561a4`-block branch
  (`MOV AL,[ESP+0x414]; TEST; JZ 0x45643f` at `0x456193`–`0x45619c`).
- Hill pointer reaches strip readers two ways (observation, asm):
  `MOV ECX,EBP` before `00435cb0`/`00435740`/`00435140`
  (`0x4561a2/0x4561b6/0x4561da`); `MOV ECX,[ESI+0x58]` before `00434ff0`
  (`0x455f73`, `0x4564fc`). Same pointer (stored at entry).
- Sole caller: `FUN_00463840` (matches strip_slot_readers §3).

## 3. Observation: strip slots read (all via callees, none inline)

Body has NO direct `[X+0x50/0x58/0x60/0x68]` hill-slot reads (observation:
only `+0x58` hits in 868 insns are the `[ESI+0x58]` hill-pointer
store/loads above; other `+0x50` hits are `[ESP+0x..]` locals). Slots read
through (prior dossiers for callee internals):

- b50+b60 via `FUN_00435740` (`0x4561b8`, ECX=hill) — min2 combine.
- b50+b58 via `FUN_00435140` (`0x4561dc`, ECX=hill) — fresh evidence
  `ev_771048828e4fab075b1cf5077bf5e434c169e0ffaea589b49d476b24f2a419a9`:
  `de380` test → `|p2|` vs `de3e0` compare → `de3e0` result or `004351a0`
  grid fallback.
- b60+b68 via `FUN_00434ff0` (`0x455f78`, ECX=`[ESI+0x58]`) — terrain-base
  eval; result gated `FCOMP [0x5cea90]=5.0; TEST AH,0x41` (`0x455f7d`–`0x455f88`).
- `FUN_004351a0` grid helper called directly at `0x455f97`, `0x456550`,
  `0x456589` (tree/judgetower loops).

## 4. Observation: frame/matrix placement IS here (scenery)

- `FUN_0046f9f0` (79 B, `ev_76dee726...`): translation-matrix composer —
  calls `FUN_0046ef20(1,0,0,0, 0,1,0,0, 0,0,1,0, p2,p3,p4, 1)`.
- `FUN_0046fa40` (70 B, `ev_60348d98...`): scale-matrix composer —
  calls `FUN_0046ef20(p2,0,0,0, 0,p3,0,0, 0,0,p4,0, 0,0,0, 1)`.
- `FUN_0046ef20` (123 B, `ev_3ff5fe4d...`): 4x4 matrix-object constructor —
  writes 16 dwords into ECX object + vtable `PTR_FUN_005cf270`.
- Placement block (`0x4561a4`–`0x456269`, param_3 != 0 path), asm-observed:
  `EDI = hill+0x1b8` (`00435cb0` = `return ECX+0x1b8`, 7 B,
  `ev_ac087183...`); `f = *EDI` (`00436610` = `return *ECX` float, 3 B,
  `ev_28c55364...`); `g = 00435740(hill)`; `FADD` → `f+g`;
  `h = [hill+0x1bc]` (`00408860` = `return *(ECX+4)`, 4 B,
  `ev_1767e095...`, ECX=EDI); `m = 00435140(hill, f+g, h)`;
  `0046f9f0(buf, f+g, m, h)` → matrix with translation `(f+g, m, h)`;
  `operator_new(0xb8)` + `FUN_00423a20` scene node (1973 B,
  `ev_22ecfe6b...`, string `root`, copies matrix words into new object);
  `FUN_00409060(node, 00408960(buf)=[buf+0x8c], buf)` render submit, result
  refcount-stored into `[ECX+0xec/0xf0]`.
- Tree loop (`00435c00` count / `00435c40` iterate): per-tree `00434ff0`
  gate (> 5.0) → `004351a0` → translation matrix `0046f9f0` + scale matrix
  `0046fa40` → `00409060(tree-model, ...)` (`0x4560bd`).
- Startbanner (`0x456122` block): `00435600` → `FLD [EAX]; FSUB
  [0x5ceba4]` (−0.8, decompiler `*pf - 0.8`) → `004de3e0` xform →
  `00436610` → `0046f9f0` → `00409060(startbanner-model)` (`0x45618e`).
- Judge-tower loop (`fVar6 = 0..5`, 5 placements): `00436610`,
  `0047dbd0`, `004de3e0`, `004351a0` min-select, `0046f9f0`,
  `00409060(judge-model)` (`0x4565c4`).
- Getter family (all 4 B, pure): `00408870`/`00408880`/`00408890`/
  `004088a0` = `*(ECX+0xc/0x10/0x14/0x18)`
  (`ev_f69b70aa.../ev_5357fab8.../ev_9f9817fe.../ev_0e66ffc5...`);
  `00454070` = `*(ECX+8)` (`ev_957f232b...`); `00408960` = `*(ECX+0x8c)`
  (`ev_37911c62...`).

## 5. Observation: asset loading (non-placement)

- Strings (14 refs, `ev_a6d83c30...`): `Materials\material1.txt`;
  `Textures\sky-summer.png` / `sky-winter.png` (season-selected);
  `3DModels\tree-summer/winter-model.txt`,
  `startbanner-model.txt`, `judgetower-summer/winter-model.txt`
  (season-selected); models loaded via `FUN_00406450` × 3, materials via
  `FUN_0040ca10(0x43938000, sky-png, material1.txt)`.
- Lighting presets by season: `0046e2e0(1,1,1,1)` winter vs
  `0046e2e0(0.3,0.4,0.45,1)` + `0046e300(0.6,0.7,0.65,1)` summer
  (decompiler float constants; exact push order in asm `0x455bec`–`0x455c51`).
- Refcount-store idiom repeated for `[ECX+0x7c/0x80]` (material),
  `[0xac/0xb0]`, `[0xec/0xf0]` (placed nodes): release-old
  (`*ref--`, virtual dtor if 0, `0059c120` free), store-new + fresh
  `operator_new(4)` refcount. Observation: shape only, not transcribed.

## 6. Recommendation: ONE next target

`FUN_00457110` — unchanged from strip_slot_readers §5: sole consumer of
the b58/b68 predicate pair, unmapped, no strings. 00455ba0's placement
role is now closed for scenery frames; 00457110 remains the only
strip-gated consumer with unknown role (placement gate? physics?
export?). Not `FUN_00409060`: larger surface (878 B) and its submit
role is sufficiently established by call pattern here.

## Unknowns

- U1 (open): `00409060` internals (878 B, `ev_9de90fef...`, strings
  `Invalid data exception` × 2, throws via `0041ed70`+`__CxxThrowException`
  if `[ECX+0xd5] != 0` or `004041f0` false) — submit role is inference
  from call pattern (model handle + matrix buffer + tag), not pseudocode.
- U2 (open): `0046f910` / `0046efc0` / `0046efa0` roles (matrix-stack /
  render-state ops in tree/banner loops; callees-only, not analyzed).
- U3 (open): `00423a20` full semantics beyond matrix-copy + `root`
  (1973 B; only head transcribed); `00422b50` + `004364f0`–`00436520`
  chain role in the param_3 branch (model-variant selection? inference only).
- U4 (open): which placed object the `0x4561a4` block positions (model
  handle built at `0x456207`–`0x456269` via the `00463ed0…00422b50`
  chain; no asset string on this path — variant/child model).
- U5 (carried): terrain-mesh vertex placement / 29 m anchor gap — NOT in
  00455ba0 (no vertex iteration; matrices are per-object frames only).
  Placement-recon U4 now narrowed to terrain mesh, not scenery.
- U6 (carried): hill-base register proof is now direct (param_1 → EBP →
  ECX), closing strip_slot_readers U1 for the 00455ba0 call sites only;
  `004348a0`-EBP / `00434ff0`-ESI bases remain inference.
- U7 (method): body conclusions from `analyze_function` pseudocode +
  targeted instruction context (`ev_b6c83121...` full-text scan for
  slot/matrix/float patterns, 868 insns); full-instruction read done once,
  no per-block audit trail beyond cited sites.
