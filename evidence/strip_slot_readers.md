# Strip-slot readers: consumers of hill+0x50/+0x58/+0x60/+0x68

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`, SHA-256 `3619dcbd...`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`. Parent dossiers:
`evidence/00436620_composition.md` (slots b50/b58/b60/b68 co-reside in one
hill object built by `FUN_00433a60`, strips allocated by `FUN_004dd5c0`),
`evidence/00466a20_consumer.md` U4 (escalation source),
`evidence/00436620_placement_recon.md` section 4 (reader sweep tasked here).
Method: `read_function_instructions` slot-pattern scan + `analyze_function`
pseudocode/callers/callees/strings. No Rust transcribed. `engine/src/mesh.rs`
untouched.

## 1. Claim

Four small functions read the hill strip slots directly; all do scalar
range/min/max/predicate combines, none places frames. The terrain builder
itself also reads b50/b60 inline. Downstream consumers split three ways:
build-time terrain combine (`004348a0`), scenery placement (`0043c120`
pillars), render-asset loading (`00455ba0`), plus one unmapped consumer
(`00457110`, sole caller of the b58/b68 predicate pair). The 29 m anchor gap
is in none of these; it resolves further downstream (see recommendation).

Slot base register = hill object is inference from entry convention
(`ECX` = hill object at builder call sites, composition dossier) plus slot
match (`+0x50/+0x58` are the exact inrun-builder emit slots,
`+0x60/+0x68` the landing-builder slots). Offset reads themselves are
observation.

## 2. Observation: direct readers

- `FUN_00435740` (39 bytes, `ev_a133d803b0d2472992c42ed72dee2e557292a2dd8f2b02a1525c6a1ae307e055`;
  instr `ev_d03460c8e4b9d4c8d78b6ea4aa08d7d3c0ddfee6d63be2ef8a8f98b9f32e1cf3`):
  `MOV ECX,[EAX+0x60]` + `MOV ESI,[EAX+0x50]`, chained
  `FUN_004de320` calls, result into `FUN_00468340` (min2, 9 insns,
  `ev_100c6f814b93ff7280291c0222a5fc44cb989498809b85e369c3a3a682c2546d`).
  Reads b60 + b50. Callers (3, `ev_5aa003983ceef87609fe393082c039522e5f6d42309a6ccf7a5275044a55d9fd`):
  `0x4348a0` (terrain builder, 2 sites), `0x43c120` (pillars),
  `0x455ba0` (render assets). No strings.
- `FUN_00435770` (15 insns, `ev_d66bd1dc5deab63b520f3b17a68006fc8eb0b15966195f55f54ce82f6adb4328`;
  instr `ev_a7d63f24ff8431275aef363f291acaf3da29110a926fff44f504d846e8cb8829`):
  identical shape on b60 + b50 but `FUN_004de350` chain into
  `FUN_00468360` (max2). Caller (1,
  `ev_56717b004dc57788252754a27c23253b361b34cb51072db6d1a26d8bbfe5526e`):
  `0x4348a0` only. Twin of `00435740`, build-time only.
- `FUN_004357a0` (39 insns, `ev_dec4855e23df2b6b27beb7717794b0d671c06d630ea4012f359db71561458c68`;
  instr `ev_1f6b7f211c7040c1c5ca1f6f700bcb0ef2124e7eb6b9304a113eac255671ed03`):
  reads `[ESI+0x58]` (b58) 4x; range/xform predicate via
  `004de320/004de350/004de3e0` with x87 `FCOMP/FNSTSW` compares
  (`TEST AH,0x41` / `TEST AH,0x1`), returns bool (`RET 8`). Caller (1,
  `ev_ef38492e4c4ae326ce6e7573c2a00088cd6582bd3604a5ca4bd5173d3b4cd2c8`):
  `0x457110` only.
- `FUN_00435810` (39 insns, `ev_515fb6fcc8b275fae63f966f107f38c26255a6e81bfa4ebe64fb7143263453a3`;
  instr `ev_72b087fc098dfec0aa99948cedcea88104ccf40403078ec5f0a44b4d5d34bb47`):
  identical predicate on `[ESI+0x68]` (b68). Caller (1,
  `ev_f2af7535e1360e6a2c200c2e6a6fb0aa0d44fef8e27dc1c220b24fe71d38e146`):
  `0x457110` only. Twin of `004357a0`.
- `FUN_004348a0` (terrain builder) reads slots inline too (522 insns,
  `ev_e1d67596da7c48592483b73f26bef4a9b2f205e9440c1d4cf7d3ebc2d9e3342b`):
  `[EBP+0x60]` at `0x434a14/0x434a20/0x434ba2`, `[EBP+0x50]` at
  `0x434a2c/0x434a38/0x434be5`. Base `EBP` = hill object is inference
  (needs pseudocode check); offsets exact. Also hosts the two
  `00435740/00435770` call sites.
- `FUN_00434ff0` (terrain base, 75 insns,
  `ev_0433699bb331d66f116383bad3e1172ddab9753a961077637c6c7b0638496952`;
  instr `ev_66d68e1d1ab259c4e460e82dca0bcc0da1477faaef2804396b58aa4ae350f8d7`):
  loads `[ESI+0x68]` (`0x435014`) and `[ESI+0x60]` (`0x435018`) as the
  `this` pointers for its `de350/de320/de3e0` chain (decompiler renders them
  as float args; asm shows the strip loads). Callees
  `00468310/00468360/004de320/004de350/004de3e0`, no strings. Callers:
  `0x4348a0`, `0x455ba0`. Consumes b60/b68. Matches `mesh.rs` terrain-base
  record (branch shape, clamp/max).
- `FUN_00435140` (36 insns,
  `ev_402df928708fd27d5821c394cdaedfa5ba2d6aeafbd85be1e492337fe8020f32`;
  instr `ev_cbd97feb680613b0c7fb81e6814e40cac74af753bbd9e66cf792b1b4947166e0`):
  reads `[ESI+0x50]` (`0x43514c/0x435176`) and `[ESI+0x58]` (`0x43515c`);
  dispatches via `004de380/004de3e0` test into grid helper `FUN_004351a0`.
  Caller (1): `0x455ba0`. Consumes b50/b58 on the render-asset path.
- `FUN_004351a0` (839 bytes, `ev_b4a5c82b1fa25c4590f7d951393436a4ff90d0fe343aca3e70adb89bb9703e53`):
  NOT a direct slot reader (takes floats, min/max grid math + takeoff
  markers `00538660`); noted because all three downstream consumers
  (`0x43c120/0x455ba0/0x457110`) call it. Secondary, not a reader.

Callee roles used above: `004de320/004de350` = strip lo/hi getters,
`004de3e0` = strip xform (per `engine/src/mesh.rs` terrain-base record);
`00468340/00468360` = min2/max2 (9-insn / twin, x87 `FCOMP/FNSTSW/TEST`
shape; max2 also matches `mesh.rs` `max2` NaN mapping). Strip-emit writers
(`004dda60/004ddae0/004dd970/004ddf10/004ddcb0`) are called ONLY from the two
builders (`ev_df733611...`, `ev_77072012...`, `ev_3ac35511...`,
`ev_46a4fb4e...`, `ev_70c97af2...`) — readers go through slot pointers, not
the emit API.

## 3. Observation: downstream consumer roles (render? export? physics?)

- Build-time: `FUN_004348a0` (terrain builder) combines b50/b60 scalars
  (`00435740/00435770`) and reads both slots inline. No frame transform.
- Scenery placement: `FUN_0043c120` (4367 bytes,
  `ev_774882003a1acfd4fe12f79904f06e77b526bdc212226efcb4c101ba274d6b4c`;
  strings `fpillar/bpillar/lpillar/rpillar`) calls `00435740` + `004351a0`
  (+ xform `004de3e0`). Reads strips to place pillars. Caller `0x438990`.
  Inference: scenery-placement reader.
- Render-asset loading: `FUN_00455ba0` (3081 bytes,
  `ev_a6d83c30d189d7b64683ac44027665ea10683bee1884f5f6a1964e6890c070f8`;
  strings `Materials\material1.txt`, `Textures\sky-*.png`,
  `3DModels\*-model.txt`) calls `00435740` + `00435140` + `00434ff0`.
  Reads b50/b60/b58 + terrain base while loading models/materials/textures.
  Caller `0x463840` (whose callees also include string plumbing `00466a20`,
  `ev_9bd9f0d3...` family context). Inference: render-side asset setup, not
  frame placement (no strip vertex iteration observed in its callee set).
- Unmapped: `FUN_00457110` (4003 bytes,
  `ev_22c4ae8986fd71006a2e78006c30efaae9d6e87e29e01686266cb5fbd5e90e90`;
  no strings; caller `0x4570b0`; callees `ev_8ae4e1fd2f5309c2f92a7b62bb914a16b21654e2195fa6bce9ac5b8abcc903aa`):
  sole caller of b58/b68 predicates (`004357a0/00435810`) plus grid
  `004351a0`, `004de350/004de3e0/004de430`, takeoff markers
  (`00538660/00538680/005386a0`), `00451c20`. Inference: strip-gated logic
  with marker output; physics vs placement vs export undetermined.
- Holder, not reader: `FUN_004ece10` (`ev_ec34c0994196691114cd5eb4cb80d54a3c7674ae906761c72d928835d0928ede`)
  creates a hill object via `FUN_00433a60` (`operator_new(0x288)`) but never
  calls `FUN_00436620`; stores the pointer at container `+0x78`
  (`in_ECX[0x1e]`). Seventh `00433a60` caller
  (`ev_4a3eb31112ff56f29c2fe22343bbb97ce5847ad328c579f982c99b9ea7957cda`:
  `0x4444a0/0x4a4210/0x4dcd40/0x4ece10/0x4ed6a0/0x517ff0/0x542450`).
  Ownership path, no slot reads.

## 4. Observation: negative results

- Hill-load wrappers (`004444a0` etc.) contain no slot reads (parent
  dossiers: zero float ops in the two scanned bodies; shared callees are
  string/file/path helpers).
- The float-heavy `0x439370`-`0x4449a0` cluster (`FUN_0043a420`
  `ev_c72086bba3a58927bbf1dad0929361387ed2d381b9662ec5b64bfa79c009345c`,
  `FUN_00440690` `ev_8e106b87ec5662acb156ee33abfde4ca3258a3d86c7c4d0ccc32b378372ee640`,
  `FUN_00441170` `ev_b1ce03cb0e78408ea522a891f45e84e3f75a687b01c3e31ce3436b7d724b8f4d`,
  `FUN_00441f80` `ev_35d62a9a4dd0a4a068e6af1ce2c3761ae72d1f1d4e0a2343087d1a7f13ddc009`,
  `FUN_00439370` `ev_46e42b7399facfe8c0172a0cb4d419295d5304fdf3497e29cda6fd5c65b01f14`,
  `FUN_0043ecf0` `ev_d1360082acb3abad511f33b1d80a96c7b20b5ece9823df92e91ef346cc8724f2`,
  all callees of `FUN_00438990` per `ev_9bd9f0d32aff10b8753d8bc2851d2a6565813b5ebce48d1a58841d6bc00e68ed`)
  reads `[X+0x54]` (+ `[X+0x58]` flag byte) on a DIFFERENT object, never
  hill `+0x50/+0x58/+0x60/+0x68` (non-ESP hits are `+0x54` only; `+0x50` etc.
  hits are `[ESP+..]` locals). Not hill-strip readers; input object unmapped.
- `FUN_00438990` itself: 50 insns (`ev_a9506f3ae31d0e93687a5211707595804cbe48e712aa53cb484e9c791e62e90d`),
  single slot-like access is a byte WRITE `[ESI+0x58]`. Not a reader.
- `FUN_004570b0` (caller of `00457110`): 28 insns
  (`ev_e1484b634c7ad755a277505f5d6bab67d2598e89d4a4bb48a81f8db975efaf35`),
  zero slot reads. Pure dispatcher.
- `FUN_004449a0` (a `004de320` caller): 495 insns
  (`ev_349c0facf2e6e7382f5fca50305494a72876f6192251d2b6f1582d695bc9824e`),
  zero slot-pattern hits. Its `de320` input is not hill-slot-derived.
- Scenery leafs `00435880/00435990/00435aa0` (instr
  `ev_e3c2b80d.../ev_3eebf68a.../ev_6a2710d9...`) touch `+0x218`-family
  slots of their own object. Not strip readers.

## 5. Recommendation: ONE next target

`FUN_00457110` — sole consumer of the b58/b68 predicate pair, plus grid
`004351a0`, xform `004de3e0/004de430`, and takeoff markers; 4003 bytes,
unmapped, no strings to pre-classify. Analyzing it answers what the b58/b68
containment tests decide (placement gate? physics gate? export filter).
Not `FUN_00438990`: bigger surface, no direct slot reads of its own.

## Unknowns

- U1 (open): base-register proof — `EBP` in `004348a0`, `ESI` in
  `00434ff0/00435140`, `EAX/ECX` in `00435740/00435770/004357a0/00435810`
  are hill-object pointers by slot-match + entry-convention inference only;
  no per-site dataflow proof that each base is the `00433a60` object.
- U2 (open): which `de320` vs `de350` input (b60 vs b50) feeds min vs max in
  `00435740/00435770` (decompiler drops the `ECX`-passing `MOV`s); which of
  `[ESI+0x60]/[ESI+0x68]` feeds which getter in `00434ff0` branch A.
- U3 (open): `FUN_00457110` role (physics/placement/export) and what its
  `00451c20`, `004de430`, `00453860`-family outputs do with predicate results.
- U4 (open): strip vertex-iteration API — no function yet observed walking
  strip vertices into world space; the 29 m anchor gap still has no
  render-side resolution. The `+0x54`-object cluster (`00438990` callees)
  is the alternate lead, input object unmapped.
- U5 (carried): terrain heightfield output slot offset(s) still unmapped
  (composition U1); relative frame placement still unmapped (composition U4
  / placement-recon U4 / consumer U4 — narrowed, not closed).
- U6 (method): slot scan covers `read_function_instructions` text for
  `[reg + 0x50/0x58/0x60/0x68]` over ~20 targeted functions (strip-API
  callers + wrapper-relative candidates), not the full 624-procedure binary;
  an indirect reader (slot copied through an unexamined intermediary) would
  not match.
