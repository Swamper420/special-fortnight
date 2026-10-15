# Mesh composition: `FUN_00436620` is a dispatcher, no placement transform inside

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE. Dossiers below are Ghidra 12.1.2
representations, not original source.

Primary dossiers: `analyze_function(FUN_00436620)` pseudocode+assembly
(ev_2352cfc0a62667e9c1355a274abf6e663dfecb54f35d9625bcf96a6b4cb52ef5),
same-procedure refs/callees/callers/strings
(ev_c396a14fe16e2c9f12f027213985f9cf0dddfe5e10fa0723ae62088028d6b48a).
Body: single range `0x436620-0x437a1f`, 5120 bytes, 126 basic blocks.

## 1. Claim

`FUN_00436620` applies NO relative-placement transform between the
inrun / landing / terrain meshes. It version-gates, walks the hill XML
(`inrun` → `dhill` → `terrain` sections), and calls each mesh builder
exactly once on the SAME hill object. The four profile strips
(b50/b58/b60/b68) plus the terrain heightfield therefore co-reside in
one object at fixed slots; how their SEPARATE local frames compose in
world space is still unmapped and lives outside this function.

## 2. Observation: dispatch shape (pseudocode + assembly)

Entry (observation, `0x436646`: `MOV EDI, ECX`): thiscall, hill
object in `EDI`. Exit (observation): two `FUN_0040fc70` calls then
`return FUN_004684f0()` — both 7-byte leaves, no callees, no strings
(ev_774a854ebbd913f3f8f23c149a797f3669526b7cd120f87fe4010e7239ced918,
ev_0c5aeb5c5bb12538c4634acd0db316e5cd3c0d4292d87a0e19206515ffab3765);
opaque epilogue, not mesh composition.

Sequence (observation, pseudocode + call-site assembly):

1. Two wide-string prefix copies (`0059ce28/00402d50/0059def4`
   prologue, `0x436620-0x436707`), RSA key init (`00412070` pair +
   `004f89e0`), hill decrypt (`0055fcb0`).
2. Version gate: `hill` lookup (`00435530`), then `version` compares
   (`0055cc80` + `0059d435`); mismatch throws `Invalid version: `
   (`0x43686d-0x436a28`). Observation: composition runs only on
   version match.
3. `inrun` section loop (`0055cd70/0055cd90` iteration): `profile`
   args parsed per key (`0055cc80` key lookup → `004cae40` float
   parse; angle keys additionally `FMUL [0x0061b880]` then
   `FMUL [0x005ce060]`, e.g. `0x436bac/0x436bb4`), then:

   - `0x436c09: MOV ECX, EDI` / `0x436c0b: CALL 0x00434020`
     (inrun builder), `0x436c10: JMP 0x00437226` (loop bump).
4. `dhill` section loop: same parse pattern (angle converts at
   `0x4372f8`, `0x437408/0x437410`, `0x43742e/0x437436`), then:

   - `0x437434: MOV ECX, EDI` / `0x43743f: CALL 0x00434390`
     (landing builder), `JMP 0x00437546`.
5. `terrain` section loop: same parse pattern (angle converts at
   `0x437649/0x43766f`), then:

   - `0x437700: MOV ECX, EDI` / `0x437702: CALL 0x004348a0`
     (terrain builder), `JMP 0x00437802`.

Between the three builder calls there is only next-section tag
dispatch (`00435530` + `0059d435` against `railing/frame/startgate/
startbanner/flag/stairs/pillar/fence/judgetower/trees` plus scenery
leaf calls — markers/scenery, out of scope, untouched). No float
arithmetic combines builder outputs; no matrix/placement call takes
more than one strip as input.

## 3. Observation: strips co-reside at fixed slots of one object

- Inrun builder `FUN_00434020` (ev_9c614a51421f3fa4d57b4684d5ac3aeea2ebf6d035106bd1b1d495c8089d5967;
  instructions ev_f8aaee702eef395105e7510e3025990d7aa5213cc8f750ff198b11e23e009ce9):
  emits run on `ECX=[ESI+0x50]` (b50: `0x434063/0x434084/0x43416c/
  0x434233...`) and `ECX=[ESI+0x58]` (b58: `0x4340f7/0x434115/
  0x43428a...`).
- Landing builder `FUN_00434390` (instructions
  ev_cda7ff5bfda702a992e45e0253f4b5d52cb5c5703b93d60a37c7979ffd34d6f9):
  emits run on `[ESI+0x60]` (b60) and `[ESI+0x68]` (b68).
- Terrain builder `FUN_004348a0`
  (ev_6aa12cdd56427e2cd5c7cc4e87752d27985c3bf515442de3b43e3c416a697016):
  heightfield via `FUN_00434ff0` + clamp/max helpers; its output
  slot offsets in the hill object not mapped (U1).
- All three builders take the same object: every call site reloads
  `ECX` from `EDI`, never from a per-mesh allocation. Inference:
  composition at this level = co-location in one object, not a
  transform. Relative frame placement (the 29 m cross-mesh anchor
  gap noted in `engine/src/mesh.rs`) is therefore decided elsewhere
  (caller side or render; callers listed below, unexamined).

## 4. Callers / callees (from ev_c396...)

Callers (6, unexamined — placement may live in one of these):
`0x4444a0 FUN_004444a0`, `0x4a4210 FUN_004a4210`,
`0x4dcd40 FUN_004dcd40`, `0x4ed6a0 FUN_004ed6a0`,
`0x517ff0 FUN_00517ff0`, `0x542450 FUN_00542450`.

Callees (44): mesh builders `00434020/00434390/004348a0`;
scenery/marker leafs `00435880/00435990/00435aa0/00435e70/00436020/
00436150/00436160/004361f0/00436320/00436530/00436540/00436580/
00436590/004682a0/0046efb0/00502610` (out of scope); XML/key
helpers `00435530/0055cc80/0055cd70/0055cd90/0055fcb0/004cae40/
004caee0/004e5620/004e56d0`; string/exception plumbing
(`00402ce0/00402d50/00402ed0/00403090/004030b0/00403580/0040fc70/
00412070/0041ed70/00510380/0059c120/__CxxThrowException@8/
0059ce28/0059d435/0059def4/004684f0/004f89e0`).

Referenced strings (selection): `hill`, `version`,
`Invalid version: `, `inrun`, `dhill`, `terrain`, `profile`,
`copyright`, `date`, `railing`, `frame`, `startgate`,
`startbanner`, `flag`, `stairs`, `pillar`, `fence`, `judgetower`,
`trees`, `Invalid file: `.

## 5. Rust transcription

`engine/src/mesh.rs`: `COMPOSE_ORDER = ["inrun", "dhill", "terrain"]`
and `compose(hill, inrun, dhill, terrain)` — runs the three builders
in observed order on one shared object. Models ONLY order + sharing;
emits no transform, matching the observed absence. Test
`composition_dispatch_order_shared_object` uses generated stubs.

## Unknowns

- U1 (unknown): terrain heightfield output slot offset(s) in the
  hill object; `004348a0` internals beyond `00434ff0`/clamp/max
  (ev_6aa12cdd... pseudocode not yet transcribed here).
- U2 (unknown): exact stack-push → builder-param mapping (push order
  observed; callee signatures `undefined FUN_00434020()` etc.
  unmapped, so which pushed float feeds which named key is by
  `mesh.rs` anchor analysis, not by this dossier).
- U3 (unknown): loop-counter width/wrap at the three section loops
  (`iVar+1` in decompiler; INC-vs-ADD and wrap behavior not
  examined — bounds are small, no claim made).
- U4 (unknown, the OPEN item): relative placement of the separate
  b50/b58/b60/b68/terrain frames in world space. Observation: it is
  NOT in `FUN_00436620`. Inference: caller-side or render-side;
  candidate callers listed above, none examined.
- U5 (inference, carried): `[0x61b880]`=pi (file 0.0, set at
  runtime), `[0x5ce060]`=1/180 — assumed from `FMUL` pair usage at
  every angle-key parse site, consistent with `mesh.rs`.
- U6 (out of scope, untouched): takeoff markers (`+0x268/+0x274`
  via `00538660` in builders), scenery leaf calls, curve objects
  (`00443370/00443060`), `de150` key/tree.
