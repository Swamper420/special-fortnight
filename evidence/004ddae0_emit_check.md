# Emit topology → polyline (FUN_004ddae0 + builder emits)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE. Session opened via
`tools.rea.open_binary`; dossiers below are Ghidra 12.1.2
representations, not original source.

## 1. Claim: all builder emits share one guard shape

Observation (pseudocode + assembly, branch order as listed):

- `FUN_004dda60` (moveTo/open, ev_dc072bc4d26593dbc704ff773f658e0b574f3d9123c1242e6f6462855f1bf781):
  `0x4dda60-0x4ddadf`, 41 insns.
  1. `if ([ECX+0x30] != 0) throw` (`0x4dda66-0x4dda87`,
     `TEST AL,AL / JZ 0x4dda8c`, throw path builds via
     `FUN_00406b90` + `__CxxThrowException@8`).
  2. `if ([ECX+0x0c] != 0) throw` (`0x4dda8c-0x4ddab2`,
     same throw shape) — strip must be empty.
  3. `FUN_004de150(x, y)` (index/key insert).
  4. `[ECX+0x20]=x; [ECX+0x24]=y; [ECX+0x28]=x; [ECX+0x2c]=x`
     (`0x4ddac3-0x4ddad6`: three stores from the x slot).
- `FUN_004ddae0` (point/lineTo emit, ev_0e21f579bf25485d670b2cfc922cbdd9e15cd0ea41240154f726dcbf59134881;
  same dossier earlier as ev_bd4ae778d6a363c86919a585c4330e718db913b0ca4c25f806a8e788d7b6d5d5):
  `0x4ddae0-0x4ddca1`, 144 insns, callers exactly
  `0x434020` (inrun) + `0x434390` (landing).
  1. `if ([ECX+0x30] != 0) throw "Invalid data exception"`
     (`0x4ddafe-0x4ddb29`; string `0x6067a8` referenced at
     `0x4ddb09`, exception type `DAT_005e6210`, vtable
     `PTR_FUN_005cd370`).
  2. `if (x < [ECX+0x20]) throw` (`0x4ddb2e-0x4ddb62`:
     `FLD [ESP+0x48]; FCOMP [ESI+0x20]; FNSTSW AX; TEST AH,1;
     JZ 0x4ddb67`). TEST AH,1 tests x87 C0, which is also
     set on unordered (NaN) — NaN x takes the throw path.
  3. `if (x == [ECX+0x20]) return` (no-op)
     (`0x4ddb67-0x4ddb73`: second `FLD/FCOMP/FNSTSW;
     TEST AH,0x40; JNZ 0x4ddc8f`). Equal-X points are
     silently dropped.
  4. Else build + append + index + advance cursor:
     - `operator_new(0x14)` then `FUN_00442fb0(prev_x, prev_y,
       x, y)` (`0x4ddb79-0x4ddba3`); null → null-object path.
     - refcounted node `operator_new(4)` with `*node=1`
       (`0x4ddbb8-0x4ddbde`).
     - intrusive list insert at `[ECX+0x08]`
       (`0x4ddbde-0x4ddc15`: `*new=prev-or-self;
       new[1]=next-or-self; prev.next=new; next.prev=new`).
     - `if (new+8 != 0) FUN_004306e0(&node)` (copy/assign,
       ev_de3fa310209521f45049b116689cb758dcc2ff701b6a7bcc4510f15fa7721880:
       `*dst=*src; dst[1]=src[1]; if (dst[1]) (*dst[1])++`).
     - `[ECX+0x0c]++` (`INC EDX` at `0x4ddc2f` — i32 wrap).
     - refcount release pair via `FUN_0059c120`
       (`0x4ddc3f-0x4ddc67`).
     - `FUN_004de150(x, y)` (`0x4ddc6b-0x4ddc77`).
     - `[ECX+0x20]=x; [ECX+0x24]=y; [ECX+0x2c]=x`
       (`0x4ddc7c-0x4ddc8c`).
- `FUN_004ddf10` (4-arg curve strip, ev_3c9208062c5770b9885e4ec998fa94a30a979f28adacb2e105f9a7da9b507943
  head + ev_dfeb6c903431528eba3e6c2e4f1ec1b26b266ed6b33d882e39385878a3df3449 tail):
  `0x4ddf10-0x4de143`, 185 insns, callers `0x434020/0x434390`.
  Same guard triple (flag at `0x4ddf2b-0x4ddf59`, decrease at
  `0x4ddf5e-0x4ddf93`, equal-return at `0x4ddf98-0x4ddfa1+`),
  but the segment object is built by `FUN_00443370`
  (not yet analyzed — open, see Unknowns) and appended via
  the `FUN_00477450` + `FUN_00517ca0` slot path
  (`0x4de026-0x4de04b`), then a stepping loop
  (`0x4de0af-0x4de10a`): while cursor < target, evaluate
  vtable `[+4]` (atan), `[+8]`, advance
  `y = cos(p3)*|f*0.025| + p4`, feed each step through
  vtable `[+0]` + `FUN_004de150`; final `FUN_004de150(p1,p2)`
  and `[0x20]=p1; [0x24]=p2; [0x2c]=p1`.
- `FUN_004ddcb0` (4-arg arc strip, landing only,
  ev_978c39e0950a94784ab3014e5e52cc0678e927408ca3ee184fef712a97a8b0f7):
  `0x4ddcb0-0x4ddf0d`, 200 insns, caller only `0x434390`.
  Same guard triple (`0x4ddcd7-0x4ddd05`,
  `0x4ddd0a-0x4ddd15+`); segment built by `FUN_00443060`;
  same slot-append path; stepping loop clamps
  `|f*0.025|` at `10.0`.
- `FUN_004dd970` (seal, ev_09cb8d914080dd3aab0d88a318b0fd00ce8bdf61436a397bbf45d9d93fae8cc2):
  `0x4dd970-0x4dd974`, 2 insns: `[ECX+0x30]=1`. After this,
  every emit on the same builder throws (guard 1).
- `FUN_004de150` (index/key insert, ev_4a972653aa3af3a10b000c0efd012078566df638345258f3bed487588c02e558):
  `0x4de150-0x4de23e`. Throws on flag; builds key via
  `FUN_00538460(x,y)`; walks tree at `[ECX+0x14]` against
  sentinel `DAT_0061bb58` comparing `node[3]` vs key
  (`FCOMP [ESI+0x0c]`); dispatches `FUN_004def20` /
  `FUN_004df1d0` by `[ECX+0x18]`. Key function + tree
  shape open (see Unknowns).

Callees of `004ddae0`: `0041ed70` (message build),
`004306e0` (refcount copy), `00442fb0` (segment build),
`004de150` (index), `0059c120` (release),
`operator_new`, `__CxxThrowException@8`. No strings besides
`Invalid data exception` (`0x6067a8`, both throw sites).

## 2. Segment build `FUN_00442fb0` (ev_ed3e43fbcc60a4766afd4d9ea8549bca9ae77e59649cd0ee096d0e2fe050a4ac)

`FUN_00442f30(prev_x, prev_y?)`-ish prefix call, then:

- `obj[0] = vtable 0x5ce0e8`; if `|x2-x1| > 0.0`
  (`FABS; FCOMP [0x5ce0e0]; TEST AH,0x41`):
  `obj[3] = (y2-y1)/(x2-x1)` (slope),
  `obj[4] = y1 - x1*slope` (intercept);
- else `obj[3] = 0`, `obj[4] = y1`.
- I.e. a linear y(x) segment. Degrees of freedom beyond
  slope/intercept (object is `0x14` bytes) open.

## 3. Arg slot layout (observed caller assembly)

Inrun `FUN_00434020` (ev_9c614a51421f3fa4d57b4684d5ac3aeea2ebf6d035106bd1b1d495c8089d5967),
`0x434020-0x43438e`, caller `FUN_00436620`; emits run on
TWO builders, `ECX=[ESI+0x50]` and `ECX=[ESI+0x58]`
(builder objects created by `FUN_004dd5c0`,
ev_30407bbaef69fa43b56447ea0fb34e2ff4c4c3d88f21a890ef233a928fd6cb9b):

- b50: `dda60(P3.x-lz, P3.y)` (`0x43420d-0x434225`) —
  moveTo; `ddae0(P3.x, P3.y)` (`0x43422a-0x434237`);
  `ddae0(P2.x, P2.y)` (`0x43423c-0x434249`);
  `ddf10(P0ish...)` (`0x43424e-0x434265`);
  `ddae0(0, ht)` (`0x43426a-0x434273`); `dd970`
  (`0x434278-0x43427b`).
- b58: `dda60(P3.x-lz, ws*0.5)` (`0x434280-0x434297`);
  `ddae0(0, ws*0.5)` (`0x43429c-0x4342a1`); `dd970`.
- Takeoff markers after: two `FUN_00538660` calls storing
  to `[ESI+0x268/0x26c/0x270]` and `[ESI+0x274/0x278/0x27c]`
  + `[ESI+0x25c]=0`, `[ESI+0x280]=-as`,
  `[ESI+0x284]=P3.x` — out of scope (markers, not emits).

Landing `FUN_00434390` (ev_2688609fa0aa2753420fd0d6a4146336de1fdb7c4ab5127851fecea522a0c87e):

- b60 (`[ESI+0x60]`): `dda60(0,0)`; `ddcb0(...)`;
  `ddf10(...)`; `ddf10(...)`; `ddae0(p9', fVar7)`;
  `ddcb0(...)`; direct `FUN_00443060(...)`; 10×
  `FUN_004432a0` sample + `de150` loop
  (`0x4346cf-0x43473b`, `uVar13<10`); `dd970`.
- b68 (`[ESI+0x68]`): `dda60(0, ar*0.5)`;
  `ddae0(...)`; `ddae0(...)`; `ddae0(...)`;
  `ddf10(...)`; `dd970`.

Note: `mesh.rs` `lineto1` doc (`x=as_rad`) disagrees with
the decompiler's `ddae0(fVar6,fVar7)=(P3.x,P3.y)` slot
read here (ESP-shift at `0x43416b PUSH ECX` re-bases later
`[ESP+X]` by −4; Ghidra's stack/param mapping past that
point is suspect). Slot ORDER (which stack word feeds
param_1 vs param_2) past the shift is therefore Unknown —
anchor math untouched, flagged not changed.

## 4. Strip encoding (observed)

- One strip = one builder object (`dd5c0` init: list head
  at `+0x08` self-linked, count `+0x0c=0`, flag `+0x30`
  clear, cursor `+0x20/0x24/0x28/0x2c`).
- `dda60` opens (cursor = first point, count must be 0).
- Each `ddae0/ddf10/ddcb0` appends exactly one list node
  (linear segment vs curve object), `count++` (`INC`,
  i32 wrap), cursor x advances strictly (equal dropped,
  decrease throws), and feeds every produced point through
  `de150`.
- `dd970` seals (`+0x30=1`); the two builders are sealed
  independently, each exactly once per
  `00434020/00434390` run.
- Net effect: each strip is an X-monotone polyline
  (strictly increasing in x after equal-drop), i.e. a
  function y(x) over its span. Node layout past
  slope/intercept (`442fb0` +0x0c/+0x10), the `443370` /
  `443060` curve objects, the `477450/517ca0` slot path,
  and the `538460/de150` key/tree are NOT mapped (open).

## 5. Rust transcription

`engine/src/mesh.rs`: `EmitAction::{Emit,IgnoreEqual}`,
`EmitErr::{Closed,Decrease}`, `emit_check(closed,
cursor_x, x)` (branch order = asm: closed → decrease
(C0 incl. NaN) → equal (C3) → emit), `moveto_check(closed,
count)`, `StripCursor::{advance, seal}` (`count`
`wrapping_add(1)`, f32 stores). NaN x → `Decrease`
(matches unordered→C0 throw before the equality test).

## Unknowns

- U1: stack-slot → param mapping past the `0x43416b`
  ESP-shift: decompiler param names vs `mesh.rs` anchor
  names (`lineto1` axis-role question) unverified.
- U2: `FUN_00443370` / `FUN_00443060` curve object layout;
  `477450/517ca0` slot path vs `ddae0` direct-insert path
  equivalence unproven.
- U3: `FUN_00538460` key + `de150` tree shape (`0061bb58`
  sentinel, `+0x14/+0x18` fields); node `0x14`-byte layout
  past slope/intercept.
- U4: float compare exactness: x87 80-bit `FCOMP` vs f32
  compare — near-equal values could differ at the
  dropped-vs-emitted boundary; tolerance unmeasured.
- U5: `[0x61b880]`=pi assumed (file 0.0, set at runtime);
  composition of b50/b58/b60/b68 frames unmapped
  (separate task, untouched).

Status update (inrun `ddf10`): `evidence/00434020_ddf10_args.md`
maps the `0x43424e-0x434265` slots to
`ddf10(A0x, A0y, A1x, A1y)` and on to ctor
`(cx=A1x, cy=A1y, prev=cursor, new=(A0x,A0y))`.
Landing `ddcb0`/`ddf10` slots stay open (U2 remainder).
