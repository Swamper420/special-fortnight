# Scenery family sweep: section tags, leaves, and deviations from the stairs skeleton

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE, Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Dossiers below are Ghidra 12.1.2
representations, not original source.

Base pattern: `evidence/00435880_scenery.md` (stairs
`FUN_00435880`: `new(size)` → ctor → `FUN_00436020` 4-float store
→ refcount wrapper → vector append at a hill slot). Dispatcher:
`FUN_00436620` (`evidence/00436620_composition.md`).

## 1. Claim

Only 3 of the 10 scenery sections follow the allocate-store-append
skeleton: `stairs` (`00435880`), `pillar` (`00435990`),
`trees` (`00435aa0` — wider variant, 8 params, no `00436020`).
The other 7 sections (`railing`, `frame`, `startgate`,
`startbanner`, `flag`, `fence`, `judgetower`) write **inline**
into fixed hill-object slots via tiny pure stores/getters and never
allocate or touch a vector. `FUN_00435e70` is not a leaf at all: it
is a 3-param string-assign helper called from 6 sections.

## 2. Dispatch map (observed, `read_function_instructions`)

Dossier with all 15 tag dispatches
(`ev_0c0f842f5fdd4e7b65a294270b326cd40585198212cb80d56d4cd578c4e29840`);
leaf-call hits
(`ev_4f19198fa0f769b25ad993554a1176508330f49a2f1a7d3a2d06d527b8ee1dc9`).
Each block = tag `PUSH 0x60xxxx` + `CALL 00435530` + `CALL 0059d435`
fall-through, ending at the next tag or a loop-bump `JMP`.
Tag strings (`list_strings`, UTF-16): `railing`@`0x608d8c`
(`ev_b44c1c328659ff4a90fa8400bd82ce09c84f6c1c1b43a7c58f7cae423ec481cc`),
`frame`@`0x608d48`
(`ev_471fe840f6410575f4badc2a0955ef8560a245996d1a1bf879d2b1b449460baa`),
`startgate`@`0x608d1c`
(`ev_4c19f9a4e2c60aa3948d2f6872bd25cac7287a715203c17fd86765bc02218556`),
`startbanner`@`0x608cfc`
(`ev_3b92e5526abf74f127a3ba0eade904cf89f60ed06f17dddcb1d8ae75a718f958`),
`flag`@`0x608cf0`
(`ev_dc3ea11ab030734ec9c37c638ea53d2a2c0ff2769ba743629484764b50004732`),
`stairs`@`0x608c90`
(`ev_5cc019caf3a18b9f1292e08e231fa8d653d6d3b332245fd5f1db567697832e4e`),
`pillar`@`0x608c60`
(`ev_68ee62aea76dac63e6e4c1fee88f29383a1cfffa1280bdce1dd50e1bd92abb45`),
`fence`@`0x608bd0`
(`ev_3f35072329903f799c37665561206e4dfe44d0d97884db73f388d752364b9f3e`),
`judgetower`@`0x608bb8`
(`ev_084bc457df5c7f6aed4e441f4f5f5279dff916bc9a43dc4b4c538697146ca8de`),
`trees`@`0x608b5c`
(`ev_1d7b6b55bdcae7eae347da021c6a1f2b337334c0fa70bc5a0f44e4c1e6676b7b`).
Key names below are the first UTF-16LE token at each key address
(`read_bytes`; representative Evidence IDs in §4).

| Section (tag) | Block (`00436620`) | Calls in order | Keys pushed in order (type) |
|---|---|---|---|
| `railing` | `0x436c15–0x436d06` | `00436150`(ECX=hill+0xc4); `004682a0`(ECX=hill+0xc4)→`00435e70`; `00436160`(ECX=hill+0xc4, result discarded) | `d,h` (float `004cae40`); `c1,m1,t1` (string `004caee0`+nested); `c2,m2,t2` (nested) |
| `frame` | `0x436d0b–0x436e2f` | `004361f0`(ECX=hill+0x114); `0046efb0`→`00435e70`; `00436530`(hill+0x114+0x28)→`00435e70`; `00436540`(hill+0x114+0x4c, result discarded) | `h` (float); `c1,m1,t1`; `c2,m2,t2`; `c3,m3,t3` (strings) |
| `startgate` | `0x436e34–0x436e97` | `00436590`(ECX=hill+0x9c, result discarded — no `00435e70`; corrected per `00435e70_strings.md` §4) | `c,m,t` (strings) |
| `startbanner` | `0x436e9c–0x436eda` | `004361f0`(ECX=hill+0xc0) | `z` (float) |
| `flag` | `0x436edf–0x437020` | `00436320`(ECX=hill+0x1b8) | `cp` root + `mp,tp,mf,tf` nested (strings); `rt,rb,hp,hf,wf,z,x` (7 floats) |
| `stairs` | `0x437025–0x4370ac` + tail to `0x437146` | `00435880`(ECX=hill); then `00436580`(EAX=node→+0x10)→`00435e70`; `00502610`(node+0x34, discarded) | `z2,z1,l2,l1` (floats); tail `c1,m1,t1` (strings); tail `c2,m2,t2` (nested, feed discarded LEA) |
| `pillar` | `0x43714b–0x437221` | `00435990`(ECX=hill); then `00436580`(node+0x10)→`00435e70` | `z2,z1,x2,x1` (floats); tail `c,m,t` (strings) |
| `fence` | `0x437449–0x4374b3` | `00436590`(ECX=hill+0x184)→`00435e70` | `c,m,t` (strings) |
| `judgetower` | `0x4374b8–0x437546` | `00436020`(ECX=hill+0x1a8) | `c2,c1` (strings via `004caee0`/nested) + `z,d` (floats) — mixed 4-dword store |
| `trees` | `0x43770c–0x437802` | `00435aa0`(ECX=hill) | `s,n` (strings); `h2,h1,z2,z1,x2,x1` (6 floats) |

String-vs-float is by parse helper: `004cae40`+`FSTP` = float,
`004caee0` (or chained `0055cc80` nested lookup) = string. No `FMUL`
angle conversion at any scenery site (contrast inrun/dhill/terrain).

## 3. Leaf dossiers

### 3a. Skeleton followers

**`FUN_00435990` = `pillar`** (`ev_51c3e80a82908ea9d6f5db095926d2cb5ad5b522baf0906d6c2817b1ad942684`,
tail `ev_491d4722497590de3aa8607875fe3830fd0dd2d398c88e0d6f8037b6bb104bb3`):
268 bytes (`0x435990–0x435a9b`), `RET 0x10` (4 params), sole caller
`00436620`. `operator_new(0x34)` → ctor `FUN_00436550`
(`ev_9477c505cbcd029f1b8168e0aada12c9c0fae5aa07b606c16746d48461f5a0f3`:
`FUN_00435cc0` on `ECX+0x10`, then zeroes `[+0x0..+0xc]`, 28 bytes)
→ same `FUN_00436020` 4-float store → same refcount wrapper →
`FUN_00438070(*(hill+0x230),1,&local)` with `LEA ECX,[hill+0x228]`.
Dtor path `FUN_00436570`. Verdict: skeleton holds exactly; only the
node size (`0x34` vs `0x58`), ctor/dtor pair, vector slot
(`+0x228/+0x230` vs `+0x218/+0x220`), and insert helper differ.

**`FUN_00435aa0` = `trees`** (`ev_4dfc5f3832bbd31bbc5edbfe40c7eb6b86f8527500fc4a33d5308f1d4be3adc8`,
tail `ev_bf93297db581fd09bae00615f43dd9500b2f5588ef66e7e84d52b40acc458c69`):
288 bytes (`0x435aa0–0x435bbf`), `RET 0x20` (8 params), sole caller
`00436620`. Same wrapper shape, but: `operator_new(0x20)`; ctor
`FUN_004365a0`
(`ev_eed9f381dc722924fbeefe9385760665d1cd133759ee90bd9ccf0f49bcbc6ecd`,
36 bytes, no callees — writes `0,0,0,0,0x40c00000,0x41000000,0,0`,
i.e. floats `0,0,0,0,6.0,8.0,0,0` (0x40c00000=6.0, corrected 2026-10-16); setter `FUN_004365d0`
(`ev_d2cab5cb1479b855f61986d09953da6f1cf1c1a09b621c762eba8b0d57168987`,
58 bytes, no callees, `RET 0x20` — 8-word store, NOT `00436020`);
vector `FUN_004382f0(*(hill+0x240),1,&local)` with
`LEA ECX,[hill+0x238]`; dtor-side `FUN_00458de0`.
Verdict: skeleton shape (alloc → init → store → append) but every
inner identity differs; the shared-`00436020` assumption is FALSE here.

### 3b. Inline setters (no alloc, no vector)

- `FUN_00436150`
  (`ev_ab75e7882ce29c5a5887316d494c9823a779e9c2f31cc77c49fc3c21dcd8cebc`,
  16 bytes, no callees, `RET 8`): 2-word store (`*ECX=p1; ECX[1]=p2`).
  Railing head at hill+0xc4 (`d,h`).
- `FUN_004361f0`
  (`ev_d54bde73662912766226e4af5de59c8e8d2d1fc4575882e830216e1604ff9394`,
  9 bytes, no callees, `RET 4`): 1-word store. Frame head
  (hill+0x114, `h`), startbanner (hill+0xc0, `z`).
- `FUN_00436320` = `flag` setter
  (`ev_6ff4acb73457b907b0698b7d5f9dfa7a5c91bc65c8bbe1d27c7893eac82c4c35`,
  tail `ev_a5062f6f00bf3053e7998cdec7db37fba20de59273ce3b226384fdab2d92ed05`):
  455 bytes (`0x436320–0x4364e6`), `RET 0x30` (12 params), sole caller
  `00436620`. Stores 7 floats at `[ECX+0x0..+0x18]`, then 4 guarded
  wide-string copies (`00402d50` gate + `00402e80`/`00403280` grow +
  word-copy loops) at `[+0x1c]`, `[+0x2c]`, `[+0x3c]`, `[+0x50]`-ish
  dword pairs (`[8]/[9]`, `[0xc]/[0xd]`, `[0x10]/[0x11]`,
  `[0x14]/[0x15]/[0x16]` + final dword `[0x17]`), i.e. struct at
  hill+0x1b8 of size ≥ 0x60. Callees `00402d50/00402e80/00403280/
  00403a40/0059ce28/0059c12b` — string-runtime, not transcribed.
- `FUN_00436020` direct call at `0x437541` (judgetower): the shared
  4-word store reused inline at hill+0x1a8 with mixed
  string-ptr/float dwords (see §5 U6).

### 3c. Sub-object getters (all pure LEA/identity, no callees)

`FUN_00436160` (`ev_f8a0c64102a99ade4e77c9b87815f5081ffe93b3ed5ea2abd72e9921cded45a6`,
4 bytes: `EAX=ECX+0x2c`; also called from `00439370`);
`FUN_00436530` (`ev_cc4a06b06ada19fd90d51694d9d590ab585fae3c41f14644349bda21b54c57e4`:
`+0x28`; also from `0043a420`); `FUN_00436540`
(`ev_6cfbfa9709a7dfbc2c399b35b2d0a558cbad1fb0ec84cb7bf8964d5f0f5e73a0`:
`+0x4c`; also from `0043a420`); `FUN_00436580`
(`ev_e0ee41c83d3db1088351d1632fae3ac1f4c1c3c453384ba3635f250ac1df611b`:
`+0x10`; also from `0043c120/0043d230`); `FUN_00436590`
(`ev_880065b078eac7c644bd57b20c4787d1fb52655678b19cdb76b7f61035153018`,
3 bytes: `MOV EAX,ECX`; also from `0043bce0/0043ecf0`);
`FUN_004682a0` (`ev_19d659723bc8303054285534ab1489e091fee494f9d14d9fb018da562a6b9c69`:
`+8`); `FUN_0046efb0`
(`ev_e0bfb77172cd1a12349059393721715f15b4a727b6b7c73810f53ac1de53a84d`:
`+4`); `FUN_00502610`
(`ev_40a9118eb458f96c159e28b32da81082d80de162bb35b457da1ea0860eb8aca2`:
`+0x34`). Each feeds its result as `ECX` into `FUN_00435e70`,
except three dead calls whose results are discarded
(`00436160` railing tail, `00436540` frame tail, `00502610` stairs
tail — each followed directly by loop-bump `JMP`).

### 3d. String helper (not a leaf)

`FUN_00435e70`
(`ev_12e5d81a81c72d3c672cfd888f647612a76f9ad1a0da20308bb74faf806f208d`,
tail `ev_a38ec5973330cc00387e3adc64b97bb043c2cd2cf50c226db0eae646f2874`):
329 bytes (`0x435e70–0x435fb8`), `RET 0x0c` (3 params), called from
`00436620` at 6 sites (railing/frame/pillar-tail/stairs-tail/
startgate+fence/fence-tail). Copies a wide string into `[ECX+0x4..]`
(len `[ECX+0x8]`, cap `[ECX+0xc]`), a second into `[ECX+0x14..]`
(len `[+0x18]`), stores p3 at `[ECX+0x20]` — i.e. dest object ≥ 0x24
bytes holding two counted strings + dword. Callees
`00402920/00402e80/00403280/0059ce28/0059c12b`. Not transcribed
(string runtime + refcounting unexamined).

## 4. Key-name decodings (`read_bytes` hex → UTF-16LE first token)

- Railing/fence/startgate families: `d`@`0x608d88`
  (`ev_d9750d11e1c84ad9a9f0e7847e870ab71409a3e84695c08163be21991cf14ceb`),
  `h`@`0x608d84` (`ev_ccc1ebfe050aaea95194d986e556c16a66088b708759fdf8d5cbead4f98e7064`),
  `c1`@`0x608d7c` (`ev_753b10b61a5411487ba40896bde597c0c6a2d94d28185bd88569a5a35c15b73e`),
  `m1`@`0x608d74`, `t1`@`0x608d6c`, `c2`@`0x608d64`, `m2`@`0x608d5c`,
  `t2`@`0x608d54`, `c3`@`0x608d40`, `m3`@`0x608d38`, `t3`@`0x608d30`,
  `c`@`0x608d18`
  (`ev_97885a3cbad43e72f06050e831744d81db9f1e6ab043022548ffd2b0f7f626d6`),
  `m`@`0x608170`
  (`ev_f04f0b0c0fdcc711b6f47e316f1ed0f7e622166675c857feabd4df6eb0156455`),
  `t`@`0x608d14`.
- Stairs/pillar/trees: `z2`@`0x608c88`, `z1`@`0x608c80`,
  `x2`@`0x608c58`, `x1`@`0x608c50`, `s`@`0x608b58`
  (`ev_2f88b72a5c8e8d9e2a047491f6eb7fa9d4d371ffba0f8b7f02e2f938fa615380`),
  `n`@`0x608b54`, `h2`@`0x608b4c`, `h1`@`0x608b44`.
- Flag: `cp`@`0x608ce8`
  (`ev_e52513b34a128ed18996499d31d6a053d08b95265c49ce13bc4ee878afe24d67`),
  `mp`@`0x608ce0`, `tp`@`0x608cd8`, `mf`@`0x608cd0`, `tf`@`0x608cc8`,
  `rt`@`0x608cc0`, `rb`@`0x608cb8`, `hp`@`0x608cb0`, `hf`@`0x608ca8`,
  `wf`@`0x608ca0`, `z`@`0x6068c0`
  (`ev_428db04829a672f496b161c3eae789e9eb42fead1d96c8d833453f43eabd4b27`),
  `x`@`0x6068c8`.

## 5. Rust transcription

None added. The newly proven-pure fragments are widths of the
already-transcribed `store_float_quad` pattern (`00436150` 2-word,
`004361f0` 1-word, `004365d0` 8-word, `004365a0` const-init) or
address arithmetic on unmapped layouts (all §3c getters + identity),
so transcribing them now would duplicate or float free of any object
model. Reuse point stays `engine/src/fn_00436020.rs`. Add when a hill
or node layout is mapped and a second consumer needs the width.

## Unknowns

- U1 (open): stack-push → param mapping for every leaf (push order
  recorded in §2 table; which pushed value lands in which named slot
  is inference — `RET` widths only prove counts).
- U2 (open): node layouts beyond the stored prefix (`0x58` stairs,
  `0x34` pillar, `0x20` trees); ctor helpers `00435cc0`/`00436050`/
  `00436570`/`00458de0` internals unexamined. Note `004365a0`'s
  `6.0/8.0` defaults at `+0x10/+0x14` are dead on the trees path (3.5 label corrected)
  (fully overwritten by `004365d0`) — their purpose is unknown.
- U3 (open): vector element types at hill `+0x218/+0x228/+0x238`
  (8-byte stride assumed from wrapper shape — inference, same as
  stairs U3).
- U4 (open): whether insert positions `*(hill+0x220/+0x230/+0x240)`
  can splice mid-vector (same as stairs U4).
- U5 (open): `00435e70` dest-object type and string refcount
  semantics; p3 (`[+0x20]`) meaning per section.
- U6 (open): judgetower's mixed store — which of the 4 dwords at
  hill+0x1a8 are string pointers vs floats (push order: `c2,c1`
  strings then `z,d` floats, but slot assignment untraced).
- U7 (observation, unexplained): three dead pure calls with discarded
  results — `00436160` (railing), `00436540` (frame), `00502610`
  (stairs tail). Real `CALL`s in the instruction stream, not
  decompiler artifacts. Bounds note: `00502610` = node+0x34 is
  in-bounds only for the `0x58` stairs node, consistent with the
  pillar (`0x34`) block omitting it.
- U8 (out of scope): `004682a0/0046efb0/004502610` non-scenery callers
  (`0040d0f0/00424610/00439370/004cc080`, `00401860/0040a680/
  0040cf10/00438a80/0043a420`, `0043d230/00450ab0/00454390/004597d0`)
  unexamined; `00436530/00436540` shared with `0043a420`,
  `00436580` with `0043c120/0043d230`, `00436590` with
  `0043bce0/0043ecf0`, `00436160` with `00439370` — getter reuse
  outside scenery noted but not followed.
