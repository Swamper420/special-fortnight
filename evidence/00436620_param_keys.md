# `param_N` → hill-XML key map: `FUN_00436620` parse loops (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe`, SHA-256 `3619dcbd...`, x86 PE.
Scope: which key string feeds which builder arg slot, which keys get
the `pi × 1/180` FMUL pair. Closes U1 of `evidence/00434390_anchors.md`
and U2 of `evidence/00436620_composition.md` (modulo the reversal
inference below, U1 here).

## Evidence IDs

- `ev_4d2c6e0a3e93bb4f34a7825be0f3937b0580707b71ff04f121db95aaf8f0724f`
  (`read_function_instructions FUN_00436620`, this session, 1462 insns;
  all addresses/patterns below from it).
- `ev_d2e9b8e0d1589e7954c714054d98c79e18ef7c47cf95066716fdd42447b6f75b`
  (`analyze_function FUN_0055cc80`: key lookup, `(node=ECX, stackarg,
  key)` → value wide-string or default).
- `ev_f29ebb99b8454b1c7e81215bc4efd4b5ba5199720687fea22ff549e2e56d5451`
  (`analyze_function FUN_004cae40`: float parse of lookup result).
- `ev_c688de53e1beb95b2a109c7512e0673aeb0d7c82dd099dd330dcee21a67a4a85`
  (`analyze_function FUN_004caee0`: int parse, terrain `rs` only).
- `ev_c443a8e6940511eb047b07a9c0b3725aaf7e4c6483791ca52b325315194d371e`
  (`read_bytes 0x005ce060`: `61 0b b6 3b` = `0.0055555557f` = 1/180).
- Per-key `read_bytes` IDs: inrun table `ev_fa726853...` (80 B at
  `0x608d9c` covers all 10 keys, 8 B apart); dhill/terrain keys
  `ev_aae19e62`, `ev_bba0139d`, `ev_cf3a73fa`, `ev_7355124a`,
  `ev_7d0b3f2e`, `ev_af1b94b4`, `ev_74a6fb81`, `ev_cfe63a0c`,
  `ev_ea01d1ac`, `ev_c56355f2`, `ev_d0cbe41e`, `ev_39957002`,
  `ev_31f1c834`, `ev_0e140f0f`, `ev_2e1362ca`, `ev_07f68eac`,
  `ev_d7ad79e3`, `ev_8ecb4fbd`, `ev_8d7daca4`, `ev_cde05887`,
  `ev_78c6bcd8`, `ev_2a6a5828`, `ev_c5391fd6` (32 B each, first
  wide-string decoded).
- Cited: `ev_2352cfc0...`/`ev_c396a14f...` (composition dossier body +
  refs); `ev_73e571ff...` (`[0x61b880]` file-zero, runtime pi assumed).

## 1. Parse mechanics (observation)

Each key: `PUSH 0x61b820; PUSH <key>; MOV ECX,ESI; CALL 0055cc80;
PUSH EAX; CALL 004cae40; [FMUL pair]; FSTP [ESP]`. The `FSTP [ESP]`
writes into the slot reserved by `PUSH EAX`, so each iteration grows
the arg pile by one float: first-parsed ends deepest. `PUSH 0x61b820`
is a zeroed 64 B buffer (ev_90280e81), passed but never the key.

Reversal rule (inference): at the builder `CALL`, lowest address =
last-parsed key = `param_1`; first-parsed = `param_N`. Assumes plain
cdecl float pile, no callee-side reorder. Consistency check, not
proof: dhill gives `p1=a0` (angle, feeds `tan(-p1)` slope),
`p2=ak` (angle, feeds `pi*0.5-p2`), `p12=ar` (feeds `atan`),
`p13=w0` (feeds `dda60(0, p13*0.5)` half-width) — all match
`evidence/00434390_anchors.md` §2 roles.

Angle conversion (observation): `FMUL [0x0061b880]` (= runtime pi,
file-zero) then `FMUL [0x005ce060]` (= 1/180, proven above), i.e.
degrees → radians. Fires only on the keys listed per table.

## 2. Inrun loop → `FUN_00434020` (10 keys, `0x436aed-0x436c0b`)

Parse order (observation): `ws tz ht at lt rc as lg ls lz`.

| param | key | angle (FMUL site) |
|---|---|---|
| p1 | `lz` | |
| p2 | `ls` | |
| p3 | `lg` | |
| p4 | `as` | yes (`0x436bac/0x436bb4`) |
| p5 | `rc` | |
| p6 | `lt` | |
| p7 | `at` | yes (`0x436b52/0x436b5a`) |
| p8 | `ht` | |
| p9 | `tz` | |
| p10 | `ws` | |

Angle keys: `as`, `at`.

## 3. Landing (`dhill`) loop → `FUN_00434390` (15 keys, `0x437293-0x43743f`)

Parse order (observation): `wb wk w0 ar nr hr lb rs l2 l1 rl nk hk ak a0`.

| param | key | angle (FMUL site) |
|---|---|---|
| p1 | `a0` | yes (`0x43742e/0x437436`) |
| p2 | `ak` | yes (`0x437408/0x437410`) |
| p3 | `hk` | |
| p4 | `nk` | |
| p5 | `rl` | |
| p6 | `l1` | |
| p7 | `l2` | |
| p8 | `rs` | |
| p9 | `lb` | |
| p10 | `hr` | |
| p11 | `nr` | |
| p12 | `ar` | yes (`0x4372f8/0x437300`) |
| p13 | `w0` | |
| p14 | `wk` | |
| p15 | `wb` | |

Angle keys: `a0`, `ak`, `ar`. Derived anchor cross-check: `p4=nk`
parked at `[B+0x2c]` for `ddae0(p4, p14*0.5)`; `p8=rs` is the
`cos(A14)*p8` radius; `p15=wb` half-width.

## 4. Terrain loop → `FUN_004348a0` (12 keys, `0x4375af-0x437702`)

Parse order (observation): `rs d2 d1 l2 l1 ax az y0 l0 a0 dh in`.
`rs` alone parses via int `004caee0` (rest via float `004cae40`).

| slot | key | angle (FMUL site) |
|---|---|---|
| s1 | `in` | |
| s2 | `dh` | |
| s3 | `a0` | |
| s4 | `l0` | |
| s5 | `y0` | |
| s6 | `az` | yes (`0x43766f/0x437677`) |
| s7 | `ax` | yes (`0x437649/0x437651`) |
| s8 | `l1` | |
| s9 | `l2` | |
| s10 | `d1` | |
| s11 | `d2` | |
| s12 | `rs` (int-parsed) | |

Slots numbered s1..s12 (not `param_N`: callee signature
`FUN_004348a0` unmapped, int-vs-float slot type unknown — U2 below).
Angle keys: `ax`, `az`.

Key inventory matches `engine/src/hill.rs` doc sets exactly
(10/15/12); no new keys observed.

## Unknowns

- U1 (inference load-bearing): last-parsed = `param_1` reversal. From
  push/`FSTP` order + cdecl, cross-checked against anchor roles —
  not from a recovered callee prototype (`FUN_00434020/00434390/
  004348a0` signatures still `undefined`). If a builder reorders
  args internally, tables shift.
- U2: terrain `rs` slot type/position semantics (int `004caee0`
  result `PUSH`ed deepest, floats above; whether the callee takes an
  int or converts is unexamined).
- U3: `0x61b820` first-arg role (zeroed buffer; default-value
  pointer assumed, contents unexamined).
- U4 (carried): `[0x61b880]` = runtime pi assumed (file-zero,
  ev_73e5...); `[0x5ce060]` = 1/180 file-proven (ev_c443...).
- U5 (carried): `FUN_00434020` 10-param shape never verified against
  its body; inrun table assumes 1:1 pile consumption like landing.
