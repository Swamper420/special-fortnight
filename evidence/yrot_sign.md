# Y-rotation sign resolution (appendix to `evidence/0046efc0_multiply.md` U1)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`.
Parent U1: `FUN_0046f910` forwards slot2 `+sin` / slot8 `−sin`, opposite
handedness vs the `FUN_0046fa90` quaternion path (slot2 `−1` / slot8 `+1`
for a Y-90° quaternion) under a common row-vector reading.
Question: negated-angle caller, or genuine mismatch?

## Verdict

Genuine mismatch. Neither `0046f910` caller negates its angle, and neither
`0046fa90` caller negates its quaternion. Both transcriptions keep observed
signs (no normalization). No code or transcription change follows from this.

## 1. Observation: `FUN_0046f910` sign re-confirmed

Evidence: `ev_f40a98e88ecdf344d8daaeaed0d4f6be05a0e3befbc77ca4cb5a55fe68a52ebe`
(supersedes multiply-doc `ev_b0ab3e0a67912c5ff0eaff4e4479aeede5ff43e93ba06f9d78daa1c9258fa1b1`
for this function; same bytes).

Pseudocode (verbatim): `FUN_0046ef20(cos,0,sin,0, 0,1,0,0, −sin,0,cos,0, 0,0,0,1)`.
The single `FCHS` in the body (`0x46f94f`) negates the stored sin copy for
slot8 — part of matrix construction, not angle negation. `f910(+π/2)` yields
slot2 `+1`, slot8 `−1`. Observed.

## 2. Observation: `FUN_0046fa90` is a quaternion→matrix builder, sign layout as stated

Evidence: `ev_0adbfd8fcb8c92a7b7a380d6215a45e5dd4f3f3bc60a8866a2576323a2e6cf49`.

Pseudocode (verbatim, `param_2` = 4-float `[x,y,z,w]`):

- slot0 `= (x² + w²) − y² − z²`, slot5 `= (y² + (w²−x²)) − z²`,
  slot10 `= ((w²−x²) − y²) + z²` (standard diagonal).
- slot1 `= 2·(z·w + y·x)`, slot2 `= 2·(z·x − y·w)`,
  slot4 `= 2·(y·x − z·w)`, slot6 `= 2·(x·w + z·y)`,
  slot8 `= 2·(z·x + y·w)`, slot9 `= 2·(z·y − x·w)`.

Inference (checked arithmetic, not a new observation): for a Y-90°
quaternion `(0,s,0,c)`, slot2 `= −2sc = −1`, slot8 `= +2sc = +1` —
opposite of `f910(+π/2)`. For an X-90° quaternion `(s,0,0,c)`, slot6 `= +1`,
slot9 `= −1`, which MATCHES `FUN_0046f8a0(+π/2)` (see §5). The Y
disagreement is therefore isolated to Y, not a global transpose/convention
difference (which would flip X too).

## 3. Observation: tree-loop caller `00455ba0` passes its angle verbatim (no `FCHS`)

Evidence: `ev_20a9987bc37f750608bdb24c423f060b66ce92b946d82d06ba07240bc8c8ff96`
(868 insns).

Angle chain (asm-observed):

- `0x455fa0: PUSH 0x40490fd8` (≈ π; 3 ulp below `0x40490FDB`),
  `0x455fa5: PUSH 0x0`, `CALL 0x004df960`,
  `0x455fb3: FSTP float ptr [ESP+0x24]` — angle `= df960(0, π)`.
- `0x456011: MOV EAX,dword ptr [ESP+0x44]` (same slot after 8 net pushes;
  caller cleans all 10 pushes at `0x45602b: ADD ESP,0x28`),
  `0x45601c: PUSH EAX`, `0x456026: CALL 0x0046f910`.
- Zero `FCHS` instructions in the entire 868-insn body (counted). No
  `FSUB`-based negation on the angle path either (the 2 `FSUB`s are the
  `0x456129` sky-frame `FSUB [0x5ceba4]` and inside `004df960`'s
  `(b−a)` term — both accounted for, neither on the angle value).

Angle producer `FUN_004df960(a,b)` (Evidence
`ev_5bc12f78d5e3664e88d4be75b944810b5c22f5636eb1ad3c68f7899470d60c35`):
`RET 0x8`, `a + (b−a)·rand·2.3283064e-10`, i.e. uniform `[a,b)`. So the
tree angle is uniform `[0,π)`, positive, unnegated. (Distribution is mirror-
symmetric, so the Y-sign flip is visually unobservable here — inference.)

## 4. Observation: second `0046f910` caller `00504540` also passes its angle verbatim

Evidence: `ev_8545cec7035c4e8f17fd8a015f7d40617a0dc9d833289d2b788abe23a14419d4`
(125 insns; call at `0x5045a1`).

Angle chain (asm-observed): `FILD qword [ESP+8]` (integer ticks from
`0040e510`) → `FMUL [0x5d1540]` → `FLD double [0x5d1538]` →
`CALL 0x0059edfa` (thunk: `MOV EDX,0x618380; JMP 0x005a6d40`; Evidence
`ev_e823ce8283d0e177cc606b14764e86eb968200c1cb65109c5fc60c6889d5aef8`;
`fmod`-shaped, sign-preserving remainder) → `0x504593: FSTP [ESP+8]` →
`0x504597: MOV EAX,[ESP+8]` → `PUSH EAX; PUSH ECX; CALL 0046f910`.
Three insns between store and push; no `FCHS`, no negation. `0046f910` has
exactly these 2 caller procedures (both now traced) — the "negated caller"
hypothesis is exhausted for this function.

## 5. Cross-check: X-rotation `FUN_0046f8a0` AGREES with the quaternion path

Evidence: `ev_17f62d7eb1d5b0f12807956181721ba36f5daa8e733e0adfb0d0efded9968993`.

Pseudocode (verbatim): `FUN_0046ef20(1,0,0,0, 0,cos,sin,0, 0,−sin,cos,0, 0,0,0,1)`,
i.e. slot6 `+sin`, slot9 `−sin` — matches the quaternion X-90° outputs
(slot6 `+1`, slot9 `−1`) derived in §2. Right-handed row-vector X: agree;
right-handed row-vector Y: disagree. A blanket row/column-major mix-up would
break X as well, so the Y flip is a genuine producer-level sign difference,
not a reading-convention artifact.

## 6. Observation: `FUN_0046fa90` callers pass quaternions verbatim

- `FUN_00502340` (Evidence
  `ev_de8e7216f9e96d47358c79fa5b6358a653ebbbb3900babc31aea8372f2c829e8`):
  stores 4 stack params to `[ECX+0x144..0x150]` with `MOV` only, then
  `0x502396: CALL 0x0046fa90`. No `FCHS`.
- `FUN_00502220` (Evidence
  `ev_384a10c20c7bea905a1d6b0f28c3abcf2e86ac2041e65fcd0ee60bb434ea5353`):
  copies 4 dwords from `004df660` output with `MOV` only, then
  `0x50225b: CALL 0x0046fa90`. Zero `FCHS` in body.

(Quaternion negation `q → −q` would be unobservable anyway — same rotation.
A sign fix on the Y *component* alone would be a different rotation and was
not observed anywhere.)

## Unknowns

- U1 (closed as "genuine mismatch", no fix): the two rotation producers
  disagree on Y handedness under a common row-vector reading; both
  transcriptions keep observed signs. Deliberately NOT normalized.
- U2 (open): which producer matches downstream consumer expectation — i.e.
  whether any rendered frame visibly depends on the Y sign. Tree-loop angles
  are mirror-symmetric randoms (unobservable); `00504540` rotates by tick-
  derived angle (direction observable in principle, consumer `0040a560` /
  submit path untraced).
- U3 (open): full quaternion producers (`004df660`, and `00502340`'s
  caller-supplied quats) untraced beyond verbatim passthrough; no Y-only
  quaternion instance observed, so the §2 Y-90° comparison remains analytic
  (substituting `(0,s,0,c)` into observed formulas), not an observed call.
- U4 (method): angle-slot bookkeeping in `00455ba0` (`[ESP+0x24]` →
  `[ESP+0x44]`) resolved via decompiler pseudocode
  (`FUN_0046f910(auStack_260,pvStack_3e4)`) + `ADD ESP,0x28` push-count
  cross-check, not a formal stack-effect proof of each callee.
