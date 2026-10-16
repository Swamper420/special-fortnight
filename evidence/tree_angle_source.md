# Tree-loop rotation angle source (`[ESP+0x44]` @ `0x456011`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4` —
assumed; REA session default, corroborated by identical `00455ba0` body range
`0x455ba0`–`0x4567a8` / 868 insns).
Parents: `evidence/00409060_submit.md` §4/U3, `evidence/0046efc0_multiply.md` U1.
Method: `read_function_instructions` + `analyze_function` × 3
(`00455ba0`, `004df960`, `004df8c0`, `004df900`). No code, no engine edits.

## 1. Claim

- The angle consumed by `FUN_0046f910` at tree-loop site `0x456026`
  (read at `0x456011: MOV EAX,[ESP+0x44]`) is a **fresh uniform random in
  `[0, 0x40490FD8)` radians per submitted tree** — NOT a strip scalar,
  NOT a constant, NOT an accumulated value.
- Producer chain (observed): `0x455fae: CALL 004df960` with args
  `(0, 0x40490FD8)` → `0x455fb3: FSTP [ESP+0x24]` stash →
  `0x456011: MOV EAX,[ESP+0x44]` reload (SAME physical slot; textual offset
  differs because pushes between the two points shift ESP, §3) →
  `0x45601c: PUSH EAX; 0x456026: CALL 0046f910`.
- `FUN_004df960(p1,p2) = (p2−p1)·u·2⁻³² + p1` where `u = FUN_004df8c0()`
  (32-bit RNG output). With `(0, 0x40490FD8)` this is `π′-scaled uniform`.
  `0x40490FD8` is 3 ulps below float-π (`0x40490FDB`); treated as π
  (inference from proximity, §4/U2).
- RNG core `FUN_004df900`: LCG pair —
  `s := (s·0x8088405+1) mod 0xFFFFFFFF` twice, returns
  `(u2 & 0xFFFF0000) + (u1 >> 0x10)` (state dword at `[ECX+4]`).
  `FUN_004df8c0` wraps it with an optional 128-entry shuffle table
  (`[ECX+0xC]`, indexed `u1 & 0x7f`) when flag `[ECX+0x20C] != 0`.

## 2. Observation: textual `[ESP+0x44]` is THREE different slots

Full-instruction grep over all 868 insns of `FUN_00455ba0`
(`ev_eaa31d319cc6ae0e90072f2f916f0546303dd42fe8d9bcf65301fa87b21dc1f7`):
the ONLY write to textual `[ESP+0x44]` is
`0x455d97: MOV [ESP+0x44],EBX` (EBX=0 on that JZ path), but ESP at `0x455d97`
is the post-prologue baseline, while reads at `0x456011`/`0x456170` execute
with many dwords of pushes outstanding. Decompiler variable identity
(`ev_51949136aba667306e0bfdeac2988db57808467fdf421bf5c4105420ee4e8eec`,
`ev_5cd1e17a2e70bb402c68c4b17e1124a461d7f459fafa44b2c8ee772ac9812734`) resolves:

| site | textual read | decompiler variable | role |
|---|---|---|---|
| `0x456011` → `CALL 0046f910` | `[ESP+0x44]` | `pvStack_3e4` = return of `FUN_004df960(0,0x40490fd8)` (`0x455fae`, stashed `0x455fb3: FSTP [ESP+0x24]`) | **angle** |
| `0x456170` → `CALL 00409060` (banner) | `[ESP+0x44]` | `local_3c4` (banner model handle from `FUN_00406450`) | handle, not angle |
| `0x455d97` write | `[ESP+0x44]` | baseline-frame slot (NULL-handle path) | unrelated |

So prior U3 phrasing "angle source `[ESP+0x44]`" names a stack address, not a
variable. The angle slot's life is: written once per tree iteration at
`0x455fb3`, read once at `0x456011`. No accumulation across iterations
(observed: unconditional `FSTP` overwrite each pass through the branch).

## 3. Observation: producer sequence (asm + pseudocode)

Tree-iteration window (`0x455f8e`–`0x456026`, asm-observed):

- `0x455f8e: MOV ECX,[ESP+0x40c]`; `PUSH EBP; PUSH EBX; CALL 004351a0`;
  `0x455f9c: FSTP [ESP+0x34]` — re-derives a float bound (kept as `fVar20`).
- `0x455fa0: PUSH 0x40490fd8; 0x455fa5: PUSH 0x0`;
  `0x455fa7: LEA ECX,[ESP+0x1f4]`; `0x455fae: CALL 004df960`;
  `0x455fb3: FSTP [ESP+0x24]` — angle draw (observation).
  Decompiler verbatim: `fVar14 = (float10)FUN_004df960(0,0x40490fd8);
  pvStack_3e4 = (void *)(float)fVar14;`
- Scale triple + T/S/R compose as before (submit-doc §4, unchanged):
  `0046f9f0` (T) / `0046fa40` (S, uniform `fStack_3e0` × 3) /
  `0046f910(auStack_260, pvStack_3e4)` (R) → `0046efc0` × 2 → `(R×S)×T`.
- Consumed only inside the `5.0 < FUN_00434ff0(...)` branch
  (`0x455f7d FCOMP [0x005cea90]; 0x455f88 JNZ` skips the whole tree when the
  comparison fails) and inside the per-count inner loop
  (`0x4560dc JNZ 0x00455f1f`, count from `FUN_00549f80` @ `0x455f0e`).
  Each submitted tree therefore draws its own angle (observation: draw sits
  inside both loops).

`FUN_004df960` body (50 B, `0x4df960`–`0x4df991`,
`ev_6c8ab4e565adf33a861a4973130034fed43b82c1d3f3db1c691348d1e32bc4cd`;
insns `ev_ddc42a4d8eb43ff10f81e98cde0405ca13dfb5760e03fadb63fa8f43956a90db`):

- Pseudocode verbatim: `uVar1 = FUN_004df8c0();
  return (param_2−param_1)·uVar1·2.3283064e-10 + param_1;`
- Asm shape: `SUB ESP,8; CALL 004df8c0` (ECX = caller object through);
  `FILD qword [ESP]` (u32 → 80-bit); `FLD [ESP+0x10]` (= p2);
  `FSUB [ESP+0xC]` (= p1); `FMULP; FMUL [0x005d09e8]` (= 2⁻³² scale);
  `FADD [ESP+0xC]` (= +p1); `RET 8` (2-arg thiscall cleanup).
- Param order (observation): `PUSH 0x40490fd8; PUSH 0x0` ⇒
  `param_1 = 0`, `param_2 = 0x40490FD8`. So angle = `p2·u·2⁻³² ∈ [0, p2)`.

RNG (`ev_71d5a614245022305664fe1be244855696594ddf25345332f10ab76f887b9cb2`,
`ev_71ceb09ee1b248c834376b839286ea0fb06567a4416c3f9c1b61c5630c0e7f25`):

- `004df900` pseudocode verbatim: two `__allmul(s, 0x8088405)` /
  `__allrem(+1, 0xFFFFFFFF)` steps on state `[ECX+4]`, stores second,
  returns `(u2 & 0xFFFF0000)+(u1>>16)`.
- `004df8c0`: if `[ECX+0x20C]==0` returns `004df900()` directly, else one
  128-entry table shuffle at `[ECX+0xC]`.

## 4. Inferences (labeled)

- Angle distribution uniform `[0, π)` up to the 3-ulp shortfall of the
  constant and LCG granularity (inference from formula + constant proximity).
- Per-tree independence: fresh draw per iteration (inference from draw
  position inside both loops + unconditional overwrite).
- Y-rotation handedness question (multiply-doc U1) is unaffected: whatever
  sign convention `f910` uses, its input here is nonnegotiable random
  `[0, π)` (inference).

## Unknowns

- U1 (open): RNG **instance identity** — the `ECX` object at `0x455fa7`
  (`LEA ECX,[ESP+0x1f4]`, temp built via `004df7e0`/`004df840` @
  `0x455eeb`/`0x455f07`) is a stack temp; which heap/global RNG state it
  aliases (seed, shared vs per-scene, save/load persistence) untraced.
  Also `[ECX+0x20C]` shuffle-flag value on this path untraced (direct vs
  shuffled output).
- U2 (open, cosmetic): whether `0x40490FD8` (π−3ulp) vs float-π `0x40490FDB`
  is deliberate or a rounded constant; observable rotation difference is
  nil (~7e-8 rad max). Needs only a constant note in transcription, not a
  "fix".
- U3 (method): conclusions from Ghidra pseudocode + instruction text;
  `get_navigation_context` unavailable for provider `ghidra`
  (`capability_unavailable`), so target identity rests on matching body
  range/insn count with parent dossiers, not a fresh session binding check.

## Recommendation: ONE next target

`FUN_004df7e0` (RNG/state object init at tree-loop `0x455eeb`,
`ECX=[ESP+0x1f0]` temp) — decides U1 (which RNG instance seeds the angle
draw and whether the shuffle flag is set). Small, directly upstream.
Not `0046f910` sign (independent) and not banner/frame/tower submits
(off-scope).
