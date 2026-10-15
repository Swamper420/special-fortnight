# FUN_004348a0 sin-weight tail (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe`, SHA-256
`3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Range `0x434cd8`–`0x434dcb` (per-vertex tail, runs after the noise loop).
Closes U3 sin-weight wiring from `evidence/004348a0_terrain_loop.md`.

Evidence IDs:

- `ev_94f24797617f7e2d155cf2a6de1b2b898ad4d4cad08ecb799f335d901343720a`
  (`read_function_instructions`, all 522 insns; tail + slot producers).
- `ev_6aa12cdd56427e2cd5c7cc4e87752d27985c3bf515442de3b43e3c416a697016`
  (`analyze_function`, decompiler pseudocode; its tail call-arg recovery is
  partial — stack-slot identities below come from the instruction listing
  + an ESP simulation, not from the pseudocode).
- `ev_4a9498634e43d7183a79d5926e1820008b5f4ed346625ca9d27d985ec302e433`
  (`FUN_00468360` = `max2`), `ev_7b3d71a958a830e76ceb38a1368d863ddaa16dbc61b30c2eb8b06aa5327d3c8b`
  (`FUN_00468340` = `min2`), `ev_b11d10d4160442b15a1a12df116ebfefabba1fd641ca34de8aaebc35aa9e3344`
  (`FUN_00468310` = `clamp3`).
- `ev_7d40709b5f0d4000727bb6cc40c59cb8af5891b2511c8e7ea64c03042eb8dac2`
  (`FUN_004de320`), `ev_41ec2c996d4ed3fa66ff0369f66a4716199e2548a7acab8e386d107308264316`
  (`FUN_00434ff0` return in ST0, `RET 8`).
- Callees `FUN_004de320/004de350` return with plain `RET` (caller cleans);
  `FUN_00434ff0` `RET 8`, `FUN_004de3e0` `RET 4`, `FUN_004df960` `RET 8`,
  `FUN_004df7e0/004df840` `RET 4`, `FUN_0055b490` `RET 8` (from the
  per-callee instruction tails fetched this wave). ESP simulation over all
  522 insns with these cleanups resolves every tail cell below.

Constants (file bytes, image base `0x400000`, exact `f32` bits):

| VA | bits | value |
| --- | --- | --- |
| `[0x5ce050]` | `0x3d088889` | `0.033333335` |
| `[0x5ce054]` | `0x3e99999a` | `0.3` |
| `[0x5ce058]` | `0x3b5a740e` | `0.0033333334` |
| `[0x5cd3bc]` | `0x3f800000` | `1.0` |
| `[0x5cd378]` | `0x0` | `0.0` |

(`[0x61b880]` is pi at runtime, file `0.0` — not used by this tail.)

## Pseudocode (corrected from asm; decompiler lost the FPU weight block)

```text
// FPU stack traced op-for-op; [..] cells are entry-ESP-relative ids.
s6 = FSIN(param_6);                       // 0x434cd8, FLD cell 24 = param_6
s7 = FSIN(param_7);                       // 0x434ce9, FLD cell 28 = param_7
// 0x434cf2-0x434d0f: ST = s7*(X-Y) + Z*s6, then +param_5, FSTP f32:
wsum  = (fvar4 - lo_b60) * s7 + fvar5 * s6 + param_5;  // f32 round at store
t1 = base * 0.0033333334;                 // 0x434d11-0x434d1b, f32 round
t2 = base * 0.3;                          // 0x434d1f-0x434d29, f32 round
m1 = max2(a = param_2, b = 1.0 - t1);     // 0x434d2d-0x434d3b, NaN -> a
m1h = m1 * h;                             // 0x434d40, FSTP f32 round
m2 = min2(a = 1.0 - param_2, b = t1);     // 0x434d4b-0x434d61, NaN -> b
combined = m2 * wsum + m1h;               // 0x434d66-0x434d71, f32 round
f16 = clamp3(lo = h - t2, hi = h + t2, v = combined);  // 0x434d74-0x434d8c
f18 = min2(a = base * 0.033333335, b = 1.0);          // 0x434d95-0x434dab, NaN -> b
v = f18 * noise + f16;                    // 0x434db0-0x434dcb, single f32 round
```

## Assembly (tail `0x434cd8`–`0x434dcb`, verbatim from `ev_94f24...`)

```text
0x434cd8: FLD float ptr [ESP + 0x358]     ; param_6 (cell 24)
0x434cdf: FSIN                            ; s6
0x434ce1: MOV EAX, dword ptr [ESP + 0x348] ; param_2 bits (cell 8)
0x434ce8: PUSH ECX                        ; first max2 arg slot
0x434ce9: FLD float ptr [ESP + 0x360]     ; param_7 (cell 28)
0x434cf0: FSIN                            ; s7
0x434cf2: FLD float ptr [ESP + 0x18]      ; X = fvar4 (0x434b77 slot)
0x434cf6: FSUB float ptr [ESP + 0x2c]      ; Y = lo_b60 (0x434a1c slot)
0x434cfa: FMULP                           ; (X-Y)*s7
0x434cfc: FLD float ptr [ESP + 0x20]      ; Z = fvar5 (0x434b8f slot)
0x434d00: FMUL ST2                        ; Z*s6 (s6 kept)
0x434d02: FADDP                           ; (X-Y)*s7 + Z*s6
0x434d04: FADD float ptr [ESP + 0x358]    ; + param_5 (cell 20)
0x434d0b: FSTP float ptr [ESP + 0x14]     ; wsum, f32 round
0x434d0f: FSTP ST0                        ; discard s6
0x434d11: FLD float ptr [ESP + 0x24]      ; base (0x434ba5 slot, 434ff0 ret)
0x434d15: FMUL float ptr [0x005ce058]     ; * 0.0033333334
0x434d1b: FSTP float ptr [ESP + 0x20]     ; t1
0x434d1f: FLD float ptr [ESP + 0x24]      ; base
0x434d23: FMUL float ptr [0x005ce054]     ; * 0.3
0x434d29: FSTP float ptr [ESP + 0x18]     ; t2
0x434d2d: FLD float ptr [0x005cd3bc]      ; 1.0
0x434d33: FSUB float ptr [ESP + 0x20]     ; 1.0 - t1
0x434d37: FSTP float ptr [ESP]            ; over second push slot
0x434d3a: PUSH EAX                        ; param_2
0x434d3b: CALL 0x00468360                 ; m1 = max2(a=param_2, b=1-t1)
0x434d40: FMUL float ptr [ESP + 0x20]     ; m1*h (h cell)
0x434d44: MOV ECX, dword ptr [ESP + 0x24] ; ECX = t1 bits
0x434d48: ADD ESP, 0x8
0x434d4b: PUSH ECX                        ; t1 (survives as min2 b)
0x434d4c: PUSH ECX                        ; placeholder, overwritten next
0x434d4d: FSTP float ptr [ESP + 0x34]     ; park m1*h (f32 round)
0x434d51: FLD float ptr [0x005cd3bc]      ; 1.0
0x434d57: FSUB float ptr [ESP + 0x350]    ; 1.0 - param_2 (cell 8)
0x434d5e: FSTP float ptr [ESP]            ; over placeholder
0x434d61: CALL 0x00468340                 ; m2 = min2(a=1-param_2, b=t1)
0x434d66: FMUL float ptr [ESP + 0x18]     ; m2*wsum (wsum cell)
0x434d6a: ADD ESP, 0x4
0x434d6d: FADD float ptr [ESP + 0x30]     ; + parked m1*h
0x434d71: FSTP float ptr [ESP]            ; combined (f32 round, clamp v)
0x434d74: FLD float ptr [ESP + 0x18]      ; t2
0x434d78: FADD float ptr [ESP + 0x1c]     ; hi = t2 + h
0x434d7c: PUSH ECX
0x434d7d: FSTP float ptr [ESP]            ; hi arg
0x434d80: FLD float ptr [ESP + 0x20]      ; h
0x434d84: FSUB float ptr [ESP + 0x1c]     ; lo = h - t2
0x434d88: PUSH ECX
0x434d89: FSTP float ptr [ESP]            ; lo arg
0x434d8c: CALL 0x00468310                 ; f16 = clamp3(lo, hi, combined)
0x434d91: FSTP float ptr [ESP + 0x38]     ; park f16
0x434d95: FLD float ptr [ESP + 0x2c]      ; base
0x434d99: FMUL float ptr [0x005ce050]     ; * 0.033333335
0x434d9f: ADD ESP, 0xc
0x434da2: PUSH 0x3f800000                 ; 1.0 (min2 b)
0x434da7: PUSH ECX                        ; placeholder
0x434da8: FSTP float ptr [ESP]            ; scaled base (min2 a, f32 round)
0x434dab: CALL 0x00468340                 ; f18 = min2(a=base*1/30, b=1.0)
0x434db0: FMUL float ptr [ESP + 0x44]     ; f18*noise (noise cell)
0x434db4: MOV ESI, dword ptr [EBP + 0x78]
0x434db7: MOV EDX, dword ptr [EBP + 0x7c]
0x434dba: SUB EDX, ESI
0x434dbc: ADD ESP, 0x8
0x434dbf: FADD float ptr [ESP + 0x2c]     ; + f16
0x434dc3: SAR EDX, 0x2
0x434dc6: CMP EDX, 0x1
0x434dc9: MOV EDI, ESI
0x434dcb: FSTP float ptr [ESP + 0x38]     ; v (f32 round) -> vector push next
```

## Slot map (entry-ESP-relative cells from ESP simulation)

| Tail use | cell | producer (last write before tail read) | identity |
| --- | --- | --- | --- |
| `s6` source | 24 | incoming stack | `param_6` |
| `s7` source | 28 | incoming stack | `param_7` |
| `EAX` | 8 | incoming stack | `param_2` (bits) |
| `W` (`FADD`) | 20 | incoming stack | `param_5` read as `f32` |
| `1-param_2` subtrahend | 8 | incoming stack | `param_2` |
| `X` | −812 | `0x434b77 FSTP [ESP+0x14]` | `fvar4` (vertex x: `FILD col × [EBP+0x94] + [EBP+0x8c]`, same cell `PUSH`ed as `434ff0` arg at `0x434b98`) |
| `Y` | −792 | `0x434a1c FSTP [ESP+0x28]` | `strip_lo([EBP+0x60])` = lo_b60 (`FUN_004de320`, throws if absent) |
| `Z` | −804 | `0x434b8f FSTP [ESP+0x1c]` | `fvar5` (vertex y: `[ESP+0x58] × [EBP+0x90] + [EBP+0x88]`, same cell `PUSH`ed as `434ff0` 2nd arg at `0x434b97`) |
| `A` (base) | −800 | `0x434ba5 FSTP [ESP+0x20]` | `FUN_00434ff0(fvar4, fvar5)` return (ST0) |
| `C` (h) | −808 | `0x434bce/0x434c1c/0x434c71 FSTP [ESP+0x18]` | height accum `local_328` after guard adjusts (guard order per loop evidence, not this file) |
| noise | −772 | `0x434cd4 FSTP [ESP+0x3c]` | cosine accum (`terrain_noise`, already transcribed) |
| `ECX=t1` | −804 | `0x434d1b FSTP [ESP+0x20]` | `t1` (first `PUSH ECX` value reused as `min2` b) |

Callers: `FUN_00436620` (`0x437702`). Callee set for the whole procedure
is in `ev_6aa12...` (34ff0, 435740, 435770, 468310/340/360, 475330,
4de320/350/3e0, 4df7e0/830/840/960/9a0, 55b490, 59c120, operator_new,
__ftol, 59e643). No strings in body (numeric code + calls only).

## Combines reused (asm-shape identical, no new transcription)

- `max2(a, b)` = `FUN_00468360`: `FLD [ESP+8]; FCOMP [ESP+4]; TEST AH,1`;
  `b < a` or unordered → `a`, else `b`. = `crate::mesh::max2`.
- `min2(a, b)` = `FUN_00468340`: `FLD [ESP+8]; FCOMP [ESP+4];
  TEST AH,0x41`; `[ESP+8] <= [ESP+4]` or unordered → `[ESP+8]`
  (= first-pushed), else `[ESP+4]`. = `crate::fn_00435740::min2`
  with `(a = [ESP+4], b = [ESP+8])`.
- `clamp3(lo = [ESP+4], hi = [ESP+8], v = [ESP+0xc])` = `FUN_00468310`:
  `v < lo` or unordered → `lo`; `v > hi` → `hi`; else `v`
  (incl. unordered second stage → `v`). = `crate::mesh::clamp3`.

## Transcription

`engine/src/mesh.rs` `terrain_sin_tail` (+ consts `TERRAIN_W_LO/HI/F18`),
one `f64`-intermediate op per x87 op, one `f32` round per `FSTP`.
Covered by `mesh::tests::terrain_sin_tail_weights` (generated fixtures).

## Unknowns

- `U-host-sin`: `FSIN` is x87 80-bit; transcription uses host
  `f64::sin` on the `f32`→`f64` widened param. Bit-exactness of
  `FSIN` vs libm is not established (expected ≤ few ulp of `wsum`).
  Observation: `FLD float; FSIN` sequence. Inference: host sin.
- `U-tie-sign`: `min2`/`max2` exact tie with mixed-sign zero returns the
  first-pushed side in asm; the reused Rust transcriptions return the
  second-pushed side. Inherited from prior waves, not re-decided here.
  No behavioral difference except `±0.0` bit pattern.
- Still open, not this wave: RNG tables (`004df960/004df9a0` setup loop),
  vector growth (`operator_new`/`00475330`/`0059c120` push path), exact
  `004348a0` call-site addresses of the 2+1 reader sites (strip-minmax
  dossier U2), downstream use of the min/max results, guard-block `h`
  inputs (`local_328` producers before `0x434c71`).

## U-status

- U3 sin-weight wiring: CLOSED (this file). `v = f18*noise + f16` with
  `wsum/t1/t2/m1/m2/combined/f16/f18` mapped above.
- U3 max/min-arg order: closed earlier (`004348a0_terrain_loop.md` §U3).
- Remaining: RNG tables, vector growth, reader call-site addresses (U2),
  downstream min/max use.
