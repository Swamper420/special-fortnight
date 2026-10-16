# Terrain RNG chain `FUN_004df9a0` / `FUN_004df960` / core (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Consumer: `FUN_004348a0` setup loop (`evidence/004348a0_terrain_loop.md`):
per tap `divA/B = (|004df9a0()| + 1.0) * s`,
`phA/B = 004df960(0, 4*pi)`. Terrain call sites (observed):
`004df9a0` <- `0x43498e`, `0x4349ad`; `004df960` <- `0x4349da`, `0x4349fe`.
`engine/src/mesh.rs` untouched. No new Rust code (core already
transcribed, see §5).

Evidence IDs (new):

- `ev_33d234f61ac5d47e3d36105125f2c2b4c7ada6ab315500a0d14d4174520192f0`
  (`analyze_function FUN_004df9a0`: body `0x4df9a0-0x4df9d8`, 57 bytes,
  contiguous; full asm + callers).
- `ev_5b1cbd690ce3d8724faee46f4635e498786bb1553f033dc2d497446468a97c1f`
  (`analyze_function FUN_004df960`: body `0x4df960-0x4df991`, 50 bytes,
  contiguous; full asm + callers).
- `ev_da6cd5772f0e55ad2c1818064895ef0dfe66a304693ff17b570d2f2c06a416cc`
  (`analyze_function FUN_004df8c0`: body `0x4df8c0-0x4df8f6`, 55 bytes,
  contiguous; shuffle-table dispatch).
- `ev_a5b68c51b095e337efd78ab2751beea3bcd6a2ed1ae6add44b5f8fb71a69a76f`
  (`analyze_function FUN_004df900`: body `0x4df900-0x4df958`, 89 bytes,
  contiguous; dual-step LCG core).
- `ev_d30266c7b7825b1d1cf57a661c666c5ffbf03258ba45ebc91c6b8274dc3eb931`
  (`analyze_function FUN_004df840`: body `0x4df840-0x4df872`, 51 bytes,
  contiguous; seed + optional 128-entry table fill; 17 callers incl.
  `0x4348a0` itself).
- `ev_e34cd4eb5aaa715bd06c4484bef52af2ac6f276795cf64aa288bfe9fcdc5f5ae`
  (`read_bytes 0x5d09e8`, 4 bytes: `00 00 80 2f` = `0x2F800000`
  = 2.3283064e-10 = 2^-32, the `004df960` scale factor).

## 1. Observation: `FUN_004df900` assembly (verbatim, `ev_a5b68c51...`)

```text
0x4df900: PUSH ESI
0x4df901: PUSH EDI
0x4df902: MOV EDI, ECX
0x4df904: PUSH 0x0
0x4df906: PUSH 0x8088405
0x4df90b: PUSH 0x0
0x4df90d: MOV EAX, dword ptr [EDI + 0x4]
0x4df910: PUSH EAX
0x4df911: CALL 0x0059edb0        ; __allmul
0x4df916: ADD EAX, 0x1
0x4df919: PUSH 0x0
0x4df91b: ADC EDX, 0x0
0x4df91e: PUSH -0x1
0x4df920: PUSH EDX
0x4df921: PUSH EAX
0x4df922: CALL 0x0059ecf0        ; __allrem
0x4df927: PUSH 0x0
0x4df929: PUSH 0x8088405
0x4df92e: MOV ESI, EAX
0x4df930: PUSH 0x0
0x4df932: PUSH EAX
0x4df933: SHR ESI, 0x10
0x4df936: CALL 0x0059edb0        ; __allmul
0x4df93b: ADD EAX, 0x1
0x4df93e: PUSH 0x0
0x4df940: ADC EDX, 0x0
0x4df943: PUSH -0x1
0x4df945: PUSH EDX
0x4df946: PUSH EAX
0x4df947: CALL 0x0059ecf0        ; __allrem
0x4df94c: MOV dword ptr [EDI + 0x4], EAX
0x4df94f: AND EAX, 0xffff0000
0x4df954: ADD EAX, ESI
0x4df956: POP EDI
0x4df957: POP ESI
0x4df958: RET
```

Pseudocode (verbatim, `ev_a5b68c51...`): `l = __allmul([ECX+4],0,0x8088405,0)`;
`u1 = __allrem(l+1, 0xffffffff, 0)`; `l = __allmul(u1,0,0x8088405,0)`;
`u2 = __allrem(l+1, 0xffffffff, 0)`; `[ECX+4] = u2`;
`return (u2 & 0xffff0000) + (u1 >> 0x10)`.

Inference (exact integer math, no float): push order matches MSVC
`__allmul(a_lo,a_hi,b_lo,b_hi)` / `__allrem(divid_lo,divid_hi,divs_lo,divs_hi)`,
so with state `s=[ECX+4]`:
`s1 = (s * 0x8088405 + 1) mod 0xFFFFFFFF`,
`s2 = (s1 * 0x8088405 + 1) mod 0xFFFFFFFF`,
state becomes `s2`, output `(s2 & 0xFFFF0000) + (s1 >> 16)`
(`+` == `|`; halves do not overlap). Multiplier `0x8088405` = 134775813
(Borland LCG constant); modulus `0xFFFFFFFF` = 2^32-1 (NOT 2^32).
Products fit u64 exactly (max ~5.8e17), so the algorithm is bit-exact in
plain 64-bit arithmetic. NOT a single-step LCG: two chained steps per
output, halves spliced.

## 2. Observation: `FUN_004df8c0` / `FUN_004df840` (verbatim excerpts)

`004df8c0` (`ev_da6cd577...`): if `[ECX+0x20c]==0`, tail-calls `004df900`
(returns raw). Else: `r1=004df900(); i=r1&0x7f; old=[ECX+0xC+i*4];
[ECX+0xC+i*4]=004df900(); return old` — 128-entry shuffle table.
`004df840` (`ev_d30266c7...`): `[ECX+4]=param_1` (seed); if
`[ECX+0x20c]!=0`, fills `[ECX+0xC..+0x20B]` with 128 `004df900()` outputs.
Object layout: state `[+0x4]`, table `[+0xC..+0x20B]`, mode flag `[+0x20C]`.

## 3. Observation: `FUN_004df960` assembly (verbatim, `ev_5b1cbd69...`)

```text
0x4df960: SUB ESP, 0x8
0x4df963: CALL 0x004df8c0
0x4df968: MOV dword ptr [ESP], EAX
0x4df96c: MOV dword ptr [ESP + 0x4], 0x0
0x4df974: FILD qword ptr [ESP]     ; exact (u32 fits i64)
0x4df978: FLD float ptr [ESP + 0x10]; hi
0x4df97c: FSUB float ptr [ESP + 0xc]; lo -> (hi-lo)
0x4df980: FMULP                    ; (hi-lo)*u
0x4df982: FMUL float ptr [0x005d09e8]; * 2^-32
0x4df988: FADD float ptr [ESP + 0xc]; + lo
0x4df98c: ADD ESP, 0x8
0x4df98f: RET 0x8
```

Inference: returns `(hi-lo)*u*2^-32 + lo` in x87 extended, `u` = full
u32 from `004df8c0`. `u*2^-32` in `[0,1)`, so finite `lo<=hi` gives
`[lo,hi)`. NaN/edge: no branches, no division; NaN `lo`/`hi` poisons
output via FSUB/FADD; `inf` propagates linearly. No NaN guard observed.

## 4. Observation: `FUN_004df9a0` assembly (verbatim, `ev_33d234f6...`)

```text
0x4df9a0: PUSH ECX
0x4df9a1: PUSH ESI
0x4df9a2: PUSH EDI
0x4df9a3: MOV ESI, ECX
0x4df9a5: MOV dword ptr [ESP + 0x8], 0x0
0x4df9ad: MOV EDI, 0x10
0x4df9b2: PUSH 0x3f800000         ; +1.0f
0x4df9b7: PUSH 0xbf800000         ; -1.0f
0x4df9bc: MOV ECX, ESI
0x4df9be: CALL 0x004df960
0x4df9c3: FADD float ptr [ESP + 0x8]
0x4df9c7: DEC EDI
0x4df9c8: FSTP float ptr [ESP + 0x8]
0x4df9cc: JNZ 0x004df9b2
0x4df9ce: FLD float ptr [ESP + 0x8]
0x4df9d2: FDIV float ptr [ESI + 0x8]
0x4df9d5: POP EDI
0x4df9d6: POP ESI
0x4df9d7: POP ECX
0x4df9d8: RET
```

Inference: `acc=0; repeat 16x: acc += 004df960(-1.0,+1.0)` (x87 extended
accumulate, f32 round per store); `return acc / [ECX+8]` (`FDIV` f32
divisor field on the SAME object, ECX threaded through). Range open:
each draw in `[-1,+1)`, sum in `(-16,16)`; divisor value unobserved
(hence output range unobserved). NaN/edge: `FDIV` by `0.0` -> x87
`±inf` (no trap under default CW); NaN divisor/acc -> NaN; terrain then
applies `FABS` + `+1.0`, so sign is discarded but NaN/inf survive
(`|NaN|` unordered, `|inf|+1=inf` -> downstream `FDIV divA=inf` yields 0
taps — inference, not observed).

Callers of `004df9a0` (observed): `0x4348a0` (terrain, sites `0x43498e`,
`0x4349ad`), `0x453a60`, `0x459020`, `0x4590c0`, `0x459110`, `0x45b130`,
`0x53b640`, `0x53b7f0`. No strings referenced in any of the five bodies
(numeric + calls only).

## 5. Transcription status

`FUN_004df900` core is ALREADY transcribed: `engine/src/decrypt.rs`
`prng_step` (`s1=(s*A+1)%M`, `s2=(s1*A+1)%M`,
`out=(s2&0xFFFF0000)|(s1>>16)`, returns low byte). Cross-check this wave:
Python model of §1 against `decrypt` test vector
(`seed 0x4013CD3A` -> bytes `07 8f e5 9f`, `prng_matches_reference`)
matches exactly. First-values fixtures (u64-exact model, for the future
1:1 module): seed `0` -> `08080000 06b1dcae c04688bc 6fc8ebbb`
(end state `6fc8ff95`); seed `1` -> `dcae0808 88bc06b1 ebbbc046
7adf6fc8` (end state `7adfd1d4`). Per ponytail rung 2 (reuse) + 1:1
(one function per procedure), NO duplicate module is created now: the
full-u32-output variant, `004df8c0` shuffle, `004df960` x87 scaling, and
`004df9a0` averaging stay evidence-only until the RNG object (below) is
mapped. `mesh.rs` untouched.

## Unknowns:

- U1 (next target, single): RNG object identity feeding `FUN_004348a0` —
  trace ECX at `0x43498e`/`0x4349ad`/`0x4349da`/`0x4349fe` back to its
  allocation/seed: which `004df840` caller + seed value, mode flag
  `[+0x20C]` (raw vs 128-entry shuffle), and divisor field `[+0x8]`
  value/writer. (`004df840` caller list includes `0x4348a0` itself;
  in-body seed call-site address not yet mapped.)
- U2: seed value(s) at runtime (hill-dependent? fixed? time-derived?) —
  needs U1 first.
- U3: `004df960` exact x87 rounding vs host f64 (only matters at >1-ulp
  parity checks; integer core is bit-exact).

## Callers / callees

- `004df9a0` callees: `004df960` only. Callers: §4 list.
- `004df960` callees: `004df8c0` only. Callers: `0x4348a0` (sites
  `0x4349da`, `0x4349fe`), `0x452f70`, `0x453790`, `0x455ba0`, `0x458df0`,
  `0x45dce0`, `0x4607f0`, `0x4df9a0`, `0x53b560`, `0x53b640`, `0x53b7f0`.
- `004df8c0` callees: `004df900` only. `004df900` callees: `__allmul`
  (`0x59edb0`), `__allrem` (`0x59ecf0`) only.
