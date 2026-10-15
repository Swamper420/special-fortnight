# Takeoff markers (FUN_00538660 + stores in FUN_00434020)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE. Session opened via
`tools.rea.open_binary`; dossiers below are Ghidra 12.1.2
representations, not original source.

## 1. Claim: FUN_00538660 is a 3-word store, no branches

Observation (pseudocode, ev_04aa9bdc948aa55631ee2a96cc422cc243e9e37235a14a6d42f836d7f8819c4f):

```c
void FUN_00538660(undefined4 param_1, undefined4 param_2, undefined4 param_3)
{
  undefined4 *in_ECX;
  *in_ECX = param_1;
  in_ECX[1] = param_2;
  in_ECX[2] = param_3;
  return;
}
```

Observation (assembly, same evidence; 8 insns, `0x538660`-`0x538678`):

```
0x538660: MOV EDX, dword ptr [ESP + 0x8]
0x538664: MOV EAX, ECX
0x538666: MOV ECX, dword ptr [ESP + 0x4]
0x53866a: MOV dword ptr [EAX], ECX
0x53866c: MOV ECX, dword ptr [ESP + 0xc]
0x538670: MOV dword ptr [EAX + 0x4], EDX
0x538673: MOV dword ptr [EAX + 0x8], ECX
0x538676: RET 0xc
```

So: thiscall, `ECX` = dest, 3 stack args, callee cleans
12 bytes (`RET 0xc`). Caller passes floats by value through
integer `PUSH` + `FSTP [ESP]` overwrite (see §2); the callee
itself does pure 32-bit `MOV` copies — no float conversion,
no branches, no callees, no referenced strings/names.

Callers (observed, same evidence; 40 total, only the inrun
one is in scope): `FUN_00434020` (`0x434020`) calls it twice
(`0x4342f7`, `0x434341`). Callees: none.

## 2. Call sites in FUN_00434020 (ev_5ea46e79473f512510187be438baf8fea5ddfce8a4065e628f99b326834e9f9f dossier, ev_f8aaee702eef395105e7510e3025990d7aa5213cc8f750ff198b11e23e009ce9 raw instructions)

Observation (decompiler pseudocode tail, branch-free):

```c
fVar1 = (float)-(float10)param_4;            // -as
fVar13 = sin(-(float10)param_4);
fVar14 = cos((float10)fVar1);
puVar12 = FUN_00538660(cos*param_3 + fVar6, sin*param_3 + DAT_00608ae4 + fVar7, param_9);
[ECX+0x268] = puVar12[0]; [ECX+0x26c] = puVar12[1]; [ECX+0x270] = puVar12[2];
puVar12 = FUN_00538660((param_3+0.075)*cos + fVar6,
                       (param_3+0.075)*sin + DAT_00608ae8 + fVar7, param_9);
[ECX+0x274] = puVar12[0]; [ECX+0x278] = puVar12[1];
[ECX+0x25c] = 0;
[ECX+0x27c] = puVar12[2];
*(float*)(ECX+0x280) = fVar1;                // -as
*(float*)(ECX+0x284) = fVar6;                // P3.x
```

Observation (assembly order, `0x4342ae`-`0x43437e`):

```
0x4342ae: FLD [ESP+0x58]        ; as (slot; cf. U1)
0x4342b2: FCHS                  ; -as
0x4342b4: FST [ESP+0x58]        ; fVar1 spill (exact, FCHS+FST)
0x4342b8: FSIN                  ; sin(-as), x87 extended
0x4342ba: MOV EDI,[ESP+0x6c]    ; EDI = param_9 (opaque word)
0x4342be: PUSH EDI              ; arg3 = param_9
0x4342bf: PUSH ECX              ; stack reservation (overwritten)
0x4342c0: FSTP [ESP+0x6c]       ; sin -> f32 slot
0x4342c4: FLD [ESP+0x60]        ; -as (fVar1)
0x4342c8: FCOS                  ; cos(-as), x87 extended
0x4342ca: FSTP [ESP+0x58]       ; cos -> f32 slot
0x4342ce: FLD [ESP+0x6c]        ; sin
0x4342d2: FMUL [ESP+0x5c]       ; sin*lg (param_3; cf. U1)
0x4342d6: FADD [0x00608ae4]     ; +K1 (bits 0x3E99999A, ≈0.3, NOT exact 0.3)
0x4342dc: FADD [ESP+0x68]       ; +P3.y slot
0x4342e0: FSTP [ESP]            ; arg2 = y1 (overwrites PUSH reservation)
0x4342e3: FLD [ESP+0x58]        ; cos
0x4342e7: FMUL [ESP+0x5c]       ; cos*lg
0x4342eb: PUSH ECX              ; reservation
0x4342ec: LEA ECX,[ESP+0x30]    ; dest = temp 12-byte struct
0x4342f0: FADD [ESP+0x68]       ; +P3.x slot
0x4342f4: FSTP [ESP]            ; arg1 = x1
0x4342f7: CALL 0x00538660      ; m1 = (x1, y1, param_9)
0x4342fc: FLD [ESP+0x54]        ; lg
0x434300: FADD [0x005ce048]     ; +STEP (bits 0x3D99999A, ≈0.075)
0x434306: MOV EDX,[EAX]         ; m1.x -> [ESI+0x268] via LEA ECX,[ESI+0x268]
0x434308: LEA ECX,[ESI+0x268]
0x43430e: PUSH EDI              ; arg3 = param_9
0x43430f: MOV [ECX],EDX
0x434311: MOV EDX,[EAX+0x4]     ; m1.y -> [ESI+0x26c]
0x434314: FLD ST0               ; dup t (= lg+STEP)
0x434316: FMUL [ESP+0x68]       ; t*sin (slot shifted by PUSHes)
0x43431a: MOV [ECX+0x4],EDX
0x43431d: MOV EAX,[EAX+0x8]     ; m1.tag -> [ESI+0x270]
0x434320: PUSH ECX              ; reservation
0x434321: MOV [ECX+0x8],EAX
0x434324: FADD [0x00608ae8]     ; +K2 (bits 0x3F170A3D, ≈0.59)
0x43432a: FADD [ESP+0x68]       ; +P3.y slot
0x43432e: FSTP [ESP]            ; arg2 = y2
0x434331: PUSH ECX              ; reservation
0x434332: LEA ECX,[ESP+0x3c]    ; dest = temp struct
0x434336: FMUL [ESP+0x5c]       ; t*cos
0x43433a: FADD [ESP+0x68]       ; +P3.x slot
0x43433e: FSTP [ESP]            ; arg1 = x2
0x434341: CALL 0x00538660      ; m2 = (x2, y2, param_9)
0x434346: MOV EDX,[EAX]         ; m2.x -> [ESI+0x274]
0x434348: LEA ECX,[ESI+0x274]
0x43434e: MOV [ESI+0x274],EDX
0x434354: MOV EDX,[EAX+0x4]     ; m2.y -> [ESI+0x278]
0x434357: MOV [ECX+0x4],EDX
0x43435a: MOV EAX,[EAX+0x8]     ; tag
0x43435d: MOV [ESI+0x25c],EBP   ; = 0 (EBP zeroed at 0x43404c, never rewritten; full-list grep)
0x434363: MOV [ECX+0x8],EAX     ; m2.tag -> [ESI+0x27c]
0x434366: MOV ECX,[ESP+0x58]    ; -as bits
0x43436a: MOV [ESI+0x280],ECX   ; [ESI+0x280] = -as (bit copy)
0x434370: MOV EDX,[ESP+0x5c]    ; P3.x bits
0x434378: MOV [ESI+0x284],EDX   ; [ESI+0x284] = P3.x (bit copy)
```

Observation (file bytes at constants, `read_bytes`):

- `[0x608ae4]` = bytes `9a99993e` LE = bits `0x3E99999A`
  = `0.30000001192092896` (ev_f0e336eb94f66cfe3d36e9e9012fe49e9eb875f10e8a866f41808c00477b7aa2).
- `[0x608ae8]` = bytes `3d0a173f` LE = bits `0x3F170A3D`
  = `0.5899999737739563` (ev_64399f911cec3735a75b6d7444c45ecdc67b89ae8c819894e1cd7cf1ef72cf65).
- `[0x5ce048]` = bytes `9a99993d` LE = bits `0x3D99999A`
  = `0.07500000298023224` (ev_37b3aecb6b74902bb4d46188c314b2aecaf2ac99b6de00e6b5ae9dcefa3eab17).
- `[0x5cd3c0]` = `0x3F000000` = exactly `0.5`
  (ev_4d8f39fb76c2f74ed9e848a340b99f7147b465f1f136b1e1f059abc2e505bba8;
  used for `ws*0.5`, not markers).
- `[0x5cdda8]` = `0x3FC00000` = exactly `1.5`
  (ev_dff95907c29fc3c2830514b7b08d17d5866bb201321e1573f428c0fa47f5a4a2;
  anchor math, not markers).
- `[0x61b880]` = `0x00000000` = `0.0` in file, set to pi at
  runtime (ev_59341c3168308e6d7e96e8440d8771aba2302453178d338a60fff33c4c63a204).

## 3. Rust transcription

`engine/src/mesh.rs`: `TAKEOFF_K1/K2/STEP` via
`f32::from_bits` (exact file bits, never decimal
shorthand), `TakeoffMarkers { m1, m2, flag, neg_as,
p3x_copy }`, `takeoff_markers(lg, as_rad, p3x, p3y, tag)`:
op order = asm (`(sn*lg+K1)+P3.y`, `cs*lg+P3.x`,
`t=lg+STEP` once, `((t*sn)+K2)+P3.y`, `(t*cs)+P3.x`),
x87 extended intermediates ≈ `f64` with `FSTP` rounding
(`as f32` at each stored slot), `neg_as = -as_rad`
(exact `FCHS`), `flag = 0` (`EBP`), tag passed through.

## Unknowns

- U1 (inference, inherited): stack-slot → param symbolic
  mapping past the `0x43416b PUSH ECX` ESP-shift relies on
  the decompiler (`param_3`=lg, `param_4`=as, `fVar6`=P3.x,
  `fVar7`=P3.y, `param_9`=opaque word). Offsets, widths,
  op order, and constant bits are observed; the *names*
  lg/as/P3/tag are inference consistent with the anchor
  chain (`mesh.rs` `anchors()`) and the task brief, not
  re-proven here. Note `lg` is never consumed by
  `anchors()` — its only use is these markers.
- U2 (unknown): meaning of `param_9`/tag word and of the
  `[ESI+0x25c/0x268..0x284]` struct as a whole; which
  consumer reads the markers (composition
  `FUN_00436620` unmapped — untouched, out of scope).
- U3 (unknown): `K1≈0.3` / `K2≈0.59` physical meaning;
  recorded as exact bits, no decimal rounding in code.
- U4 (unknown): float exactness — x87 80-bit `FSIN/FCOS/
  FMUL/FADD` vs `f64` intermediates: last-ulp differences
  possible at every slot; `sin`/`cos` op-order only, no
  tolerance measured against the binary (static analysis;
  binary never executed).
- U5 (out of scope, untouched): curve objects, `de150`
  key/tree, composition transform, `ddf10/ddcb0` paths.
