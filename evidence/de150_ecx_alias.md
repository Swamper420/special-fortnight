# de150 ECX alias trace (U1 of `de150_flag.md`, next target of `strip_ctor_xrefs.md`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: strictly forward data-flow into `FUN_004de150`'s `ECX` from its
five emitter call sites plus the landing direct-insert loop: is `ECX`
always a ctor-backed strip, or does any path alias another object?
No engine code touched. Parents: `evidence/de150_flag.md` (U1),
`evidence/strip_ctor_xrefs.md` (recommended next target).

## 1. Observation: de150 has exactly five callers

`analyze_function 0x4de150`
(`ev_a72e89675a03b65e98bbffc709dcbece45ed7e7f08b603f91147b155e6bbc7e8`,
this session) confirms callers `0x434390`, `0x4dda60`, `0x4ddae0`,
`0x4ddcb0`, `0x4ddf10` — same set as `004de150_index.md` §1.
De150 entry `0x4de155: MOV EBP, ECX`, flag read
`0x4de1c8: MOV DL, [EBP+0x8]` with `EBP = ECX+0x10`, i.e.
`[ECX+0x18]`. So the question is exactly what object each call site
puts in `ECX`.

## 2. Observation: all four emitter-internal de150 sites pass `in_ECX` through

`read_function_instructions` windows (this session):

- `0x4dda60`: `0x4ddabc: MOV ECX, ESI` / `0x4ddabe: CALL 0x004de150`
  (`ev_c684fde3b083eb024998f918ef02078dc28dc057751ba03d85dea6a9ead81c81`).
  Only `MOV ESI` in body: head `0x4dda64: MOV ESI, ECX`. Single
  static assignment dominates. `ECX == in_ECX`.
- `0x4ddae0`: `0x4ddc75: MOV ECX, ESI` / `0x4ddc77: CALL 0x004de150`
  (`ev_a1f116a0f2ed84d7ac444745dfb0776c4a7244c413f77d2ea05aee7456633f21`).
  Only `MOV ESI` in body: head `0x4ddafa: MOV ESI, ECX`
  (`ev_a1f116a0...` re-read). `ECX == in_ECX`.
- `0x4ddf10` (two sites): `0x4de0ff: MOV ECX, EBX` /
  `0x4de105: CALL 0x004de150`; `0x4de116: MOV ECX, EBX` /
  `0x4de118: CALL 0x004de150`
  (`ev_d3ff4275eb70dd9accb448a3f99d627a452b070f7c40d712cf66e60da842d350`).
  Only `MOV EBX` in body: head `0x4ddf29: MOV EBX, ECX`.
  `ECX == in_ECX` at both sites.
- `0x4ddcb0` (two sites): `0x4ddecd: MOV ECX, EBX` /
  `0x4dded3: CALL 0x004de150`; `0x4ddee2: MOV ECX, EBX` /
  `0x4ddee4: CALL 0x004de150`
  (`ev_c70a3b9af6856aeed8a623249d5af75ca8ec3354ca2fda884e2599b3a327e90a`).
  Chain: head `0x4ddcd0: MOV ESI, ECX` → spill
  `0x4ddcd3: MOV [ESP+0x10], ESI` → reload
  `0x4dde3b: MOV EBX, [ESP+0x10]`; no `MOV EBX` between `0x4dde3b`
  and either site (only `MOV EBX` in body are `0x4dddc3`, before the
  reload, and the reload itself); sole slot writer before the reload
  is `0x4ddcd3` (next writer `0x4dde42` is after the reload and only
  feeds float temps + the `0x4ddec1` ESI reload). At `0x4dde3b`,
  `ESI` still holds `in_ECX` (only `MOV ESI` in body are `0x4ddcd0`,
  `0x4dde58`, `0x4ddec1`, both latter after the reload).
  `ECX == in_ECX` at both sites, via one ABI link (below).

Emitter dossiers (this session) agree on shape: each emitter reads
`[in_ECX+0x30]` guard / `[in_ECX+0x20]` cursor and forwards
`param_1/param_2` to de150
(`ev_6e25eaf52377aefd1f67b839172045190d41df0ca546edd807c28098ac63a957`,
`ev_d6f345594e071d7b861cbbb399211923cf3fa5fbe0ff4f744608a68535b88974`,
`ev_ff2485d289787b10ea503f4d7e37ccfb048285eb79c19c9c2bbad9f36c10af58`,
`ev_36d3bc70a16ee2d4f88a8e096a8f668ec488200801099146718b90d591c1baf0`).

## 3. Observation: every builder→emitter call passes a ctor-backed strip

Backward scan in `0x434020` / `0x434390`: for each emitter `CALL`,
the nearest preceding `MOV ECX` with no intervening `CALL`
(`ev_f7f67a66445221f001d2f5b1e7cfe9b1b34497cf751f21e35e22cd5a3b1608cc`,
`ev_d1fb88a82b7fb1d00d78bcfcb05167f694ad1ddd5c1a9bfc805fee787e9c6a43`,
same Evidence IDs as the prior sweep, re-read this session):

- `0x434020`: all seven emitter calls resolve to `[ESI+0x50]`
  (`0x434225→0x43416c dda60`, `0x434237→0x434233 ddae0`,
  `0x434249→0x434246 ddae0`, `0x434265→0x434261 ddf10`,
  `0x434273→0x43426e ddae0`) or `[ESI+0x58]`
  (`0x434297→0x43428a dda60`, `0x4342a1→0x43429c ddae0`).
- `0x434390`: all eleven emitter calls resolve to `[ESI+0x60]`
  (`dda60@0x4345fd`, `ddcb0@0x43463f/@0x4346a5`,
  `ddf10@0x43465b/@0x434673`, `ddae0@0x434684`) or `[ESI+0x68]`
  (`dda60@0x43475b`, `ddae0@0x434779/@0x434798/@0x4347b8`,
  `ddf10@0x4347c6`).

Per `strip_ctor_xrefs.md` §§2-3, all four slots hold objects built
by strip ctor `0x4dd5c0` (`+0x50/+0x58` of `0x434020`,
`+0x60/+0x68` of `0x434390`), which zeroes `[+0x18]`
(`0x4dd611`, `de150_flag.md` §1). No emitter call takes `ECX` from
any other source. (Decompiler pseudocode for both builders,
`ev_b8b8f0adf77ae8711d2c0929214da9fcf111ae4d97cba79fb3ad4868fc150c54`
and `ev_4508fb29cf4171528146975ebde78b0961b5994d31ac2ff826b4ffe63ac67df5`,
shows the same emitter sequence with implicit thiscall `ECX`;
the object identity comes from the assembly scan above, not the
pseudocode.)

## 4. Observation: landing-loop direct de150 call passes spilled `[ESI+0x60]`

Loop body `0x4346cf-0x43473b`
(`ev_d1fb88a82b7fb1d00d78bcfcb05167f694ad1ddd5c1a9bfc805fee787e9c6a43`):

```text
0x4346e1: MOV EDX, dword ptr [ESI + 0x60]
0x4346e4: LEA ECX, [ESP + 0x38]
0x4346e8: MOV dword ptr [ESP + 0x80], EDX   ; spill strip, ESP=E0
...
0x43471c: PUSH EAX
0x43471d: CALL 0x004432a0                   ; RET 0x4 (stdcall, ev_4189...)
0x434722: PUSH ECX
0x434723: MOV ECX, dword ptr [ESP + 0x78]
0x434727: FSTP float ptr [ESP]
0x43472a: PUSH ECX
0x43472b: MOV ECX, dword ptr [ESP + 0x88]    ; ECX = de150 this
0x434732: CALL 0x004de150                   ; RET 0x8
0x434737: INC EDI / 0x434738: CMP EDI, 0xa / 0x43473b: JC 0x004346d1
```

ESP accounting (observation from the listing + the two `RET n`
facts: `0x4432b8: RET 0x4`
(`ev_4189681ad46fd8584bc57ce3d574f8d08dce77fc0ce0eaec3834d87f0a49f131`),
de150 `RET 0x8` per `004de150_index.md` §1): after `0x43471d`,
`ESP=E0` (arg cleaned by callee); `0x434722` push → `E0-4`;
`0x43472a` push → `E0-8`; at `0x43472b`,
`[ESP+0x88] = [E0+0x80]` = the spill slot = `[ESI+0x60]` strip.
After de150's `RET 8`, `ESP=E0` again — balanced every iteration,
loop-back `JC 0x4346d1` reuses the same slot, and no instruction
in the loop body writes `[E0+0x80]` (body ESP-slot writes are
`[ESP+0x30/0x34]`, `[ESP+0x74]`, `[ESP]`-post-push only). The
`[ESP+0x88]` float reads elsewhere (`0x434588/0x43459c/0x4345ab`
`FMUL`/`FSUB`, `0x4345c4` `FST`) belong to pre-loop math at
different `ESP` and never touch this slot. So the landing-loop
`ECX` is the ctor-backed `+0x60` strip, not a float temp and not
an alias object.

## 5. Inference (labeled): alias ruled out — flag reads zero on all observed paths

Every `ECX` reaching `FUN_004de150` — four emitters × all their
sites (§2) fed by both builders (§3), plus the landing probe loop
(§4) — resolves to one of the four ctor-built strips
(`[parent+0x50/+0x58]` of `0x434020`, `[parent+0x60/+0x68]` of
`0x434390`), each zero-initialized at `[+0x18]` by `0x4dd611`.
Combined with the exhausted in-class writer search (no direct
store per `de150_flag.md` §3, no virtual setter per
`strip_vtable_sweep.md` §4, no block copy in the swept set per
`strip_blockcopy_scan.md`, no outside ctor/vtable user per
`strip_ctor_xrefs.md` §§1-2), the nonzero `def20`-always arm at
`0x4de1c8` has no reachable writer and no reachable alias carrier
on any observed path: the flag reads zero wherever the hill code
runs, and the nonzero arm is dead/defensive there. This closes
U1's last enumerated hiding place. Residual risks are below, not
a further alias inside this scope: a fully computed store
destination would still escape literal sweeps (U-computed), and
two links rest on ABI convention rather than static dominance
(Unknowns).

## Unknowns

- U-computed (carried from `strip_ctor_xrefs.md`): a store with a
  fully computed destination (strip base in one register, offset
  in another, no literal `0x18`, no vtable/ctor reference) escapes
  every sweep so far by construction. Call-shape inventory argues
  against it; data-flow not traced.
- U-ABI (new, minor): `0x4ddcb0`'s `ESI` preservation across the
  `operator_new`/`0x443060`/`0x477450` calls before `0x4dde3b`,
  and `EBX`/`ESI` preservation across the virtual calls at
  `0x4ddeca` (`ddcb0`) / `0x4de0fc` (`ddf10`), rest on callee-saved
  convention, not on static dominance (`dda60`/`ddae0`/`ddf10`-head
  chains have no such link: single assignment dominates).
- U-slot-rewrite (new): this trace proves what each builder loads
  into `ECX` at each emitter call, not that no other code
  overwrites the parent strip slots (`+0x50/+0x58/+0x60/+0x68`)
  between construction and emit. Writers to those parent slots
  outside the two builders unexamined — the remaining alias-shaped
  vector, and the ONE next target below.
- U-vtable-extent (carried): dwords at `0x5d09d8+12` and beyond
  not decoded; asserted only as non-code-pointer-shaped.

## Disposition + next target (ONE)

U1 (writer of nonzero `[strip+0x18]`) is closed as *no reachable
writer and no reachable alias on any observed path*: flag stays
zero on the hill path (§5 reasoning). Reopen only on new
observation (a store or a foreign `ECX` source).

ONE next target: sweep writers to the four parent strip slots
(`[parent+0x50]`, `[parent+0x58]`, `[parent+0x60]`,
`[parent+0x68]`) outside builders `0x434020`/`0x434390` — any
post-construction overwrite with a non-ctor object is the last
unexamined way a nonzero `+0x18` (or a foreign vtable) reaches
de150. Suggested: `xrefs` on the parent-object field addresses
is not directly available (slots are offsets, not addresses);
instead `analyze_function` the callers of `0x434020`/`0x434390`
(one level up: who owns `in_ECX` there and whether the parent
object itself is aliased/copied) and filter their instruction
listings for stores with those literal offsets.
