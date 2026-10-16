# Phase 2 tail map: V-orientation, vector growth, de150 nonzero-flag arm

Target: `dsj3v171.exe` at repo root,
SHA-256 `aea101be65bf6bbcb38f5f78cd4ed06ba7dbf46370e5fa66b6e30c5568b6796d`.
REA session default document is the inner game EXE (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`);
all addresses below are inner-EXE virtual addresses. Static analysis only;
binary never executed. No engine code touched.

## 1. V-orientation: decided in arc ctor `FUN_00443370`, field `+24` (`n`)

### Observation

- Arc element layout `0x1c` bytes: `+12=cx`, `+16=cy`, `+20=r(f32)`,
  `+24=n(i32)`; slot 0 curve `y = cy - n*sqrt(max(d,0))`,
  `d = r*r - (x-cx)^2` (`evidence/00443450_arc_xform.md`,
  `evidence/00443370_arc_ctor.md`).
- `n` writer sites (verbatim, `ev_d8ef5f607edc06a650ded6c75e839de70d3af6b0d513edb8231e472208805a00`,
  body `0x443370-0x44344b`):
  - `0x4433c7: MOV dword ptr [ESI + 0x18], 0x0` — default 0;
  - `0x4433f1: MOV dword ptr [ESI + 0x18], 0xffffffff` — `-1`, reached
    iff `p4 >= p2` AND `p6 >= p2` ordered (`FCOMP`/`FNSTSW`/`TEST AH,1`/
    `JNZ` pairs at `0x4433d3-0x4433ef`, C0-only: less OR unordered skips);
  - `0x443416: MOV dword ptr [ESI + 0x18], 0x1` — `+1`, overwrites `-1`
    on ties (`TEST AH,0x41`/`JZ` pairs at `0x4433f8-0x443414`, skip iff
    `p4 > p2` ordered);
  - `0x44341d-0x443422`: `n == 0` → `__CxxThrowException` (no element).
- Consumers of the sign (observation, no flag/byte of their own):
  - slot+4 `FUN_004434d0` (`evidence/004434d0_arc_slot1.md`): slope
    `n*(x-cx)/sqrt(s)` — sign follows `n` (and `(x-cx)`); no trig, `cy`
    never read;
  - slot+8 `FUN_00443550` (`evidence/00443550_arc_slot2.md` §5): pure
    rate `n*r`, `x` unread.
- So on the hill path the curve-side orientation (which side of the
  chord the arc bulges, slope sign, step magnitude sign) is decided
  SOLELY by `n` at these three stores; slots only propagate it.
- Ruled out as orientation deciders (observation):
  - `yrot_sign.md` (Y-rotation `FUN_0046f910` vs quaternion `0046fa90`
    genuine Y mismatch, `ev_f40a98e88ecdf344d8daaeaed0d4f6be05a0e3befbc77ca4cb5a55fe68a52ebe`,
    `ev_0adbfd8fcb8c92a7b7a380d6215a45e5dd4b0a8866a2576323a2e6cf8e3b4eefd1`):
    tree-loop/scenery rotation handedness only; hill strips never pass
    through either function; kept as-observed, no normalization.
  - `de150` tree walk (`evidence/004de150_index.md` §4): keyed by x
    only (`*pfVar5` vs `node[3]`); y rides along uncompared.

### Inference (labeled)

- `p2/p4/p6` map to (cursor-y, endpoint-y, center-y)-family per
  `00443370_arc_ctor.md` §4 + `004ddf10` ctor-arg order
  (`ev_dfeb6c903431528eba3e6c2e4f1ec1b26b266ed6b33d882e39385878a3df3449`);
  i.e. `n` = above/below test of endpoints vs arc center. One step.
- Texture-V orientation is a SEPARATE open: engine maps `v=0` to the
  texture top row (`engine/src/render.rs:91-92,139-140`, `model.rs:70-71`
  parses `v1` verbatim); original sampler-side flip (`1-v`/FCHS on the
  UV channel) unmapped — no original function/byte claimed here.

### Unknowns

- U-V1 (open): original texture-V decision (UV flip between model `v1`
  parse and D3D submit). ONE next target: trace the UV channel from
  `FUN_00455ba0` render-asset path through `FUN_00409060` submit for a
  `1-v` (`FSUB`) / sign-flip (`FCHS`/`XOR 0x80000000`) on the v lane.
- U-V2 (carried): `yrot_sign.md` U2 (which Y producer the downstream
  consumer expects); unobservable on the tree path (symmetric randoms).

## 2. Vector growth: heightfield POD-float vector `[hill+0x74/0x78/0x7c]`

### Observation

- Which vector (this session, `ev_3b34a40d08196b03ec19ea73c84690f865a8f5359ba36842a09e1acbafe983b0`,
  `read_function_instructions 0x004348a0`, 522 insns): push site
  addresses `0x434db4-0x434f63` touch ONLY `[EBP+0x74]` (begin),
  `[EBP+0x78]` (end), `[EBP+0x7c]` (cap); `EBP` = hill `this`
  (`0x4348be MOV EBP,ECX`, `ev_421834f1...` in `thr_off_writers.md`).
  This is the `+0x74` heightfield vector from `heightfield_consumer.md`
  (ctor zeroes at `0x433ae8/0x433aee/0x433af1`, `ev_767aff4b...`), NOT
  the `+0x21c`-family mesh-output vectors (`00437df0_mesh_insert.md`).
- Element size 4 bytes (observation): `SAR …,0x2` count scaling
  (`0x434dc3/0x434de0/0x434df7/0x434ba…`), `+0x4` stepping, per-element
  copy `FUN_00475330` = null-checked dword move (`ev_dfe371d10b665812f9a5ec13fbedd96f3c6b1992f6df0f17ee0c32711ad0092a`,
  7 insns: `MOV EAX,[ESP+4]; TEST; JZ; MOV ECX,[ESP+8]; MOV EDX,[ECX];
  MOV [EAX],EDX`). POD floats — contrast `004306e0` shared-ownership
  copy in the `+0x21c` family.
- Fast path (capacity free, observation): `0x434db4 ESI=end;
  0x434db7 EDX=cap; 0x434dba SUB; 0x434dc3 SAR 2; 0x434dc6 CMP EDX,1;
  0x434dcf JNC 0x434eb6` (free count `>= 1` unsigned) → append `v`
  (`[ESP+0x38]`) at end via `00475330`, `0x434f1c ADD [EBP+0x78],0x4`.
- Slow path (realloc, observation): `0x434e0a CALL 0x0059c8e9`
  (operator new, byte count `newcap<<2` at `0x434e06 SHL EAX,0x2`);
  prefix/new/suffix copied with `00475330` loops
  (`0x434e1f/0x434e39/0x434e53`); old buffer freed with
  `0x434e71 CALL 0x0059c120` (operator delete: `PUSH [ESP+4]; CALL
  0x0059f5ce`, `ev_009b46f0ed021ce78a3c4e1e76187523a7b604afdf2bb0dff7ddeb9ea33953dc`,
  4 insns); begin/end/cap rewritten at `0x434e84-0x434eae`.
- Growth rule (observation of the arithmetic with `EBX == 0`, zeroed at
  `0x434b5b`, no static write between loop head and push):
  `newcap = old_count + max(old_count, 1)` — `0x434dd8` begin==0 →
  `EAX=1, ESI=0` (empty → 1); else `EAX=max(old,1)` (`0x434de0-0x434de8`),
  `ESI=old` (`0x434df5-0x434df7`), `0x434dfa ADD EAX,ESI`; overflow
  guard `0x434dfc CMP EAX,EBX(=0); JGE` (taken unless wrapped
  negative). Textbook doubling (0→1, 1→2, n→2n).

### Inference (labeled)

- `0x0059c8e9` = `operator_new` (inference from `terrain_loop.md` naming
  + identical growth idiom proven for the `+0x21c` family in
  `00437df0_mesh_insert.md` §3 pseudocode: `operator_new(
  (old+max(count,old))<<3)`).
- Middle-insert shift arm (`0x434ec8-0x434f61` backward-shift loops via
  `00475330`, entered at `0x434f22`) is unreachable on this route:
  `ESI` (=end, `0x434db4`) and `EDI` (`=ESI`, `0x434dc9`) have no clobber
  between, so `0x434ebd-0x434ec0` computes 0 and `JNC` falls through —
  append-only in practice. Inference (jump-target sweep for other
  entries to `0x434f22` not run).

### Unknowns

- U-G1 (minor): `EBX == 0` dominance rests on the static no-write
  observation above, not a full def-use proof across the 522-insn body.
- U-G2 (carried): heightfield vector stays write-only scratch
  (`heightfield_consumer.md` U1-U5: `+0x21c`-family fillers, other-wrapper
  `+0x74` coverage, indirect reads).

## 3. de150 nonzero-flag arm: dead on the hill path (evidence only, no new REA)

### Observation (all cited, nothing re-pulled)

- Dispatch (`evidence/004de150_index.md` §5, `ev_4a972653aa3af3a10b000c0efd012078566df638345258f3bed487588c02e558`):
  `0x4de1c8 MOV DL,[EBP+0x8]` (`EBP=ECX+0x10`, i.e. `[this+0x18]`);
  nonzero → unconditional `FUN_004def20` insert (`0x4de1cf-0x4de1d9`);
  zero → unique/dedup path (`df1d0` hint + conditional insert,
  `0x4de1e8-0x4de235`).
- Writer search (`evidence/de150_flag.md`): ctor `FUN_004dd5c0` zeroes
  `[strip+0x18]` (`0x4dd611`, `ev_7183008684e7945dfb0e3b8d36c82a6b17c0eeb86865944f3db3af9bb2ae3ca0`,
  `ev_ac0b6b48507976a8d00bf3cd4fc73110f741e9f556e2e549ffbc9062462a0bb1`);
  negative sweep over emitters/builders/~70 siblings found no other
  object store (§3); virtual setter ruled out — strip vtable `0x5d09d8`
  holds exactly one entry (deleting dtor, no `+0x18` traffic;
  `evidence/strip_vtable_sweep.md` §4).
- Alias ruled out (`evidence/de150_ecx_alias.md` §§2-4): all four
  emitter-internal sites pass `in_ECX` through; every builder→emitter
  call loads a ctor-backed strip (`+0x50/+0x58` of `0x434020`,
  `+0x60/+0x68` of `0x434390`); landing probe loop passes spilled
  `[ESI+0x60]` (ESP accounting in §4).

### Inference (labeled, from `de150_ecx_alias.md` §5)

- The nonzero `def20`-always arm has no reachable writer and no
  reachable alias carrier on any observed path: the flag reads zero
  wherever hill code runs; the arm is dead/defensive there.

### Unknowns (carried, not re-opened)

- U-computed: fully computed store destination (no literal `0x18`)
  escapes literal sweeps by construction.
- U-ABI: `0x4ddcb0` `ESI`-via-spill chain + callee-saved links rest on
  convention, not static dominance.
- U-slot-rewrite: parent strip-slot overwrites outside the two builders
  unexamined (ONE next target in `de150_ecx_alias.md` §Disposition).
- What calls it with nonzero: NONE observed — no hill-path caller
  passes a nonzero-flag object; reopen only on a new observed store or
  foreign `ECX` source.

## Disposition

- V-orientation (curve side): CLOSED to ctor `00443370` `+24` stores.
  Texture-V: OPEN (U-V1, one target).
- Vector growth: CLOSED as mapped above (POD-float `+0x74` vector,
  double-on-realloc, append-only in practice). No transcription follows
  (impure allocator path; `mesh.rs` `Vec::push` stands as documented
  equivalent).
- de150 nonzero arm: CLOSED as dead-on-hill-path (evidence synthesis,
  no new REA). Reopen only on new observation.
