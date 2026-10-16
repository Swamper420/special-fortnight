# Key-to-index resolver `FUN_0055e910` (inner `DSJ3.exe`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE, Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Dossiers below are Ghidra 12.1.2
representations, not original source.

Primary dossiers (this file):
`analyze_function(FUN_0055e910)`
(`ev_9acdb5a6f6b39f0643faeeb7ff428e2163cfc4946fb6083938cf2125d2816543`:
proc/pseudocode/61-insn assembly/callers/callees/refs);
`read_function_instructions(FUN_0055e910)`
(`ev_7b9b6b3db6d9c4e53b61fcac35abedf34a3541f77781227aac3ab64cb8b83f79`:
61 insns, full body text);
`procedure_references(FUN_0055e910)` outgoing
(`ev_113a5fc395a1e5fc4cf1101dae08ad9c3f13216d4b3120ef367e6d40ad09ed05`);
`list_strings` at `0x55e910`
(`ev_09ce20209317af50cbdb46c7ac2791d0eb40130ae2fa5b571052c54bd0aa71dc`:
none);
`procedure_callers(FUN_0055e910)`
(`ev_92e7a44d4cfdd7f6423f7aaea0dfe3da66ae9de72cf6cefebb454f7056a88d74`:
sole caller `0x55cc80`);
`read_bytes 0x5cd2ec` (16 B)
(`ev_9f5013371c2027d24d79db34b128131ea300987348eae6e58962cf16048a2e22`).
Callee dossiers: `analyze_function(FUN_0055f3e0)`
(`ev_31da777613ac812075dba792875e96ab75392a2881be879c3aab173771522661`);
`read_function_instructions(FUN_0055f3e0)`
(`ev_4d707b27fd371bbab6ba1faa98c8a4b2ae68b192b930aa03274bc82f2943398e`);
`analyze_function(FUN_00407650)`
(`ev_64375970895ddf55dbc79bc93d1fde59a03108299ddf03c554c19b59ad3e29bf`:
`param_1 + 0xc`, 8 B body, no callees);
`analyze_function(FUN_00451c20)`
(`ev_ff75aa1cbf68e5526b7b30004e492242f8c8e8d97cf2b82f684c0b27dfd45c5a`:
`return *in_ECX`, 3 B body, no callees);
`analyze_function(FUN_004037e0)`
(`ev_dd9a81730b3e20138a1d779cf296c6a1ca2605e5f1376827ce1ae11bfd27ee08`:
525 B string op);
`analyze_function(FUN_00405550)`
(`ev_dc5953d3c7bd7157c9a67d38eef712ea6ff3d5eab0c72cb8f0299df50c4cacb9`:
281 B string copy);
`analyze_function(FUN_00419820)`
(`ev_aa9b2eb69e1b57eb8728a42b84d838b2e5459b9787fae8b5405414ed01c28b51`:
wide-string strict-less);
`read_function_instructions(FUN_00419820)`
(`ev_237890bd1efb886dd547afb5e74f5a689745c7f2a5dc20e8aecae5bcd568665a`).
Supersedes `ev_718e6a5533c3e080243ad0fdcb664f98e2b6c2e8694b7b402a40c2c6f896a772`
(prior `analyze_function FUN_0055e910` cited in
`evidence/0055cc80_lookup.md` §1; conclusions below replace its
"critical-section" guess — all six callees are local code with
available bodies, none is a sync import).
No Rust written: this procedure is a cache/validate wrapper, not a
pure function (string temps, SEH, callee side effects); the only
proven-pure fragments are the two trivial callees (`*ECX`, `+0xC`),
not worth transcribing alone.

## 1. Claim

`FUN_0055e910` is the private key→record resolver behind the
central lookup `FUN_0055cc80` (sole caller, `ev_92e7...`). Calling
convention (observed): `ECX` = node+`0x14` context (caller does
`LEA ECX,[EDI+0x14]` per `0055cc80_lookup.md` §1/§3), two stack
params, `RET 0x8` (`0x55e9c8`). Param order (observation, asm +
pseudocode agree): param_1 = out-pointer (`[ESP+0x24]` slot is
dereferenced for the `*out` write at `0x55e9b1-0x55e9b7`),
param_2 = key (`[ESP+0x28]` slot is copied to `EDI` at `0x55e92b`
and `EDI` feeds both string-temp builds). So:

```
void FUN_0055e910(out_record**, key_temp)   // ECX = node+0x14
```

It does NOT compute an index. It resolves a *record pointer*:
`*out` is either the cached `[ECX+4]` (= `[node+0x18]`, the
version/cached-index dword of `lookup.md` §1) or the fresh result
of the tree search `FUN_0055f3e0`. The index arithmetic
(`rec.0x1c << 5`, entry stride `0x20`) happens in the caller
(`lookup.md` §2) — `local_20` IS this `*out` (observation: caller
compares `local_20` against `[node+0x18]` and reads
`[local_20+0x1c]`, exactly the two values this function selects
between). There is no explicit miss or duplicate signal: all paths
write `*out` (observation, single convergence at `0x55e9af`);
hit/miss emerges downstream via the caller's version-compare and
null-slot check (`lookup.md` §3).

## 2. Pseudocode (decompiler, `ev_9acd...`)

```c
void FUN_0055e910(undefined4 *param_1, undefined1 *param_2)
// in_ECX = node+0x14; param_1 = out, param_2 = key temp
{
  ...
  puVar1 = param_2;
  ...
  param_2 = (undefined1 *)FUN_0055f3e0();   // ECX passthrough, key pushed (obs. §3)
  if (param_2 != *(undefined1 **)(in_ECX + 4)) {
    ...
    local_24 = (undefined1 *)FUN_00451c20(); // *ECX (identity load, obs. §3)
    ...
    puStack_3c = (undefined1 *)FUN_00407650(); // +0xC (obs. §3)
    ...
    FUN_004037e0();    // build temp1 from candidate string
    ...
    FUN_00405550(puVar1);  // build temp2 from key
    ...
    cVar2 = FUN_00419820(); // wide-string strict-less (obs. §4)
    if (cVar1 == '\0') { ... goto LAB_0055e9af; }  // AL==0 -> use fresh
  }
  local_14 = *(undefined1 **)(in_ECX + 4);  // fast path: cached
  ppuVar3 = &local_14;
LAB_0055e9af:
  *param_1 = *ppuVar3;  // *out = fresh OR cached
  ...
}
```

Assembly skeleton (`ev_7b9b...`, 61 insns, one range
`0x55e910-0x55e9ca`, 187 B, non-contiguous false, SEH prologue
`PUSH -0x1; PUSH 0x5cca28; ... FS:[0]`):

```
0x55e92b: MOV EDI,[ESP+0x28]   ; param_2 (key)
0x55e92f: MOV ESI,ECX          ; save ctx (node+0x14)
0x55e931: PUSH EDI
0x55e932: CALL 0055f3e0        ; EAX = tree search (ECX=ctx, key on stack)
0x55e937: MOV ECX,[ESI+0x4]    ; cached record ptr
0x55e93a: MOV [ESP+0x28],EAX
0x55e93e: CMP EAX,ECX
0x55e940: JZ 0x55e9a4          ; equal -> fast path (cached)
0x55e942: LEA ECX,[ESP+0x28]
0x55e946: CALL 00451c20        ; EAX = *[ESP+0x28] (identity, 3-B body)
0x55e94b: PUSH EAX
0x55e94c: CALL 00407650        ; EAX = node-ptr + 0xC (8-B body)
0x55e951: MOV DL,[EAX]         ; first byte of candidate string object
... build temp1 (004037e0 with [0x5cd2ec],0,EAX), temp2 (00405550 with EDI=key)
0x55e98a: LEA ECX,[ESI+0x1]    ; ctx+1 as compare context
0x55e995: CALL 00419820        ; AL = strict-less(a, b) (RET 0x20, 8 params)
0x55e99a: CMP AL,BL(0)
0x55e99c: JNZ 0x55e9a4         ; nonzero -> fast path (cached)
0x55e99e: LEA EAX,[ESP+0x28]   ; AL==0 -> fresh result slot
0x55e9a2: JMP 0x55e9af
0x55e9a4: MOV EAX,[ESI+0x4]    ; cached
0x55e9a7: MOV [ESP+0xc],EAX
0x55e9ab: LEA EAX,[ESP+0xc]
0x55e9af: MOV ECX,[EAX]
0x55e9b1: MOV EAX,[ESP+0x24]   ; param_1 (out)
0x55e9b7: MOV [EAX],ECX        ; *out = chosen record pointer
... SEH epilogue; RET 0x8
```

Decision table (observation):

| `f3e0()` vs `[ECX+4]` | `00419820` AL | `*out` |
|---|---|---|
| equal | (skipped) | cached `[ECX+4]` |
| differ | nonzero | cached `[ECX+4]` |
| differ | zero | fresh `f3e0()` result |

## 3. Fast path, slow path, and the tree search

- Fast path (observation): `f3e0()` result == `[ECX+4]` → `*out =
  [ECX+4]`, no string work. Since `[ECX+4]` is `[node+0x18]`
  (caller `ECX` = node+`0x14`), this is a cache-hit shortcut:
  tree state unchanged since last lookup.
- Slow path (observation): results differ → single validation
  compare. `FUN_00451c20` is a 3-byte `MOV EAX,[ECX]; RET`
  (`ev_ff75...`): with `ECX=&slot` it returns the slot contents
  unchanged (identity load — why a call exists is unexamined,
  see U3). `FUN_00407650` is 8 bytes, `param_1 + 0xc`
  (`ev_6437...`): yields candidate-node+`0xC`, the string field
  (inference from identical use in `f3e0` loop + `+0xC` feeding
  string-copy `00405550`; offset `0xC` itself is observed).
  Temp1 is built from the candidate string (`004037e0`, 525 B,
  with `PUSH [0x5cd2ec]; PUSH 0; PUSH EAX`), temp2 from the key
  (`00405550` with `PUSH EDI`). `AL==0` accepts the fresh node,
  `AL!=0` keeps the cached one.
- Actual key matching lives in `FUN_0055f3e0` (observation,
  `ev_31da...` + insns `ev_4d70...`): 181 B, one range
  `0x55f3e0-0x55f494`, `RET 0x4` (one stack param = key pushed
  by this caller; `ECX` = node+`0x14` passthrough). Shape is a
  binary-tree walk (observation): `EAX=[ECX+4]`,
  `ESI=[EAX+4]` root, sentinel `DAT_0061c784`
  (`CMP ESI,[0x61c784]`; loop exits to return when equal);
  per node the same helpers run (`004037e0` on key byte
  `AL=[EDI]`, `00407650(node)=node+0xC`, `00405550` copy,
  `00419820` compare with `ECX=ctx+1`); `AL==0` records
  `[ESP+0x10]=ESI` and descends `ESI=[ESI+0]`, `AL!=0`
  descends `ESI=[ESI+8]`; returns last-recorded node (or the
  initial `[ECX+4]` when the tree is empty — `JZ 0x55f480`
  skips the loop). Children at `+0x0`/`+0x8`, string at
  `+0xC` (offsets observed; field types unexamined).
- Direction/duplicate caveat (inference, see U1): which stack
  temp is the "first" arg of `00419820` is unmapped, so whether
  `AL==0`-records-then-goes-left means "last ≤ key" (successor
  tracking) or conflates equal with greater is NOT decided.
  Duplicate-key and miss-key behavior inside `f3e0` is
  therefore unknown beyond "returns some node pointer,
  never null-flags" (observation: no null test on the
  return in either body).

## 4. Compare helper `FUN_00419820` (observed)

220 B, `RET 0x20` (8 stack params). Entry `ECX` is overwritten
first (`MOV ECX,0x5cd2e8` default string unless a stack param
overrides — `0x41983d-0x419848`), so the `LEA ECX,[ESI+0x1]`
context pointer has no observed effect in the body (inference
from absence of a pre-overwrite `ECX` read). Core loop
(`0x419862-0x419871`) compares `word ptr [EAX]` vs
`word ptr [ECX]`, `DEC EDX` over `min(len1,len2)`; mismatch
computes `±1` via `SBB/AND 0xFE/INC` (`-1` iff first word <
second); length tiebreak (`0x419877-0x419899`); result
`AL = (first < second)` via `SETL` (`0x41989e`). So: strict
less-than on wide chars with length tiebreak (observation);
Borland string refcount-dec/free tail via `0059c120` or in-place
`DEC` (`0x4198a1-0x4198e2`). Which temp is first/second here is
the U1 gap — the predicate itself is settled.

## 5. Callers/callees/strings/data

- Callers (observation, `ev_92e7...`): exactly one,
  `FUN_0055cc80`. Private helper — no other users.
- Callees (observation, `ev_9acd...`): `0055f3e0` (tree
  search), `00451c20` (deref), `00407650` (`+0xC`),
  `004037e0` (string op), `00405550` (string copy),
  `00419820` (compare). All bodies available; none is an
  import. Prior "critical-section" guess (`lookup.md` §4,
  from names/count only) is rejected: no sync/import calls
  in the body (observation of callee list + outgoing refs
  `ev_113a...`: calls plus SEH `0x5cca28`, `FS` traffic,
  stack slots, one DATA ref `0x5cd2ec`).
- Strings (observation, `ev_09ce...`): no defined strings in
  range. DATA refs: SEH `0x5cca28`; `0x5cd2ec` pushed to
  `004037e0` (file bytes `ffffffff 203c4000 d09e4100
  d09f4100`, `ev_9f50...`: leading `-1` like the
  refcount sentinel seen at `005cd2e8` in `lookup.md` §3 —
  similarity is observation, "refcount" reading is
  inference); `0x5cd2e8` default-string use sits inside
  `00419820`, not this body.

## Unknowns

- U1 (open, load-bearing): `00419820` argument order in both
  this body and the `f3e0` loop — which temp (candidate-node
  string vs key) is "first". Blocks: tree direction (is
  `+0` the left/lesser child?), what `AL==0` vs `AL!=0`
  means for equal keys (duplicate handling), and what the
  slow-path accept/reject really validates. Needs stack-slot
  mapping of the `RET 0x20` args (or `004037e0`/`00405550`
  signatures to identify the temps).
- U2 (open): node/record layout. Observed offsets only:
  ctx (`node+0x14`) `+0x0` (unexamined), `+0x4` (cached record
  ptr = `[node+0x18]`), tree nodes `+0x0`/`+0x8` (children),
  `+0x4` (root link from parent), `+0xC` (string),
  resolver-record `+0x1c` (index field, used by caller).
  Types, sizes, and the `+0x1c`-vs-tree-node relation
  unexamined. Closes `lookup.md` U1 in part (record-pointer
  semantics settled) but not the layout half.
- U3 (open): why the slow path routes through `00451c20`
  (a 3-byte identity deref) instead of using the `f3e0`
  result directly; what `ECX=ctx+1` (`[ESI+0x1]`,
  unaligned) means to `00419820`/`004037e0` (no observed
  effect in the compare body — possible locale/mode
  convention unexamined); exact `004037e0` op (assign vs
  insert/substring of the key byte + `[0x5cd2ec]`).
- U4 (open): miss/duplicate end-to-end. This function never
  signals miss (always writes `*out`); whether a missing key
  yields the sentinel, a neighbor node, or the stale cache —
  and what duplicate keys return (first/last/none) — is
  decided inside `f3e0` + U1 and unexamined.
- U5 (carried from `lookup.md` U2/U4, narrowed): version
  semantics of `[node+0x18]` vs `f3e0()` result (generation
  counter? root pointer? — equality is the only observed
  use); `0x61b820`/`0x5cd2e8` ownership untouched.

## Next target (one)

`FUN_0055f3e0` — the tree search proper. It owns key matching,
node layout (`+0`/`+8` children, `+0xC` string, `+0x1c` index
field?), sentinel `0061c784` behavior, and miss/duplicate
semantics; without it U1/U2/U4 stay open and no lookup Rust
(including the `<<5` index arithmetic) can be transcribed.
