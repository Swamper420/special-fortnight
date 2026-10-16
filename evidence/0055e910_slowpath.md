# Resolver slow-path compare site `~0x55e995` (inner `DSJ3.exe`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE, Ghidra 12.1.2. Dossiers below are
Ghidra 12.1.2 representations, not original source. Companion:
`evidence/0055e910_resolver.md` (resolver wrapper),
`evidence/00405550_temp2.md` (f3e0 arg-order proof mirrored here).

Primary dossiers (this file):
`read_function_instructions(FUN_0055e910)`
(`ev_7ada5de5d9cf591143a33303f6e37f10988ea9e4f4ae1253e096d3559846d668`:
61 insns, full body text, NEW this session);
`analyze_function(FUN_0055e910)`
(`ev_9acdb5a6f6b39f0643faeeb7ff428e2163cfc4946fb6083938cf2125d2816543`:
proc/pseudocode/assembly/callers/callees/refs; re-observed this
session, same ID as cited in `0055e910_resolver.md`);
`read_function_instructions(FUN_00419820)`
(`ev_a8858a3534ec5467f12b7f34fbfdebf749e51c0789848113335c456206b61fab`:
body text through the compare core, NEW this session).
Adopted slot mapping (prior sessions, IDs unchanged):
`read_function_instructions(FUN_0055f3e0)`
(`ev_4d707b27fd371bbab6ba1faa98c8a4b2ae68b192b930aa03274bc82f2943398e`);
`read_function_instructions(FUN_00419820)`
(`ev_237890bd1efb886dd547afb5e74f5a689745c7f2a5dc20e8aecae5bcd568665a`);
`analyze_function(FUN_00419820)`
(`ev_45ec94653f0f444170d9ee52e8c9cb324aa7c916e970559b58c748eb75a009e8`).
No Rust written: effectful wrapper (string temps, SEH, callee side
effects); evidence only.

## 1. Claim

The slow-path compare at `0x55e995` is the exact mirror of the f3e0
loop site (`0x55f460`, closed in `00405550_temp2.md` §5). Temp
sources are swapped: the first-allocated temp is built from the
fresh-candidate string via `004037e0`, the second-allocated temp
from the key via `00405550`. The 32 B `RET 0x20` payload is
`[key-temp][candidate-temp]` laid end-to-end, so the first compare
string is the key and the second is the candidate:
`AL = (key < candidate)`. Accept/reject (observed):
`AL==0` takes the fresh `f3e0()` result (`LEA EAX,[ESP+0x28]`);
`AL!=0` keeps the cached `[ESI+0x4]` (`JZ`/`JNZ 0x55e9a4` pair).
So fresh is accepted iff `key >= candidate`, cached kept iff
`key < candidate`.

## 2. Slow-path assembly (observed, `ev_7ada...`)

```
0x55e93a: MOV [ESP+0x28],EAX      ; f3e0() result -> slot
0x55e93e: CMP EAX,ECX             ; vs cached [ESI+0x4]
0x55e940: JZ 0x55e9a4             ; equal -> cached (fast path)
0x55e942: LEA ECX,[ESP+0x28]
0x55e946: CALL 00451c20           ; EAX = [slot] (identity deref)
0x55e94b: PUSH EAX
0x55e94c: CALL 00407650           ; EAX = fresh-node + 0xC (string field)
0x55e951: MOV DL,[EAX]            ; candidate seed byte
0x55e953: SUB ESP,0xc             ; tempX alloc (12 B)
0x55e956: MOV ECX,ESP             ; dest = tempX
0x55e958: XOR EBX,EBX             ; BL = 0 (later CMP AL,BL)
0x55e95a: MOV [ESP+0x1c],ESP      ; outside-block store (frame local, see §4)
0x55e95e: MOV [ECX],DL            ; seed
0x55e960: MOV [ECX+0x4],EBX       ; null ptr
0x55e963: MOV [ECX+0x8],EBX       ; null len
0x55e966: MOV [ECX+0xc],EBX       ; third word = 0
0x55e969: MOV EDX,[0x5cd2ec]
0x55e96f: PUSH EDX
0x55e970: PUSH EBX                ; 0
0x55e971: PUSH EAX                ; fresh-node+0xC
0x55e972: CALL 004037e0           ; build tempX from candidate (RET 0xC)
0x55e977: SUB ESP,0x10            ; tempY alloc (16 B)
0x55e97a: MOV [ESP+0x3c],EBX      ; = 0, later overwritten (frame local)
0x55e97e: MOV ECX,ESP             ; dest = tempY
0x55e980: MOV [ESP+0x30],ESP      ; outside-block store (frame local)
0x55e984: PUSH EDI                ; key (param_2, EDI set at 0x55e92b)
0x55e985: CALL 00405550           ; build tempY from key (RET 0x4)
0x55e98a: LEA ECX,[ESI+0x1]       ; compare ctx (no observed body effect)
0x55e98d: MOV [ESP+0x3c],-1       ; overwrite of 0x55e97a store
0x55e995: CALL 00419820           ; RET 0x20; AL = strict-less(first, second)
0x55e99a: CMP AL,BL               ; BL = 0
0x55e99c: JNZ 0x55e9a4           ; AL!=0 -> cached
0x55e99e: LEA EAX,[ESP+0x28]      ; AL==0 -> fresh slot
0x55e9a2: JMP 0x55e9af
0x55e9a4: MOV EAX,[ESI+0x4]       ; cached record ptr
0x55e9a7: MOV [ESP+0xc],EAX
0x55e9ab: LEA EAX,[ESP+0xc]
0x55e9af: MOV ECX,[EAX]           ; convergence: ECX = chosen record
0x55e9b1: MOV EAX,[ESP+0x24]      ; param_1 (out)
0x55e9b7: MOV [EAX],ECX           ; *out = fresh OR cached
```

Decompiler convergence (`ev_9acd...`): `if (cVar2 == '\0')
ppuVar3 = &param_2;` (fresh) else cached; single `*param_1 =
*ppuVar3` write. Matches the asm arms.

## 3. ESP-slot mapping (observation, mirrors `00405550_temp2.md` §5)

`ESPe` = ESP at `0x55e937` (post-`f3e0` call; `RET 0x4` already
restored the pushed key). `PUSH EAX` at `0x55e94b` is consumed in
place by plain-`RET` `00407650` (same shape as the f3e0 stale
`PUSH ESI`): the pushed fresh-node ptr stays on the stack.

| step | insns | ESP after |
|---|---|---|
| pre-slow-path | — | `ESPe` |
| stale push | `0x55e94b PUSH EAX` (consumed in place) | `ESPe-4` |
| tempX alloc | `0x55e953 SUB ESP,0xc` | `B+16 = ESPe-16` (tempX base) |
| tempX build | `PUSH,PUSH,PUSH + CALL 004037e0` (`RET 0xC`) | `B+16` |
| tempY alloc | `0x55e977 SUB ESP,0x10` | `B = ESPe-32` (tempY base) |
| tempY build | `PUSH EDI + CALL 00405550` (`RET 0x4`) | `B` |
| compare call | `0x55e995 CALL 00419820` (`RET 0x20`) | `B+32 = ESPe` |

Balance check (observation): `RET 0x20` pops exactly the 32 B
below the stale push (16 tempY + 4 stale + 12 tempX), restoring
`ESPe` — so the 32 B block `[B..B+31]` IS the 8-dword arg
payload, passed by overlap; there are no pushes between
`0x55e985` and `0x55e995`.

Temp identities (observed): tempX dest `ECX=ESP` at `0x55e956`
is filled from `EAX` = fresh-node+`0xC` via `004037e0` (3 pushes:
`[0x5cd2ec]`, 0, node-str); tempY dest `ECX=ESP` at `0x55e97e`
is filled from `EDI` = key via `00405550` (1 push). So
`[B..B+15]` = tempY = key temp, `[B+16..B+31]` = tempX =
candidate temp (its `+0xC` third word lands on the stale-push
slot at `ESPe-4`, same overlap shape as `00405550_temp2.md` §3).

Callee frame (observed, `ev_a885...` + adopted `ev_2378...` /
`ev_45ec...`): 7 pushes + retaddr = same 28 B prologue as the
f3e0 site; string-slot reads identical:
`[ESP+0x24]` first ptr (`ESI`, word-walked), `[ESP+0x28]` first
len (`EDI`, min/tiebreak), `[ESP+0x34]` second ptr (`EBP`),
`[ESP+0x38]` second len (`EBX`). First string = block start =
tempY = key; second string = block second half = tempX =
candidate. Result `AL = (first < second)` via `SETL`
(`ev_a885...` core `0x419862-0x41989e` matches the settled
predicate). Hence `AL = (key < candidate)` — the mirror of the
f3e0 `AL = (candidate < key)`.

Decision table (observation):

| `f3e0()` vs `[ECX+4]` | `00419820` AL | `*out` |
|---|---|---|
| equal | (skipped, `JZ`) | cached `[ECX+4]` |
| differ | nonzero (`key < candidate`) | cached `[ECX+4]` |
| differ | zero (`key >= candidate`) | fresh `f3e0()` result |

Meaning (inference from this mapping + the f3e0 record rule in
`00405550_temp2.md` §5): the f3e0 loop only records nodes with
`candidate >= key`, so a fresh (differing, recorded) result
already satisfies `candidate >= key`. Conjoined with the
slow-path accept condition `key >= candidate`, accept ⟺
`candidate == key` (exact-match validation); the reject arm is
`candidate > key` (strict-successor overshoot = miss → keep
cache). Equal-key duplicates take the accept side. The
`ECX=[ESI+0x1]` context has no observed body effect (entry
`MOV ECX,0x5cd2e8` overwrite, `ev_a885...` `0x41983d-0x419848`).

## 4. Callers/callees/strings/data

- Callers (observation, `ev_9acd...` + `0055e910_resolver.md`
  §5): exactly one, `FUN_0055cc80`. Private helper.
- Callees (observation, `ev_9acd...`): `0055f3e0` (tree search),
  `00451c20` (3-B identity deref), `00407650` (`+0xC`),
  `004037e0` (tempX/candidate build), `00405550` (tempY/key
  build), `00419820` (strict-less). None analyzed here; role
  labels positional.
- Strings (observation, adopted `ev_09ce...` in resolver dossier):
  none in range.
- Data refs (observation): SEH `0x5cca28`; `0x5cd2ec` pushed to
  `004037e0` (`0x55e969/0x55e96f`); `0x5cd2e8` default-string use
  inside `00419820`, not this body. Outside-block stores (not
  compare args, all above the 32 B block): `[B+0x1c]-family`
  self-ref (`0x55e95a`), `[B+0x30]` self-ref (`0x55e980`),
  `[B+0x3c]` 0→-1 (`0x55e97a`→`0x55e98d`); post-compare
  `[ESP+0xc]` cached slot (`0x55e9a7`) reuses the `0x55e95a`
  frame address after `RET 0x20` restored `ESPe`. Consumers
  unexamined (same class as `00405550_temp2.md` U1).

## Unknowns

- U1 (open, non-load-bearing for direction): consumers of the
  outside-block stores (§4); whether `[B+0x3c]` 0→-1 is an
  SEH/mode flag the compare or temps read — no reader observed
  in either body, so compare semantics unaffected either way.
- U2 (open, carried): exact `004037e0` op (assign vs
  insert/substring of key byte + `[0x5cd2ec]`), `+0xC`
  third-word meaning, `+0x0` seed-byte consumer. Neither builder
  reads dest `+0x0` after writing it and the compare never reads
  args `i=0/i=4`, so the seed's reader is still unidentified.
- U3 (open, carried from resolver U3): why the slow path routes
  through `00451c20` (identity deref) instead of using the
  `f3e0` result directly; what `ECX=ctx+1` means (no observed
  effect in the compare body).
- U4 (open, narrowed but not closed): end-to-end miss/duplicate
  behavior still needs the `f3e0` empty-tree/sentinel path
  (`JZ 0x55f480` skips loop, returns initial `[ECX+4]`) read
  together with this accept rule; the conjunction
  accept-iff-equal in §3 is inference from two observed
  mappings, not a traced execution.

## Next target (one)

`FUN_004037e0` — the 3-param string op used for tempX here (and
temp1 at f3e0): pin its exact op (roles of the key byte,
`[0x5cd2ec]`, and third word) via its body + the two call sites.
That closes the temp-construction half of U2/U3; without it all
lookup Rust stays blocked on unproven temp semantics.
