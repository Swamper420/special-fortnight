# Central hill-config lookup `FUN_0055cc80` (inner `DSJ3.exe`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE, Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Dossiers below are Ghidra 12.1.2
representations, not original source.

Primary dossiers (this file):
`analyze_function(FUN_0055cc80)`
(`ev_dd06d83890b8f5a6107e064e7b6288e11f41fb9544d6e54d06d59036438c851c`:
proc/callees/callers/pseudocode);
`read_function_instructions(FUN_0055cc80)`
(`ev_5c30584239f062e774605c8b1fa3dcefaff8cd5514dbcf076df0041ee21f3d43`:
73 insns, full body text);
`analyze_function(FUN_0055e910)`
(`ev_718e6a5533c3e080243ad0fdcb664f98e2b6c2e8694b7b402a40c2c6f896a772`:
key-to-index resolver, pseudocode + callees).
Cited prior: `ev_d2e9b8e0d1589e7954c714054d98c79e18ef7c47cf95066716fdd42447b6f75b`
(`analyze_function FUN_0055cc80` from `evidence/00436620_param_keys.md`,
claim `(node=ECX, stackarg, key) -> value wide-string or default`);
`ev_90280e813806b6eb2430d71666b46c967a4022990831bbc3541d43ab23a7e425`
(`read_bytes 0x61b820`, 64 zero bytes);
`ev_55e6b334ba07f7caf826843ab54a89dbaa3990b32143a8229bd3d2854c9bb151`
(`read_bytes 0x5cd2e8`, 64 B default record);
`ev_53a05bb312bcb6ff82ed8bf326dfae623df5961e00af1177585eb033c43007af`
(`list_strings` at `0x55cc80`: no defined strings);
`ev_140983e30e3896284cf5e21c00533c9abbc8856350aa587d3b64ce6b166809d6`
(`procedure_references FUN_0055cc80` outgoing).
No Rust written: key matching lives in `FUN_0055e910` (unmapped);
only the index-arithmetic fragment below is pure, and it is blocked on
`local_20` semantics (AGENTS.md evidence-first).

## 1. Claim

`FUN_0055cc80` is the central config lookup. Calling convention
(observed): `ECX` = node pointer, two stack params, `RET 0x8` (both
`RET` sites `0x55cd4e`/`0x55cd66`). At hill parse sites
(`evidence/00435e70_strings.md` §3, `evidence/00436620_param_keys.md`
§1) the pattern is:

```
PUSH 0x61b820; PUSH <key>; MOV ECX,ESI; CALL 0055cc80
```

so stack param_1 (at `[ESP+4]`) = key wide-string, stack param_2 (at
`[ESP+8]`) = `0x61b820` scratch pointer. Returns `wchar_t*` (borrowed):
table value on hit, caller scratch or shared empty string on the two
miss paths (§3). Body is one contiguous range `0x55cc80-0x55cd68`
(233 bytes, contains entry, non-contiguous false).

Node structure (observed offsets only): `[ECX+0x18]` = cached
version/index dword; `[ECX+0x28]` = table-base dword. Inner resolver
is called with `ECX = node+0x14` (`0x55ccf6: LEA ECX,[EDI+0x14]`).

## 2. Pseudocode (decompiler, `ev_dd06...`)

```c
undefined2 * FUN_0055cc80(undefined4 param_1, undefined2 *param_2)
{
  // param_1 = key (stack), param_2 = 0x61b820 scratch (stack, also
  // reused as return-value slot by decompiler); in_ECX = node.
  ...
  FUN_00402e80(0);                    // init local string temp
  iVar2 = FUN_0059ce28(param_1);      // wcslen(key)
  cVar1 = FUN_00402d50(iVar2, 1);     // alloc-check
  if (cVar1 != '\0') {
    FUN_00402920(local_18, param_1, iVar2);   // copy key to temp
    *(undefined2 *)(local_18 + iVar2 * 2) = 0; // NUL
    local_14 = iVar2;
  }
  FUN_0055e910(&local_20, local_1c);  // ECX=node+0x14; local_20=index
  FUN_00402e80(1);                    // free key temp BEFORE returns
  if ((local_20 != *(int *)(in_ECX + 0x18)) &&
      (param_2 = *(undefined2 **)(*(int *)(local_20 + 0x1c) * 0x20
                                  + *(int *)(in_ECX + 0x28) + 0x14),
       param_2 == (undefined2 *)0x0)) {
    return &DAT_005cd2e8;             // null slot -> shared empty
  }
  return param_2;  // covers table hit AND version-equal path (§3)
}
```

Assembly tail (`ev_5c30...`) makes the three exits explicit:

```
0x55cd19: MOV EAX,[ESP+0xc]    ; local_20 (resolver output)
0x55cd1d: MOV ECX,[EDI+0x18]   ; node cached version
0x55cd20: CMP EAX,ECX
0x55cd22: JZ 0x55cd51           ; equal -> return [ESP+0x34] (scratch)
0x55cd24: MOV EDX,[EAX+0x1c]   ; index field of resolver record
0x55cd2a: SHL EDX,5             ; *0x20 = entry size
0x55cd2d: LEA EAX,[EDX+EAX+0x10]; + table base [EDI+0x28] (EAX input)
0x55cd31: MOV EAX,[EAX+0x4]     ; value wide-string ptr
0x55cd34: TEST EAX,EAX
0x55cd36: JNZ 0x55cd55          ; non-null -> return value
0x55cd3a: MOV EAX,0x5cd2e8      ; null -> shared default
0x55cd51: MOV EAX,[ESP+0x34]    ; version-equal -> caller scratch arg
0x55cd55: ...epilogue; RET 0x8
```

Pure fragment (proven, but NOT transcribed to Rust — blocked on
`local_20` record layout, see Unknowns):

```
entry_addr = table_base(node+0x28) + (resolver_rec(local_20).field_0x1c << 5) + 0x10
value = *(entry_addr + 4)   // null -> default
```

Entry size `0x20` from `SHL 5`; value at entry offset `+0x4`.

## 3. Node structure, key match, default/miss behavior

- Node (observation): `ECX+0x14` feeds the resolver as context;
  `ECX+0x18` cached version/index compared against resolver output;
  `ECX+0x28` table base. Nothing else of the node is touched here.
- Key match (observation + delegation): the key stack arg is
  `wcslen`'d (`FUN_0059ce28`), copied into a local temp
  (`FUN_00402d50` gate, `FUN_00402920` copy + explicit NUL at
  `[tmp+len*2]`), and handed to `FUN_0055e910` with `ECX=node+0x14`.
  No byte-compare happens in this body — matching is entirely inside
  `0055e910` (inference from absence + call shape). Temp is freed via
  `FUN_00402e80(1)` before any return, so all returns are borrowed
  (inference): table memory, caller scratch, or shared default — never
  the temp.
- Hit (observation): versions differ and slot non-null → return
  `[base + (rec.0x1c<<5) + 0x10] + 4` contents, a `wchar_t*` the
  callers feed directly to `004cae40` (float) or, for `c`-keys, to
  `004caee0` (int) per `param_keys.md` §1/§4.
- Miss path A — version-equal (observation): `local_20 ==
  [node+0x18]` → return the caller's second stack arg (`0x61b820`).
  File bytes there are 64× `0x00` (`ev_9028...`); runtime content
  unexamined, but at parse sites this pointer is pushed as `PUSH EAX`
  into the float/int parse pile, so it must read as empty/zero there
  (inference). Closes `00435e70_strings.md` U3 in part: `0x61b820` is
  the version-equal default pointer (observation of use; "constant
  section/table selector" hypothesis in U3 is rejected for these call
  sites — it is returned, not read as a selector, on this path).
- Miss path B — null slot (observation): versions differ but value
  ptr is null → return `&DAT_005cd2e8`. First 8 bytes
  `00 00 00 00 ff ff ff ff` (`ev_55e6...`): first wide char is NUL,
  i.e. an empty wide string (observation; `-1` field looks like a
  shared-refcount sentinel — inference). This closes
  `00435e70_strings.md` U6 in part: a null return cannot escape —
  both miss paths return non-null empty-ish pointers (observation of
  both exits; whether `wcslen` on them is safe depends on the parse
  callees, still open).
- Value ownership (inference): borrowed in all paths. Downstream,
  `FUN_00435e70` copies `m`/`t` results into counted-string slots and
  aliases the `c` result raw at `[ECX+0x20]` (`strings.md` §1/U2) —
  consistent with a table-owned string. Who frees table memory is
  unexamined.

## 4. Callers/callees/strings

- Callees (`ev_dd06...`): `FUN_0059ce28` (wcslen), `FUN_00402d50`
  (alloc-check), `FUN_00402920` (word copy), `FUN_00402e80`
  (string-temp init/free), `FUN_0055e910` (resolver). Referenced
  strings in body: none (`ev_53a0...` empty; only DATA ref is the SEH
  `0x5cc8e8` + `FS:[0]` prologue per `ev_1409...`).
- Callers: 32 total, including `FUN_00436620` (hill dispatcher) plus
  `00404a20/00424b90/00427400/00428580/0042b8f0/00445720/00466e20/
  0046dd90/00495ce0/...` (first 10 of `ev_dd06...`; full list in
  dossier). So this is a shared runtime lookup, not hill-specific —
  hill use is ~all parse sites (§1 pattern) but far from the only user.
- Resolver `FUN_0055e910` (`ev_718e...`, `ECX`-context + `(out,
  key-temp)` args): on some global-state comparison calls
  `FUN_0055f3e0/00451c20/00407650/004037e0/00405550/00419820`
  (critical-section + string-table-shaped helpers — inference from
  names/count only, bodies unexamined) and writes `*out`; fast path
  copies `[ECX+4]`. Decompiler output only; instruction-level
  key-compare unmapped.

## Unknowns

- U1 (open, load-bearing): `FUN_0055e910` semantics — key→index
  algorithm, `local_20` record layout (only `+0x1c` observed here),
  `[ECX+4]` fast-path value, and when the slow path fires. Blocks any
  Rust transcription of the lookup.
- U2 (open): version field semantics — what `[node+0x18]` and
  `local_20` count (config generation? table pointer?), and why
  version-equal returns the caller scratch instead of probing the
  table. Runtime `0x61b820` content (file-zero, never observed live).
- U3 (open): `DAT_005cd2e8` full record type — empty-string singleton
  assumed from leading NUL; `-1` refcount and following
  `203c4000...` dwords uninterpreted.
- U4 (open): `FUN_00402d50(iVar2,1)` failure path (`JZ 0x55ccec`
  skips copy, passes uninitialized temp to resolver?) — whether len-0
  or alloc-fail keys still resolve; key-empty behavior unexamined.
- U5 (open): table entry layout beyond `+0x4` value pointer and
  `0x20` stride; which field (if any) holds the key for collision
  handling.
- U6 (carried, narrowed): `00435e70_strings.md` U2 (`c`-string
  ownership) — now: borrowed table/scratch/default memory at lookup
  exit; freer still unknown. U4 (why only `c` gets `004caee0`) —
  untouched. U5/U7/U8 — untouched.

## Next target (one)

`FUN_0055e910` — the key→index resolver. It decides what key match
means and what `local_20` points at; without it the index arithmetic
in §2 cannot be transcribed and the U1/U2 ownership + hit/miss
questions stay open.
