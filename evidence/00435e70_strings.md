# String-assign helper `FUN_00435e70` (3-param, `RET 0x0c`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), x86 PE, Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Dossiers below are Ghidra 12.1.2
representations, not original source.

Primary dossiers (this file): `analyze_function(FUN_00435e70)`
(`ev_87ae95f3296c457201c5ab6e44e3b33454addbe9003bb69e99a83e8466c6d96a`:
proc/callees/callers/pseudocode/blocks);
`read_function_instructions(FUN_00435e70)`
(`ev_5207d175bc170bc0bda8c9f747ae30c228e25053b3f61362fc9a69dda3597131`);
`read_function_instructions(FUN_00436620)` call-site windows
(`ev_4d2c6e0a3e93bb4f34a7825be0f3937b0580707b71ff04f121db95aaf8f0724f`).
Supersedes the §3d sketch in `evidence/scenery_family.md`
(`ev_12e5d81a81c72d3c672cfd888f647612a76f9ad1a0da20308bb74faf806f208d`,
tail `ev_a38ec5973330cc00387e3adc64b97bb043c2cd2cf50c226db0eae646f2874`),
which stands except for the startgate correction in §4 below.
No Rust written: string runtime stays opaque (AGENTS.md evidence-first;
no pure fragment — both string slots route through refcount/alloc
helpers).

## 1. Claim

`FUN_00435e70` is a thiscall helper (`ECX` = dest object, 3 stack
params, `RET 0x0c`, body `0x435e70–0x435fb8`, 329 bytes). It assigns
two counted wide strings into fixed slots of the dest object and
stores the third param raw:

- slot A: `[ECX+0x4]` = chars ptr, `[ECX+0x8]` = len, `[ECX+0xc]` = cap;
- slot B: `[ECX+0x14]` = chars ptr, `[ECX+0x18]` = len, `[ECX+0x1c]` = cap;
- `[ECX+0x20]` = param_3 dword, stored raw (no strlen, no copy).

Dest object is ≥ `0x24` bytes holding two counted strings + one dword.
Per-slot logic (observed, both slots identical in shape): `wcslen`
new value (`FUN_0059ce28`); inspect refcount byte at `[oldptr-1]`;
if old unshared/absent → release-or-reuse path; if old shared and new
len is 0 → decrement refcount and clear; else if existing cap fits
(`cap <= 0x1f` AND `cap >= len`) reuse buffer, else release
(`FUN_00402e80(1)`) + alloc (`FUN_00403280(len)`) and copy chars +
NUL terminator. Slot A copies via `FUN_00402920`; slot B copies via
an inline word loop (same op, two spellings — observation).

Param roles at every call site (observed push order, §3): param_1 =
`t`-key string (last pushed), param_2 = `m`-key string, param_3 =
`c`-key string (first pushed, via `004caee0`). So slot A gets `t`,
slot B gets `m`, `[+0x20]` gets the `c` string pointer aliased.

## 2. Pseudocode (decompiler, abridged to control flow)

Full text in `ev_87ae95f3...`. Shape:

```
wcslen(param_1); if (len > 0x7ffffffd) abort(0059c12b)   // guard
old = [ECX+4]
if (old==0 || [old-1]==0 || [old-1]==-1):   // unshared/absent
    if (len==0): release(1); goto second
    if (cap>0x1f || cap<len): release(1); goto realloc_A
    else: goto copy_A                              // reuse small fitting buf
else:                                                // shared
    if (len==0): [old-1]--; release(0); goto second
realloc_A: alloc(len)
copy_A: memcpy_word([ECX+4], param_1, len); [ECX+8]=len; [old+len*2]=0
second:  // same with param_2 into [ECX+0x14/0x18/0x1c], EDI=ECX+0x10
[ECX+0x20] = param_3   // all paths (3 stores: 0x435f44/0x435f5f/0x435fb0)
```

Assembly notes (`ev_5207d175...`): `ESI=ECX` dest held across both
halves; `EBX` = param_1, `EBP` = param_2 (`[ESP+0x18]`), param_3
re-read from `[ESP+0x1c]` at each of the 3 stores. `RET 0xc`
confirms 3 stack params; `ECX` dest is the implicit 4th (thiscall).

## 3. Call sites (all in `FUN_00436620`, sole caller)

Six `CALL 0x00435e70` sites (`ev_4d2c6e0a...` filter): `0x436cbb`,
`0x436d97`, `0x436de4`, `0x4370fb`, `0x437221`, `0x4374ae` — i.e.
6 sites across 5 sections (frame has two). Uniform prefix shape per
site (railing shown, `0x436c73–0x436cbb`):

```
PUSH 0x61b820; PUSH <c-key>; CALL 0055cc80; PUSH EAX; CALL 004caee0  // c-str
MOV ECX,ESI; PUSH EAX          // param_3 slot (first pushed)
PUSH 0x61b820; PUSH <m-key>; CALL 0055cc80; PUSH EAX                 // param_2
PUSH 0x61b820; PUSH <t-key>; CALL 0055cc80; PUSH EAX                 // param_1
<getter>; MOV ECX,EAX; CALL 00435e70   // RET 0xc pops the 3 PUSH EAX
```

| Site | Section | Keys (c/m/t) | Dest (`ECX` via getter) |
|---|---|---|---|
| `0x436cbb` | railing | `c1/m1/t1` | `004682a0`(+8) on hill+0xc4 → hill+0xcc |
| `0x436d97` | frame-1 | `c1/m1/t1` | `0046efb0`(+4) on hill+0x114 → hill+0x118 |
| `0x436de4` | frame-2 | `c2/m2/t2` | `00436530`(+0x28) on hill+0x114 → hill+0x12c |
| `0x4370fb` | stairs tail | `c1/m1/t1` | `00436580`(+0x10) on alloc'd node → node+0x10 |
| `0x437221` | pillar tail | `c/m/t` | `00436580`(+0x10) on alloc'd node → node+0x10 |
| `0x4374ae` | fence | `c/m/t` | `00436590`(identity) on hill+0x184 |

Key addresses (`c1`=`0x608d7c`, `m1`=`0x608d74`, `t1`=`0x608d6c`,
`c2`=`0x608d64`, `m2`=`0x608d5c`, `t2`=`0x608d54`, `c`=`0x608d18`,
`m`=`0x608170`, `t`=`0x608d14`) per `evidence/scenery_family.md` §4;
`0x61b820` pushed at every lookup (role unknown — see Unknowns).

## 4. Correction to `scenery_family.md`

Its §2 table says startgate calls `00436590→00435e70`. Observed
startgate block (`0x436e34–0x436e97`, same `ev_4d2c6e0a...`): the
three string pushes happen (`0x436e5e/0x436e69/0x436e79`), then
`0x436e8b: PUSH EAX; 0x436e8c: LEA ECX,[EDI+0x9c]; 0x436e92: CALL
00436590; 0x436e97: JMP 0x0043721f` — getter result discarded, **no**
`CALL 00435e70`. Startgate builds the same 3-value stack tuple then
drops it. (Flag/trees/judgetower/startbanner never reference the
helper either.) True count: 6 CALL sites, 5 sections.

## 5. Callees (string runtime, not transcribed)

- `FUN_0059ce28` = wide `wcslen` (observed: scan `short*` to NUL,
  return count; `ev_ae21a8df1ba2eeadb4fce2d2cc4af1381044dc670bb22117a93d10fb3ebf028a`).
  Both param_1 and param_2 go through it unconditionally → on every
  non-crashing path both are valid non-null `wchar*` (derived; note
  there is NO null check before the first deref — contrast the
  `TEST ECX,ECX` guards on the stored slot pointers).
- `FUN_00402920` = word copy loop (`dst,src,count`;
  `ev_e539064e5ecae538db76e627ec6036d276f7980bb428590e42599938d57f853b`).
- `FUN_00402e80` = refcount release + slot clear (`ECX` = slot base;
  arg 1 = release old: if `[ptr-1]` is `0`/`-1` free via `0059c120`,
  else decrement; then zero `[+0x4/+0x8/+0xc]`; arg 0 skips release,
  just zeroes; pseudo `ev_c39a03a7934fb1fae7a01615c04dbaf2a5fec8ddf3feb867abc0fd352a984cc6`).
  Borland-AnsiString-style layout inferred from this shape — inference.
- `FUN_00403280` = buffer alloc (`(len|0x1f)+2` capped, `*2` bytes via
  `operator_new`; pseudo
  `ev_f114cef97ec6b13afaa5846203ed5efafef00c5bde58f8f53404c86087c0156f`).
- `FUN_0059c12b` = oversize abort (`len > 0x7ffffffd`); unexamined.

Referenced strings in helper dossier: none. Callers: `FUN_00436620`
only (dossier incoming; 6 intra-dispatcher sites above).

## Unknowns

- U1 (open): dest-object type. Hill-inline slots (railing/frame/fence)
  vs alloc'd-node slots (stairs/pillar tails) share the same `0x24`-byte
  two-string+dword layout — whether one struct type or two remains unknown.
- U2 (open): `[ECX+0x20]` (param_3 = `c`-string) ownership. Stored raw,
  never copied/strlen'd/freed here — borrowed alias (inference). Who frees
  it, and whether it aliases `004caee0` parse output or table memory, unknown.
- U3 (open): `0x61b820` pushed at every `0055cc80` lookup — constant section/
  table selector (inference). Meaning unconfirmed.
- U4 (open): `0055cc80` return semantics for `m`/`t` (raw pushes, no
  `004caee0` parse, yet consumed as `wchar*`). Why `c` alone needs the
  `004caee0` parse is unknown.
- U5 (open): cap-gate purpose — existing buffers with `cap > 0x1f` are
  always discarded even when large enough (observation, both slots).
  Policy reason unknown.
- U6 (open): null-safety — no null check on param_1/param_2 before
  `wcslen` deref. Whether lookups can return null (crash path) unknown.
- U7 (open): `FUN_0059c12b` abort body and `FUN_0059c120` free path
  unexamined; startgate's build-then-drop tuple (stack effect at the
  `JMP 0x43721f` target) untraced.
- U8 (out of scope): `004682a0/0046efb0/00436530/00436580/00436590`
  getter internals beyond offsets (already in `scenery_family.md` §3c).

## Next target (one)

`FUN_0055cc80` (nested key lookup, 3 stack args + `ECX`, `0x61b820`
selector). It decides what `m`/`t`/`c` values ARE (table entry vs
string) and whether param_3 aliases its output — unlocks U2/U4 and the
ownership question blocking any Rust transcription.
