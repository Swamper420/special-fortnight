# Formats (Phase 1 target)

## Cipher (BROKEN 2026-10-15, reimplemented in `engine/src/decrypt.rs`)

Every payload file = 0x100-byte header + ciphertext. Let `H` be the
header as LE int, `K` the per-type modulus (fixed 512-hex blobs in
the binary, parsed 3 nibbles per 12-bit limb LE from the end —
`FUN_0040feb0`):

- `S = H^0x10001 mod K` (square-and-multiply `FUN_004122d0`).
- `R = S[0..127] ^ S[128..255]` (bit permute + bigint XOR
  `FUN_00410740`); round seeds = `R` as 4 LE u32.
- 4 rounds: LCG keystream XOR over the whole body
  (`FUN_004df900`: `s1=(s*0x8088405+1) mod 0xFFFFFFFF`,
  `s2=(s1*0x8088405+1) mod 0xFFFFFFFF`, byte `(s1>>16)&0xFF`).
- Plaintext is BOM-checked XML/text (`FUN_0055fcb0`); dual MD5
  verify (`FUN_0046fd90`+`FUN_004107f0`).

Keys: resources (`Resource.00*`) = `K_RES_HEX` (`@0x605e5c`);
languages (`*.lan`) = `K_LAN_HEX` (`@0x605a00`). Verified: full
`Resource.000` → UTF-16 manifest, `English.lan` → UTF-8 strings,
`Resource.001` slices → UTF-8 models.

## Manifest (`Resource.000`, 18984 B UTF-16 after decrypt)

`<resourcelist version="1.7" file="Data Files\Resources\Resource.001">`
+ 145 `<file id size offset/>` slicing `Resource.001`
(`engine/src/manifest.rs`).

## Models (`Resource.001` entries, UTF-8 with BOM after decrypt)

`<3dmodel>` of `<batch id texture1 material fvf order>` with nested
`<vertex id x y z u1 v1/>` and `<face v1 v2 v3/>` (1-based).
`engine/src/model.rs`; e.g. judgetower-summer: 18 batches.
Textures referenced (`Textures\*.png`) live in later entries
(still embedded in the same blob; PNG decode post-decrypt).

## Languages (`*.lan`, ~37 KB each after decrypt)

UTF-8 with BOM, `<string id content/>` (610 strings in English;
`|` = line break). `engine/src/lang.rs`.

## Hills (`*.hil`) — LICENSE-BLOCKED, no guessing

40 files, 1906–3487 B, entropy ~7.9: encrypted with the same
construction but license-derived keys. The game gates hills behind
registration (`REGHILL`: "Please register DSJ3 ... to play this
hill!"; demo gets 36 fewer hills). Hill loader is `FUN_00436620`
(keys `hill/dhill/terrain/judgetower/fence/pillar/stairs/flag/
trees`); key globals (`0x61bb68/0x61be20`) are overwritten by the
registration RSA unit (`FUN_00428580`, needs `Resource.002` +
license) after the static init values. No license = no hill keys;
static-blob keys exhaustively fail (all 17 blobs × both RSA
directions × exponents 3/17/257/65537/filename-MD5s). Do NOT
fabricate hill geometry — smells like progress, isn't.

`Resource.002` (843 B) is the license/signature package (opaque,
same reason).

## Loader strings (inner `DSJ3.exe`, UTF-16 file offsets)

`Hills` 0x20b29a/0x20b300, `Languages` 0x205992, `Resource`
0x205e1a/0x205e2e/0x20819e/0x2081b2, `Data Files`
0x20597c/0x205e04/0x208188/0x20b284, `.lan` 0x2059a8.
Full REA evidence: `analysis/*-recon.md`, `analysis/decrypt-notes.md`
(scratch, gitignored; Evidence IDs inside).
