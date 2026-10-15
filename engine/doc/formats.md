# Formats (Phase 1 target)

Status 2026-10-15: all three payload families are encrypted.
Observed on a live `--extract` tree (bytes stay in `/tmp`, never here):

- 40 `.hil`, 1906–3487 B, no magic, entropy ~7.9 bits/B, 256/256
  byte values present: encrypted, not raw floats. HS number from
  filename only.
- 6 `.lan`, ~37 KB each, entropy 7.996: encrypted.
- `Resource.000` 19240 B, `Resource.001` 2627904 B, `Resource.002`
  843 B, entropy ~8.0. 42 raw `BM` pairs in `.001` are chance bytes
  (0/42 valid BITMAPFILEHEADER): no texture decode before decrypt.

Loader strings live in inner `DSJ3.exe` (2233240 B, PE32 i386) as
UTF-16 (file offsets): `Hills` 0x20b29a/0x20b300, `Languages`
0x205992, `Resource` 0x205e1a/0x205e2e/0x20819e/0x2081b2,
`Data Files` 0x20597c/0x205e04/0x208188/0x20b284, `.lan`
0x2059a8. ASCII `hill` xrefs are noise (2 hits, see scope note).

Next: REA on inner `DSJ3.exe` — xrefs to those string addresses,
then decrypt routine, then spec + parser per format. Fixtures in
`engine/tests/` stay generated-only.
