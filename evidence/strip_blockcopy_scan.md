# Block-copy scan for `[strip+0x18]` writer (U1 of `de150_flag.md`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: strictly whether any block copy (`REP MOVS*`, `MOVSD` loop,
`memcpy`-style call, `0x34`-byte struct copy) in the swept set writes the
`[strip+0x18]` mode flag read at `0x4de1c8`. No engine code touched.
Parent context: `evidence/de150_flag.md` (U1), `evidence/strip_vtable_sweep.md`
(virtual setter ruled out; this scan was its recommended next target).

Procedure inventory: `list_procedures`
`ev_7015a97ff33c12877418fd7b79cc3a067db4e5160f5ca6b68a7d311662ed7674`
(14224 total); filter `0x4dd5c0-0x4e1b50` yields 81 procedures; plus builders
`0x434020`, `0x434390` = 83-procedure swept set.
`binary_overview` `ev_9724d959565bff31f2911dfadfe486347473d70dcf170e0ac59259698d3a0f6a`.

## 1. Observation: zero `REP`/`MOVS`/`STOS` in all 83 swept procedures

`read_function_instructions` per procedure, filter `/REP|MOVS|STOS|MEMCPY/i`
(all case variants). Every procedure returns zero hits. Counts below are the
returned instruction totals (proving the reads were non-empty except for
2-insn stubs, which are enumerated too):

```text
proc      insns  evidence_id
0x4dd5c0    75   ev_95cad0e5afa7e76d1bf14eccf653bdac33e6f9db71474654f95c59edbbafda36
0x4dd6c0    11   ev_6a73cd333868d3e203c788b5767feb29d22467508acd9738a0ccfd8f4df068d6
0x4dd6e0   138   ev_9243d090bdc67d06f1f4492e0824be6e175c945de926bf4a8ed954d42f4a54d2
0x4dd880    86   ev_14861b5221cf53964caf5333f572538ee805f459d9d1b06b7821d143440a5f28
0x4dd970     2   ev_830c13d76331c5400adcd0515cc0a82e85f687099413e5d27c3b06d0720f54d9
0x4dd980    89   ev_3e33f5de870b70dffcbb98daf95ca5b03bfd0c7cc9200819e9261d769f79140e
0x4dda60    41   ev_c684fde3b083eb024998f918ef02078dc28dc057751ba03d85dea6a9ead81c81
0x4ddae0   144   ev_a1f116a0f2ed84d7ac444745dfb0776c4a7244c413f77d2ea05aee7456633f21
0x4ddcb0   200   ev_c70a3b9af6856aeed8a623249d5af75ca8ec3354ca2fda884e2599b3a327e90a
0x4ddf10   185   ev_d3ff4275eb70dd9accb448a3f99d627a452b070f7c40d712cf66e60da842d350
0x4de150   100   ev_36b7a8bbc8fec698690120afc306de67fdee8dbb5f7976ef20b150e339fab7
0x4de240    40   ev_fceaa44d3610f4d59f5c8f8723cffad9113e29aad158817ecc6778adbd3cde6e
0x4de2a0    42   ev_9d38aba08382a25cfbcdb9177cdf6bfe1c7a511d9c23af799f155e7d29cfbc5d
0x4de320    15   ev_fcc41de91e80999890990cc65c27434ce2a7d617f096bca796273df1784a885a
0x4de350    15   ev_96d9889bd700f94eb54d3d74a87b81b3ff665af7c33d842497195b004f0a18fe
0x4de380    28   ev_076622dc639d0514ab370c9f3b78798796ebed6c284befea050d1ad438163c58
0x4de3e0    23   ev_b7992e2f5d2001d3d948495b2d7f84c12abab6749d1eea031cf3f9d96a9ce872
0x4de430    25   ev_488e8d1f1ea07ba4fffcb72baa9362aa034dd11e3012d3191ca2ac676c201bbb
0x4de480    23   ev_9900296905fa787ffa718abc8e34bb1ac4f90db5f962c98863a130974c2765a6
0x4de4d0    23   ev_840307b2aefa2b03aac4303740975c61d819f8b95a104e1ac100aae144e39f73
0x4de520    39   ev_ec6c90c1d1014512410601ca4bfdac3e4deb5daa09dc26f18fbe4046a749bfd4
0x4de5a0    94   ev_8ffd4cf4470d15bb2e38c729f423702824382a2992471ebebfb46a1f3bbfc782
0x4de6b0    89   ev_240e1ec85f921f98e0f999c2bc00675f11a11d44259f54111a6c97fed46a3214
0x4de7c0    20   ev_76a4299e1161b88909ba664ff3cc83e4ebe239bcf3d12d7f329857d88db99a9b
0x4de7f0    66   ev_b0b3137c13188d7089836e924f89f572089479bb1f7606446762785e9778f840
0x4de8c0   119   ev_6ccaa2cd746728a21a963fadc7bae8578606feb4a51bf7b1909238bfcd7c85a4
0x4dea20    39   ev_a63928a95d5c19bd1204f1a229cd1a4cd7d3436d385653940e04324db6add902
0x4dea80    38   ev_b39552118fffc742f015c17c71c2de48242b880e327fed636d5c31cf7b249ff7
0x4deae0   364   ev_412bd82cfdc663c41d13155e7793424a7235bdae205626183e036f32552ee63a
0x4deee0    25   ev_c1e650cff689c57fa3559647c742a13b61bb57dc4e5ed98dff30524833123792
0x4def20   211   ev_25ed637bd2ca34ca5321a35908d93f49ddaea60fe5439700fe9ea229c21e2de7
0x4df190    27   ev_1d98b2e38aef6fdd48464b26d62363665c417432b79f332aa17bb7ed5e0db4ef
0x4df1d0    38   ev_ced754a44b4e66e34a2070d84c6a8753fbe238bf3d788e2663c07cc4cffba5b5
0x4df230    31   ev_052dd49616b7dc846f09ae0f2c08db801f930fca98754a6f9db28fdd7e7450eb
0x4df280    18   ev_c28dbdb1fdcf1b48dc4d3976383bc215c44c650181048acd5488dd89d3ea15f3
0x4df2d0    28   ev_836f099c7df44723f3d1a784d8fafff45fd5a9ca9a98c7caecf063dfeb4e1ae7
0x4df350    10   ev_fb341875049542f0aafb1f33b10bdc6d53a7a3c2c16fcafb7f541ba77299f0c5
0x4df370    11   ev_9527d108b61398b31b88f5e1b15c0b1b4f3cf66df5ad718ab0f5769a5d085c06
0x4df390    21   ev_478d782b28a836ea559b709f3dcb239ad269993f73c572933a3f07a15227df27
0x4df3c0    41   ev_4d06df06ead66d27392a87fdd87226395e91485f3551e763a0036421f2531b71
0x4df430    57   ev_8bc59bd16e51397bde9a94d7cbec34ff6059b4cff4c44bff17a0be30e6b474dd
0x4df4d0    24   ev_d1db620e3d3a0ac4da961a14522013d652d4ec8ac70dd5c1a9e3b99db2f4bd86fa1a
0x4df510    60   ev_bdeebe67ec78a11bcf7500a7bcaffc0bec9a3df23ae872c4496b1b73eace4ccd
0x4df5b0    23   ev_c941c9f9bbe43c6b623275840bd2e96e2bd96203dfdb654dd5cb36f46c492cb0
0x4df5f0    24   ev_480089f747cc3b9641296f98758d13ccbb27fcd9ae164cc609bd2c5a7762bf48
0x4df630    14   ev_6078639560adf570655a38b1bf56d445550cd024e4383617c4674a271db9fa3a
0x4df660    57   ev_fd26eba0e1985b0bf24eb576e76d45a30cbea7311c74caf09bc179d19bc41559
0x4df700    65   ev_21c32d31ae17eefe7771a9db294d67501a79cc0d0b826e82e8c97fe713bedec5
0x4df7e0    13   ev_0ec716c1c0a9845d823d30c3045aaa9941c012c528b678c92023aad03980e728
0x4df810    11   ev_cc408c70e357d17fb4004b37c3b87d1f37cc13cef7588e1527cd622a51b31c58
0x4df830     2   ev_e431be39f49e420b4c13bc92a903838c83003bc5e4b9e3f5261a4df1fd538046
0x4df840    21   ev_093eb0f889a589b9d97000a0efcd5b32ffe78a0bb81d7d08381cb0695cdaa3f2
0x4df880     9   ev_5add07cd70032524107c7b4d07c4c47a27e91c23695698469fb924c0cca280b8
0x4df8a0     9   ev_5a9f94d62edb05919f36f15ba83c7943e8a26449d243f5172588f4eab94352d4
0x4df8c0    23   ev_f9748f05de2bd6aa10aa01087599ab3cdeca4ec8f47837e3971262353350f304
0x4df900    36   ev_a4dd19baa570044399e4cc0937334e967441b5a8ed77da051d33632a22c0ec11
0x4df960    12   ev_ddc42a4d8eb43ff10f81e98cde0405ca13dfb5760e03fadb63fa8f43956a90db
0x4df9a0    20   ev_23c3dba810f2460c59ce1093696d9a8fb6ecede5cb660766e405039fc34f6785
0x4dfa10    14   ev_49a0669e9c45a54ca06df3c502b46c404ce51d2d09424678ef21d668f821038c
0x4dfa40    11   ev_a6fd5cd5a0ab55dd408a7433ee7fbb11b007ab8afed4822854c5d68786637ec7
0x4dfa60     2   ev_131d18765699cd1e7f63f2956ec274bd5ff992358edf3eed478633368abb8f48
0x4dfa70     4   ev_cf7c034ba11b4f8fbe0201e493382c948b5f1d9b56138042c9a13606807c215e
0x4dfa80    10   ev_981683d8c7e872d22ff4cc981bf06d66767d0553fc62e8e6246409cad35008a6
0x4dfb30   992   ev_b2406d2b1791fcf3cb212a0ac076ecfa21f1ce06f573ac41e258f261304dc6da
0x4e0740    11   ev_e83c8e5f36f7d5ea07883ce7ffcf58b1a7de8a2be910a570d7430655f3b68ad5
0x4e0760   219   ev_cdfa0b5b0e377bc5059c370aa6acb8ef91d55aa027d6fdf5c2972d0f5c6b2b35
0x4e09d0    19   ev_1c12289d28aefb0434f83d489ee3cafc7fb3a310cb7538370f8cc2641f916edf
0x4e0a10     2   ev_5f35c509c46ed4a3a893037a26d6074c0b18a3b074f93c720c8e05dd6bd7fa36
0x4e0a20     2   ev_2ed37c6655cf0784568d629887205e79a33002469813bc0e57be09e8fe7f1df1
0x4e0aa0    16   ev_0caecadf904443d20d2472aa2570d0112098356a0a399852925b6d2861a20844
0x4e0b10     5   ev_d9c296b4c5c6f20809e58c75368f5a3b47a59b1190f79695502a0685c013e8e6
0x4e0b30     4   ev_1e29141e84d4f8b14b103a447315789431cff2a8bbaac0ea4bc1bd457d092191
0x4e0b70     5   ev_62d9b6136ea846c7dd0cc9fa326d972f1fcc5a1609ee5e23991e30efe361726c
0x4e0b90     4   ev_ad2eb061f97ad7b07127253d8b82d859ec884ea6a5dc2399c302fbe2832780f1
0x4e0c20   785   ev_7672933a51842972455ac0247e13d9b508c323926ca9b00070975f68e3cea840
0x4e1620    11   ev_883fe8d73bc308b85d073bd9a716b33fa730ab9a859fc737d03ad1f9d73fe8be
0x4e1640   219   ev_6d020fb4b7c2918a416e03bf94dbcc189a78e398fd47a50d1bb78032fd453346
0x4e1900    33   ev_ad50ea17998f8e5b3e0e05d50f4ccdffc17b9e724b7600f217f61756ff34f91a
0x4e1970    11   ev_3095218d5978ed6b9a41a8fb20351e6db06e481220088093b37baeed89ff24b1
0x4e1990     2   ev_4215a11fc9b871d77ba592ee4904505986f685bdfd17ee540a73fcd37e0c8042
0x4e19a0    96   ev_f3c54c602f81cb883c40598c8fb1a84382a391ec3861af0f40d6cc38ece60eef
0x4e1b50   848   ev_1cbfa7efe7fc8d4a801d96d44077c2ac5a8f32d0e2470f60f339708bcb4b5773
0x434020   282   ev_f7f67a66445221f001d2f5b1e7cfe9b1b34497cf751f21e35e22cd5a3b1608cc
0x434390   385   ev_d1fb88a82b7fb1d00d78bcfcb05167f694ad1ddd5c1a9bfc805fee787e9c6a43
```

No `REP`, `MOVS`, `STOS`, `MEMCPY` (either case) in any of them. This rules
out inline `rep movs` block copies in the swept set. (Helper interiors are a
separate question, see §2 and Unknowns.)

## 2. Observation: no `memcpy`-style call; `0x34` hits are alloc-size or stack slots

`search_procedures "memcpy"` → zero matches
(`ev_7c74480afce8624ced1d81de9b966583a3c285abcda6e821279122e2f3a7e7b9`);
`"copy"` → only `KERNEL32.DLL::CopyFileA` (file API, out of scope) and
`0x59f507 __copysign` (math helper)
(`ev_a9c9fdd2af43be8cb5aabdd76db2ad6b8cedb130c0f1ef42e0999f5a42108e32`).
There is no named `memcpy` import to call.

Full `CALL` inventory of the swept set (from the same `read_bytes`-backed
reads) shows only heap/exception helpers (`0x59c8e9`, `0x59c120`, `0x59c314`,
`0x59c3b0`), lock/except helpers (`0x406b90`, `0x59ccce`), float helpers
(`0x538460` family), and intra-range direct calls — no caller passes a
`strip+0x18` destination to a copy helper.

All `0x34` immediates in the swept set, verbatim:

- `0x43403e: PUSH 0x34`, `0x4340d0: PUSH 0x34` (`0x434020`: `operator_new`
  sizes for the two strips), `0x4343ae: PUSH 0x34`, `0x434440: PUSH 0x34`
  (`0x434390`: `operator_new` sizes) — allocation sizes, not copy lengths.
- `0x4ddab2/0x4ddac7: MOV EDX,[ESP+0x34]`, `0x4ddcea/0x4ddd23: LEA ECX,[ESP+0x34]`,
  `0x4de132: MOV ECX,[ESP+0x34]`, `0x4de6b0: SUB ESP,0x34` /
  `0x4de7b0: ADD ESP,0x34`, `0x4de81b...: [ESP+0x34]` float compares,
  `0x4df660: LEA ECX,[ESP+0x34]`, `0x4df700: LEA EDX,[ESP+0x34]`,
  `0x4dfb48/0x4e00b8...: [ESP+0x34]` register spills, `0x4344f6: FADD [ESP+0x34]`,
  `0x4346d5/0x434806/0x43485a/0x43485f: [ESP+0x34]` temps — all `ESP`-relative
  stack slots or frame sizes, not a `0x34`-byte struct copy with a strip
  destination.

## 3. Observation: large-function `EDI`/`ESI` traffic is parent-class init, not strip copies

Deep check on the six widest functions (no `LOOP`/`JCXZ`/`MOVS`/`REP`/`STOS`/
`XCHG` in any of them):

- `0x4dfb30` (992 insns, `ev_b2406d2b1791fcf3cb212a0ac076ecfa21f1ce06f573ac41e258f261304dc6da`):
  `EDI`/`ESI` stores are `[ESI+0x50..0x98]` runs plus vtable `0x5d09f4`.
- `0x4e0c20` (785, `ev_7672933a51842972455ac0247e13d9b508c323926ca9b00070975f68e3cea840`):
  `[ESI+0x5c..0xa0]` runs plus vtable `0x5d0a74`.
- `0x4e1b50` (848, `ev_1cbfa7efe7fc8d4a801d96d44077c2ac5a8f32d0e2470f60f339708bcb4b5773`):
  `[ESI+0x5c..0x98]` runs plus vtable `0x5d0b94`.
- `0x4e0760` (219, `ev_cdfa0b5b0e377bc5059c370aa6acb8ef91d55aa027d6fdf5c2972d0f5c6b2b35`),
  `0x4e1640` (219, `ev_6d020fb4b7c2918a416e03bf94dbcc189a78e398fd47a50d1bb78032fd453346`):
  descending `[ESI+0xa0..0x50]` zeroing runs, vtables `0x5d09f4`/`0x5d0a74`.
- `0x4def20` (211, `ev_25ed637bd2ca34ca5321a35908d93f49ddaea60fe5439700fe9ea229c21e2de7`):
  only `[ESI+0x0/0x4/0x8]` node-field stores — list node, never `+0x18`.

None installs the strip vtable `0x5d09d8`; all are different (larger) classes.
Unrolled dword copies covering `+0x18` with a literal offset are additionally
already ruled out by the `+0x18` negative sweep in `de150_flag.md` §3 (any
such copy would contain one literal `+0x18` store).

## 4. Inference (labeled)

The `rep movs`/block-copy mechanism for U1 is ruled out **within the swept
set** (83 procedures + 2 builders): no `REP`/`MOVS`/`STOS` opcode, no named
`memcpy`, no `0x34`-length copy call, and the heavy `EDI`/`ESI` traffic
belongs to other classes. Combined with `de150_flag.md` §3 (no direct store)
and `strip_vtable_sweep.md` §4 (no virtual setter), the only remaining
mechanism is a writer **outside** `0x4dd5c0-0x4e1b50` (or outside the two
builders). This is inference: absence from the swept set does not prove no
writer exists (see Unknowns).

## Unknowns

- U1 (still open, narrowed twice): nonzero writer of `[strip+0x18]`. Direct
  stores, virtual setters, and now inline block copies are all ruled out in
  the swept set. Remaining: writer outside `0x4dd5c0-0x4e1b50` / outside
  `0x434020`+`0x434390` (e.g. a deserializer, file loader, or second
  construction path that builds a `0x34`-byte strip-lookalike and hands it to
  `0x4de150`).
- U-helper: interiors of callees (`0x59c8e9`, `0x406b90`, `0x538460` family,
  `0x45ad30`, `0x467380`, …) not instruction-verified; a helper hiding a
  `REP MOVS` that takes a caller-supplied strip pointer is implausible from
  the call-site shapes (length/address arguments absent) but not
  instruction-verified.
- U-computed: a copy with a fully computed destination (strip base in a
  register, offset in another register, no literal `0x18` anywhere) would
  escape both this sweep and the `+0x18` literal sweep; the CALL inventory
  shows no such copy call shape, but data-flow was not traced.

## Next target (ONE)

Enumerate cross-references to the strip vtable base `0x5d09d8` (`xrefs`) and
incoming callers of the ctor `0x4dd5c0` outside `0x434020`/`0x434390`: any
additional instantiation site outside the swept range is the last place a
nonzero `[strip+0x18]` writer can hide.
