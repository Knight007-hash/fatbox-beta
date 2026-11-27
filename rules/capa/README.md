# capa rules and library signatures (T-14)

FatBox's code analysis (`fatbox/static/code_analysis.py`) runs [capa](https://github.com/mandiant/capa)
by Mandiant on each sample, in memory. capa's Python package does not include its rules or its library
signatures, so they live here, at a pinned version, and reach the VM with **Update VM** like the YARA
rules. capa needs no network of its own (INV-7).

| Folder | What | Source | Version | License |
|---|---|---|---|---|
| `rules/` | 1,054 capa rules (`*.yml`, 391 of them in `nursery/`) | `mandiant/capa-rules`, tag `v10.0.0` (`capa-rules-10.0.0.zip`, sha256 `c27974b03020dd563125b40b20d26eeaee13a5cc5c0c2be1d1a7ee57098cbd2f`) | 10.0.0 | Apache-2.0, `rules/LICENSE.txt` |
| `sigs/` | 3 FLIRT library signature files + their README | the `sigs/` folder of the `flare_capa-10.0.0` source package on PyPI | 10.0.0 | Apache-2.0 (Mandiant, see `sigs/README.md`) |

`VERSION` holds the rules version shown in each report ("rules v10.0.0"). Only the rule files and the
license were copied from the zip; its `.github/` scripts were left out.

The signatures name known library code (Microsoft C runtime, ATL/MFC, zlib and other common C libraries) so
capa skips it: a clean program's runtime then no longer reads as "parses PE headers" or "encodes with XOR".

The rules' `examples:` lines name public sample hashes chosen by the capa authors. They are not samples
FatBox fetched and no sample is stored here.

## Updating

Keep the rules on the same major version as the `flare-capa` library in `requirements.in`. To move up:
download the matching `capa-rules` release zip and the `flare_capa` source package, replace `rules/` and
`sigs/`, update `VERSION` and the table above, and run `python -m pytest -q`. This is a PR like any other.
