# Third-party licenses

scadenza is Apache-2.0. The binary links open-source Go modules under
Apache-2.0, BSD-3-Clause, MIT and ISC licenses; none is copyleft.

`dependencies.csv` lists, for every package linked into the binary, the module
path, the URL of its license file and the license type. Regenerate it with
`scripts/third-party-licenses.sh` whenever dependencies change (the release
checklist in [docs/release.md](../docs/release.md) includes this step).

Release archives include `LICENSE` and `NOTICE`. Copies of notices required for
data or code derived into this repository belong in this directory with their
provenance and the affected files. Do not copy third-party data or code without
recording its public source and license.
