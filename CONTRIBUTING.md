# Contributing

A contribution should record or improve a bounded guest-code finding, or
maintain a reproducible headless query that establishes one.

AI-assisted changes also follow the portable policy in
[`docs/ai_agents/README.md`](docs/ai_agents/README.md).

## Findings

Keep the claim narrow and identify the image, guest locator, evidence source,
confidence, and remaining uncertainty. Follow the [topic manifest
contract](docs/topic-manifests.md) when recording a bounded finding. Put the
durable fact in one canonical manifest, catalog, or structure note. Link to it
from other documentation.
Preserve source and external provenance, and do not promote raw
decompiler output as evidence.

## Repository changes

Keep game assets, decrypted images, Ghidra projects, raw query output, and
generated code outside the tracked tree. Use the existing read-only query
workflow for inspections and keep mutating repair runs disposable. Update
`docs/README.md` when adding a tracked Markdown page under `docs/`.

## Verification

Run the repository gate and whitespace check before submitting a change:

```powershell
cd <repo>; .\tools\verify.ps1
cd <repo>; git diff --check
```

The gate checks catalog contracts, focused tests, and repository hygiene. It
does not independently prove guest behavior.
