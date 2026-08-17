# Catalog contract

The four files under `manifests/catalogs/` are the canonical inventories of
symbols, structs and fields, vtables and slots, and explicit relations. Topic
manifests remain investigation records and are not generated from catalogs or
rewritten when a fact is promoted.

## Identity and formats

IDs are unique within the current catalogs. Allocate the next four-digit value
for the entity kind: `RVA-SYM-`, `RVA-STR-`, `RVA-FLD-`, `RVA-VTBL-`,
`RVA-SLOT-`, or `RVA-REL-`. The validation gate rejects a repeated ID anywhere
in the four catalogs.

Catalog IDs remain reserved through symbol 0164, struct 0030, field 0089,
vtable 0023, and relation 0239. An established entity keeps its ID. Allocate a
new entity after the applicable reserved maximum; do not fill an apparent gap
with a different entity.

Guest virtual addresses use exactly `0x` followed by eight uppercase hexadecimal
digits. Struct and slot offsets use `0x` followed by uppercase hexadecimal with
no redundant leading zeroes. Address-derived placeholder names such as
`sub_82267A28` are preferred until evidence supports a semantic name.

Every top-level record references `../image.json`, the version 1.3 image
contract. A native address or evidence locator enters a catalog only after it is
verified against that image.

## Evidence and confidence

Each claim has one or more evidence entries. Supported evidence kinds are
`topic-manifest`, `ghidra-static`, `generated-code`, `runtime-probe`, and
`external-reference`. A topic-manifest locator is a catalog-relative JSON file
plus a resolving JSON Pointer, for example
`../runtime-baseline.json#/configuredRoot`. Other locator forms are constrained
by the catalog schemas.

Confidence is exactly `confirmed`, `strong`, `candidate`, or `rejected`.
`confirmed` requires authoritative static identity or runtime corroboration for
a behavioral claim. `strong` has direct evidence with a remaining boundary.
`candidate` is a bounded interpretation still needing discrimination.
`rejected` preserves a falsified candidate when retaining it prevents repeated
work. Every claim records at least one unresolved alternative or an explicit
falsification condition.

## Relations

Relations are asserted records, never generated from names, address proximity,
or matching shapes. Both endpoints must be existing symbol, struct, field,
vtable, or slot IDs. A relation is added only when its own evidence states that
edge. Evidence for the endpoint records alone is insufficient.

Run `tools\verify.ps1` after every catalog edit. It loads all four schemas,
checks repository-wide IDs and endpoints, resolves topic-manifest evidence, and
runs focused negative tests for the gate.
