# Topic manifest contract

Topic manifests are the durable investigation records in `manifests/*.json`.
They preserve one bounded question, its current-image evidence, its limits, and
the supported conclusion. The topic manifest is the canonical home for that
finding; raw decompiler output, query reports, and runtime logs remain scratch.

Catalogs have a different role. The four files in `manifests/catalogs/` are the
canonical inventories of reusable symbols, structures and fields, vtables and
slots, and explicit relations. A catalog record is not an investigation log,
and a topic manifest is not an alternate catalog. Promote a supported fact into
the applicable catalog when it becomes a reusable entity or relation, then
leave the investigation record intact. Catalog evidence may point back to a
manifest with a JSON Pointer; do not copy the catalog inventory into the
manifest or rewrite the manifest as a second catalog.

## Identity and common fields

Every topic manifest is a JSON file directly under `manifests/` whose `topic`
field is present. The current checkout enforces this common contract:

| Field | Rule |
| --- | --- |
| `schemaVersion` | Exactly `1`. |
| `id` | Unique across topic manifests and matches `RVA-F-` plus four digits. |
| `topic` | Lowercase kebab-case, unique, and equal to the filename stem. |
| `status` | `open` or `closed`; this records whether the bounded investigation remains active. |
| `confidence` | `confirmed`, `strong`, `candidate`, or `rejected`. |
| `image` | Exactly `image.json`, the version 1.3 image contract. |
| `question` | Current manifests carry a narrow question that the packet answers or bounds; this is a contribution convention rather than a field checked by the focused manifest test. |

`scope` describes the bounded functions, fields, addresses, or other surface.
`currentEvidence` records the current-image support when the packet uses that
section. `guards` state claims that must not be inferred, and `conclusion`
states the supported result. These descriptive sections are conventions rather
than a fixed schema so a packet can preserve the shape needed by its finding.

Confidence labels describe the evidence, not completion status:

- `confirmed` requires authoritative static identity or runtime corroboration
  for a behavioral claim.
- `strong` has direct evidence with a remaining boundary.
- `candidate` is a bounded interpretation that still needs discrimination.
- `rejected` preserves a falsified candidate when retaining it prevents
  repeated work.

## Dependencies and current evidence

New packets use optional `dependencies`: a list of objects with a `topic` and a
concise `use`. The focused test requires each listed topic to be lowercase
kebab-case and resolve to `manifests/<topic>.json` in the current checkout; the
contribution contract additionally requires `use` to state why the dependency
matters. Older packets may carry `dependsOn` or omit `use`; normalize those only
when editing that packet. Dependencies name current packet inputs, not old
paths, commits, migrations, or relocation history. A dependent packet still
carries its own current-image locators.

`currentEvidence` is optional, but when present it must describe evidence in the
current checkout. Keep methods, entries, locators, and qualifications here;
history is not evidence. Do not use the history keys `commit`, `migration`,
`relocation`, or `sourceEvidence` anywhere in a topic manifest. Do not use these
comparison or source-target keys in `currentEvidence`: `pairs`, `source`,
`sourceAddress`, `sourceInstructionCount`, `sourceVtable`, `target`,
`targetAddress`, `targetInstructionCount`, and `targetVtable`.

A qualification records the remaining boundary, unresolved alternative, or
falsification condition. Use exact guest addresses and offsets, and identify
the static, generated, runtime, or external evidence that supports the narrow
claim. Do not turn address proximity, matching shapes, or a decompiler guess
into an identity or behavioral claim.

## Promotion

Start with a narrow read-only query and keep its output in ignored scratch.
Before promotion, verify the claim against the pinned image in
`manifests/image.json`. For behavior, compare a narrow generated-code window
and use a default-off runtime probe. Promote only the compact supported fact,
its evidence, uncertainty, guards, and conclusion into the topic manifest.

If the fact is reusable by other analysis, promote its entity or explicit edge
to the applicable canonical catalog. Give the catalog claim its own evidence
and, for a topic-manifest locator, a resolving JSON Pointer. Catalog promotion
does not make the catalog a source of the investigation record and does not
require rewriting the topic manifest.

## Structural example

The following shows the shape of a bounded packet. The example is illustrative;
the dependency must be an existing topic in a real manifest.

```json
{
  "schemaVersion": 1,
  "id": "RVA-F-0099",
  "topic": "example-boundary",
  "status": "closed",
  "confidence": "strong",
  "image": "image.json",
  "question": "Where does the bounded producer write the record?",
  "scope": { "function": "0x82123456", "recordOffset": "0x10" },
  "dependencies": [
    { "topic": "scene-render-tree-publication", "use": "current owner boundary" }
  ],
  "currentEvidence": {
    "method": "foreground read-only query and narrow generated-code comparison",
    "entries": [
      { "role": "record producer", "address": "0x82123456", "confidence": "strong" }
    ],
    "qualification": "The record field is bounded; its original semantic name remains unresolved."
  },
  "guards": ["Do not infer runtime success from this static boundary."],
  "conclusion": "The producer writes the bounded record field at offset 0x10."
}
```
