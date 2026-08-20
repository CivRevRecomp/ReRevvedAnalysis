# Save storage and slot identity

The player-facing slot label is separate from the internal storage filename.
Ruleset persistence must use the internal filename inside the selected
user/device content namespace.

## Selected content record

The save/load picker owns 11 UI records with stride `0x164`. On acceptance,
`SelectedContentRecordCopy` at `0x82DDBFF8` copies a `0x13C`-byte payload to
the caller. The reusable field is:

| Offset | Recovered meaning |
| --- | --- |
| `0x108` | NUL-terminated internal slot filename read by both manual save and load owners |

The filename is not a global identity. Two users or storage devices may expose
the same filename, so a host sidecar key must retain the selected content
namespace.

The image also contains raw slot roots `save1` through `save9`, `save0`, and
`saveb` through `savei` at pointer table `0x82F77368`. These strings describe
the internal namespace, but the normalized filename read from record offset
`0x108` is the accepted sidecar component. Do not substitute the localized
`Save @NUM`, `Autosave %d`, or other display labels.

## Recovered functions

Names below describe recovered semantics, not original debug symbols.

| Address | Semantic name | Role |
| --- | --- | --- |
| `0x82DDDFC0` | `SaveContentEnumerate` | Resolves the selected user and enumerates eleven type-1 content records. |
| `0x82D83208` | `SaveSlotPick` | Opens the slot picker in save mode and returns an accepted record. |
| `0x82D834F0` | `LoadSlotPick` | Opens the slot picker in load mode and returns an accepted record. |
| `0x82DDBFF8` | `SelectedContentRecordCopy` | Copies the accepted record payload to its caller. |
| `0x82D82510` | `SaveGameToSelectedContent` | Uses record `+0x108`, serializes the game, and finalizes the content file. |
| `0x82D84238` | `LoadGameFromSelectedContent` | Uses record `+0x108`, opens the content, and invokes the native deserializer. |

## Sidecar intervention edges

The load function entry at `0x82D84238` is before content open and before the
native deserializer call at `0x82D844CC`. A host can check ruleset identity
there and stop a mismatched load before native state changes.

The save serializer returns at `0x82D82984`. The function then combines that
result with file-finalization status. At `0x82D829E8`, `r25` is the final
boolean and the selected filename remains live through `r29`. A sidecar may be
atomically replaced only when this result is nonzero.

## Implementation guard

A future host-only sidecar should contain the locked ruleset identifier,
version, and configuration hash. It must be resolved in the same selected
user/device content namespace as the native slot, checked before load, and
committed with an atomic temporary-file replacement only after save success.
The native save remains unchanged.
