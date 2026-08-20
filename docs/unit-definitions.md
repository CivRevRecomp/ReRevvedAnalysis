# Unit definitions

Version 1.3 stores 29 unit definitions at `0x82F700D8`. Each record is
`0x94` bytes. The unit type byte at offset `0x1` of the `0x54`-byte runtime
unit record indexes this table.

The names below are recovered semantic labels, not original debug symbols.
The machine-readable evidence and qualifications live in
[`unit-definitions-ai-evaluation.json`](../manifests/unit-definitions-ai-evaluation.json)
and the reusable catalogs.

## Recovered layout and readers

| Item | Address or offset | Accepted meaning |
|---|---:|---|
| Unit-definition table | `0x82F700D8` | 29 records with stride `0x94` |
| Runtime unit type | unit record `+0x1` | Zero-based index into the definition table |
| Internal name | definition `+0x0` | NUL-terminated record name when present |
| Base attack | definition `+0x40` | Signed byte read by `EffectiveUnitAttackLookup` |
| Base defense | definition `+0x41` | Signed byte read by `EffectiveUnitDefenseLookup` |
| Effective attack reader | `0x82CF2230` | Applies unit and civilization modifiers to base attack |
| Effective defense reader | `0x82CF21A0` | Applies unit and civilization modifiers to base defense |

The remaining bytes in the word beginning at `+0x40` are intentionally
unnamed. Their adjacency to attack and defense does not prove movement or any
other gameplay meaning.

## UnitType values

| ID | Internal name | Attack | Defense |
|---:|---|---:|---:|
| 0 | Settlers | 0 | 0 |
| 1 | FSettler | 0 | 0 |
| 2 | Naval Crew | 0 | 1 |
| 3 | Barbarian Hot | 1 | 1 |
| 4 | Barbarian Temperate | 1 | 1 |
| 5 | Barbarian Cold | 1 | 1 |
| 6 | Warrior | 1 | 1 |
| 7 | Militia | 0 | 1 |
| 8 | Legion | 2 | 1 |
| 9 | Archer | 1 | 2 |
| 10 | Riflemen | 3 | 5 |
| 11 | Modern Infantry | 4 | 8 |
| 12 | Horsemen | 2 | 1 |
| 13 | Knights | 4 | 2 |
| 14 | Tank | 10 | 6 |
| 15 | Phalanx | 1 | 3 |
| 16 | Catapult | 4 | 1 |
| 17 | Cannon | 6 | 2 |
| 18 | Artillery | 16 | 2 |
| 19 | Submarine | 12 | 2 |
| 20 | Galley | 1 | 1 |
| 21 | Galleon | 2 | 2 |
| 22 | Cruiser | 6 | 6 |
| 23 | Battleship | 12 | 18 |
| 24 | Space Station | 0 | 3 |
| 25 | Bomber | 18 | 3 |
| 26 | Fighter | 6 | 4 |
| 27 | ICBM | 0 | 0 |
| 28 | Spy | 0 | 0 |

Definitions 3 through 5 have an empty string at the record start. Their labels
come from the record-local strings `Barbarian_Hot`, `Barbarian_Temperate`, and
`Barbarian_Cold` at `+0x20`; the table above renders underscores as spaces.

## Simulation and AI consumers

`CombatResolve` at `0x82CD9970` calls both effective stat readers. Three
independent AI-side functions also call both readers:

- `AIUnitChoiceEvaluate` at `0x82CB44E0`
- `AITurnUnitEvaluation` at `0x82CB6E48`
- `AITurnUnitFilter` at `0x82CBF570`

A default-off runtime probe observed the shared readers during AI turns for
players 1 through 5. It also observed the combat path for an AI attacker and a
human defender. For base attack and defense, a table change therefore reaches
both combat simulation and the recovered AI evaluation paths through the same
effective accessors.

This is not general AI parity for a unique-unit modification. Costs, movement,
abilities, flags, production weights, display names, and naval or air special
behavior require independent producer-consumer mapping before mutation.
