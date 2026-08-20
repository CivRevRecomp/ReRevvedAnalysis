# Civilization bonuses

Each civilization has one starting bonus and four cumulative era bonuses.
Because every game begins in the Ancient era, both the starting bonus and the
Ancient era bonus apply immediately. Later eras add another bonus without
removing either one.

The starting bonus is separate from the image-backed era-bonus table at
`0x82F6F950`. Starting bonuses are heterogeneous: some grant initial state such
as a technology, building, unit, gold, or map knowledge, while others establish
an ongoing rule. The era table contains 16 civilization rows with four 32-bit
bonus IDs per row, one unlock for each era. Each row is `0x10` bytes and the
complete table is `0x100` bytes.

The names below are recovered semantic labels, not original debug symbols.

## Recovered storage and lookup

| Item | Address | Accepted meaning |
| --- | ---: | --- |
| Civilization era-bonus table | `0x82F6F950` | 16 rows by four cumulative era-unlock IDs |
| Civilization name pointers | `0x82F7A348` | 16 internal names aligned with the bonus rows |
| Player era array | `0x830ECD08` | Current era index consumed for each player |
| Player civilization array | `0x830ECD28` | Civilization index selecting one table row |
| Excluded player global | `0x82F700B0` | Player index for which the lookup returns false |
| `ActiveCivilizationBonusLookup` | `0x82CF0CB0` | Shared activation owner and only recovered table reader |
| Starting-bonus text owner | `0x82CF97D0` | Presents the separate starting bonus through `@CIVBONUSTEXT` |

`ActiveCivilizationBonusLookup` receives the requested bonus ID in `r3`, the
player index in `r4`, and an exact-era flag in `r5`.

- In cumulative mode (`r5 == 0`), it clamps the player's era to 0 through 3
  and searches every row entry from Ancient through the current era.
- In exact mode (`r5 != 0`), it compares only the current-era entry and does
  not clamp the era before indexing.
- It returns false when the requested player equals the excluded-player value.

All 95 known call sites across 30 functions use cumulative mode. No exact-mode
caller is known. Do not call exact mode without an
independent era-range guard.

## Starting bonuses

| Civ ID | Internal name | Starting bonus |
| ---: | --- | --- |
| 0 | Roman | Knowledge of Code of Laws and Republic government |
| 1 | Egyptian | An Ancient Wonder |
| 2 | Greek | A Courthouse in the capital |
| 3 | Spanish | Knowledge of Navigation |
| 4 | German | Automatic upgrades for Elite units |
| 5 | Russian | More of the surrounding map revealed |
| 6 | Chinese | Knowledge of Writing |
| 7 | American | A Great Person |
| 8 | Japanese | Knowledge of Ceremonial Burial |
| 9 | French | A Cathedral in the capital |
| 10 | Indian | Access to all resources |
| 11 | Arab | Knowledge of Religion |
| 12 | Aztec | Additional starting gold |
| 13 | African | A lower combat-strength threshold for overrunning enemies |
| 14 | Mongolian | Increased trade from captured cities |
| 15 | English | Knowledge of Monarchy |

These bonuses are not entries in the four-value era table. They also should not
all be described as passive effects: several are one-time grants or initial game
state, while the German, Indian, African, and Mongolian bonuses establish
ongoing rules.

## Civilization rows

The four values are ordered Ancient, Medieval, Industrial, and Modern. They
are cumulative unlocks, not four mutually exclusive replacements.

| Civ ID | Internal name | Ancient | Medieval | Industrial | Modern |
| ---: | --- | ---: | ---: | ---: | ---: |
| 0 | Roman | 1 | 24 | 23 | 36 |
| 1 | Egyptian | 32 | 58 | 12 | 38 |
| 2 | Greek | 60 | 23 | 20 | 28 |
| 3 | Spanish | 7 | 6 | 25 | 41 |
| 4 | German | 50 | 30 | 19 | 47 |
| 5 | Russian | 16 | 26 | 17 | 34 |
| 6 | Chinese | 36 | 10 | 20 | 42 |
| 7 | American | 47 | 35 | 16 | 2 |
| 8 | Japanese | 28 | 27 | 42 | 26 |
| 9 | French | 59 | 1 | 13 | 12 |
| 10 | Indian | 42 | 43 | 5 | 18 |
| 11 | Arab | 38 | 9 | 14 | 47 |
| 12 | Aztec | 46 | 4 | 1 | 25 |
| 13 | African | 55 | 8 | 25 | 17 |
| 14 | Mongolian | 40 | 3 | 56 | 48 |
| 15 | English | 61 | 6 | 41 | 51 |

`African` is the internal image string for civilization index 13. This page
does not substitute a player-facing civilization name.

The Japanese row illustrates the two-layer model. Japan begins with knowledge
of Ceremonial Burial, while its Ancient entry is bonus ID 28, which adds one
food to sea tiles. Both apply from the Ancient era onward; Medieval, Industrial,
and Modern each add another cumulative era bonus.

## Shared consumers

The table has no known writer, initializer, copied row cache, or second reader.
Gameplay consumers call
`ActiveCivilizationBonusLookup` rather than reading rows directly. These
consumers include combat, rush-cost calculation, effective unit-stat readers,
AI-side evaluation, production and economy paths, and other gameplay systems.

This convergence gives a future generic era-bonus variant one shared table and
lookup mechanism. It does not by itself prove that every possible changed era
bonus produces correct AI behavior.

## Modification guards

- Do not treat later-era entries as replacements for earlier bonuses.
- Do not assume the starting bonuses pass through the era-bonus lookup. The
  shared lookup owns the four cumulative era entries, not the separate starting
  package.
- Do not patch individual era-bonus consumer branches for a generic variant;
  recovered era-bonus consumers already converge on the shared lookup.
- Do not assign gameplay meanings to numeric bonus IDs unless their effects
  are mapped.
- Do not infer AI behavioral parity solely because AI functions call the same
  lookup.
- Do not distribute a changed table without save-slot ruleset identity,
  pre-load mismatch handling, and an explicit multiplayer policy.
