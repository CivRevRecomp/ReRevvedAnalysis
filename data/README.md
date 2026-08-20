# Reference data

These CSV files are the canonical player-facing labels and descriptions used by
the recovered game reference:

- `civilizations.csv` owns civilization display names, leaders, and starting
  bonus descriptions. Its starting-bonus ID column remains blank because no
  shared starting-bonus ID storage has been recovered.
- `era-bonus-definitions.csv` owns one gameplay description for each recovered
  era-bonus ID.

Recovered civilization IDs, internal names, row order, and four era-bonus ID
assignments remain canonical in
[`civilization-bonus-storage.json`](../manifests/civilization-bonus-storage.json).
Run `python tools/reference_data.py --write` after changing either CSV or the
manifest. The repository verification gate rejects a stale rendered table.

Player-facing civilization data was normalized from the [Civilization Wiki
list](https://civilization.fandom.com/wiki/Civilizations_%28CivRev%29) and
cross-checked against the [StrategyWiki civilization
reference](https://strategywiki.org/wiki/Civilization_Revolution/Civilizations).
External references help interpret the retail data; they do not override the
recovered image assignments.
