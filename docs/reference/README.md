# Recovered game reference

These pages present settled guest-code findings by game system. They are the
readable layer over the topic manifests and reusable catalogs, not a separate
source of evidence.

- [Unit definitions](unit-definitions.md) - unit type IDs, base combat stats,
  and shared combat and AI consumers.
- [Civilization bonuses](civilization-bonuses.md) - civilization starting
  bonuses, the 16 by 4 cumulative era-bonus table, and its shared activation
  lookup.
- [Save storage and slot identity](save-storage.md) - selected record layout,
  internal filenames, and pre-load/post-save sidecar edges.

Keep related strings, semantic function names, enum values, fields, and guards
together on the applicable system page. Do not create separate string,
function, or enum inventories here; the machine-readable catalogs provide the
canonical cross-system indexes.
