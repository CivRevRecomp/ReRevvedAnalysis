from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path


CIVILIZATION_HEADERS = (
    "civ_id",
    "internal_name",
    "display_name",
    "leader",
    "starting_bonus_id",
    "starting_bonus",
)
BONUS_HEADERS = ("bonus_id", "effect")
ERA_NAMES = ("Ancient", "Medieval", "Industrial", "Modern")
BONUS_TABLE_BEGIN = "<!-- civilization-bonus-map:begin -->"
BONUS_TABLE_END = "<!-- civilization-bonus-map:end -->"
ID_TABLE_BEGIN = "<!-- civilization-era-id-map:begin -->"
ID_TABLE_END = "<!-- civilization-era-id-map:end -->"


class ReferenceDataError(ValueError):
    pass


@dataclass(frozen=True)
class Civilization:
    civ_id: int
    internal_name: str
    display_name: str
    leader: str
    starting_bonus: str


@dataclass(frozen=True)
class CivilizationRow:
    index: int
    name: str
    bonuses: tuple[int, int, int, int]


@dataclass(frozen=True)
class ReferenceData:
    civilizations: tuple[Civilization, ...]
    bonus_effects: dict[int, str]
    manifest_rows: tuple[CivilizationRow, ...]


def _read_csv(
    path: Path,
    headers: tuple[str, ...],
    allow_empty: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            if tuple(reader.fieldnames or ()) != headers:
                raise ReferenceDataError(
                    f"{path.name}: expected headers {','.join(headers)}"
                )
            rows = list(reader)
    except csv.Error as error:
        raise ReferenceDataError(f"{path.name}: malformed CSV: {error}") from error

    for row_number, row in enumerate(rows, start=2):
        if None in row:
            raise ReferenceDataError(f"{path.name}:{row_number}: extra CSV field")
        for header in headers:
            value = row.get(header)
            if value is None or (not value and header not in allow_empty):
                raise ReferenceDataError(
                    f"{path.name}:{row_number}: {header} is required"
                )
            if value != value.strip():
                raise ReferenceDataError(
                    f"{path.name}:{row_number}: {header} has outer whitespace"
                )
            if "|" in value or "\n" in value or "\r" in value:
                raise ReferenceDataError(
                    f"{path.name}:{row_number}: {header} is not Markdown-safe"
                )
            markers = (
                BONUS_TABLE_BEGIN,
                BONUS_TABLE_END,
                ID_TABLE_BEGIN,
                ID_TABLE_END,
            )
            if any(marker in value for marker in markers):
                raise ReferenceDataError(
                    f"{path.name}:{row_number}: {header} contains a generated marker"
                )
    return rows


def _parse_id(value: str, location: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ReferenceDataError(f"{location}: expected decimal integer") from error
    if str(parsed) != value or parsed < 0:
        raise ReferenceDataError(f"{location}: expected canonical nonnegative integer")
    return parsed


def _load_civilizations(path: Path) -> tuple[Civilization, ...]:
    raw_rows = _read_csv(
        path, CIVILIZATION_HEADERS, allow_empty=frozenset({"starting_bonus_id"})
    )
    if any(row["starting_bonus_id"] for row in raw_rows):
        raise ReferenceDataError(
            "civilizations.csv: starting_bonus_id must remain blank until recovered"
        )
    rows = tuple(
        Civilization(
            civ_id=_parse_id(row["civ_id"], f"{path.name}:{index}:civ_id"),
            internal_name=row["internal_name"],
            display_name=row["display_name"],
            leader=row["leader"],
            starting_bonus=row["starting_bonus"],
        )
        for index, row in enumerate(raw_rows, start=2)
    )
    expected_ids = tuple(range(16))
    actual_ids = tuple(row.civ_id for row in rows)
    if actual_ids != expected_ids:
        raise ReferenceDataError(
            "civilizations.csv: civ_id values must be unique and ordered 0 through 15"
        )
    for field_name in ("internal_name", "display_name"):
        values = tuple(getattr(row, field_name) for row in rows)
        if len(values) != len(set(values)):
            raise ReferenceDataError(
                f"civilizations.csv: duplicate {field_name} value"
            )
    return rows


def _load_bonus_effects(path: Path) -> dict[int, str]:
    raw_rows = _read_csv(path, BONUS_HEADERS)
    effects: dict[int, str] = {}
    ids: list[int] = []
    for row_number, row in enumerate(raw_rows, start=2):
        bonus_id = _parse_id(
            row["bonus_id"], f"{path.name}:{row_number}:bonus_id"
        )
        if bonus_id == 0:
            raise ReferenceDataError(
                f"{path.name}:{row_number}: bonus_id must be positive"
            )
        if bonus_id in effects:
            raise ReferenceDataError(
                f"{path.name}:{row_number}: duplicate bonus_id {bonus_id}"
            )
        effects[bonus_id] = row["effect"]
        ids.append(bonus_id)
    if ids != sorted(ids):
        raise ReferenceDataError(
            "era-bonus-definitions.csv: bonus_id values must be numerically ordered"
        )
    return effects


def _load_manifest_rows(path: Path) -> tuple[CivilizationRow, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        shape = document["storage"]["shape"]
        raw_rows = document["storage"]["rows"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ReferenceDataError(f"{path.name}: invalid storage.rows") from error

    expected_shape = {
        "civilizations": 16,
        "erasPerCivilization": 4,
        "entrySize": 4,
        "rowSize": 16,
        "totalSize": 256,
    }
    if shape != expected_shape:
        raise ReferenceDataError(f"{path.name}: unexpected storage.shape")
    if not isinstance(raw_rows, list):
        raise ReferenceDataError(f"{path.name}: storage.rows must be a list")

    rows: list[CivilizationRow] = []
    for raw in raw_rows:
        try:
            index = raw["index"]
            name = raw["name"]
            bonuses = tuple(raw["bonuses"])
        except (KeyError, TypeError) as error:
            raise ReferenceDataError(f"{path.name}: malformed civilization row") from error
        if type(index) is not int or not isinstance(name, str):
            raise ReferenceDataError(f"{path.name}: invalid row index or name")
        if len(bonuses) != len(ERA_NAMES) or not all(
            type(value) is int and value > 0 for value in bonuses
        ):
            raise ReferenceDataError(
                f"{path.name}: row {index} must have four positive bonus IDs"
            )
        rows.append(CivilizationRow(index, name, bonuses))

    if tuple(row.index for row in rows) != tuple(range(16)):
        raise ReferenceDataError(
            f"{path.name}: row indexes must be unique and ordered 0 through 15"
        )
    return tuple(rows)


def load_reference_data(repo: Path) -> ReferenceData:
    civilizations = _load_civilizations(repo / "data" / "civilizations.csv")
    bonus_effects = _load_bonus_effects(
        repo / "data" / "era-bonus-definitions.csv"
    )
    manifest_rows = _load_manifest_rows(
        repo / "manifests" / "civilization-bonus-storage.json"
    )

    for civilization, manifest_row in zip(civilizations, manifest_rows, strict=True):
        if civilization.civ_id != manifest_row.index:
            raise ReferenceDataError(
                f"civilization {civilization.civ_id}: manifest index mismatch"
            )
        if civilization.internal_name != manifest_row.name:
            raise ReferenceDataError(
                f"civilization {civilization.civ_id}: internal name "
                f"{civilization.internal_name!r} disagrees with manifest "
                f"{manifest_row.name!r}"
            )

    assigned_ids = {
        bonus_id for row in manifest_rows for bonus_id in row.bonuses
    }
    defined_ids = set(bonus_effects)
    missing_ids = sorted(assigned_ids - defined_ids)
    unused_ids = sorted(defined_ids - assigned_ids)
    if missing_ids:
        raise ReferenceDataError(
            "era-bonus-definitions.csv: missing assigned IDs "
            + ", ".join(map(str, missing_ids))
        )
    if unused_ids:
        raise ReferenceDataError(
            "era-bonus-definitions.csv: unused IDs "
            + ", ".join(map(str, unused_ids))
        )

    return ReferenceData(civilizations, bonus_effects, manifest_rows)


def _display_label(civilization: Civilization) -> str:
    if civilization.display_name == civilization.internal_name:
        return civilization.display_name
    return (
        f"{civilization.display_name} "
        f"(`{civilization.internal_name}` internally)"
    )


def _render_bonus_table(data: ReferenceData) -> str:
    lines = [
        "| Civilization | Leader | Starting | Ancient | Medieval | Industrial | Modern |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for civilization, manifest_row in zip(
        data.civilizations, data.manifest_rows, strict=True
    ):
        effects = [data.bonus_effects[bonus_id] for bonus_id in manifest_row.bonuses]
        cells = [
            _display_label(civilization),
            civilization.leader,
            civilization.starting_bonus,
            *effects,
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _render_id_table(data: ReferenceData) -> str:
    lines = [
        "| Civ ID | Internal name | Ancient | Medieval | Industrial | Modern |",
        "| ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in data.manifest_rows:
        cells = [str(row.index), row.name, *(str(value) for value in row.bonuses)]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _replace_region(text: str, begin: str, end: str, body: str) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ReferenceDataError(
            f"civilization-bonuses.md: expected one {begin} and one {end} marker"
        )
    if text.index(begin) >= text.index(end):
        raise ReferenceDataError(
            f"civilization-bonuses.md: crossed generated markers {begin} and {end}"
        )
    prefix, remainder = text.split(begin, 1)
    current, suffix = remainder.split(end, 1)
    if not current.startswith("\n") or not current.endswith("\n"):
        raise ReferenceDataError(
            f"civilization-bonuses.md: malformed generated region {begin}"
        )
    return prefix + begin + "\n" + body + "\n" + end + suffix


def render_document(text: str, data: ReferenceData) -> str:
    text = _replace_region(
        text, BONUS_TABLE_BEGIN, BONUS_TABLE_END, _render_bonus_table(data)
    )
    return _replace_region(text, ID_TABLE_BEGIN, ID_TABLE_END, _render_id_table(data))


def check_repository(repo: Path) -> ReferenceData:
    data = load_reference_data(repo)
    path = repo / "docs" / "reference" / "civilization-bonuses.md"
    current = path.read_text(encoding="utf-8")
    expected = render_document(current, data)
    if current != expected:
        raise ReferenceDataError(
            "civilization-bonuses.md: rendered tables are stale; run "
            "python tools/reference_data.py --write"
        )
    return data


def write_repository(repo: Path) -> tuple[ReferenceData, bool]:
    data = load_reference_data(repo)
    path = repo / "docs" / "reference" / "civilization-bonuses.md"
    current = path.read_text(encoding="utf-8")
    expected = render_document(current, data)
    if current == expected:
        return data, False
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(expected)
    return data, True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate or render normalized reference data"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="update generated Markdown regions instead of checking them",
    )
    args = parser.parse_args()

    try:
        if args.write:
            data, changed = write_repository(args.repo.resolve())
            action = "updated" if changed else "unchanged"
        else:
            data = check_repository(args.repo.resolve())
            action = "passed"
    except (OSError, ReferenceDataError) as error:
        parser.exit(1, f"reference-data: {error}\n")

    print(
        "reference-data: "
        f"{action} civilizations={len(data.civilizations)} "
        f"eraBonuses={len(data.bonus_effects)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
