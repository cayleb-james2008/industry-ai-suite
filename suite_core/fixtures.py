"""Tenant-partitioned JSON/CSV fixture loading with strict schemas and provenance."""

import csv
import hashlib
import io
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .privacy import redact
from .security import _valid_id


class FixtureError(ValueError):
    """Fixture path, content, or schema is invalid."""


@dataclass(frozen=True)
class FixtureSchema:
    fields: Mapping[str, type]

    def __post_init__(self) -> None:
        supported = {str, int, float, bool}
        if not self.fields or any(not isinstance(name, str) or kind not in supported
                                  for name, kind in self.fields.items()):
            raise FixtureError("schema must map field names to str, int, float, or bool")


@dataclass(frozen=True)
class FixtureData:
    rows: tuple[dict[str, object], ...]
    provenance: dict[str, object]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError("duplicate JSON field")
        result[key] = value
    return result


def _parse_csv_value(value: str, kind: type) -> object:
    try:
        if kind is str:
            return value
        if kind is int:
            return int(value)
        if kind is float:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError
            return number
        if value.lower() in {"true", "false"}:
            return value.lower() == "true"
    except ValueError as exc:
        raise FixtureError("fixture value does not match its schema") from exc
    raise FixtureError("fixture value does not match its schema")


class FixtureAdapter:
    """Read only from `<base>/<tenant>/<relative path>` and reject all path escapes."""

    def __init__(self, base_dir: str | Path, tenant_id: str) -> None:
        if not _valid_id(tenant_id):
            raise FixtureError("tenant ID must be an opaque safe ID")
        try:
            base = Path(base_dir).resolve(strict=True)
            tenant_path = base / tenant_id
            if tenant_path.is_symlink():
                raise FixtureError("tenant fixture directory is outside the fixture root")
            tenant_root = tenant_path.resolve(strict=True)
        except OSError as exc:
            raise FixtureError("tenant fixture directory is unavailable") from exc
        if not tenant_root.is_dir() or tenant_root == base or not tenant_root.is_relative_to(base):
            raise FixtureError("tenant fixture directory is outside the fixture root")
        self.root = tenant_root
        self.tenant_id = tenant_id

    def load(self, relative_path: str | Path, schema: FixtureSchema) -> FixtureData:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or "\x00" in str(relative):
            raise FixtureError("fixture path denied")
        try:
            path = (self.root / relative).resolve(strict=True)
        except OSError as exc:
            raise FixtureError("fixture file is unavailable") from exc
        if not path.is_file() or not path.is_relative_to(self.root) or path.suffix.lower() not in {".json", ".csv"}:
            raise FixtureError("fixture path denied")
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
            if path.suffix.lower() == ".json":
                document = json.loads(text, object_pairs_hook=_unique_object)
                if not isinstance(document, dict) or set(document) - {"rows", "provenance"}:
                    raise FixtureError("fixture JSON must contain rows and optional provenance")
                rows = document.get("rows")
                declared = document.get("provenance", {})
                if not isinstance(declared, dict):
                    raise FixtureError("fixture provenance must be an object")
                parsed_rows = self._json_rows(rows, schema)
            else:
                parsed_rows = self._csv_rows(text, schema)
                declared = {}
        except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
            raise FixtureError("fixture content is invalid") from exc
        provenance = {
            "tenant_id": self.tenant_id,
            "source_id": path.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "format": path.suffix.lower()[1:],
            "schema": {name: kind.__name__ for name, kind in schema.fields.items()},
            "declared": redact(declared),
        }
        return FixtureData(rows=tuple(parsed_rows), provenance=provenance)

    @staticmethod
    def _json_rows(rows: object, schema: FixtureSchema) -> list[dict[str, object]]:
        if not isinstance(rows, list) or not rows:
            raise FixtureError("fixture must contain at least one row")
        result: list[dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(schema.fields):
                raise FixtureError("fixture row fields do not match schema")
            if any(type(row[name]) is not kind for name, kind in schema.fields.items()):
                raise FixtureError("fixture value does not match schema")
            result.append(dict(row))
        return result

    @staticmethod
    def _csv_rows(text: str, schema: FixtureSchema) -> list[dict[str, object]]:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        fields = reader.fieldnames or []
        if len(fields) != len(set(fields)) or set(fields) != set(schema.fields):
            raise FixtureError("CSV columns do not match schema")
        rows = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise FixtureError("CSV row is incomplete")
            rows.append({name: _parse_csv_value(row[name], kind) for name, kind in schema.fields.items()})
        if not rows:
            raise FixtureError("fixture must contain at least one row")
        return rows
