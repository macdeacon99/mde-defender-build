"""
Loads Microsoft's published Defender-for-Endpoint macOS preference schema
(com.microsoft.wdav) and exposes a small, predictable model on top of it.

The schema itself is the source of truth for *what is configurable*. We never
hand-maintain the list of settings; we read Microsoft's schema.json and walk it.
Refresh it any time with:  python mde_builder.py --refresh-schema
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_URL = (
    "https://raw.githubusercontent.com/microsoft/mdatp-xplat/master/macos/schema/schema.json"
)
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "data" / "schema.json"


def refresh_schema(path: Path = DEFAULT_SCHEMA_PATH) -> str:
    """Download the latest schema from Microsoft and cache it. Returns version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(SCHEMA_URL, timeout=30) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)  # validate it parses before writing
    path.write_text(raw, encoding="utf-8")
    return str(data.get("__version", "unknown"))


def load_schema(path: Path = DEFAULT_SCHEMA_PATH) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Schema not found at {path}. Run with --refresh-schema while online."
        )
    return json.loads(path.read_text(encoding="utf-8"))


# --- node model ------------------------------------------------------------

OBJECT = "object"
SCALAR_TYPES = {"boolean", "string", "integer", "number"}


def node_kind(node: dict[str, Any]) -> str:
    """Classify a JSON-schema node into object / array / scalar type."""
    t = node.get("type")
    if t == "array":
        return "array"
    if t in SCALAR_TYPES:
        return t
    if "properties" in node:
        return OBJECT
    # Microsoft's top-level sections omit "type" but carry "properties".
    return t or "unknown"


@dataclass
class Setting:
    """A single configurable leaf (scalar) within the schema."""

    path: list[str]  # e.g. ["antivirusEngine", "enableRealTimeProtection"]
    kind: str  # boolean | string | integer | number
    title: str
    description: str
    default: Any = None
    enum: list[str] | None = None
    enum_titles: list[str] | None = None

    @property
    def dotted(self) -> str:
        return ".".join(self.path)

    @property
    def section(self) -> str:
        return self.path[0]


@dataclass
class ArraySetting:
    """A list-valued setting (exclusions, tags, threatTypeSettings, ...)."""

    path: list[str]
    title: str
    description: str
    item_kind: str  # "string" or "object"
    item_properties: dict[str, Any] = field(default_factory=dict)

    @property
    def dotted(self) -> str:
        return ".".join(self.path)

    @property
    def section(self) -> str:
        return self.path[0]


class SchemaModel:
    """Convenience wrapper around the loaded schema."""

    def __init__(self, schema: dict[str, Any]):
        self.raw = schema
        self.version = str(schema.get("__version", "unknown"))
        self.sections: list[str] = list(schema.get("properties", {}).keys())

    def section_node(self, section: str) -> dict[str, Any]:
        return self.raw["properties"][section]

    def settings_for(self, section: str) -> list[Setting | ArraySetting]:
        """Flatten a section into its configurable settings, in schema order."""
        out: list[Setting | ArraySetting] = []
        self._walk(self.section_node(section), [section], out)
        return out

    def _walk(self, node: dict[str, Any], path: list[str], out: list) -> None:
        kind = node_kind(node)
        if kind == OBJECT:
            props = node.get("properties", {})
            ordered = sorted(props.items(), key=lambda kv: kv[1].get("propertyOrder", 1_000_000))
            for name, child in ordered:
                self._walk(child, path + [name], out)
        elif kind == "array":
            items = node.get("items", {})
            ik = node_kind(items)
            out.append(
                ArraySetting(
                    path=path,
                    title=node.get("title", path[-1]),
                    description=node.get("description", ""),
                    item_kind="object" if ik == OBJECT else "string",
                    item_properties=items.get("properties", {}) if ik == OBJECT else {},
                )
            )
        else:
            opts = node.get("options", {}) or {}
            out.append(
                Setting(
                    path=path,
                    kind=kind,
                    title=node.get("title", path[-1]),
                    description=node.get("description", ""),
                    default=node.get("default"),
                    enum=node.get("enum"),
                    enum_titles=opts.get("enum_titles"),
                )
            )

    def section_title(self, section: str) -> str:
        return self.section_node(section).get("title", section)
