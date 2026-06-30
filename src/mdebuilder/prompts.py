"""
Thin prompt layer. Uses `questionary` for a nice arrow-key TUI when available,
and falls back to plain stdlib input() so the tool still runs on a locked-down
box with nothing pip-installed. This is what keeps it "runs anywhere".
"""

from __future__ import annotations

from typing import Any

try:  # pragma: no cover - presence depends on environment
    import questionary

    _HAVE_Q = True
except Exception:  # noqa: BLE001
    questionary = None
    _HAVE_Q = False


def have_questionary() -> bool:
    return _HAVE_Q


def confirm(message: str, default: bool = False) -> bool:
    if _HAVE_Q:
        return bool(questionary.confirm(message, default=default).ask())
    suffix = " [Y/n] " if default else " [y/N] "
    ans = input(message + suffix).strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def select(message: str, choices: list[str], default: str | None = None) -> str:
    if _HAVE_Q:
        return questionary.select(message, choices=choices, default=default).ask()
    print(message)
    for i, c in enumerate(choices, 1):
        marker = " (default)" if c == default else ""
        print(f"  {i}) {c}{marker}")
    while True:
        raw = input("Choose number: ").strip()
        if not raw and default is not None:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        print("  Invalid choice.")


def checkbox(message: str, choices: list[str], preselected: list[str] | None = None) -> list[str]:
    preselected = preselected or []
    if _HAVE_Q:
        qs = [questionary.Choice(c, checked=(c in preselected)) for c in choices]
        return questionary.checkbox(message, choices=qs).ask() or []
    print(message + "  (comma-separated numbers, blank = none)")
    for i, c in enumerate(choices, 1):
        mark = "*" if c in preselected else " "
        print(f"  [{mark}] {i}) {c}")
    raw = input("Select: ").strip()
    if not raw:
        return list(preselected)
    picked = []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit() and 1 <= int(tok) <= len(choices):
            picked.append(choices[int(tok) - 1])
    return picked


def text(message: str, default: str = "") -> str:
    if _HAVE_Q:
        return questionary.text(message, default=default).ask() or default
    suffix = f" [{default}] " if default else " "
    ans = input(message + suffix).strip()
    return ans or default


def ask_value(setting) -> Any:
    """Prompt for one scalar Setting, honouring its type / enum / default."""
    label = f"{setting.title}  ({setting.dotted})"
    if setting.description:
        print(f"    \u2139  {setting.description}")

    if setting.enum:
        choices = list(setting.enum)
        # show friendlier titles if the schema provides them
        if setting.enum_titles and len(setting.enum_titles) == len(choices):
            display = [f"{v}  \u2014 {t}" for v, t in zip(choices, setting.enum_titles)]
            chosen = select(label, display, default=None)
            return choices[display.index(chosen)]
        return select(label, choices, default=str(setting.default) if setting.default else None)

    if setting.kind == "boolean":
        return confirm(label, default=bool(setting.default))

    if setting.kind in ("integer", "number"):
        raw = text(label, default=str(setting.default if setting.default is not None else ""))
        try:
            return int(raw) if setting.kind == "integer" or float(raw).is_integer() else float(raw)
        except (ValueError, AttributeError):
            return setting.default

    # string
    return text(label, default=str(setting.default) if setting.default is not None else "")
