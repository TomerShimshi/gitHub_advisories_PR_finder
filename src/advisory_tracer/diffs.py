"""Parse GitHub unified-diff patches: hunks, the lines a fix touched, and quote checks."""

import re
from dataclasses import dataclass, field
from typing import Any, Literal

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Files whose changes don't carry the vulnerable code itself.
_AUXILIARY_RE = re.compile(
    r"(^|/)(tests?|testing|docs?|examples?|\.github|changelog\.d|news)/"
    r"|(^|/)test_[^/]*$|_tests?\.[a-z]+$|\.test\.[a-z]+$|\.spec\.[a-z]+$"
    r"|(^|/)(CHANGELOG|CHANGES|HISTORY|NEWS|RELEASE[-_]?NOTES)[^/]*$"
    r"|\.(md|rst|txt|lock)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|uv\.lock)$",
    re.IGNORECASE,
)
# Prefixes models add when quoting code: "L75:", "75 |", "+", "path.py:75:".
_QUOTE_PREFIX_RE = re.compile(r"^\s*(?:[\w./-]+\.\w+:\d+:?|L\d+\s*[:|]?|\d+\s*[:|])?\s*[+-]?")
# Added lines that don't change behaviour on their own (imports, blank lines, comments). A hunk
# adding only these isn't "a missing check", so its context isn't vulnerable code.
_TRIVIAL_ADDITION_RE = re.compile(
    r"^\s*($|#|//|/\*|\*|import\s|from\s+\S+\s+import\s|#include\s|using\s|use\s|require\(|"
    r"const\s+\w+\s*=\s*require\(|package\s)"
)
# Context lines kept around a hunk that only adds lines (a missing check).
_CONTEXT_FOR_ADDITIONS = 3


@dataclass
class Hunk:
    old_start: int
    new_start: int
    # (kind, old_line, new_line, text); kind is " ", "-" or "+". The absent side is None.
    lines: list[tuple[str, int | None, int | None, str]] = field(default_factory=list)


@dataclass
class TouchedLine:
    path: str
    old_line: int  # Line number in the parent (pre-fix) version of the file.
    text: str
    kind: Literal["removed", "context"]  # context = next to lines a fix only added


def is_auxiliary(path: str) -> bool:
    """Tests, docs, changelogs and lockfiles: listed, but not where vulnerable code lives."""
    return bool(_AUXILIARY_RE.search(path))


def parse_patch(patch: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    current: Hunk | None = None
    old = new = 0
    for raw in patch.splitlines():
        if match := _HUNK_RE.match(raw):
            old, new = int(match[1]), int(match[3])
            current = Hunk(old_start=old, new_start=new)
            hunks.append(current)
            continue
        if current is None or raw.startswith("\\"):  # "\ No newline at end of file"
            continue
        kind, text = (raw[:1] or " "), raw[1:]
        if kind == "-":
            current.lines.append(("-", old, None, text))
            old += 1
        elif kind == "+":
            current.lines.append(("+", None, new, text))
            new += 1
        else:
            current.lines.append((" ", old, new, text))
            old += 1
            new += 1
    return hunks


def touched_lines(files: list[dict[str, Any]]) -> list[TouchedLine]:
    """Lines of the pre-fix code that a fix changed: removed lines, plus the context around
    hunks that only add lines (the code that lacked a check). Auxiliary files are skipped."""
    result: list[TouchedLine] = []
    for f in files:
        path, patch = f.get("filename", ""), f.get("patch")
        if not patch or is_auxiliary(path) or f.get("status") == "added":
            continue
        for hunk in parse_patch(patch):
            removed = [(o, t) for k, o, _, t in hunk.lines if k == "-" and o is not None]
            if removed:
                result.extend(TouchedLine(path, o, t, "removed") for o, t in removed)
                continue
            if all(_TRIVIAL_ADDITION_RE.match(t) for k, _, _, t in hunk.lines if k == "+"):
                continue
            result.extend(
                TouchedLine(path, o, t, "context")
                for o, t in _context_around_additions(hunk)
                if t.strip()
            )
    return result


def _context_around_additions(hunk: Hunk) -> list[tuple[int, str]]:
    """Old-side context lines just before and after each run of added lines."""
    keep: dict[int, str] = {}
    lines = hunk.lines
    for i, (kind, _, _, _) in enumerate(lines):
        if kind != "+":
            continue
        start, stop = max(0, i - _CONTEXT_FOR_ADDITIONS), i + 1 + _CONTEXT_FOR_ADDITIONS
        for k, o, _, t in lines[start:stop]:
            if k == " " and o is not None:
                keep[o] = t
    return sorted(keep.items())


def added_lines(files: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Per file, the text of every line a commit added (for checking quoted code)."""
    result: dict[str, list[str]] = {}
    for f in files:
        if f.get("patch"):
            result[f["filename"]] = [
                t for hunk in parse_patch(f["patch"]) for k, _, _, t in hunk.lines if k == "+"
            ]
    return result


def quote_in_added_lines(files: list[dict[str, Any]], quote: str, path: str | None = None) -> bool:
    """True if every non-blank line of `quote` was added by this commit (whitespace-insensitive),
    in `path` if given. Used to reject reasoning that quotes code the commit didn't write."""
    wanted = [_norm(_QUOTE_PREFIX_RE.sub("", line)) for line in quote.splitlines()]
    wanted = [w for w in wanted if w]
    if not wanted:
        return False
    for name, lines in added_lines(files).items():
        if path and name != path:
            continue
        available = {_norm(line) for line in lines}
        if all(w in available for w in wanted):
            return True
    return False


def _norm(line: str) -> str:
    return " ".join(line.split())
