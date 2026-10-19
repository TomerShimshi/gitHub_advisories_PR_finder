import pytest

from advisory_tracer.diffs import (
    is_auxiliary,
    parse_patch,
    quote_in_added_lines,
    touched_lines,
)

PATCH = """@@ -10,5 +10,6 @@ def load(path):
     base = get_base()
-    full = base + path
-    return open(full)
+    full = safe_join(base, path)
+    check(full)
+    return open(full)

@@ -40,3 +41,5 @@ def other():
     a = 1
+    if not allowed(a):
+        raise PermissionError
     b = 2
     c = 3"""


def test_parse_patch_tracks_old_and_new_line_numbers() -> None:
    hunks = parse_patch(PATCH)

    assert [(h.old_start, h.new_start) for h in hunks] == [(10, 10), (40, 41)]
    removed = [(o, t.strip()) for k, o, _, t in hunks[0].lines if k == "-"]
    assert removed == [(11, "full = base + path"), (12, "return open(full)")]
    added = [n for k, _, n, _ in hunks[1].lines if k == "+"]
    assert added == [42, 43]


def test_touched_lines_removed_and_context_for_missing_checks() -> None:
    lines = touched_lines([{"filename": "pkg/loader.py", "status": "modified", "patch": PATCH}])

    removed = [(t.old_line, t.kind) for t in lines if t.kind == "removed"]
    context = [(t.old_line, t.text.strip()) for t in lines if t.kind == "context"]
    assert removed == [(11, "removed"), (12, "removed")]
    # The second hunk only adds a check: the surrounding old code is what lacked it.
    assert context == [(40, "a = 1"), (41, "b = 2"), (42, "c = 3")]


def test_touched_lines_skips_tests_new_files_and_import_only_hunks() -> None:
    imports_only = "@@ -1,2 +1,3 @@\n import os\n+from collections import deque\n import re"
    files = [
        {"filename": "tests/test_loader.py", "status": "modified", "patch": PATCH},
        {"filename": "pkg/new.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1"},
        {"filename": "pkg/a.py", "status": "modified", "patch": imports_only},
        {"filename": "pkg/big.bin", "status": "modified"},  # No patch.
    ]

    assert touched_lines(files) == []


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_x.py", True),
        ("src/pkg/test_x.py", True),
        ("web/src/app.spec.ts", True),
        ("docs/index.rst", True),
        ("CHANGELOG.md", True),
        ("uv.lock", True),
        ("src/pkg/loader.py", False),
        ("src/pkg/latest.py", False),
    ],
)
def test_is_auxiliary(path: str, expected: bool) -> None:
    assert is_auxiliary(path) is expected


@pytest.mark.parametrize(
    "quote",
    [
        "full = safe_join(base, path)",
        "+    full = safe_join(base, path)",
        "L11: full = safe_join(base, path)",
        "pkg/loader.py:11:   full = safe_join(base, path)\n   check(full)",
        "  if not allowed(a):\n      raise PermissionError",
    ],
)
def test_quote_found_in_added_lines(quote: str) -> None:
    files = [{"filename": "pkg/loader.py", "patch": PATCH}]

    assert quote_in_added_lines(files, quote)
    assert quote_in_added_lines(files, quote, path="pkg/loader.py")


@pytest.mark.parametrize(
    "quote",
    [
        "full = base + path",  # Removed, not added.
        "full = safe_join(base, path)\nreturn eval(full)",  # Second line is made up.
        "",
    ],
)
def test_quote_not_found(quote: str) -> None:
    files = [{"filename": "pkg/loader.py", "patch": PATCH}]

    assert not quote_in_added_lines(files, quote)


def test_quote_in_wrong_file_is_rejected() -> None:
    files = [{"filename": "pkg/loader.py", "patch": PATCH}]

    assert not quote_in_added_lines(files, "check(full)", path="pkg/other.py")
