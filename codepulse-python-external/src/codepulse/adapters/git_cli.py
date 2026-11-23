"""SourcePort over the git CLI. Read-only: only diff, ls-files, show, and rev-parse are run."""

import re
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from codepulse.core.errors import SourceError, SourceReadError
from codepulse.core.ports import ChangedFile, LineRange

GIT_TIMEOUT_S = 60
# -U0 hunk header; only the new-side start/count matter for attribution.
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
# Stable, machine-readable output regardless of the user's git config.
_BASE_ARGS = ("-c", "core.quotepath=off", "--no-pager")


_C_ESCAPE = re.compile(r'\\([0-7]{3}|[abtnvfr"\\])')
_C_SIMPLE = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _diff_path(raw: str) -> str | None:
    """Path from a ``+++`` header: strips git's trailing tab (added for names with
    spaces) and undoes C-quoting (names with quotes, tabs, newlines, or control bytes)."""
    raw = raw.removesuffix("\t")
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        quoted, out, pos = raw[1:-1], bytearray(), 0
        # Octal escapes are UTF-8 bytes, so decode only after reassembling the byte string.
        for m in _C_ESCAPE.finditer(quoted):
            out += quoted[pos : m.start()].encode("utf-8")
            out.append(int(m[1], 8) if len(m[1]) == 3 else _C_SIMPLE[m[1]])
            pos = m.end()
        out += quoted[pos:].encode("utf-8")
        raw = out.decode("utf-8", "surrogateescape")
    return raw[2:] if raw.startswith("b/") else None


def parse_hunks(diff: str) -> dict[str, tuple[LineRange, ...]]:
    """New-side line ranges per file from ``git diff -U0`` output."""
    out: dict[str, list[LineRange]] = {}
    current: list[LineRange] | None = None
    in_header = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_header, current = True, None
        elif in_header and line.startswith("+++ "):
            in_header = False
            path = _diff_path(line[4:])
            current = None if path is None else out.setdefault(path, [])
        elif current is not None and (m := _HUNK.match(line)):
            start, count = int(m[1]), int(m[2] or 1)
            if count:  # count 0 is a pure deletion: no new lines to attribute
                current.append((start, start + count - 1))
    return {path: tuple(ranges) for path, ranges in out.items()}


class GitCliSource:
    def __init__(self, repo_root: Path, git_binary: str | None = None) -> None:
        self._root = repo_root.resolve()
        binary = git_binary or shutil.which("git")
        if binary is None:
            raise SourceError("git executable not found on PATH")
        self._git = binary

    def _run(self, *args: str) -> str:
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, shell=False, refs validated first
                [self._git, *_BASE_ARGS, *args],
                cwd=self._root,
                capture_output=True,
                timeout=GIT_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SourceError(f"git {args[0]} timed out after {GIT_TIMEOUT_S}s") from None
        except OSError as exc:
            raise SourceError(f"cannot run git: {exc.strerror}") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise SourceError(f"git {args[0]} failed in {self._root}: {err}")
        return proc.stdout.decode("utf-8", "surrogateescape")

    def _verify_ref(self, ref: str) -> None:
        # A leading dash would be parsed as an option, whatever position it sits in.
        if not ref or ref.startswith("-"):
            raise SourceError(f"invalid ref {ref!r}")
        try:
            self._run("rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
        except SourceError:
            raise SourceError(f"unknown ref {ref!r} in {self._root}") from None

    def commit_of(self, ref: str) -> str | None:
        """Commit SHA for the run envelope; None outside a git repo or for unknown refs."""
        try:
            self._verify_ref(ref)
            return self._run(
                "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"
            ).strip()
        except SourceError:
            return None

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        self._verify_ref(base)
        self._verify_ref(head)
        span = f"{base}...{head}"  # three-dot: head's changes since the merge-base (D1)
        diff_args = ("--no-color", "--no-ext-diff", "--no-textconv", "--diff-filter=ACMR")
        names = self._run("diff", *diff_args, "--name-only", "-z", span, "--")
        hunks = parse_hunks(self._run("diff", *diff_args, "-U0", span, "--"))
        return [ChangedFile(p, hunks.get(p, ())) for p in sorted(filter(None, names.split("\0")))]

    def tracked_files(self, ref: str | None = None) -> Sequence[str]:
        args = ("ls-tree", "-r", "--name-only", "-z", ref) if ref else ("ls-files", "-z")
        return sorted(filter(None, self._run(*args).split("\0")))

    def read_text(self, path: str, ref: str | None) -> str:
        full = (self._root / path).resolve()
        if not full.is_relative_to(self._root):
            raise SourceReadError(f"{path}: resolves outside the repository root")
        if ref is None:
            try:
                data = full.read_bytes()
            except OSError as exc:
                raise SourceReadError(f"{path}: {exc.strerror}") from exc
        else:
            self._verify_ref(ref)
            try:
                data = self._run("show", f"{ref}:{path}").encode("utf-8", "surrogateescape")
            except SourceError as exc:
                raise SourceReadError(f"{path}@{ref}: not found") from exc
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise SourceReadError(f"{path}: not valid UTF-8") from None
