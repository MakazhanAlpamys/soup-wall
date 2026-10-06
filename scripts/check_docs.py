# SPDX-License-Identifier: Apache-2.0
"""Check repository-local documentation links without dependencies or network access.

Supported subset: inline Markdown links/images (including nested image links,
quoted/parenthesized titles and angle-bracket destinations), HTML img src, and
ATX heading fragments with duplicate slug suffixes. Fenced and inline code are
excluded. Reference links, arbitrary HTML, setext headings, explicit HTML anchors
and fragments in non-Markdown files are outside this check's scope.

Git-tracked Markdown and nonignored local Markdown additions are scanned. Link
targets must be tracked: stage newly linked files before running this checker.
"""

import argparse
import html
from html.parser import HTMLParser
from pathlib import Path
import posixpath
import re
import stat
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*)|[ \t]*)$")
INLINE_CODE = re.compile(r"(`+)(.*?)(?<!`)\1(?!`)")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class ImageSources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []

    def handle_starttag(self, tag, attributes):
        if tag == "img":
            for name, value in attributes:
                if name == "src" and value is not None:
                    self.targets.append(value)
                    break


def git(root, *arguments):
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True
    ).stdout


def safe_path(root, relative):
    """Do not follow a tracked pathname replaced by a symlink or Windows junction."""
    path = root
    for part in Path(relative).parts:
        path = path / part
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise ValueError("symlink or reparse path is unsupported")
    return path


def markdown_lines(text):
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
            continue
        if match:
            fence = match[1]
            continue
        yield number, line


def heading_anchors(lines):
    anchors = set()
    for _, line in lines:
        match = HEADING.match(line)
        if not match:
            continue
        title = re.sub(r"[ \t]+#+[ \t]*$", "", match[1] or "")
        title = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", title)
        title = html.unescape(re.sub(r"<[^>]*>", "", title)).lower()
        slug = "".join(
            character for character in title
            if character in "_- " or unicodedata.category(character)[0] not in "PS"
        ).replace(" ", "-")
        anchor, suffix = slug, 0
        while anchor in anchors:
            suffix += 1
            anchor = f"{slug}-{suffix}"
        anchors.add(anchor)
    return anchors


def destination(text, start):
    """Read one inline destination and optional title, retaining nested parentheses."""
    position = start
    while position < len(text) and text[position].isspace():
        position += 1
    if position < len(text) and text[position] == "<":
        end = text.find(">", position + 1)
        if end == -1:
            return None
        target, position = text[position + 1:end], end + 1
    else:
        beginning, depth = position, 0
        while position < len(text):
            character = text[position]
            if character == "\\":
                position += 2
                continue
            if character == ")" and depth == 0 or character.isspace():
                break
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            position += 1
        target = text[beginning:position]
    while position < len(text) and text[position].isspace():
        position += 1
    if position < len(text) and text[position] in "\"'(":
        closing = ")" if text[position] == "(" else text[position]
        position += 1
        while position < len(text) and text[position] != closing:
            position += 2 if text[position] == "\\" else 1
        position += 1
        while position < len(text) and text[position].isspace():
            position += 1
    if position >= len(text) or text[position] != ")":
        return None
    return re.sub(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])", r"\1", target), position + 1


def link_destinations(line):
    line = INLINE_CODE.sub(lambda match: " " * len(match[0]), line)
    position, brackets = 0, 0
    while position < len(line):
        character = line[position]
        if character == "\\":
            position += 2
            continue
        if character == "[":
            brackets += 1
        elif character == "]" and brackets:
            brackets -= 1
            if position + 1 < len(line) and line[position + 1] == "(":
                result = destination(line, position + 2)
                if result:
                    target, position = result
                    yield target
                    continue
        position += 1
    images = ImageSources()
    images.feed(line)
    yield from images.targets


def check(root, tracked, sources):
    documents, problems = {}, []
    for source in sources:
        try:
            documents[source] = list(markdown_lines(safe_path(root, source).read_text(encoding="utf-8")))
        except (OSError, UnicodeError, ValueError) as error:
            problems.append((source, 1, f"cannot read Markdown: {error}"))
    anchors = {source: heading_anchors(lines) for source, lines in documents.items()}
    count = 0
    for source, lines in documents.items():
        for number, line in lines:
            for original in link_destinations(line):
                if SCHEME.match(original) or original.startswith("//"):
                    continue
                count += 1
                try:
                    parts = urlsplit(original)
                    decoded = unquote(parts.path).replace("\\", "/")
                    if decoded.startswith("/") or re.match(r"^[A-Za-z]:", decoded):
                        raise ValueError("outside repository")
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(source), decoded)) if decoded else source
                    if target == ".." or target.startswith("../"):
                        raise ValueError("outside repository")
                    path = safe_path(root, target)
                    if not path.exists():
                        raise ValueError("missing file")
                    if path.is_dir():
                        descendants = (name for name in tracked if target == "." or name.startswith(target + "/"))
                        if not any(safe_path(root, name).is_file() for name in descendants):
                            raise ValueError("directory has no Git-tracked files")
                    elif target not in tracked:
                        raise ValueError("target is not Git-tracked")
                    elif parts.fragment and path.suffix.lower() == ".md":
                        if unquote(parts.fragment) not in anchors.get(target, set()):
                            raise ValueError("missing heading")
                except (OSError, ValueError) as error:
                    problems.append((source, number, f"{original}: {error}"))
    return count, sorted(problems)


def main():
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode("utf-8").strip())
        tracked = set(git(root, "ls-files", "--cached", "-z").decode("utf-8").split("\0")) - {""}
        additions = set(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode("utf-8").split("\0")) - {""}
        sources = sorted(name for name in tracked | additions if Path(name).suffix.lower() == ".md")
        count, problems = check(root, tracked, sources)
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        print(f"Documentation check could not inspect the Git repository: {type(error).__name__}", file=sys.stderr)
        return 2
    for source, number, message in problems:
        print(f"{source}:{number}: {message}")
    print(f"Checked {len(sources)} Markdown files and {count} local links; {len(problems)} errors.")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
