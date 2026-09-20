"""Extract mechanically checkable claims from a vulnerability report.

The report is untrusted free-form text (markdown, email, plain text).
This module never touches the repository; it only decides *what the
report asserts*. Extraction is deliberately conservative: a borderline
token is dropped rather than risk grading prose as if it were a code
citation. The failure mode we optimize against is a false NOT FOUND on
something that was never a claim in the first place.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .claims import Claim, ClaimType
from .stopwords import is_stopword

# --------------------------------------------------------------------------
# regexes
# --------------------------------------------------------------------------

SOURCE_EXTS = (
    "c|h|cc|cpp|cxx|hpp|hh|hxx|py|pyi|rs|go|js|jsx|ts|tsx|mjs|cjs|java|rb|"
    "php|swift|kt|kts|scala|zig|lua|pl|pm|sh|bash|zsh|ps1|bat|sql|proto|m|"
    "mm|cs|fs|ml|mli|ex|exs|erl|hrl|clj|cljs|hs|elm|dart|r|jl|nim|sv|vhd|"
    "asm|s|S|md|rst|txt|toml|yaml|yml|json|xml|html|css|scss|vue|svelte|"
    "cfg|ini|conf|cmake|mk|gradle|properties|tf|gemspec|podspec|ac|am|m4|in"
)

FILE_RE = re.compile(
    r"(?<![\w/@.-])"
    # A path may not begin with '-': such a string is a command-line
    # option, not a file a report is citing, and it must never reach the
    # git layer as a pathspec.
    r"((?:[A-Za-z0-9_.+][A-Za-z0-9_.+-]*/)*[A-Za-z0-9_.+][A-Za-z0-9_.+-]*"
    r"\.(?:%s))" % SOURCE_EXTS
    # An optional position: ":42", ":42-60", ":42:8" (line:column), or
    # GitHub's permalink form "#L42" / "#L42-L60". A cited range whose
    # end lies past the file is a checkable error, and dropping the end
    # silently graded "src/http.c:1-9000" on line 1 alone.
    + r"(?::(\d+)(?:-(\d+))?(?::\d+)?|\#[Ll](\d+)(?:-[Ll]?(\d+))?)?"
    + r"(?!\.?\w)"
)

#: ``./lib/http.c`` names the same file as ``lib/http.c``, and that prefix
#: is the only decoration a citation carries. Stripping it with
#: ``lstrip("./")`` removed a character *set* instead: it turned
#: ``.github/workflows/ci.yml`` into a path no tree has ever contained, and
#: quietly rebased ``../src/http.c`` onto the repository root.
LEADING_DOT_SLASH_RE = re.compile(r"^(?:\./)+")

#: Famous "X.js"-style product names that read as file paths in prose.
PRODUCT_FILE_NAMES = frozenset(
    {
        "node.js", "vue.js", "react.js", "angular.js", "next.js", "nuxt.js",
        "express.js", "three.js", "d3.js", "chart.js", "moment.js",
        "backbone.js", "ember.js", "nest.js", "deno.js", "p5.js",
    }
)

URL_RE = re.compile(r"(?:https?|ftp)://\S+")

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

COMMIT_CONTEXT_RE = re.compile(r"\bcommits?\s+`?([0-9a-f]{7,40})\b", re.IGNORECASE)
COMMIT_BARE_RE = re.compile(r"\b([0-9a-f]{40})\b")

#: A word that says a nearby hex span is a revision rather than a number.
COMMIT_WORD_RE = re.compile(
    r"\b(?:commits?|sha1?s?|revs?|revisions?|hash(?:es)?)\b", re.IGNORECASE
)
#: How much text either side of a span still counts as "near" it.
COMMIT_CONTEXT_CHARS = 48

INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")

IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
PAREN_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,78}(?:::[A-Za-z_][A-Za-z0-9_]{0,78}){0,4})\(")
SNAKE2_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+){2,})\b")
FUNC_CONTEXT_RE = re.compile(
    r"\b(?:function|method|routine|handler|api)\s+[`\"']?"
    r"([A-Za-z_][A-Za-z0-9_.]{0,78}(?:::[A-Za-z_][A-Za-z0-9_.]{0,78}){0,4})"
    r"[`\"']?",
    re.IGNORECASE,
)

#: "`foo()` in `lib/bar.c`" - the report attributes a symbol to a file.
#: Checking the pair together catches a real function name cited in a file
#: it does not live in, which grading them separately would miss.
ATTRIBUTION_RE = re.compile(
    r"[`\"']?\b([A-Za-z_][A-Za-z0-9_]{0,78}(?:::[A-Za-z_][A-Za-z0-9_]{0,78}){0,4})"
    r"\b(?:\s*\(\s*\))?[`\"']?"
    r"\s*(?:function\s+)?(?:is\s+)?(?:defined\s+|declared\s+|implemented\s+|"
    r"located\s+|found\s+)?(?:in|of|from|inside|within|at)\s+"
    r"(?:the\s+)?(?:file\s+)?[`\"']?"
    r"((?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\.(?:%s))\b" % SOURCE_EXTS,
)

VER = r"(\d+(?:\.\d+)+[a-z]?)"
#: Same pattern, named, for use alongside other named groups.
VER_NAMED = r"(?P<ver>\d+(?:\.\d+)+[a-z]?)"
VERSION_RANGE_RE = re.compile(
    r"(?:versions?\s+|v)%s\s*(?:through|to|until|up\s+to|-|–|—)\s*v?%s"
    % (VER, VER),
    re.IGNORECASE,
)
VERSION_BETWEEN_RE = re.compile(
    r"between\s+(?:versions?\s+)?v?%s\s+and\s+v?%s" % (VER, VER), re.IGNORECASE
)
VERSION_ROLE_RES: List[Tuple[str, re.Pattern]] = [
    (
        "introduced",
        re.compile(
            r"(?:introduced|added|appears?(?:\s+first)?)\s+in\s+(?:version\s+|v)?%s"
            % VER,
            re.IGNORECASE,
        ),
    ),
    (
        "introduced",
        re.compile(r"\bsince\s+(?:version\s+|v)?%s" % VER, re.IGNORECASE),
    ),
    (
        "fixed",
        re.compile(
            r"(?:fixed|patched|resolved|addressed)\s+in\s+(?:version\s+|v)?%s"
            % VER,
            re.IGNORECASE,
        ),
    ),
    (
        "affected",
        re.compile(
            r"(?:affects?|affecting|impacts?|present\s+in|prior\s+to|before|"
            r"tested\s+(?:on|against|with)|reproduced\s+(?:on|in|with)|"
            r"observed\s+in|as\s+of)\s+"
            # A product name before the number ("tested on Ubuntu 22.04")
            # is captured so the checker knows the version is not ours.
            r"(?P<product>[A-Za-z][A-Za-z0-9_.-]{0,20}\s+)?(?:version\s+|v)?%s"
            % VER_NAMED,
            re.IGNORECASE,
        ),
    ),
    (
        "affected",
        re.compile(r"\bversions?\s+v?%s" % VER, re.IGNORECASE),
    ),
]

FRAME_ASAN_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+([A-Za-z_][A-Za-z0-9_:.<>~]*)"
    r"(?:\s*\([^)]*\))?"
    r"(?:\s+(?:at\s+)?([^\s:()]+):(\d+)(?::\d+)?)?"
)
FRAME_GDB_RE = re.compile(
    r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([A-Za-z_][A-Za-z0-9_:.<>~]*)"
    r"\s*\([^)]*\)\s+at\s+([^\s:()]+):(\d+)"
)

#: CommonMark allows any info string after the opening fence
#: (```c title="x", ```{.c}), and a closing fence must be at least
#: as long as the opener and carry no info string. The pattern matches
#: the opener only; ``_fence_match`` checks the rest of the line.
FENCE_RE = re.compile(r"^(`{3,}|~{3,})[ \t]*(\S*)")

DIFF_FILE_RE = re.compile(r"^(?:\+\+\+|---)\s+(?:[ab]/)?(\S+)")

#: Prose markers (searched in the 3 lines above a code block) that say the
#: block quotes the project's source rather than reporter-supplied PoC code.
QUOTE_MARKERS_RE = re.compile(
    r"(?:vulnerable\s+(?:code|function|snippet)|relevant\s+(?:code|source|snippet)|"
    r"(?:code|snippet|excerpt|source|function|implementation|definition)\s+"
    r"(?:from|in|of|at)\b|from\s+the\s+(?:source|code(?:base)?|repo|repository|file|tree)|"
    r"the\s+(?:current\s+)?(?:implementation|definition|source)\b|"
    r"looks\s+like\s+this|is\s+(?:defined|implemented)\s+(?:in|as)|"
    r"as\s+(?:seen|shown|found)\s+in)\b",
    re.IGNORECASE,
)
POC_MARKERS_RE = re.compile(
    r"(?:\bpoc\b|proof.of.concept|exploit|payload|reproduc|"
    r"following\s+(?:script|program|python|code\s+to)|run\s+(?:the|this)|"
    r"save\s+(?:this|the\s+following)|trigger\s+(?:the|this)|patch\b|"
    r"suggested\s+fix|proposed\s+fix)",
    re.IGNORECASE,
)

CODE_LANGS = frozenset(
    {
        "c", "cpp", "c++", "h", "python", "py", "rust", "rs", "go", "golang",
        "javascript", "js", "typescript", "ts", "java", "ruby", "rb", "php",
        "swift", "kotlin", "scala", "zig", "lua", "perl", "haskell", "csharp",
        "cs", "objc", "objective-c", "sql", "html", "css", "xml", "json",
        "yaml", "toml",
    }
)
SHELL_LANGS = frozenset({"sh", "bash", "shell", "console", "zsh", "shell-session"})

MAX_QUOTE_LINES = 8
MIN_QUOTE_LINE_LEN = 12
MAX_CLAIMS = 200
#: Line numbers past this are not plausible source positions, and
#: Python refuses to int() a numeric string longer than 4300 digits.
MAX_LINE_DIGITS = 9
#: Prose lines longer than this are data (hex dumps, minified blobs,
#: base64), not citations, and scanning them only costs time.
MAX_PROSE_LINE = 2000

#: Claim types kept first when the budget bites: these are the ones
#: that require having read the code, and so the ones an attacker
#: most wants pushed off the end of the list.
_PRIORITY_TYPES = frozenset(
    {
        ClaimType.SYMBOL,
        ClaimType.STACK_FRAME,
        ClaimType.QUOTED_CODE,
        ClaimType.FILE_LINE,
    }
)


#: Words that can precede a version without naming a different product.
_VERSION_FILLER = frozenset(
    {
        "the", "a", "an", "on", "in", "at", "with", "against", "to", "of",
        "and", "or", "both", "all", "only", "up", "release", "releases",
        "version", "versions", "tag", "build", "branch", "it", "this",
        "that", "our", "your", "their", "its", "current", "latest",
        "stable", "master", "main", "from", "since", "before", "after",
        "using", "under", "than", "as", "is", "was", "are", "were",
    }
)


def _named_product(match: "re.Match") -> Optional[str]:
    """The product a version was attributed to, if it is not ours.

    "tested on Ubuntu 22.04" is a claim about Ubuntu, and checking it
    against this project's release tags would report a real environment
    note as a nonexistent version.
    """
    if "product" not in match.re.groupindex:
        return None
    raw = match.group("product")
    if not raw:
        return None
    word = raw.strip().strip(",;:").lower()
    if not word or word in _VERSION_FILLER:
        return None
    return raw.strip()


def _file_position(match: "re.Match") -> Tuple[Optional[int], Optional[int]]:
    """(start, end) line numbers from a FILE_RE match, either notation."""
    start = _safe_line(match.group(2)) or _safe_line(match.group(4))
    end = _safe_line(match.group(3)) or _safe_line(match.group(5))
    if start is not None and end is not None and end < start:
        end = None
    return start, end


def _line_claim(path: str, start: int, end: Optional[int]) -> Tuple[str, Dict[str, Any]]:
    """The claim value and payload for a cited line or line range."""
    extra: Dict[str, Any] = {"path": path, "line": start}
    if end is not None and end != start:
        extra["end_line"] = end
        return f"{path}:{start}-{end}", extra
    return f"{path}:{start}", extra


def _safe_line(text: Optional[str]) -> Optional[int]:
    """A report-supplied line number, or None if it is not one."""
    if not text or len(text) > MAX_LINE_DIGITS or not text.isdigit():
        return None
    value = int(text)
    return value if value > 0 else None


def _tree_relative_path(value: str) -> Optional[str]:
    """The path a citation names relative to the repository root, or None.

    None means the citation climbs above the root ("../src/http.c"): it
    is written relative to a directory the report never gave us, so the
    tree can neither confirm nor refute it. Dropping it is the only
    honest answer available here - rebasing it onto the root corroborates
    a path the repository does not have, and grading it against the root
    accuses the reporter of inventing one.
    """
    path = LEADING_DOT_SLASH_RE.sub("", value)
    if ".." in path.split("/"):
        return None
    return path


def _fence_match(line: str) -> Optional["re.Match"]:
    """The code fence opening *line*, or None if it does not open one.

    A backtick after the info string means the line is prose containing
    inline code, not a fence. That check lives here rather than in a
    trailing ``[^`]*$`` because the regex form backtracked quadratically:
    a single 100 KB line took ~23 seconds, and this pass runs before the
    MAX_PROSE_LINE guard that treats over-long lines as data.
    """
    m = FENCE_RE.match(line)
    if m is None or "`" in line[m.end():]:
        return None
    return m


def _mask(line: str, match: "re.Match") -> str:
    start, end = match.span()
    return line[:start] + " " * (end - start) + line[end:]


def _mask_all(line: str, pattern: re.Pattern) -> str:
    return pattern.sub(lambda m: " " * len(m.group(0)), line)


def _looks_like_identifier(token: str) -> bool:
    if len(token) < 4 or len(token) > 80:
        return False
    if is_stopword(token):
        return False
    has_underscore = "_" in token.strip("_")
    has_camel = bool(re.search(r"[a-z][A-Z]", token))
    has_scope = "::" in token
    return has_underscore or has_camel or has_scope


class _Block:
    def __init__(self, start_line: int, lang: str):
        self.start_line = start_line
        self.lang = lang.lower()
        self.lines: List[str] = []


def _classify_block(block: _Block) -> str:
    text = "\n".join(block.lines)
    nonempty = [l for l in block.lines if l.strip()]
    if not nonempty:
        return "empty"
    if any(
        FRAME_ASAN_RE.match(l) or FRAME_GDB_RE.match(l) for l in nonempty
    ) or "ERROR: AddressSanitizer" in text or "SUMMARY: AddressSanitizer" in text:
        return "trace"
    if nonempty[0].startswith("diff --git") or (
        any(l.startswith("+++ ") for l in nonempty)
        and any(l.startswith("@@") for l in nonempty)
    ):
        return "diff"
    if block.lang in SHELL_LANGS:
        return "shell"
    shellish = sum(1 for l in nonempty if l.lstrip().startswith(("$ ", "% ", "> ")))
    if shellish >= max(1, len(nonempty) // 3):
        return "shell"
    if block.lang in CODE_LANGS:
        return "code"
    codeish = sum(
        1 for l in nonempty if re.search(r"[;{}()=]|->|\breturn\b|\bif\b", l)
    )
    if codeish >= max(1, len(nonempty) // 2):
        return "code"
    return "output"


#: Line-number gutters that code viewers add when you copy from them:
#: "  142  code", "142: code", "142 | code", "142→code".
GUTTER_RE = re.compile(r"^\s*\d{1,6}\s*(?:[:|→\t]|(?=\s{2,}))\s*")


def _strip_gutter(line: str) -> str:
    """Remove a copied line-number prefix, if the block consistently has one.

    A reporter who copies from GitHub's blob view brings the line numbers
    along. Searching for "142  if (len > MAX)" finds nothing, and the
    report gets told it quotes code the project does not contain.
    """
    return GUTTER_RE.sub("", line, count=1)


def _quote_candidate_lines(lines: List[str]) -> List[str]:
    # Only strip gutters when most non-empty lines have one; otherwise a
    # legitimate line starting with a number would be mangled.
    nonempty = [l for l in lines if l.strip()]
    guttered = sum(1 for l in nonempty if GUTTER_RE.match(l))
    if nonempty and guttered >= max(2, int(len(nonempty) * 0.6)):
        lines = [_strip_gutter(l) for l in lines]

    candidates = []
    for raw in lines:
        stripped = raw.strip()
        if len(stripped) < MIN_QUOTE_LINE_LEN:
            continue
        if stripped.startswith(("//", "#", "*", "/*", "--", "'''", '"""')):
            continue
        if re.fullmatch(r"[{}()\[\];,\s]*", stripped):
            continue
        candidates.append(stripped)
    if len(candidates) <= MAX_QUOTE_LINES:
        return candidates
    # Sample for coverage, not for distinctiveness. Picking the longest
    # lines let an attacker paste a genuine excerpt with one short
    # fabricated line inserted - the payload line is exactly the one a
    # longest-first sample drops, and the block then scored 8/8.
    step = len(candidates) / MAX_QUOTE_LINES
    return [candidates[int(i * step)] for i in range(MAX_QUOTE_LINES)]


#: Filenames a reporter gives their own attachment. A block headed
#: "# poc.py" is the reporter's script, not a quote from the codebase.
POC_FILENAME_RE = re.compile(
    r"^(?:poc|pocs|exploit|repro|reproducer|reproduce|trigger|crash|test_?poc|"
    r"attack|payload|fuzz|harness|solve|pwn|demo)\b",
    re.IGNORECASE,
)


def _first_line_path_hint(block: _Block) -> Optional[str]:
    """A leading comment like ``// lib/http.c`` names the quoted file."""
    for raw in block.lines[:2]:
        stripped = raw.strip()
        if not stripped.startswith(("//", "#", "/*", "*", ";")):
            continue
        m = FILE_RE.search(stripped)
        if not m:
            continue
        path = m.group(1)
        if POC_FILENAME_RE.match(path.rsplit("/", 1)[-1]):
            return None
        return path
    return None


BLOCKQUOTE_RE = re.compile(r"^\s{0,3}(?:>\s?)+")


def _unwrap_blockquotes(lines: List[str]) -> Tuple[List[str], bool]:
    """Strip leading ``>`` markers so quoted reports parse normally.

    Maintainers receive reports as forwarded email and as markdown
    blockquotes; without this, a fenced code block inside the quote is
    invisible to the fence scanner and its contents get graded as prose.
    Line numbering is preserved so every claim still points at the right
    line of the original file.
    """
    quoted = sum(1 for l in lines if BLOCKQUOTE_RE.match(l) and l.strip() != ">")
    substantive = sum(1 for l in lines if l.strip())
    if not quoted or not substantive:
        return lines, False
    # Only unwrap when quoting is pervasive enough to be the report's own
    # formatting rather than an occasional inline citation.
    if quoted / substantive < 0.5:
        return lines, False
    return [BLOCKQUOTE_RE.sub("", l) for l in lines], True


def extract_claims(
    text: str, stats: Optional[Dict[str, Any]] = None
) -> Tuple[List[Claim], List[str]]:
    """Return (claims, notes) extracted from the report text.

    Pass a dict as *stats* to also receive coverage details, notably
    ``dropped``: claims the budget prevented us from checking. A
    caller that grades the report must not call it fully grounded
    while anything is in there.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    lines, unwrapped = _unwrap_blockquotes(lines)

    claims: List[Claim] = []
    notes: List[str] = []
    if unwrapped:
        notes.append(
            "the report is quoted text (email forward or markdown "
            "blockquote); quote markers were stripped before parsing."
        )

    # ---- pass 1: separate fenced code blocks from prose -------------------
    blocks: List[_Block] = []
    prose: List[Tuple[int, str]] = []  # (1-based line number, text)
    current: Optional[_Block] = None
    fence_marker = ""
    fence_len = 3
    block_quote_depth = 0
    for i, line in enumerate(lines, start=1):
        # A fence may sit behind a blockquote prefix even in reports that
        # are not pervasively quoted; look past the prefix to find it, and
        # remember the prefix so the block's own lines get unwrapped too.
        qm = BLOCKQUOTE_RE.match(line)
        depth = len(qm.group(0).replace(" ", "")) if qm else 0
        body = line[qm.end():] if qm else line
        fence = _fence_match(body.strip())

        if current is None and fence:
            fence_marker = fence.group(1)[0]
            fence_len = len(fence.group(1))
            block_quote_depth = depth
            current = _Block(i, fence.group(2))
            continue
        if (
            current is not None
            and fence
            and fence.group(1)[0] == fence_marker
            # CommonMark: the closer must be at least as long as the
            # opener, so a ``` inside a ```` block does not end it.
            and len(fence.group(1)) >= fence_len
            and not fence.group(2)
        ):
            blocks.append(current)
            current = None
            continue
        if current is not None:
            current.lines.append(body if block_quote_depth else line)
        else:
            prose.append((i, line))
    if current is not None:
        # Unterminated fence: treat its content as a block anyway.
        blocks.append(current)

    # Indented code blocks (4+ spaces) in otherwise plain reports are left
    # as prose on purpose: email quoting and lists look identical, and a
    # wrong guess would grade prose as code.

    def add(claim: Claim) -> None:
        claims.append(claim)

    # ---- pass 2: prose claims ---------------------------------------------
    long_lines = 0
    for lineno, raw in prose:
        if not raw.strip():
            continue
        if len(raw) > MAX_PROSE_LINE:
            long_lines += 1
            continue
        context = raw.strip()[:160]

        line = _mask_all(raw, URL_RE)

        # Symbol-to-file attributions are read first, off the unmasked
        # line, so both the inline-code pass and the prose pass below can
        # attach them: "`foo()` in `lib/bar.c`" is one claim, not two.
        attributed = {}
        for m in ATTRIBUTION_RE.finditer(line.replace("`", " ")):
            name, path = m.group(1), _tree_relative_path(m.group(2))
            if path is None or not _looks_like_identifier(name):
                continue
            if path.lower() in PRODUCT_FILE_NAMES:
                continue
            attributed[name] = path

        # Inline code spans next; their contents are deliberate citations.
        for m in INLINE_CODE_RE.finditer(line):
            span = m.group(1).strip()
            # The prose around a span is what tells a commit hash apart
            # from a fill pattern of the same shape.
            near_start = max(0, m.start() - COMMIT_CONTEXT_CHARS)
            near = line[near_start:m.end() + COMMIT_CONTEXT_CHARS]
            _extract_from_code_span(span, lineno, context, add, attributed, near)
        # Keep span text in place (minus backticks) so context patterns
        # like "affects `8.9.0`" still see the value.
        line = line.replace("`", " ")

        for m in CVE_RE.finditer(line):
            add(
                Claim(
                    ClaimType.CVE,
                    m.group(0).upper(),
                    lineno,
                    context,
                    "prose",
                    {"year": int(m.group(1))},
                )
            )
        line = _mask_all(line, CVE_RE)

        for m in COMMIT_CONTEXT_RE.finditer(line):
            add(Claim(ClaimType.COMMIT, m.group(1).lower(), lineno, context, "prose"))
        for m in COMMIT_BARE_RE.finditer(line):
            add(Claim(ClaimType.COMMIT, m.group(1).lower(), lineno, context, "prose"))
        line = _mask_all(line, COMMIT_BARE_RE)

        # Versions (before masking files: "curl-8.9.0.tar.gz" is unusual
        # enough to ignore).
        consumed_spans: List[Tuple[int, int]] = []
        for m in VERSION_RANGE_RE.finditer(line):
            add(
                Claim(
                    ClaimType.VERSION,
                    f"{m.group(1)} .. {m.group(2)}",
                    lineno,
                    context,
                    "prose",
                    {"role": "range", "start": m.group(1), "end": m.group(2)},
                )
            )
            consumed_spans.append(m.span())
        for m in VERSION_BETWEEN_RE.finditer(line):
            add(
                Claim(
                    ClaimType.VERSION,
                    f"{m.group(1)} .. {m.group(2)}",
                    lineno,
                    context,
                    "prose",
                    {"role": "range", "start": m.group(1), "end": m.group(2)},
                )
            )
            consumed_spans.append(m.span())

        def in_consumed(pos: int) -> bool:
            return any(s <= pos < e for s, e in consumed_spans)

        for role, pattern in VERSION_ROLE_RES:
            for m in pattern.finditer(line):
                if in_consumed(m.start("ver" if "ver" in m.re.groupindex else 1)):
                    continue
                version = (
                    m.group("ver")
                    if "ver" in m.re.groupindex
                    else m.group(1)
                )
                if not version:
                    continue
                extra = {"role": role}
                product = _named_product(m)
                if product:
                    extra["product"] = product
                add(
                    Claim(
                        ClaimType.VERSION,
                        version,
                        lineno,
                        context,
                        "prose",
                        extra,
                    )
                )
                consumed_spans.append(m.span())

        # Stack frames occasionally appear un-fenced in prose.
        fm = FRAME_ASAN_RE.match(raw) or FRAME_GDB_RE.match(raw)
        if fm:
            groups = fm.groups()
            func = groups[0]
            path = groups[1] if len(groups) > 1 else None
            ln = _safe_line(groups[2]) if len(groups) > 2 else None
            add(
                Claim(
                    ClaimType.STACK_FRAME,
                    func,
                    lineno,
                    context,
                    "prose",
                    {"function": func, "path": path, "line": ln},
                )
            )
            continue

        # File paths (with optional :line).
        for m in FILE_RE.finditer(line):
            path = _tree_relative_path(m.group(1))
            if path is None:
                continue
            for prefix in ("a/", "b/"):
                if path.startswith(prefix):
                    path = path[len(prefix):]
            if path.lower() in PRODUCT_FILE_NAMES:
                continue
            start, end = _file_position(m)
            if start is not None:
                value, payload = _line_claim(path, start, end)
                add(
                    Claim(
                        ClaimType.FILE_LINE, value, lineno, context,
                        "prose", payload,
                    )
                )
            else:
                add(
                    Claim(
                        ClaimType.FILE, path, lineno, context, "prose",
                        {"path": path},
                    )
                )
        line = _mask_all(line, FILE_RE)

        # Symbols: explicit call syntax, "function X" phrasing, or
        # unambiguous multi-underscore identifiers.
        seen_here = set()
        def add_symbol(name: str, style: str) -> None:
            extra = {"style": style}
            if name in attributed:
                extra["in_file"] = attributed[name]
            add(Claim(ClaimType.SYMBOL, name, lineno, context, "prose", extra))

        for m in PAREN_CALL_RE.finditer(line):
            name = m.group(1)
            if _looks_like_identifier(name) and name not in seen_here:
                seen_here.add(name)
                add_symbol(name, "call")
        for m in FUNC_CONTEXT_RE.finditer(line):
            name = m.group(1).rstrip(".")
            if _looks_like_identifier(name) and name not in seen_here:
                seen_here.add(name)
                add_symbol(name, "named")
        for m in SNAKE2_RE.finditer(line):
            name = m.group(1)
            if (
                name not in seen_here
                and not is_stopword(name)
                and len(name) >= 8
            ):
                seen_here.add(name)
                add_symbol(name, "bare")
        # A token the report itself places in a source file is a citation
        # by declaration, so it clears the bar that bare prose tokens must
        # meet ("checked_alloc is defined in lib/util.c").
        for name in attributed:
            if name not in seen_here:
                seen_here.add(name)
                add_symbol(name, "attributed")

    # ---- pass 3: code blocks ----------------------------------------------
    skipped_poc_blocks = 0
    for block in blocks:
        kind = _classify_block(block)
        context = f"code block at line {block.start_line}"

        if kind == "trace":
            for offset, raw in enumerate(block.lines):
                fm = FRAME_ASAN_RE.match(raw) or FRAME_GDB_RE.match(raw)
                if not fm:
                    continue
                groups = fm.groups()
                func = groups[0]
                path = groups[1] if len(groups) > 1 else None
                ln = _safe_line(groups[2]) if len(groups) > 2 else None
                if is_stopword(func):
                    continue
                add(
                    Claim(
                        ClaimType.STACK_FRAME,
                        func,
                        block.start_line + offset + 1,
                        raw.strip()[:160],
                        "code-block",
                        {"function": func, "path": path, "line": ln},
                    )
                )
            continue

        if kind == "diff":
            hint_path: Optional[str] = None
            removed_or_context: List[str] = []
            # A patch that creates a file has "--- /dev/null" as its
            # pre-image. Its post-image path is what the reporter proposes
            # to add, not a file they claim already exists, so it must not
            # be graded as a citation.
            creates_file = any(
                raw.startswith("--- ") and "/dev/null" in raw
                for raw in block.lines
            )
            for raw in block.lines:
                dm = DIFF_FILE_RE.match(raw)
                if dm and dm.group(1) not in ("/dev/null",):
                    path = dm.group(1)
                    hint_path = path
                    if not creates_file:
                        add(
                            Claim(
                                ClaimType.FILE, path, block.start_line,
                                context, "diff", {"path": path},
                            )
                        )
                elif raw.startswith("-") and not raw.startswith("---"):
                    removed_or_context.append(raw[1:])
                elif raw.startswith(" "):
                    removed_or_context.append(raw[1:])
            candidates = _quote_candidate_lines(removed_or_context)
            if candidates:
                add(
                    Claim(
                        ClaimType.QUOTED_CODE,
                        f"patch context ({len(candidates)} lines sampled)",
                        block.start_line,
                        context,
                        "diff",
                        {"lines": candidates, "hint_path": hint_path,
                         "origin": "patch"},
                    )
                )
            continue

        if kind != "code":
            continue

        # Only grade a code block against the tree when the report claims
        # it QUOTES the tree. A reporter's own PoC must never be graded.
        preceding = [
            t for (n, t) in prose if 0 <= block.start_line - n <= 3 and t.strip()
        ]
        preceding_text = " ".join(preceding[-3:])
        hint = _first_line_path_hint(block)
        says_poc = bool(POC_MARKERS_RE.search(preceding_text))
        says_quote = bool(QUOTE_MARKERS_RE.search(preceding_text))
        if says_poc and (says_quote or hint is not None):
            # The lead-in calls the block both things. Never grade it -
            # it may be the reporter's own code - but never silently drop
            # it either, or one incidental "patch" hides an invented
            # "vulnerable source" block from the dossier entirely.
            add(
                Claim(
                    ClaimType.QUOTED_CODE,
                    f"code block at line {block.start_line} (not graded)",
                    block.start_line,
                    preceding_text.strip()[:160] or context,
                    "code-block",
                    {"lines": [], "hint_path": hint, "origin": "ambiguous"},
                )
            )
            continue
        if says_poc:
            skipped_poc_blocks += 1
            continue
        if not says_quote and hint is None:
            skipped_poc_blocks += 1
            continue

        candidates = _quote_candidate_lines(block.lines)
        if not candidates:
            continue
        if hint is None:
            for n, t in reversed(prose):
                if n >= block.start_line:
                    continue
                if block.start_line - n > 3:
                    break
                fmatch = FILE_RE.search(_mask_all(t, URL_RE))
                if fmatch:
                    # A traversal path names no file we can grade, so the
                    # block keeps its "no hint" state rather than a wrong one.
                    hint = _tree_relative_path(fmatch.group(1))
                    break
        add(
            Claim(
                ClaimType.QUOTED_CODE,
                f"quoted source ({len(candidates)} lines sampled)",
                block.start_line,
                (preceding_text.strip() or context)[:160],
                "code-block",
                {"lines": candidates, "hint_path": hint, "origin": "quote"},
            )
        )

    if long_lines:
        notes.append(
            f"{long_lines} line(s) longer than {MAX_PROSE_LINE} characters "
            "were skipped as data rather than prose."
        )
    if skipped_poc_blocks:
        notes.append(
            f"{skipped_poc_blocks} code block(s) looked like reporter-supplied "
            "PoC/exploit code and were NOT graded against the tree."
        )

    # ---- pass 4: dedupe and prune -----------------------------------------
    claims = _dedupe(claims)
    claims, dropped = _apply_budget(claims)
    if dropped:
        summary = ", ".join(
            f"{count} {ctype.value}" for ctype, count in sorted(
                dropped.items(), key=lambda kv: -kv[1]
            )
        )
        notes.append(
            f"The report exceeded the {MAX_CLAIMS}-claim budget; "
            f"{sum(dropped.values())} claim(s) were not checked "
            f"({summary}). This dossier does not speak to them."
        )
    if stats is not None:
        stats["dropped"] = {c.value: n for c, n in dropped.items()}
    return claims, notes


def _apply_budget(claims: List[Claim]) -> Tuple[List[Claim], Dict[ClaimType, int]]:
    """Trim to the budget without discarding the evidence that matters.

    Truncating in document order was a complete bypass: prose is parsed
    before code blocks, so quoted code and trace frames always sat at the
    tail. Pasting a directory listing above them pushed every fabricated
    claim past the cap, and the report graded FULLY GROUNDED because the
    fabrications were deleted before anything looked at them.

    Claims that require having read the code are kept first; the cheap,
    numerous ones give up their slots.
    """
    if len(claims) <= MAX_CLAIMS:
        return claims, {}

    priority = [c for c in claims if c.type in _PRIORITY_TYPES]
    rest = [c for c in claims if c.type not in _PRIORITY_TYPES]

    priority_kept = priority[:MAX_CLAIMS]
    room = MAX_CLAIMS - len(priority_kept)
    rest_kept = rest[:room]
    kept = priority_kept + rest_kept

    dropped: Dict[ClaimType, int] = {}
    for claim in priority[len(priority_kept):] + rest[len(rest_kept):]:
        dropped[claim.type] = dropped.get(claim.type, 0) + 1

    # Restore document order among what survived.
    order = {id(c): i for i, c in enumerate(claims)}
    kept.sort(key=lambda c: order[id(c)])
    return kept, dropped


def _extract_from_code_span(
    span: str, lineno: int, context: str, add, attributed=None,
    near_text: str = "",
) -> None:
    """Claims from an inline `code span` - a deliberate citation."""
    attributed = attributed or {}

    def symbol_extra(name: str, style: str) -> Dict[str, Any]:
        extra: Dict[str, Any] = {"style": style}
        if name in attributed:
            extra["in_file"] = attributed[name]
        return extra

    if len(span) > 200:
        return
    fm = FILE_RE.fullmatch(span) or FILE_RE.fullmatch(span.rstrip("()"))
    if fm:
        path = _tree_relative_path(fm.group(1))
        if path is None or path.lower() in PRODUCT_FILE_NAMES:
            return
        span_start, span_end = _file_position(fm)
        if span_start is not None:
            value, payload = _line_claim(path, span_start, span_end)
            add(
                Claim(
                    ClaimType.FILE_LINE, value, lineno, context,
                    "inline-code", payload,
                )
            )
        else:
            add(
                Claim(
                    ClaimType.FILE, path, lineno, context, "inline-code",
                    {"path": path},
                )
            )
        return
    if CVE_RE.fullmatch(span):
        m = CVE_RE.fullmatch(span)
        add(
            Claim(
                ClaimType.CVE, span.upper(), lineno, context, "inline-code",
                {"year": int(m.group(1))},
            )
        )
        return
    if re.fullmatch(r"[0-9a-f]{7,40}", span):
        # Hex shape alone is not a commit citation: `41414141` is a fill
        # pattern, `16777216` is a size, and a 32-character span is as
        # likely the MD5 of the PoC attachment. Length and letters do not
        # separate them, so require the report to say what it is citing -
        # "no commit with this hash exists" is an accusation about a claim
        # the reporter never made.
        if COMMIT_WORD_RE.search(near_text):
            add(
                Claim(
                    ClaimType.COMMIT, span.lower(), lineno, context,
                    "inline-code",
                )
            )
        return
    if re.fullmatch(r"v?\d+(?:\.\d+)+[a-z]?", span):
        # A bare backticked version has no stated role; still checkable.
        add(
            Claim(
                ClaimType.VERSION, span.lstrip("v"), lineno, context,
                "inline-code", {"role": "mentioned"},
            )
        )
        return

    # Single identifier, possibly with call parens: `foo_bar()` / `Foo::bar`.
    single = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_:.]*[A-Za-z0-9_])\s*(?:\([^)]*\))?", span
    )
    if single:
        name = single.group(1)
        if _looks_like_identifier(name):
            add(
                Claim(
                    ClaimType.SYMBOL, name, lineno, context, "inline-code",
                    symbol_extra(name, "span"),
                )
            )
        return

    # Expression span: pull out the distinctive identifiers, capped.
    found = 0
    seen = set()
    for m in PAREN_CALL_RE.finditer(span):
        name = m.group(1)
        if name in seen or not _looks_like_identifier(name):
            continue
        seen.add(name)
        add(
            Claim(
                ClaimType.SYMBOL, name, lineno, context, "inline-code",
                symbol_extra(name, "span-call"),
            )
        )
        found += 1
        if found >= 3:
            return
    for m in SNAKE2_RE.finditer(span):
        name = m.group(1)
        if name in seen or is_stopword(name) or len(name) < 8:
            continue
        seen.add(name)
        add(
            Claim(
                ClaimType.SYMBOL, name, lineno, context, "inline-code",
                symbol_extra(name, "span-bare"),
            )
        )
        found += 1
        if found >= 3:
            return


def _dedupe(claims: List[Claim]) -> List[Claim]:
    out: List[Claim] = []
    seen: Dict[tuple, Claim] = {}
    for claim in claims:
        key = claim.key()
        if key in seen:
            continue
        seen[key] = claim
        out.append(claim)

    # A FILE claim is redundant when a FILE_LINE claim covers the same path.
    file_line_paths = {
        c.extra.get("path") for c in out if c.type is ClaimType.FILE_LINE
    }
    # A SYMBOL claim is redundant only when a stack frame will actually
    # be graded for the same name. A pathless frame grades UNCHECKABLE,
    # so pruning on it would let one frame-shaped line launder every
    # fabricated symbol in the report into "cannot tell".
    frame_funcs = {
        c.extra.get("function")
        for c in out
        if c.type is ClaimType.STACK_FRAME and c.extra.get("path")
    }
    pruned = []
    for claim in out:
        if claim.type is ClaimType.FILE and claim.extra.get("path") in file_line_paths:
            continue
        if claim.type is ClaimType.SYMBOL and claim.value in frame_funcs:
            continue
        pruned.append(claim)
    return pruned
