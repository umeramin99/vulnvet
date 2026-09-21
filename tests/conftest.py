import subprocess

import pytest

HTTP_C = """\
#include <stdio.h>
#include <string.h>

#define MAX_HEADER 8192

struct request {
    char method[8];
    char path[1024];
    int header_count;
};

static int parse_header_line(struct request *req, const char *line, size_t len)
{
    if (len > MAX_HEADER)
        return -1;
    req->header_count++;
    return 0;
}

int handle_request(struct request *req, const char *buf, size_t len)
{
    const char *cursor = buf;
    while (len > 0) {
        int rc = parse_header_line(req, cursor, len);
        if (rc < 0)
            return rc;
        cursor++;
        len--;
    }
    return 0;
}
"""

UTIL_C = """\
#include <stdlib.h>

/* Build with --max-count=5 --fixed-strings for the bounded variant.
   This literal exists so tests can search for an option-shaped string
   that is genuinely present in the tree. */

void *checked_alloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr)
        abort();
    return ptr;
}
"""


def git(cwd, *args):
    subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )


@pytest.fixture(scope="session")
def fixture_repo(tmp_path_factory):
    """A small C project with two tagged releases."""
    path = tmp_path_factory.mktemp("demo-repo")
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")

    (path / "src").mkdir()
    (path / "src" / "http.c").write_text(HTTP_C, encoding="utf-8")
    (path / "lib").mkdir()
    (path / "lib" / "util.c").write_text(UTIL_C, encoding="utf-8")
    (path / "README.md").write_text("# demo project\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "initial import")
    git(path, "tag", "v1.0.0")

    (path / "src" / "http.c").write_text(HTTP_C + "\n/* hardening pass */\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "fix header parsing bounds")
    git(path, "tag", "v1.1.0")

    return str(path)


@pytest.fixture(scope="session")
def fixture_head_sha(fixture_repo):
    out = subprocess.run(
        ["git", "-C", fixture_repo, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


@pytest.fixture(scope="session")
def submodule_repo(tmp_path_factory):
    """A superproject with a real gitlink, for submodule-aware checks."""
    base = tmp_path_factory.mktemp("submodule-case")
    dep = base / "dep"
    dep.mkdir()
    git(dep, "init", "-q")
    git(dep, "config", "user.email", "test@example.invalid")
    git(dep, "config", "user.name", "Test")
    (dep / "src").mkdir()
    (dep / "src" / "parser.c").write_text(
        "int dep_parse_header(char *b)\n{\n    return 0;\n}\n", encoding="utf-8"
    )
    git(dep, "add", "-A")
    git(dep, "commit", "-q", "-m", "dep")

    main = base / "main"
    main.mkdir()
    git(main, "init", "-q")
    git(main, "config", "user.email", "test@example.invalid")
    git(main, "config", "user.name", "Test")
    (main / "app.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    git(main, "add", "-A")
    git(main, "commit", "-q", "-m", "init")
    git(
        main, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
        str(dep), "third_party/dep",
    )
    git(main, "add", "-A")
    git(main, "commit", "-q", "-m", "add submodule")
    return str(main)


@pytest.fixture
def dirty_repo(tmp_path):
    """A checkout with uncommitted work, as a maintainer's usually is.

    The other fixtures commit everything, so nothing else exercises the
    case where the report describes code that exists on disk but not yet
    in any revision.
    """
    path = tmp_path / "dirty"
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    (path / "src").mkdir()
    (path / "src" / "http.c").write_text(
        "int parse_header(char *b)\n{\n    return 0;\n}\n", encoding="utf-8"
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "init")

    # Work in progress: a new function and a new file, neither committed.
    (path / "src" / "http.c").write_text(
        "int parse_header(char *b)\n{\n    return 0;\n}\n\n"
        "int validate_length(size_t n)\n{\n"
        "    size_t limit = 1024;\n"
        "    if (n >= limit)\n"
        "        return 0;\n"
        "    return 1;\n}\n",
        encoding="utf-8",
    )
    (path / "src" / "newfile.c").write_text(
        "int brand_new_helper(void) { return 1; }\n", encoding="utf-8"
    )
    return str(path)


ENGINE_PY = '''\
class Engine:
    """A database engine, cited the way Python reports cite one."""

    def __init__(self, conn):
        self.conn = conn

    def _run_query(self, sql):
        return self.conn.execute(sql)


def module_helper(value):
    return value
'''

RENDER_PY = '''\
class Renderer:
    def render_template(self, name):
        return name
'''


@pytest.fixture(scope="session")
def class_repo(tmp_path_factory):
    """A Python project: methods live on classes and are cited that way.

    The C fixture cannot exercise "Engine._run_query" at all, and that
    spelling - never the literal text of any source line - is how most
    of the world writes a method citation.
    """
    path = tmp_path_factory.mktemp("class-repo")
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")

    (path / "app").mkdir()
    (path / "app" / "engine.py").write_text(ENGINE_PY, encoding="utf-8")
    (path / "app" / "render.py").write_text(RENDER_PY, encoding="utf-8")
    (path / "docs").mkdir()
    (path / "docs" / "CHANGELOG.md").write_text(
        "# Changes\n\n- 1.0.0: removed `retired_member`, which used to exist.\n",
        encoding="utf-8",
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "initial import")
    git(path, "tag", "v1.0.0")
    return str(path)


@pytest.fixture(scope="session")
def ahead_repo(tmp_path_factory):
    """A clean checkout sitting on a newer revision than the one graded.

    This is the ordinary case for a maintainer: HEAD is main, --rev is
    the release the report is about. Nothing is uncommitted, so a check
    gated on dirtiness never looked here.
    """
    path = tmp_path_factory.mktemp("ahead-repo")
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")

    (path / "src").mkdir()
    (path / "src" / "http.c").write_text(
        "int parse_header(char *b)\n{\n    return 0;\n}\n", encoding="utf-8"
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "init")
    git(path, "tag", "v1.0.0")

    (path / "src" / "http.c").write_text(
        "int parse_header(char *b)\n{\n    return 0;\n}\n\n"
        "int validate_body_length(size_t n)\n{\n    return n < 1024;\n}\n",
        encoding="utf-8",
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "add length validation")
    git(path, "tag", "v1.1.0")
    return str(path)
