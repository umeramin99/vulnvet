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
    (path / "src" / "http.c").write_text(HTTP_C)
    (path / "lib").mkdir()
    (path / "lib" / "util.c").write_text(UTIL_C)
    (path / "README.md").write_text("# demo project\n")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "initial import")
    git(path, "tag", "v1.0.0")

    (path / "src" / "http.c").write_text(HTTP_C + "\n/* hardening pass */\n")
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
