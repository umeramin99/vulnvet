"""Filter lists that keep claim extraction honest.

Symbol extraction from free-form prose is where a tool like this either
earns trust or loses it. Everything here exists to push borderline tokens
toward "not extracted" rather than risk a false NOT FOUND verdict on
something that was never a code reference in the first place.
"""

from __future__ import annotations

#: snake_case-looking vulnerability jargon that reports use as terminology,
#: not as identifiers ("a classic use_after_free scenario").
VULN_JARGON = frozenset(
    {
        "use_after_free",
        "double_free",
        "buffer_overflow",
        "heap_overflow",
        "stack_overflow",
        "integer_overflow",
        "integer_underflow",
        "out_of_bounds",
        "out_of_bound",
        "off_by_one",
        "format_string",
        "null_pointer_dereference",
        "null_dereference",
        "type_confusion",
        "race_condition",
        "memory_corruption",
        "memory_leak",
        "remote_code_execution",
        "arbitrary_code_execution",
        "code_execution",
        "command_injection",
        "sql_injection",
        "path_traversal",
        "directory_traversal",
        "denial_of_service",
        "privilege_escalation",
        "information_disclosure",
        "proof_of_concept",
        "supply_chain",
        "zero_day",
        "n_day",
        "heap_spray",
        "return_oriented_programming",
        "cross_site_scripting",
        "cross_site_request_forgery",
        "server_side_request_forgery",
        "insecure_deserialization",
        "prototype_pollution",
        "uninitialized_memory",
        "wild_pointer",
        "dangling_pointer",
    }
)

#: Tool / product / ecosystem names that match identifier syntax but are
#: never repository symbols.
PRODUCT_NAMES = frozenset(
    {
        # tooling commonly namedropped in reports
        "addresssanitizer",
        "memorysanitizer",
        "threadsanitizer",
        "undefinedbehaviorsanitizer",
        "leaksanitizer",
        "libfuzzer",
        "honggfuzz",
        "valgrind",
        "gdb",
        "lldb",
        "objdump",
        "readelf",
        "strace",
        "ltrace",
        "wireshark",
        "tcpdump",
        "burpsuite",
        "metasploit",
        "ghidra",
        "binwalk",
        "afl",
        "aflplusplus",
        "clusterfuzz",
        "osssfuzz",
        "oss_fuzz",
        "syzkaller",
        # ecosystems / products
        "github",
        "gitlab",
        "bitbucket",
        "hackerone",
        "bugcrowd",
        "javascript",
        "typescript",
        "openssl",
        "libressl",
        "boringssl",
        "websocket",
        "websockets",
        "nodejs",
        "graphql",
        "postgresql",
        "mysql",
        "sqlite",
        "mongodb",
        "redis",
        "nginx",
        "apache",
        "kubernetes",
        "docker",
        "openssh",
        "systemd",
        "windows",
        "linux",
        "macos",
        "android",
        "ubuntu",
        "debian",
        "fedora",
        "curl",
        "wget",
        "python",
        "golang",
        "rustlang",
        "stackoverflow",
        "mitre",
        "nvd",
        "cvss",
        "cwe",
        "cve",
        "poc",
        "asan",
        "msan",
        "ubsan",
        "tsan",
    }
)

#: Common English words / report boilerplate that can sneak through the
#: identifier regexes, mostly via inline code spans like `payload`.
COMMON_WORDS = frozenset(
    {
        "the", "and", "for", "with", "this", "that", "from", "into",
        "when", "then", "than", "will", "would", "could", "should",
        "here", "there", "where", "which", "while", "after", "before",
        "above", "below", "under", "over", "between", "during",
        "function", "functions", "method", "methods", "class", "classes",
        "struct", "structs", "variable", "variables", "parameter",
        "parameters", "argument", "arguments", "value", "values",
        "buffer", "buffers", "pointer", "pointers", "array", "arrays",
        "string", "strings", "integer", "integers", "byte", "bytes",
        "size", "length", "offset", "index", "count", "flag", "flags",
        "input", "output", "request", "requests", "response", "responses",
        "header", "headers", "packet", "packets", "payload", "payloads",
        "server", "servers", "client", "clients", "socket", "sockets",
        "connection", "connections", "session", "sessions",
        "attacker", "attackers", "victim", "user", "users", "admin",
        "exploit", "exploits", "vulnerability", "vulnerabilities",
        "vulnerable", "impact", "severity", "critical", "high", "medium",
        "low", "risk", "issue", "issues", "bug", "bugs", "crash",
        "crashes", "overflow", "underflow", "overread", "overwrite",
        "leak", "leaks", "free", "freed", "alloc", "allocated",
        "allocation", "memory", "heap", "stack", "kernel", "process",
        "thread", "threads", "handler", "handlers", "callback",
        "callbacks", "return", "returns", "call", "calls", "called",
        "calling", "code", "source", "line", "lines", "file", "files",
        "version", "versions", "release", "releases", "commit", "commits",
        "branch", "master", "main", "patch", "patched", "fix", "fixed",
        "fixes", "affected", "affects", "steps", "reproduce",
        "reproduction", "trigger", "triggers", "triggered", "cause",
        "causes", "caused", "result", "results", "example", "examples",
        "note", "notes", "true", "false", "null", "none", "void",
        "static", "const", "unsigned", "signed", "char", "short", "long",
        "float", "double", "test", "tests", "testing", "error", "errors",
        "warning", "warnings", "debug", "info", "data", "content",
        "contents", "config", "configuration", "default", "defaults",
        "option", "options", "case", "cases", "check", "checks",
        "checked", "validate", "validation", "sanitize", "sanitization",
        "encode", "encoding", "decode", "decoding", "parse", "parser",
        "parsing", "format", "formats", "type", "types", "object",
        "objects", "instance", "instances", "field", "fields", "member",
        "members", "element", "elements", "token", "tokens", "secret",
        "secrets", "password", "passwords", "credential", "credentials",
        "malloc", "calloc", "realloc", "memcpy", "memmove", "memset",
        "strcpy", "strncpy", "strcat", "strlen", "sprintf", "snprintf",
        "printf", "fprintf", "sizeof", "typedef", "endif", "ifdef",
        "ifndef", "include", "define", "pragma",
    }
)

#: C standard library / language builtins. These are real symbols but
#: their presence or absence in a project tree proves nothing about the
#: report, so extracting them only dilutes the dossier.
#: (libc allocation/string functions are covered by COMMON_WORDS above.)
LANGUAGE_BUILTINS = frozenset(
    {
        "size_t", "ssize_t", "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uintptr_t",
        "intptr_t", "ptrdiff_t", "wchar_t", "off_t", "pid_t", "time_t",
        "va_list", "file", "errno", "stdin", "stdout", "stderr",
        "std", "string_view", "unique_ptr", "shared_ptr", "nullptr",
        "println", "console_log", "eval", "exec", "self", "cls",
        "__init__", "__main__", "__name__", "__file__", "__dict__",
        "__repr__", "__str__", "__len__", "__eq__", "__hash__",
        "toString", "valueOf", "hasOwnProperty",
    }
)


def is_stopword(token: str) -> bool:
    lowered = token.lower()
    return (
        lowered in VULN_JARGON
        or lowered in PRODUCT_NAMES
        or lowered in COMMON_WORDS
        or token in LANGUAGE_BUILTINS
        or lowered in LANGUAGE_BUILTINS
    )
