"""AST-based static analysis rules for Python source.

Each rule looks for a specific vulnerability *shape* (an AST pattern), not
just a keyword, so it can tell ``subprocess.run(["ls", "-la"])`` (fine) apart
from ``subprocess.run(cmd, shell=True)`` where ``cmd`` is built from request
data (CWE-78). Rules favor precision over recall: this powers a portfolio
demo and a CI gate, not a production SAST engine, so a rule that fires
constantly on safe code is worse than one that misses an edge case.

Severity scale: "critical" > "high" > "medium" > "low".
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")

_SECRET_NAME_RE = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token)$",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUES = {"", "changeme", "todo", "xxx", "redacted", "example", "<password>", "..."}

_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GENERIC_SECRET_ASSIGN_RE = re.compile(
    r"""(?i)\b(password|passwd|secret|api_key|apikey|access_key|token)\b["']?\s*[:=]\s*["'][^"'\s]{6,}["']"""
)

_HASH_FUNCS = {"md5", "sha1"}
_WEAK_RANDOM_FUNCS = {"random", "randint", "choice", "randrange", "uniform", "getrandbits"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    cwe: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "remediation": self.remediation,
        }


REMEDIATION = {
    "command-injection": "Avoid shell=True with dynamic input; pass a list of arguments to "
    "subprocess and never interpolate untrusted data into a shell string.",
    "eval-exec": "Replace eval/exec with a safe alternative (ast.literal_eval for data, "
    "an explicit dispatch table for behavior). Never eval() untrusted input.",
    "insecure-deserialization": "Do not unpickle or yaml.load() data from an untrusted source. "
    "Use yaml.safe_load(), or a plain-data format like JSON, instead.",
    "sql-injection": "Use parameterized queries (cursor.execute(query, params)) instead of "
    "building SQL with string formatting or concatenation.",
    "hardcoded-secret": "Move the credential to an environment variable or a secrets manager "
    "(Vault, AWS Secrets Manager, etc.) and rotate the exposed value.",
    "weak-hash": "Use hashlib.sha256 or a purpose-built KDF (bcrypt, scrypt, argon2) for "
    "passwords; md5/sha1 are broken for any security-relevant use.",
    "weak-randomness": "Use the `secrets` module (secrets.token_urlsafe, secrets.choice) for "
    "tokens, passwords, or anything security-sensitive — `random` is not cryptographically secure.",
    "disabled-tls-verification": "Never disable TLS verification in production code; if a "
    "custom CA is needed, pass its bundle instead of verify=False.",
    "debug-mode-enabled": "Ensure debug mode is disabled (or gated behind an environment check) "
    "before deploying — debug mode can expose stack traces, source, and a remote debugger.",
    "path-traversal": "Validate and normalize the path (os.path.realpath) and confirm it stays "
    "within an allowed base directory before opening it.",
}


def _is_str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_dynamic_string(node: ast.AST | None) -> bool:
    """True if node builds a string from a non-literal value (f-string, concat, %, .format())."""
    if node is None or _is_str_literal(node):
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _call_qualname(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _uses_weak_random(value: ast.AST) -> bool:
    """True if any call anywhere in ``value`` (e.g. inside a join/generator) uses `random.*`."""
    for node in ast.walk(value):
        if isinstance(node, ast.Call):
            qualname = _call_qualname(node) or ""
            if qualname.startswith("random.") or qualname in _WEAK_RANDOM_FUNCS:
                return True
    return False


def _kwarg(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


class SecurityVisitor(ast.NodeVisitor):
    """Walks a module's AST once, collecting :class:`Finding` objects."""

    def __init__(self, filename: str, source_lines: list[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        self._param_names_by_line: dict[int, set[str]] = {}

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add(self, rule_id: str, cwe: str, title: str, severity: str, lineno: int) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                cwe=cwe,
                title=title,
                severity=severity,
                file=self.filename,
                line=lineno,
                snippet=self._snippet(lineno),
                remediation=REMEDIATION[rule_id],
            )
        )

    # -- assignments: hardcoded secrets, weak-randomness-into-secret -------
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_secret_assignment(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_secret_assignment(self, name: str, value: ast.AST, lineno: int) -> None:
        if not _SECRET_NAME_RE.search(name):
            return
        if _is_str_literal(value) and value.value.strip().lower() not in _PLACEHOLDER_VALUES:
            severity = "critical" if "private" in name.lower() or "aws" in name.lower() else "high"
            self._add("hardcoded-secret", "CWE-798", f"Hardcoded credential in `{name}`", severity, lineno)
        elif _uses_weak_random(value):
            self._add(
                "weak-randomness",
                "CWE-330",
                f"`{name}` derived from the non-cryptographic `random` module",
                "high",
                lineno,
            )

    # -- function defs: track parameter names for the path-traversal heuristic
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        params = {a.arg for a in node.args.args}
        for child in ast.walk(node):
            self._param_names_by_line.setdefault(getattr(child, "lineno", -1), set()).update(params)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # same handling

    # -- calls: the bulk of the rules ---------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        qualname = _call_qualname(node) or ""
        self._check_command_injection(node, qualname)
        self._check_eval_exec(node, qualname)
        self._check_deserialization(node, qualname)
        self._check_sql_injection(node, qualname)
        self._check_weak_hash(node, qualname)
        self._check_disabled_tls(node, qualname)
        self._check_debug_mode(node, qualname)
        self._check_path_traversal(node, qualname)
        self.generic_visit(node)

    def _check_command_injection(self, node: ast.Call, qualname: str) -> None:
        first_arg = node.args[0] if node.args else None
        if qualname == "os.system" and first_arg is not None and not _is_str_literal(first_arg):
            self._add("command-injection", "CWE-78", "os.system() with a dynamic command", "high", node.lineno)
            return
        shell_kw = _kwarg(node, "shell")
        is_shell_true = isinstance(shell_kw, ast.Constant) and shell_kw.value is True
        subprocess_funcs = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
        if is_shell_true and qualname in subprocess_funcs:
            severity = "high" if first_arg is not None and not _is_str_literal(first_arg) else "medium"
            self._add(
                "command-injection", "CWE-78", f"{qualname}() called with shell=True", severity, node.lineno
            )

    def _check_eval_exec(self, node: ast.Call, qualname: str) -> None:
        if qualname in {"eval", "exec"} and node.args:
            severity = "high" if not _is_str_literal(node.args[0]) else "medium"
            self._add("eval-exec", "CWE-95", f"Use of {qualname}()", severity, node.lineno)

    def _check_deserialization(self, node: ast.Call, qualname: str) -> None:
        if qualname in {"pickle.load", "pickle.loads", "pickle.Unpickler"}:
            self._add(
                "insecure-deserialization", "CWE-502", f"{qualname}() can execute arbitrary code", "high", node.lineno
            )
            return
        if qualname == "yaml.load":
            loader = _kwarg(node, "Loader")
            loader_name = ""
            if isinstance(loader, ast.Attribute):
                loader_name = loader.attr
            if loader is None or loader_name in {"Loader", "UnsafeLoader", "FullLoader"}:
                self._add(
                    "insecure-deserialization",
                    "CWE-502",
                    "yaml.load() without Loader=yaml.SafeLoader",
                    "high",
                    node.lineno,
                )

    def _check_sql_injection(self, node: ast.Call, qualname: str) -> None:
        if qualname.endswith((".execute", ".executemany")) and node.args:
            if _is_dynamic_string(node.args[0]):
                self._add(
                    "sql-injection",
                    "CWE-89",
                    f"{qualname}() built from a dynamic string",
                    "high",
                    node.lineno,
                )

    def _check_weak_hash(self, node: ast.Call, qualname: str) -> None:
        if qualname in {f"hashlib.{fn}" for fn in _HASH_FUNCS}:
            self._add(
                "weak-hash", "CWE-327", f"{qualname}() is cryptographically broken", "medium", node.lineno
            )

    def _check_disabled_tls(self, node: ast.Call, qualname: str) -> None:
        verify_kw = _kwarg(node, "verify")
        if verify_kw is not None and isinstance(verify_kw, ast.Constant) and verify_kw.value is False:
            self._add(
                "disabled-tls-verification",
                "CWE-295",
                f"{qualname}() called with verify=False",
                "high",
                node.lineno,
            )
        elif qualname == "ssl._create_unverified_context":
            self._add(
                "disabled-tls-verification", "CWE-295", "ssl._create_unverified_context() disables TLS verification", "high", node.lineno
            )

    def _check_debug_mode(self, node: ast.Call, qualname: str) -> None:
        if qualname.endswith(".run"):
            debug_kw = _kwarg(node, "debug")
            if isinstance(debug_kw, ast.Constant) and debug_kw.value is True:
                self._add(
                    "debug-mode-enabled", "CWE-489", f"{qualname}(debug=True) leaves debug mode on", "medium", node.lineno
                )

    def _check_path_traversal(self, node: ast.Call, qualname: str) -> None:
        if qualname != "open" or not node.args:
            return
        arg = node.args[0]
        params = self._param_names_by_line.get(node.lineno, set())
        if isinstance(arg, ast.Name) and arg.id in params:
            self._add(
                "path-traversal",
                "CWE-22",
                f"open() called directly on parameter `{arg.id}` with no path validation",
                "medium",
                node.lineno,
            )
        elif _is_dynamic_string(arg):
            names_used = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            if names_used & params:
                self._add(
                    "path-traversal",
                    "CWE-22",
                    "open() path built from an unvalidated function parameter",
                    "medium",
                    node.lineno,
                )


def scan_source(source: str, filename: str = "<string>") -> list[Finding]:
    """Parse ``source`` and return every :class:`Finding` the rules produce.

    Returns a single "unparseable-file" style empty list on a syntax error —
    callers that need to surface parse failures should catch ``SyntaxError``
    themselves; this stays a pure "run the rules" entry point.
    """
    tree = ast.parse(source, filename=filename)
    visitor = SecurityVisitor(filename, source.splitlines())
    visitor.visit(tree)
    findings = list(visitor.findings)
    findings.extend(_scan_secret_patterns(source, filename))
    return findings


def _scan_secret_patterns(source: str, filename: str) -> list[Finding]:
    """Regex sweep for secrets the AST assignment check can't see (e.g. dict literals)."""
    findings = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if _AWS_KEY_RE.search(line):
            findings.append(
                Finding(
                    rule_id="hardcoded-secret",
                    cwe="CWE-798",
                    title="Hardcoded AWS access key ID",
                    severity="critical",
                    file=filename,
                    line=lineno,
                    snippet=line.strip(),
                    remediation=REMEDIATION["hardcoded-secret"],
                )
            )
        elif match := _GENERIC_SECRET_ASSIGN_RE.search(line):
            # Skip the plain `name = "literal"` shape — the AST visitor above
            # already catches that precisely (and applies the placeholder
            # allowlist). Only fire here for shapes it can't see: dict/kwarg
            # entries where the secret-looking name isn't the assign target.
            stripped = line.strip()
            leading = line[: match.start()].strip()
            if leading:
                findings.append(
                    Finding(
                        rule_id="hardcoded-secret",
                        cwe="CWE-798",
                        title="Hardcoded credential in a literal",
                        severity="high",
                        file=filename,
                        line=lineno,
                        snippet=stripped,
                        remediation=REMEDIATION["hardcoded-secret"],
                    )
                )
    return findings
