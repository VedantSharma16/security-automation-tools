"""AST-based detector for known-insecure Python coding patterns.

Working from the parsed AST (rather than regex over source text) means each
rule reasons about actual call targets and keyword arguments, so it survives
formatting differences and produces far fewer false positives than a
line-oriented grep would.
"""

from __future__ import annotations

import ast
from pathlib import Path

from codesec.findings import Finding, Severity

_SENSITIVE_NAME_HINTS = ("token", "secret", "password", "passwd", "apikey", "api_key", "key")


def _dotted_name(node: ast.AST) -> str:
    """Best-effort reconstruction of a dotted call target, e.g. 'os.system'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _get_keyword(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_const_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_const_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _snippet(source_lines: list, lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_label: str, source_lines: list):
        self.file_label = file_label
        self.source_lines = source_lines
        self.findings: list = []
        self._assign_target_stack: list = []

    def _emit(self, node, **kwargs) -> None:
        self.findings.append(
            Finding(
                file=self.file_label,
                line=node.lineno,
                column=node.col_offset + 1,
                snippet=_snippet(self.source_lines, node.lineno),
                **kwargs,
            )
        )

    # -- assignments, tracked so weak-randomness checks can see the target name --
    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        self._assign_target_stack.append(names)
        self.generic_visit(node)
        self._assign_target_stack.pop()

    def _current_targets_look_sensitive(self) -> bool:
        if not self._assign_target_stack:
            return False
        names = self._assign_target_stack[-1]
        return any(hint in n.lower() for n in names for hint in _SENSITIVE_NAME_HINTS)

    # -- dangerous dynamic execution --
    def visit_Call(self, node: ast.Call) -> None:
        target = _dotted_name(node.func)
        simple_name = target.rsplit(".", 1)[-1] if target else ""

        if simple_name in ("eval", "exec") and not target.count("."):
            self._emit(
                node,
                rule_id="py-eval-exec",
                title=f"Use of {simple_name}()",
                severity=Severity.HIGH,
                cwe="CWE-95",
                description=(
                    f"{simple_name}() executes a string as code. If any part of the input "
                    "can be influenced by a user, this is arbitrary code execution."
                ),
                remediation=(
                    f"Avoid {simple_name}() on dynamic input. Use ast.literal_eval() for "
                    "data, or a safe parser/dispatch table instead of executing code."
                ),
            )

        elif target in ("os.system", "os.popen", "commands.getoutput"):
            self._emit(
                node,
                rule_id="py-os-system",
                title=f"Command Execution via {target}()",
                severity=Severity.HIGH,
                cwe="CWE-78",
                description=(
                    f"{target}() runs a command through the system shell. If any argument "
                    "is built from external input, this allows OS command injection."
                ),
                remediation=(
                    "Use subprocess.run([...], shell=False) with an argument list instead "
                    "of building a shell command string."
                ),
            )

        elif target in (
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        ):
            shell_kw = _get_keyword(node, "shell")
            if _is_const_true(shell_kw):
                first_arg = node.args[0] if node.args else None
                is_dynamic = not (
                    isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)
                )
                self._emit(
                    node,
                    rule_id="py-subprocess-shell-true",
                    title=f"{target}() called with shell=True",
                    severity=Severity.CRITICAL if is_dynamic else Severity.MEDIUM,
                    cwe="CWE-78",
                    description=(
                        "shell=True invokes a system shell to run the command. "
                        + (
                            "The command is built from a non-literal expression, so this is "
                            "very likely OS command injection if any part is user-influenced."
                            if is_dynamic
                            else "No dynamic input was detected here, but shell=True is "
                            "unnecessary risk surface."
                        )
                    ),
                    remediation=(
                        "Pass the command as a list of arguments and drop shell=True. "
                        "If shell features are truly required, use shlex.quote() on every "
                        "externally-influenced fragment."
                    ),
                )

        elif target in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            self._emit(
                node,
                rule_id="py-insecure-deserialization",
                title=f"Insecure Deserialization via {target}()",
                severity=Severity.HIGH,
                cwe="CWE-502",
                description=(
                    f"{target}() can execute arbitrary code while deserializing "
                    "attacker-controlled data."
                ),
                remediation=(
                    "Never unpickle data from an untrusted source. Prefer a safe, "
                    "schema-validated format such as JSON for cross-trust-boundary data."
                ),
            )

        elif target in ("yaml.load", "yaml.unsafe_load"):
            loader_kw = _get_keyword(node, "Loader")
            loader_name = _dotted_name(loader_kw) if loader_kw is not None else None
            if target == "yaml.unsafe_load" or loader_kw is None or loader_name in (
                "yaml.Loader",
                "yaml.UnsafeLoader",
                "yaml.FullLoader",
            ):
                self._emit(
                    node,
                    rule_id="py-yaml-unsafe-load",
                    title="Unsafe YAML Deserialization",
                    severity=Severity.HIGH,
                    cwe="CWE-502",
                    description=(
                        "yaml.load() without Loader=yaml.SafeLoader (or yaml.unsafe_load) "
                        "can construct arbitrary Python objects from the input document."
                    ),
                    remediation="Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
                )

        elif target in ("hashlib.md5", "hashlib.sha1"):
            algo = target.rsplit(".", 1)[-1]
            self._emit(
                node,
                rule_id="py-weak-hash",
                title=f"Use of Weak Hash Algorithm ({algo})",
                severity=Severity.MEDIUM,
                cwe="CWE-327",
                description=(
                    f"{algo} is cryptographically broken and unsuitable for password "
                    "hashing or integrity-sensitive use."
                ),
                remediation=(
                    "For passwords use a slow KDF (bcrypt, scrypt, or Argon2). For "
                    "integrity/checksums prefer sha256 or better."
                ),
            )

        elif target in ("random.random", "random.randint", "random.choice", "random.randrange"):
            if self._current_targets_look_sensitive():
                self._emit(
                    node,
                    rule_id="py-weak-randomness",
                    title="Predictable Randomness for Security-Sensitive Value",
                    severity=Severity.MEDIUM,
                    cwe="CWE-330",
                    description=(
                        "The `random` module is not cryptographically secure, but the "
                        "result is assigned to a variable that looks security-sensitive."
                    ),
                    remediation="Use the `secrets` module (e.g. secrets.token_urlsafe()) for tokens, keys, or passwords.",
                )

        elif target in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"):
            verify_kw = _get_keyword(node, "verify")
            if _is_const_false(verify_kw):
                self._emit(
                    node,
                    rule_id="py-tls-verify-disabled",
                    title="TLS Certificate Verification Disabled",
                    severity=Severity.HIGH,
                    cwe="CWE-295",
                    description="verify=False disables TLS certificate validation, enabling MITM attacks.",
                    remediation="Remove verify=False. If a private CA is needed, pass verify='/path/to/ca-bundle.pem' instead.",
                )

        elif simple_name == "run" and _is_const_true(_get_keyword(node, "debug")):
            self._emit(
                node,
                rule_id="py-debug-mode-enabled",
                title="Debug Mode Enabled",
                severity=Severity.MEDIUM,
                cwe="CWE-489",
                description=(
                    "Running a web app with debug=True can expose an interactive "
                    "debugger/stack traces to remote clients, which is remote code "
                    "execution in frameworks like Flask/Werkzeug."
                ),
                remediation="Disable debug mode in production; drive it from an environment variable that defaults to False.",
            )

        # SQL injection: cursor.execute("...", ...) built by string concatenation/formatting
        if simple_name in ("execute", "executemany") and node.args:
            first_arg = node.args[0]
            if _looks_like_dynamic_sql(first_arg):
                self._emit(
                    node,
                    rule_id="py-sql-injection",
                    title="Possible SQL Injection",
                    severity=Severity.CRITICAL,
                    cwe="CWE-89",
                    description=(
                        "The SQL query passed to execute() is built by string "
                        "concatenation/formatting instead of parameter binding."
                    ),
                    remediation=(
                        "Use parameterized queries, e.g. "
                        'cursor.execute("SELECT * FROM t WHERE id = ?", (value,)).'
                    ),
                )

        self.generic_visit(node)


def _looks_like_dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def scan_source(source: str, file_label: str) -> list:
    try:
        tree = ast.parse(source, filename=file_label)
    except SyntaxError:
        return []
    visitor = _Visitor(file_label, source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def scan_file(path: Path) -> list:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_source(source, str(path))


def scan_path(root: Path) -> list:
    findings = []
    if root.is_file():
        if root.suffix == ".py":
            findings.extend(scan_file(root))
        return findings
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", "__pycache__", ".venv", "venv"} for part in path.parts):
            continue
        findings.extend(scan_file(path))
    return findings
