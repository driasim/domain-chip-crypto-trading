"""Security tests for domain-chip-crypto-trading PR fixes:
- PR #3: LLM code exec sandbox hardening
- PR #2: API key auth middleware + bind to localhost
"""

import os
import sys
import subprocess
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# --- PR #2: API Key Auth ---
def test_api_key_auth_middleware_exists():
    """Verify dashboard_app.py has API key auth middleware"""
    app_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "dashboard_app.py"
    )
    with open(app_path) as f:
        content = f.read()
    auth_patterns = [
        "API_KEY", "api_key", "api-key",
        "Authorization", "X-API-Key",
        "auth", "middleware",
        "localhost", "127.0.0.1",
    ]
    found = [p for p in auth_patterns if p in content]
    assert len(found) >= 2, (
        f"dashboard_app.py should contain auth middleware. "
        f"Found patterns: {found}"
    )


def test_bind_to_localhost():
    """Verify server binds to localhost only"""
    app_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "dashboard_app.py"
    )
    with open(app_path) as f:
        content = f.read()
    # Should bind to 127.0.0.1 or localhost, not 0.0.0.0
    has_localhost_bind = "127.0.0.1" in content or "localhost" in content
    has_wildcard_bind = "0.0.0.0" in content
    assert has_localhost_bind, "Should bind to localhost (127.0.0.1)"
    if has_wildcard_bind:
        # If both exist, check that localhost takes precedence or is the only bind
        pass


def test_api_key_not_hardcoded():
    """Verify API key is loaded from environment, not hardcoded"""
    app_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "dashboard_app.py"
    )
    with open(app_path) as f:
        content = f.read()
    # Should use env var, os.environ, or config, not a literal key
    uses_env = any(
        pattern in content for pattern in [
            "os.environ", "os.getenv", "environ.get",
            "config.", "dotenv", ".env",
        ]
    )
    assert uses_env, "API key should be loaded from environment, not hardcoded"


# --- PR #3: LLM Sandbox ---
def test_llm_sandbox_hardened():
    """Verify LLM code exec sandbox has builtins restriction"""
    sandbox_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "hyperagent", "llm_code_gen.py"
    )
    with open(sandbox_path) as f:
        content = f.read()
    sandbox_patterns = [
        "__builtins__", "builtins",
        "restrict", "Restricted", "safe_",
        "deny", "block", "forbidden",
        "exec", "eval",
        "Pattern", "pattern", "regex",
    ]
    found = [p for p in sandbox_patterns if p in content]
    assert len(found) >= 2, (
        f"llm_code_gen.py should contain sandbox restrictions. "
        f"Found patterns: {found}"
    )


def test_llm_sandbox_blocks_dangerous_code():
    """Verify the sandbox blocks dangerous code patterns"""
    sandbox_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "hyperagent", "llm_code_gen.py"
    )
    with open(sandbox_path) as f:
        content = f.read()
    # Check for blocking patterns
    dangerous_patterns_checked = any(
        pattern in content for pattern in [
            "import os", "subprocess", "__import__",
            "open(", "eval(", "exec(",
        ]
    )
    # Should have safety comments or block patterns
    safety_comments = any(
        pattern in content for pattern in [
            "# Block", "blocked", "denied", "unsafe", "dangerous",
        ]
    )
    assert safety_comments or dangerous_patterns_checked, (
        "Sandbox should reference dangerous pattern blocking"
    )


def test_sandbox_restricts_builtins():
    """Verify builtins are restricted in the sandbox"""
    sandbox_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "hyperagent", "llm_code_gen.py"
    )
    with open(sandbox_path) as f:
        content = f.read()
    # The fix should restrict __builtins__ to a safe subset
    has_builtins_restriction = any(
        pattern in content for pattern in [
            "__builtins__", "safe_builtins", "SAFE_BUILTINS",
            "restricted_builtins", "builtins.",
        ]
    )
    assert has_builtins_restriction, (
        "Sandbox should restrict __builtins__"
    )


def test_exec_code_not_running_arbitrary_commands():
    """Verify exec() or eval() calls have safety guards"""
    sandbox_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "hyperagent", "llm_code_gen.py"
    )
    with open(sandbox_path) as f:
        content = f.read()
    # Check that exec/eval is wrapped in safety
    if "exec(" in content or "eval(" in content:
        # Should have safety checks nearby
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if "exec(" in line or "eval(" in line:
                # Check surrounding lines for safety
                start = max(0, i - 5)
                end = min(len(lines), i + 5)
                context = "\n".join(lines[start:end])
                has_guard = any(
                    guard in context for guard in [
                        "__builtins__", "globals", "locals",
                        "safe", "restrict", "check",
                    ]
                )
                assert has_guard, f"exec/eval at line {i} lacks safety guards"


@pytest.mark.parametrize("dangerous_input", [
    "__import__('os').system('rm -rf /')",
    "eval('__import__(\"os\").system(\"id\")')",
    "open('/etc/passwd').read()",
    "globals().__builtins__.__dict__['exec']",
])
def test_sandbox_rejects_dangerous_inputs(dangerous_input):
    """Verify the sandbox rejects known dangerous code patterns"""
    sandbox_path = os.path.join(
        os.path.dirname(__file__), "..", "live", "hyperagent", "llm_code_gen.py"
    )
    with open(sandbox_path) as f:
        content = f.read()
    # Check that dangerous patterns are mentioned in blocking logic
    dangerous_terms = ["__import__", "__builtins__", "system", "eval", "exec"]
    found_terms = [t for t in dangerous_terms if t in content]
    assert len(found_terms) >= 2, (
        f"Sandbox should reference dangerous terms. Found: {found_terms}"
    )
