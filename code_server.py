"""Code MCP: read-only repo investigation.

Wraps `git log|show|grep` inside the repo the Resource Registry maps the
service to. Only the read-only git subcommands listed in config/policy.yaml
are reachable -- push/commit/checkout/reset/etc are hard-blocked.

Run:  python code_server.py
Requires: pip install mcp pyyaml   (git must be on PATH)
"""
import os
import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from common.loader import load_yaml
from common.policy import CONFIG_DIR, PolicyEngine, PolicyViolation
from common.registry import ServiceRegistry

mcp = FastMCP(
    "code-mcp",
    host=os.environ.get("MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MCP_PORT", "8703")),
)
policy = PolicyEngine()
registry = ServiceRegistry()
_repo_config = load_yaml(CONFIG_DIR / "code_repos.yaml")["repositories"]

_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _repo_path(service_name: str) -> Path:
    repo_name = registry.repository_name(service_name)
    if repo_name not in _repo_config:
        raise PolicyViolation(f"No repository configured for '{repo_name}'")
    path = Path(_repo_config[repo_name]["path"]).resolve()
    if not path.is_dir():
        raise PolicyViolation(f"Configured repository path does not exist: {path}")
    return path


def _run_git(repo: Path, subcommand: str, args: list, ok_returncodes=(0,)) -> str:
    policy.assert_git_command_allowed(subcommand)
    result = subprocess.run(
        ["git", subcommand, *args],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=policy.request_timeout(),
    )
    if result.returncode not in ok_returncodes:
        raise RuntimeError(result.stderr.strip() or f"git {subcommand} failed")
    return result.stdout


@mcp.tool()
def get_recent_commits(service_name: str, since_hours: int = 24, limit: int = 20) -> list:
    """List recent commits in the repo mapped to service_name."""
    try:
        repo = _repo_path(service_name)
        out = _run_git(
            repo,
            "log",
            [f"--since={since_hours}.hours", f"-n{limit}", "--pretty=format:%H|%an|%ad|%s", "--date=iso"],
        )
        commits = []
        for line in out.splitlines():
            if not line.strip():
                continue
            sha, author, date, subject = line.split("|", 3)
            commits.append({"sha": sha, "author": author, "date": date, "subject": subject})
        policy.audit("get_recent_commits", service_name, {"since_hours": since_hours}, "ok", f"{len(commits)} commits")
        return commits
    except PolicyViolation as e:
        policy.audit("get_recent_commits", service_name, {}, "blocked", str(e))
        raise


@mcp.tool()
def get_commit_diff(service_name: str, commit_sha: str) -> str:
    """Show the diff introduced by a specific commit."""
    if not _SHA_RE.match(commit_sha):
        raise PolicyViolation("commit_sha must look like a git SHA")
    repo = _repo_path(service_name)
    diff = _run_git(repo, "show", [commit_sha])
    policy.audit("get_commit_diff", service_name, {"commit_sha": commit_sha}, "ok")
    return diff


@mcp.tool()
def search_code(service_name: str, query: str, limit: int = 50) -> list:
    """Search the repo's tracked files for a literal string or regex."""
    repo = _repo_path(service_name)
    out = _run_git(repo, "grep", ["-n", "-e", query], ok_returncodes=(0, ))
    lines = out.splitlines()[:limit]
    policy.audit("search_code", service_name, {"query": query}, "ok", f"{len(lines)} matches")
    return lines


if __name__ == "__main__":
    mcp.run(transport="sse")
