"""The parts users depend on that aren't Python: the plugin manifest and the project metadata."""

import json
import subprocess
import tomllib

from harness import ROOT, env_for


def manifest() -> dict:
    return json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())


def test_plugin_and_project_versions_match():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert manifest()["version"] == project["version"]


def test_the_plugins_launch_command_starts_the_server(tmp_path):
    """Run exactly what Claude Code runs, with `status` appended, from an unrelated directory."""
    server = manifest()["mcpServers"]["backchannel"]
    args = [a.replace("${CLAUDE_PLUGIN_ROOT}", str(ROOT)) for a in server["args"]]
    assert "--locked" in args and "--no-config" in args  # dependencies come from uv.lock, whatever the cwd holds
    (tmp_path / "pyproject.toml").write_text("this is not valid toml and must never be read [[[")
    r = subprocess.run(
        [server["command"], *args, "status"],
        env=env_for("client", "pkg", 1, tmp_path / "data"),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert r.returncode == 0 and "name pkg, key " in r.stdout, r.stderr[-400:]
