"""The parts users depend on that aren't Python: the plugin manifest and the project metadata."""

import json
import subprocess
import tomllib

from harness import ROOT, env_for


def manifest() -> dict:
    return json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())


def test_every_apps_plugin_files_agree():
    """The repository is a plugin for three apps at once; their manifests must not drift apart."""
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    for name in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json", ".antigravity-plugin/plugin.json"):
        assert json.loads((ROOT / name).read_text())["version"] == version, name
    launch = ["--no-config", "--locked", "--no-dev", "backchannel"]
    servers = [
        json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["mcpServers"]["backchannel"],
        json.loads((ROOT / "codex.mcp.json").read_text())["mcpServers"]["backchannel"],
        json.loads((ROOT / "mcp_config.json").read_text())["mcpServers"]["backchannel"],
    ]
    assert all(s["command"] == "uv" and s["args"][-4:] == launch for s in servers)
    hooks = {
        "claude": json.loads((ROOT / "hooks/hooks.json").read_text())["hooks"],
        "codex": json.loads((ROOT / "hooks/codex.json").read_text())["hooks"],
        "gemini": json.loads((ROOT / "hooks.json").read_text())["backchannel"],
    }
    for app, events in hooks.items():
        commands = json.dumps(events)
        assert f" {app}" in commands and "backchannel hook" in commands and "--locked" in commands, app


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
