import json

import pytest

from guardian.day2 import preview


@pytest.mark.parametrize("reason", ["commit", "verdict", "approval", "branch"])
def test_refuses_invalid_preview(tmp_path, monkeypatch, reason):
    commit = "a" * 40
    candidate = {"commit": commit, "verdict": "Verified", "branch": "guardian/test", "actions": ["ACT-001"]}
    if reason == "verdict":
        candidate["verdict"] = "Failed"
    folder = tmp_path / "day2"
    folder.mkdir()
    (folder / "validation_latest.json").write_text(json.dumps({"combined": candidate}))
    monkeypatch.setattr(preview.approvals, "approved_actions",
                        lambda out: [] if reason == "approval" else [{"id": "ACT-001"}])

    def git_only(*args):
        assert reason == "branch" and args[0] == "git"
        return "b" * 40

    monkeypatch.setattr(preview, "command", git_only)
    with pytest.raises(ValueError):
        preview.launch(tmp_path, tmp_path, "old" if reason == "commit" else commit)
