"""Tests for the CLAASP v5 review-branch workflow routing."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)
QUALITY = ROOT / ".github" / "workflows" / "claasp-quality.yaml"
RELEASE_IMAGE = ROOT / ".github" / "workflows" / "claasp-v5-release-image.yaml"
REVIEW_CONDITION = (
    "if: github.event_name != 'pull_request' || github.base_ref == 'claasp-v5' || "
    "github.head_ref == 'claasp-v5' || startsWith(github.base_ref, 'feat/')"
)


def _job_blocks(workflow: Path) -> dict[str, str]:
    """Return top-level job blocks from a GitHub Actions workflow."""

    lines = workflow.read_text(encoding="utf-8").splitlines()
    jobs_index = lines.index("jobs:")
    starts = [
        index
        for index in range(jobs_index + 1, len(lines))
        if lines[index].startswith("  ")
        and not lines[index].startswith("    ")
        and lines[index].endswith(":")
    ]
    blocks: dict[str, str] = {}
    for position, start in enumerate(starts):
        stop = starts[position + 1] if position + 1 < len(starts) else len(lines)
        blocks[lines[start].strip()[:-1]] = "\n".join(lines[start:stop])
    return blocks


def test_review_workflows_accept_review_and_stack_bases():
    expected = {
        "claasp-v5",
        "develop",
        "feat/latex-report-tables",
        "feat/statistical-supplied-datasets",
        "feat/fractional-trail-queries",
        "feat/boolean-algebraic-systems",
        "feat/monomial-analysis-workflows",
    }
    for workflow in (QUALITY, RELEASE_IMAGE):
        # Restrict the check to pull-request routing, excluding push branches
        # and path filters. Validate the complete allowlist rather than its
        # previous inline YAML spelling.
        trigger = workflow.read_text(encoding="utf-8").split("  pull_request:\n", 1)[1]
        branches = trigger.split("    paths:", 1)[0]
        actual = set(re.findall(r"^\s+- ([^\s#]+)\s*$", branches, re.MULTILINE))
        assert actual == expected, workflow.name


def test_every_review_workflow_job_rejects_unrelated_develop_prs():
    quality_jobs = _job_blocks(QUALITY)
    image_jobs = _job_blocks(RELEASE_IMAGE)

    assert len(quality_jobs) == 13
    assert len(image_jobs) == 2
    assert all(REVIEW_CONDITION in block for block in quality_jobs.values())
    assert all(REVIEW_CONDITION in block for block in image_jobs.values())


def test_merge_queue_requests_checks_only_for_claasp_v5():
    for workflow in (QUALITY, RELEASE_IMAGE):
        triggers = workflow.read_text(encoding="utf-8").split("\njobs:", 1)[0]
        match = re.search(r"(?ms)^  merge_group:\n(.*?)(?=^  \S|^\S|\Z)", triggers)
        assert match is not None, workflow.name
        values = re.findall(r"^\s+- ([^\s#]+)\s*$", match[1], re.MULTILINE)
        assert values == ["checks_requested", "claasp-v5"], workflow.name


def test_merge_queue_jobs_check_the_group_commit():
    for workflow in (QUALITY, RELEASE_IMAGE):
        text = workflow.read_text(encoding="utf-8")
        # checkout's default ref is the merge-group commit. Overriding it with
        # a PR head would omit the target branch and earlier queued changes.
        assert "github.event.pull_request.head" not in text
        for block in _job_blocks(workflow).values():
            assert "github.event_name != 'pull_request'" in block


def test_queue_rule_preserves_stack_ancestry_and_targets_only_claasp_v5():
    rule = json.loads(
        (ROOT / ".github/rulesets/claasp-v5-merge-queue.json").read_text(encoding="utf-8")
    )
    assert rule["conditions"]["ref_name"] == {"include": ["refs/heads/claasp-v5"], "exclude": []}
    assert rule["target"] == "branch"
    assert rule["enforcement"] == "active"
    assert rule["bypass_actors"] == []
    (queue,) = rule["rules"]
    assert queue["type"] == "merge_queue"
    assert queue["parameters"]["merge_method"] == "MERGE"
    assert queue["parameters"]["grouping_strategy"] == "ALLGREEN"
