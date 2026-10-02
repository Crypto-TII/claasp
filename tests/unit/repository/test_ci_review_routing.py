"""Tests for the CLAASP v5 review-branch workflow routing."""

from __future__ import annotations

from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)
QUALITY = ROOT / ".github" / "workflows" / "claasp-quality.yaml"
RELEASE_IMAGE = ROOT / ".github" / "workflows" / "claasp-v5-release-image.yaml"
REVIEW_CONDITION = (
    "if: github.event_name != 'pull_request' || github.base_ref == 'claasp-v5' || "
    "github.head_ref == 'claasp-v5'"
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


def test_review_workflows_accept_both_review_directions():
    quality = QUALITY.read_text(encoding="utf-8")
    image = RELEASE_IMAGE.read_text(encoding="utf-8")

    assert "      - claasp-v5\n      - develop" in quality
    assert "branches: [claasp-v5, develop]" in image


def test_every_review_workflow_job_rejects_unrelated_develop_prs():
    quality_jobs = _job_blocks(QUALITY)
    image_jobs = _job_blocks(RELEASE_IMAGE)

    assert len(quality_jobs) == 13
    assert len(image_jobs) == 2
    assert all(REVIEW_CONDITION in block for block in quality_jobs.values())
    assert all(REVIEW_CONDITION in block for block in image_jobs.values())
