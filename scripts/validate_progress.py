"""Check task-tracker structure and WIP constraints in PROGRESS.md."""

from __future__ import annotations

import re
from pathlib import Path


def main() -> int:
    text = Path("PROGRESS.md").read_text(encoding="utf-8-sig")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        raise SystemExit("Tracker contains an invalid control character")
    registry_heading = "## Atomic Task Registry (WIP=2)"
    if text.count(registry_heading) != 1:
        raise SystemExit("Expected exactly one canonical task registry")

    registry = text.split(registry_heading, 1)[1].split(
        "## Dependency and Infrastructure Status", 1
    )[0]
    blocks = re.findall(
        r"- \*\*Task ID:\*\* `([^`]+)`([\s\S]*?)(?=\n- \*\*Task ID:|\n### Phase |\n---|\Z)",
        registry,
    )
    if not blocks:
        raise SystemExit("No task records found")

    ids = [task_id for task_id, _ in blocks]
    duplicates = sorted({task_id for task_id in ids if ids.count(task_id) > 1})
    if duplicates:
        raise SystemExit(f"Duplicate task IDs: {', '.join(duplicates)}")

    phase_records = re.split(r"(?=^### Phase )", registry, flags=re.MULTILINE)
    for phase in phase_records:
        phase_ids = re.findall(r"\*\*Task ID:\*\* `(TASK-\d+\.\d+)`", phase)
        numeric_ids = [tuple(map(int, task_id.removeprefix("TASK-").split("."))) for task_id in phase_ids]
        if numeric_ids != sorted(numeric_ids):
            raise SystemExit(f"Task IDs are out of order in {phase.splitlines()[0]}")

    allowed = {"not_started", "active", "blocked", "passing"}
    active = 0
    occupied_ids = set()
    for task_id, block in blocks:
        status = re.search(r"\*\*Status:\*\* `([^`]+)`", block)
        if not status or status.group(1) not in allowed:
            raise SystemExit(f"{task_id} has missing/invalid status")
        if status.group(1) == "active":
            active += 1
        if status.group(1) in {"active", "blocked"}:
            occupied_ids.add(task_id)
        for field in ("Description", "Verification Command", "Acceptance Criteria"):
            if not re.search(rf"\*\*{re.escape(field)}:\*\*\s*\S", block):
                raise SystemExit(f"{task_id} lacks {field}")

    declared = re.search(r"Active WIP Count:\*\* (\d+).*?(\d+) / 2", text)
    if len(occupied_ids) > 2 or not declared or int(declared.group(1)) != len(occupied_ids):
        raise SystemExit(f"Active WIP mismatch: records={active}, declared={declared}")
    header = text.split("**Active Tasks (WIP=2):**", 1)[1].split("**Active WIP Count:**", 1)[0]
    declared_ids = set(re.findall(r"`(TASK-\d+\.\d+)`", header))
    if declared_ids != occupied_ids:
        raise SystemExit(f"Active header does not match registry: {declared_ids} != {occupied_ids}")

    dates = re.findall(r"^\| (\d{4}-\d{2}-\d{2}) \|", text, flags=re.MULTILINE)
    if dates != sorted(dates):
        raise SystemExit("Execution log is not chronological")

    print(f"PROGRESS.md valid: {len(blocks)} unique tasks; occupied WIP {len(occupied_ids)}/2 ({active} active)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
