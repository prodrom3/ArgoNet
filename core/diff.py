# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Compare current results against a previous JSON snapshot."""

import json
from pathlib import Path
from typing import Any


def load_previous(path: str) -> dict[str, dict[str, Any]]:
    """Load a previous results JSON file, keyed by target."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results_list: list[dict[str, Any]]
    if "results" in data:
        results_list = data["results"]
    else:
        results_list = [data]
    return {r["target"]: r for r in results_list}


def diff_results(
    current: list[dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare current results against previous, returning a list of changes."""
    changes: list[dict[str, Any]] = []

    current_targets = {r["target"] for r in current}
    previous_targets = set(previous.keys())

    # New targets
    for target in current_targets - previous_targets:
        changes.append({"target": target, "change": "new", "details": "New target added"})

    # Removed targets
    for target in previous_targets - current_targets:
        changes.append({"target": target, "change": "removed", "details": "Target no longer present"})

    # Changed targets
    for r in current:
        target = r["target"]
        if target not in previous:
            continue
        prev = previous[target]
        target_changes = _diff_dicts(prev, r, target)
        changes.extend(target_changes)

    return changes


def _diff_dicts(
    old: dict[str, Any], new: dict[str, Any], target: str,
) -> list[dict[str, Any]]:
    """Find differences between two result dicts."""
    changes: list[dict[str, Any]] = []
    all_keys = set(old.keys()) | set(new.keys())

    for key in sorted(all_keys):
        if key in ("target", "is_ip"):
            continue
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            if old_val is None:
                changes.append({
                    "target": target, "change": "added",
                    "field": key, "value": _summarize(new_val),
                })
            elif new_val is None:
                changes.append({
                    "target": target, "change": "removed",
                    "field": key, "value": _summarize(old_val),
                })
            else:
                changes.append({
                    "target": target, "change": "changed",
                    "field": key,
                    "old": _summarize(old_val),
                    "new": _summarize(new_val),
                })
    return changes


def _summarize(value: Any) -> str:
    """Create a short summary of a value for display."""
    if isinstance(value, list):
        if len(value) <= 3:
            return str(value)
        return f"[{len(value)} items]"
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"))[:80]
    return str(value)
