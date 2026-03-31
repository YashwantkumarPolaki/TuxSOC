"""
inmemory_correlator.py — Layer 5a: In-Memory Batch Correlator
=============================================================
Groups a batch of BackendDetection dicts by shared Source IP or
Destination IP, builds attack timelines, and injects
`parent_incident_id` on sub-events so the frontend can link them
to their master incident.

This runs AFTER all per-record L2–L4 processing is complete and
BEFORE the BEC kill-chain detector (_correlate_incidents) in
main_orchestrator.py.

Correlation algorithm:
  1. Group detections by source_ip, then by destination_ip
  2. Groups with >1 member elect a master (highest anomaly_score)
  3. Sub-events get parent_incident_id = master.incident_id
  4. Master gets engine_3_correlation.attack_timeline merged from all members
  5. Deduplicate timeline entries by (timestamp, detail)
  6. Single-event detections pass through unchanged
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_pivot_key(detection: dict) -> str | None:
    """Return the grouping key: source_ip preferred, then destination_ip."""
    raw = detection.get("raw_event") or {}
    src = raw.get("source_ip")
    dst = raw.get("destination_ip")
    return src or dst or None


def _merge_timelines(detections: list[dict]) -> list[dict]:
    """
    Merge attack_timeline entries from all detections in a group,
    deduplicating by (timestamp, detail).
    """
    seen: set[str] = set()
    merged: list[dict] = []
    for d in detections:
        for entry in d.get("engine_3_correlation", {}).get("attack_timeline", []):
            key = f"{entry.get('timestamp', '')}::{entry.get('detail', '')}"
            if key not in seen:
                seen.add(key)
                merged.append(entry)
    merged.sort(key=lambda e: e.get("timestamp", ""))
    return merged


def _make_master_id(group: list[dict]) -> str:
    anchor = group[0]
    src = (anchor.get("raw_event") or {}).get("source_ip") or anchor.get("incident_id", "")
    ts  = anchor.get("timestamp", "")
    return "CORR-" + hashlib.md5(f"{src}-{ts}".encode()).hexdigest()[:10].upper()


def _build_correlation_block(master_id: str, group: list[dict]) -> dict:
    """Build the engine_3_correlation block for the master incident."""
    timeline = _merge_timelines(group)
    return {
        "event_count":        len(group),
        "attack_timeline":    timeline,
        "correlated_log_ids": [d["incident_id"] for d in group],
        "parent_incident_id": None,  # master has no parent
    }


# ── Public entry point ────────────────────────────────────────────────────────

def enrich_all_correlations(detections: list[dict]) -> list[dict]:
    """
    Group detections by shared source_ip / destination_ip and inject
    parent_incident_id on sub-events.

    Parameters
    ----------
    detections : list of BackendDetection dicts (post L2–L4)

    Returns
    -------
    list of BackendDetection dicts with correlation enrichment applied.
    Order: master incidents first within each group, then sub-events,
    then ungrouped singles.
    """
    if len(detections) <= 1:
        return detections

    # ── Step 1: Skip backend-produced masters (is_master=True) ───────
    backend_masters = [d for d in detections if d.get("is_master")]
    candidates      = [d for d in detections if not d.get("is_master")]

    # ── Step 2: Group by pivot key ────────────────────────────────────
    groups: dict[str, list[dict]] = defaultdict(list)
    ungrouped: list[dict] = []

    for d in candidates:
        key = _get_pivot_key(d)
        if key:
            groups[key].append(d)
        else:
            ungrouped.append(d)

    # ── Step 3: Process each group ────────────────────────────────────
    result: list[dict] = list(backend_masters)

    for key, group in groups.items():
        if len(group) == 1:
            # Single event — no correlation needed, pass through
            result.append(group[0])
            continue

        # Elect master: highest anomaly_score
        master_detection = max(
            group,
            key=lambda d: d.get("engine_1_anomaly", {}).get("anomaly_score", 0.0)
        )
        master_id = master_detection["incident_id"]

        # Build merged timeline for master
        corr_block = _build_correlation_block(master_id, group)

        # Update master with merged correlation block
        updated_master = {
            **master_detection,
            "engine_3_correlation": {
                **master_detection.get("engine_3_correlation", {}),
                "event_count":        corr_block["event_count"],
                "attack_timeline":    corr_block["attack_timeline"],
                "correlated_log_ids": corr_block["correlated_log_ids"],
            },
            "event_count": len(group),
        }
        result.append(updated_master)

        # Inject parent_incident_id on sub-events
        for d in group:
            if d["incident_id"] == master_id:
                continue  # skip the master itself
            sub = {
                **d,
                "parent_incident_id": master_id,
                "engine_3_correlation": {
                    **d.get("engine_3_correlation", {}),
                    "parent_incident_id": master_id,
                },
            }
            result.append(sub)

    result.extend(ungrouped)
    return result
