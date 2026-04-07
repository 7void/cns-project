from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    arr = sorted(values)
    k = (len(arr) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(arr[int(k)])
    d0 = arr[f] * (c - k)
    d1 = arr[c] * (k - f)
    return float(d0 + d1)


def scenario_rows(run_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    run_id = run_data.get("run")
    key_id = (run_data.get("target") or {}).get("key_id")
    file_id = (run_data.get("target") or {}).get("file_id")
    for s in run_data.get("scenarios", []):
        name = s.get("scenario")
        if name in {"invalid_signature_threshold", "stale_timestamp_threshold"}:
            attempts = s.get("attempts", [])
            poisoned_at = s.get("poisoned_at_attempt")
            for a in attempts:
                resp = a.get("response") or {}
                rows.append(
                    {
                        "run": run_id,
                        "key_id": key_id,
                        "file_id": file_id,
                        "scenario": name,
                        "attempt": a.get("attempt"),
                        "duration_ms": a.get("duration_ms", 0),
                        "ok": a.get("ok"),
                        "error": a.get("error"),
                        "status": resp.get("status"),
                        "denial_reason": resp.get("denial_reason"),
                        "key_status": resp.get("key_status"),
                        "poisoned_at_attempt": poisoned_at,
                    }
                )
        elif name == "canary_then_probe":
            canary = s.get("canary") or {}
            probe = s.get("probe") or {}
            canary_resp = canary.get("response") or {}
            probe_resp = probe.get("response") or {}
            rows.append(
                {
                    "run": run_id,
                    "key_id": key_id,
                    "file_id": file_id,
                    "scenario": name,
                    "attempt": 1,
                    "duration_ms": canary.get("duration_ms", 0),
                    "ok": canary.get("ok"),
                    "error": canary.get("error"),
                    "status": canary_resp.get("status"),
                    "denial_reason": "",
                    "key_status": "",
                    "poisoned_at_attempt": "",
                    "event": "canary_call",
                }
            )
            rows.append(
                {
                    "run": run_id,
                    "key_id": key_id,
                    "file_id": file_id,
                    "scenario": name,
                    "attempt": 2,
                    "duration_ms": probe.get("duration_ms", 0),
                    "ok": probe.get("ok"),
                    "error": probe.get("error"),
                    "status": probe_resp.get("status"),
                    "denial_reason": probe_resp.get("denial_reason"),
                    "key_status": probe_resp.get("key_status"),
                    "poisoned_at_attempt": "",
                    "event": "post_canary_probe",
                }
            )
        elif name in {"key_mismatch", "not_authorized"}:
            r = s.get("result") or {}
            resp = r.get("response") or {}
            rows.append(
                {
                    "run": run_id,
                    "key_id": key_id,
                    "file_id": file_id,
                    "scenario": name,
                    "attempt": 1,
                    "duration_ms": r.get("duration_ms", 0),
                    "ok": r.get("ok"),
                    "error": r.get("error"),
                    "status": resp.get("status"),
                    "denial_reason": resp.get("denial_reason"),
                    "key_status": resp.get("key_status"),
                    "poisoned_at_attempt": "",
                }
            )
        else:
            rows.append(
                {
                    "run": run_id,
                    "key_id": key_id,
                    "file_id": file_id,
                    "scenario": name,
                    "attempt": "",
                    "duration_ms": 0,
                    "ok": False,
                    "error": s.get("error", "unknown"),
                    "status": "",
                    "denial_reason": "",
                    "key_status": "",
                    "poisoned_at_attempt": "",
                }
            )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_scenario[str(r["scenario"])].append(r)

    scenario_summary: dict[str, Any] = {}
    for scenario, items in by_scenario.items():
        latencies = [float(i.get("duration_ms") or 0) for i in items]
        denial_counts = Counter(str(i.get("denial_reason") or "") for i in items if i.get("denial_reason"))
        poisoned_hits = sum(1 for i in items if str(i.get("key_status") or "") == "POISONED")
        scenario_summary[scenario] = {
            "events": len(items),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "p50_latency_ms": round(percentile(latencies, 0.50), 3) if latencies else 0.0,
            "p95_latency_ms": round(percentile(latencies, 0.95), 3) if latencies else 0.0,
            "poisoned_event_count": poisoned_hits,
            "poisoned_event_rate": round(poisoned_hits / len(items), 4) if items else 0.0,
            "denial_reason_counts": dict(denial_counts),
        }

    return {
        "total_events": len(rows),
        "scenario_summary": scenario_summary,
    }


def write_csv(rows: list[dict[str, Any]], out_path: Path) -> None:
    fieldnames = [
        "run",
        "key_id",
        "file_id",
        "scenario",
        "event",
        "attempt",
        "duration_ms",
        "ok",
        "error",
        "status",
        "denial_reason",
        "key_status",
        "poisoned_at_attempt",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze CNS benchmark attack suite results.")
    parser.add_argument("--input", required=True, help="Path to benchmark results directory")
    args = parser.parse_args()

    in_dir = Path(args.input)
    if not in_dir.exists():
        raise SystemExit(f"Input directory not found: {in_dir}")

    run_files = sorted(in_dir.glob("run-*.json"))
    if not run_files:
        raise SystemExit(f"No run files found in: {in_dir}")

    rows: list[dict[str, Any]] = []
    for run_file in run_files:
        data = json.loads(run_file.read_text(encoding="utf-8-sig"))
        rows.extend(scenario_rows(data))

    summary = summarize(rows)
    summary["input_dir"] = str(in_dir)
    summary["run_files"] = len(run_files)

    events_csv = in_dir / "events.csv"
    summary_json = in_dir / "summary.json"
    scenario_csv = in_dir / "scenario_summary.csv"

    write_csv(rows, events_csv)
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    with scenario_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "scenario",
            "events",
            "avg_latency_ms",
            "p50_latency_ms",
            "p95_latency_ms",
            "poisoned_event_count",
            "poisoned_event_rate",
            "denial_reason_counts",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for scenario, info in summary["scenario_summary"].items():
            writer.writerow(
                {
                    "scenario": scenario,
                    "events": info["events"],
                    "avg_latency_ms": info["avg_latency_ms"],
                    "p50_latency_ms": info["p50_latency_ms"],
                    "p95_latency_ms": info["p95_latency_ms"],
                    "poisoned_event_count": info["poisoned_event_count"],
                    "poisoned_event_rate": info["poisoned_event_rate"],
                    "denial_reason_counts": json.dumps(info["denial_reason_counts"], ensure_ascii=False),
                }
            )

    print("Analysis complete.")
    print(f"Input: {in_dir}")
    print(f"Events CSV: {events_csv}")
    print(f"Scenario Summary CSV: {scenario_csv}")
    print(f"Summary JSON: {summary_json}")


if __name__ == "__main__":
    main()
