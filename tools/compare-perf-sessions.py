#!/usr/bin/env python3
"""Compare benchmark session directories without hiding invalid runs."""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


def results(root: Path):
    out = []
    paths = list(root.glob("download/result.json")) + list(root.glob("*/download/result.json"))
    for path in sorted(set(paths)):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            out.append({"path": str(path), "valid": False, "error": str(exc)})
            continue
        doc["path"] = str(path)
        doc["valid"] = True
        out.append(doc)
    return out


def median(values):
    return statistics.median(values) if values else None


def summary(items):
    numeric = ("received_mbps", "tayga_cpu_cores", "tayga_core_per_gbps",
               "tun_drops", "retransmits", "elapsed_s")
    return {key: {"n": len(values), "median": median(values),
                  "min": min(values), "max": max(values)}
            for key in numeric
            if (values := [float(x[key]) for x in items if x.get("valid") and key in x])}


def workload_signature(item):
    return (item.get("direction"), item.get("clients"), item.get("expected_clients"),
            item.get("workload_protocol"))


def pct_change(old, new):
    if old in (None, 0) or new is None:
        return None
    return (new - old) / old * 100.0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--json", type=Path, help="write machine-readable comparison")
    parser.add_argument("--markdown", type=Path, help="write Markdown comparison")
    args = parser.parse_args()

    base = results(args.baseline)
    cand = results(args.candidate)
    base_valid = [x for x in base if x.get("valid")]
    cand_valid = [x for x in cand if x.get("valid")]
    warnings = []
    if not base_valid or not cand_valid:
        warnings.append("one side has no readable result.json")
    signatures = {workload_signature(x) for x in base_valid + cand_valid}
    if len(signatures) > 1:
        warnings.append("baseline and candidate workloads are not identical")
    base_summary = summary(base)
    cand_summary = summary(cand)
    changes = {}
    for key in sorted(set(base_summary) & set(cand_summary)):
        changes[key + "_percent"] = pct_change(base_summary[key]["median"], cand_summary[key]["median"])
    report = {
        "baseline": str(args.baseline), "candidate": str(args.candidate),
        "baseline_summary": base_summary, "candidate_summary": cand_summary,
        "changes_percent": changes, "warnings": warnings,
        "baseline_invalid": [x for x in base if not x.get("valid")],
        "candidate_invalid": [x for x in cand if not x.get("valid")],
    }
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(payload)
    rows = ["| Metric | Baseline median | Candidate median | Change |"]
    rows.append("|---|---:|---:|---:|")
    for key in sorted(set(base_summary) & set(cand_summary)):
        b = base_summary[key]["median"]
        c = cand_summary[key]["median"]
        change = changes.get(key + "_percent")
        rendered_change = "n/a" if change is None or not math.isfinite(change) else f"{change:.3f}%"
        rows.append(f"| {key} | {b:.6g} | {c:.6g} | {rendered_change} |")
    markdown = "\n".join(["# Perf session comparison", "", *rows, "", "Warnings: " + ("; ".join(warnings) if warnings else "none"), ""])
    if args.markdown:
        args.markdown.write_text(markdown)
    print(payload, end="")
    return 2 if warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
