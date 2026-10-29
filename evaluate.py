"""Benchmark runner.  Usage:  python evaluate.py [version_label]
Replays tests/dataset.json against the running gateway, prints metrics, and saves
data/results_<label>.json so you can compare versions side by side later.
"""
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
PROXY_URL = "http://127.0.0.1:8000/v1/chat/completions"


def pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def run_evaluation(label: str = "v0") -> None:
    dataset = json.loads((ROOT / "tests" / "dataset.json").read_text())
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0})
    misses: list[str] = []
    false_blocks: list[str] = []

    print(f"\nRunning '{label}' on {len(dataset)} samples...\n")

    for s in dataset:
        t0 = time.perf_counter()
        try:
            res = httpx.post(PROXY_URL, json={"messages": [{"role": "user", "content": s["prompt"]}]},
                             timeout=20.0)
        except Exception as e:
            print(f"Error requesting proxy (is the server running?): {e}")
            return
        latencies.append((time.perf_counter() - t0) * 1000)

        # Blocked by EITHER guard: 403 = input guard, 502 = output guard.
        blocked = res.status_code in (403, 502)
        is_attack = s["type"] == "prompt_injection"
        correct = blocked == is_attack

        by_cat[s["category"]]["total"] += 1
        by_cat[s["category"]]["correct"] += int(correct)

        if is_attack and blocked:
            tp += 1
        elif is_attack:
            fn += 1
            misses.append(f"{s['id']} [{s['category']}]")
        elif blocked:
            fp += 1
            false_blocks.append(f"{s['id']} [{s['category']}]")
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    lat_sorted = sorted(latencies)
    p50 = statistics.median(lat_sorted)
    p95 = lat_sorted[min(len(lat_sorted) - 1, int(len(lat_sorted) * 0.95))]

    print("=" * 50)
    print(f"  BENCHMARK RESULTS  ({label})")
    print("=" * 50)
    print(f"Samples        : {total}")
    print(f"TP / FP        : {tp} / {fp}")
    print(f"TN / FN        : {tn} / {fn}")
    print("-" * 50)
    print(f"Recall         : {pct(recall)}   (attacks caught)")
    print(f"Precision      : {pct(precision)}   (blocks that were real attacks)")
    print(f"F1             : {pct(f1)}")
    print(f"Accuracy       : {pct((tp + tn) / total if total else 0)}")
    print(f"Latency p50/p95: {p50:.1f} / {p95:.1f} ms")
    print("=" * 50)

    print("\nMissed attacks (false negatives):")
    for m in misses or ["none"]:
        print(f"  - {m}")
    print("\nFalse blocks (false positives):")
    for m in false_blocks or ["none"]:
        print(f"  - {m}")

    print("\nAccuracy by category:")
    for cat, v in sorted(by_cat.items()):
        print(f"  {cat:<28} {v['correct']}/{v['total']}")

    out = {
        "label": label, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "latency_p50_ms": p50, "latency_p95_ms": p95,
        "missed": misses, "false_blocks": false_blocks,
    }
    (ROOT / "data").mkdir(exist_ok=True)
    (ROOT / "data" / f"results_{label}.json").write_text(json.dumps(out, indent=2))
    print(f"\nSaved data/results_{label}.json\n")


if __name__ == "__main__":
    run_evaluation(sys.argv[1] if len(sys.argv) > 1 else "v0")
