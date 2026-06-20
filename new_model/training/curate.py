"""Phase 2 curation: dedup training records and carve a validation split.

"Curate ruthlessly" — a smaller clean set beats a large noisy one. This:
  - drops exact-duplicate examples (same user+assistant content),
  - drops near-empty / malformed records,
  - splits into train/val by a fixed seed (this val is for training-time early
    stopping ONLY; it is drawn from the train half, never the eval holdout).

Input:  data/train.jsonl  (from convert.py)
Output: data/train.curated.jsonl, data/val.jsonl + a stats summary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from typing import List


def _key(rec: dict) -> str:
    msgs = {m["role"]: m["content"] for m in rec.get("messages", [])}
    blob = (msgs.get("user", "") + "\x00" + msgs.get("assistant", "")).encode()
    return hashlib.sha256(blob).hexdigest()


def _valid(rec: dict) -> bool:
    msgs = {m["role"]: m["content"] for m in rec.get("messages", [])}
    return bool(msgs.get("user", "").strip()) and bool(msgs.get("assistant", "").strip())


def load_jsonl(path: str) -> List[dict]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def dump_jsonl(path: str, recs: List[dict]) -> None:
    with open(path, "w") as fh:
        fh.write("\n".join(json.dumps(r, ensure_ascii=False) for r in recs))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/train.jsonl")
    ap.add_argument("--out-dir", default="data")
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    recs = load_jsonl(args.inp)
    n_raw = len(recs)

    seen, deduped = set(), []
    for r in recs:
        if not _valid(r):
            continue
        k = _key(r)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    rng = random.Random(args.seed)
    rng.shuffle(deduped)
    cut = int(len(deduped) * (1 - args.val_frac))
    train, val = deduped[:cut], deduped[cut:]

    dump_jsonl(f"{args.out_dir}/train.curated.jsonl", train)
    dump_jsonl(f"{args.out_dir}/val.jsonl", val)

    n_pos = sum(1 for r in train if "Findings:" in r["messages"][-1]["content"])
    print(f"raw={n_raw} valid+deduped={len(deduped)} "
          f"(dropped {n_raw - len(deduped)})")
    print(f"train={len(train)} (vuln={n_pos}, clean={len(train) - n_pos}) "
          f"val={len(val)}")
    print("wrote data/train.curated.jsonl, data/val.jsonl")


if __name__ == "__main__":
    main()
