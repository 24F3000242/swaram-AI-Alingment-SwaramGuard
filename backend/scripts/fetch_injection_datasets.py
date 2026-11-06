"""Download the public prompt-injection datasets used to train and test the injection classifier.

    python scripts/fetch_injection_datasets.py        # -> datasets/injection/<name>-<split>.jsonl

Rows are read as plain text through the Hugging Face datasets-server API (no extra packages). Only datasets with an
open license are used:
- deepset/prompt-injections (Apache-2.0): train -> training, test -> held-out evaluation
- jackhhao/jailbreak-classification (Apache-2.0): train -> training, test -> held-out evaluation
- reshabhs/SPML_Chatbot_Prompt_Injection (MIT): training
- Lakera/gandalf_ignore_instructions (MIT): test -> held-out evaluation (injections only, so it measures recall)
"""
from __future__ import annotations

import csv
import io
import json
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "datasets" / "injection"
API = "https://datasets-server.huggingface.co/rows"

SOURCES = {  # name -> (dataset, splits, row -> (text, label 0/1))
    "deepset": ("deepset/prompt-injections", ("train", "test"), lambda r: (r["text"], int(r["label"]))),
    "jailbreak": ("jackhhao/jailbreak-classification", ("train", "test"),
                  lambda r: (r["prompt"], 1 if r["type"] == "jailbreak" else 0)),
    "spml": ("reshabhs/SPML_Chatbot_Prompt_Injection", ("train",),
             lambda r: (r["User Prompt"], int(r["Prompt injection"]))),
    "gandalf": ("Lakera/gandalf_ignore_instructions", ("test",), lambda r: (r["text"], 1)),
}


def fetch(dataset: str, split: str, convert) -> list[dict]:
    rows, offset = [], 0
    with httpx.Client(timeout=60) as c:
        while True:
            for attempt in range(8):  # the public API rate-limits: back off and retry
                r = c.get(API, params={"dataset": dataset, "config": "default", "split": split,
                                       "offset": offset, "length": 100})
                if r.status_code == 200:
                    break
                time.sleep(min(60, 5 * 2 ** attempt))
            time.sleep(0.5)
            r.raise_for_status()
            batch = r.json()["rows"]
            for item in batch:
                text, label = convert(item["row"])
                if isinstance(text, str) and text.strip():
                    rows.append({"text": text, "label": label})
            offset += len(batch)
            if len(batch) < 100:
                return rows


CSV_FILES = {  # large datasets: one raw CSV download instead of hundreds of rate-limited row requests
    "reshabhs/SPML_Chatbot_Prompt_Injection": "spml_prompt_injection.csv",
}


def fetch_csv(dataset: str, convert) -> list[dict]:
    url = f"https://huggingface.co/datasets/{dataset}/resolve/main/{CSV_FILES[dataset]}"
    r = httpx.get(url, timeout=120, follow_redirects=True)
    r.raise_for_status()
    rows = []
    for row in csv.DictReader(io.StringIO(r.text)):
        text, label = convert(row)
        if isinstance(text, str) and text.strip():
            rows.append({"text": text, "label": label})
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (dataset, splits, convert) in SOURCES.items():
        for split in splits:
            path = OUT / f"{name}-{split}.jsonl"
            if path.exists() and "--force" not in sys.argv:
                print(f"{path.name}: already there", flush=True)
                continue
            rows = fetch_csv(dataset, convert) if dataset in CSV_FILES else fetch(dataset, split, convert)
            path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            print(f"{path.name}: {len(rows)} rows, {sum(r['label'] for r in rows)} injections", flush=True)


if __name__ == "__main__":
    main()
