# Dataset generator (AI-mode runs)

Generates many runs where each agent's model (Gemini) decides its own actions, then exports them in the
existing 12-field canonical JSONL format and scores them with Threat Detection.

```bash
cd backend
python scripts/generate_dataset.py --dry-run             # plan + model-call estimate
python scripts/generate_dataset.py --runs 3 --learn 3    # writes ../datasets/<date>/
python scripts/generate_dataset.py --out ../datasets/night1   # same folder again = resume
python scripts/generate_dataset.py --live-guard contain   # also stop hijacked agents mid-run
```

Needs `GEMINI_API_KEY` in `backend/.env`. The free tier allows 15 calls/min and **500 calls/day** on Flash-Lite
(measured Nov 2026), so a 5-agent run (~16 calls) takes about a minute and one key manages ~30 runs a day.
The local cap is `GEMINI_DAILY_BUDGET` (default 100 calls/day; set it to 480 for a full-day batch). If the quota
runs out mid-batch the generator stops; run the same command later and it continues where it left off.
`datasets/` is gitignored.

## Output folder

| File | For | Contents |
|---|---|---|
| `events/<run_id>.jsonl` | **Data Optimizer (member 2)** | Canonical 12-field events, one file per run. Same contract as before; no labels inside. |
| `labels.jsonl` | Evaluation | One line per run: scenario, seed, agents (role, permissions), ground-truth culprits and events, AI counts. |
| `detection.jsonl` | Threat Detection | Alerts per run, agents caught / missed / falsely flagged. |
| `summary.md` / `summary.json` | Everyone | Hijack rate per attack, recall, precision, false alarms; with `--live-guard contain`, runs where data left, attacks stopped before the first harmful action, innocent agents paused. |
| `baseline_profile.json` | Threat Detection | Baseline after learning the batch's clean runs. |

**Only new thing in the events:** `details.ai_trace` on events an agent's model caused:
`backend`, `model`, `round`, `source` (`model` or `fallback`), `decision` (raw model reply), `refused`
(what it declined and why), `exposed_to_untrusted` (it had just read planted content). It is an extra key
inside `details`, so existing parsers can ignore it.

**Ground truth:** labels are outcome-based. An agent is a culprit if it was a scripted attacker or if its own
model took an action outside its policy (for example after a prompt injection). Learning runs are clean
`normal_collaboration` runs folded into the baseline before the test runs.
