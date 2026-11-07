# Prompt-injection classifier (SG-028)

SwarmGuard used to catch prompt injections only by what an agent *did* afterwards (SG-012 and the live tripwire).
SG-028 also checks the **text itself**. Every untrusted input an agent reads is scored by a trained classifier: an
email, a web page, a tool result, or a ticket filed from outside.

- **Model:** logistic regression over hashed word 1–2-grams and character 4-grams.
- **Code:** `backend/app/modules/detection/injection_classifier.py`, with weights in `.../data/injection_model.json`
  (60k weights, 1 MB).
- **Cost:** pure Python with no extra packages, well under a millisecond per document.
- **Rebuild:** `python scripts/fetch_injection_datasets.py`, then `python scripts/train_injection_classifier.py`.
  Training takes about 15 seconds.

## What it was trained on

| Source | License | Used for |
|---|---|---|
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) (16,011 prompts) | MIT | Training |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), train split | Apache-2.0 | Training |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification), train split | Apache-2.0 | Training |
| Generated workspace-style examples (see below) | ours | Training |
| deepset test split, jackhhao test split, [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) test split | as above, MIT | **Evaluation only** |
| Our 18 hand-written scenario injections, plus 16 benign workspace documents | ours | **Evaluation only** |

The public datasets are mostly *direct* attacks typed by a user. Our threat is *indirect*: instructions hidden in
content an agent reads. So training adds 2,800 generated workspace-style examples:
- indirect injections assembled from the fuzzer's parts and from varied phrasings;
- benign work documents, including legitimate "upload to the approved partner" and "forward the notes" instructions,
  so the model learns intent, not the word "upload".

The 18 scenario texts used for evaluation were never trained on.

## Results on data it never trained on

The threshold is 0.5, picked on a validation split.

| Test set | Size | Precision | Recall | False-alarm rate |
|---|---|---|---|---|
| deepset test | 116 (60 injections) | 0.97 | 0.58 | 1.8% |
| jackhhao jailbreak test | 262 (139 jailbreaks) | 0.89 | 0.99 | 13.8% |
| Lakera Gandalf test (injections only) | 112 | — | 0.97 | — |
| **SwarmGuard scenarios + benign workspace docs** | 34 (18 injections) | **1.00** | **0.67** | **0%** |

The validation split (15% held out of the training mix) scores F1 0.99. That number is optimistic, because generated
examples resemble each other. The table above is the honest measure.

**What it catches** (score ≥ 0.9): the phishing email, a message posing as the planner, the worm notice, the
pre-filled reply, the "red-team drill", the sleeper note, the GDPR ticket, and the three-sources ticket.
**What it misses:**
- the fake policy update (0.13);
- the look-alike destination (0.26);
- the fake upload error (0.22);
- the poisoned memory note (0.37);
- the two halves of the split payload.

These read like ordinary policy pages or notices, and text alone can't tell them apart from real ones. That's why
the behaviour rules stay: SG-012, the tripwire, the egress allowlist and the proxy catch what the agent does next.

**Known weaknesses:**
- A linear model can be beaten by paraphrasing.
- Recall on deepset is low partly because some of that set is in German, and almost all training data is English.
- On jackhhao's benign role-play prompts it raises 14% false alarms. Those are chat prompts, not workspace documents;
  on our own documents it raised none.

## Two more detectors, and a plug-in for a stronger model

Beyond the trained linear model, SG-028's score is the highest of:
- the **trained model** (hashed word and character n-grams);
- a **policy-aware destination check**: untrusted content that names an external destination not on the deployment's
  allowlist (e.g. "uploads now go to X", "retry via Y"). This catches injections that read like ordinary policy pages,
  which wording-based models miss. On our 18 hand-written injections it lifted recall from 0.67 to **0.94** (17/18),
  at the cost of 1 false alarm on the attacker's own planted wiki page.

The classifier scores the text as written; it does not undo character-level obfuscation. Hidden characters, encoded
blobs and mixed-alphabet letters in agent messages are flagged separately by SG-020.

For deployments that want more than a linear model, set `SWARMGUARD_INJECTION_SCORER_URL` to a service running a
stronger classifier (e.g. Meta Prompt Guard on a GPU box): SwarmGuard POSTs `{"text"}`, expects `{"score": 0..1}`, and
takes the higher of the two scores. Any failure falls back to the built-in model, so it never breaks detection.

External, held-out benchmark (AgentDojo, five real models, `docs/swarm-traces.md`): recall 0.66 on 2,810 attacked tool
results, 0.10 false positives on clean ones.

## How it's used

- **SG-028 alert (always on).** A run-level alert names the source and who read it. The reader is not blamed. If the
  reader then acts out of policy, SG-012 blames it as before.
- **Live quarantine (opt-in).** Set `quarantine_live: true` in SG-028's params (Rules page or
  `PUT /api/detection-rules/SG-028`). In `contain` mode, untrusted content scoring ≥ `quarantine_threshold` (0.9) is then
  withheld before the agent reads it. Within that setting, a gullible model in the phishing scenario never sees the
  email. It's off by default, because withholding a legitimate email also has a cost.
- **Scope.** It covers everything reported through ingest, the SDK and the LangChain handler (`untrusted_tools`
  output), as well as simulated runs.
