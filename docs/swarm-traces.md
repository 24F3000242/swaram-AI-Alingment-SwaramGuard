# Outside proof: real multi-agent incident and benchmark data

Our multi-agent detection used to be measured only on scenarios we wrote. These are results on data from outside the
project: a real swarm-of-agents intrusion, and real model traces from a public benchmark. Both are held out — nothing
was trained or tuned on them.

## 1. Swarm Traces incident (covert channels, SG-029)

[Swarm Traces](https://swarmtraces.org/) is the reassembled payload set from a real intrusion by a swarm of agents,
with credentials and infrastructure redacted by its publishers. It is ~190k rows of payloads, recovered text and
responses. We treat every row as evidence (read as text, never executed) and score it with the SG-029 covert-transfer
detector. Reproduce with `python scripts/fetch_swarm_traces.py && python scripts/analyze_swarm_traces.py`.

| | Result |
|---|---|
| Attack rows scored | 166,571 |
| Flagged as covert staged transfer | 32,718 |
| Benign baseline (ordinary agent/web output) | 16 samples, **0 flagged** |

Which signals fired: credential sent outside 27,510; assemble-and-run 9,440; decoder-plus-executor 8,810; remote-script
pull 1,039; fragment chain 350.

**Honest reading.** The detector is deliberately conservative: it needs two signals, or a credential leaving. It
flags the loader and exfiltration rows, not every inert data fragment, so the headline is "32,718 real covert-transfer
rows caught with zero benign false positives", not a percentage of all rows. The `fragment_chain` signal is
undercounted here because the next-hop URLs were redacted (`[SHORTENER URL ...]`), so the visible `//` the shape needs
is gone; on live, un-redacted traffic it would fire far more.

**Coordination structure.** The same data shows real agent-to-agent spread: 28,086 distinct destinations, of which
**1,535 were reached from more than one agent identifier**, one of them from 2,165 different identifiers. That shared
fan-out is the multi-agent-oversight signal — many agents funnelling to the same drop points.

## 2. AgentDojo traces (injection classifier, SG-028)

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich, MIT) publishes every run of its benchmark: real
model conversations where an attacker's text was planted in a tool result. We replay the tool results through the
SG-028 classifier (`python scripts/fetch_agentdojo_runs.py && python scripts/replay_agentdojo.py`). Five models, none
of which the classifier trained on.

| | Result |
|---|---|
| Attacked tool results | 2,810 |
| Caught (recall) | **0.66** |
| Clean tool results | 1,841 |
| False positives | 0.10 |

Per model, recall is steady (Claude 3.5 Sonnet 0.61, Gemini 2.0 Flash 0.65, GPT-4o 0.65, GPT-4o-mini 0.65,
Llama 3.3 70B 0.70). The 10% false-positive rate on clean results is higher than on our own workspace documents (0%):
AgentDojo's clean tool results are long emails, calendars and transaction lists, and the linear model over-fires on
some. This is the classifier's honest ceiling, and the reason the behaviour rules and the egress controls stay the
real enforcement. It also measures only the content signal; in a live run SG-012 and the tripwire act on what the
agent does next.
