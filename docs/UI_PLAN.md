# SwarmGuard Dashboard: Apple-Style UX/UI Redesign Plan

Owner: Member 5 (Dashboard & Evaluation). Executor: Anto (coding agent).
Drop this file in the repo as `docs/UI_PLAN.md`. Work in `dashboard/` on branch `member-5-dashboard`.

---

## 0. Kickoff prompt (paste this to Anto first)

> You are redesigning the **presentation layer only** of the SwarmGuard dashboard (Vite app, `localhost:5173`).
> Read `docs/UI_PLAN.md` fully, then inspect the repo and list: routes, components, CSS files, data hooks, dependencies.
> Rules:
> 1. Do NOT change API calls, data hooks, JSONL/SQLite handling, or the shared schemas in `shared/contracts.md`.
> 2. Work phase by phase (section 9). After each phase, run the app, take screenshots at 1920x1080 and 1280x720 in light AND dark mode, save them to `docs/screens/phase-N/`, and tell me what changed.
> 3. Never show a simulated action as "blocked". Only `mode === "enforced"` may use that word. Keep/ add the unit test (section 7).
> 4. No invented metrics. If a number is not in the data, show "Not run yet".
> 5. Use design tokens from section 3 only. No hard-coded colors, sizes or shadows in components.
> 6. Stop and ask if a requirement conflicts with existing code.

---

## 1. Review of the current UI (from 26 screenshots)

The app works and is not a blank slate: there are 5 module pages, real data, a threat matrix, an agent graph, a swimlane timeline, a risk ranking and an evaluation suite. The skeleton (light gray canvas, white rounded cards, big page titles, segmented Table/JSON toggle, pill buttons) is already in the right direction. The problem is not the components, it is the **structure, density and noise**.

### Scorecard

| Area | Score /10 | Why |
|---|---|---|
| Apple look and feel | 5 | Right bones, but too many accent colors (orange eyebrow, purple "Layer" pill, mint-to-lilac gradient banner, blue links, red/orange/green dots) |
| Information architecture | 4 | Organized by teammate ("Module 1..5", "(MEMBER 3)" labels visible), not by what a judge wants to see |
| First impression | 4 | Landing page is a simulator config form. The incident story is on the last page |
| Evidence clarity | 6 | Strong content (event IDs, Bayesian "why this agent", graph), but the Evidence panel is empty by default: "Select an alert to inspect its evidence chain" |
| Readability | 5 | Table text is about 12px gray, IDs truncated (`agt-…-03`, `Unauthorized access t…`), tables overflow to the right and cut off the severity column |
| Simulated vs enforced honesty | 8 | `would block` + `simulated` pills and "Containment (gateway-enforced) 0.0%" are honest and good. Keep this |
| Page length / scanning | 3 | Threat Detection is a scroll of 20 checkbox rules before you reach findings |
| Visual hierarchy of the hero visual | 4 | Agent graph (your best visual) is small, half-width, tiny labels |
| **Overall** | **5 / 10** | Solid foundation, needs a re-organization more than a re-skin |

### Specific problems to fix

1. **Org-chart navigation.** Sidebar mirrors team roles. Judges think in "what happened, why, what did we do, does it work".
2. **Config before findings.** Every page opens with a form (Run simulation, Run detection, Apply policy). Controls should be secondary.
3. **Internal jargon on screen.** "System 2 (Explicit Rule)", "Layer: System 2", "SEC-01", "SG-001", "(MEMBER 3)", OWASP codes. Replace with plain English; keep codes as small secondary text.
4. **Color overload.** Apple uses one accent. Here: blue + orange + purple + mint + red + green + amber all compete.
5. **Repeated chrome.** The five green dots (simulated, collected, detected, responded, evaluated) appear on every page and in the sidebar. Search + Table/JSON + Export repeated on every table.
6. **Truncated and horizontally scrolling tables.** Show 4 to 5 columns max, move the rest to a detail drawer.
7. **Strong claims without footnotes.** "VERIFIED RESILIENT", "PASSED: 225", "100% precision" read as marketing. They are measured on synthetic data and must say so (footnote system, section 5).
8. **Tiny type.** Body and table text must be 14px or larger.
9. **Empty default states.** Auto-select the highest-severity alert so the evidence is visible immediately.

### Keep as-is (already good)

Rounded cards, large page titles, segmented Table/JSON, "Why this agent" posterior explanation, missing-log resilience concept, honest gateway-enforced containment metric, red path in the graph, swimlane timeline concept.

---

## 2. What we borrow from apple.com/in/store

Observed on the page (structure, not pixel specs): a slim translucent **global nav** with centered links; one huge **page title** ("Store") with a single-line subtitle; a small **quick-links row** under the title (Find a Store, Order Status, Shopping Help, Your Saves); large rounded **tiles** with generous space; and a **footnote system** where claims carry symbols (◊ ∆ ± † ‡) explained at the bottom of the page.

Translate to SwarmGuard:

| Apple pattern | SwarmGuard equivalent |
|---|---|
| Translucent global nav | Top bar replaces the left sidebar (frees width for graph and tables) |
| Giant title + one-line subtitle | Each page: one title, one sentence |
| Quick-links row | Overview shortcuts: Latest incident, Run a scenario, Export report, See evaluation |
| Big rounded tiles | Stat tiles, agent tiles, response cards |
| Footnote symbols | Every metric/claim gets † ‡ with a caveat (synthetic data, simulation mode) |
| Sticky local nav (product pages) | Sticky sub-tabs inside a page (e.g. Incident: Summary / Evidence / Response) |
| Restraint | One accent color. Color means severity or mode only |

Note: exact Apple tokens below are my approximation of Apple's design language, not values scraped from their CSS.

---

## 3. Design tokens (`src/theme/tokens.css`)

```css
:root {
  /* type */
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", Inter, "Segoe UI", system-ui, sans-serif;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;

  /* surfaces */
  --bg: #ffffff;
  --bg-alt: #f5f5f7;          /* alternate section bands */
  --card: #ffffff;
  --card-alt: #fbfbfd;
  --hairline: #d2d2d7;

  /* text */
  --text: #1d1d1f;
  --text-2: #6e6e73;
  --text-3: #86868b;

  /* the ONE accent */
  --accent: #0071e3;
  --accent-hover: #0077ed;
  --link: #0066cc;

  /* semantic (use only for severity / mode / status) */
  --crit: #d70015;   --crit-bg: rgba(215, 0, 21, .08);
  --high: #c93400;   --high-bg: rgba(201, 52, 0, .08);
  --med:  #a05a00;   --med-bg:  rgba(160, 90, 0, .08);
  --low:  #6e6e73;   --low-bg:  rgba(110, 110, 115, .10);
  --ok:   #248a3d;   --ok-bg:   rgba(36, 138, 61, .08);

  /* shape */
  --r-card: 18px;  --r-tile: 24px;  --r-btn: 980px;  --r-input: 12px;
  --shadow-1: 0 1px 2px rgba(0,0,0,.04), 0 4px 16px rgba(0,0,0,.05);
  --shadow-2: 0 8px 30px rgba(0,0,0,.12);

  /* glass nav */
  --glass: rgba(255,255,255,.72);
  --glass-blur: saturate(180%) blur(20px);

  /* motion */
  --ease: cubic-bezier(.28, .11, .32, 1);
  --t-fast: 180ms;  --t-base: 300ms;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { /* mirror in [data-theme="dark"] too */
    --bg: #000000;  --bg-alt: #101012;  --card: #1c1c1e;  --card-alt: #232326;
    --hairline: #3a3a3c;
    --text: #f5f5f7;  --text-2: #a1a1a6;  --text-3: #86868b;
    --accent: #2997ff;  --accent-hover: #4aa8ff;  --link: #2997ff;
    --crit: #ff453a;  --high: #ff9f0a;  --med: #ffd60a;  --low: #98989d;  --ok: #30d158;
    --glass: rgba(29,29,31,.72);
    --shadow-1: 0 1px 2px rgba(0,0,0,.5);
  }
}
```

### Type scale

| Role | Size / weight | Notes |
|---|---|---|
| Page title | 56px / 600, letter-spacing -0.015em, line-height 1.07 | 40px under 900px width |
| Page subtitle | 21px / 400, `--text-2` | max 1 line to 2 lines, max-width 640px |
| Section title | 32px / 600 | |
| Card title | 21px / 600 | |
| Body | 17px / 400, line-height 1.47 | |
| Table / dense UI | 14px minimum | Never below 14px |
| Caption / footnote | 12px / 400, `--text-3` | footnotes only |
| Mono IDs | 13px `--mono` | |

### Layout

- Content max-width 1120px, centered, 24px side padding. Graph and timeline may break out to 1280px.
- Vertical rhythm: sections 96px apart, cards 24px gap. Alternate `--bg` and `--bg-alt` bands.
- No hard borders on cards. Use `--shadow-1` or a 1px `--hairline` only inside tables.

### Color usage rules

1. Accent blue is for primary buttons, links, focus and selected state. Nothing else.
2. Red/orange/amber/gray = severity (critical/high/medium/low). Green = enforced or healthy. Gray dashed = simulated.
3. No gradients except the nav glass. Delete the mint-lilac banner.
4. Pills only for severity and mode. Everything else is plain text.

---

## 4. Information architecture

Replace the left sidebar with a **global top bar** (48px, glass, sticky):

`SwarmGuard` (left) · **Overview · Incidents · Swarm · Responses · Evaluation · Pipeline** (center) · run selector pill + theme toggle (right)

| Old | New | Notes |
|---|---|---|
| Module 5 Dashboard | **Overview** | Becomes the landing page |
| Module 3 alerts + evidence | **Incidents** | Alerts list + auto-opened detail |
| Graph + timeline + agents | **Swarm** | Big graph, timeline, agent tiles |
| Module 4 response log | **Responses** | Cards, mode pills |
| Module 5 metrics + suite | **Evaluation** | Tiles + chart + footnotes |
| Modules 1 to 4 pages | **Pipeline** (secondary) | Keep working: Simulator, Collector, Detector, Policy as sub-tabs. These hold the run/config forms |

Route map (hash routing stays): `#/` overview · `#/incidents/:alertId?` · `#/swarm` · `#/responses` · `#/evaluation` · `#/pipeline/{simulator|collector|detection|response}`. Old routes (`#/detection`, `#/dashboard`, ...) must redirect to the closest new one.

Run selector: global, in the top bar, remembers last selection. Replaces "Input dataset" dropdowns on every page.

---

## 5. Honesty system (judges will check this)

- **Footnotes, Apple-style.** Any metric or claim gets a symbol; page ends with a footnote block.
  - `†` Measured on labeled synthetic scenarios, not real traffic.
  - `‡` Simulation mode: decisions are recorded, no tool call was actually stopped.
  - `§` Missing-log runs drop events at random with fixed seeds.
  - Footer line on every page: "A detection is not proof of compromise."
- **ModePill**
  - `simulation` → gray dashed outline, text **"Would deny (replay)"** / "Would pause (replay)" / "Alert only".
  - `enforced` → solid green, lock icon, text **"Blocked at gateway"**.
  - The word "blocked" must never render unless `mode === "enforced"`.
- Remove "VERIFIED RESILIENT". Use a neutral heading: "Detection accuracy on synthetic scenarios†".
- If an evaluation value is absent: render "Not run yet" with a "Run evaluation" link. Never a placeholder number.
- Ground-truth labels appear on Evaluation only, never in Incidents or Swarm.

---

## 6. Page specs

### 6.1 Overview (`#/`)

- Title **"SwarmGuard."**  Subtitle: "Watching how your agents work together, and flagging when they shouldn't."
- Quick links row (text links with chevron): Latest incident › · Run a scenario › · Export report › · See evaluation ›
- **Verdict tile** (full width, large, `--card`): one sentence from data, e.g. "3 incidents in run-06ce195c. 2 agents flagged." Left: severity breakdown as small dots + counts. Right: primary button **Open incident** (goes to the highest severity alert).
- **Stat tiles** (4 across, 1 big number each, thin weight 48px): Agents · Events · Incidents · Responses. Subtext 14px.
- **Pipeline status** as ONE compact horizontal stepper (Simulated → Collected → Detected → Responded → Evaluated) shown only on Overview. Delete the dots from sidebar and every other page.
- Below: "Latest incidents" (top 3 as cards: severity dot, plain-English title, agents, time) and "Mode" card showing simulation vs enforced counts.

### 6.2 Incidents (`#/incidents/:alertId?`)

Split view. Left 360px list, right detail. Auto-select highest severity on load. Never show an empty state if alerts exist.

**List item:** severity dot + short plain-English title ("Customer PII sent to external paste site"), agent names ("coder"), relative time. Rule code (SG-002) small gray.

**Detail (sticky sub-tabs: Summary · Evidence · Response):**
- Large title = alert summary in one sentence. Under it: rule name, detection time.
- **ScoreRing** (0 to 1, ring fills, number centered, severity-colored) next to severity label.
- **What happened**: ordered event chips (`evt_0002 → evt_0003`) in a horizontal stepper. Click chip → right drawer with raw JSON (monospace) + copy button. Every alert event_id must resolve; if not, show "Event not found in collector" in `--high`.
- **Why we flagged it**: 2 to 3 plain sentences + collapsible "How this was scored" holding the Bayesian explanation and rare-for-role bits already built.
- **What we did**: linked response card with ModePill and `reason`.
- Footnote block (†, ‡).

### 6.3 Swarm (`#/swarm`)

- **Graph** full width (1280px, min 520px tall). Nodes: 56px circles with role initial, name below at 14px. Edges: 1.5px `--hairline`. Suspicious path: `--crit`, 3px, subtle animated dash (disabled under reduced motion). Hidden-channel edge: dashed. Click node → drawer with agent role, permissions, risk %, events. Legend moves to a single line below.
- **Timeline** swimlane under the graph: lanes per agent, dots 10px, flagged dots red with halo, hover tooltip (time, action, resource, event_id). Time axis labeled. Brush to zoom is optional (stretch).
- **Agent tiles** (grid, 3 across): name, role, status dot, risk %, 3 mini counts. Flagged agents get a 1px `--crit` hairline and "Flagged" text, not a filled red block.

### 6.4 Responses (`#/responses`)

Vertical list of cards: decision (large), ModePill, alert link chip, agent(s), `reason`, timestamp. Top of page: a one-sentence banner that depends on data. If all are simulation: "All 3 responses were recorded in simulation. No action was actually stopped.‡" Group by mode when both exist.

### 6.5 Evaluation (`#/evaluation`)

- Title "Does it work?" Subtitle: "Accuracy on labeled synthetic scenarios, including missing logs.†"
- Tiles (4 across): Precision · Recall · False positives · Detection latency. Second row: Containment (decisions) · Containment (gateway-enforced) · Evidence coverage · TP/FP/FN/TN.
- **Missing-log chart** replaces the four small boxes: line or bar chart, x = events dropped (0, 10, 30, 50%), y = % attacks caught, two series: SwarmGuard vs per-agent-only baseline (if baseline data exists; otherwise show only SwarmGuard and state "baseline not run"). 
- Run controls (agents per run, drop rates, seeds, Run suite) go inside a "Run settings" sheet (button top right), not inline.
- Ground-truth labeled scenario table at the bottom.

### 6.6 Pipeline (secondary, `#/pipeline/...`)

Keep all four module pages functional with minimal changes:
- Hide "Module N" eyebrow and "(MEMBER N)" strings. Use plain titles: Agent simulator, Event collector, Threat detection, Security response.
- Page opens with **results first**, config in a "Run settings" button → sheet.
- **Detection rules**: collapse the 20-rule matrix into one searchable list grouped by the 4 categories (Data & access, Behaviour & intent, Loss of control, Multi-agent & system). Each rule: name, one line, severity dot, iOS-style toggle. 20 rows must not push findings off screen: render it behind a "Rules (20)" tab.
- Raw / normalized event tables: sticky header, 5 columns, row click → drawer.

---

## 7. Component inventory (`src/components/`)

| Component | Spec |
|---|---|
| `GlobalNav` | 48px, glass, sticky, active item has 2px accent underline, keyboard accessible |
| `PageHeader` | title + subtitle + optional quick links |
| `Tile` | 24px radius, 32px padding, label 14px `--text-2`, value 48px/300 or 600 |
| `Card` | 18px radius, `--shadow-1`, hover lift 2px only when clickable |
| `Pill` | severity variants (crit/high/med/low), 12px caps-free, 6px 12px padding |
| `ModePill` | see section 5. **Unit test:** render for each mode; assert "blocked" text appears only when `mode === "enforced"` |
| `ScoreRing` | SVG ring, 120px, animates 0 to value in 600ms with `--ease` |
| `EvidenceChip` | mono 13px, hairline outline, click opens `Drawer` |
| `Drawer` | right sheet 480px, backdrop blur, Esc closes, focus trapped |
| `Segmented` | existing Table/JSON toggle, restyled to iOS segmented control |
| `DataTable` | 14px, sticky header, 5-column cap, row click → drawer, no horizontal scroll at 1280px |
| `Stepper` | pipeline status and evidence chain |
| `Footnotes` | collects symbols used on page, renders block at the bottom |
| `EmptyState` | icon, one sentence, one action. Never a bare gray sentence |
| `Skeleton` | shimmer placeholder while loading |
| `ThemeToggle` | light / dark / system, persists |

Buttons: primary = filled `--accent`, radius 980px, 17px, height 44px. Secondary = `--bg-alt` fill, text `--text`. Link buttons = `--link` with trailing chevron.

---

## 8. Copy and data-display rules

1. No team names or module numbers anywhere in UI text.
2. Replace "System 2 (Explicit Rule)" with "Rule-based". Replace "Layer: ..." pills with nothing.
3. Plain titles first, codes second: "Customer PII sent to external paste site" with `SG-002` small and gray.
4. Never truncate IDs with an ellipsis in the middle. Show the short agent name ("coder") and the full ID on hover with a copy button. Event IDs always in full in mono.
5. Times: relative ("2 min ago") with absolute UTC on hover. Keep ISO-8601 UTC in raw JSON and drawers.
6. Sentence case everywhere. No emoji. Icons from `lucide-react` (or existing icon set) at 1.5px stroke.
7. Numbers: tabular figures (`font-variant-numeric: tabular-nums`).

---

## 9. Build phases for Anto (stop after any phase and still have a demoable app)

**Phase 0: Foundation (about 1.5 h)**
- Add `tokens.css`, type scale, dark-mode variables, base resets.
- Build `GlobalNav`, `PageHeader`, `Card`, `Tile`, `Pill`, `ModePill` (+ test), `Footnotes`, `ThemeToggle`.
- Replace sidebar with top bar; add route redirects; move run selector into the bar.
- Remove: "Module N" eyebrows, "(MEMBER N)" text, pipeline dots from sidebar, gradient banner.
- Screenshot check: every existing page still loads.

**Phase 1: The story (about 3 h)**
- Overview page (6.1) and Incidents page (6.2) with `Drawer`, `EvidenceChip`, `ScoreRing`.
- Auto-select top alert. All evidence resolves or shows the not-found state.
- This phase alone is the demo.

**Phase 2: Proof (about 3 h)**
- Swarm (6.3), Responses (6.4), Evaluation (6.5) with the missing-log chart and footnotes.

**Phase 3: Clean-up (about 2 h)**
- Pipeline pages restyled (6.6), rules tab, "Run settings" sheet, table 5-column cap, row drawers.
- Skeletons and empty states everywhere.

**Phase 4: Polish and ship (about 1.5 h)**
- Dark mode pass on every page, focus rings, reduced motion, 1280px and 768px layouts.
- Screenshots for `docs/evaluation.md` (light + dark, each page).
- Lighthouse accessibility 90+ on Overview and Incidents.

---

## 10. Definition of done

- [ ] Landing page is Overview and shows the incident verdict without scrolling at 1920x1080.
- [ ] An alert's evidence is visible within one click from the landing page (zero clicks inside Incidents).
- [ ] Every alert's `event_ids` open raw event JSON; missing ones are flagged, not hidden.
- [ ] No horizontal scrollbar at 1280px on any page.
- [ ] Body and table text 14px or larger; contrast AA in light and dark.
- [ ] Only one accent color on screen; severity and mode are the only other colors.
- [ ] "blocked" appears only for `enforced` (unit test passes).
- [ ] No "Module N", "(MEMBER N)", "System 2", or mid-ellipsis truncated IDs in UI.
- [ ] Every metric has a † or ‡ where it comes from synthetic data or simulation.
- [ ] Missing data shows "Not run yet", never a made-up value.
- [ ] Old hash routes redirect; run selection persists across pages.
- [ ] Works with fixtures only (no teammate online) and with the live API.

---

## 11. Do not

- Do not change `shared/contracts.md`, event/alert/response field names, or API payloads.
- Do not add libraries beyond what is needed for charts and animation (`recharts` or `visx`, optional `framer-motion`). No Streamlit.
- Do not add more colors, gradients, shadows or font sizes than the tokens define.
- Do not delete working Pipeline functionality. Demote and restyle it.
- Do not present simulated results as real enforcement anywhere, including screenshots and the README.
