const puppeteer = require("puppeteer-core");
const fs = require("fs");
const path = require("path");

const targetDirs = [
  path.resolve("c:/Users/Vyom/OneDrive/Documents/vedantaa/app/screenshots"),
  path.resolve("c:/Users/Vyom/OneDrive/Documents/vedantaa/swaram/app/screenshots"),
  path.resolve("c:/Users/Vyom/OneDrive/Documents/vedantaa/swaram/docs/screens/phase-final"),
];

for (const d of targetDirs) {
  fs.mkdirSync(d, { recursive: true });
}

const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const baseUrl = "http://127.0.0.1:5173";
const targetRunId = "run-9934e524";

const views = [
  {
    id: "01_overview",
    hash: "#/",
    description: "System Overview with verdict banner, 4 stat tiles, and recent alerts",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "01c_owasp_coverage",
    hash: "#/owasp",
    description: "OWASP Top 10 for Agentic Applications: 29 detection rules and pre-execution enforcement",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "01b_live_stream",
    hash: "#/live",
    description: "Live Guard & Gemini Quota monitoring view with agent pause/resume controls",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "02_incidents_evidence",
    hash: "#/incidents",
    description: "Incident deep dive with Evidence tab and raw event JSON slide-over drawer open",
    action: async (page) => {
      await page.waitForSelector("button", { timeout: 8000 });
      // Switch to Evidence tab
      const buttons = await page.$$("button");
      for (const b of buttons) {
        const text = await page.evaluate((el) => el.textContent, b);
        if (text && text.includes("Evidence")) {
          await b.click();
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 600));

      // Click on first evidence chip/row to open slide-over drawer
      const chip = await page.$(".incident-evidence-chip, .incident-evidence-row, [data-event-id]");
      if (chip) {
        await chip.click();
        await new Promise((r) => setTimeout(r, 800));
      } else {
        const rows = await page.$$("tbody tr, div[class*='cursor-pointer']");
        if (rows.length > 0) {
          await rows[0].click();
          await new Promise((r) => setTimeout(r, 800));
        }
      }
    },
  },
  {
    id: "02b_incidents_bayesian",
    hash: "#/incidents",
    description: "Incident view with Bayesian Attribution & Multi-Agent Risk Breakdown",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "02c_incidents_response",
    hash: "#/incidents",
    description: "Incident view on Response & Mitigation tab showing isolation controls",
    action: async (page) => {
      const buttons = await page.$$("button");
      for (const b of buttons) {
        const text = await page.evaluate((el) => el.textContent, b);
        if (text && text.includes("Response & Mitigation")) {
          await b.click();
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "03_swarm_topology",
    hash: "#/swarm",
    description: "Circular Swarm Topology graph with agent nodes, evidence links, and timeline",
    action: async (page) => {
      await page.waitForSelector("svg", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 800));
    },
  },
  {
    id: "03b_swarm_agent_drawer",
    hash: "#/swarm",
    description: "Swarm Topology with Agent Detail slide-over drawer open",
    action: async (page) => {
      await page.waitForSelector("svg circle", { timeout: 8000 });
      // Click an agent node in the SVG circle
      const circles = await page.$$("svg circle");
      if (circles.length > 1) {
        await circles[1].click();
        await new Promise((r) => setTimeout(r, 800));
      }
    },
  },
  {
    id: "04_responses_review_queue",
    hash: "#/responses",
    description: "Human-in-the-loop review queue card and honesty enforcement pills",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      // Click 'Pending' tab to verify interactivity
      const tabs = await page.$$("button");
      for (const t of tabs) {
        const text = await page.evaluate((el) => el.textContent, t);
        if (text && text.trim() === "Pending") {
          await t.click();
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "05_evaluation_metrics",
    hash: "#/evaluation",
    description: "Evaluation dashboard with 8 benchmark tiles and missing-log resilience curve",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 800));
    },
  },
  {
    id: "06_pipeline_simulator",
    hash: "#/pipeline/simulator",
    description: "Simulation configuration pipeline with scenario and drop rate parameters",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "07_pipeline_collector",
    hash: "#/pipeline/collector",
    description: "Telemetry collector, event normalizer, and deduplication pipeline",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
  {
    id: "08_pipeline_detection_rules",
    hash: "#/pipeline/detection",
    description: "Threat detection matrix with 20 rules categorized across 4 threat domains",
    action: async (page) => {
      await page.waitForSelector("button", { timeout: 8000 });
      // Switch to 'Rules (20)' tab on Detection page
      const buttons = await page.$$("button");
      for (const b of buttons) {
        const text = await page.evaluate((el) => el.textContent, b);
        if (text && text.includes("Rules (20)")) {
          await b.click();
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 800));
    },
  },
  {
    id: "08b_pipeline_detection_observability",
    hash: "#/pipeline/detection",
    description: "12-Component Observability Framework: Simulator vs Collector architecture",
    action: async (page) => {
      await page.waitForSelector("button", { timeout: 8000 });
      // Switch to 'Observability (12)' tab on Detection page
      const buttons = await page.$$("button");
      for (const b of buttons) {
        const text = await page.evaluate((el) => el.textContent, b);
        if (text && text.includes("Observability (12)")) {
          await b.click();
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 800));
    },
  },
  {
    id: "09_pipeline_response",
    hash: "#/pipeline/response",
    description: "Automated response policy engine, quarantine rules, and webhook routing",
    action: async (page) => {
      await page.waitForSelector(".card", { timeout: 8000 });
      await new Promise((r) => setTimeout(r, 600));
    },
  },
];

const resolutions = [
  { label: "1920x1080", w: 1920, h: 1080 },
  { label: "1280x720", w: 1280, h: 720 },
];

async function runAudit() {
  console.log("=== SwaramGuard Full Interactive Audit & Visual Verification ===");
  console.log(`Target Run: ${targetRunId}`);
  console.log(`Base URL: ${baseUrl}`);
  console.log(`Theme: Locked Pure Apple Light Mode\n`);

  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--hide-scrollbars",
    ],
  });

  const errors = [];
  const warnings = [];

  try {
    for (const res of resolutions) {
      console.log(`\n------------------ Capturing at ${res.label} ------------------`);
      const page = await browser.newPage();
      await page.setViewport({ width: res.w, height: res.h, deviceScaleFactor: 1 });
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "light" }]);

      page.on("console", (msg) => {
        const text = msg.text();
        if (msg.type() === "error") {
          console.error(`[Browser Error] ${text}`);
          errors.push({ resolution: res.label, text });
        } else if (msg.type() === "warn" && !text.includes("Download the React DevTools")) {
          warnings.push({ resolution: res.label, text });
        }
      });

      page.on("pageerror", (err) => {
        console.error(`[Uncaught Page Error] ${err.message}`);
        errors.push({ resolution: res.label, text: err.message });
      });

      // Warm up first page load with target URL directly
      await page.goto(`${baseUrl}/#/`, { waitUntil: "networkidle0", timeout: 15000 });
      await page.evaluate((activeRun) => {
        try {
          localStorage.setItem("sg_theme", "light");
          localStorage.setItem("swaramguard.selectedRun", activeRun);
          document.documentElement.setAttribute("data-theme", "light");
        } catch {}
      }, targetRunId);

      for (const view of views) {
        const filename = `${view.id}_light_${res.label}.png`;
        const url = `${baseUrl}/${view.hash}`;

        await page.goto(url, { waitUntil: "networkidle0", timeout: 15000 }).catch(() => {});
        await new Promise((r) => setTimeout(r, 600));

        // Execute view-specific interactions
        try {
          if (view.action) {
            await view.action(page);
          }
        } catch (actionErr) {
          console.warn(`[Action Warning] ${view.id}: ${actionErr.message}`);
        }

        // Forensic UI assertions
        const pageText = await page.evaluate(() => document.body.innerText);
        
        // Assert no decorative emojis
        const emojiRegex = /[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/u;
        if (emojiRegex.test(pageText)) {
          console.warn(`[EMOJI WARNING] View ${view.id} contains decorative emojis!`);
        }

        // Take snapshot across all target directories
        const primaryPath = path.join(targetDirs[0], filename);
        await page.screenshot({ path: primaryPath, fullPage: false });

        for (let i = 1; i < targetDirs.length; i++) {
          fs.copyFileSync(primaryPath, path.join(targetDirs[i], filename));
        }

        const sizeKb = (fs.statSync(primaryPath).size / 1024).toFixed(1);
        console.log(`✓ [${res.label}] ${view.id} -> ${filename} (${sizeKb} KB) - ${view.description}`);
      }

      await page.close();
    }

    console.log("\n=== Audit Summary ===");
    console.log(`Total views captured: ${views.length * resolutions.length}`);
    console.log(`Browser Errors Logged: ${errors.length}`);
    if (errors.length > 0) {
      console.log("Logged errors:", JSON.stringify(errors, null, 2));
    } else {
      console.log("Zero browser errors detected during audit!");
    }
  } finally {
    await browser.close();
  }
}

runAudit().catch((err) => {
  console.error("Audit script failed:", err);
  process.exit(1);
});
