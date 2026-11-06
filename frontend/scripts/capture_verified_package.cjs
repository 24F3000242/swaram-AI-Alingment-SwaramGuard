const puppeteer = require("puppeteer-core");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const targetDirs = [
  path.resolve("c:/Users/Vyom/OneDrive/Documents/vedantaa/app/screenshots"),
  path.resolve("c:/Users/Vyom/OneDrive/Documents/vedantaa/swaram/app/screenshots"),
];

for (const d of targetDirs) {
  fs.mkdirSync(d, { recursive: true });
}

const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const baseUrl = "http://127.0.0.1:5173";

const pages = [
  { name: "01_overview", hash: "#/" },
  { name: "02_incidents_evidence", hash: "#/incidents", action: "evidence_drawer" },
  { name: "02_incidents_response", hash: "#/incidents", action: "response_tab" },
  { name: "03_swarm", hash: "#/swarm", action: "swarm_topology" },
  { name: "04_responses", hash: "#/responses" },
  { name: "05_evaluation", hash: "#/evaluation" },
  { name: "06_pipeline_simulator", hash: "#/pipeline/simulator" },
  { name: "07_pipeline_collector", hash: "#/pipeline/collector" },
  { name: "08_pipeline_detection_rules", hash: "#/pipeline/detection", action: "rules_tab" },
  { name: "09_pipeline_response", hash: "#/pipeline/response" },
];

const resolutions = [
  { label: "1920x1080", w: 1920, h: 1080 },
  { label: "1280x720", w: 1280, h: 720 },
];

const themes = ["light", "dark"];

function sha256(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function getOrCreateRunId() {
  console.log("Checking backend runs and seeding coordinated_leakage...");
  try {
    const runsRes = await fetch("http://127.0.0.1:8000/api/runs");
    const runsData = await runsRes.json();
    let targetRun = runsData.find((r) => r.scenario_id === "coordinated_leakage" && r.counts?.alerts > 0);
    
    if (!targetRun) {
      console.log("Seeding fresh coordinated_leakage run...");
      const simRes = await fetch("http://127.0.0.1:8000/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_id: "coordinated_leakage",
          agent_count: 5,
          seed: 42,
          gateway_mode: "monitor",
          drop_rate: 0,
          agent_backend: "deterministic",
          persist: true,
          auto_pipeline: true,
        }),
      });
      const simData = await simRes.json();
      targetRun = simData.run;
    }
    
    const runId = targetRun.run_id;
    console.log(`Using target run: ${runId}`);
    
    // Ensure evaluated
    console.log(`Ensuring evaluation exists for ${runId}...`);
    await fetch("http://127.0.0.1:8000/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: runId, persist: true }),
    });

    return runId;
  } catch (err) {
    console.warn("Error preparing run, falling back to default:", err.message);
    return "run-9934e524";
  }
}

async function run() {
  const runId = await getOrCreateRunId();
  console.log(`Launching Chrome with Puppeteer for run ${runId}...`);

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

  const capturedHashes = {};

  try {
    for (const r of resolutions) {
      for (const t of themes) {
        console.log(`\n--- Capturing ${t.toUpperCase()} theme at ${r.label} ---`);
        const page = await browser.newPage();
        await page.setViewport({ width: r.w, height: r.h, deviceScaleFactor: 1 });
        await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: t }]);

        // Pre-set localStorage & theme attributes before page script runs
        await page.evaluateOnNewDocument(
          (theme, activeRun) => {
            localStorage.setItem("sg_theme", theme);
            localStorage.setItem("swaramguard.selectedRun", activeRun);
            document.documentElement.setAttribute("data-theme", theme);
          },
          t,
          runId
        );

        for (const p of pages) {
          const filename = `${p.name}_${t}_${r.label}.png`;
          const primaryOut = path.join(targetDirs[0], filename);
          const url = `${baseUrl}/${p.hash}`;

          // Navigate cleanly from blank state to avoid SPA state carry-over
          await page.goto("about:blank");
          await page.goto(url, { waitUntil: "networkidle0", timeout: 15000 }).catch(() => {});
          
          // Settle time for React state hydration & animation
          await new Promise((resolve) => setTimeout(resolve, 800));

          // Page-specific interactions
          if (p.action === "evidence_drawer") {
            try {
              // Click Evidence tab button
              const buttons = await page.$$("button");
              for (const b of buttons) {
                const text = await page.evaluate((el) => el.textContent, b);
                if (text && text.includes("Evidence")) {
                  await b.click();
                  break;
                }
              }
              await new Promise((resolve) => setTimeout(resolve, 400));

              // Click evidence chip to open drawer
              await page.waitForSelector(".incident-evidence-chip, .incident-evidence-row", { timeout: 4000 });
              const chip = await page.$(".incident-evidence-chip, .incident-evidence-row");
              if (chip) {
                await chip.click();
                await new Promise((resolve) => setTimeout(resolve, 600));
              }
            } catch (e) {
              console.warn(`Could not open evidence drawer on ${filename}:`, e.message);
            }
          } else if (p.action === "response_tab") {
            try {
              // Click Response & Mitigation tab button
              const buttons = await page.$$("button");
              for (const b of buttons) {
                const text = await page.evaluate((el) => el.textContent, b);
                if (text && text.includes("Response & Mitigation")) {
                  await b.click();
                  break;
                }
              }
              await new Promise((resolve) => setTimeout(resolve, 500));
            } catch (e) {
              console.warn(`Could not switch to response tab on ${filename}:`, e.message);
            }
          } else if (p.action === "rules_tab") {
            try {
              // Click Rules (20) tab on Detection page
              const buttons = await page.$$("button");
              for (const b of buttons) {
                const text = await page.evaluate((el) => el.textContent, b);
                if (text && text.includes("Rules")) {
                  await b.click();
                  break;
                }
              }
              await new Promise((resolve) => setTimeout(resolve, 600));
            } catch (e) {
              console.warn(`Could not switch to rules tab on ${filename}:`, e.message);
            }
          } else if (p.action === "swarm_topology") {
            try {
              await page.waitForSelector("svg", { timeout: 4000 });
              await new Promise((resolve) => setTimeout(resolve, 600));
            } catch (e) {}
          }

          // Take screenshot
          await page.screenshot({ path: primaryOut, fullPage: false });
          fs.copyFileSync(primaryOut, path.join(targetDirs[1], filename));

          const hash = sha256(primaryOut);
          const key = `${p.name}_${r.label}`;
          if (!capturedHashes[key]) capturedHashes[key] = {};
          capturedHashes[key][t] = { file: filename, hash };

          console.log(`Captured: ${filename} (sha256: ${hash.slice(0, 10)}...)`);
        }

        await page.close();
      }
    }

    // Verify Light vs Dark distinctness
    console.log("\n--- Verification: Checking Light vs Dark Byte Difference ---");
    let identicalCount = 0;
    for (const [key, pair] of Object.entries(capturedHashes)) {
      const lightHash = pair.light.hash;
      const darkHash = pair.dark.hash;
      if (lightHash === darkHash) {
        console.error(`FAIL: ${key} light and dark screenshots are BYTE-IDENTICAL! (${lightHash})`);
        identicalCount++;
      } else {
        console.log(`PASS: ${key} verified distinct. (Light: ${lightHash.slice(0, 8)}... | Dark: ${darkHash.slice(0, 8)}...)`);
      }
    }

    if (identicalCount > 0) {
      throw new Error(`Verification failed: ${identicalCount} screen(s) had identical light/dark captures.`);
    }

    console.log("\nSUCCESS: All screenshots captured and verified distinct between Light and Dark themes!");
  } finally {
    await browser.close();
  }
}

run().catch((err) => {
  console.error("Capture script encountered error:", err);
  process.exit(1);
});
