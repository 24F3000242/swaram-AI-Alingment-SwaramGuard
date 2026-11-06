const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

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
  { name: "02_incidents", hash: "#/incidents" },
  { name: "03_swarm", hash: "#/swarm" },
  { name: "04_responses", hash: "#/responses" },
  { name: "05_evaluation", hash: "#/evaluation" },
  { name: "06_pipeline_simulator", hash: "#/pipeline/simulator" },
  { name: "07_pipeline_collector", hash: "#/pipeline/collector" },
  { name: "08_pipeline_detection", hash: "#/pipeline/detection" },
  { name: "09_pipeline_response", hash: "#/pipeline/response" },
];

const resolutions = [
  { label: "1920x1080", w: 1920, h: 1080 },
  { label: "1280x720", w: 1280, h: 720 },
];

const themes = [
  { name: "light", flag: "--force-prefers-color-scheme=light" },
  { name: "dark", flag: "--force-prefers-color-scheme=dark" },
];

console.log("Capturing all 9 page screenshots across resolutions and themes for Claude Review Package...");

for (const p of pages) {
  for (const t of themes) {
    for (const r of resolutions) {
      const filename = `${p.name}_${t.name}_${r.label}.png`;
      const primaryOut = path.join(targetDirs[0], filename);
      const url = `${baseUrl}/${p.hash}`;
      const cmd = `"${chromePath}" --headless=new --disable-gpu ${t.flag} --window-size=${r.w},${r.h} --screenshot="${primaryOut}" "${url}"`;
      try {
        execSync(cmd, { stdio: "ignore" });
        // copy to secondary target dir
        fs.copyFileSync(primaryOut, path.join(targetDirs[1], filename));
        console.log(`Saved: ${filename}`);
      } catch (err) {
        console.error(`Failed: ${filename}`, err.message);
      }
    }
  }
}

console.log("All screenshots captured and mirrored successfully!");
