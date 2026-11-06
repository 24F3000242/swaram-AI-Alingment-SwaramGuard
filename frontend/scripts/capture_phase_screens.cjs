const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const phase = process.argv[2] || "phase-2";
const outputDir = path.resolve(__dirname, `../../docs/screens/${phase}`);
fs.mkdirSync(outputDir, { recursive: true });

const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const baseUrl = "http://127.0.0.1:5173";

let pages = [];
if (phase === "phase-3") {
  pages = [
    { name: "pipeline_simulator", hash: "#/pipeline/simulator" },
    { name: "pipeline_collector", hash: "#/pipeline/collector" },
    { name: "pipeline_detection", hash: "#/pipeline/detection" },
    { name: "pipeline_response", hash: "#/pipeline/response" },
    { name: "overview", hash: "#/" },
    { name: "incidents", hash: "#/incidents" },
  ];
} else if (phase === "phase-2") {
  pages = [
    { name: "swarm", hash: "#/swarm" },
    { name: "responses", hash: "#/responses" },
    { name: "evaluation", hash: "#/evaluation" },
    { name: "overview", hash: "#/" },
    { name: "incidents", hash: "#/incidents" },
  ];
} else if (phase === "phase-1") {
  pages = [
    { name: "overview", hash: "#/" },
    { name: "incidents", hash: "#/incidents" },
    { name: "pipeline", hash: "#/pipeline/simulator" },
  ];
} else {
  pages = [
    { name: "overview", hash: "#/" },
    { name: "incidents", hash: "#/incidents" },
    { name: "pipeline", hash: "#/pipeline/simulator" },
  ];
}

const resolutions = [
  { label: "1920x1080", w: 1920, h: 1080 },
  { label: "1280x720", w: 1280, h: 720 },
];

const themes = [
  { name: "light", flag: "--force-prefers-color-scheme=light" },
  { name: "dark", flag: "--force-prefers-color-scheme=dark" },
];

console.log(`Capturing screenshots for ${phase}...`);

for (const p of pages) {
  for (const t of themes) {
    for (const r of resolutions) {
      const filename = `${p.name}_${t.name}_${r.label}.png`;
      const outPath = path.join(outputDir, filename);
      const url = `${baseUrl}/${p.hash}`;
      const cmd = `"${chromePath}" --headless=new --disable-gpu ${t.flag} --window-size=${r.w},${r.h} --screenshot="${outPath}" "${url}"`;
      try {
        execSync(cmd, { stdio: "ignore" });
        console.log(`Saved: ${filename}`);
      } catch (err) {
        console.error(`Failed: ${filename}`, err.message);
      }
    }
  }
}

console.log("Screenshot capture complete.");
