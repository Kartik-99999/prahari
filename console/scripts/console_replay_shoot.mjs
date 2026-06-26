// Capture the replay at three playhead times (foothold / confirmed / end).
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const BASE = process.env.CONSOLE_URL ?? "http://localhost:3000";
const OUT = "../docs";
mkdirSync(OUT, { recursive: true });

const shots = [
  { t: "2026-05-02T11:00:00", file: "replay_1.png", label: "foothold (May 2)" },
  { t: "2026-05-04T03:00:00", file: "replay_2.png", label: "confirmed (May 4)" },
  { t: "2026-05-21T23:59:00", file: "replay_3.png", label: "end (May 21)" },
];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });

for (const s of shots) {
  await page.goto(`${BASE}/?t=${encodeURIComponent(s.t)}`, {
    waitUntil: "networkidle",
    timeout: 60000,
  });
  await page.waitForSelector("canvas", { timeout: 20000 });
  await page.waitForTimeout(2500); // let reveal + layout settle
  await page.screenshot({ path: `${OUT}/${s.file}`, fullPage: true });
  console.log(`captured ${s.file} @ ${s.label}`);
}

await browser.close();
