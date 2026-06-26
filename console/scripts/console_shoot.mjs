// Capture the Prahari console showpiece (graph + ATT&CK) at 16:9.
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const URL = process.env.CONSOLE_URL ?? "http://localhost:3000";
const OUT = process.env.OUT_DIR ?? "../docs";

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
await page.goto(URL, { waitUntil: "networkidle", timeout: 60000 });

// wait for the cytoscape canvas + let fcose settle
await page.waitForSelector("canvas", { timeout: 20000 });
await page.waitForTimeout(3000);

mkdirSync(OUT, { recursive: true });
await page.screenshot({ path: `${OUT}/console_graph.png`, fullPage: true });
console.log("captured console_graph.png");

// switch to the ATT&CK frame
await page.getByRole("button", { name: /ATT&CK/ }).click();
await page.waitForTimeout(1500);
await page.screenshot({ path: `${OUT}/console_attack.png`, fullPage: true });
console.log("captured console_attack.png");

await browser.close();
