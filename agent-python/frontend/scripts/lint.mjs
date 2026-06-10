import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "tests", "scripts"];
const failures = [];

for (const file of walk(roots)) {
  const text = readFileSync(file, "utf8");
  if (file.startsWith("src/") && file !== "src/api.js" && /\bfetch\s*\(/.test(text)) {
    failures.push(`${file}: raw fetch calls must stay in src/api.js`);
  }
  if (file.startsWith("src/") && /\bconsole\.(log|debug|info)\s*\(/.test(text)) {
    failures.push(`${file}: remove debug console output`);
  }
  if (file.startsWith("src/") && (/VITE_API_KEY\s*=\s*[^#\s]/.test(text) || /x-api-key["']?\s*:\s*["'][^"']+["']/.test(text))) {
    failures.push(`${file}: possible hardcoded API key`);
  }
}

if (failures.length) {
  for (const failure of failures) console.error(failure);
  process.exit(1);
}

function walk(paths) {
  const files = [];
  for (const path of paths) collect(path, files);
  return files.filter((file) => /\.(js|jsx|mjs|cjs|env|md)$/.test(file));
}

function collect(path, files) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const current = join(path, entry.name);
    if (entry.isDirectory()) collect(current, files);
    else files.push(current);
  }
}
