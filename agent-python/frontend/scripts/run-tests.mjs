import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";

const cacheDir = join(process.cwd(), "node_modules", ".cache");
mkdirSync(cacheDir, { recursive: true });
const outputDir = mkdtempSync(join(cacheDir, "threat-agent-frontend-tests-"));
const outputFile = join(outputDir, "bundle.mjs");

try {
  await build({
    entryPoints: ["tests/frontend.test.jsx"],
    bundle: true,
    outfile: outputFile,
    platform: "node",
    format: "esm",
    jsx: "automatic",
    logLevel: "silent",
    external: ["node:test", "node:assert/strict", "react", "react-dom/server", "react/jsx-runtime"],
    define: {
      "import.meta.env.VITE_API_BASE": "\"http://api.test\"",
    },
  });

  const result = spawnSync(process.execPath, ["--test", outputFile], { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(outputDir, { recursive: true, force: true });
}
