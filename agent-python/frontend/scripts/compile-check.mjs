import { build } from "esbuild";

await build({
  entryPoints: ["src/main.jsx"],
  bundle: true,
  write: false,
  outdir: "node_modules/.cache/compile-check",
  platform: "browser",
  format: "esm",
  jsx: "automatic",
  logLevel: "info",
  define: {
    "import.meta.env.VITE_API_BASE": "\"http://127.0.0.1:8000\"",
  },
});
