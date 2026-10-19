import { build } from "esbuild";
import { mkdir, copyFile, writeFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
await mkdir("web/dist", { recursive: true });
await build({
  entryPoints: ["web/app.ts"],
  outfile: "web/dist/app.js",
  bundle: true,
  minify: true,
  sourcemap: false,
  target: ["es2022"],
  platform: "browser",
  format: "esm",
  legalComments: "eof",
});
for (const file of ["index.html", "style.css"])
  await copyFile(`web/${file}`, `web/dist/${file}`);
const sources = ["src/core.ts", "src/indexeddb.ts", "web/app.ts"];
const manifest = {
  build: "agent-runtime-browser-v1",
  sharedCore: true,
  sourceDigests: Object.fromEntries(
    await Promise.all(
      sources.map(async (file) => [
        file,
        createHash("sha256")
          .update(await readFile(file))
          .digest("hex"),
      ]),
    ),
  ),
  runtime: "Browser / IndexedDB",
  networkInference: false,
};
await writeFile(
  "web/dist/build.json",
  JSON.stringify(manifest, null, 2) + "\n",
);
console.log(
  "Built web/dist: shared core + IndexedDB adapter, no external runtime dependencies.",
);
