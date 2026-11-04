import { cpSync, existsSync, mkdirSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const standalone = resolve(root, ".next", "standalone");

function copyIntoStandalone(source, destination) {
  if (!existsSync(source)) return;
  mkdirSync(dirname(destination), { recursive: true });
  cpSync(source, destination, { recursive: true, force: true });
}

copyIntoStandalone(
  resolve(root, ".next", "static"),
  resolve(standalone, "apps", "web", ".next", "static"),
);
copyIntoStandalone(resolve(root, "public"), resolve(standalone, "apps", "web", "public"));

const server = spawn(process.execPath, [resolve(standalone, "apps", "web", "server.js")], {
  cwd: standalone,
  env: { ...process.env, HOSTNAME: "127.0.0.1", PORT: "3011" },
  stdio: "inherit",
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.kill(signal));
}
server.on("exit", (code) => process.exit(code ?? 0));
