import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { PORT } from "../config/config.service.js";

const testPort = Number(PORT) + 10;
const baseUrl = `http://127.0.0.1:${testPort}`;
const server = spawn(process.execPath, ["index.js"], {
  env: { ...process.env, NODE_ENV: "test", PORT: String(testPort) },
  stdio: "inherit",
});

let serverReady = false;
const runTestFile = async (file) => {
  const test = spawn(process.execPath, [`tests/${file}`], {
    env: { ...process.env, NODE_ENV: "test", PORT: String(testPort), API_URL: baseUrl },
    stdio: "inherit",
  });
  return new Promise((resolve, reject) => {
    test.once("error", reject);
    test.once("exit", (code) => resolve(code ?? 1));
  });
};

try {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Test server exited with code ${server.exitCode}`);
    try {
      const response = await fetch(`${baseUrl}/`);
      if (response.ok) {
        serverReady = true;
        break;
      }
    } catch {
      // Server is still starting.
    }
    await delay(250);
  }
  if (!serverReady) throw new Error("Test server did not start in time");

  const resetPasswordPage = await fetch(`${baseUrl}/reset-password`);
  if (!resetPasswordPage.ok) throw new Error(`Reset-password page returned ${resetPasswordPage.status}`);
  const missingRoute = await fetch(`${baseUrl}/api/v1/not-found`);
  if (missingRoute.status !== 404) throw new Error(`Unknown API route returned ${missingRoute.status}, expected 404`);
  console.log("PASS public pages and unknown-route handling");

  for (const file of ["auth-smoke.js", "messages-smoke.js", "upload-smoke.js"]) {
    const exitCode = await runTestFile(file);
    if (exitCode !== 0) {
      process.exitCode = exitCode;
      break;
    }
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  server.kill("SIGTERM");
}
