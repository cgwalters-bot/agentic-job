// Keep transient GitHub throttling from losing a job before it starts. Debug
// headers stay in memory: never print gh's trace (it can contain credentials).
import { execFile, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

const execute = promisify(execFile);
const BUDGET_MS = 120_000;

export function prepare(run = spawnSync) {
  if (run("gh", ["--version"], { stdio: "ignore" }).status === 0) return;
  const manager = ["dnf", "apt-get"].find(name => run(name, ["--version"], { stdio: "ignore" }).status === 0);
  if (!manager) throw new Error("gh is required; no supported package manager found");
  const result = run("sudo", [manager, "install", "-y", "gh"], { stdio: "inherit" });
  if (result.error || result.status !== 0) throw new Error("could not install gh");
}

export async function github(args, { missing = false, run = execute, now = Date.now, wait = sleep } = {}) {
  const deadline = now() + BUDGET_MS;
  for (let attempt = 0; ; attempt++) {
    try {
      const result = await run("gh", args, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024,
        timeout: Math.max(1, deadline - now()), env: { ...process.env, GH_DEBUG: "api" } });
      return result.stdout;
    } catch (error) {
      const trace = String(error.stderr ?? "");
      const statuses = [...trace.matchAll(/HTTP\/\S+\s+(\d{3})/g)];
      const status = Number(statuses.at(-1)?.[1]);
      if (missing && status === 404) return null;
      // A request can follow redirects. Headers must belong to the failed
      // response, not an earlier one in the trace.
      const response = trace.slice(statuses.at(-1)?.index ?? 0);
      const header = (name) => response.match(new RegExp(`^< ${name}:[ \\t]*(.+)$`, "im"))?.[1]?.trim();
      const after = header("retry-after");
      const reset = header("x-ratelimit-reset");
      const limited = [403, 429].includes(status) && (after !== undefined || header("x-ratelimit-remaining") === "0" || /(?:secondary rate limit|API rate limit exceeded)/i.test(trace));
      if (!limited) throw new Error(`GitHub request failed${status ? ` (HTTP ${status})` : ""}; check token permissions and resource availability`);
      let delay = Math.min(1000 * 2 ** attempt, 30_000);
      if (after !== undefined) {
        const seconds = Number(after);
        const requested = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(after) - now();
        if (Number.isFinite(requested)) delay = Math.max(delay, requested);
      }
      if (reset && header("x-ratelimit-remaining") === "0" && Number.isFinite(Number(reset))) {
        delay = Math.max(delay, Number(reset) * 1000 - now());
      }
      if (now() + delay >= deadline) throw new Error(`GitHub rate limit (HTTP ${status}); retry budget exhausted`);
      await wait(delay);
    }
  }
}

export async function download(url, missing = false, { run = execute } = {}) {
  const api = /^https:\/\/api\.github\.com\/(.+)$/.exec(url);
  if (api) return github(["api", api[1]], { missing, run });
  const asset = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\/([^/]+)$/.exec(url);
  if (!asset) throw new Error("unsupported release URL");
  // Not `gh release download`: it looks up published (REST) and draft
  // (GraphQL) releases concurrently, so the last status in its trace need not
  // be the lookup's, and an absent release can end in GraphQL's 200. One REST
  // lookup at a time keeps 404 and rate-limit statuses unambiguous.
  const [, repository, tag, name] = asset;
  const release = await github(["api", `repos/${repository}/releases/tags/${encodeURIComponent(tag)}`], { missing, run });
  if (release === null) return null;
  const id = JSON.parse(release).assets?.find(item => item.name === name)?.id;
  if (!Number.isSafeInteger(id)) {
    if (missing) return null;
    throw new Error(`release ${tag} has no asset ${name}`);
  }
  return github(["api", "-H", "Accept: application/octet-stream", `repos/${repository}/releases/assets/${id}`], { run });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "download") {
    const bytes = await download(process.argv[3], process.argv[4] === "missing");
    if (bytes === null) process.exitCode = 2;
    else process.stdout.write(bytes);
  } else prepare();
}
