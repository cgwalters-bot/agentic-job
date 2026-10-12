// Refuse unvalidated host families before the action changes the machine.
// Read os-release as data, never as shell code; ID_LIKE is not support evidence.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REFUSAL = "secure-host: requires Ubuntu 26.04 or RHEL 10; cannot establish a supported host from /etc/os-release";

export function supportedHost(text) {
  const fields = new Map();
  for (const line of text.split("\n")) {
    if (!/^(ID|VERSION_ID)=/.test(line)) continue;
    const match = /^(ID|VERSION_ID)=(?:"([a-z0-9.]+)"|'([a-z0-9.]+)'|([a-z0-9.]+))$/.exec(line);
    if (!match || fields.has(match[1])) return false;
    fields.set(match[1], match[2] ?? match[3] ?? match[4]);
  }
  const id = fields.get("ID");
  const version = fields.get("VERSION_ID") ?? "";
  return (id === "ubuntu" && version === "26.04") ||
    (id === "rhel" && /^10(?:\.\d+)*$/.test(version));
}

export function requireSupportedHost(path = "/etc/os-release") {
  let supported = false;
  try {
    supported = supportedHost(readFileSync(path, "utf8"));
  } catch {
    // A missing/unreadable release file cannot establish support either.
  }
  if (!supported) throw new Error(REFUSAL);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireSupportedHost();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
