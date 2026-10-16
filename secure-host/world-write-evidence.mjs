// Fresh disposable hosts only: never run this inside an existing sandbox.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const inputs = ["secure-host/binary.sh", "crates/agentic-job/bpf/world_write.bpf.c",
  "crates/agentic-job/bpf/world_write_policy.h"];
const digest = path => createHash("sha256").update(readFileSync(path)).digest("hex");
const command = (program, args) => execFileSync(program, args, {
  encoding: "utf8", timeout: 300_000, maxBuffer: 1024 * 1024,
});
// As the release build compiles it.
const compileObject = (out, run) => run("bash", ["secure-host/binary.sh", "object", "--out", out]);

// Record success only after each assertion-bearing command exits successfully.
// A failed probe must never leave a green-looking acceptance summary.
// BINARY is this checkout's agentic-job, which admits the host and loads
// the policy as the secure-host action does.
export function evidence(out, binary, { run = command, hash = digest, build = compileObject,
  osRelease = readFileSync("/etc/os-release", "utf8"),
  publish = text => appendFileSync(process.env.GITHUB_STEP_SUMMARY, text),
  clock = () => performance.now() } = {}) {
  const lines = ["## World-write acceptance", "",
    "Threat: an unprivileged process changing another user's globally writable root-filesystem objects.",
    "Fresh host only; no fallback. RHEL results must not be inferred from Ubuntu.", ""];
  const stage = (name, action) => {
    const start = clock();
    try {
      const output = action();
      lines.push(`### ${name}: PASS (${((clock() - start) / 1000).toFixed(3)} s)`,
        "", "```text", String(output ?? "").replaceAll("```", "'''").slice(0, 16_384), "```", "");
    } catch (error) {
      lines.push(`### ${name}: FAIL (${((clock() - start) / 1000).toFixed(3)} s)`,
        "", "```text", String(error.message).replaceAll("```", "'''").slice(0, 16_384), "```", "");
      throw error;
    }
  };
  let passed = false;
  try {
    stage("Host admission", () => run(binary, ["secure-host", "supported"]));
    stage("Host and source", () => [run("git", ["rev-parse", "HEAD"]),
      run("uname", ["-a"]), osRelease,
      ...inputs.map(path => `${hash(path)}  ${path}`)].join("\n"));
    stage("Required packages", () => {
      const os = osRelease;
      if (/^ID=["']?ubuntu["']?$/m.test(os)) {
        run("sudo", [binary, "secure-host", "apt"]);
        const packages = ["clang", "linux-tools-common", `linux-tools-${run("uname", ["-r"]).trim()}`, "util-linux"];
        run("sudo", ["apt-get", "-o", "Acquire::Retries=3", "install", "-y", "--no-install-recommends", ...packages]);
        return run("dpkg-query", ["-W", ...packages]);
      }
      if (/^ID=["']?rhel["']?$/m.test(os)) {
        run("sudo", ["dnf", "install", "-y", "clang", "bpftool", "util-linux"]);
        return run("rpm", ["-q", "clang", "bpftool", "util-linux"]);
      }
      throw new Error("unsupported evidence host");
    });
    stage("Build inputs and object SHA-256", () => {
      const commands = [];
      build(out, (program, args) => {
        commands.push(JSON.stringify([program, ...args]));
        run(program, args);
      });
      return [run("clang", ["--version"]), ...commands,
        `${hash(`${out}/world_write.bpf.o`)}  world_write.bpf.o`].join("\n");
    });
    stage("Baseline: foreign and owner writes succeed", () => run("sudo", ["node", "secure-host/world-write-host.mjs", "before"]));
    stage("Policy active: four links checked, map enabled, denial and owner control", () =>
      run("sudo", [binary, "secure-host", "world-write", `${out}/world_write.bpf.o`]));
    stage("After loader exits: foreign write EACCES, owner write succeeds; operation matrix", () =>
      run("sudo", ["node", "secure-host/world-write-host.mjs", "after"]));
    stage("Loader version", () => run("sudo", ["bpftool", "version"]));
    passed = true;
  } finally {
    lines.push(passed ? "**PASS: all controls passed.**" : "**FAIL: acceptance incomplete; do not run untrusted steps.**", "");
    publish(lines.join("\n"));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2] || !process.argv[3] || !process.env.GITHUB_STEP_SUMMARY) {
    throw new Error("requires output directory, agentic-job binary and GITHUB_STEP_SUMMARY");
  }
  evidence(process.argv[2], resolve(process.argv[3]));
}
