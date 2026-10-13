// Access-time world-write protection; all kernel loading goes through bpftool.
import { execFileSync } from "node:child_process";
import { chmodSync, chownSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, statfsSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { endianness } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { requireSupportedHost } from "./platform.mjs";

export const PIN = "/sys/fs/bpf/agentic-job-world-write";
export const PROGRAMS = ["world_write_permission", "world_write_open",
  "world_write_file_permission", "world_write_setattr"];

// Linux userspace dev_t is not the kernel's 12:20 dev_t. No kernel offsets.
export function rootConfig(dev, order = endianness()) {
  const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & 0xfffff000n);
  const minor = (dev & 0xffn) | ((dev >> 12n) & 0xffffff00n);
  if (major > 0xfffn || minor > 0xfffffn) throw new Error("root device exceeds kernel dev_t");
  const bytes = Buffer.alloc(8);
  const write = order === "LE" ? bytes.writeUInt32LE.bind(bytes) : bytes.writeUInt32BE.bind(bytes);
  write(Number((major << 20n) | minor), 0);
  write(1, 4);
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0"));
}

export function attach(object, dev, run) {
  run("bpftool", ["prog", "loadall", object, `${PIN}/links`,
    "autoattach", "pinmaps", `${PIN}/maps`]);
  // autoattach can fall back to pinning a program. A program pin is NOT an
  // attachment: require each expected pin to be a tracing link before enabling.
  // bpftool's single-link show path can return -1 after printing valid JSON:
  // do_show tests stale errno instead of do_show_link's result (v7.6.0).
  // Enumeration terminates on ENOENT and -f includes the actual pin paths.
  const links = JSON.parse(run("bpftool", ["-j", "-f", "link", "show"]));
  if (!Array.isArray(links)) throw new Error("expected bpftool link array");
  for (const name of PROGRAMS) {
    const matches = links.filter(link => Array.isArray(link.pinned) &&
      link.pinned.includes(`${PIN}/links/${name}`));
    if (matches.length !== 1 || matches[0].type !== "tracing" ||
        matches[0].attach_type !== "modify_return") {
      throw new Error(`not a modify-return tracing link: ${name}`);
    }
  }
  run("bpftool", ["map", "update", "pinned", `${PIN}/maps/root_fs`,
    "key", "hex", "00", "00", "00", "00", "value", "hex", ...rootConfig(dev)]);
}

// Where the image lacks it. Ubuntu's bpftool is a wrapper for the running
// kernel's linux-tools package (hosted ubuntu-26.04 ships both); RHEL's is
// the bpftool package. os-release was admitted by requireSupportedHost.
export function bpftoolInstall(osRelease, kernel) {
  const id = /^ID="?([a-z0-9.]+)"?$/m.exec(osRelease)?.[1];
  if (id === "ubuntu") {
    if (!/^[A-Za-z0-9.+-]+$/.test(kernel)) throw new Error(`unexpected kernel release ${JSON.stringify(kernel)}`);
    return ["apt-get", ["-o", "Acquire::Retries=3", "install", "-y", "--no-install-recommends",
      "linux-tools-common", `linux-tools-${kernel}`]];
  }
  if (id === "rhel") return ["dnf", ["install", "-y", "bpftool"]];
  throw new Error(`no bpftool package known for ${id ?? "this host"}`);
}

export function ensureBpftool(run, osRelease) {
  try {
    run("bpftool", ["version"]);
    return;
  } catch {
    // Missing, or Ubuntu's wrapper without the running kernel's tools.
  }
  const [command, args] = bpftoolInstall(osRelease, run("uname", ["-r"]).trim());
  run(command, args);
  run("bpftool", ["version"]);
}

export function runCommand(command, args) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000, maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    throw new Error(`${[command, ...args].map(arg => JSON.stringify(arg)).join(" ")}: ` +
      `exit status ${error.status ?? "unavailable"}, signal ${error.signal ?? "none"}` +
      `\n${error.message}\nstderr: ${error.stderr?.trim() || "(empty)"}`, { cause: error });
  }
}

export function reportRefusal(error, run = runCommand, log = console.error) {
  log(`world-write setup refused: ${error.message}`);
  for (const [command, args] of [["bpftool", ["version"]], ["uname", ["-r"]]]) {
    try {
      log(`${command} ${args.join(" ")}: ${run(command, args).trim()}`);
    } catch (diagnosticError) {
      log(`diagnostic failed: ${diagnosticError.message}`);
    }
  }
}

// OBJECT is the release's, taken by its pinned checksum with the binary
// (binary.mjs), or compiled with a build of the same source: no compiler here.
export function load(object) {
  requireSupportedHost();
  if (process.getuid() !== 0) throw new Error("world-write loading requires root");
  if (!object || !lstatSync(object).isFile()) throw new Error(`policy object ${object} is not a regular file`);
  const run = runCommand;
  ensureBpftool(run, readFileSync("/etc/os-release", "utf8"));
  if (Number(statfsSync("/sys/fs/bpf").type) !== 0xcafe4a11) {
    run("mount", ["-t", "bpf", "bpf", "/sys/fs/bpf"]);
  }
  // An exclusive, root-owned directory: refuse reruns/stale pins instead of
  // replacing a live policy.
  mkdirSync(PIN, { mode: 0o700 });
  const uid = Number(run("id", ["-u", "nobody"]).trim());
  if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error("requires an unprivileged nobody user for the activation probe");
  // Fixed-size fixtures, not an inventory. A baseline and owned positive
  // control distinguish an actual policy denial from DAC or a broken launcher.
  const probe = mkdtempSync("/.agentic-world-write-");
  try {
    chmodSync(probe, 0o755);
    for (const name of ["foreign", "owned"]) {
      writeFileSync(`${probe}/${name}`, "probe", { mode: 0o600 });
      chmodSync(`${probe}/${name}`, 0o666);
    }
    chownSync(`${probe}/owned`, uid, statSync(`${probe}/owned`).gid);
    const write = (name, denied) => run("runuser", ["-u", "nobody", "--", process.execPath, "-e",
      `const fs = require('node:fs'); let denied = false;
       try { fs.appendFileSync(process.argv[1], 'control'); }
       catch (e) { if (e.code !== 'EACCES') throw e; denied = true; }
       if (denied !== (process.argv[2] === 'true')) process.exit(1);`,
      `${probe}/${name}`, String(denied)]);
    write("foreign", false);
    write("owned", false);
    attach(object, statSync("/", { bigint: true }).dev, run);
    write("foreign", true);
    write("owned", false);
  } finally {
    for (const name of ["foreign", "owned"]) unlinkSync(`${probe}/${name}`);
    rmdirSync(probe);
  }
  console.log("world-write: enabled root-device policy; four tracing links pinned");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    load(process.argv[2]);
  } catch (error) {
    reportRefusal(error);
    process.exitCode = 1;
  }
}
