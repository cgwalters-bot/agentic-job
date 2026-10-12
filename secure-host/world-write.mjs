// Experimental access-time protection; all kernel loading goes through bpftool.
import { execFileSync } from "node:child_process";
import { chmodSync, chownSync, mkdirSync, mkdtempSync, rmdirSync, statfsSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { endianness } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { requireSupportedHost } from "./platform.mjs";

export const PIN = "/sys/fs/bpf/agentic-job-world-write";
export const BUILD = "/var/lib/agentic-job-world-write";
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
  for (const name of PROGRAMS) {
    const info = JSON.parse(run("bpftool", ["-j", "link", "show", "pinned", `${PIN}/links/${name}`]));
    if (info.type !== "tracing" || info.attach_type !== "modify_return") {
      throw new Error(`not a modify-return tracing link: ${name}`);
    }
  }
  run("bpftool", ["map", "update", "pinned", `${PIN}/maps/root_fs`,
    "key", "hex", "00", "00", "00", "00", "value", "hex", ...rootConfig(dev)]);
}

export function load() {
  requireSupportedHost();
  if (process.getuid() !== 0) throw new Error("world-write loading requires root");
  const run = (command, args) => execFileSync(command, args, {
    encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], timeout: 120_000,
  });
  if (Number(statfsSync("/sys/fs/bpf").type) !== 0xcafe4a11) {
    run("mount", ["-t", "bpf", "bpf", "/sys/fs/bpf"]);
  }
  // Exclusive, root-owned directories: refuse reruns/stale pins instead of
  // replacing a live policy. bpftool mounts bpffs when needed.
  mkdirSync(BUILD, { mode: 0o700 });
  mkdirSync(PIN, { mode: 0o700 });
  const source = fileURLToPath(new URL("../crates/agentic-job/bpf/world_write.bpf.c", import.meta.url));
  const object = `${BUILD}/world_write.bpf.o`;
  run("clang", ["-O2", "-g", "-target", endianness() === "LE" ? "bpfel" : "bpfeb",
    "-Wall", "-Wextra", "-Werror", "-c", source, "-o", object]);
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
    load();
  } catch (error) {
    console.error(`world-write setup refused: ${error.message}`);
    process.exitCode = 1;
  }
}
