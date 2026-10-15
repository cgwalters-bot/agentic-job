// A reusable workflow's identity, never the caller's ref, selects the release.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { NAMES, OBJECT, TARGET, checked, readPin } from "./binary.mjs";

export async function fetchTagged({ repository, ref, commit, source, out, fetchFile, verify }) {
  const prefix = `${repository}/.github/workflows/policy.yml@refs/tags/`;
  if (!ref?.startsWith(prefix)) return false;
  const tag = ref.slice(prefix.length);
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(tag) || !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("invalid tagged workflow identity");
  }
  // Resolve the tag, including annotated tags, rather than trusting a release's
  // target_commitish (which may be a moving branch). A moved tag must not make
  // a workflow resolved earlier execute another commit's binary.
  const resolved = JSON.parse(await fetchFile(`https://api.github.com/repos/${repository}/commits/${tag}`));
  if (resolved.sha !== commit) throw new Error("release tag does not match the workflow commit");
  const from = `https://github.com/${repository}/releases/download/${tag}`;
  const path = join(out, "release.json");
  const bundle = join(out, "provenance.jsonl");
  writeFileSync(path, await fetchFile(`${from}/release.json`));
  writeFileSync(bundle, await fetchFile(`${from}/provenance.jsonl`));
  // Verify before trusting any manifest field: a release editor can replace
  // assets and checksums, but cannot sign a manifest as release.yml on main
  // running at the workflow's commit.
  verify("gh", ["attestation", "verify", path, "--bundle", bundle,
    "--repo", repository, "--cert-identity", `https://github.com/${repository}/.github/workflows/release.yml@refs/heads/main`,
    "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"]);
  const pin = readPin(path);
  if (pin.repository !== repository || pin.release !== tag || pin.target !== TARGET || pin.source !== source || pin.commit !== commit) {
    throw new Error("tagged release manifest does not match the workflow source");
  }
  for (const name of [...NAMES, OBJECT]) {
    if (!/^[0-9a-f]{64}$/.test(pin.sha256?.[name] ?? "")) throw new Error(`missing checksum for ${name}`);
    const asset = name === OBJECT ? name : `${name}-${TARGET}`;
    const bytes = checked(pin, name, await fetchFile(`${from}/${asset}`));
    writeFileSync(join(out, name), bytes, { mode: name === OBJECT ? 0o644 : 0o755 });
  }
  return true;
}
