//! `setup.agents`: agent programs from npm tarballs pinned in this
//! binary, unpacked here, without npm.
//!
//! `npm install -g NAME@VERSION` resolves the version's dependencies
//! afresh at every run, within their ranges, and runs their install
//! scripts as root: a dependency published since the last review runs
//! as root on the host before the network rules load. Here the whole
//! set is reviewed in [`LOCK`] instead, each package by npm's own
//! SHA-512 integrity, fetched from one registry at a URL made from its
//! name and version, and no script of any of them runs. A tarball that
//! does not match its pin is refused, and so the agent.
//!
//! [`LOCK`] is for Linux on x86-64 with glibc, what the runners are;
//! elsewhere setup refuses, and `setup.npm` remains. An agent whose
//! package needs its install script to pick a platform binary
//! (`opencode-ai`) is pinned as that binary's package instead.
//! `just agents-lock` writes an entry from npm's own resolution.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const LOCK: &str = include_str!("agents.toml");
pub const REGISTRY: &str = "https://registry.npmjs.org";
/// Where setup installs them, each in its own directory, and links
/// their programs.
pub const ROOT: &str = "/opt/agentic-job/agents";
pub const BIN_DIR: &str = "/usr/local/bin";
/// What [`LOCK`] was resolved for, in npm's names.
pub const PLATFORM: (&str, &str, &str) = ("linux", "x64", "glibc");
/// The largest tarball is a platform binary of about 90 MB compressed.
const MAX_TARBALL_BYTES: u64 = 256 << 20;
/// Unpacked, per agent: Claude Code's binary alone is 250 MB.
const MAX_UNPACKED_BYTES: u64 = 1 << 30;
const MAX_FILES: usize = 100_000;
const MAX_PACKAGES: usize = 1000;
const FETCH_ATTEMPTS: u32 = 3;
const FETCH_PAUSE: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(300);
/// Tarballs fetched at once.
const FETCH_WORKERS: usize = 8;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    agent: Vec<Agent>,
}

/// One agent: what `setup.agents` names, the programs it links and every
/// package it needs, laid out as npm would under `node_modules`.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub spec: String,
    /// A program name in [`BIN_DIR`], and the file it runs, relative to
    /// the agent's directory.
    pub bin: BTreeMap<String, String>,
    pub package: Vec<Package>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    /// `node_modules/NAME`, nested for a version that another package
    /// needs of its own.
    pub path: String,
    pub version: String,
    /// npm's `dist.integrity`: `sha512-` and the digest in base64.
    pub integrity: String,
}

impl Package {
    /// The package's name, the last `node_modules/` of its path.
    pub fn name(&self) -> &str {
        self.path
            .rsplit_once("node_modules/")
            .map_or(self.path.as_str(), |(_, name)| name)
    }

    /// Where npm publishes the version. Made, not read from the lock, so
    /// that no entry can send setup to another host.
    pub fn url(&self) -> String {
        let name = self.name();
        let base = name.rsplit('/').next().unwrap_or(name);
        format!("{REGISTRY}/{name}/-/{base}-{}.tgz", self.version)
    }

    fn validate(&self) -> Result<()> {
        // Lowercase names without a leading dot, so no part is `..`.
        let part = |s: &str| {
            !s.is_empty()
                && !s.starts_with(['.', '_'])
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._~".contains(&b))
        };
        let mut segments = self.path.split('/');
        let mut depth = 0;
        while let Some(segment) = segments.next() {
            let name = match segments.next() {
                Some(scope) if segment == "node_modules" && scope.starts_with('@') => {
                    part(&scope[1..]) && segments.next().is_some_and(part)
                }
                Some(name) => segment == "node_modules" && part(name),
                None => false,
            };
            depth += 1;
            ensure!(name && depth <= 16, "{:?} names no npm package", self.path);
        }
        ensure!(
            self.version.starts_with(|c: char| c.is_ascii_digit())
                && self
                    .version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b)),
            "{}: {:?} is not an exact version",
            self.path,
            self.version
        );
        ensure!(
            self.integrity
                .strip_prefix("sha512-")
                .is_some_and(|digest| digest.len() == 88),
            "{}: {:?} is not a SHA-512 integrity",
            self.path,
            self.integrity
        );
        Ok(())
    }
}

impl Agent {
    fn validate(&self) -> Result<()> {
        // The spec names the agent's directory.
        ensure!(
            self.spec.rsplit_once('@').is_some_and(|(name, _)| {
                Package {
                    path: format!("node_modules/{name}"),
                    version: self.spec[name.len() + 1..].to_owned(),
                    integrity: format!("sha512-{}", "A".repeat(88)),
                }
                .validate()
                .is_ok()
            }),
            "{:?} is not NAME@VERSION",
            self.spec
        );
        ensure!(
            !self.package.is_empty() && self.package.len() <= MAX_PACKAGES,
            "{}: {} packages",
            self.spec,
            self.package.len()
        );
        for package in &self.package {
            package
                .validate()
                .with_context(|| format!("pinned agent {}", self.spec))?;
        }
        ensure!(!self.bin.is_empty(), "{}: links no program", self.spec);
        for (name, target) in &self.bin {
            ensure!(
                !name.starts_with(['.', '-'])
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)),
                "{}: {name:?} is not a program name",
                self.spec
            );
            ensure!(
                Path::new(target)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
                    && self
                        .package
                        .iter()
                        .any(|p| target.starts_with(&format!("{}/", p.path))),
                "{}: {name} runs {target:?}, which is in none of its packages",
                self.spec
            );
        }
        Ok(())
    }

    /// The directory under a root that holds it: its spec, `/` made `+`.
    fn dir(&self) -> String {
        self.spec.replace('/', "+")
    }
}

fn lock() -> Result<Vec<Agent>> {
    let lock: Lock = toml::from_str(LOCK).context("reading the agents' pins")?;
    for agent in &lock.agent {
        agent.validate()?;
    }
    Ok(lock.agent)
}

/// The pinned agents' specs, for `setup.agents` to be checked against.
pub fn pinned() -> Result<Vec<String>> {
    Ok(lock()?.into_iter().map(|agent| agent.spec).collect())
}

/// Installs SPEC under ROOT and links its programs in BIN_DIR, each
/// tarball as FETCH returns it for its URL. Returns the agent's directory.
pub fn install(
    spec: &str,
    root: &Path,
    bin_dir: &Path,
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>> + Sync),
) -> Result<PathBuf> {
    check_platform()?;
    install_agent(&find(spec)?, root, bin_dir, fetch)
}

fn find(spec: &str) -> Result<Agent> {
    lock()?
        .into_iter()
        .find(|agent| agent.spec == spec)
        .with_context(|| format!("setup.agents: {spec:?} is not a pinned agent"))
}

/// Whether this host is the one the pins are for. The workflow's agent
/// runner is the caller's to choose, so setup asks before it changes
/// anything.
pub fn check_platform() -> Result<()> {
    ensure!(
        std::env::consts::OS == PLATFORM.0 && std::env::consts::ARCH == "x86_64",
        "setup.agents: the pins are for {}-{}, not this {}-{}; use setup.npm (the workflow's npm input)",
        PLATFORM.0,
        PLATFORM.1,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

/// The runtime is the image's: an agent whose program is a script is
/// refused before its install, not at its launch, on a host without it.
pub fn check_node(spec: &str) -> Result<()> {
    let agent = find(spec)?;
    ensure!(
        !agent.bin.values().any(|target| target.ends_with(".js"))
            || crate::sandbox::host::has_program("node"),
        "setup.agents: {spec} runs on node, and this host has none; add it to setup.packages"
    );
    Ok(())
}

fn install_agent(
    agent: &Agent,
    root: &Path,
    bin_dir: &Path,
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>> + Sync),
) -> Result<PathBuf> {
    // Every tarball is checked before anything is unpacked.
    let tarballs = fetch_all(&agent.package, fetch)?;
    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let dir = root.join(agent.dir());
    // Fresh, so nothing in it is a link that a write could follow.
    fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
    let mut budget = Budget {
        bytes: MAX_UNPACKED_BYTES,
        files: MAX_FILES,
    };
    for (package, tarball) in agent.package.iter().zip(&tarballs) {
        unpack(tarball, &dir.join(&package.path), &mut budget)
            .with_context(|| format!("unpacking {}@{}", package.name(), package.version))?;
    }
    for (name, target) in &agent.bin {
        let target = dir.join(target);
        let metadata = fs::symlink_metadata(&target)
            .with_context(|| format!("{}: no {}", agent.spec, target.display()))?;
        ensure!(
            metadata.is_file(),
            "{}: {} is not a file",
            agent.spec,
            target.display()
        );
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        let link = bin_dir.join(name);
        // As `npm install -g` would, replacing what was there.
        match fs::symlink_metadata(&link) {
            Ok(old) if old.is_dir() => bail!("{} is a directory", link.display()),
            Ok(_) => {
                fs::remove_file(&link).with_context(|| format!("removing {}", link.display()))?
            }
            Err(_) => {}
        }
        std::os::unix::fs::symlink(&target, &link)
            .with_context(|| format!("linking {}", link.display()))?;
    }
    Ok(dir)
}

/// The tarballs, in the packages' order, each checked against its pin.
fn fetch_all(
    packages: &[Package],
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>> + Sync),
) -> Result<Vec<Vec<u8>>> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<Result<Vec<u8>>>>> =
        packages.iter().map(|_| Default::default()).collect();
    std::thread::scope(|scope| {
        for _ in 0..FETCH_WORKERS.min(packages.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(package) = packages.get(i) else {
                        break;
                    };
                    let result = fetch_checked(package, fetch);
                    if let Ok(mut slot) = results[i].lock() {
                        *slot = Some(result);
                    }
                }
            });
        }
    });
    packages
        .iter()
        .zip(results)
        .map(|(package, slot)| {
            slot.into_inner()
                .ok()
                .flatten()
                .with_context(|| format!("{} was not fetched", package.url()))?
        })
        .collect()
}

fn fetch_checked(
    package: &Package,
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>> + Sync),
) -> Result<Vec<u8>> {
    let url = package.url();
    let mut attempt = 1;
    let bytes = loop {
        match fetch(&url) {
            Ok(bytes) => break bytes,
            Err(error) if attempt < FETCH_ATTEMPTS => {
                eprintln!(
                    "warning: fetching {url} failed (attempt {attempt} of {FETCH_ATTEMPTS}): {error:#}"
                );
                std::thread::sleep(FETCH_PAUSE * attempt);
                attempt += 1;
            }
            Err(error) => return Err(error.context(format!("fetching {url}"))),
        }
    };
    let fetched = integrity(&bytes);
    // Not retried: the registry served other bytes for a published
    // version, which another attempt should not be given the chance of.
    ensure!(
        fetched == package.integrity,
        "{}@{}: checksum mismatch: pinned {}, fetched {fetched}; refusing it",
        package.name(),
        package.version,
        package.integrity
    );
    Ok(bytes)
}

/// npm's integrity string of BYTES.
pub fn integrity(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA512, bytes);
    format!("sha512-{}", base64(digest.as_ref()))
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Over the whole of an agent: a zip-bomb stops here.
struct Budget {
    bytes: u64,
    files: usize,
}

/// A package's gzipped tarball into DEST, without its top directory, as
/// npm unpacks it: regular files and directories, everything else
/// (links, devices) skipped, as npm skips them too. Files are 0755 when
/// the tarball makes them executable and 0644 otherwise.
fn unpack(tarball: &[u8], dest: &Path, budget: &mut Budget) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut components = path.components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))),
            "{} is outside the package",
            path.display()
        );
        let relative: PathBuf = components.collect();
        ensure!(
            relative
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "{} is outside the package",
            path.display()
        );
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = dest.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("creating {}", target.display()))?;
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        ensure!(budget.files > 0, "more than {MAX_FILES} files");
        budget.files -= 1;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mode = if entry.header().mode()? & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&target)
            .with_context(|| format!("creating {}", target.display()))?;
        let written = std::io::copy(&mut (&mut entry).take(budget.bytes + 1), &mut file)
            .with_context(|| format!("writing {}", target.display()))?;
        ensure!(
            written <= budget.bytes,
            "more than {MAX_UNPACKED_BYTES} bytes unpacked"
        );
        budget.bytes -= written;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.flush()?;
    }
    Ok(())
}

/// The system's CA bundles, Debian's and Fedora's: what the host's own
/// npm and curl trust, a proxy's CA included, after `SSL_CERT_FILE`.
/// Without one, the roots built into ureq. The pins, not TLS, are what
/// make a tarball the reviewed one.
const CA_BUNDLES: [&str; 2] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
];

fn http() -> Result<ureq::Agent> {
    let mut tls = ureq::tls::TlsConfig::builder();
    let bundles = std::env::var_os("SSL_CERT_FILE")
        .map(PathBuf::from)
        .into_iter()
        .chain(CA_BUNDLES.iter().map(PathBuf::from));
    if let Some(pem) = bundles.into_iter().find_map(|path| fs::read(path).ok()) {
        let certs: Vec<_> = ureq::tls::parse_pem(&pem)
            .filter_map(|item| match item {
                Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                _ => None,
            })
            .collect();
        if !certs.is_empty() {
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
        }
    }
    Ok(ureq::Agent::config_builder()
        .tls_config(tls.build())
        .timeout_global(Some(FETCH_TIMEOUT))
        .max_redirects(0)
        .build()
        .into())
}

/// Fetches URL over HTTPS, bounded, on one connection pool for the
/// whole install.
pub fn fetch(url: &str) -> Result<Vec<u8>> {
    static HTTP: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    let http = match HTTP.get() {
        Some(http) => http,
        None => {
            let agent = http()?;
            HTTP.get_or_init(|| agent)
        }
    };
    let mut response = http.get(url).call()?;
    Ok(response
        .body_mut()
        .with_config()
        .limit(MAX_TARBALL_BYTES)
        .read_to_vec()?)
}

/// The lock entry of SPEC, linking BIN, from npm's `package-lock.json`
/// of an install of it with `--os`, `--cpu` and `--libc` set to
/// [`PLATFORM`]. Refuses a package with an install script, which would
/// not run, and one npm would fetch from anywhere but [`Package::url`].
pub fn lock_entry(spec: &str, bin: BTreeMap<String, String>, package_lock: &str) -> Result<String> {
    let lock: Value = serde_json::from_str(package_lock).context("reading package-lock.json")?;
    let packages = lock["packages"]
        .as_object()
        .context("package-lock.json has no packages (lockfileVersion 3)")?;
    let fits = |key: &str, want: &str, entry: &Value| {
        let Some(list) = entry[key].as_array() else {
            return true;
        };
        let list: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
        list.contains(&want)
            || (list.iter().all(|s| s.starts_with('!')) && !list.contains(&&*format!("!{want}")))
    };
    let mut pinned = Vec::new();
    for (path, entry) in packages {
        if path.is_empty() || entry["dev"] == true || entry["inBundle"] == true {
            continue;
        }
        if !(fits("os", PLATFORM.0, entry)
            && fits("cpu", PLATFORM.1, entry)
            && fits("libc", PLATFORM.2, entry))
        {
            continue;
        }
        ensure!(
            entry["hasInstallScript"] != true,
            "{path} has an install script, which would not run"
        );
        let field = |key: &str| {
            entry[key]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{path} has no {key}"))
        };
        let package = Package {
            path: path.clone(),
            version: field("version")?,
            integrity: field("integrity")?,
        };
        package.validate()?;
        ensure!(
            field("resolved")? == package.url(),
            "{path} is fetched from {}, not {}",
            field("resolved")?,
            package.url()
        );
        pinned.push(package);
    }
    pinned.sort_by(|a, b| a.path.cmp(&b.path));
    let agent = Agent {
        spec: spec.to_owned(),
        bin,
        package: pinned,
    };
    agent.validate()?;
    Ok(toml::to_string(&Lock { agent: vec![agent] })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gzipped package tarball of (path, mode, content) entries.
    fn tarball(files: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, mode, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(*mode);
            header.set_entry_type(tar::EntryType::Regular);
            // Through the header, so that `..` reaches the archive as is.
            header.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn agent(packages: &[(&str, &[u8])]) -> Agent {
        Agent {
            spec: "fixture@1.0.0".into(),
            bin: [("fixture".into(), "node_modules/fixture/bin/run.js".into())].into(),
            package: packages
                .iter()
                .map(|(path, tarball)| Package {
                    path: (*path).into(),
                    version: "1.0.0".into(),
                    integrity: integrity(tarball),
                })
                .collect(),
        }
    }

    #[test]
    fn base64_matches_npm() {
        // RFC 4648's vectors.
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
        assert_eq!(
            integrity(b""),
            "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        );
    }

    #[test]
    fn installs_offline_from_fixture_tarballs() {
        let main = tarball(&[
            ("package/package.json", 0o644, b"{\"name\":\"fixture\"}"),
            ("package/bin/run.js", 0o644, b"#!/usr/bin/env node\n"),
            ("package/lib/tool", 0o775, b"tool"),
        ]);
        let dep = tarball(&[("package/index.js", 0o644, b"module.exports = 1\n")]);
        let agent = agent(&[
            ("node_modules/fixture", &main),
            ("node_modules/fixture/node_modules/@scope/dep", &dep),
        ]);
        agent.validate().unwrap();
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        // A program already there is replaced, as npm would.
        fs::write(bin.join("fixture"), "old").unwrap();
        let fetch = |url: &str| -> Result<Vec<u8>> {
            Ok(match url {
                "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz" => main.clone(),
                "https://registry.npmjs.org/@scope/dep/-/dep-1.0.0.tgz" => dep.clone(),
                _ => bail!("no {url} offline"),
            })
        };
        let dir = install_agent(&agent, &root.path().join("agents"), &bin, &fetch).unwrap();
        assert_eq!(dir, root.path().join("agents/fixture@1.0.0"));
        let program = dir.join("node_modules/fixture/bin/run.js");
        assert_eq!(fs::read_link(bin.join("fixture")).unwrap(), program);
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&program), 0o755);
        assert_eq!(mode(&dir.join("node_modules/fixture/lib/tool")), 0o755);
        assert_eq!(mode(&dir.join("node_modules/fixture/package.json")), 0o644);
        assert_eq!(
            fs::read_to_string(dir.join("node_modules/fixture/node_modules/@scope/dep/index.js"))
                .unwrap(),
            "module.exports = 1\n"
        );
        // Installed once: a second time would write into what is there.
        assert!(install_agent(&agent, &root.path().join("agents"), &bin, &fetch).is_err());
    }

    #[test]
    fn refuses_a_mismatched_checksum_before_unpacking() {
        let main = tarball(&[("package/bin/run.js", 0o644, b"pinned")]);
        let agent = agent(&[("node_modules/fixture", &main)]);
        let other = tarball(&[("package/bin/run.js", 0o644, b"served")]);
        let root = tempfile::tempdir().unwrap();
        let error = install_agent(&agent, &root.path().join("agents"), root.path(), &|_| {
            Ok(other.clone())
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("fixture@1.0.0: checksum mismatch: pinned sha512-")
                && message.contains("refusing it"),
            "{message}"
        );
        assert!(!root.path().join("agents").exists());
        assert!(!root.path().join("fixture").exists());
    }

    #[test]
    fn unpack_refuses_paths_out_of_the_package_and_bounds_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut budget = Budget {
            bytes: 1 << 20,
            files: 10,
        };
        for path in ["package/../escape", "../escape"] {
            let error = unpack(&tarball(&[(path, 0o644, b"x")]), dir.path(), &mut budget);
            assert!(error.is_err(), "{path}");
        }
        assert!(!dir.path().parent().unwrap().join("escape").exists());
        // A link is skipped, as npm skips it, not written or followed.
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        builder
            .append_link(&mut header, "package/link", "/etc/passwd")
            .unwrap();
        let linked = builder.into_inner().unwrap().finish().unwrap();
        unpack(&linked, dir.path(), &mut budget).unwrap();
        assert!(fs::symlink_metadata(dir.path().join("link")).is_err());
        let mut small = Budget {
            bytes: 3,
            files: 10,
        };
        assert!(
            unpack(
                &tarball(&[("package/a", 0o644, b"abcd")]),
                dir.path(),
                &mut small
            )
            .is_err()
        );
        let mut few = Budget {
            bytes: 100,
            files: 1,
        };
        let two = tarball(&[("package/a", 0o644, b"a"), ("package/b", 0o644, b"b")]);
        assert!(unpack(&two, dir.path(), &mut few).is_err());
    }

    #[test]
    fn packages_and_programs_refuse_what_could_leave_the_directory() {
        for (path, version, integrity, accepted) in [
            ("node_modules/zod", "4.6.5", "a".repeat(88), true),
            (
                "node_modules/@scope/name/node_modules/x",
                "1.0.0-rc.1+b",
                "a".repeat(88),
                true,
            ),
            ("node_modules/..", "1.0.0", "a".repeat(88), false),
            ("node_modules/@scope/..", "1.0.0", "a".repeat(88), false),
            ("node_modules/@../x", "1.0.0", "a".repeat(88), false),
            ("node_modules/Zod", "1.0.0", "a".repeat(88), false),
            ("node_modules/zod/", "1.0.0", "a".repeat(88), false),
            ("lib/zod", "1.0.0", "a".repeat(88), false),
            ("", "1.0.0", "a".repeat(88), false),
            ("node_modules/zod", "^4.0.0", "a".repeat(88), false),
            ("node_modules/zod", "4.0.0", "a".repeat(87), false),
        ] {
            let package = Package {
                path: path.into(),
                version: version.into(),
                integrity: format!("sha512-{integrity}"),
            };
            assert_eq!(package.validate().is_ok(), accepted, "{path} {version}");
        }
        let tgz = tarball(&[]);
        for (name, target, accepted) in [
            ("fixture", "node_modules/fixture/bin/run.js", true),
            ("-fixture", "node_modules/fixture/bin/run.js", false),
            ("a/b", "node_modules/fixture/bin/run.js", false),
            ("fixture", "node_modules/fixture/../../../etc/passwd", false),
            ("fixture", "/usr/bin/node", false),
            ("fixture", "node_modules/other/run.js", false),
        ] {
            let mut agent = agent(&[("node_modules/fixture", &tgz)]);
            agent.bin = [(name.into(), target.into())].into();
            assert_eq!(agent.validate().is_ok(), accepted, "{name} {target}");
        }
        for (spec, accepted) in [
            ("fixture@1.0.0", true),
            ("@scope/fixture@1.0.0", true),
            ("fixture", false),
            ("fixture@latest", false),
            ("../fixture@1.0.0", false),
            ("@scope/../../x@1.0.0", false),
        ] {
            let mut agent = agent(&[("node_modules/fixture", &tgz)]);
            agent.spec = spec.into();
            assert_eq!(agent.validate().is_ok(), accepted, "{spec}");
        }
    }

    #[test]
    fn the_lock_is_valid_and_has_the_workflows_defaults() {
        let pinned = pinned().unwrap();
        let workflow =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/policy.yml");
        let workflow = fs::read_to_string(workflow).unwrap();
        let line = workflow
            .lines()
            .find(|line| line.trim_start().starts_with("AGENTS:"))
            .unwrap();
        let defaults: Vec<&str> = line
            .split('\'')
            .skip(1)
            .step_by(2)
            .filter(|s| s.contains('@'))
            .collect();
        assert!(!defaults.is_empty(), "{line}");
        for spec in defaults {
            assert!(pinned.iter().any(|p| p == spec), "{spec} is not pinned");
        }
    }

    #[test]
    fn lock_entries_come_from_npm_resolution() {
        let entry = |path: &str, extra: Value| {
            let name = path.rsplit_once("node_modules/").unwrap().1;
            let base = name.rsplit('/').next().unwrap();
            let mut value = serde_json::json!({
                "version": "1.0.0",
                "resolved": format!("{REGISTRY}/{name}/-/{base}-1.0.0.tgz"),
                "integrity": format!("sha512-{}", "a".repeat(88)),
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            (path.to_owned(), value)
        };
        let lock = |entries: Vec<(String, Value)>| {
            let mut packages: serde_json::Map<String, Value> = entries.into_iter().collect();
            packages.insert(String::new(), serde_json::json!({"name": "x"}));
            serde_json::json!({"lockfileVersion": 3, "packages": packages}).to_string()
        };
        let bin: BTreeMap<String, String> =
            [("tool".into(), "node_modules/tool/bin/tool".into())].into();
        let text = lock_entry(
            "tool@1.0.0",
            bin.clone(),
            &lock(vec![
                entry("node_modules/tool", serde_json::json!({})),
                entry("node_modules/tool-linux-x64", serde_json::json!({"os": ["linux"], "cpu": ["x64"], "libc": ["glibc"], "optional": true})),
                entry("node_modules/tool-linux-x64-musl", serde_json::json!({"os": ["linux"], "cpu": ["x64"], "libc": ["musl"], "optional": true})),
                entry("node_modules/tool-darwin-arm64", serde_json::json!({"os": ["darwin"], "cpu": ["arm64"]})),
                entry("node_modules/not-windows", serde_json::json!({"os": ["!win32"]})),
                entry("node_modules/test-only", serde_json::json!({"dev": true})),
            ]),
        )
        .unwrap();
        let parsed: Lock = toml::from_str(&text).unwrap();
        let paths: Vec<&str> = parsed.agent[0]
            .package
            .iter()
            .map(|p| p.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "node_modules/not-windows",
                "node_modules/tool",
                "node_modules/tool-linux-x64"
            ]
        );
        for (extra, refusal) in [
            (
                serde_json::json!({"hasInstallScript": true}),
                "install script",
            ),
            (
                serde_json::json!({"resolved": "https://elsewhere.example/tool.tgz"}),
                "is fetched from",
            ),
            (serde_json::json!({"integrity": "sha1-abc"}), "SHA-512"),
        ] {
            let error = lock_entry(
                "tool@1.0.0",
                bin.clone(),
                &lock(vec![entry("node_modules/tool", extra)]),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(refusal), "{error:#}");
        }
    }
}
