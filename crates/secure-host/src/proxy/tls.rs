//! Both sides of the proxy's TLS: the certificate authority it signs
//! each host's certificate with, for the sandbox user, who trusts it
//! alone; and the client that checks the real server's certificate
//! against Mozilla's roots, as mitmproxy does with certifi's.
//!
//! The authority's key is made once and kept in the proxy's state
//! directory, mode 0600 in a 0700 directory of the proxy's user, so a
//! restart signs with the key whose certificate setup published. Only
//! the key is kept: a certificate is checked against the published
//! authority's name and key, which are made again the same.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// In the proxy's state directory.
pub const CA_KEY: &str = "ca-key.pem";

pub const CA_CERT: &str = "ca-cert.pem";

const CA_NAME: &str = "agentic-job egress proxy";

const MODE_KEY: u32 = 0o600;

/// The authority's validity, from the day its key was made, and a host
/// certificate's, from the day before it was made (clocks drift).
const CA_YEARS: i32 = 10;

pub(super) const HOST_DAYS: u64 = 30;

/// How long before it expires a cached host certificate is made again,
/// so that a proxy running for longer than [`HOST_DAYS`] never shows an
/// expired one.
pub(super) const RENEW_DAYS: u64 = 7;

/// The most host certificates kept; past it the cache starts again.
/// Each name the sandbox user asks for adds one.
const MAX_CACHED: usize = 4096;

/// HTTP/1.1 alone: the proxy reads every request through hyper's
/// HTTP/1 server, and a client offered nothing else speaks it.
const ALPN_HTTP1: &[u8] = b"http/1.1";

pub(super) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, CA_NAME);
    name.push(DnType::OrganizationName, CA_NAME);
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let today = chrono::Utc::now().date_naive();
    let (year, month, day) = ymd(today - chrono::Days::new(1));
    params.not_before = rcgen::date_time_ymd(year, month, day);
    params.not_after = rcgen::date_time_ymd(chrono::Datelike::year(&today) + CA_YEARS, 1, 1);
    Ok(params)
}

/// DAY as rcgen takes it.
fn ymd(day: chrono::NaiveDate) -> (i32, u8, u8) {
    use chrono::Datelike;
    // Months and days are at most 12 and 31.
    (
        day.year(),
        u8::try_from(day.month()).unwrap_or(1),
        u8::try_from(day.day()).unwrap_or(1),
    )
}

/// The authority, and the host certificates it has made.
pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    /// One key for every host certificate, as mitmproxy has it.
    host_key: KeyPair,
    cache: Mutex<HashMap<String, Cached>>,
}

struct Cached {
    config: Arc<ServerConfig>,
    /// The day from which it is made again.
    renew: chrono::NaiveDate,
}

impl Authority {
    /// The authority whose key is in DIR, made there first if there is
    /// none, and its certificate written beside it if that is missing.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let key_path = dir.join(CA_KEY);
        let key = match crate::files::read_regular(&key_path, 1 << 16) {
            Ok(pem) => {
                let pem = String::from_utf8(pem).context("the authority's key is not UTF-8")?;
                KeyPair::from_pem(&pem).context("reading the authority's key")?
            }
            Err(crate::files::ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate().context("making the authority's key")?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(MODE_KEY)
                    .open(&key_path)
                    .with_context(|| format!("creating {}", key_path.display()))?;
                file.write_all(key.serialize_pem().as_bytes())
                    .and_then(|()| file.sync_all())
                    .with_context(|| format!("writing {}", key_path.display()))?;
                key
            }
            Err(err) => {
                return Err(err).with_context(|| format!("reading {}", key_path.display()));
            }
        };
        let authority = Self::new(key)?;
        let cert_path = dir.join(CA_CERT);
        if !cert_path.exists() {
            fs::write(&cert_path, &authority.ca_pem)
                .with_context(|| format!("writing {}", cert_path.display()))?;
        }
        Ok(authority)
    }

    pub fn new(key: KeyPair) -> Result<Self> {
        let params = ca_params()?;
        let ca = params
            .self_signed(&key)
            .context("signing the authority's certificate")?;
        Ok(Self {
            issuer: Issuer::new(params, key),
            ca_der: ca.der().clone(),
            ca_pem: ca.pem(),
            host_key: KeyPair::generate().context("making the host certificates' key")?,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    /// The TLS server configuration that shows the sandbox user a
    /// certificate for NAME: the name it asked for, or the CONNECT's
    /// host when it asked for none.
    pub fn server_config(&self, name: &str) -> Result<Arc<ServerConfig>> {
        self.server_config_on(name, chrono::Utc::now().date_naive())
    }

    /// [`Self::server_config`] as of TODAY.
    pub(super) fn server_config_on(
        &self,
        name: &str,
        today: chrono::NaiveDate,
    ) -> Result<Arc<ServerConfig>> {
        let name = name.to_ascii_lowercase();
        if let Some(cached) = self.lock_cache().get(&name)
            && today < cached.renew
        {
            return Ok(cached.config.clone());
        }
        let config = Arc::new(self.make_config(&name, today)?);
        let mut cache = self.lock_cache();
        if cache.len() >= MAX_CACHED && !cache.contains_key(&name) {
            cache.clear();
        }
        let cached = Cached {
            config: config.clone(),
            renew: today + chrono::Days::new(HOST_DAYS - RENEW_DAYS),
        };
        cache.insert(name, cached);
        Ok(config)
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, Cached>> {
        // A panic elsewhere leaves a cache that is still whole.
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn make_config(&self, name: &str, today: chrono::NaiveDate) -> Result<ServerConfig> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let san = match name.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                name.try_into()
                    .map_err(|err| anyhow!("{name:?} is not a DNS name: {err}"))?,
            ),
        };
        params.subject_alt_names = vec![san];
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, name);
        params.distinguished_name = subject;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let (year, month, day) = ymd(today - chrono::Days::new(1));
        params.not_before = rcgen::date_time_ymd(year, month, day);
        let (year, month, day) = ymd(today + chrono::Days::new(HOST_DAYS));
        params.not_after = rcgen::date_time_ymd(year, month, day);
        let cert = params
            .signed_by(&self.host_key, &self.issuer)
            .with_context(|| format!("signing a certificate for {name}"))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.host_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_no_client_auth()
            // The leaf alone: the client has the authority, as setup
            // published it on first start.
            .with_single_cert(vec![cert.der().clone()], key)
            .context("the host certificate")?;
        config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        Ok(config)
    }
}

/// The client configuration for real servers, which trusts ROOTS (in
/// production Mozilla's, [`mozilla_roots`]).
pub fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
    Ok(Arc::new(config))
}

pub fn mozilla_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// The name a server's certificate is checked for: HOST, bracketed or
/// not if it is an IPv6 address.
pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(bare.to_owned()).map_err(|err| anyhow!("{host:?}: {err}"))
}
