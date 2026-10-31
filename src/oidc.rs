//! Native OIDC authentication for redlib.
//!
//! This is a fork addition, not an upstream feature. It turns redlib into an
//! OpenID Connect relying party so the instance can be exposed publicly while
//! still requiring a login, without putting an authenticating reverse proxy in
//! front of it. Traffic from configured CIDRs skips authentication entirely.
//!
//! Design notes:
//!
//! * **Stateless sessions.** The container runs with a read-only root
//!   filesystem and no database, so there is nowhere to persist a session
//!   table. Sessions are therefore HS256-signed JWTs held in a cookie: the
//!   server keeps no state and sessions survive restarts and replica changes.
//!   The tradeoff is that individual sessions cannot be revoked before they
//!   expire -- rotating `REDLIB_OIDC_SESSION_SECRET` invalidates all of them.
//!
//! * **Client IP trust.** The bypass allowlist is only as trustworthy as the
//!   address it matches against. `X-Forwarded-For` is attacker-controlled, so
//!   it is consulted *only* when the connecting peer is itself a configured
//!   trusted proxy, and the chain is walked from the right, skipping trusted
//!   hops. See [`resolve_client_ip`].

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use ipnet::IpNet;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::body::Body;
use crate::config;

/// Everything under this prefix is served by us and must never be gated,
/// otherwise the login redirect would loop forever.
/// Paths the gate never blocks. `/healthz` answers "ok" without touching
/// Reddit or any state; `/healthz/reddit` stays gated.
const UNGATED_PATHS: [&str; 4] = ["/oidc/login", "/oidc/callback", "/oidc/logout", "/healthz"];

/// The only path `REDLIB_MCP_TOKEN` opens.
const MCP_PATH: &str = "/mcp";

/// Paths `REDLIB_READ_TOKEN` never opens, together with everything under
/// them: `/settings/restore` and `/settings/update` change preferences on a
/// GET, `/mcp` has its own token, and `/oidc` belongs to the login flow.
const READ_TOKEN_EXCLUDED: [&str; 3] = ["/settings", MCP_PATH, "/oidc"];

// `__Host-` makes browsers accept these only with Secure, Path=/ and no
// Domain, so another host under the same parent domain cannot set or shadow
// them. The prefix changed the names, which logged everyone out once.
const SESSION_COOKIE: &str = "__Host-redlib_session";
const TX_COOKIE: &str = "__Host-redlib_oidc_tx";
const DEFAULT_SCOPES: &str = "openid profile email";
const DEFAULT_SESSION_TTL: u64 = 86_400;
/// How long a user has to complete the login round-trip.
const TX_TTL: u64 = 600;
/// How far ahead of our clock an ID token's `iat` may be.
const MAX_IAT_SKEW: u64 = 300;
/// Shortest accepted `REDLIB_OIDC_SESSION_SECRET`, in bytes: the size of the
/// HMAC-SHA256 key it becomes.
const MIN_SESSION_SECRET_LEN: usize = 32;

fn now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

fn setting(key: &str) -> Option<String> {
	config::get_setting(key).filter(|v| !v.trim().is_empty())
}

/// Cryptographically secure random bytes, base64url-encoded.
///
/// Deliberately not `fastrand`, which is seeded predictably and is not safe
/// for PKCE verifiers, CSRF state, or nonces.
fn random_token(bytes: usize) -> String {
	let mut buf = vec![0u8; bytes];
	if getrandom::getrandom(&mut buf).is_err() {
		// A failing CSPRNG is not something we can paper over safely.
		panic!("OS random number generator unavailable; refusing to issue OIDC tokens");
	}
	URL_SAFE_NO_PAD.encode(buf)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Parsed, validated auth configuration. Built once at startup.
pub struct AuthConfig {
	pub enabled: bool,
	pub issuer: String,
	pub client_id: String,
	pub client_secret: String,
	pub redirect_uri: String,
	pub scopes: String,
	pub session_ttl: u64,
	pub allowed_groups: Vec<String>,
	pub bypass_cidrs: Vec<IpNet>,
	pub trusted_proxies: Vec<IpNet>,
	session_key: Vec<u8>,
	/// Settings that are present but unusable. `load` refuses to start when
	/// there are any.
	problems: Vec<String>,
}

/// Reads `REDLIB_OIDC_ENABLED`. Unset is off; a value that is neither a
/// recognised yes nor a recognised no is an error, not a guess, because
/// guessing "off" would publish the instance without a login.
fn parse_enabled(raw: Option<&str>) -> Result<bool, String> {
	let Some(raw) = raw else { return Ok(false) };
	match raw.trim().to_ascii_lowercase().as_str() {
		"on" | "true" | "1" | "yes" => Ok(true),
		"off" | "false" | "0" | "no" => Ok(false),
		_ => Err(format!("REDLIB_OIDC_ENABLED is {raw:?}; use on/off, true/false, yes/no or 1/0")),
	}
}

/// Parses a comma-separated CIDR list. Bare addresses (`10.0.0.1`) are
/// accepted and treated as single-host networks. Invalid entries are logged
/// and skipped rather than aborting startup, so one typo in a long list does
/// not take the instance down.
fn parse_cidrs(raw: Option<String>, field: &str) -> Vec<IpNet> {
	let Some(raw) = raw else { return Vec::new() };
	raw
		.split(',')
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.filter_map(|entry| {
			entry
				.parse::<IpNet>()
				.or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
				.map_err(|_| warn!("{field}: ignoring unparseable CIDR {entry:?}"))
				.ok()
		})
		.collect()
}

impl AuthConfig {
	/// Loads the configuration and refuses to start a half-configured relying
	/// party: one that silently let everyone through would be the worst
	/// possible outcome here.
	fn load() -> Self {
		let cfg = Self::load_unchecked();

		let mut problems = cfg.problems.clone();
		if cfg.enabled {
			let missing = cfg.missing_required();
			if !missing.is_empty() {
				problems.push(format!("REDLIB_OIDC_ENABLED is on but these are unset: {}", missing.join(", ")));
			}
		}
		assert!(problems.is_empty(), "Refusing to start: {}", problems.join("; "));

		let ignored = cfg.ignored_settings();
		if !ignored.is_empty() {
			warn!(
				"OIDC IS OFF, so this instance needs no login, yet {} {} set. If it should be behind a login, set REDLIB_OIDC_ENABLED=on.",
				ignored.join(", "),
				if ignored.len() == 1 { "is" } else { "are" }
			);
		}

		if cfg.enabled {
			info!(
				"OIDC enabled: issuer={} bypass_cidrs={:?} trusted_proxies={:?} allowed_groups={:?}",
				cfg.issuer, cfg.bypass_cidrs, cfg.trusted_proxies, cfg.allowed_groups
			);

			if cfg.trusted_proxies.is_empty() {
				info!("REDLIB_TRUSTED_PROXIES is empty; X-Forwarded-For will be ignored and the peer address used directly.");
			}
		}

		cfg
	}

	fn load_unchecked() -> Self {
		let mut problems = Vec::new();

		// `redlib.toml` booleans arrive as "on"/"off". An unreadable value
		// counts as on, so that whatever else is missing is reported too, and
		// `load` refuses to start either way.
		let enabled = parse_enabled(config::get_setting("REDLIB_OIDC_ENABLED").as_deref()).unwrap_or_else(|e| {
			problems.push(e);
			true
		});

		let bypass_cidrs = parse_cidrs(setting("REDLIB_AUTH_BYPASS_CIDRS"), "REDLIB_AUTH_BYPASS_CIDRS");
		let trusted_proxies = parse_cidrs(setting("REDLIB_TRUSTED_PROXIES"), "REDLIB_TRUSTED_PROXIES");

		// Derive a fixed-length key from the configured secret so that
		// operators are not forced to supply exactly N bytes. Hashing hides
		// the length but adds no strength, so a minimum is enforced.
		let session_key = match setting("REDLIB_OIDC_SESSION_SECRET") {
			Some(secret) => {
				if enabled && secret.trim().len() < MIN_SESSION_SECRET_LEN {
					problems.push(format!(
						"REDLIB_OIDC_SESSION_SECRET is {} bytes; it must be at least {MIN_SESSION_SECRET_LEN}, e.g. `openssl rand -hex 32`",
						secret.trim().len()
					));
				}
				Sha256::digest(secret.as_bytes()).to_vec()
			}
			None if enabled => {
				// A random per-process key still works, but every restart (and
				// every replica) invalidates sessions, so say so loudly.
				warn!("REDLIB_OIDC_SESSION_SECRET is unset; generating an ephemeral key. Sessions will not survive a restart and will not work across replicas.");
				Sha256::digest(random_token(32).as_bytes()).to_vec()
			}
			None => Vec::new(),
		};

		Self {
			enabled,
			issuer: setting("REDLIB_OIDC_ISSUER").unwrap_or_default().trim_end_matches('/').to_string(),
			client_id: setting("REDLIB_OIDC_CLIENT_ID").unwrap_or_default(),
			client_secret: setting("REDLIB_OIDC_CLIENT_SECRET").unwrap_or_default(),
			redirect_uri: setting("REDLIB_OIDC_REDIRECT_URI").unwrap_or_default(),
			scopes: setting("REDLIB_OIDC_SCOPES").unwrap_or_else(|| DEFAULT_SCOPES.to_string()),
			session_ttl: setting("REDLIB_OIDC_SESSION_TTL").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_SESSION_TTL),
			allowed_groups: setting("REDLIB_OIDC_ALLOWED_GROUPS")
				.map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
				.unwrap_or_default(),
			bypass_cidrs,
			trusted_proxies,
			session_key,
			problems,
		}
	}

	/// OIDC settings that are set while OIDC is off. That usually means the
	/// switch itself was forgotten, and the instance is public by mistake.
	fn ignored_settings(&self) -> Vec<&'static str> {
		if self.enabled {
			return Vec::new();
		}
		["REDLIB_OIDC_ISSUER", "REDLIB_OIDC_CLIENT_ID", "REDLIB_OIDC_CLIENT_SECRET", "REDLIB_OIDC_SESSION_SECRET"]
			.into_iter()
			.filter(|key| setting(key).is_some())
			.collect()
	}

	/// The settings a working relying party cannot do without.
	fn missing_required(&self) -> Vec<&'static str> {
		[
			("REDLIB_OIDC_ISSUER", &self.issuer),
			("REDLIB_OIDC_CLIENT_ID", &self.client_id),
			("REDLIB_OIDC_CLIENT_SECRET", &self.client_secret),
			("REDLIB_OIDC_REDIRECT_URI", &self.redirect_uri),
		]
		.into_iter()
		.filter(|(_, v)| v.is_empty())
		.map(|(k, _)| k)
		.collect()
	}

	fn encoding_key(&self) -> EncodingKey {
		EncodingKey::from_secret(&self.session_key)
	}

	fn decoding_key(&self) -> DecodingKey {
		DecodingKey::from_secret(&self.session_key)
	}
}

/// Forced in `main` before the listener starts, so a misconfiguration stops
/// the process at startup instead of panicking inside the first request.
pub static AUTH: LazyLock<AuthConfig> = LazyLock::new(AuthConfig::load);

pub fn enabled() -> bool {
	AUTH.enabled
}

// ---------------------------------------------------------------------------
// Client IP resolution
// ---------------------------------------------------------------------------

/// Determines the effective client IP for allowlist purposes.
///
/// `peer` is the actual TCP peer address, which cannot be forged. If the peer
/// is not a configured trusted proxy, it *is* the client and `X-Forwarded-For`
/// is ignored outright -- otherwise anyone could send
/// `X-Forwarded-For: 192.168.1.1` and walk straight past the login.
///
/// If the peer is a trusted proxy, the XFF chain is walked from right to left
/// (nearest hop first) and the first address that is not itself a trusted
/// proxy is returned. Walking from the right matters: the left-hand entries
/// are the ones a client can prepend.
///
/// `None` means the client is unknown: the peer is a trusted proxy but the
/// chain names no client. The proxy's own address is deliberately not used
/// then. Proxies often sit inside a bypass range, and falling back to them
/// would let every request they forward skip the login.
pub fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
	resolve_with(&AUTH.trusted_proxies, peer, headers)
}

fn resolve_with(trusted: &[IpNet], peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
	let peer = canonical(peer);

	if !trusted.iter().any(|net| net.contains(&peer)) {
		return Some(peer);
	}

	// Every header line counts, in order: a proxy may append a line of its
	// own rather than extend the client's.
	let lines = headers.get_all("x-forwarded-for").iter().map(|v| v.to_str().ok()).collect::<Option<Vec<_>>>()?;

	// Nearest hop first. The first entry that can't be read ends the walk with
	// an unknown client: skipping it would let entries the client wrote
	// further left decide.
	for entry in lines.iter().flat_map(|line| line.split(',')).rev() {
		let ip = canonical(parse_forwarded_ip(entry.trim())?);
		if !trusted.iter().any(|net| net.contains(&ip)) {
			return Some(ip);
		}
	}
	None
}

/// One `X-Forwarded-For` entry: a bare IPv4 or IPv6 address, or an IPv6
/// address in brackets. Ports and anything else are refused.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
	match entry.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
		Some(v6) => v6.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6),
		None => entry.parse().ok(),
	}
}

/// Normalises IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) down to plain
/// IPv4.
///
/// This is load-bearing, not cosmetic. redlib listens on `[::]` by default, so
/// on a dual-stack socket every IPv4 client is reported as an IPv4-mapped IPv6
/// peer. Without this, an operator's `10.42.0.0/16` bypass rule would never
/// match anything and the allowlist would silently do nothing.
fn canonical(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
		v4 => v4,
	}
}

/// Whether this address is allowed to skip authentication.
pub fn is_bypassed(ip: IpAddr) -> bool {
	let ip = canonical(ip);
	AUTH.bypass_cidrs.iter().any(|net| net.contains(&ip))
}

// ---------------------------------------------------------------------------
// Session and transaction tokens
// ---------------------------------------------------------------------------

/// The authenticated identity, as carried in the session cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
	pub sub: String,
	#[serde(default)]
	pub username: String,
	#[serde(default)]
	pub email: String,
	#[serde(default)]
	pub groups: Vec<String>,
	pub exp: u64,
	pub iat: u64,
}

/// In-flight login state, signed and handed to the browser as a short-lived
/// cookie so that the callback can verify it without server-side storage.
#[derive(Debug, Serialize, Deserialize)]
struct LoginTx {
	state: String,
	nonce: String,
	verifier: String,
	/// Where to send the user once login completes.
	redirect_to: String,
	exp: u64,
}

fn sign<T: Serialize>(claims: &T) -> Result<String, String> {
	encode(&Header::new(Algorithm::HS256), claims, &AUTH.encoding_key()).map_err(|e| format!("failed to sign token: {e}"))
}

fn verify<T: for<'de> Deserialize<'de>>(token: &str) -> Result<T, String> {
	let mut validation = Validation::new(Algorithm::HS256);
	// These are our own tokens, not the provider's; there is no audience or
	// issuer to check, but `exp` is still enforced (the default).
	validation.validate_aud = false;
	validation.required_spec_claims.clear();
	validation.required_spec_claims.insert("exp".to_string());

	decode::<T>(token, &AUTH.decoding_key(), &validation)
		.map(|data| data.claims)
		.map_err(|e| format!("invalid token: {e}"))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
	headers
		.get_all("cookie")
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|raw| raw.split(';'))
		.find_map(|pair| {
			let (k, v) = pair.split_once('=')?;
			(k.trim() == name).then(|| v.trim().to_string())
		})
}

/// Whether the request carries the bearer token configured under `key`.
///
/// Session cookies are unusable by headless clients such as an MCP client, so
/// a long random token stands in for them. The gate consults
/// `REDLIB_MCP_TOKEN` for [`MCP_PATH`] only and `REDLIB_READ_TOKEN` only where
/// [`read_token_applies`] says so. Returns false whenever no token is
/// configured, so an unset value can never authorise anything.
///
/// The comparison hashes both sides first. A plain `==` on the raw strings
/// short-circuits at the first differing byte, which leaks the length of the
/// matching prefix and lets an attacker recover the token byte by byte.
/// Comparing digests makes the timing independent of how much of the token was
/// correct.
fn bearer_token_valid(headers: &HeaderMap, key: &str) -> bool {
	let Some(expected) = setting(key) else {
		return false;
	};

	let Some(presented) = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.and_then(|v| {
			// Auth schemes are case-insensitive (RFC 9110 11.1).
			let (scheme, token) = v.split_once(' ')?;
			scheme.eq_ignore_ascii_case("bearer").then_some(token)
		})
		.map(str::trim)
		.filter(|t| !t.is_empty())
	else {
		return false;
	};

	Sha256::digest(presented.as_bytes()) == Sha256::digest(expected.as_bytes())
}

/// Whether `REDLIB_READ_TOKEN` may open this request: GET or HEAD only, so it
/// can never submit a form, and nowhere in [`READ_TOKEN_EXCLUDED`]. The prefix
/// match ignores case, so a differently cased path cannot slip past it.
fn read_token_applies(method: &Method, path: &str) -> bool {
	if !matches!(*method, Method::GET | Method::HEAD) {
		return false;
	}
	!READ_TOKEN_EXCLUDED.iter().any(|excluded| is_at_or_under(path, excluded))
}

/// Whether `path` is `prefix` or lies under it, ignoring ASCII case.
fn is_at_or_under(path: &str, prefix: &str) -> bool {
	let Some(head) = path.get(..prefix.len()) else {
		return false;
	};
	head.eq_ignore_ascii_case(prefix) && matches!(path.as_bytes().get(prefix.len()), None | Some(b'/'))
}

/// Reads and validates the session cookie, if present and well-formed.
pub fn session_from(headers: &HeaderMap) -> Option<Session> {
	let raw = cookie_value(headers, SESSION_COOKIE)?;
	match verify::<Session>(&raw) {
		Ok(session) => Some(session),
		Err(e) => {
			debug!("rejecting session cookie: {e}");
			None
		}
	}
}

/// Always `Secure`, which the `__Host-` prefix requires. Browsers treat
/// `http://localhost` as secure, so a local `cargo run` still works; any
/// other instance has to be served over HTTPS.
fn cookie_attrs(max_age: u64) -> String {
	format!("Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}; Secure")
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
	issuer: String,
	authorization_endpoint: String,
	token_endpoint: String,
	jwks_uri: String,
	#[serde(default)]
	end_session_endpoint: Option<String>,
}

/// Discovery document and JWKS, fetched lazily and cached in memory.
///
/// Cached indefinitely on success; a failed fetch is not cached, so a provider
/// that is briefly unreachable at startup recovers on the next request.
static DISCOVERY: LazyLock<tokio::sync::RwLock<Option<Discovery>>> = LazyLock::new(|| tokio::sync::RwLock::new(None));
static JWKS: LazyLock<tokio::sync::RwLock<Option<JwkSet>>> = LazyLock::new(|| tokio::sync::RwLock::new(None));

/// Upper bound on each request to the provider, so one that is down or wedged
/// fails the login instead of holding the handler open.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

static HTTP: LazyLock<wreq::Client> = LazyLock::new(|| wreq::Client::builder().timeout(HTTP_TIMEOUT).build().expect("failed to build OIDC HTTP client"));

async fn discovery() -> Result<Discovery, String> {
	if let Some(cached) = DISCOVERY.read().await.clone() {
		return Ok(cached);
	}

	let url = format!("{}/.well-known/openid-configuration", AUTH.issuer);
	debug!("fetching OIDC discovery document from {url}");

	let resp = HTTP.get(&url).send().await.map_err(|e| format!("discovery request to {url} failed: {e}"))?;
	if !resp.status().is_success() {
		return Err(format!("discovery request to {url} returned HTTP {}", resp.status()));
	}
	let doc: Discovery = resp.json().await.map_err(|e| format!("could not parse discovery document: {e}"))?;

	// The issuer in the document is authoritative for later ID-token
	// validation, but a mismatch with what we were configured with means the
	// operator pointed us somewhere unexpected.
	if doc.issuer.trim_end_matches('/') != AUTH.issuer {
		warn!(
			"configured issuer {} does not match discovery issuer {}; using the latter for validation",
			AUTH.issuer, doc.issuer
		);
	}

	*DISCOVERY.write().await = Some(doc.clone());
	Ok(doc)
}

/// Fetches the provider's signing keys. `force` bypasses the cache, which is
/// what happens when a token arrives with an unrecognised `kid` -- the usual
/// sign that the provider rotated its keys.
async fn jwks(force: bool) -> Result<JwkSet, String> {
	if !force {
		if let Some(cached) = JWKS.read().await.clone() {
			return Ok(cached);
		}
	}

	let uri = discovery().await?.jwks_uri;
	let resp = HTTP.get(&uri).send().await.map_err(|e| format!("JWKS request to {uri} failed: {e}"))?;
	if !resp.status().is_success() {
		return Err(format!("JWKS request to {uri} returned HTTP {}", resp.status()));
	}
	let set: JwkSet = resp.json().await.map_err(|e| format!("could not parse JWKS: {e}"))?;

	*JWKS.write().await = Some(set.clone());
	Ok(set)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn redirect_to(location: &str, cookies: &[String]) -> Response<Body> {
	let mut builder = Response::builder().status(StatusCode::FOUND).header("location", location);
	for cookie in cookies {
		builder = builder.header("set-cookie", cookie);
	}
	builder.body(Body::empty()).unwrap_or_default()
}

fn error_page(status: StatusCode, message: &str) -> Response<Body> {
	Response::builder()
		.status(status)
		.header("content-type", "text/html; charset=utf-8")
		.body(Body::from(format!(
			"<!DOCTYPE html><html><head><title>Authentication error</title></head>\
			<body><h1>Authentication error</h1><p>{}</p>\
			<p><a href=\"/oidc/login\">Try again</a></p></body></html>",
			htmlescape::encode_minimal(message)
		)))
		.unwrap_or_default()
}

/// The `redirect` query parameter of a login request, if it is a path on this
/// instance; the front page otherwise. Accepting an absolute or
/// protocol-relative URL here would make login an open redirector.
fn redirect_target(query: Option<&str>) -> String {
	query
		.and_then(|q| {
			serde_urlencoded::from_str::<Vec<(String, String)>>(q)
				.ok()?
				.into_iter()
				.find(|(k, _)| k == "redirect")
				.map(|(_, v)| v)
		})
		.and_then(|p| local_path(&p))
		.unwrap_or_else(|| "/".to_string())
}

/// Whether `p` starts like a path on this instance: one `/`, then anything
/// but a second `/` or a `\`.
fn is_single_slash_path(p: &str) -> bool {
	let mut chars = p.chars();
	chars.next() == Some('/') && !matches!(chars.next(), Some('/' | '\\'))
}

/// `p` rebuilt as a path and query on this instance, or `None` if a browser
/// could read it as a URL on another host.
///
/// Browsers treat `\` as `/` and silently drop tabs and newlines, so any of
/// those can turn `/\evil.example` or `/<TAB>/evil.example` into
/// `//evil.example`. They are refused outright rather than cleaned up.
fn local_path(p: &str) -> Option<String> {
	if !is_single_slash_path(p) || p.chars().any(|c| c == '\\' || c.is_control() || c.is_whitespace()) {
		return None;
	}

	// Rebuild from a parsed URL so only a path and a query come out. Parsing
	// also resolves dot segments, which can produce a fresh `//`, so the
	// result is checked again.
	let base = url::Url::parse("http://redlib.invalid/").ok()?;
	let url = base.join(p).ok()?;
	if url.origin() != base.origin() {
		return None;
	}
	let mut out = url.path().to_string();
	if let Some(query) = url.query() {
		out.push('?');
		out.push_str(query);
	}
	is_single_slash_path(&out).then_some(out)
}

/// Starts the authorization-code flow.
pub async fn login(req: Request<Body>) -> Result<Response<Body>, String> {
	let disco = match discovery().await {
		Ok(d) => d,
		Err(e) => {
			error!("OIDC discovery failed: {e}");
			return Ok(error_page(StatusCode::BAD_GATEWAY, "Could not reach the identity provider."));
		}
	};

	let state = random_token(32);
	let nonce = random_token(32);
	let verifier = random_token(64);
	let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

	let tx = LoginTx {
		state: state.clone(),
		nonce: nonce.clone(),
		verifier,
		redirect_to: redirect_target(req.uri().query()),
		exp: now() + TX_TTL,
	};
	let tx_token = sign(&tx)?;

	let query = serde_urlencoded::to_string([
		("response_type", "code"),
		("client_id", &AUTH.client_id),
		("redirect_uri", &AUTH.redirect_uri),
		("scope", &AUTH.scopes),
		("state", &state),
		("nonce", &nonce),
		("code_challenge", &challenge),
		("code_challenge_method", "S256"),
	])
	.map_err(|e| format!("could not build authorization URL: {e}"))?;

	let sep = if disco.authorization_endpoint.contains('?') { '&' } else { '?' };
	let location = format!("{}{sep}{query}", disco.authorization_endpoint);

	Ok(redirect_to(&location, &[format!("{TX_COOKIE}={tx_token}; {}", cookie_attrs(TX_TTL))]))
}

#[derive(Deserialize)]
struct TokenResponse {
	id_token: String,
}

/// Claims we care about from the provider's ID token.
#[derive(Debug, Deserialize)]
struct IdClaims {
	sub: String,
	#[serde(default)]
	preferred_username: Option<String>,
	#[serde(default)]
	name: Option<String>,
	#[serde(default)]
	email: Option<String>,
	#[serde(default)]
	groups: Vec<String>,
	#[serde(default)]
	nonce: Option<String>,
	#[serde(default, deserialize_with = "one_or_many")]
	aud: Vec<String>,
	#[serde(default)]
	azp: Option<String>,
	#[serde(default)]
	iat: Option<u64>,
}

/// Handles the provider's redirect back to us.
pub async fn callback(req: Request<Body>) -> Result<Response<Body>, String> {
	let params: Vec<(String, String)> = req.uri().query().and_then(|q| serde_urlencoded::from_str(q).ok()).unwrap_or_default();
	let param = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());

	// The provider reports failures (e.g. the user hit "deny") in-band. Both
	// values are attacker-controlled: they are logged with `{:?}` so they
	// cannot inject log lines, and the page shows a fixed message so nobody
	// can put words in this instance's mouth.
	if let Some(err) = param("error") {
		warn!("identity provider returned error {err:?}: {:?}", param("error_description"));
		return Ok(error_page(StatusCode::FORBIDDEN, "The identity provider did not complete the sign-in."));
	}

	let (Some(code), Some(state)) = (param("code"), param("state")) else {
		return Ok(error_page(StatusCode::BAD_REQUEST, "Missing authorization code."));
	};

	let Some(tx_raw) = cookie_value(req.headers(), TX_COOKIE) else {
		return Ok(error_page(StatusCode::BAD_REQUEST, "Login session expired. Please try again."));
	};
	let tx: LoginTx = match verify(&tx_raw) {
		Ok(tx) => tx,
		Err(e) => {
			warn!("rejecting login transaction cookie: {e}");
			return Ok(error_page(StatusCode::BAD_REQUEST, "Login session expired. Please try again."));
		}
	};

	// CSRF defence: the state we signed must match the one echoed back.
	if tx.state != state {
		warn!("OIDC state mismatch; possible CSRF attempt");
		return Ok(error_page(StatusCode::BAD_REQUEST, "Invalid login state."));
	}

	let claims = match exchange_and_validate(&code, &tx).await {
		Ok(claims) => claims,
		Err(e) => {
			error!("OIDC token exchange failed: {e}");
			return Ok(error_page(StatusCode::FORBIDDEN, "Could not complete sign-in."));
		}
	};

	if !AUTH.allowed_groups.is_empty() && !claims.groups.iter().any(|g| AUTH.allowed_groups.contains(g)) {
		warn!("denying {}: groups {:?} do not intersect the allowlist", claims.sub, claims.groups);
		return Ok(error_page(StatusCode::FORBIDDEN, "Your account is not permitted to access this instance."));
	}

	let issued = now();
	let session = Session {
		sub: claims.sub.clone(),
		username: claims.preferred_username.or(claims.name).unwrap_or_else(|| claims.sub.clone()),
		email: claims.email.unwrap_or_default(),
		groups: claims.groups,
		exp: issued + AUTH.session_ttl,
		iat: issued,
	};
	let token = sign(&session)?;
	info!("OIDC login succeeded for {}", session.username);

	Ok(redirect_to(
		&tx.redirect_to,
		&[
			format!("{SESSION_COOKIE}={token}; {}", cookie_attrs(AUTH.session_ttl)),
			// Retire the transaction cookie now that it has been consumed.
			format!("{TX_COOKIE}=; {}", cookie_attrs(0)),
		],
	))
}

/// Exchanges the authorization code for tokens and fully validates the ID
/// token: signature against the provider's JWKS, plus issuer, audience,
/// expiry, and the nonce we generated at login.
async fn exchange_and_validate(code: &str, tx: &LoginTx) -> Result<IdClaims, String> {
	let disco = discovery().await?;

	let form = serde_urlencoded::to_string([
		("grant_type", "authorization_code"),
		("code", code),
		("redirect_uri", &AUTH.redirect_uri),
		("client_id", &AUTH.client_id),
		("client_secret", &AUTH.client_secret),
		("code_verifier", &tx.verifier),
	])
	.map_err(|e| format!("could not encode token request: {e}"))?;

	let resp = HTTP
		.post(&disco.token_endpoint)
		.header("content-type", "application/x-www-form-urlencoded")
		.body(form)
		.send()
		.await
		.map_err(|e| format!("token request failed: {e}"))?;

	let status = resp.status();
	if !status.is_success() {
		let body = resp.text().await.unwrap_or_default();
		return Err(format!("token endpoint returned HTTP {status}: {body}"));
	}

	let tokens: TokenResponse = resp.json().await.map_err(|e| format!("could not parse token response: {e}"))?;

	let header = decode_header(&tokens.id_token).map_err(|e| format!("malformed ID token: {e}"))?;
	let kid = header.kid.ok_or("ID token has no key id")?;

	// An unknown kid usually means the provider rotated keys, so refetch once
	// before giving up.
	let mut set = jwks(false).await?;
	if set.find(&kid).is_none() {
		debug!("key id {kid} not in cached JWKS; refetching");
		set = jwks(true).await?;
	}
	let jwk = set.find(&kid).ok_or_else(|| format!("no signing key matches key id {kid}"))?;

	validate_id_token(&tokens.id_token, jwk, &disco.issuer, &AUTH.client_id, &tx.nonce)
}

/// Checks an ID token's signature against `jwk` and its claims against what
/// this relying party expects.
fn validate_id_token(id_token: &str, jwk: &Jwk, issuer: &str, client_id: &str, nonce: &str) -> Result<IdClaims, String> {
	let key = DecodingKey::from_jwk(jwk).map_err(|e| format!("unusable signing key: {e}"))?;

	// The algorithm comes from our side, never from the token's header, so a
	// token cannot pick a weaker check for itself.
	let mut validation = Validation::new(id_token_algorithm(jwk)?);
	validation.set_audience(&[client_id]);
	validation.set_issuer(&[issuer]);
	validation.set_required_spec_claims(&["iss", "aud", "exp"]);

	let claims = decode::<IdClaims>(id_token, &key, &validation)
		.map_err(|e| format!("ID token validation failed: {e}"))?
		.claims;

	// jsonwebtoken neither requires nor checks `iat`.
	let iat = claims.iat.ok_or("ID token has no iat")?;
	if iat > now() + MAX_IAT_SKEW {
		return Err(format!("ID token iat {iat} is in the future"));
	}

	// OIDC Core 3.1.3.7: with several audiences, `azp` must name us; when
	// present at all, it must be us.
	if (claims.aud.len() > 1 || claims.azp.is_some()) && claims.azp.as_deref() != Some(client_id) {
		return Err(format!("ID token azp {:?} is not this client", claims.azp));
	}

	// Binds this ID token to the login request that started the flow,
	// preventing token replay.
	if claims.nonce.as_deref() != Some(nonce) {
		return Err("ID token nonce does not match the login request".to_string());
	}

	Ok(claims)
}

/// The algorithm an ID token signed with `jwk` must use: the key's declared
/// `alg` if it has one, RS256 (the OIDC default) otherwise. Symmetric and
/// encryption algorithms are refused.
fn id_token_algorithm(jwk: &Jwk) -> Result<Algorithm, String> {
	let Some(declared) = jwk.common.key_algorithm else {
		return Ok(Algorithm::RS256);
	};
	match declared.to_string().parse::<Algorithm>() {
		Ok(Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) | Err(_) => Err(format!("signing key declares {declared}, which is not an asymmetric signature algorithm")),
		Ok(alg) => Ok(alg),
	}
}

/// `aud` may be a single string or an array of them.
fn one_or_many<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
	#[derive(Deserialize)]
	#[serde(untagged)]
	enum OneOrMany {
		One(String),
		Many(Vec<String>),
	}
	Ok(match OneOrMany::deserialize(deserializer)? {
		OneOrMany::One(aud) => vec![aud],
		OneOrMany::Many(auds) => auds,
	})
}

/// Clears the local session, then hands off to the provider's end-session
/// endpoint when it advertises one.
pub async fn logout(_req: Request<Body>) -> Result<Response<Body>, String> {
	let clear = format!("{SESSION_COOKIE}=; {}", cookie_attrs(0));

	let location = match discovery().await {
		Ok(disco) => disco.end_session_endpoint.unwrap_or_else(|| "/".to_string()),
		Err(_) => "/".to_string(),
	};

	Ok(redirect_to(&location, &[clear]))
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/// Decides whether a request may proceed.
///
/// Returns `None` to allow the request through, or `Some(response)` to
/// short-circuit it (a redirect to login for browsers, a 401 otherwise).
///
/// Only the login endpoints and `/healthz` are exempt (`UNGATED_PATHS`).
/// Static files, `/healthz/reddit` and `/mcp` are gated like everything
/// else; MCP clients present `REDLIB_MCP_TOKEN` as a bearer token, which
/// opens `/mcp` and nothing else. Read-only services present
/// `REDLIB_READ_TOKEN`, which opens GET and HEAD requests outside
/// [`READ_TOKEN_EXCLUDED`].
///
/// `method` is the request's original method, before the server maps HEAD
/// to GET for routing.
pub fn gate(peer: IpAddr, method: &Method, path: &str, query: Option<&str>, headers: &HeaderMap) -> Option<Response<Body>> {
	if !AUTH.enabled {
		return None;
	}

	// The login endpoints must stay reachable or login could never complete,
	// and kubelet probes /healthz from the pod-network bridge, which is a
	// trusted-proxy address without X-Forwarded-For and so gets no bypass.
	// Exact matches only: a prefix would hand every other /oidc/... path,
	// and whatever request handling sits behind it, to anonymous clients.
	if UNGATED_PATHS.contains(&path) {
		return None;
	}

	// An unknown client is never bypassed, but can still authenticate.
	let client = resolve_client_ip(peer, headers);
	if client.is_some_and(is_bypassed) {
		note_pass("bypass", client, peer);
		return None;
	}

	// Checked before the cookie so that MCP clients have a credential they can
	// actually present. Only for `/mcp`: a token handed to an MCP client must
	// not open the rest of the instance. `path` has already been normalised
	// by the server (no doubled or trailing slashes).
	if path == MCP_PATH && bearer_token_valid(headers, "REDLIB_MCP_TOKEN") {
		note_pass("bearer", client, peer);
		return None;
	}

	// For services that only read pages. Never for a method that can submit
	// a form, never for settings, and never for /mcp or /oidc.
	if read_token_applies(method, path) && bearer_token_valid(headers, "REDLIB_READ_TOKEN") {
		note_pass("read-token", client, peer);
		return None;
	}

	if session_from(headers).is_some() {
		return None;
	}

	debug!("unauthenticated request from {client:?} for {path}");
	note_denial(client, peer, path);

	// Programmatic clients get a plain 401 rather than an HTML redirect they
	// cannot follow. This is what an MCP client or curl will see.
	if !wants_html(headers) {
		return Some(
			Response::builder()
				.status(StatusCode::UNAUTHORIZED)
				.header("www-authenticate", format!("Bearer realm=\"{}\"", AUTH.issuer))
				.header("content-type", "application/json")
				.body(Body::from(r#"{"error":"unauthorized","error_description":"Authentication required."}"#))
				.unwrap_or_default(),
		);
	}

	Some(redirect_to(&login_target(path, query), &[]))
}

/// Longest path and query the login redirect will carry. It comes back in
/// the signed login cookie, and browsers drop cookies over 4 KiB.
const MAX_REDIRECT_LEN: usize = 1024;

/// The login URL that sends the user back to `path` and `query` afterwards.
/// The login endpoint validates the target again, so this only has to keep
/// it small: the query is dropped if it is too long, the path as well if
/// that is.
fn login_target(path: &str, query: Option<&str>) -> String {
	let full = match query.filter(|q| !q.is_empty()) {
		Some(q) => format!("{path}?{q}"),
		None => path.to_string(),
	};
	let back = [full.as_str(), path].into_iter().find(|p| p.len() <= MAX_REDIRECT_LEN).unwrap_or("/");
	format!("/oidc/login?redirect={}", urlencoding_path(back))
}

// ---------------------------------------------------------------------------
// Gate logging
// ---------------------------------------------------------------------------

/// Lets one line through per key and interval, and counts what it held back.
/// The table is capped, so an attacker who varies the key cannot grow it
/// without bound: once it is full of live entries, new keys are not
/// itemised until old ones expire. They are counted, and `summary` reports
/// the count once per interval, so a full table never hides activity. That
/// caps the lines per interval at `cap` plus one.
struct LogThrottle<K> {
	interval: Duration,
	cap: usize,
	seen: HashMap<K, (Instant, u32)>,
	/// Keys turned away because the table was full, since the last summary.
	refused: u32,
	last_summary: Option<Instant>,
}

impl<K: Hash + Eq> LogThrottle<K> {
	fn new(interval: Duration, cap: usize) -> Self {
		Self {
			interval,
			cap,
			seen: HashMap::new(),
			refused: 0,
			last_summary: None,
		}
	}

	/// `Some(n)` if a line may be logged now, where `n` is how many were held
	/// back for this key since the last one; `None` if it should be held back.
	fn allow(&mut self, key: K, now: Instant) -> Option<u32> {
		if let Some((last, held)) = self.seen.get_mut(&key) {
			if now.duration_since(*last) < self.interval {
				*held = held.saturating_add(1);
				return None;
			}
			*last = now;
			return Some(std::mem::take(held));
		}
		if self.seen.len() >= self.cap {
			let interval = self.interval;
			self.seen.retain(|_, (last, _)| now.duration_since(*last) < interval);
			if self.seen.len() >= self.cap {
				self.refused = self.refused.saturating_add(1);
				return None;
			}
		}
		self.seen.insert(key, (now, 0));
		Some(0)
	}

	/// `Some(n)` if a summary line may be logged now, where `n` is how many
	/// requests from keys the full table could not itemise were turned away
	/// since the last one.
	fn summary(&mut self, now: Instant) -> Option<u32> {
		if self.refused == 0 || self.last_summary.is_some_and(|last| now.duration_since(last) < self.interval) {
			return None;
		}
		self.last_summary = Some(now);
		Some(std::mem::take(&mut self.refused))
	}
}

/// The throttle key for a client: IPv6 addresses are keyed by their /64,
/// because one subscriber holds a whole /64 and could otherwise present a
/// new "client" with every request.
fn log_key(ip: IpAddr) -> IpAddr {
	match canonical(ip) {
		IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
		v4 => v4,
	}
}

/// One denial line per client per minute.
static DENIAL_LOG: LazyLock<Mutex<LogThrottle<IpAddr>>> = LazyLock::new(|| Mutex::new(LogThrottle::new(Duration::from_secs(60), 1024)));

/// One line per client and kind of pass per day, so the first use of a
/// bypass address or of the MCP token is on record without logging every
/// request.
static PASS_LOG: LazyLock<Mutex<LogThrottle<(&'static str, IpAddr)>>> = LazyLock::new(|| Mutex::new(LogThrottle::new(Duration::from_secs(86_400), 1024)));

/// The most of a path that goes into a log line.
const MAX_LOGGED_PATH: usize = 200;

fn describe_client(client: Option<IpAddr>) -> String {
	client.map_or_else(|| "unknown".to_string(), |ip| ip.to_string())
}

/// Logs a denied request at info, at most once a minute per client. The
/// path is attacker-controlled, so it is escaped and cut short; the query
/// string is left out because it can carry secrets.
fn note_denial(client: Option<IpAddr>, peer: IpAddr, path: &str) {
	let peer = canonical(peer);
	let now = Instant::now();
	let (allowed, overflow) = {
		let mut table = DENIAL_LOG.lock().unwrap_or_else(PoisonError::into_inner);
		let allowed = table.allow(log_key(client.unwrap_or(peer)), now);
		let overflow = if allowed.is_none() { table.summary(now) } else { None };
		(allowed, overflow)
	};
	if let Some(n) = overflow {
		info!("OIDC gate: {n} more denials from clients not itemised (log table full)");
	}
	if let Some(held) = allowed {
		let path: String = path.chars().take(MAX_LOGGED_PATH).collect();
		let held = if held > 0 {
			format!(" ({held} more from this client in the last minute)")
		} else {
			String::new()
		};
		info!("OIDC gate: denied {path:?} from client {} (peer {peer}){held}", describe_client(client));
	}
}

/// Logs the first request a client gets through without a session, as a
/// `kind` of "bypass" (address allowlist) or "bearer" (MCP token).
fn note_pass(kind: &'static str, client: Option<IpAddr>, peer: IpAddr) {
	let peer = canonical(peer);
	let now = Instant::now();
	let (allowed, overflow) = {
		let mut table = PASS_LOG.lock().unwrap_or_else(PoisonError::into_inner);
		let allowed = table.allow((kind, log_key(client.unwrap_or(peer))), now);
		let overflow = if allowed.is_none() { table.summary(now) } else { None };
		(allowed, overflow)
	};
	if let Some(n) = overflow {
		info!("OIDC gate: {n} more {kind} passes from clients not itemised (log table full)");
	}
	if allowed.is_some() {
		info!("OIDC gate: first {kind} pass from client {} (peer {peer})", describe_client(client));
	}
}

/// Percent-encodes a path (and query) for use as a query-string value.
fn urlencoding_path(path: &str) -> String {
	serde_urlencoded::to_string([("r", path)])
		.map(|s| s.trim_start_matches("r=").to_string())
		.unwrap_or_else(|_| "/".to_string())
}

/// Distinguishes a browser from a programmatic client, so each gets an
/// appropriate rejection.
fn wants_html(headers: &HeaderMap) -> bool {
	headers.get("accept").and_then(|v| v.to_str().ok()).is_some_and(|a| a.contains("text/html"))
}

#[cfg(test)]
mod login_query_tests {
	use super::*;
	use hyper::header::HeaderValue;
	use sealed_test::prelude::*;

	fn browser() -> HeaderMap {
		let mut map = HeaderMap::new();
		map.insert("accept", HeaderValue::from_static("text/html,application/xhtml+xml,*/*;q=0.8"));
		map
	}

	/// The `Location` the gate answers an anonymous browser with.
	fn login_location(path: &str, query: Option<&str>) -> String {
		let res = gate("203.0.113.9".parse().unwrap(), &Method::GET, path, query, &browser()).expect("must be gated");
		res.headers().get("location").unwrap().to_str().unwrap().to_string()
	}

	/// Where the login endpoint would send the user back to, given the gate's `Location`.
	fn landing(location: &str) -> String {
		redirect_target(location.split_once('?').map(|(_, q)| q))
	}

	// Audit info item: server.rs passed only the path to the gate, so a login
	// started from `/search?q=x` came back as `/search`.
	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn the_login_round_trip_keeps_the_query_string() {
		let location = login_location("/search", Some("q=x&sort=new"));
		assert_eq!(location, "/oidc/login?redirect=%2Fsearch%3Fq%3Dx%26sort%3Dnew");
		assert_eq!(landing(&location), "/search?q=x&sort=new");

		// Reserved characters survive both layers of encoding.
		let location = login_location("/r/rust/search", Some("q=a+b%26c&restrict_sr=on"));
		assert_eq!(landing(&location), "/r/rust/search?q=a+b%26c&restrict_sr=on");

		// No query, no question mark.
		assert_eq!(landing(&login_location("/r/rust", None)), "/r/rust");
		assert_eq!(landing(&login_location("/r/rust", Some(""))), "/r/rust");
	}

	// The query rides through the same same-origin validation as the path.
	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn the_query_cannot_point_the_redirect_off_site() {
		// A query is just data after a local path, however URL-shaped.
		for query in ["redirect=https://evil.example", "next=//evil.example", "u=http://evil.example/&x=1"] {
			let target = landing(&login_location("/", Some(query)));
			assert_eq!(target, format!("/?{query}"));
			assert!(target.starts_with("/?"), "{target}");
		}

		// A path the validator refuses is refused whatever the query says.
		assert_eq!(landing(&login_location("/\\evil.example", Some("q=x"))), "/");
		assert_eq!(landing(&login_location("//evil.example", Some("q=x"))), "/");
		// So is a query a browser would read differently from the server.
		assert_eq!(landing(&login_location("/search", Some("q=a\tb"))), "/");
		assert_eq!(landing(&login_location("/search", Some("q=a\\b"))), "/");
	}

	// The target lives in a cookie, and browsers drop cookies over 4 KiB, which
	// would break the login altogether.
	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn an_oversized_query_is_dropped_and_the_path_kept() {
		let long = format!("q={}", "a".repeat(5000));
		let location = login_location("/search", Some(&long));
		assert_eq!(landing(&location), "/search");
		assert!(location.len() < 200, "{}", location.len());

		// A path that long has nowhere sensible to go back to.
		let location = login_location(&format!("/{}", "a".repeat(5000)), Some("q=x"));
		assert_eq!(landing(&location), "/");
	}

	// Programmatic clients still get the plain 401, with nothing of the URL in it.
	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn programmatic_clients_still_get_a_401_with_a_query() {
		let res = gate("203.0.113.9".parse().unwrap(), &Method::GET, "/search", Some("q=x"), &HeaderMap::new()).expect("must be gated");
		assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
	}
}

#[cfg(test)]
mod log_throttle_tests {
	use super::*;

	const MINUTE: Duration = Duration::from_secs(60);

	#[test]
	fn one_line_per_key_per_interval_and_the_rest_are_counted() {
		let mut t = LogThrottle::new(MINUTE, 8);
		let start = Instant::now();
		assert_eq!(t.allow("a", start), Some(0));
		for n in 1..=5 {
			assert_eq!(t.allow("a", start + Duration::from_secs(n)), None);
		}
		// Another key is its own story.
		assert_eq!(t.allow("b", start + Duration::from_secs(6)), Some(0));
		// After the interval the next line reports what was held back.
		assert_eq!(t.allow("a", start + MINUTE), Some(5));
		assert_eq!(t.allow("a", start + MINUTE + Duration::from_secs(1)), None);
	}

	#[test]
	fn keys_the_full_table_turns_away_are_counted_and_summarised_once_per_interval() {
		let mut t = LogThrottle::new(MINUTE, 2);
		let start = Instant::now();
		assert_eq!(t.summary(start), None, "nothing refused, nothing to say");
		assert_eq!(t.allow(1, start), Some(0));
		assert_eq!(t.allow(2, start), Some(0));
		for key in 3..=7 {
			assert_eq!(t.allow(key, start), None);
		}
		assert_eq!(t.summary(start), Some(5));
		assert_eq!(t.summary(start), None);
		// More turned away inside the interval wait for the next summary.
		assert_eq!(t.allow(8, start + Duration::from_secs(1)), None);
		assert_eq!(t.summary(start + Duration::from_secs(1)), None);
		assert_eq!(t.allow(9, start + Duration::from_secs(2)), None);
		assert_eq!(t.summary(start + MINUTE), Some(2));
	}

	#[test]
	fn ipv6_clients_are_keyed_by_their_64_and_mapped_ipv4_by_the_v4_address() {
		let key = |s: &str| log_key(s.parse().unwrap());
		assert_eq!(key("2001:db8::1"), key("2001:db8::ffff:ffff:ffff:ffff"));
		assert_ne!(key("2001:db8::1"), key("2001:db8:0:1::1"));
		assert_eq!(key("::ffff:203.0.113.9"), key("203.0.113.9"));
		assert_ne!(key("203.0.113.9"), key("203.0.113.10"));
	}

	#[test]
	fn the_table_cannot_grow_past_its_cap() {
		let mut t = LogThrottle::new(MINUTE, 4);
		let start = Instant::now();
		for key in 0..4 {
			assert_eq!(t.allow(key, start), Some(0));
		}
		// Full of live entries: new keys are held back, not stored.
		for key in 4..1000 {
			assert_eq!(t.allow(key, start + Duration::from_secs(1)), None);
		}
		assert_eq!(t.seen.len(), 4);
		// Once the old entries expire, new keys fit again.
		assert_eq!(t.allow(1000, start + MINUTE), Some(0));
		assert!(t.seen.len() <= 4);
	}
}

#[cfg(test)]
mod gate_log_tests {
	use super::*;
	use hyper::header::HeaderValue;
	use sealed_test::prelude::*;
	use std::sync::Mutex;

	// Audit finding #13: denials and bypass or bearer passes left no trace at
	// the info level the deployment runs at. Every test runs in its own
	// process (`sealed_test`), so the global logger below is its own too.
	struct Capture(Mutex<Vec<(log::Level, String)>>);

	impl log::Log for Capture {
		fn enabled(&self, _: &log::Metadata) -> bool {
			true
		}
		fn log(&self, record: &log::Record) {
			self.0.lock().unwrap().push((record.level(), record.args().to_string()));
		}
		fn flush(&self) {}
	}

	static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

	fn capture_info_logs() {
		log::set_logger(&CAPTURE).expect("one logger per test process");
		// What the deployment runs at.
		log::set_max_level(log::LevelFilter::Info);
		// Loading the config logs its own summary; that is not what is under test.
		let _ = enabled();
		logged();
	}

	/// What was logged at info or above since the last call.
	fn logged() -> Vec<String> {
		std::mem::take(&mut *CAPTURE.0.lock().unwrap())
			.into_iter()
			.filter(|(level, _)| *level <= log::Level::Info)
			.map(|(_, line)| line)
			.collect()
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
		let mut map = HeaderMap::new();
		for (name, value) in pairs {
			map.append(*name, HeaderValue::from_str(value).unwrap());
		}
		map
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_TRUSTED_PROXIES", "10.42.0.0/16"),
	])]
	fn a_denial_is_logged_at_info_with_the_resolved_client_ip() {
		capture_info_logs();

		let res = gate(
			ip("10.42.0.7"),
			&Method::GET,
			"/r/rust",
			Some("token=hunter2"),
			&headers(&[("x-forwarded-for", "203.0.113.9")]),
		);
		assert!(res.is_some());

		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("203.0.113.9"), "{lines:?}");
		assert!(lines[0].contains("/r/rust"), "{lines:?}");
		// The proxy that forwarded it is worth knowing too, the query is not.
		assert!(lines[0].contains("10.42.0.7"), "{lines:?}");
		assert!(!lines[0].contains("hunter2"), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn denials_are_sampled_per_client_so_a_flood_cannot_flood_the_log() {
		capture_info_logs();

		// One client trying paths: one line, whatever it asks for.
		for n in 0..500 {
			assert!(gate(ip("203.0.113.9"), &Method::GET, &format!("/oidc/x{n}"), None, &HeaderMap::new()).is_some());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "{} lines", lines.len());
		assert!(lines[0].contains("203.0.113.9"), "{lines:?}");

		// Another client is a separate story and still gets its line.
		assert!(gate(ip("203.0.113.10"), &Method::GET, "/", None, &HeaderMap::new()).is_some());
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("203.0.113.10"), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn a_logged_path_cannot_forge_log_lines() {
		capture_info_logs();

		assert!(gate(ip("203.0.113.9"), &Method::GET, "/x\n2026-01-01 INFO oidc: forged\r", None, &HeaderMap::new()).is_some());
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(!lines[0].contains('\n') && !lines[0].contains('\r'), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.0.0/16"),
	])]
	fn the_first_bypass_pass_per_client_is_logged_once() {
		capture_info_logs();

		for _ in 0..20 {
			assert!(gate(ip("192.168.1.20"), &Method::GET, "/", None, &HeaderMap::new()).is_none());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("bypass") && lines[0].contains("192.168.1.20"), "{lines:?}");

		assert!(gate(ip("192.168.1.21"), &Method::GET, "/", None, &HeaderMap::new()).is_none());
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("192.168.1.21"), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_MCP_TOKEN", "correct-horse-battery-staple"),
	])]
	fn the_first_bearer_pass_per_client_is_logged_once_without_the_token() {
		capture_info_logs();

		let bearer = headers(&[("authorization", "Bearer correct-horse-battery-staple")]);
		for _ in 0..20 {
			assert!(gate(ip("203.0.113.9"), &Method::GET, "/mcp", None, &bearer).is_none());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("bearer") && lines[0].contains("203.0.113.9"), "{lines:?}");
		assert!(!lines[0].contains("correct-horse"), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn ordinary_traffic_is_not_logged() {
		capture_info_logs();

		// The probe and the login endpoints are open by design, and a signed-in
		// user is not news.
		for path in ["/healthz", "/oidc/login", "/oidc/callback"] {
			assert!(gate(ip("203.0.113.9"), &Method::GET, path, None, &HeaderMap::new()).is_none());
		}
		let token = sign(&Session {
			sub: "user-1".into(),
			username: "user".into(),
			email: String::new(),
			groups: vec![],
			exp: now() + 3600,
			iat: now(),
		})
		.unwrap();
		let cookie = headers(&[("cookie", &format!("{SESSION_COOKIE}={token}"))]);
		assert!(gate(ip("203.0.113.9"), &Method::GET, "/", None, &cookie).is_none());
		assert_eq!(logged(), Vec::<String>::new());
	}
}

#[cfg(test)]
mod gate_log_flood_tests {
	use super::*;
	use sealed_test::prelude::*;
	use std::sync::Mutex;

	// Review of the observability branch: the throttle tables are capped, but
	// once full they dropped new clients without a trace, so an attacker with
	// a /64 (or a proxy pool) could switch denial logging off for everyone
	// else. Each test runs in its own process (`sealed_test`).
	struct Capture(Mutex<Vec<(log::Level, String)>>);

	impl log::Log for Capture {
		fn enabled(&self, _: &log::Metadata) -> bool {
			true
		}
		fn log(&self, record: &log::Record) {
			self.0.lock().unwrap().push((record.level(), record.args().to_string()));
		}
		fn flush(&self) {}
	}

	static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

	fn capture_info_logs() {
		log::set_logger(&CAPTURE).expect("one logger per test process");
		log::set_max_level(log::LevelFilter::Info);
		// Loading the config logs its own summary; that is not what is under test.
		let _ = enabled();
		logged();
	}

	fn logged() -> Vec<String> {
		std::mem::take(&mut *CAPTURE.0.lock().unwrap())
			.into_iter()
			.filter(|(level, _)| *level <= log::Level::Info)
			.map(|(_, line)| line)
			.collect()
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	/// The n-th distinct IPv4 client, none of them in the test's trusted or bypass ranges.
	fn v4_client(n: u32) -> IpAddr {
		IpAddr::from([100, 64 + (n >> 16) as u8, (n >> 8) as u8, n as u8])
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn one_ipv6_prefix_is_one_client_for_the_log() {
		capture_info_logs();

		// A single /64 hands out 2^64 addresses; they are one subscriber.
		for n in 0..1100u32 {
			let client = ip(&format!("2001:db8::{n:x}"));
			assert!(gate(client, &Method::GET, "/secret-probe", None, &HeaderMap::new()).is_some());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "{} lines", lines.len());

		// The next /64 is somebody else.
		assert!(gate(ip("2001:db8:0:1::1"), &Method::GET, "/", None, &HeaderMap::new()).is_some());
		assert_eq!(logged().len(), 1);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn a_full_denial_table_still_leaves_a_trace_for_new_clients() {
		capture_info_logs();

		// Fill the table with distinct clients; each gets its own line.
		let mut itemised = 0;
		for n in 0..1024 {
			assert!(gate(v4_client(n), &Method::GET, "/filler", None, &HeaderMap::new()).is_some());
			itemised += logged().len();
		}
		assert_eq!(itemised, 1024);

		// Now a fresh client probes. It cannot get a line of its own, but the
		// denials must not vanish: a summary line has to say they happened.
		for n in 0..50 {
			assert!(gate(v4_client(5000 + n), &Method::GET, "/secret-probe", None, &HeaderMap::new()).is_some());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "one summary line per interval, got {lines:?}");
		assert!(lines[0].contains("not itemised"), "{lines:?}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_AUTH_BYPASS_CIDRS", "100.64.0.0/10"),
	])]
	fn a_full_pass_table_still_leaves_a_trace_for_new_clients() {
		capture_info_logs();

		let mut itemised = 0;
		for n in 0..1024 {
			assert!(gate(v4_client(n), &Method::GET, "/", None, &HeaderMap::new()).is_none());
			itemised += logged().len();
		}
		assert_eq!(itemised, 1024);

		for n in 0..50 {
			assert!(gate(v4_client(5000 + n), &Method::GET, "/", None, &HeaderMap::new()).is_none());
		}
		let lines = logged();
		assert_eq!(lines.len(), 1, "{lines:?}");
		assert!(lines[0].contains("not itemised"), "{lines:?}");
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hyper::header::HeaderValue;
	use sealed_test::prelude::*;

	fn net(s: &str) -> IpNet {
		s.parse().unwrap()
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
		let mut map = HeaderMap::new();
		for (name, value) in pairs {
			map.append(*name, HeaderValue::from_str(value).unwrap());
		}
		map
	}

	fn xff(value: &str) -> HeaderMap {
		headers(&[("x-forwarded-for", value)])
	}

	fn location(res: &Response<Body>) -> String {
		res.headers().get("location").unwrap().to_str().unwrap().to_string()
	}

	fn body_text(res: Response<Body>) -> String {
		let bytes = futures_lite::future::block_on(res.into_body().collect_bytes()).unwrap();
		String::from_utf8(bytes.to_vec()).unwrap()
	}

	const BROWSER: (&str, &str) = ("accept", "text/html,application/xhtml+xml,*/*;q=0.8");
	const OUTSIDE: &str = "203.0.113.9";

	// --- Ported from the original module ------------------------------------

	#[test]
	fn parses_cidrs_and_bare_addresses() {
		let parsed = parse_cidrs(Some("192.168.0.0/16, 10.42.0.0/16 ,203.0.113.5".to_string()), "test");
		assert_eq!(parsed, vec![net("192.168.0.0/16"), net("10.42.0.0/16"), net("203.0.113.5/32")]);
	}

	#[test]
	fn skips_unparseable_cidrs() {
		let parsed = parse_cidrs(Some("192.168.0.0/16,not-an-ip,10.0.0.0/8".to_string()), "test");
		assert_eq!(parsed, vec![net("192.168.0.0/16"), net("10.0.0.0/8")]);
	}

	#[test]
	fn canonicalises_ipv4_mapped_addresses() {
		// redlib listens on `[::]`, so this is how a real IPv4 client from the
		// pod network actually arrives. It must match an IPv4 CIDR.
		assert_eq!(canonical(ip("::ffff:10.42.0.5")), ip("10.42.0.5"));
		// Genuine IPv6 must be left alone.
		assert_eq!(canonical(ip("fd12::1")), ip("fd12::1"));

		let nets = [net("10.42.0.0/16")];
		let mapped = canonical(ip("::ffff:10.42.0.5"));
		assert!(nets.iter().any(|n| n.contains(&mapped)), "IPv4-mapped peer must match an IPv4 bypass CIDR");
	}

	// The original tests re-implemented the selection logic next to the
	// tests; these call the same function the gate uses, with an explicit
	// proxy list instead of the global config.

	#[test]
	fn mapped_peer_is_recognised_as_a_trusted_proxy() {
		// Same trap one layer up: the proxy check must see through the mapping,
		// or XFF would be ignored and every client would look like the proxy.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("::ffff:10.42.0.7"), &xff("203.0.113.9"));
		assert_eq!(got, Some(ip("203.0.113.9")));
	}

	#[test]
	fn ignores_forwarded_header_from_untrusted_peer() {
		// The spoofing case: a direct client claims to be on the LAN.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("203.0.113.9"), &xff("192.168.1.5"));
		assert_eq!(got, Some(ip("203.0.113.9")));
	}

	#[test]
	fn takes_rightmost_untrusted_hop_from_trusted_peer() {
		let trusted = [net("10.42.0.0/16")];
		// Client prepended a forged entry; the real address is on the right.
		let got = resolve_with(&trusted, ip("10.42.0.7"), &xff("192.168.1.5, 203.0.113.9"));
		assert_eq!(got, Some(ip("203.0.113.9")));
	}

	#[test]
	fn skips_trusted_hops_in_the_chain() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), &xff("203.0.113.9, 10.42.0.3"));
		assert_eq!(got, Some(ip("203.0.113.9")));
	}

	#[test]
	fn reads_every_forwarded_for_header_in_order() {
		// A second header line is how a proxy that appends rather than merges
		// adds its hop; reading only the first line takes the client's word.
		let trusted = [net("10.42.0.0/16")];
		let h = headers(&[("x-forwarded-for", "192.168.1.5"), ("x-forwarded-for", "203.0.113.9")]);
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &h), Some(ip("203.0.113.9")));
	}

	#[test]
	fn stops_at_the_first_entry_it_cannot_read() {
		// Skipping an unreadable hop would hand the decision to whatever the
		// client wrote further left.
		let trusted = [net("10.42.0.0/16")];
		for chain in [
			"192.168.1.5, garbage, 10.42.0.3",
			"192.168.1.5, 203.0.113.9:4711",
			"192.168.1.5, [2001:db8::1]:443",
			"192.168.1.5, , 10.42.0.3",
			"192.168.1.5, unknown",
			"192.168.1.5,",
		] {
			assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &xff(chain)), None, "{chain:?}");
		}

		let mut h = xff("192.168.1.5");
		h.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff").unwrap());
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &h), None, "non-UTF-8 value");
	}

	#[test]
	fn accepts_bare_and_bracketed_ipv6_hops() {
		let trusted = [net("10.42.0.0/16")];
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &xff("2001:db8::1")), Some(ip("2001:db8::1")));
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &xff("[2001:db8::1]")), Some(ip("2001:db8::1")));
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &xff("[::ffff:192.168.1.5]")), Some(ip("192.168.1.5")));
	}

	#[test]
	fn client_is_unknown_when_the_chain_is_all_trusted() {
		let trusted = [net("10.42.0.0/16")];
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &xff("10.42.0.3")), None);
	}

	#[test]
	fn client_is_unknown_without_forwarded_header_from_a_proxy() {
		let trusted = [net("10.42.0.0/16")];
		assert_eq!(resolve_with(&trusted, ip("10.42.0.7"), &HeaderMap::new()), None);
	}

	#[test]
	fn peer_that_is_not_a_proxy_is_the_client_without_forwarded_header() {
		let trusted = [net("10.42.0.0/16")];
		assert_eq!(resolve_with(&trusted, ip("192.168.1.5"), &HeaderMap::new()), Some(ip("192.168.1.5")));
		assert_eq!(resolve_with(&[], ip("10.42.0.7"), &HeaderMap::new()), Some(ip("10.42.0.7")));
	}

	#[test]
	fn bypass_matching_covers_v4_and_v6() {
		let nets = [net("192.168.0.0/16"), net("fd00::/8")];
		assert!(nets.iter().any(|n| n.contains(&ip("192.168.4.20"))));
		assert!(nets.iter().any(|n| n.contains(&ip("fd12::1"))));
		assert!(!nets.iter().any(|n| n.contains(&ip("203.0.113.1"))));
	}

	// --- Pure helpers -------------------------------------------------------

	#[test]
	fn login_redirect_only_accepts_local_paths() {
		assert_eq!(redirect_target(Some("redirect=%2Fr%2Frust")), "/r/rust");
		assert_eq!(redirect_target(Some("x=1&redirect=/u/spez")), "/u/spez");
		// Anything that could leave this instance is replaced by the front page.
		assert_eq!(redirect_target(Some("redirect=https%3A%2F%2Fevil.example")), "/");
		assert_eq!(redirect_target(Some("redirect=%2F%2Fevil.example")), "/");
		assert_eq!(redirect_target(Some("redirect=evil.example")), "/");
		assert_eq!(redirect_target(Some("")), "/");
		assert_eq!(redirect_target(None), "/");
	}

	#[test]
	fn login_redirect_rejects_paths_a_browser_would_read_as_another_host() {
		// Browsers treat `\` like `/` and strip tabs and newlines from URLs, so
		// each of these can turn into `//evil.example` by the time it is used.
		for (raw, decoded) in [
			("%2F%5Cevil.example", "/\\evil.example"),
			("%2F%09%2Fevil.example", "/\t/evil.example"),
			("%2F%2Fevil", "//evil"),
			("%2F%0D%0Ax", "/\r\nx"),
			("%2F%0B%2Fx", "/\x0b/x"),
			("%2Fr%2Frust%5C..%5Cevil", "/r/rust\\..\\evil"),
			("%2F%7F", "/\x7f"),
			// Dot segments collapse to `//evil.example` once normalised.
			("%2F.%2F%2Fevil.example", "/.//evil.example"),
			("%2Fr%2Frust%20x", "/r/rust x"),
			("https%3A%2F%2Fevil", "https://evil"),
			("", ""),
		] {
			assert_eq!(redirect_target(Some(&format!("redirect={raw}"))), "/", "{decoded:?}");
		}
	}

	#[test]
	fn login_redirect_keeps_a_local_path_and_query() {
		assert_eq!(redirect_target(Some("redirect=%2Fr%2Frust%3Fsort%3Dnew")), "/r/rust?sort=new");
		assert_eq!(redirect_target(Some("redirect=%2F")), "/");
	}

	#[test]
	fn login_path_is_percent_encoded() {
		assert_eq!(urlencoding_path("/r/rust/comments/abc"), "%2Fr%2Frust%2Fcomments%2Fabc");
	}

	#[test]
	fn browsers_are_told_apart_from_programmatic_clients() {
		assert!(wants_html(&headers(&[BROWSER])));
		assert!(!wants_html(&headers(&[("accept", "application/json")])));
		assert!(!wants_html(&headers(&[("accept", "*/*")])));
		assert!(!wants_html(&HeaderMap::new()));
	}

	#[test]
	fn cookies_are_host_only_and_always_secure() {
		// With the `__Host-` prefix a browser only accepts the cookie when it is
		// Secure, has Path=/ and no Domain, so a sibling subdomain can neither
		// set nor shadow it.
		for name in [SESSION_COOKIE, TX_COOKIE] {
			assert!(name.starts_with("__Host-"), "{name}");
		}
		let attrs = cookie_attrs(60);
		let attrs: Vec<&str> = attrs.split("; ").collect();
		for wanted in ["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=60", "Secure"] {
			assert!(attrs.contains(&wanted), "{wanted} missing from {attrs:?}");
		}
		assert!(!attrs.iter().any(|a| a.to_ascii_lowercase().starts_with("domain")), "{attrs:?}");
	}

	#[test]
	fn cookie_value_finds_the_named_cookie_only() {
		let h = headers(&[("cookie", "a=1; redlib_session=tok; b=2"), ("cookie", "redlib_oidc_tx=tx")]);
		assert_eq!(cookie_value(&h, "redlib_session").as_deref(), Some("tok"));
		assert_eq!(cookie_value(&h, "redlib_oidc_tx").as_deref(), Some("tx"));
		assert_eq!(cookie_value(&h, "redlib"), None);
	}

	#[test]
	fn provider_error_text_is_not_shown_to_the_user() {
		// Anyone can send a victim to the callback with an error of their
		// choosing, so its text must not appear on our page as if it were ours.
		let req = Request::builder()
			.uri("/oidc/callback?error=access_denied&error_description=Call+0800-SCAM+to+restore+access")
			.body(Body::empty())
			.unwrap();
		let res = futures_lite::future::block_on(callback(req)).unwrap();
		assert_eq!(res.status(), StatusCode::FORBIDDEN);
		let body = body_text(res);
		assert!(!body.contains("SCAM") && !body.contains("access_denied"), "{body}");
	}

	#[test]
	#[sealed_test]
	fn a_provider_that_never_answers_does_not_hang_the_request() {
		// Accepts connections and then says nothing, like a wedged provider.
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		std::thread::spawn(move || {
			let held: Vec<_> = listener.incoming().collect();
			drop(held);
		});
		// The config is read on first use, which is after this in a fresh process.
		std::env::set_var("REDLIB_OIDC_ISSUER", format!("http://{addr}"));

		let runtime = tokio::runtime::Runtime::new().unwrap();
		let outcome = runtime.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(30), discovery()).await });
		let result = outcome.expect("discovery must give up on its own instead of waiting forever");
		assert!(result.is_err());
	}

	// --- ID token validation ------------------------------------------------

	/// A throwaway RSA key generated for these tests only. It signs nothing
	/// outside them.
	const TEST_RSA_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCj078mBSOUBQdc
YItNTy0SlvLN+eFKHxLJsLBLPI8K87Dzoe/iFI+BxJwizHVXzC2nCa1ugdGCh+DD
F8xjYvaUWB1HWj+oKpCP38Gwsw1ra0M1igEw6YXVcqJWnkY4/f+9zMU322UI7oSE
ZldjUHf2iuew52XPB+CKNF7rW0MI03WEraRvSZRCI25j0hM6rwVJ/8KuTN0yn2ap
8uvubu1clPdpKj+o0vXMIt9fpzIy0159IhfhOAbAIG3EotBmgyrO+toVF8+ceYW7
/9lK0L6dOnB1BRR8cf3NfTKQV83RMLAfkQobDDznRb8Tl+YE+BrOdqxaC9lhOY+J
qL1k2/m3AgMBAAECggEASMaSnlggEuwc9ftpRmGKuzxVBg0f+GZPWUtlNTbksE/K
5p+kSYEqstHdLlQ3OFZaXV6eLX37zQmBXgkfYXMf6IwwDXdY2eJ2r4MNruoLZxGS
HKF+n/TM4CH5XZMXzM+AoRbq8UJD4rDaK1qvLU4czGeuPta8UjjElYBoPhMfdzaK
ZVbBlf/7+2KjFOwg5jKvd5mWdz0CLKjopTgP6N1Lf1BUWB5UEyJ7madtqv1l/ieI
MsnxXZ2ReFnF82BilVJj5KGhnDTCr239IGRgsvYWBVsUf/7/s8gZHv79678+JvoS
9oAdzbBV544Yipxt8c6AMpcuOWW6L/+xtR5vfVuxIQKBgQDUmnwHhXGimBHKA9or
KB5ydXLqqlTzOD9hGrdWJtzRhNiqnQwUobrsJe5Lb/Ix8npvsrlhSLzyBmcjiNrP
VdWHsqGkc8pSDbMrpOqZ85Z/SbdSHFVQI9JtuBP78khYUL+/L0iBbHE4pgYYLj6e
0ciFVyXZZmRUHKl/zYD48R285wKBgQDFRHk3tpdN8C5x5XL8/Sya72nNRYb6SuUS
H8DqxscM2EGBFlhcT2oAqUhlK3dDYi3yqmrthclpP2OR7JXtMd+QUbgmHH5vX1Zz
tedPcDYUWXAgUMJpVlR6PX1uD8YxpEfgezMVloT3b2egIut61Q7oZ2V/rsbWVfu9
ABCeNjbysQKBgFzvSthe1NWmc+BC3tOOrgCKprk9y/Sl2c6wxwO56T0NPUkXbXh3
WiZwTkJbpRuAS1UYY0DLcwy5D8zQvhV0B+tRgqdIlmBX7MJfTM4PVPI/Xwtdp01o
20tq9BFmT4mLgsYn/SHWLYf9yxw22tjCC01+UuU9hQ3fmZhsVLx9aepxAoGBALWu
fdHhGfMPHUeK4l+8sQM1MwV6XnlQ1y7dDeltD9B1r8a7FMBX57IaNvHumVX3K4hO
ilKeIEUNu5+e/OpLP7MEgIyhO5VJgi7pvtL77uLJCKrKlnM7rmwzC719S7VWr1hB
P2hHi8jz0sW6w5QKfENxTxrMlpa69DI6yBNerTbRAoGARVkLBM8CGUZjCgliH5Pj
WyPWnm8ZfUBbac30QyGiUL24qebj7he+dZF4ypIUiFtDYf6Yjf6uf0S3GJn+77T6
dJGqFkpWGrtruNnGsiU+N3pTukrhvuUdiFXAIQ931FTNPdiKwUI5wgqbJmlR2IGm
J6LdBPXCFDZfsB7AdnW3CIo=
-----END PRIVATE KEY-----";
	/// The modulus of [`TEST_RSA_KEY`], base64url-encoded as in a JWK.
	const TEST_RSA_N: &str = "o9O_JgUjlAUHXGCLTU8tEpbyzfnhSh8SybCwSzyPCvOw86Hv4hSPgcScIsx1V8wtpwmtboHRgofgwxfMY2L2lFgdR1o_qCqQj9_BsLMNa2tDNYoBMOmF1XKiVp5GOP3_vczFN9tlCO6EhGZXY1B39ornsOdlzwfgijRe61tDCNN1hK2kb0mUQiNuY9ITOq8FSf_CrkzdMp9mqfLr7m7tXJT3aSo_qNL1zCLfX6cyMtNefSIX4TgGwCBtxKLQZoMqzvraFRfPnHmFu__ZStC-nTpwdQUUfHH9zX0ykFfN0TCwH5EKGww850W_E5fmBPgaznasWgvZYTmPiai9ZNv5tw";
	const TEST_ISSUER: &str = "https://idp.example/application/o/redlib/";

	fn test_jwk(alg: Option<&str>) -> Jwk {
		let mut jwk = serde_json::json!({"kty": "RSA", "kid": "k1", "use": "sig", "n": TEST_RSA_N, "e": "AQAB"});
		if let Some(alg) = alg {
			jwk["alg"] = alg.into();
		}
		serde_json::from_value(jwk).unwrap()
	}

	fn id_claims() -> serde_json::Value {
		serde_json::json!({"iss": TEST_ISSUER, "aud": "id", "sub": "u1", "nonce": "n1", "iat": now(), "exp": now() + 300})
	}

	fn id_token(alg: Algorithm, claims: &serde_json::Value) -> String {
		let mut header = Header::new(alg);
		header.kid = Some("k1".into());
		encode(&header, claims, &EncodingKey::from_rsa_pem(TEST_RSA_KEY.as_bytes()).unwrap()).unwrap()
	}

	fn check_id_token(token: &str, jwk: &Jwk) -> Result<IdClaims, String> {
		validate_id_token(token, jwk, TEST_ISSUER, "id", "n1")
	}

	#[test]
	fn accepts_a_well_formed_id_token() {
		let claims = check_id_token(&id_token(Algorithm::RS256, &id_claims()), &test_jwk(None)).unwrap();
		assert_eq!(claims.sub, "u1");
		check_id_token(&id_token(Algorithm::RS256, &id_claims()), &test_jwk(Some("RS256"))).unwrap();
	}

	#[test]
	fn id_token_algorithm_is_pinned_not_taken_from_the_token() {
		// The token's own header must not choose how it is checked.
		for alg in [Algorithm::RS384, Algorithm::RS512, Algorithm::PS256] {
			assert!(check_id_token(&id_token(alg, &id_claims()), &test_jwk(None)).is_err(), "{alg:?} against an RS256 key");
		}
		let hs = encode(&Header::new(Algorithm::HS256), &id_claims(), &EncodingKey::from_secret(TEST_RSA_N.as_bytes())).unwrap();
		assert!(check_id_token(&hs, &test_jwk(None)).is_err(), "HS256");

		// A key that declares its algorithm gets exactly that one.
		check_id_token(&id_token(Algorithm::RS384, &id_claims()), &test_jwk(Some("RS384"))).unwrap();
		assert!(check_id_token(&id_token(Algorithm::RS256, &id_claims()), &test_jwk(Some("RS384"))).is_err());
	}

	#[test]
	fn id_token_must_carry_iss_aud_exp_and_iat() {
		for claim in ["iss", "aud", "exp", "iat"] {
			let mut claims = id_claims();
			claims.as_object_mut().unwrap().remove(claim);
			assert!(check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).is_err(), "without {claim}");
		}
	}

	#[test]
	fn id_token_with_several_audiences_must_name_us_as_azp() {
		let mut claims = id_claims();
		claims["aud"] = serde_json::json!(["id", "other"]);
		assert!(check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).is_err(), "no azp");

		claims["azp"] = "other".into();
		assert!(check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).is_err(), "someone else's azp");

		claims["azp"] = "id".into();
		check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).unwrap();
	}

	#[test]
	fn id_token_must_not_be_issued_in_the_future() {
		let mut claims = id_claims();
		claims["iat"] = (now() + 600).into();
		assert!(check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).is_err(), "10 minutes ahead");

		// Small clock skew is fine.
		claims["iat"] = (now() + 120).into();
		check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).unwrap();
	}

	#[test]
	fn id_token_must_match_issuer_audience_and_nonce() {
		for (claim, value) in [("iss", "https://evil.example/"), ("aud", "other"), ("nonce", "n2")] {
			let mut claims = id_claims();
			claims[claim] = value.into();
			assert!(check_id_token(&id_token(Algorithm::RS256, &claims), &test_jwk(None)).is_err(), "wrong {claim}");
		}
	}

	// --- Configuration ------------------------------------------------------

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "on")])]
	fn enabled_without_required_settings_names_what_is_missing() {
		let cfg = AuthConfig::load_unchecked();
		assert!(cfg.enabled);
		assert_eq!(
			cfg.missing_required(),
			vec!["REDLIB_OIDC_ISSUER", "REDLIB_OIDC_CLIENT_ID", "REDLIB_OIDC_CLIENT_SECRET", "REDLIB_OIDC_REDIRECT_URI"]
		);
	}

	#[test]
	#[sealed_test]
	fn settings_are_read_from_redlib_toml() {
		std::fs::write(
			"redlib.toml",
			"REDLIB_OIDC_ENABLED = true\n\
			REDLIB_OIDC_ISSUER = \"https://idp.example/application/o/redlib/\"\n\
			REDLIB_OIDC_CLIENT_ID = \"id\"\n\
			REDLIB_OIDC_CLIENT_SECRET = \"secret\"\n\
			REDLIB_OIDC_REDIRECT_URI = \"https://redlib.example/oidc/callback\"\n\
			REDLIB_OIDC_SESSION_TTL = 3600\n\
			REDLIB_OIDC_ALLOWED_GROUPS = \"admins, readers\"\n\
			REDLIB_AUTH_BYPASS_CIDRS = \"192.168.0.0/16,100.64.0.0/10\"\n\
			REDLIB_TRUSTED_PROXIES = \"10.42.0.0/16\"\n",
		)
		.unwrap();
		let cfg = AuthConfig::load_unchecked();
		// A TOML boolean arrives as "on", which must count as enabled.
		assert!(cfg.enabled);
		assert!(cfg.missing_required().is_empty());
		// The trailing slash is dropped so discovery URLs don't get `//`.
		assert_eq!(cfg.issuer, "https://idp.example/application/o/redlib");
		assert_eq!(cfg.scopes, DEFAULT_SCOPES);
		assert_eq!(cfg.session_ttl, 3600);
		assert_eq!(cfg.allowed_groups, vec!["admins", "readers"]);
		assert_eq!(cfg.bypass_cidrs, vec![net("192.168.0.0/16"), net("100.64.0.0/10")]);
		assert_eq!(cfg.trusted_proxies, vec![net("10.42.0.0/16")]);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "off"), ("REDLIB_OIDC_ISSUER", "https://idp.example")])]
	fn only_on_true_or_1_enable_auth() {
		assert!(!AuthConfig::load_unchecked().enabled);
	}

	/// The message `AuthConfig::load` refuses to start with, if it refuses.
	fn startup_refusal() -> Option<String> {
		let err = std::panic::catch_unwind(AuthConfig::load).err()?;
		Some(
			err
				.downcast_ref::<String>()
				.cloned()
				.or_else(|| err.downcast_ref::<&str>().map(ToString::to_string))
				.unwrap_or_default(),
		)
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "off"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
	])]
	fn settings_left_behind_while_disabled_are_reported() {
		let cfg = AuthConfig::load_unchecked();
		assert_eq!(cfg.ignored_settings(), vec!["REDLIB_OIDC_ISSUER", "REDLIB_OIDC_SESSION_SECRET"]);
		// A warning, not a refusal: turning auth off on purpose must still work.
		assert_eq!(startup_refusal(), None);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", " TRUE ")])]
	fn enabled_ignores_case_and_surrounding_space() {
		assert!(AuthConfig::load_unchecked().enabled);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "Yes")])]
	fn yes_enables_auth() {
		assert!(AuthConfig::load_unchecked().enabled);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "NO")])]
	fn no_disables_auth() {
		assert!(!AuthConfig::load_unchecked().enabled);
		assert_eq!(startup_refusal(), None);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "ture"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
	])]
	fn a_misspelt_enabled_value_refuses_to_start() {
		// Reading a typo as "off" would silently publish the instance.
		let refusal = startup_refusal().expect("must refuse to start");
		assert!(refusal.contains("REDLIB_OIDC_ENABLED") && refusal.contains("ture"), "{refusal}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		// 31 bytes: one short.
		("REDLIB_OIDC_SESSION_SECRET", "0123456789abcdef0123456789abcde"),
	])]
	fn a_short_session_secret_refuses_to_start() {
		// Hashing a short secret does not make it any harder to guess, and
		// whoever guesses it can mint sessions.
		let refusal = startup_refusal().expect("must refuse to start");
		assert!(refusal.contains("REDLIB_OIDC_SESSION_SECRET") && refusal.contains("32"), "{refusal}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
	])]
	fn a_32_byte_session_secret_is_enough() {
		assert_eq!(startup_refusal(), None);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "")])]
	fn an_empty_enabled_value_refuses_to_start() {
		let refusal = startup_refusal().expect("must refuse to start");
		assert!(refusal.contains("REDLIB_OIDC_ENABLED"), "{refusal}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_CLIENT_SECRET", "client-secret-value"),
		("REDLIB_OIDC_SESSION_SECRET", "session-secret-value"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.77.0/24"),
		("REDLIB_TRUSTED_PROXIES", "10.99.0.0/16"),
		("REDLIB_MCP_TOKEN", "mcp-token-value"),
	])]
	fn secrets_and_network_layout_never_reach_info_json() {
		// `/info.json` serializes the whole config.
		let json = serde_json::to_string(&crate::config::Config::load()).unwrap();
		for leaked in ["client-secret-value", "session-secret-value", "192.168.77.0", "10.99.0.0", "mcp-token-value"] {
			assert!(!json.contains(leaked), "{leaked} is in /info.json");
		}
	}

	// --- The gate, against the real global config ---------------------------

	#[test]
	#[sealed_test]
	fn gate_is_open_when_disabled() {
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &headers(&[BROWSER])).is_none());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_redirects_browsers_to_login() {
		let res = gate(ip(OUTSIDE), &Method::GET, "/r/rust/comments/abc", None, &headers(&[BROWSER])).expect("must be gated");
		assert_eq!(res.status(), StatusCode::FOUND);
		assert_eq!(location(&res), "/oidc/login?redirect=%2Fr%2Frust%2Fcomments%2Fabc");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_answers_programmatic_clients_with_401_json() {
		let res = gate(ip(OUTSIDE), &Method::GET, "/r/rust", None, &headers(&[("accept", "application/json")])).expect("must be gated");
		assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
		assert_eq!(res.headers()["www-authenticate"], "Bearer realm=\"https://idp.example/application/o/redlib\"");
		assert_eq!(res.headers()["content-type"], "application/json");
		assert_eq!(body_text(res), r#"{"error":"unauthorized","error_description":"Authentication required."}"#);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_never_blocks_its_own_endpoints() {
		// The login endpoints, or login could never complete, and the bare
		// liveness check, which kubelet probes from the node's pod-network
		// bridge address: a trusted-proxy address that sends no
		// X-Forwarded-For, so it gets no bypass.
		for path in ["/oidc/login", "/oidc/callback", "/oidc/logout", "/healthz"] {
			assert!(gate(ip(OUTSIDE), &Method::GET, path, None, &headers(&[BROWSER])).is_none(), "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_covers_every_other_path() {
		// Only the three login endpoints and the bare liveness check are
		// exempt. Everything else, including anything else under /oidc/ and
		// the Reddit health report, needs a session, a bypass address or the
		// bearer token.
		for path in [
			"/",
			"/healthz/reddit",
			"/healthz/reddit.json",
			"/style.css",
			"/info.json",
			"/mcp",
			"/oidc",
			"/oidc/",
			"/oidc/x",
			"/oidc/login/x",
			"/oidc/loginx",
			"/healthzx",
		] {
			let res = gate(ip(OUTSIDE), &Method::GET, path, None, &HeaderMap::new()).unwrap_or_else(|| panic!("{path} must be gated"));
			assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.0.0/16,127.0.0.0/8"),
		("REDLIB_TRUSTED_PROXIES", "10.42.0.0/16"),
	])]
	fn gate_lets_bypass_addresses_through() {
		assert!(gate(ip("192.168.1.20"), &Method::GET, "/", None, &headers(&[BROWSER])).is_none());
		// Dual-stack sockets report IPv4 clients as mapped IPv6.
		assert!(gate(ip("::ffff:127.0.0.1"), &Method::GET, "/", None, &headers(&[BROWSER])).is_none());
		// Through the trusted proxy, the forwarded address decides.
		assert!(gate(ip("10.42.0.7"), &Method::GET, "/", None, &xff("192.168.1.20")).is_none());
		assert!(gate(ip("10.42.0.7"), &Method::GET, "/", None, &xff(OUTSIDE)).is_some());
		// The proxy itself is not a bypass address.
		assert!(gate(ip("10.42.0.7"), &Method::GET, "/", None, &HeaderMap::new()).is_some());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.0.0/16"),
	])]
	fn gate_ignores_forged_forwarded_for_without_trusted_proxies() {
		let res = gate(ip(OUTSIDE), &Method::GET, "/", None, &xff("192.168.1.20"));
		assert_eq!(res.expect("forged XFF must not bypass").status(), StatusCode::UNAUTHORIZED);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
		// The proxy's range is also a bypass range, as in the deployment.
		("REDLIB_AUTH_BYPASS_CIDRS", "10.42.0.0/16,192.168.0.0/16"),
		("REDLIB_TRUSTED_PROXIES", "10.42.0.0/16"),
	])]
	fn a_proxy_that_names_no_client_is_not_a_bypass() {
		// Without a usable client address the proxy's own address must not
		// stand in for it, or every request it forwards would skip the login.
		let proxy = ip("10.42.0.7");
		for (label, h) in [
			("no X-Forwarded-For", HeaderMap::new()),
			("only trusted hops", xff("10.42.0.3")),
			("only trusted hops, several", xff("10.42.0.3, 10.42.0.4")),
			("nothing parseable", xff("unknown")),
		] {
			let res = gate(proxy, &Method::GET, "/", None, &h).unwrap_or_else(|| panic!("{label}: must not bypass"));
			assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{label}");
		}

		// A forwarded bypass address still gets through the proxy.
		assert!(gate(proxy, &Method::GET, "/", None, &xff("192.168.1.20")).is_none());
		// A peer that is not a proxy is the client, e.g. a kubelet probe from a node.
		assert!(gate(ip("192.168.1.20"), &Method::GET, "/", None, &HeaderMap::new()).is_none());
		// An unknown client can still log in.
		let token = sign(&session(now() + 3600)).unwrap();
		assert!(gate(proxy, &Method::GET, "/", None, &session_cookie(&token)).is_none());
	}

	fn session(exp: u64) -> Session {
		Session {
			sub: "user-1".into(),
			username: "user".into(),
			email: String::new(),
			groups: vec![],
			exp,
			iat: now(),
		}
	}

	fn session_cookie(token: &str) -> HeaderMap {
		headers(&[("cookie", &format!("theme=dark; {SESSION_COOKIE}={token}")), BROWSER])
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_accepts_a_valid_session_cookie() {
		let token = sign(&session(now() + 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&token)).is_none());
		assert_eq!(session_from(&session_cookie(&token)).unwrap().sub, "user-1");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn gate_rejects_expired_tampered_and_foreign_sessions() {
		// Expired beyond jsonwebtoken's default 60 s leeway.
		let expired = sign(&session(now() - 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&expired)).is_some(), "expired");

		// Payload swapped under an existing signature.
		let valid = sign(&session(now() + 3600)).unwrap();
		let mut parts: Vec<&str> = valid.split('.').collect();
		let forged_claims = URL_SAFE_NO_PAD.encode(
			serde_json::to_vec(&Session {
				sub: "admin".into(),
				..session(now() + 3600)
			})
			.unwrap(),
		);
		parts[1] = &forged_claims;
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&parts.join("."))).is_some(), "tampered");

		// Signed with a different key.
		let foreign = encode(&Header::new(Algorithm::HS256), &session(now() + 3600), &EncodingKey::from_secret(b"other")).unwrap();
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&foreign)).is_some(), "foreign key");

		// `alg: none` must never be accepted.
		let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
		let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&session(now() + 3600)).unwrap());
		assert!(
			gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&format!("{header}.{claims}."))).is_some(),
			"alg none"
		);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn login_transaction_cookie_is_not_a_session() {
		// Both are signed with the same key; the claim shapes must keep them apart.
		let tx = sign(&LoginTx {
			state: "s".into(),
			nonce: "n".into(),
			verifier: "v".into(),
			redirect_to: "/".into(),
			exp: now() + TX_TTL,
		})
		.unwrap();
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&tx)).is_some());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
	])]
	fn sessions_still_work_with_an_ephemeral_key() {
		let token = sign(&session(now() + 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), &Method::GET, "/", None, &session_cookie(&token)).is_none());
	}

	fn bearer(value: &str) -> HeaderMap {
		headers(&[("authorization", value), ("accept", "application/json")])
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_MCP_TOKEN", "correct-horse-battery-staple"),
	])]
	fn gate_accepts_the_bearer_token_only_on_mcp() {
		// The scheme is case-insensitive (RFC 9110 11.1).
		for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
			let value = format!("{scheme} correct-horse-battery-staple");
			assert!(gate(ip(OUTSIDE), &Method::GET, "/mcp", None, &bearer(&value)).is_none(), "{scheme}");
		}

		// The token is for the MCP endpoint. A leaked one must not open the
		// rest of the instance.
		for path in ["/", "/r/rust", "/info.json", "/mcp/other", "/mcpx"] {
			let res = gate(ip(OUTSIDE), &Method::GET, path, None, &bearer("Bearer correct-horse-battery-staple")).unwrap_or_else(|| panic!("{path} must be gated"));
			assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_MCP_TOKEN", "correct-horse-battery-staple"),
	])]
	fn gate_rejects_wrong_or_malformed_bearer_tokens() {
		for value in [
			"Bearer correct-horse-battery",
			"Bearer correct-horse-battery-staplex",
			"Bearer ",
			"Basic correct-horse-battery-staple",
			"correct-horse-battery-staple",
		] {
			let res = gate(ip(OUTSIDE), &Method::GET, "/mcp", None, &bearer(value)).unwrap_or_else(|| panic!("{value:?} must not pass"));
			assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{value:?}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_MCP_TOKEN", "   "),
	])]
	fn an_unset_or_blank_token_authorises_nothing() {
		for value in ["Bearer ", "Bearer    ", "Bearer x"] {
			assert!(gate(ip(OUTSIDE), &Method::GET, "/mcp", None, &bearer(value)).is_some(), "{value:?}");
		}
	}
}

/// `REDLIB_READ_TOKEN`: a bearer token for in-cluster services that only
/// read pages. Kept apart from the main test module, which covers sessions,
/// bypasses and the MCP token.
#[cfg(test)]
mod read_token_tests {
	use super::*;
	use hyper::header::HeaderValue;
	use sealed_test::prelude::*;

	const OUTSIDE: &str = "203.0.113.9";
	const TOKEN: &str = "read-only-token-0123456789abcdef";

	fn outside() -> IpAddr {
		OUTSIDE.parse().unwrap()
	}

	fn bearer(value: &str) -> HeaderMap {
		let mut map = HeaderMap::new();
		map.append("authorization", HeaderValue::from_str(value).unwrap());
		map.append("accept", HeaderValue::from_static("application/json"));
		map
	}

	fn with_token() -> HeaderMap {
		bearer(&format!("Bearer {TOKEN}"))
	}

	fn assert_rejected(method: &Method, path: &str, headers: &HeaderMap) {
		let res = gate(outside(), method, path, None, headers).unwrap_or_else(|| panic!("{method} {path} must be gated"));
		assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_READ_TOKEN", "read-only-token-0123456789abcdef"),
	])]
	fn opens_pages_for_get_and_head() {
		for path in ["/r/rust", "/r/rust/comments/1abcdef/some_title", "/", "/user/someone", "/info.json"] {
			for method in [Method::GET, Method::HEAD] {
				assert!(gate(outside(), &method, path, None, &with_token()).is_none(), "{method} {path}");
			}
		}

		// The scheme is case-insensitive (RFC 9110 11.1).
		for scheme in ["bearer", "BEARER", "BeArEr"] {
			let headers = bearer(&format!("{scheme} {TOKEN}"));
			assert!(gate(outside(), &Method::GET, "/r/rust", None, &headers).is_none(), "{scheme}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_READ_TOKEN", "read-only-token-0123456789abcdef"),
	])]
	fn never_allows_a_method_that_can_change_state() {
		for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS] {
			for path in ["/r/rust", "/r/rust/subscribe", "/settings", "/settings/encoded-restore"] {
				assert_rejected(&method, path, &with_token());
			}
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_READ_TOKEN", "read-only-token-0123456789abcdef"),
	])]
	fn never_opens_settings_mcp_or_oidc() {
		// /settings/restore and /settings/update change preferences on GET,
		// /mcp has its own token, and /oidc/ belongs to the login flow.
		for path in [
			"/settings",
			"/settings/update",
			"/settings/restore",
			"/Settings",
			"/SETTINGS/update",
			"/mcp",
			"/mcp/other",
			"/oidc",
			"/oidc/other",
		] {
			for method in [Method::GET, Method::HEAD] {
				assert_rejected(&method, path, &with_token());
			}
		}

		// Paths that merely start with the same letters are ordinary pages.
		for path in ["/settingsx", "/mcpx", "/oidcx"] {
			assert!(gate(outside(), &Method::GET, path, None, &with_token()).is_none(), "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_READ_TOKEN", "read-only-token-0123456789abcdef"),
		("REDLIB_MCP_TOKEN", "mcp-token-0123456789abcdef"),
	])]
	fn rejects_wrong_or_malformed_tokens() {
		for value in [
			"Bearer read-only-token-0123456789abcde",
			"Bearer read-only-token-0123456789abcdefx",
			"Bearer ",
			"Basic read-only-token-0123456789abcdef",
			"read-only-token-0123456789abcdef",
			// The MCP token is not a read token.
			"Bearer mcp-token-0123456789abcdef",
		] {
			assert_rejected(&Method::GET, "/r/rust", &bearer(value));
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
		("REDLIB_READ_TOKEN", "   "),
	])]
	fn a_blank_token_authorises_nothing() {
		for value in ["Bearer ", "Bearer    ", "Bearer x"] {
			assert_rejected(&Method::GET, "/r/rust", &bearer(value));
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret-0123456789abcdef"),
	])]
	fn an_unset_token_authorises_nothing() {
		for value in ["Bearer ", "Bearer x", "Bearer read-only-token-0123456789abcdef"] {
			assert_rejected(&Method::GET, "/r/rust", &bearer(value));
		}
	}

	#[test]
	#[sealed_test(env = [("REDLIB_READ_TOKEN", "read-only-token-0123456789abcdef")])]
	fn is_loaded_but_never_reaches_info_json() {
		assert_eq!(crate::config::get_setting("REDLIB_READ_TOKEN").as_deref(), Some(TOKEN));
		let json = serde_json::to_string(&crate::config::Config::load()).unwrap();
		assert!(!json.contains(TOKEN), "the read token is in /info.json");
	}
}
