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

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::{Body, HeaderMap, Request, Response, StatusCode};
use ipnet::IpNet;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config;

/// Everything under this prefix is served by us and must never be gated,
/// otherwise the login redirect would loop forever.
pub const OIDC_PREFIX: &str = "/oidc/";

const SESSION_COOKIE: &str = "redlib_session";
const TX_COOKIE: &str = "redlib_oidc_tx";
const DEFAULT_SCOPES: &str = "openid profile email";
const DEFAULT_SESSION_TTL: u64 = 86_400;
/// How long a user has to complete the login round-trip.
const TX_TTL: u64 = 600;

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
	fn load() -> Self {
		let enabled = setting("REDLIB_OIDC_ENABLED").map(|v| v == "on" || v == "true" || v == "1").unwrap_or(false);

		let bypass_cidrs = parse_cidrs(setting("REDLIB_AUTH_BYPASS_CIDRS"), "REDLIB_AUTH_BYPASS_CIDRS");
		let trusted_proxies = parse_cidrs(setting("REDLIB_TRUSTED_PROXIES"), "REDLIB_TRUSTED_PROXIES");

		let issuer = setting("REDLIB_OIDC_ISSUER").unwrap_or_default();
		let client_id = setting("REDLIB_OIDC_CLIENT_ID").unwrap_or_default();
		let client_secret = setting("REDLIB_OIDC_CLIENT_SECRET").unwrap_or_default();
		let redirect_uri = setting("REDLIB_OIDC_REDIRECT_URI").unwrap_or_default();

		// Derive a fixed-length key from the configured secret so that
		// operators are not forced to supply exactly N bytes.
		let session_key = match setting("REDLIB_OIDC_SESSION_SECRET") {
			Some(secret) => Sha256::digest(secret.as_bytes()).to_vec(),
			None if enabled => {
				// A random per-process key still works, but every restart (and
				// every replica) invalidates sessions, so say so loudly.
				warn!("REDLIB_OIDC_SESSION_SECRET is unset; generating an ephemeral key. Sessions will not survive a restart and will not work across replicas.");
				Sha256::digest(random_token(32).as_bytes()).to_vec()
			}
			None => Vec::new(),
		};

		let cfg = Self {
			enabled,
			issuer: issuer.trim_end_matches('/').to_string(),
			client_id,
			client_secret,
			redirect_uri,
			scopes: setting("REDLIB_OIDC_SCOPES").unwrap_or_else(|| DEFAULT_SCOPES.to_string()),
			session_ttl: setting("REDLIB_OIDC_SESSION_TTL").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_SESSION_TTL),
			allowed_groups: setting("REDLIB_OIDC_ALLOWED_GROUPS")
				.map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
				.unwrap_or_default(),
			bypass_cidrs,
			trusted_proxies,
			session_key,
		};

		if cfg.enabled {
			// Fail fast and loudly: a half-configured RP that silently lets
			// everyone through is the worst possible outcome here.
			let missing: Vec<&str> = [
				("REDLIB_OIDC_ISSUER", &cfg.issuer),
				("REDLIB_OIDC_CLIENT_ID", &cfg.client_id),
				("REDLIB_OIDC_CLIENT_SECRET", &cfg.client_secret),
				("REDLIB_OIDC_REDIRECT_URI", &cfg.redirect_uri),
			]
			.iter()
			.filter(|(_, v)| v.is_empty())
			.map(|(k, _)| *k)
			.collect();

			assert!(missing.is_empty(), "REDLIB_OIDC_ENABLED is on but these are unset: {}", missing.join(", "));

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

	fn encoding_key(&self) -> EncodingKey {
		EncodingKey::from_secret(&self.session_key)
	}

	fn decoding_key(&self) -> DecodingKey {
		DecodingKey::from_secret(&self.session_key)
	}
}

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
pub fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
	let trusted = &AUTH.trusted_proxies;
	let peer = canonical(peer);

	if !trusted.iter().any(|net| net.contains(&peer)) {
		return peer;
	}

	let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
		return peer;
	};

	xff
		.split(',')
		.map(str::trim)
		.filter_map(|s| s.parse::<IpAddr>().ok())
		.map(canonical)
		.rev()
		.find(|ip| !trusted.iter().any(|net| net.contains(ip)))
		.unwrap_or(peer)
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
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
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
		.filter_map(|pair| {
			let (k, v) = pair.split_once('=')?;
			(k.trim() == name).then(|| v.trim().to_string())
		})
		.next()
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

/// `Secure` is omitted for loopback so that a local `cargo run` over plain
/// HTTP still works; everything else is assumed to be behind TLS.
fn cookie_attrs(secure: bool, max_age: u64) -> String {
	let base = format!("Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
	if secure {
		format!("{base}; Secure")
	} else {
		base
	}
}

fn is_secure_context() -> bool {
	AUTH.redirect_uri.starts_with("https://")
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

static HTTP: LazyLock<wreq::Client> = LazyLock::new(|| wreq::Client::builder().build().expect("failed to build OIDC HTTP client"));

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

/// Starts the authorization-code flow.
pub async fn login(req: Request<Body>) -> Result<Response<Body>, String> {
	let disco = match discovery().await {
		Ok(d) => d,
		Err(e) => {
			error!("OIDC discovery failed: {e}");
			return Ok(error_page(StatusCode::BAD_GATEWAY, "Could not reach the identity provider."));
		}
	};

	// Only ever redirect back to a path on this instance. Accepting an
	// absolute URL here would make this an open redirector.
	let redirect_to_path = req
		.uri()
		.query()
		.and_then(|q| {
			serde_urlencoded::from_str::<Vec<(String, String)>>(q)
				.ok()?
				.into_iter()
				.find(|(k, _)| k == "redirect")
				.map(|(_, v)| v)
		})
		.filter(|p| p.starts_with('/') && !p.starts_with("//"))
		.unwrap_or_else(|| "/".to_string());

	let state = random_token(32);
	let nonce = random_token(32);
	let verifier = random_token(64);
	let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

	let tx = LoginTx {
		state: state.clone(),
		nonce: nonce.clone(),
		verifier,
		redirect_to: redirect_to_path,
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

	Ok(redirect_to(&location, &[format!("{TX_COOKIE}={tx_token}; {}", cookie_attrs(is_secure_context(), TX_TTL))]))
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
}

/// Handles the provider's redirect back to us.
pub async fn callback(req: Request<Body>) -> Result<Response<Body>, String> {
	let params: Vec<(String, String)> = req.uri().query().and_then(|q| serde_urlencoded::from_str(q).ok()).unwrap_or_default();
	let param = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());

	// The provider reports failures (e.g. the user hit "deny") in-band.
	if let Some(err) = param("error") {
		let description = param("error_description").unwrap_or_else(|| err.clone());
		warn!("identity provider returned error {err}: {description}");
		return Ok(error_page(StatusCode::FORBIDDEN, &description));
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
			format!("{SESSION_COOKIE}={token}; {}", cookie_attrs(is_secure_context(), AUTH.session_ttl)),
			// Retire the transaction cookie now that it has been consumed.
			format!("{TX_COOKIE}=; {}", cookie_attrs(is_secure_context(), 0)),
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
	let key = DecodingKey::from_jwk(jwk).map_err(|e| format!("unusable signing key: {e}"))?;

	let algorithm = header.alg;
	let mut validation = Validation::new(algorithm);
	validation.set_audience(&[&AUTH.client_id]);
	validation.set_issuer(&[&disco.issuer]);

	let data = decode::<IdClaims>(&tokens.id_token, &key, &validation).map_err(|e| format!("ID token validation failed: {e}"))?;

	// Binds this ID token to the login request that started the flow,
	// preventing token replay.
	if data.claims.nonce.as_deref() != Some(tx.nonce.as_str()) {
		return Err("ID token nonce does not match the login request".to_string());
	}

	Ok(data.claims)
}

/// Clears the local session, then hands off to the provider's end-session
/// endpoint when it advertises one.
pub async fn logout(_req: Request<Body>) -> Result<Response<Body>, String> {
	let clear = format!("{SESSION_COOKIE}=; {}", cookie_attrs(is_secure_context(), 0));

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
/// short-circuit it (a redirect to login, for browsers).
pub fn gate(peer: IpAddr, path: &str, headers: &HeaderMap) -> Option<Response<Body>> {
	if !AUTH.enabled {
		return None;
	}

	// Our own endpoints must stay reachable or login could never complete.
	if path.starts_with(OIDC_PREFIX) {
		return None;
	}

	let client = resolve_client_ip(peer, headers);
	if is_bypassed(client) {
		return None;
	}

	if session_from(headers).is_some() {
		return None;
	}

	debug!("unauthenticated request from {client} for {path}");

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

	let target = format!("/oidc/login?redirect={}", urlencoding_path(path));
	Some(redirect_to(&target, &[]))
}

/// Percent-encodes a path for use as a query-string value.
fn urlencoding_path(path: &str) -> String {
	serde_urlencoded::to_string([("r", path)])
		.map(|s| s.trim_start_matches("r=").to_string())
		.unwrap_or_else(|_| "/".to_string())
}

/// Distinguishes a browser from a programmatic client, so each gets an
/// appropriate rejection.
fn wants_html(headers: &HeaderMap) -> bool {
	headers.get("accept").and_then(|v| v.to_str().ok()).map(|a| a.contains("text/html")).unwrap_or(false)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn net(s: &str) -> IpNet {
		s.parse().unwrap()
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

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

	// `resolve_client_ip` reads the global config, so these exercise the same
	// selection logic against an explicit proxy list instead.
	fn resolve_with(trusted: &[IpNet], peer: IpAddr, xff: Option<&str>) -> IpAddr {
		let peer = canonical(peer);
		if !trusted.iter().any(|n| n.contains(&peer)) {
			return peer;
		}
		let Some(xff) = xff else { return peer };
		xff
			.split(',')
			.map(str::trim)
			.filter_map(|s| s.parse::<IpAddr>().ok())
			.map(canonical)
			.rev()
			.find(|i| !trusted.iter().any(|n| n.contains(i)))
			.unwrap_or(peer)
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

	#[test]
	fn mapped_peer_is_recognised_as_a_trusted_proxy() {
		// Same trap one layer up: the proxy check must see through the mapping,
		// or XFF would be ignored and every client would look like the proxy.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("::ffff:10.42.0.7"), Some("203.0.113.9"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn ignores_forwarded_header_from_untrusted_peer() {
		// The spoofing case: a direct client claims to be on the LAN.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("203.0.113.9"), Some("192.168.1.5"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn takes_rightmost_untrusted_hop_from_trusted_peer() {
		let trusted = [net("10.42.0.0/16")];
		// Client prepended a forged entry; the real address is on the right.
		let got = resolve_with(&trusted, ip("10.42.0.7"), Some("192.168.1.5, 203.0.113.9"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn skips_trusted_hops_in_the_chain() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), Some("203.0.113.9, 10.42.0.3"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn falls_back_to_peer_when_chain_is_all_trusted() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), Some("10.42.0.3"));
		assert_eq!(got, ip("10.42.0.7"));
	}

	#[test]
	fn bypass_matching_covers_v4_and_v6() {
		let nets = [net("192.168.0.0/16"), net("fd00::/8")];
		assert!(nets.iter().any(|n| n.contains(&ip("192.168.4.20"))));
		assert!(nets.iter().any(|n| n.contains(&ip("fd12::1"))));
		assert!(!nets.iter().any(|n| n.contains(&ip("203.0.113.1"))));
	}
}
