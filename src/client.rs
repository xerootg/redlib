use crate::body::Body;
use crate::config::get_setting;
use crate::dbg_msg;
use crate::oauth::{token_daemon, Oauth};
use crate::server::RequestExt;
use crate::utils::format_url;
use arc_swap::ArcSwap;
use cached::proc_macro::cached;
use futures_lite::future::block_on;
use futures_lite::{future::Boxed, FutureExt};
use hyper::{header, Request as HyperRequest, Response as HyperResponse};
use log::{info, warn};
use percent_encoding::{percent_encode, CONTROLS};
use std::net::SocketAddr;
use std::path::Path;
use std::result::Result;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use wreq::dns::{Addrs, GaiResolver, Name, Resolve, Resolving};
use wreq::redirect::Policy;
use wreq::{header as wreq_header, Client as WreqClient, Method, Response as WreqResponse};
use wreq_util::{Emulation, Platform, Profile};

const REDDIT_URL_BASE: &str = "https://oauth.reddit.com";
const REDDIT_URL_BASE_HOST: &str = "oauth.reddit.com";

const REDDIT_SHORT_URL_BASE: &str = "https://redd.it";
const REDDIT_SHORT_URL_BASE_HOST: &str = "redd.it";

pub(crate) const ALTERNATIVE_REDDIT_URL_BASE: &str = "https://www.reddit.com";
const ALTERNATIVE_REDDIT_URL_BASE_HOST: &str = "www.reddit.com";

/// Configuration variable holding the `Cookie` header of a logged-in
/// reddit.com session.
const REDDIT_COOKIE_SETTING: &str = "REDLIB_REDDIT_COOKIE";

/// File with more sessions, one per line, so they can change without a restart.
const REDDIT_COOKIE_FILE_SETTING: &str = "REDLIB_REDDIT_COOKIE_FILE";

/// How often the session file is checked for changes.
const REDDIT_COOKIE_FILE_RECHECK_SECS: u64 = 10;

/// Upper bound for the configured cookie. A browser sends a few kilobytes at
/// most; anything larger is a configuration mistake.
const REDDIT_COOKIE_MAX_LEN: usize = 8192;

pub static CLIENT: LazyLock<ArcSwap<WreqClient>> = LazyLock::new(|| ArcSwap::from_pointee(build_client()));

/// Runs `future` on one runtime shared by every test. `CLIENT` keeps its
/// connections in a pool, and each connection lives on the runtime that opened
/// it, so with a runtime per test, a test that finishes takes down
/// connections other tests are still using.
#[cfg(test)]
pub(crate) fn block_on_shared<F: std::future::Future>(future: F) -> F::Output {
	static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
	RUNTIME.block_on(future)
}

pub static OAUTH_CLIENT: LazyLock<ArcSwap<Oauth>> = LazyLock::new(|| {
	let client = block_on(Oauth::new());
	tokio::spawn(token_daemon());
	ArcSwap::new(client.into())
});

pub static OAUTH_RATELIMIT_REMAINING: AtomicU16 = AtomicU16::new(99);

/// Lower the local quota estimate by one, without ever wrapping below zero.
pub fn burn_rate_limit_unit() {
	OAUTH_RATELIMIT_REMAINING.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1))).ok();
}

pub static OAUTH_IS_ROLLING_OVER: AtomicBool = AtomicBool::new(false);

const URL_PAIRS: [(&str, &str); 2] = [
	(ALTERNATIVE_REDDIT_URL_BASE, ALTERNATIVE_REDDIT_URL_BASE_HOST),
	(REDDIT_SHORT_URL_BASE, REDDIT_SHORT_URL_BASE_HOST),
];

/// Draw weights. `REFUSED` is low but not 0, so a fingerprint Reddit
/// unblocks gets picked up again.
const SERVED: u32 = 20;
const REFUSED: u32 = 1;

/// How long a fingerprint Reddit blocked at runtime is left out of the draw.
const BLOCK_SECS: u64 = 6 * 60 * 60;

/// Reddit blocks anonymous JSON for Chrome 132+, Edge 135+ and Firefox 135+
/// (probe, October 2026). No OkHttp: Reddit blocks most of it outright.
const EMULATIONS: &[(Profile, &[Platform], u32)] = {
	use Platform::*;
	use Profile::*;
	&[
		(Chrome149, &[Windows, MacOS, Linux, Android], REFUSED),
		(Chrome148, &[Windows, MacOS, Linux, Android], REFUSED),
		(Chrome147, &[Windows, MacOS, Linux, Android], REFUSED),
		(Chrome146, &[Windows, MacOS, Linux, Android], REFUSED),
		(Chrome145, &[Windows, MacOS, Linux, Android], REFUSED),
		(Chrome131, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome130, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome129, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome128, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome127, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome126, &[Windows, MacOS, Linux, Android], SERVED),
		(Chrome124, &[Windows, MacOS, Linux, Android], SERVED),
		(Edge148, &[Windows, MacOS], REFUSED),
		(Edge147, &[Windows, MacOS], REFUSED),
		(Edge146, &[Windows, MacOS], REFUSED),
		(Edge145, &[Windows, MacOS], REFUSED),
		(Edge134, &[Windows, MacOS], SERVED),
		(Edge131, &[Windows, MacOS], SERVED),
		(Edge127, &[Windows, MacOS], SERVED),
		(Edge122, &[Windows, MacOS], SERVED),
		(Firefox151, &[Windows, MacOS, Linux, Android], REFUSED),
		(Firefox150, &[Windows, MacOS, Linux, Android], REFUSED),
		(Firefox149, &[Windows, MacOS, Linux, Android], REFUSED),
		(Firefox148, &[Windows, MacOS, Linux, Android], REFUSED),
		(Firefox147, &[Windows, MacOS, Linux, Android], REFUSED),
		// wreq-util has no macOS user agent for these two
		(Firefox133, &[Windows, Linux, Android], SERVED),
		(Firefox128, &[Windows, Linux], SERVED),
		(FirefoxAndroid135, &[Android], SERVED),
		(Safari26_4, &[MacOS], SERVED),
		(Safari26_3, &[MacOS], SERVED),
		(Safari26_2, &[MacOS], SERVED),
		(Safari26_1, &[MacOS], SERVED),
		(Safari26, &[MacOS], SERVED),
		(Safari18_5, &[MacOS], SERVED),
		(Safari18_3_1, &[MacOS], SERVED),
		(Safari18_3, &[MacOS], SERVED),
		(Safari18_2, &[MacOS], SERVED),
		(Safari18, &[MacOS], SERVED),
		(Safari17_6, &[MacOS], SERVED),
		(Safari17_5, &[MacOS], SERVED),
		(SafariIos26_2, &[IOS], SERVED),
		(SafariIos26, &[IOS], SERVED),
		(SafariIos18_1_1, &[IOS], SERVED),
		(SafariIos17_4_1, &[IOS], SERVED),
		(SafariIpad26_2, &[IOS], SERVED),
		(SafariIPad26, &[IOS], SERVED),
		(SafariIPad18, &[IOS], SERVED),
		(Opera131, &[Windows, MacOS], SERVED),
		(Opera130, &[Windows, MacOS], SERVED),
		(Opera129, &[Windows, MacOS], SERVED),
		(Opera128, &[Windows, MacOS], SERVED),
		(Opera127, &[Windows, MacOS], SERVED),
		(Opera126, &[Windows, MacOS], SERVED),
		(Opera125, &[Windows, MacOS], SERVED),
		(Opera124, &[Windows, MacOS], SERVED),
	]
};

/// Known-good fingerprints for the tests, checked by `test_probe_fingerprints`.
const TEST_EMULATIONS: &[(Profile, &[Platform], u32)] = {
	use Platform::*;
	use Profile::*;
	&[
		(Chrome131, &[Windows, Android], SERVED),
		(Edge134, &[Windows], SERVED),
		(Firefox133, &[Linux], SERVED),
		(Safari26_4, &[MacOS], SERVED),
		(Safari18_5, &[MacOS], SERVED),
		(SafariIos26_2, &[IOS], SERVED),
		(Opera131, &[Windows, MacOS], SERVED),
	]
};

/// One browser emulation the client can use.
struct Fingerprint {
	profile: Profile,
	platform: Platform,
	weight: u32,
	/// Unix time until which Reddit is taken to block it, 0 if it doesn't.
	blocked_until: AtomicU64,
}

impl Fingerprint {
	fn weight(&self, now: u64) -> u32 {
		if self.blocked_until.load(Ordering::Relaxed) > now {
			0
		} else {
			self.weight
		}
	}
}

fn flatten(table: &[(Profile, &[Platform], u32)]) -> Vec<Fingerprint> {
	table
		.iter()
		.flat_map(|&(profile, platforms, weight)| {
			platforms.iter().map(move |&platform| Fingerprint {
				profile,
				platform,
				weight,
				blocked_until: AtomicU64::new(0),
			})
		})
		.collect()
}

static FINGERPRINTS: LazyLock<Vec<Fingerprint>> = LazyLock::new(|| flatten(if cfg!(test) { TEST_EMULATIONS } else { EMULATIONS }));

/// Index into `FINGERPRINTS` of the emulation in use.
static EMULATION: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Unix time of the last emulation switch, so a burst of blocked requests
/// switches only once.
static LAST_REROLL: AtomicU64 = AtomicU64::new(0);
const REROLL_COOLDOWN_SECS: u64 = 60;

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A weighted random index other than `current`.
fn pick(weights: &[u32], current: usize) -> usize {
	let others = || weights.iter().enumerate().filter(|&(i, _)| i != current);
	let total: u32 = others().map(|(_, w)| w).sum();
	if total == 0 {
		let count = others().count();
		return others().nth(fastrand::usize(..count)).map_or(0, |(i, _)| i);
	}
	let mut draw = fastrand::u32(..total);
	for (i, &weight) in others() {
		if draw < weight {
			return i;
		}
		draw -= weight;
	}
	unreachable!("the draw is below the total weight")
}

fn client_for(profile: Profile, platform: Platform) -> WreqClient {
	WreqClient::builder()
		.emulation(Emulation::builder().profile(profile).platform(platform).build())
		.redirect(Policy::none())
		.dns_resolver(RedgifsIpv4Resolver(GaiResolver::new()))
		.build()
		.expect("Should always be able to build a client")
}

/// Builds a client with another, weighted random browser emulation.
pub fn build_client() -> WreqClient {
	let now = now_secs();
	let weights: Vec<u32> = FINGERPRINTS.iter().map(|f| f.weight(now)).collect();
	let index = pick(&weights, EMULATION.load(Ordering::Relaxed));
	EMULATION.store(index, Ordering::Relaxed);
	let Fingerprint { profile, platform, .. } = FINGERPRINTS[index];
	info!("Building Wreq client with random emulation {profile:?} on {platform:?}");
	client_for(profile, platform)
}

/// The emulation `CLIENT` uses, for `fingerprint_blocked`.
pub(crate) fn current_emulation() -> usize {
	EMULATION.load(Ordering::Relaxed)
}

/// Reddit's fingerprint block page. Private or banned subs answer JSON 403s.
pub(crate) fn is_fingerprint_block(status: u16, content_type: Option<&[u8]>, body: &[u8]) -> bool {
	status == 403 && content_type.is_some_and(|v| v.starts_with(b"text/html")) && String::from_utf8_lossy(body).to_lowercase().contains("blocked by network security")
}

/// Leaves emulation `index` out for `BLOCK_SECS` and switches away from it,
/// unless `CLIENT` already switched since the request went out.
pub(crate) fn fingerprint_blocked(index: usize) {
	let Some(fingerprint) = FINGERPRINTS.get(index) else {
		return;
	};
	if current_emulation() != index {
		return;
	}
	let now = now_secs();
	if fingerprint.blocked_until.swap(now + BLOCK_SECS, Ordering::Relaxed) <= now {
		info!(
			"Reddit blocks anonymous JSON for {:?} on {:?}, leaving it out for {} hours",
			fingerprint.profile,
			fingerprint.platform,
			BLOCK_SECS / 3600
		);
	}
	reroll_client("Reddit blocked the browser emulation");
}

/// Set at startup when Redlib runs IPv6-only.
pub static IPV6_ONLY: AtomicBool = AtomicBool::new(false);

/// RedGifs binds its API token to the IP that fetched it, and a dual-stack host
/// can connect over either IPv4 or IPv6. RedGifs hosts therefore resolve to IPv4
/// only, unless Redlib runs IPv6-only or there is no IPv4 address.
struct RedgifsIpv4Resolver(GaiResolver);

impl Resolve for RedgifsIpv4Resolver {
	fn resolve(&self, name: Name) -> Resolving {
		let pin = !IPV6_ONLY.load(Ordering::Relaxed) && crate::redgifs::is_redgifs_domain(name.as_str());
		let lookup = self.0.resolve(name);
		Box::pin(async move {
			let addrs = lookup.await?;
			if !pin {
				return Ok(addrs);
			}
			Ok(Box::new(prefer_ipv4(addrs.collect()).into_iter()) as Addrs)
		})
	}
}

fn prefer_ipv4(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
	let v4: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv4).collect();
	if v4.is_empty() {
		addrs
	} else {
		v4
	}
}

/// Switches `CLIENT` to another browser emulation, at most once per
/// `REROLL_COOLDOWN_SECS`, and logs `reason`. Returns whether it switched.
pub(crate) fn reroll_client(reason: &str) -> bool {
	let now = now_secs();
	let last = LAST_REROLL.load(Ordering::Relaxed);
	if now.saturating_sub(last) < REROLL_COOLDOWN_SECS || LAST_REROLL.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
		return false;
	}
	warn!("{reason}, switching the browser emulation");
	CLIENT.store(Arc::new(build_client()));
	crate::redgifs::clear_token();
	true
}

/// The `Cookie` headers of logged-in reddit.com sessions, from configuration.
///
/// Reddit stopped serving `.json` to logged-out clients: it answers with an
/// HTML block page and HTTP 403. A real session cookie makes the same request
/// return JSON, which is the only way to keep post and comment pages working.
/// Several sessions are separated by `|` and used in turn, followed by those
/// in the session file. Each comes with a label for the logs, which must never
/// show the cookie itself.
pub(crate) fn session_cookies() -> Vec<(String, String)> {
	let from_setting = get_setting(REDDIT_COOKIE_SETTING)
		.unwrap_or_default()
		.split('|')
		.enumerate()
		.map(|(i, part)| (format!("#{}", i + 1), part.to_string()))
		.collect::<Vec<_>>();
	let from_file = get_setting(REDDIT_COOKIE_FILE_SETTING)
		.map(|path| COOKIE_FILE.lock().map(|mut file| file.sessions(Path::new(&path), now_secs())).unwrap_or_default())
		.unwrap_or_default();

	let mut seen = std::collections::HashSet::new();
	from_setting
		.into_iter()
		.chain(from_file)
		.filter(|(_, part)| !part.trim().is_empty())
		.filter_map(|(label, part)| match session_cookie(&part) {
			Ok(cookie) => seen.insert(cookie.clone()).then_some((label, cookie)),
			Err(reason) => {
				warn_once(format!("Ignoring session {label}: {reason}"));
				None
			}
		})
		.collect()
}

static COOKIE_FILE: LazyLock<std::sync::Mutex<CookieFile>> = LazyLock::new(Default::default);

/// The lines of the session file as last read, so a broken edit keeps the
/// sessions that worked.
#[derive(Default)]
struct CookieFile {
	checked: Option<u64>,
	version: Option<(SystemTime, u64)>,
	sessions: Vec<(String, String)>,
}

impl CookieFile {
	fn sessions(&mut self, path: &Path, now: u64) -> Vec<(String, String)> {
		if self.checked.is_none_or(|checked| now.saturating_sub(checked) >= REDDIT_COOKIE_FILE_RECHECK_SECS) {
			self.checked = Some(now);
			self.reload(path);
		}
		self.sessions.clone()
	}

	fn reload(&mut self, path: &Path) {
		let version = std::fs::metadata(path).and_then(|meta| Ok((meta.modified()?, meta.len())));
		if version.as_ref().ok() == self.version.as_ref() {
			return;
		}
		match version.and_then(|version| Ok((version, std::fs::read_to_string(path)?))) {
			Ok((version, text)) => {
				self.version = Some(version);
				self.sessions = cookie_file_lines(&text);
				info!("Read {} session line(s) from {REDDIT_COOKIE_FILE_SETTING}", self.sessions.len());
			}
			Err(e) => warn_once(format!(
				"Couldn't read {REDDIT_COOKIE_FILE_SETTING} ({e}), keeping the {} session line(s) read last",
				self.sessions.len()
			)),
		}
	}
}

/// The sessions in a session file: one per line, `#` starts a comment line.
fn cookie_file_lines(text: &str) -> Vec<(String, String)> {
	text
		.lines()
		.enumerate()
		.map(|(i, line)| (format!("file line {}", i + 1), line.trim().to_string()))
		.filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
		.collect()
}

/// The `Cookie` header for a configured session, or why it can't be used.
///
/// Only `reddit_session` is needed, so a bare value is taken as one. An
/// expired one is skipped before Reddit refuses it, since every refusal
/// counts against the browser emulation.
fn session_cookie(raw: &str) -> Result<String, &'static str> {
	let cookie = sanitize_cookie(raw).ok_or("not a valid Cookie header")?;
	let cookie = if cookie.contains('=') { cookie } else { format!("reddit_session={cookie}") };
	let session = cookie
		.split(';')
		.find_map(|pair| pair.trim().strip_prefix("reddit_session="))
		.ok_or("no reddit_session cookie")?;
	if jwt_expiry(session).is_some_and(|expiry| expiry <= now_secs()) {
		return Err("its reddit_session has expired");
	}
	Ok(cookie)
}

/// The `exp` claim of a JWT, if `token` is one.
fn jwt_expiry(token: &str) -> Option<u64> {
	use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
	let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?).ok()?;
	claims["exp"].as_f64().map(|exp| exp as u64)
}

/// Logs `message` the first time only: the sessions are read on every request.
fn warn_once(message: String) {
	static SEEN: LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> = LazyLock::new(Default::default);
	if SEEN.lock().is_ok_and(|mut seen| seen.insert(message.clone())) {
		warn!("{message}");
	}
}

/// Trims and validates a `Cookie` header from configuration.
///
/// The value goes into a single header line, so control characters (which could
/// end the line and inject another header) and non-ASCII bytes are rejected
/// rather than forwarded to Reddit.
fn sanitize_cookie(raw: &str) -> Option<String> {
	let cookie = raw.trim();

	if cookie.is_empty() || cookie.len() > REDDIT_COOKIE_MAX_LEN || !cookie.is_ascii() || cookie.chars().any(char::is_control) {
		return None;
	}

	Some(cookie.to_string())
}

/// Gets the canonical path for a resource on Reddit. This is accomplished by
/// making a `HEAD` request to Reddit at the path given in `path`.
///
/// This function returns `Ok(Some(path))`, where `path`'s value is identical
/// to that of the value of the argument `path`, if Reddit responds to our
/// `HEAD` request with a 2xx-family HTTP code. It will also return an
/// `Ok(Some(String))` if Reddit responds to our `HEAD` request with a
/// `Location` header in the response, and the HTTP code is in the 3xx-family;
/// the `String` will contain the path as reported in `Location`. The return
/// value is `Ok(None)` if Reddit responded with a 3xx, but did not provide a
/// `Location` header. An `Err(String)` is returned if Reddit responds with a
/// 429, or if we were unable to decode the value in the `Location` header.
#[cached(max_size = 1024, ttl_secs = 600)]
#[async_recursion::async_recursion]
pub async fn canonical_path(path: String, tries: i8) -> Result<Option<String>, String> {
	if tries == 0 {
		return Ok(None);
	}

	// for each URL pair, try the HEAD request
	let res = {
		// for url base and host in URL_PAIRS, try reddit_short_head(path.clone(), true, url_base, url_base_host) and if it succeeds, set res. else, res = None
		let mut res = None;
		for (url_base, url_base_host) in URL_PAIRS {
			res = reddit_short_head(path.clone(), true, url_base, url_base_host).await.ok();
			if let Some(res) = &res {
				if !res.status().is_client_error() {
					break;
				}
			}
		}
		res
	};

	let res = res.ok_or_else(|| "Unable to make HEAD request to Reddit.".to_string())?;
	let status = res.status().as_u16();
	let policy_error = res.headers().get(wreq_header::RETRY_AFTER).is_some();

	match status {
		// If Reddit responds with a 2xx, then the path is already canonical.
		200..=299 => Ok(Some(path)),

		// If Reddit responds with a 301, then the path is redirected.
		301 => match res.headers().get(wreq_header::LOCATION) {
			Some(val) => {
				let Ok(original) = val.to_str() else {
					return Err("Unable to decode Location header.".to_string());
				};

				// We need to strip the .json suffix from the original path.
				// In addition, we want to remove share parameters.
				// Cut it off here instead of letting it propagate all the way
				// to main.rs
				let stripped_uri = original.strip_suffix(".json").unwrap_or(original).split('?').next().unwrap_or_default();

				// The reason why we now have to format_url, is because the new OAuth
				// endpoints seem to return full paths, instead of relative paths.
				// So we need to strip the .json suffix from the original path, and
				// also remove all Reddit domain parts with format_url.
				// Otherwise, it will literally redirect to Reddit.com.
				let uri = format_url(stripped_uri);

				// Decrement tries and try again
				canonical_path(uri, tries - 1).await
			}
			None => Ok(None),
		},

		// If Reddit responds with anything other than 3xx (except for the 2xx and 301
		// as above), return a None.
		300..=399 => Ok(None),

		// Rate limiting
		429 => Err("Too many requests.".to_string()),

		// Special condition rate limiting - https://github.com/redlib-org/redlib/issues/229
		403 if policy_error => Err("Too many requests.".to_string()),

		_ => Ok(
			res
				.headers()
				.get(wreq_header::LOCATION)
				.map(|val| percent_encode(val.as_bytes(), CONTROLS).to_string().trim_start_matches(REDDIT_URL_BASE).to_string()),
		),
	}
}

/// Every host `proxy` may fetch from, one per media route (see `main.rs` and
/// `redgifs.rs`). A new route needs its host added here.
const PROXY_HOSTS: &[&str] = &[
	"v.redd.it",
	"packaged-media.redd.it",
	"external-packaged-media.redd.it",
	"i.redd.it",
	"a.thumbs.redditmedia.com",
	"b.thumbs.redditmedia.com",
	"emoji.redditmedia.com",
	"reddit-econ-prod-assets-permanent.s3.amazonaws.com",
	"preview.redd.it",
	"external-preview.redd.it",
	"styles.redditmedia.com",
	"www.redditstatic.com",
	"media.giphy.com",
	"media.redgifs.com",
];

/// Fills the route parameters of `req` into `format`, parses the result and
/// checks it against `PROXY_HOSTS`.
fn proxy_url(req: &HyperRequest<Body>, format: &str) -> Result<wreq::Uri, String> {
	let mut url = format!("{format}?{}", req.uri().query().unwrap_or_default());

	// For each parameter in request
	for (name, value) in &req.params() {
		// Fill the parameter value in the url
		url = url.replace(&format!("{{{name}}}"), value);
	}

	// First parameter is target URL (mandatory).
	let uri = wreq::Uri::try_from(url).map_err(|_| "Couldn't parse URL".to_string())?;

	// Route parameters can end up in the host (`{loc}view.redd.it`), so check
	// the host that came out, not the one the route meant. Only whole, listed
	// hosts pass: no IP literal, port or userinfo, and no other subdomain.
	let host_allowed = uri.scheme_str() == Some("https")
		&& uri.host().is_some_and(|host| PROXY_HOSTS.contains(&host))
		&& uri.authority().is_some_and(|authority| Some(authority.as_str()) == uri.host());
	if host_allowed {
		Ok(uri)
	} else {
		Err("Host not allowed".to_string())
	}
}

/// The upstream headers the media proxy passes on. Anything else, such as
/// `Set-Cookie`, `Location` or `Content-Security-Policy`, stays behind.
const PROXY_RESPONSE_HEADERS: &[&str] = &[
	"content-type",
	"content-length",
	"content-range",
	"content-encoding",
	"accept-ranges",
	"cache-control",
	"expires",
	"last-modified",
];

/// Whether `content_type` is something the media proxy serves: images, video,
/// audio, fonts and the streaming playlists. Pages, scripts and SVG are not,
/// since the proxy serves from redlib's own origin.
fn proxy_content_type_allowed(content_type: Option<&header::HeaderValue>) -> bool {
	let Some(content_type) = content_type.and_then(|value| value.to_str().ok()) else {
		return false;
	};
	let media_type = content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
	media_type != "image/svg+xml"
		&& (["image/", "video/", "audio/", "font/"].iter().any(|prefix| media_type.starts_with(prefix))
			|| [
				"application/vnd.apple.mpegurl",
				"application/x-mpegurl",
				"application/dash+xml",
				"application/octet-stream",
				"binary/octet-stream",
			]
			.contains(&media_type.as_str()))
}

/// Limits what the media proxy hands to the browser: media types only, with
/// the headers in `PROXY_RESPONSE_HEADERS`. Redirects are not passed on (the
/// browser would follow them straight to Reddit) and an upstream error page is
/// swapped for a plain text one with the same status.
fn restrict_proxy_response(mut res: HyperResponse<Body>) -> HyperResponse<Body> {
	let status = res.status();
	// A 304 answers a conditional request and has no body or type.
	let not_modified = status == hyper::StatusCode::NOT_MODIFIED;
	if !not_modified && (status.is_redirection() || !proxy_content_type_allowed(res.headers().get(header::CONTENT_TYPE))) {
		return if status.is_client_error() || status.is_server_error() {
			proxy_error(status.as_u16(), "Upstream error")
		} else {
			proxy_error(502, "Bad gateway")
		};
	}

	let unwanted: Vec<_> = res.headers().keys().filter(|name| !PROXY_RESPONSE_HEADERS.contains(&name.as_str())).cloned().collect();
	for name in unwanted {
		res.headers_mut().remove(name);
	}
	res
}

/// A plain text error for a client of the media proxy. It says what went wrong
/// in general terms and never repeats the URL it was asked to fetch.
fn proxy_error(status: u16, message: &'static str) -> HyperResponse<Body> {
	HyperResponse::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
		.body(Body::from(message))
		.unwrap()
}

pub async fn proxy(req: HyperRequest<Body>, format: &str) -> Result<HyperResponse<Body>, String> {
	let Ok(wreq_uri) = proxy_url(&req, format) else {
		return Ok(proxy_error(400, "Bad request"));
	};

	let mut builder = CLIENT.load_full().get(wreq_uri);

	// Copy useful headers from original request
	for &key in &["Range", "If-Modified-Since", "Cache-Control"] {
		if let Some(value) = req.headers().get(key) {
			builder = builder.header(key, value.as_bytes());
		}
	}

	// Add User-Agent header of the currently spoofed device
	{
		let client = OAUTH_CLIENT.load_full();
		builder = builder.header("User-Agent", client.user_agent());
	}

	// This is needed or Reddit will redirect us to a /media landing page that just renders the image.
	builder = builder.header(wreq_header::ACCEPT, "*/*");

	builder.send().await.map(|res| restrict_proxy_response(res.into_hyper_response())).or_else(|e| {
		// Not `e`: wreq puts the upstream URL in its errors.
		dbg_msg!("proxy request failed: {}", e);
		Ok(proxy_error(502, "Bad gateway"))
	})
}

/// Makes a GET request to Reddit at `path`. By default, this will honor HTTP
/// 3xx codes Reddit returns and will automatically redirect.
pub(crate) fn reddit_get(path: String, quarantine: bool) -> Boxed<Result<WreqResponse, String>> {
	request(&Method::GET, path, true, quarantine, REDDIT_URL_BASE, REDDIT_URL_BASE_HOST)
}

/// Makes a HEAD request to Reddit at `path, using the short URL base. This will not follow redirects.
fn reddit_short_head(path: String, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<WreqResponse, String>> {
	request(&Method::HEAD, path, false, quarantine, base_path, host)
}

// /// Makes a HEAD request to Reddit at `path`. This will not follow redirects.
// fn reddit_head(path: String, quarantine: bool) -> Boxed<Result<Response<Body>, String>> {
// 	request(&Method::HEAD, path, false, quarantine, false)
// }
// Unused - reddit_head is only ever called in the context of a short URL

/// Makes a request to Reddit. If `redirect` is `true`, `request_with_redirect`
/// will recurse on the URL that Reddit provides in the Location HTTP header
/// in its response.
fn request(method: &'static Method, path: String, redirect: bool, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<WreqResponse, String>> {
	follow_redirects(path, redirect, move |path| send_to_reddit(method, path, quarantine, base_path, host)).boxed()
}

/// Sends one request to Reddit, with the current OAuth headers.
fn send_to_reddit(
	method: &'static Method,
	path: String,
	quarantine: bool,
	base_path: &'static str,
	host: &'static str,
) -> impl std::future::Future<Output = Result<WreqResponse, String>> {
	// Build Reddit URL from path.
	let url = format!("{base_path}{path}");

	let mut headers: Vec<(String, String)> = vec![
		("Host".into(), host.into()),
		(
			"Cookie".into(),
			if quarantine {
				"_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D".into()
			} else {
				"".into()
			},
		),
	];

	{
		let client = OAUTH_CLIENT.load_full();
		for (key, value) in client.headers_map.clone() {
			headers.push((key, value));
		}
	}

	// shuffle headers: https://github.com/redlib-org/redlib/issues/324
	fastrand::shuffle(&mut headers);

	let mut builder = CLIENT.load_full().request(method.clone(), &url);

	for (key, value) in headers {
		builder = builder.header(key, value);
	}

	async move {
		builder.send().await.map_err(|e| {
			dbg_msg!("{method} {REDDIT_URL_BASE}{path}: {}", e);

			e.to_string()
		})
	}
}

/// Most redirects `follow_redirects` follows before it gives up. Reddit sends
/// a handful at most (a short link, then the canonical path).
const MAX_REDIRECTS: usize = 10;

/// Sends the request for `path` with `send` and, if `redirect` is `true`,
/// follows the redirects Reddit answers with, up to `MAX_REDIRECTS`.
async fn follow_redirects<F, Fut>(mut path: String, redirect: bool, send: F) -> Result<WreqResponse, String>
where
	F: Fn(String) -> Fut,
	Fut: std::future::Future<Output = Result<WreqResponse, String>>,
{
	for _ in 0..=MAX_REDIRECTS {
		let response = send(path).await?;

		// Reddit may respond with a 3xx. Decide whether or not to
		// redirect based on caller params.
		if !response.status().is_redirection() || !redirect {
			return Ok(response);
		}
		let location_header = response.headers().get(wreq::header::LOCATION);
		if location_header.and_then(|h| h.to_str().ok()) == Some(ALTERNATIVE_REDDIT_URL_BASE) {
			return Err("Reddit response was invalid".to_string());
		}
		path = location_header
			.map(|val| {
				// We need to make adjustments to the URI
				// we get back from Reddit. Namely, we
				// must:
				//
				//     1. Remove the authority (e.g.
				//     https://www.reddit.com) that may be
				//     present, so that we recurse on the
				//     path (and query parameters) as
				//     required.
				//
				//     2. Percent-encode the path.
				let new_path = percent_encode(val.as_bytes(), CONTROLS)
					.to_string()
					.trim_start_matches(REDDIT_URL_BASE)
					.trim_start_matches(ALTERNATIVE_REDDIT_URL_BASE)
					.to_string();
				format!("{new_path}{}raw_json=1", if new_path.contains('?') { "&" } else { "?" })
			})
			.unwrap_or_default();
	}
	Err("Too many redirects".to_string())
}

pub(crate) trait IntoHyperResponse {
	fn into_hyper_response(self) -> HyperResponse<Body>;
}

impl IntoHyperResponse for WreqResponse {
	fn into_hyper_response(self) -> HyperResponse<Body> {
		let status = self.status();
		let version = self.version();

		let mut builder = HyperResponse::builder().status(status.as_u16()).version(match version {
			wreq::Version::HTTP_09 => hyper::Version::HTTP_09,
			wreq::Version::HTTP_10 => hyper::Version::HTTP_10,
			wreq::Version::HTTP_11 => hyper::Version::HTTP_11,
			wreq::Version::HTTP_2 => hyper::Version::HTTP_2,
			wreq::Version::HTTP_3 => hyper::Version::HTTP_3,
			_ => hyper::Version::HTTP_11,
		});

		for (name, value) in self.headers() {
			builder = builder.header(
				header::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
				header::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
			);
		}

		builder.body(Body::from_stream(self.bytes_stream())).unwrap()
	}
}

#[cfg(test)]
mod redirect_limit_tests {
	use super::*;
	use std::sync::atomic::AtomicUsize;
	use std::time::Duration;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	/// A local HTTP server: `/loop` redirects to itself forever, `/a` redirects
	/// to `/b` once, everything else is a 200. Returns its address and a hit counter.
	async fn redirect_server() -> (SocketAddr, Arc<AtomicUsize>) {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let hits = Arc::new(AtomicUsize::new(0));
		let counter = hits.clone();
		tokio::spawn(async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else { return };
				counter.fetch_add(1, Ordering::SeqCst);
				tokio::spawn(async move {
					let mut buf = vec![0u8; 4096];
					let n = stream.read(&mut buf).await.unwrap_or(0);
					let request = String::from_utf8_lossy(&buf[..n]).to_string();
					let target = request.split_whitespace().nth(1).unwrap_or_default().to_string();
					let reply = if target.starts_with("/loop") {
						"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
					} else if target.starts_with("/a") {
						"HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
					} else {
						"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
					};
					let _ = stream.write_all(reply.as_bytes()).await;
				});
			}
		});
		(addr, hits)
	}

	fn follow(addr: SocketAddr, path: &str) -> impl std::future::Future<Output = Result<WreqResponse, String>> {
		let client = WreqClient::builder().redirect(Policy::none()).build().unwrap();
		follow_redirects(path.to_string(), true, move |path| {
			let request = client.get(format!("http://{addr}{path}")).send();
			async move { request.await.map_err(|e| e.to_string()) }
		})
	}

	#[test]
	fn test_redirect_loop_is_cut_off() {
		block_on_shared(async {
			let (addr, hits) = redirect_server().await;
			let result = tokio::time::timeout(Duration::from_secs(10), follow(addr, "/loop")).await;
			assert!(result.is_ok(), "a redirect loop must end instead of running forever");
			assert!(result.unwrap().is_err(), "a redirect loop must be an error");
			assert!(hits.load(Ordering::SeqCst) <= 20, "too many hops: {}", hits.load(Ordering::SeqCst));
		});
	}

	#[test]
	fn test_single_redirect_is_followed() {
		block_on_shared(async {
			let (addr, _) = redirect_server().await;
			let response = tokio::time::timeout(Duration::from_secs(10), follow(addr, "/a")).await.unwrap().unwrap();
			assert_eq!(response.status().as_u16(), 200);
		});
	}
}

#[cfg(test)]
mod proxy_target_tests {
	use super::*;
	use route_recognizer::Params;

	fn target(format: &str, params: &[(&str, &str)], query: &str) -> Result<wreq::Uri, String> {
		let mut req = HyperRequest::builder().uri(format!("/x?{query}")).body(Body::empty()).unwrap();
		let mut route_params = Params::new();
		for (name, value) in params {
			route_params.insert((*name).to_string(), (*value).to_string());
		}
		req.set_params(route_params);
		proxy_url(&req, format)
	}

	const PREVIEW: &str = "https://{loc}view.redd.it/{id}";
	const AWARD: &str = "https://{loc}view.redd.it/award_images/{fullname}/{id}";
	const THUMB: &str = "https://{point}.thumbs.redditmedia.com/{id}";

	#[test]
	fn test_the_routes_still_reach_their_hosts() {
		type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
		let cases: &[Case] = &[
			(PREVIEW, &[("loc", "pre"), ("id", "a.jpg")], "preview.redd.it"),
			(PREVIEW, &[("loc", "external-pre"), ("id", "a.jpg")], "external-preview.redd.it"),
			(AWARD, &[("loc", "pre"), ("fullname", "t5_1"), ("id", "a.png")], "preview.redd.it"),
			(THUMB, &[("point", "a"), ("id", "a.jpg")], "a.thumbs.redditmedia.com"),
			(THUMB, &[("point", "b"), ("id", "a.jpg")], "b.thumbs.redditmedia.com"),
			(
				"https://v.redd.it/{id}/{prefix}_{size}",
				&[("id", "abc"), ("prefix", "DASH"), ("size", "720.mp4")],
				"v.redd.it",
			),
			("https://v.redd.it/{id}/{path}", &[("id", "abc"), ("path", "HLSPlaylist.m3u8")], "v.redd.it"),
			("https://packaged-media.redd.it/{path}", &[("path", "abc/pb/m2-res_1080p.mp4")], "packaged-media.redd.it"),
			(
				"https://external-packaged-media.redd.it/{path}",
				&[("path", "abc/pb/m2-res_1080p.mp4")],
				"external-packaged-media.redd.it",
			),
			("https://i.redd.it/{path}", &[("path", "abc.jpg")], "i.redd.it"),
			("https://emoji.redditmedia.com/{id}/{name}", &[("id", "abc"), ("name", "Emoji")], "emoji.redditmedia.com"),
			(
				"https://reddit-econ-prod-assets-permanent.s3.amazonaws.com/asset-manager/{subreddit_id}/{filename}",
				&[("subreddit_id", "t5_1"), ("filename", "a.png")],
				"reddit-econ-prod-assets-permanent.s3.amazonaws.com",
			),
			("https://styles.redditmedia.com/{path}", &[("path", "t5_1/styles/a.png")], "styles.redditmedia.com"),
			("https://www.redditstatic.com/{path}", &[("path", "desktop2x/img/a.png")], "www.redditstatic.com"),
			("https://media.giphy.com/media/{id}/giphy.{ext}", &[("id", "abc"), ("ext", "gif")], "media.giphy.com"),
			("https://media.redgifs.com/Some.mp4", &[], "media.redgifs.com"),
		];
		for (format, params, host) in cases {
			let uri = target(format, params, "a=b").unwrap_or_else(|e| panic!("{format} {params:?}: {e}"));
			assert_eq!(uri.host(), Some(*host), "{format} {params:?}");
			assert_eq!(uri.scheme_str(), Some("https"));
			assert_eq!(uri.query(), Some("a=b"));
		}
	}

	#[test]
	fn test_ip_literal_in_the_host_slot_is_rejected() {
		// The audit's payloads: /preview/[::ffff:10.x.x.x]/x and /thumb/[::1]/x.
		for loc in ["[::ffff:10.0.0.1]", "[::1]", "[2001:db8::1]", "[::ffff:10.0.0.1]:8443", "10.0.0.1"] {
			assert!(target(PREVIEW, &[("loc", loc), ("id", "x")], "").is_err(), "preview loc {loc}");
			assert!(target(AWARD, &[("loc", loc), ("fullname", "f"), ("id", "x")], "").is_err(), "award loc {loc}");
			assert!(target(THUMB, &[("point", loc), ("id", "x")], "").is_err(), "thumb point {loc}");
		}
	}

	#[test]
	fn test_other_hosts_in_the_host_slot_are_rejected() {
		for loc in ["evil", "x.evil.example/", "pre.", "i", "PRE", "pre@evil.example/", "pre:8443@evil.example/", ""] {
			assert!(target(PREVIEW, &[("loc", loc), ("id", "x")], "").is_err(), "preview loc {loc}");
		}
		for point in ["evil", "c", "a.evil", "", "A", "a@evil.example/#"] {
			assert!(target(THUMB, &[("point", point), ("id", "x")], "").is_err(), "thumb point {point}");
		}
	}

	#[test]
	fn test_a_rejected_target_gets_a_generic_text_error() {
		let mut req = HyperRequest::builder().uri("/preview/[::1]/x.jpg").body(Body::empty()).unwrap();
		let mut params = Params::new();
		params.insert("loc".to_string(), "[::1]".to_string());
		params.insert("id".to_string(), "x.jpg".to_string());
		req.set_params(params);
		block_on_shared(async {
			let res = proxy(req, PREVIEW).await.expect("a rejected target is an answer, not an error");
			assert_eq!(res.status().as_u16(), 400);
			assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/plain; charset=utf-8");
			let body = String::from_utf8(res.into_body().collect_bytes().await.unwrap().to_vec()).unwrap();
			assert!(!body.contains("::1") && !body.contains("redd.it"), "the error repeats the target: {body}");
		});
	}
}

#[cfg(test)]
mod proxy_response_tests {
	use super::*;

	fn upstream(status: u16, headers: &[(&str, &str)]) -> HyperResponse<Body> {
		let mut builder = HyperResponse::builder().status(status);
		for (name, value) in headers {
			builder = builder.header(*name, *value);
		}
		builder.body(Body::from("body")).unwrap()
	}

	fn header<'a>(res: &'a HyperResponse<Body>, name: &str) -> Option<&'a str> {
		res.headers().get(name).map(|v| v.to_str().unwrap())
	}

	#[test]
	fn test_media_passes_with_only_its_own_headers() {
		let res = restrict_proxy_response(upstream(
			200,
			&[
				("Content-Type", "image/jpeg"),
				("Content-Length", "4"),
				("Cache-Control", "max-age=60"),
				("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT"),
				("Accept-Ranges", "bytes"),
				("Set-Cookie", "session=attacker; Path=/"),
				("Location", "https://example.com/"),
				("Content-Security-Policy", "default-src *"),
				("Access-Control-Allow-Origin", "*"),
				("Content-Disposition", "attachment"),
				("X-Reddit-Cache", "HIT"),
				("Server", "snooserv"),
			],
		));
		assert_eq!(res.status().as_u16(), 200);
		for kept in ["Content-Type", "Content-Length", "Cache-Control", "Last-Modified", "Accept-Ranges"] {
			assert!(header(&res, kept).is_some(), "{kept} was dropped");
		}
		for dropped in [
			"Set-Cookie",
			"Location",
			"Content-Security-Policy",
			"Access-Control-Allow-Origin",
			"Content-Disposition",
			"X-Reddit-Cache",
			"Server",
		] {
			assert!(header(&res, dropped).is_none(), "{dropped} was passed through");
		}
	}

	#[test]
	fn test_media_types_pass() {
		for content_type in [
			"image/png",
			"image/webp",
			"IMAGE/GIF",
			"video/mp4",
			"audio/mp4",
			"application/vnd.apple.mpegurl",
			"application/x-mpegURL; charset=utf-8",
			"application/dash+xml",
			"application/octet-stream",
			"binary/octet-stream",
		] {
			let res = restrict_proxy_response(upstream(200, &[("Content-Type", content_type)]));
			assert_eq!(res.status().as_u16(), 200, "{content_type}");
			assert_eq!(header(&res, "Content-Type"), Some(content_type));
		}
		let partial = restrict_proxy_response(upstream(206, &[("Content-Type", "video/mp4"), ("Content-Range", "bytes 0-3/10")]));
		assert_eq!(partial.status().as_u16(), 206);
		assert_eq!(header(&partial, "Content-Range"), Some("bytes 0-3/10"));
		let unchanged = restrict_proxy_response(upstream(304, &[("Cache-Control", "max-age=60")]));
		assert_eq!(unchanged.status().as_u16(), 304);
	}

	#[test]
	fn test_active_content_types_are_refused() {
		for content_type in [
			"text/html",
			"text/html; charset=utf-8",
			"text/javascript",
			"application/javascript",
			"image/svg+xml",
			"application/xhtml+xml",
			"text/xml",
		] {
			let res = restrict_proxy_response(upstream(200, &[("Content-Type", content_type)]));
			assert_eq!(res.status().as_u16(), 502, "{content_type}");
			assert_eq!(header(&res, "Content-Type"), Some("text/plain; charset=utf-8"), "{content_type}");
		}
		let untyped = restrict_proxy_response(upstream(200, &[]));
		assert_eq!(untyped.status().as_u16(), 502);
	}

	#[test]
	fn test_upstream_errors_keep_their_status_but_not_their_page() {
		let res = restrict_proxy_response(upstream(404, &[("Content-Type", "text/html")]));
		assert_eq!(res.status().as_u16(), 404);
		assert_eq!(header(&res, "Content-Type"), Some("text/plain; charset=utf-8"));
	}

	#[test]
	fn test_redirects_are_not_passed_to_the_browser() {
		let res = restrict_proxy_response(upstream(302, &[("Location", "https://example.com/"), ("Content-Type", "image/png")]));
		assert_eq!(res.status().as_u16(), 502);
		assert!(header(&res, "Location").is_none());
	}
}

#[cfg(test)]
mod outbound_timeout_tests {
	use super::*;
	use std::time::Duration;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	/// A local HTTP server that accepts connections and then goes quiet:
	/// `/headers` never answers, anything else sends headers and half of
	/// its body, then stalls.
	async fn stalling_server() -> SocketAddr {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		tokio::spawn(async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else { return };
				tokio::spawn(async move {
					let mut buf = vec![0u8; 4096];
					let n = stream.read(&mut buf).await.unwrap_or(0);
					if !String::from_utf8_lossy(&buf[..n]).starts_with("GET /headers") {
						let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf").await;
					}
					// Hold the connection open without another byte.
					tokio::time::sleep(Duration::from_secs(3600)).await;
				});
			}
		});
		addr
	}

	fn client() -> WreqClient {
		client_for(Profile::Chrome131, Platform::Linux)
	}

	#[test]
	fn test_a_peer_that_never_answers_times_out() {
		block_on_shared(async {
			let addr = stalling_server().await;
			let request = client().get(format!("http://{addr}/headers")).send();
			let result = tokio::time::timeout(Duration::from_secs(10), request).await;
			assert!(result.is_ok(), "the request waited for a peer that never answers");
			assert!(result.unwrap().is_err());
		});
	}

	#[test]
	fn test_a_body_that_stalls_times_out() {
		block_on_shared(async {
			let addr = stalling_server().await;
			let response = client().get(format!("http://{addr}/body")).send().await.unwrap();
			let result = tokio::time::timeout(Duration::from_secs(10), response.bytes()).await;
			assert!(result.is_ok(), "the body read waited for a peer that went quiet");
			assert!(result.unwrap().is_err());
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use {crate::config::get_setting, sealed_test::prelude::*};

	#[test]
	fn test_prefer_ipv4_keeps_ipv6_without_ipv4() {
		let v4: SocketAddr = "104.18.36.123:443".parse().unwrap();
		let v6: SocketAddr = "[2606:4700:440a::ac40:9785]:443".parse().unwrap();
		assert_eq!(prefer_ipv4(vec![v6, v4]), vec![v4]);
		assert_eq!(prefer_ipv4(vec![v6]), vec![v6]);
	}

	#[test]
	fn test_cookie_is_trimmed_and_kept_intact() {
		assert_eq!(
			sanitize_cookie("  reddit_session=abc; token_v2=def; over18=1\n").as_deref(),
			Some("reddit_session=abc; token_v2=def; over18=1")
		);
	}

	#[test]
	fn test_empty_cookie_is_not_a_cookie() {
		assert_eq!(sanitize_cookie(""), None);
		assert_eq!(sanitize_cookie("   \n\t "), None);
	}

	#[test]
	fn test_cookie_cannot_inject_headers() {
		// A newline in the value would let it add headers to the request. A
		// trailing newline alone is harmless and trimmed, so test a second line.
		assert_eq!(sanitize_cookie("reddit_session=abc\r\nX-Injected: yes"), None);
		assert_eq!(sanitize_cookie("reddit_session=abc\nSet-Cookie: evil=1"), None);
		assert_eq!(sanitize_cookie("reddit_session=abc\u{0}"), None);
		// Header values are ASCII: non-ASCII bytes are not valid there.
		assert_eq!(sanitize_cookie("reddit_session=ábc"), None);
	}

	#[test]
	fn test_overlong_cookie_is_rejected() {
		let cookie = format!("reddit_session={}", "a".repeat(REDDIT_COOKIE_MAX_LEN));
		assert_eq!(sanitize_cookie(&cookie), None);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_REDDIT_COOKIE", "reddit_session=abc; token_v2=def")])]
	fn test_session_cookie_comes_from_the_environment() {
		assert_eq!(session_cookies(), vec![("#1".to_string(), "reddit_session=abc; token_v2=def".to_string())]);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_REDDIT_COOKIE", "reddit_session=a; token_v2=b | reddit_session=c\u{1}| |reddit_session=d")])]
	fn test_several_session_cookies_are_split_and_numbered() {
		// The invalid second session is dropped, the empty one skipped, and the
		// numbers keep pointing at the position in the setting.
		assert_eq!(
			session_cookies(),
			vec![
				("#1".to_string(), "reddit_session=a; token_v2=b".to_string()),
				("#4".to_string(), "reddit_session=d".to_string())
			]
		);
	}

	fn jwt(exp: u64) -> String {
		use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
		format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", URL_SAFE_NO_PAD.encode(format!("{{\"exp\":{exp}}}")))
	}

	#[test]
	fn test_session_cookie_needs_only_reddit_session() {
		assert_eq!(session_cookie(" abc ").as_deref(), Ok("reddit_session=abc"));
		assert_eq!(session_cookie("reddit_session=abc").as_deref(), Ok("reddit_session=abc"));
		assert_eq!(session_cookie("token_v2=abc"), Err("no reddit_session cookie"));
	}

	#[test]
	fn test_sessions_in_the_old_documented_form_still_work() {
		// `reddit_session=...;token_v2=...` as the old docs asked for, with a
		// long expired token_v2: sent exactly as before
		let old = format!("reddit_session={};token_v2={}", jwt(now_secs() + 3600), jwt(1000));
		assert_eq!(session_cookie(&format!(" {old} ")), Ok(old));
	}

	#[test]
	#[sealed_test]
	fn test_old_session_setting_keeps_every_session() {
		let old = |n: u64| format!("reddit_session={};token_v2={}", jwt(now_secs() + n), jwt(1000));
		std::env::set_var("REDLIB_REDDIT_COOKIE", format!("{} | {}|{}", old(1000), old(2000), old(3000)));
		assert_eq!(
			session_cookies(),
			vec![("#1".to_string(), old(1000)), ("#2".to_string(), old(2000)), ("#3".to_string(), old(3000))]
		);
	}

	#[test]
	fn test_expired_session_cookie_is_skipped() {
		let valid = jwt(now_secs() + 3600);
		assert_eq!(session_cookie(&valid), Ok(format!("reddit_session={valid}")));
		assert_eq!(
			session_cookie(&format!("token_v2=x; reddit_session={}", jwt(now_secs() - 1))),
			Err("its reddit_session has expired")
		);
		// Older sessions aren't JWTs; Reddit decides about those
		assert!(session_cookie("reddit_session=123%2C2024-01-01T00%3A00%3A00%2Cabc").is_ok());
	}

	#[test]
	fn test_session_file_skips_comments_and_blank_lines() {
		let text = "# Account 1\nreddit_session=a\n\n  # Account 2\n  b  \n";
		assert_eq!(
			cookie_file_lines(text),
			vec![("file line 2".to_string(), "reddit_session=a".to_string()), ("file line 5".to_string(), "b".to_string())]
		);
	}

	#[test]
	fn test_session_file_is_reread_when_it_changes() {
		let dir = std::env::temp_dir().join(format!("redlib-sessions-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("sessions.txt");
		let mut file = CookieFile::default();
		let names = |sessions: Vec<(String, String)>| sessions.into_iter().map(|(_, cookie)| cookie).collect::<Vec<_>>();

		std::fs::write(&path, "a\n").unwrap();
		assert_eq!(names(file.sessions(&path, 100)), ["a"]);
		// Not checked again before the interval is up
		std::fs::write(&path, "a\nb\n").unwrap();
		assert_eq!(names(file.sessions(&path, 105)), ["a"]);
		assert_eq!(names(file.sessions(&path, 110)), ["a", "b"]);
		// A file that went missing keeps the sessions read last
		std::fs::remove_file(&path).unwrap();
		assert_eq!(names(file.sessions(&path, 120)), ["a", "b"]);
		std::fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	#[sealed_test]
	fn test_sessions_come_from_the_setting_and_the_file() {
		std::fs::write("sessions.txt", "# throwaway\nreddit_session=b\nreddit_session=a\n").unwrap();
		std::env::set_var("REDLIB_REDDIT_COOKIE", "reddit_session=a");
		std::env::set_var("REDLIB_REDDIT_COOKIE_FILE", "sessions.txt");
		// The duplicate in the file is dropped
		assert_eq!(
			session_cookies(),
			vec![
				("#1".to_string(), "reddit_session=a".to_string()),
				("file line 2".to_string(), "reddit_session=b".to_string())
			]
		);
	}

	#[test]
	#[sealed_test]
	fn test_session_cookie_is_optional() {
		// CI sets one for the live tests
		std::env::remove_var("REDLIB_REDDIT_COOKIE");
		assert!(session_cookies().is_empty());
	}

	#[test]
	#[sealed_test]
	fn test_new_client_never_reuses_the_current_emulation() {
		for _ in 0..200 {
			let before = EMULATION.load(Ordering::Relaxed);
			build_client();
			assert_ne!(EMULATION.load(Ordering::Relaxed), before);
		}
	}

	#[test]
	#[sealed_test]
	fn test_reroll_waits_for_the_cooldown() {
		assert!(reroll_client("test"));
		assert!(!reroll_client("test"));
		LAST_REROLL.store(LAST_REROLL.load(Ordering::Relaxed) - REROLL_COOLDOWN_SECS, Ordering::Relaxed);
		assert!(reroll_client("test"));
	}

	#[test]
	fn test_pick_skips_the_current_and_zero_weights() {
		for _ in 0..200 {
			assert_eq!(pick(&[0, 5, 0, 5], 1), 3);
			assert_ne!(pick(&[5, 5, 5], 0), 0);
		}
	}

	#[test]
	fn test_pick_falls_back_to_any_other_when_all_are_blocked() {
		for _ in 0..200 {
			assert_ne!(pick(&[0, 0, 0], 2), 2);
		}
	}

	#[test]
	fn test_pick_follows_the_weights() {
		let picks = (0..10_000).filter(|_| pick(&[SERVED, REFUSED, 0], 2) == 1).count();
		assert!((300..700).contains(&picks), "{picks}");
	}

	#[test]
	#[sealed_test]
	fn test_blocked_fingerprint_is_not_picked_until_it_expires() {
		build_client();
		let blocked = current_emulation();
		fingerprint_blocked(blocked);
		assert_ne!(current_emulation(), blocked, "switched away from it");
		let now = now_secs();
		assert_eq!(FINGERPRINTS[blocked].weight(now), 0);
		for _ in 0..200 {
			build_client();
			assert_ne!(current_emulation(), blocked);
		}

		assert_eq!(FINGERPRINTS[blocked].weight(now + BLOCK_SECS + 1), SERVED);
		FINGERPRINTS[blocked].blocked_until.store(now - 1, Ordering::Relaxed);
		assert!((0..1000).any(|_| {
			build_client();
			current_emulation() == blocked
		}));
	}

	#[test]
	#[sealed_test]
	fn test_block_of_a_previous_emulation_is_ignored() {
		build_client();
		let previous = current_emulation();
		build_client();
		fingerprint_blocked(previous);
		assert_eq!(FINGERPRINTS[previous].weight(now_secs()), SERVED);
	}

	#[test]
	fn test_fingerprint_block_page_is_told_from_json_403s() {
		let html = Some(&b"text/html; charset=utf-8"[..]);
		let page = b"<!DOCTYPE html><html><body>You've been blocked by network security.</body></html>";
		assert!(is_fingerprint_block(403, html, page));
		// a private subreddit
		let private = br#"{"reason": "private", "message": "Forbidden", "error": 403}"#;
		assert!(!is_fingerprint_block(403, Some(b"application/json; charset=UTF-8"), private));
		assert!(!is_fingerprint_block(403, html, b"<html>Forbidden</html>"));
		assert!(!is_fingerprint_block(200, html, page));
	}

	#[test]
	fn test_emulation_tables() {
		let pairs = |table| flatten(table).into_iter().map(|f| (format!("{:?}", f.profile), format!("{:?}", f.platform), f.weight));
		let all: Vec<_> = pairs(EMULATIONS).collect();
		assert!(all.iter().all(|(profile, ..)| !profile.starts_with("OkHttp")));
		let unique: std::collections::HashSet<_> = all.iter().map(|(profile, platform, _)| (profile, platform)).collect();
		assert_eq!(unique.len(), all.len(), "duplicate pairs");
		for (profile, platform, weight) in pairs(TEST_EMULATIONS) {
			assert_eq!(weight, SERVED);
			assert!(
				all.contains(&(profile.clone(), platform.clone(), SERVED)),
				"{profile} on {platform} isn't SERVED in EMULATIONS"
			);
		}
	}

	/// What Reddit answers one fingerprint: token, listing and GraphQL query.
	async fn probe(profile: Profile, platform: Platform) -> (String, String, String) {
		let pause = || tokio::time::sleep(std::time::Duration::from_millis(300));
		let client = client_for(profile, platform);
		let headers = match crate::oauth::android_headers(&client).await {
			Ok(headers) => headers,
			Err(e) => return (format!("failed: {}", e.chars().take(60).collect::<String>()), "-".into(), "-".into()),
		};
		pause().await;

		let mut builder = client.get(format!("{REDDIT_URL_BASE}/r/rust/hot.json?raw_json=1&limit=1"));
		for (key, value) in &headers {
			builder = builder.header(key, value);
		}
		let json = match builder.send().await {
			Ok(res) => {
				let status = res.status().as_u16();
				let content_type = res.headers().get(wreq_header::CONTENT_TYPE).map(|v| v.as_bytes().to_vec());
				let body = res.bytes().await.unwrap_or_default();
				if is_fingerprint_block(status, content_type.as_deref(), &body) {
					"blocked".to_string()
				} else if serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|v| v["kind"] == "Listing") {
					"ok".to_string()
				} else {
					format!("{status}")
				}
			}
			Err(e) => format!("failed: {e}"),
		};
		pause().await;

		let body = serde_json::json!({
			"operationName": "SubredditInfoByName",
			"variables": { "subredditName": "rust", "filterGated": true, "includeDevvitData": false, "includeRecapFields": false, "includeWelcomePage": false },
			"extensions": { "persistedQuery": { "version": 1, "sha256Hash": crate::backends::gql::SUBREDDIT_INFO_HASH } },
		});
		let mut builder = client
			.post(crate::backends::gql::GQL_URL)
			.header("X-APOLLO-OPERATION-NAME", "SubredditInfoByName")
			.header("X-APOLLO-OPERATION-ID", crate::backends::gql::SUBREDDIT_INFO_HASH);
		for (key, value) in headers.iter().filter(|(key, _)| !key.eq_ignore_ascii_case("content-type")) {
			builder = builder.header(key, value);
		}
		let gql = match builder.json(&body).send().await {
			Ok(res) => {
				let status = res.status().as_u16();
				match res.json::<serde_json::Value>().await {
					Ok(v) if !v["data"]["subredditInfoByName"].is_null() => "ok".to_string(),
					_ => format!("{status}"),
				}
			}
			Err(e) => format!("failed: {e}"),
		};
		pause().await;
		("ok".into(), json, gql)
	}

	/// Fails when a fingerprint the tests use is blocked.
	#[test]
	#[ignore = "live: probes every fingerprint, run with --ignored"]
	fn test_probe_fingerprints() {
		use std::fmt::Write;
		let tested: Vec<(String, String)> = flatten(TEST_EMULATIONS).iter().map(|f| (format!("{:?}", f.profile), format!("{:?}", f.platform))).collect();
		let mut table = String::from("| profile | platform | weight | token | json | gql | tests |\n|---|---|---|---|---|---|---|\n");
		let mut broken = Vec::new();
		let mut surprises = Vec::new();
		block_on_shared(async {
			for fingerprint in flatten(EMULATIONS) {
				let (profile, platform) = (format!("{:?}", fingerprint.profile), format!("{:?}", fingerprint.platform));
				let (token, json, gql) = probe(fingerprint.profile, fingerprint.platform).await;
				let weight = if fingerprint.weight == SERVED { "served" } else { "refused" };
				let in_tests = tested.contains(&(profile.clone(), platform.clone()));
				let row = format!("| {profile} | {platform} | {weight} | {token} | {json} | {gql} | {} |", if in_tests { "yes" } else { "" });
				println!("{row}");
				writeln!(table, "{row}").unwrap();
				if in_tests && json != "ok" {
					broken.push(format!("{profile} on {platform}"));
				}
				// a failed token or request says nothing about the weight
				if (json == "ok" || json == "blocked") && (fingerprint.weight == SERVED) != (json == "ok") {
					surprises.push(format!("{profile} on {platform} ({weight}, json {json})"));
				}
			}
		});
		let mut summary = format!("## Fingerprints\n\n{table}\n");
		if !surprises.is_empty() {
			writeln!(summary, "Weight doesn't match the answer: {}\n", surprises.join(", ")).unwrap();
		}
		if !broken.is_empty() {
			writeln!(summary, "**Used by the tests but not served:** {}\n", broken.join(", ")).unwrap();
		}
		println!("{summary}");
		if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
			use std::io::Write as _;
			let mut file = std::fs::OpenOptions::new().append(true).create(true).open(path).unwrap();
			file.write_all(summary.as_bytes()).unwrap();
		}
		assert!(broken.is_empty(), "the tests use fingerprints Reddit blocks: {}", broken.join(", "));
	}

	#[test]
	#[sealed_test(env = [("REDLIB_DEFAULT_SUBSCRIPTIONS", "rust")])]
	fn test_default_subscriptions() {
		tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
			let subscriptions = get_setting("REDLIB_DEFAULT_SUBSCRIPTIONS");
			assert!(subscriptions.is_some());
		});
	}

	#[test]
	fn test_obfuscated_share_link() {
		crate::client::block_on_shared(async {
			let share_link = "/r/rust/s/kPgq8WNHRK".into();
			// Correct link without share parameters
			let canonical_link = "/r/rust/comments/18t5968/why_use_tuple_struct_over_standard_struct/kfbqlbc/".into();
			assert_eq!(canonical_path(share_link, 3).await, Ok(Some(canonical_link)));
		});
	}

	#[test]
	#[sealed_test]
	fn test_rate_limit_counter_decrements_one_unit() {
		OAUTH_RATELIMIT_REMAINING.store(50, Ordering::SeqCst);
		burn_rate_limit_unit();
		assert_eq!(OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst), 49);
	}

	#[test]
	#[sealed_test]
	fn test_rate_limit_counter_saturates_at_zero() {
		OAUTH_RATELIMIT_REMAINING.store(0, Ordering::SeqCst);
		for _ in 0..100 {
			burn_rate_limit_unit();
		}
		assert_eq!(OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst), 0);
	}

	#[test]
	#[sealed_test]
	fn test_rate_limit_burst_across_zero_arms_rollover_guard() {
		// json() triggers a token rollover when it reads `current_rate_limit < 10`.
		// A burst crossing zero must leave the counter below that threshold.
		OAUTH_RATELIMIT_REMAINING.store(5, Ordering::SeqCst);
		for _ in 0..10 {
			burn_rate_limit_unit();
		}
		assert!(OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst) < 10);
	}

	#[test]
	#[sealed_test]
	fn test_rate_limit_concurrent_bursts_never_wrap() {
		OAUTH_RATELIMIT_REMAINING.store(2, Ordering::SeqCst);
		let handles: Vec<_> = (0..8)
			.map(|_| {
				std::thread::spawn(|| {
					let mut max_seen = 0u16;
					for _ in 0..500 {
						burn_rate_limit_unit();
						max_seen = max_seen.max(OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst));
					}
					max_seen
				})
			})
			.collect();
		let max_seen = handles.into_iter().map(|h| h.join().unwrap()).max().unwrap();
		assert!(max_seen <= 2, "counter wrapped: observed {max_seen}");
		assert_eq!(OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst), 0);
	}
}
