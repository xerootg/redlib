#![allow(dead_code)]
#![allow(clippy::cmp_owned)]

use brotli::enc::{BrotliCompress, BrotliEncoderParams};
use cached::proc_macro::cached;
use cookie::Cookie;
use futures_lite::{future::Boxed, Future, FutureExt};
use http_body::Body as _;
use hyper::{body::Incoming, header, service::service_fn, HeaderMap, Method, Request, Response};
use hyper_util::{
	rt::{TokioExecutor, TokioIo, TokioTimer},
	server::{conn::auto, graceful::GracefulShutdown},
};
use libflate::gzip;
use route_recognizer::{Params, Router};
use std::{
	cmp::Ordering,
	collections::hash_map::RandomState,
	fmt::Display,
	hash::BuildHasher,
	io,
	pin::Pin,
	result::Result,
	str::{from_utf8, Split},
	string::ToString,
	sync::LazyLock,
};
use time::OffsetDateTime;

use crate::{body::Body, config, dbg_msg, oidc};

const BANNED_USER_AGENTS: &[&str] = &[
	"AI2Bot",
	"Ai2Bot-Dolma",
	"Amazonbot",
	"Andibot",
	"Applebot",
	"Applebot-Extended",
	"Awario",
	"Brightbot 1.0",
	"Bytespider",
	"CCBot",
	"ChatGPT-User",
	"Claude-SearchBot",
	"Claude-User",
	"Claude-Web",
	"ClaudeBot",
	"Cotoyogi",
	"Crawlspace",
	"Datenbank Crawler",
	"Devin",
	"Diffbot",
	"DuckAssistBot",
	"Echobot Bot",
	"EchoboxBot",
	"FacebookBot",
	"Factset_spyderbot",
	"FirecrawlAgent",
	"FriendlyCrawler",
	"GPTBot",
	"Google-CloudVertexBot",
	"Google-Extended",
	"GoogleOther",
	"GoogleOther-Image",
	"GoogleOther-Video",
	"ICC-Crawler",
	"ISSCyberRiskCrawler",
	"ImagesiftBot",
	"Kangaroo Bot",
	"Meta-ExternalAgent",
	"Meta-ExternalFetcher",
	"MistralAI-User",
	"MistralAI-User/1.0",
	"MyCentralAIScraperBot",
	"NovaAct",
	"OAI-SearchBot",
	"Operator",
	"PanguBot",
	"Panscient",
	"Perplexity-User",
	"PerplexityBot",
	"PetalBot",
	"PhindBot",
	"Poseidon Research Crawler",
	"QualifiedBot",
	"QuillBot",
	"SBIntuitionsBot",
	"Scrapy",
	"SemrushBot",
	"SemrushBot-BA",
	"SemrushBot-CT",
	"SemrushBot-OCOB",
	"SemrushBot-SI",
	"SemrushBot-SWA",
	"Sidetrade indexer bot",
	"TikTokSpider",
	"Timpibot",
	"VelenPublicWebCrawler",
	"WARDBot",
	"Webzio-Extended",
	"YandexAdditional",
	"YandexAdditionalBot",
	"YouBot",
	"aiHitBot",
	"anthropic-ai",
	"bedrockbot",
	"cohere-ai",
	"cohere-training-data-crawler",
	"facebookexternalhit",
	"iaskspider/2.0",
	"img2dataset",
	"meta-externalagent",
	"meta-externalfetcher",
	"omgili",
	"omgilibot",
	"panscient.com",
	"quillbot.com",
	"wpbot",
];

type BoxResponse = Pin<Box<dyn Future<Output = Result<Response<Body>, String>> + Send>>;

/// Compressors for the response Body, in ascending order of preference.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum CompressionType {
	Passthrough,
	Gzip,
	Brotli,
}

/// All browsers support gzip, so if we are given `Accept-Encoding: *`, deliver
/// gzipped-content.
///
/// Brotli would be nice universally, but Safari (iOS, iPhone, macOS) reportedly
/// doesn't support it yet.
const DEFAULT_COMPRESSOR: CompressionType = CompressionType::Gzip;

/// Longest Accept-Encoding header we will parse. Real clients send well under
/// 100 bytes.
const MAX_ACCEPT_ENCODING_LEN: usize = 256;

impl CompressionType {
	/// Returns a `CompressionType` given a content coding
	/// in [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.4)
	/// format.
	fn parse(s: &str) -> Option<Self> {
		let c = match s {
			// Compressors we support.
			"gzip" => Self::Gzip,
			"br" => Self::Brotli,

			// The wildcard means that we can choose whatever
			// compression we prefer. In this case, use the
			// default.
			"*" => DEFAULT_COMPRESSOR,

			// Compressor not supported.
			_ => return None,
		};

		Some(c)
	}
}

impl Display for CompressionType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Gzip => write!(f, "gzip"),
			Self::Brotli => write!(f, "br"),
			Self::Passthrough => Ok(()),
		}
	}
}

pub struct Route<'a> {
	router: &'a mut Router<fn(Request<Body>) -> BoxResponse>,
	path: String,
}

pub struct Server {
	pub default_headers: HeaderMap,
	router: Router<fn(Request<Body>) -> BoxResponse>,
}

#[macro_export]
macro_rules! headers(
	{ $($key:expr => $value:expr),+ } => {
		{
			let mut m = hyper::HeaderMap::new();
			$(
				if let Ok(val) = hyper::header::HeaderValue::from_str($value) {
					m.insert($key, val);
				}
			)+
			m
		}
	 };
);

pub trait RequestExt {
	fn params(&self) -> Params;
	fn param(&self, name: &str) -> Option<String>;
	fn set_params(&mut self, params: Params) -> Option<Params>;
	fn cookies(&self) -> Vec<Cookie<'_>>;
	fn cookie(&self, name: &str) -> Option<Cookie<'_>>;
}

pub trait ResponseExt {
	fn cookies(&self) -> Vec<Cookie<'_>>;
	fn insert_cookie(&mut self, cookie: Cookie<'_>);
	fn remove_cookie(&mut self, name: String);
}

impl RequestExt for Request<Body> {
	fn params(&self) -> Params {
		self.extensions().get::<Params>().unwrap_or(&Params::new()).clone()
		// self.extensions()
		// 	.get::<RequestMeta>()
		// 	.and_then(|meta| meta.route_params())
		// 	.expect("Routerify: No RouteParams added while processing request")
	}

	fn param(&self, name: &str) -> Option<String> {
		self.params().find(name).map(std::borrow::ToOwned::to_owned)
	}

	fn set_params(&mut self, params: Params) -> Option<Params> {
		self.extensions_mut().insert(params)
	}

	fn cookies(&self) -> Vec<Cookie<'_>> {
		self.headers().get("Cookie").map_or(Vec::new(), |header| {
			header
				.to_str()
				.unwrap_or_default()
				.split("; ")
				.map(|cookie| Cookie::parse(cookie).unwrap_or_else(|_| Cookie::from("")))
				.collect()
		})
	}

	fn cookie(&self, name: &str) -> Option<Cookie<'_>> {
		self.cookies().into_iter().find(|c| c.name() == name)
	}
}

impl ResponseExt for Response<Body> {
	fn cookies(&self) -> Vec<Cookie<'_>> {
		self.headers().get("Cookie").map_or(Vec::new(), |header| {
			header
				.to_str()
				.unwrap_or_default()
				.split("; ")
				.map(|cookie| Cookie::parse(cookie).unwrap_or_else(|_| Cookie::from("")))
				.collect()
		})
	}

	fn insert_cookie(&mut self, cookie: Cookie<'_>) {
		if let Ok(val) = header::HeaderValue::from_str(&cookie.to_string()) {
			self.headers_mut().append("Set-Cookie", val);
		}
	}

	fn remove_cookie(&mut self, name: String) {
		let removal_cookie = Cookie::build(name).path("/").http_only(true).expires(OffsetDateTime::now_utc());
		if let Ok(val) = header::HeaderValue::from_str(&removal_cookie.to_string()) {
			self.headers_mut().append("Set-Cookie", val);
		}
	}
}

impl Route<'_> {
	fn method(&mut self, method: &Method, dest: fn(Request<Body>) -> BoxResponse) -> &mut Self {
		self.router.add(&format!("/{}{}", method.as_str(), self.path), dest);
		self
	}

	/// Add an endpoint for `GET` requests
	pub fn get(&mut self, dest: fn(Request<Body>) -> BoxResponse) -> &mut Self {
		self.method(&Method::GET, dest)
	}

	/// Add an endpoint for `POST` requests
	pub fn post(&mut self, dest: fn(Request<Body>) -> BoxResponse) -> &mut Self {
		self.method(&Method::POST, dest)
	}
}

impl Default for Server {
	fn default() -> Self {
		Self::new()
	}
}

impl Server {
	pub fn new() -> Self {
		Self {
			default_headers: HeaderMap::new(),
			router: Router::new(),
		}
	}

	pub fn at(&mut self, path: &str) -> Route<'_> {
		Route {
			path: path.to_owned(),
			router: &mut self.router,
		}
	}

	pub fn listen(self, addr: &str) -> Boxed<Result<(), std::io::Error>> {
		// Build SocketAddr from provided address
		let address: std::net::SocketAddr = addr.parse().unwrap_or_else(|_| panic!("Cannot parse {addr} as address (example format: 0.0.0.0:8080)"));

		let router = std::sync::Arc::new(self.router);
		let default_headers = self.default_headers;

		// Called once per request with the connection's real TCP peer, which,
		// unlike any header, cannot be forged. It anchors the OIDC bypass
		// allowlist -- see `oidc::resolve_client_ip`.
		let service = move |req: Request<Incoming>, peer: std::net::IpAddr| {
			let req = req.map(Body::new);
			let req_headers = req.headers().clone();
			let def_headers = default_headers.clone();

			// Catch robots.txt-disrespecful bots who still identify themselves
			// Typically justified as "human triggered" actions.
			if match config::get_setting("REDLIB_ROBOTS_DISABLE_INDEXING") {
				Some(val) => val == "on",
				None => false,
			} {
				if let Some(user_agent) = req_headers.get("user-agent") {
					if let Ok(user_agent_str) = user_agent.to_str() {
						for banned in BANNED_USER_AGENTS {
							if user_agent_str.contains(banned) {
								return new_boilerplate(def_headers, req_headers, 403, Body::from("Forbidden")).boxed();
							}
						}
					}
				}
			}

			let path = normalize_path(req.uri().path());

			// Enforce OIDC before anything else routes. Returns None when the
			// request is allowed through -- because auth is off, the client is
			// in a bypass CIDR, it already holds a valid session, or it is
			// hitting the /oidc/ endpoints.
			if let Some(mut res) = oidc::gate(peer, &path, req.uri().query(), &req_headers) {
				res.headers_mut().extend(def_headers);
				return async move { Ok(res) }.boxed();
			}

			// Replace HEAD with GET for routing
			let (method, is_head) = match req.method() {
				&Method::HEAD => (&Method::GET, true),
				method => (method, false),
			};

			// Match the visited path with an added route
			match router.recognize(&format!("/{}{}", method.as_str(), path)) {
				// If a route was configured for this path
				Ok(found) => {
					let mut parammed = req;
					parammed.set_params(found.params().clone());

					// Run the route's function
					let func = (found.handler().to_owned().to_owned())(parammed);
					async move {
						match func.await {
							Ok(mut res) => {
								res.headers_mut().extend(def_headers);
								if is_head {
									*res.body_mut() = Body::empty();
								} else {
									let _ = compress_response(&req_headers, &mut res).await;
								}

								Ok(res)
							}
							Err(msg) => new_boilerplate(def_headers, req_headers, 500, if is_head { Body::empty() } else { Body::from(msg) }).await,
						}
					}
					.boxed()
				}
				// If there was a routing error
				Err(e) => new_boilerplate(def_headers, req_headers, 404, if is_head { Body::empty() } else { e.into() }).boxed(),
			}
		};

		async move {
			let listener = tokio::net::TcpListener::bind(address).await?;
			let mut builder = auto::Builder::new(TokioExecutor::new());
			// Required by http1's default header read timeout.
			builder.http1().timer(TokioTimer::new());
			let graceful = GracefulShutdown::new();
			let mut shutdown = std::pin::pin!(shutdown_signal());

			loop {
				tokio::select! {
					conn = listener.accept() => {
						let (stream, remote) = match conn {
							Ok(conn) => conn,
							Err(e) => {
								dbg_msg!(e);
								continue;
							}
						};
						let handle = service.clone();
						let peer = remote.ip();
						let service = service_fn(move |req| handle(req, peer));
						let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service).into_owned();
						let conn = graceful.watch(conn);
						tokio::spawn(async move {
							if let Err(e) = conn.await {
								dbg_msg!(e);
							}
						});
					}
					() = &mut shutdown => break,
				}
			}

			graceful.shutdown().await;
			Ok(())
		}
		.boxed()
	}
}

/// The path the gate and the router both see: doubled slashes collapsed,
/// encoded slashes decoded and trailing slashes removed.
///
/// Repeated until nothing changes, because one round can leave work for the
/// next: `/%2Fmcp` becomes `//mcp`. The gate compares the result with exact
/// paths such as `/mcp`, so it has to be the form the router sees too.
/// Every round that changes anything makes the path shorter, so this ends.
fn normalize_path(raw: &str) -> String {
	let mut path = raw.to_string();
	loop {
		let before = path.len();

		// Remove double slashes and decode encoded slashes
		path = path.replace("//", "/").replace("%2F", "/");

		// Remove trailing slashes
		if path != "/" && path.ends_with('/') {
			path.pop();
		}

		// Reddit permalinks end in a slash, so feed URLs are often written `/r/rust/top/.rss`
		if path != "/.rss" && path.ends_with("/.rss") {
			path.replace_range(path.len() - "/.rss".len().., ".rss");
		}

		if path.len() == before {
			return path;
		}
	}
}

async fn shutdown_signal() {
	#[cfg(windows)]
	// Wait for the CTRL+C signal
	tokio::signal::ctrl_c().await.expect("Failed to install CTRL+C signal handler");

	#[cfg(unix)]
	{
		// Wait for CTRL+C or SIGTERM signals
		let mut signal_terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("Failed to install SIGTERM signal handler");
		tokio::select! {
			_ = tokio::signal::ctrl_c() => (),
			_ = signal_terminate.recv() => ()
		}
	}
}

/// Create a boilerplate Response for error conditions. This response will be
/// compressed if requested by client.
async fn new_boilerplate(
	default_headers: HeaderMap<header::HeaderValue>,
	req_headers: HeaderMap<header::HeaderValue>,
	status: u16,
	body: Body,
) -> Result<Response<Body>, String> {
	// The bodies are plain error messages.
	match Response::builder().status(status).header(header::CONTENT_TYPE, "text/plain; charset=utf-8").body(body) {
		Ok(mut res) => {
			let _ = compress_response(&req_headers, &mut res).await;

			res.headers_mut().extend(default_headers.clone());
			Ok(res)
		}
		Err(msg) => Err(msg.to_string()),
	}
}

/// Determines the desired compressor based on the Accept-Encoding header.
///
/// This function will honor the [q-value](https://developer.mozilla.org/en-US/docs/Glossary/Quality_values)
///  for each compressor. The q-value is an optional parameter, a decimal value
/// on \[0..1\], to order the compressors by preference. An Accept-Encoding value
/// with no q-values is also accepted.
///
/// Here are [examples](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding#examples)
/// of valid Accept-Encoding headers.
///
/// ```http
/// Accept-Encoding: gzip
/// Accept-Encoding: gzip, compress, br
/// Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1
/// ```
///
/// The result is deliberately not memoised: the header is attacker-controlled,
/// so a cache keyed on it grows without bound, while parsing it is cheap.
/// Headers longer than [`MAX_ACCEPT_ENCODING_LEN`] are not compressed for.
fn determine_compressor(accept_encoding: String) -> Option<CompressionType> {
	if accept_encoding.is_empty() || accept_encoding.len() > MAX_ACCEPT_ENCODING_LEN {
		return None;
	};

	// Keep track of the compressor candidate based on both the client's
	// preference and our own. Concrete examples:
	//
	// 1. "Accept-Encoding: gzip, br" => assuming we like brotli more than
	//    gzip, and the browser supports brotli, we choose brotli
	//
	// 2. "Accept-Encoding: gzip;q=0.8, br;q=0.3" => the client has stated a
	//    preference for gzip over brotli, so we choose gzip
	//
	// To do this, we need to define a struct which contains the requested
	// requested compressor (abstracted as a CompressionType enum) and the
	// q-value. If no q-value is defined for the compressor, we assume one of
	// 1.0. We first compare compressor candidates by comparing q-values, and
	// then CompressionTypes. We keep track of whatever is the greatest per our
	// ordering.

	struct CompressorCandidate {
		alg: CompressionType,
		q: f64,
	}

	impl Ord for CompressorCandidate {
		fn cmp(&self, other: &Self) -> Ordering {
			// Compare q-values. Break ties with the
			// CompressionType values.

			match self.q.total_cmp(&other.q) {
				Ordering::Equal => self.alg.cmp(&other.alg),
				ord => ord,
			}
		}
	}

	impl PartialOrd for CompressorCandidate {
		fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
			Some(self.cmp(other))
		}
	}

	impl PartialEq for CompressorCandidate {
		fn eq(&self, other: &Self) -> bool {
			(self.q == other.q) && (self.alg == other.alg)
		}
	}

	impl Eq for CompressorCandidate {}

	// This is the current candidate.
	//
	// Assmume no candidate so far. We do this by assigning the sentinel value
	// of negative infinity to the q-value. If this value is negative infinity,
	// that means there was no viable compressor candidate.
	let mut cur_candidate = CompressorCandidate {
		alg: CompressionType::Passthrough,
		q: f64::NEG_INFINITY,
	};

	// This loop reads the requested compressors and keeps track of whichever
	// one has the highest priority per our heuristic.
	for val in accept_encoding.split(',') {
		let mut q: f64 = 1.0;

		// The compressor and q-value (if the latter is defined)
		// will be delimited by semicolons.
		let mut spl: Split<'_, char> = val.split(';');

		// Get the compressor. For example, in
		//   gzip;q=0.8
		// this grabs "gzip" in the string. It
		// will further validate the compressor against the
		// list of those we support. If it is not supported,
		// we move onto the next one.
		let compressor: CompressionType = match spl.next() {
			// CompressionType::parse will return the appropriate enum given
			// a string. For example, it will return CompressionType::Gzip
			// when given "gzip".
			Some(s) => match CompressionType::parse(s.trim()) {
				Some(candidate) => candidate,

				// We don't support the requested compression algorithm.
				None => continue,
			},

			// We should never get here, but I'm paranoid.
			None => continue,
		};

		// Get the q-value. This might not be defined, in which case assume
		// 1.0.
		if let Some(s) = spl.next() {
			if !(s.len() > 2 && s.starts_with("q=")) {
				// If the q-value is malformed, the header is malformed, so
				// abort.
				return None;
			}

			match s[2..].parse::<f64>() {
				Ok(val) => {
					if (0.0..=1.0).contains(&val) {
						q = val;
					} else {
						// If the value is outside [0..1], header is malformed.
						// Abort.
						return None;
					};
				}
				Err(_) => {
					// If this isn't a f64, then assume a malformed header
					// value and abort.
					return None;
				}
			}
		};

		// If new_candidate > cur_candidate, make new_candidate the new
		// cur_candidate. But do this safely! It is very possible that
		// someone gave us the string "NAN", which (&str).parse::<f64>
		// will happily translate to f64::NAN.
		let new_candidate = CompressorCandidate { alg: compressor, q };
		if let Some(ord) = new_candidate.partial_cmp(&cur_candidate) {
			if ord == Ordering::Greater {
				cur_candidate = new_candidate;
			}
		};
	}

	if cur_candidate.q == f64::NEG_INFINITY {
		None
	} else {
		Some(cur_candidate.alg)
	}
}

/// Compress the response body, if possible or desirable. The Body will be
/// compressed in place, and a new header Content-Encoding will be set
/// indicating the compression algorithm.
///
/// This function deems Body eligible compression if and only if the following
/// conditions are met:
///
/// 1. the HTTP client requests a compression encoding in the Content-Encoding
///    header (hence the need for the `req_headers`);
///
/// 2. the content encoding corresponds to a compression algorithm we support;
///
/// 3. the Media type in the Content-Type response header is text with any
///    subtype (e.g. text/plain) or application/json.
///
/// `compress_response` returns Ok on successful compression, or if not all three
/// conditions above are met. It returns Err if there was a problem decoding
/// any header in either `req_headers` or res, but res will remain intact.
///
/// This function logs errors to stderr, but only in debug mode. No information
/// is logged in release builds.
async fn compress_response(req_headers: &HeaderMap<header::HeaderValue>, res: &mut Response<Body>) -> Result<(), String> {
	// Check if the data is eligible for compression.
	if let Some(hdr) = res.headers().get(header::CONTENT_TYPE) {
		match from_utf8(hdr.as_bytes()) {
			Ok(val) => {
				let s = val.to_string();

				// TODO: better determination of what is eligible for compression
				if !(s.starts_with("text/") || s.starts_with("application/json")) {
					return Ok(());
				};
			}
			Err(e) => {
				dbg_msg!(e);
				return Err(e.to_string());
			}
		};
	} else {
		// Response declares no Content-Type. Assume for simplicity that it
		// cannot be compressed.
		return Ok(());
	};

	// Don't bother if the size of the size of the response body will fit
	// within an IP frame (less the bytes that make up the TCP/IP and HTTP
	// headers).
	if res.body().size_hint().lower() < 1452 {
		return Ok(());
	};

	// Check to see which compressor is requested, and if we can use it.
	let accept_encoding: String = match req_headers.get(header::ACCEPT_ENCODING) {
		None => return Ok(()), // Client requested no compression.

		Some(hdr) => match String::from_utf8(hdr.as_bytes().into()) {
			Ok(val) => val,

			#[cfg(debug_assertions)]
			Err(e) => {
				dbg_msg!(e);
				return Ok(());
			}

			#[cfg(not(debug_assertions))]
			Err(_) => return Ok(()),
		},
	};

	let compressor: CompressionType = match determine_compressor(accept_encoding) {
		Some(c) => c,
		None => return Ok(()),
	};

	// Get the body from the response.
	let body_bytes: Vec<u8> = match std::mem::take(res.body_mut()).collect_bytes().await {
		Ok(b) => b.to_vec(),
		Err(e) => {
			dbg_msg!(e);
			return Err(e.to_string());
		}
	};

	// Compress! This is CPU-bound and takes long enough on a big page to stall
	// every other request on this worker (including /healthz), so run it on the
	// blocking pool.
	let compressed = tokio::task::spawn_blocking(move || compress_body(compressor, body_bytes))
		.await
		.map_err(|e| e.to_string())
		.and_then(|result| result);
	match compressed {
		Ok(compressed) => {
			// We get here iff the compression was successful. Replace the body
			// with the compressed payload, and add the appropriate
			// Content-Encoding header in the response. Remove any precomputed
			// Content-Length, as it will no longer be valid.
			let headers = res.headers_mut();
			headers.insert(header::CONTENT_ENCODING, compressor.to_string().parse().unwrap());
			headers.remove(header::CONTENT_LENGTH);

			*(res.body_mut()) = Body::from(compressed);
		}

		Err(e) => return Err(e),
	}

	Ok(())
}

/// Keyed digest of a response body, used as the `compress_body` cache key.
fn body_digest(body: &[u8]) -> u64 {
	static HASHER: LazyLock<RandomState> = LazyLock::new(RandomState::new);
	HASHER.hash_one(body)
}

/// Compresses a `Vec<u8>` given a [`CompressionType`].
///
/// This is a helper function for [`compress_response`] and should not be
/// called directly.

// I've chosen a TTL of 600 (== 10 minutes) since compression is
// computationally expensive and we don't want to be doing it often. This is
// larger than backends::json's TTL, but that's okay, because if backends::json
// returns a new serde_json::Value, body_bytes changes, so this function will
// execute again.
//
// The cache key is a digest of the body, not the body itself, so an entry
// doesn't keep a second copy of the page alive. The digest is SipHash with
// per-process random keys, so a client can't forge a collision to get another
// page's compressed bytes served.
#[cached(
	max_size = 100,
	ttl_secs = 600,
	key = "(CompressionType, usize, u64)",
	convert = r#"{ (compressor, body_bytes.len(), body_digest(&body_bytes)) }"#
)]
fn compress_body(compressor: CompressionType, body_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
	// io::Cursor implements io::Read, required for our encoders.
	let mut reader = io::Cursor::new(body_bytes);

	let compressed: Vec<u8> = match compressor {
		CompressionType::Gzip => {
			let mut gz: gzip::Encoder<Vec<u8>> = match gzip::Encoder::new(Vec::new()) {
				Ok(gz) => gz,
				Err(e) => {
					dbg_msg!(e);
					return Err(e.to_string());
				}
			};

			match io::copy(&mut reader, &mut gz) {
				Ok(_) => match gz.finish().into_result() {
					Ok(compressed) => compressed,
					Err(e) => {
						dbg_msg!(e);
						return Err(e.to_string());
					}
				},
				Err(e) => {
					dbg_msg!(e);
					return Err(e.to_string());
				}
			}
		}

		CompressionType::Brotli => {
			// The library default is quality 11, which took 3.8 s for a 426 KB
			// thread page. Quality 5 is a common choice for dynamic content; on
			// the pages we measured it made the output about 15% larger.
			let brotli_params = BrotliEncoderParams {
				quality: 5,
				..BrotliEncoderParams::default()
			};

			let mut compressed = Vec::<u8>::new();
			match BrotliCompress(&mut reader, &mut compressed, &brotli_params) {
				Ok(_) => compressed,
				Err(e) => {
					dbg_msg!(e);
					return Err(e.to_string());
				}
			}
		}

		// This arm is for any requested compressor for which we don't yet
		// have an implementation.
		CompressionType::Passthrough => {
			let msg = "unsupported compressor".to_string();
			return Err(msg);
		}
	};

	Ok(compressed)
}

/// Regression tests for the compression denial of service (audit findings 2,
/// 6 and the compress_body half of 17).
#[cfg(test)]
mod compress_dos_tests {
	use super::*;
	use lipsum::lipsum;
	use std::sync::{Arc, Mutex};

	/// Finding 2: `determine_compressor` was memoised on the raw header, so every
	/// distinct huge Accept-Encoding stayed in memory forever. No browser sends
	/// more than a few dozen bytes, so an oversized header is simply not
	/// compressed for (and must not be remembered).
	#[test]
	fn oversized_accept_encoding_is_ignored() {
		for i in 0..50 {
			let header = format!("gzip, x{i}{}", "a".repeat(300_000));
			assert_eq!(determine_compressor(header), None);
		}
		// Ordinary headers still work.
		assert_eq!(determine_compressor("gzip, deflate, br, zstd".to_string()), Some(CompressionType::Brotli));
	}

	/// Finding 17: the `compress_body` cache used the whole body as its key, so
	/// each entry held the page twice. The key must be a small digest.
	#[test]
	fn compress_body_cache_key_does_not_hold_the_body() {
		let body = lipsum(40_000).into_bytes();
		assert!(body.len() > 100_000);
		compress_body(CompressionType::Gzip, body).unwrap();

		let keys = COMPRESS_BODY.read().key_order();
		assert!(!keys.is_empty());
		for key in keys {
			let shown = format!("{key:?}");
			assert!(shown.len() < 256, "cache key is {} bytes long", shown.len());
		}
	}

	/// Finding 6: Brotli quality 11 ran on the async worker for seconds. On a
	/// single-threaded runtime, a task that is already queued must get to run
	/// while a large body is being compressed, so compression has to be moved
	/// off the runtime thread. This is ordering-based, not timing-based.
	#[tokio::test(flavor = "current_thread")]
	async fn compressing_a_large_page_does_not_block_the_runtime() {
		let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

		let mut req_headers = HeaderMap::new();
		req_headers.insert(header::ACCEPT_ENCODING, header::HeaderValue::from_static("br"));
		let mut res = Response::builder()
			.status(200)
			.header(header::CONTENT_TYPE, "text/html")
			.body(Body::from(lipsum(20_000)))
			.unwrap();

		let compress_order = order.clone();
		let compress = tokio::spawn(async move {
			compress_response(&req_headers, &mut res).await.unwrap();
			compress_order.lock().unwrap().push("compressed");
			res
		});
		let other_order = order.clone();
		let other = tokio::spawn(async move {
			other_order.lock().unwrap().push("other task ran");
		});

		let res = compress.await.unwrap();
		other.await.unwrap();

		assert_eq!(res.headers().get(header::CONTENT_ENCODING).unwrap(), "br");
		assert_eq!(*order.lock().unwrap(), vec!["other task ran", "compressed"]);
	}
}

#[cfg(test)]
mod boilerplate_tests {
	use super::*;

	#[test]
	fn test_error_boilerplate_is_declared_plain_text() {
		for status in [403, 404, 500] {
			let res = futures_lite::future::block_on(new_boilerplate(HeaderMap::new(), HeaderMap::new(), status, Body::from("<script>alert(1)</script>"))).unwrap();
			assert_eq!(res.status().as_u16(), status);
			assert_eq!(res.headers().get(header::CONTENT_TYPE).map(|v| v.to_str().unwrap()), Some("text/plain; charset=utf-8"));
		}
	}
}

#[cfg(test)]
mod path_normalization_tests {
	use super::*;
	use route_recognizer::Router as RouteRecognizer;

	/// Spellings of `/mcp` that only collapse to it after more than one round
	/// of removing doubled slashes, decoding `%2F` and trimming slashes.
	const MCP_SPELLINGS: [&str; 9] = [
		"/%2Fmcp",
		"//%2Fmcp",
		"/%2F/mcp",
		"/%2F%2Fmcp",
		"///mcp",
		"/mcp%2F%2F",
		"/mcp///",
		"/mcp/%2F",
		"/%2F%2F%2Fmcp%2F%2F%2F",
	];

	// Audit info item: path normalisation is single-pass (server.rs:337-347).
	// The OIDC gate scopes the MCP bearer token to exactly `/mcp` on the
	// normalised path, so the gate and the router must see one stable form.
	#[test]
	fn normalising_a_path_twice_changes_nothing() {
		for raw in MCP_SPELLINGS
			.into_iter()
			.chain(["/", "//", "/%2F", "/r/rust//", "/r/rust%2F%2F", "/a/%2F/b", "/a/.rss", "/a//.rss", "/a%2F.rss%2F", "/.rss/"])
		{
			let once = normalize_path(raw);
			assert_eq!(normalize_path(&once), once, "{raw:?} normalised to {once:?}, which normalises again");
		}
	}

	#[test]
	fn every_spelling_of_mcp_normalises_to_mcp() {
		for raw in MCP_SPELLINGS {
			assert_eq!(normalize_path(raw), "/mcp", "{raw:?}");
		}
	}

	#[test]
	fn ordinary_paths_are_unchanged() {
		for (raw, want) in [
			("/", "/"),
			("/r/rust", "/r/rust"),
			("/r/rust/", "/r/rust"),
			("/r//rust", "/r/rust"),
			("/r%2Frust", "/r/rust"),
			("/r/rust/top/.rss", "/r/rust/top.rss"),
			("/mcp/other", "/mcp/other"),
			("/mcpx", "/mcpx"),
		] {
			assert_eq!(normalize_path(raw), want, "{raw:?}");
		}
	}

	// The reverse of the above: the router must not be more generous than the
	// gate. A path the gate does not see as `/mcp` must not route to it.
	#[test]
	fn the_router_does_not_read_unnormalised_slashes_as_mcp() {
		let mut router = RouteRecognizer::new();
		router.add("/GET/mcp", ());
		assert!(router.recognize("/GET/mcp").is_ok());
		for raw in ["//mcp", "/mcp/", "///mcp"] {
			assert!(router.recognize(&format!("/GET{raw}")).is_err(), "{raw}");
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use brotli::Decompressor as BrotliDecompressor;
	use futures_lite::future::block_on;
	use lipsum::lipsum;
	use std::{boxed::Box, io};

	#[test]
	fn test_determine_compressor() {
		// Single compressor given.
		assert_eq!(determine_compressor("unsupported".to_string()), None);
		assert_eq!(determine_compressor("gzip".to_string()), Some(CompressionType::Gzip));
		assert_eq!(determine_compressor("*".to_string()), Some(DEFAULT_COMPRESSOR));

		// Multiple compressors.
		assert_eq!(determine_compressor("gzip, br".to_string()), Some(CompressionType::Brotli));
		assert_eq!(determine_compressor("gzip;q=0.8, br;q=0.3".to_string()), Some(CompressionType::Gzip));
		assert_eq!(determine_compressor("br, gzip".to_string()), Some(CompressionType::Brotli));
		assert_eq!(determine_compressor("br;q=0.3, gzip;q=0.4".to_string()), Some(CompressionType::Gzip));

		// Invalid q-values.
		assert_eq!(determine_compressor("gzip;q=NAN".to_string()), None);
	}

	#[test]
	fn test_compress_response() {
		// compress_response runs the compressor on tokio's blocking pool, so a
		// runtime has to be entered even though the future is driven by block_on.
		let rt = tokio::runtime::Runtime::new().unwrap();
		let _guard = rt.enter();

		// This macro generates an Accept-Encoding header value given any number of
		// compressors.
		macro_rules! ae_gen {
			($x:expr) => {
				$x.to_string().as_str()
			};

			($x:expr, $($y:expr),+) => {
				format!("{}, {}", $x.to_string(), ae_gen!($($y),+)).as_str()
			};
		}

		for accept_encoding in [
			"*",
			ae_gen!(CompressionType::Gzip),
			ae_gen!(CompressionType::Brotli, CompressionType::Gzip),
			ae_gen!(CompressionType::Brotli),
		] {
			// Determine what the expected encoding should be based on both the
			// specific encodings we accept.
			let expected_encoding: CompressionType = match determine_compressor(accept_encoding.to_string()) {
				Some(s) => s,
				None => panic!("determine_compressor(accept_encoding.to_string()) => None"),
			};

			// Build headers with our Accept-Encoding.
			let mut req_headers = HeaderMap::new();
			req_headers.insert(header::ACCEPT_ENCODING, header::HeaderValue::from_str(accept_encoding).unwrap());

			// Build test response.
			let lorem_ipsum: String = lipsum(10000);
			let expected_lorem_ipsum = Vec::<u8>::from(lorem_ipsum.as_str());
			let mut res = Response::builder()
				.status(200)
				.header(header::CONTENT_TYPE, "text/plain")
				.body(Body::from(lorem_ipsum))
				.unwrap();

			// Perform the compression.
			if let Err(e) = block_on(compress_response(&req_headers, &mut res)) {
				panic!("compress_response(&req_headers, &mut res) => Err(\"{e}\")");
			};

			// If the content was compressed, we expect the Content-Encoding
			// header to be modified.
			assert_eq!(
				res
					.headers()
					.get(header::CONTENT_ENCODING)
					.unwrap_or_else(|| panic!("missing content-encoding header"))
					.to_str()
					.unwrap_or_else(|_| panic!("failed to convert Content-Encoding header::HeaderValue to String")),
				expected_encoding.to_string()
			);

			// Decompress body and make sure it's equal to what we started
			// with.
			//
			// In the case of no compression, just make sure the "new" body in
			// the Response is the same as what with which we start.
			let body_vec = match block_on(std::mem::take(res.body_mut()).collect_bytes()) {
				Ok(b) => b.to_vec(),
				Err(e) => panic!("{e}"),
			};

			if expected_encoding == CompressionType::Passthrough {
				assert!(body_vec.eq(&expected_lorem_ipsum));
				continue;
			}

			// This provides an io::Read for the underlying body.
			let mut body_cursor: io::Cursor<Vec<u8>> = io::Cursor::new(body_vec);

			// Match the appropriate decompresor for the given
			// expected_encoding.
			let mut decoder: Box<dyn io::Read> = match expected_encoding {
				CompressionType::Gzip => match gzip::Decoder::new(&mut body_cursor) {
					Ok(dgz) => Box::new(dgz),
					Err(e) => panic!("{e}"),
				},

				CompressionType::Brotli => Box::new(BrotliDecompressor::new(body_cursor, expected_lorem_ipsum.len())),

				_ => panic!("no decompressor for {expected_encoding}"),
			};

			let mut decompressed = Vec::<u8>::new();
			if let Err(e) = io::copy(&mut decoder, &mut decompressed) {
				panic!("{e}");
			};

			assert!(decompressed.eq(&expected_lorem_ipsum));
		}
	}
}
