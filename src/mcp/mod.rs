//! Model Context Protocol server exposing Reddit to AI agents.
//!
//! Transport is Streamable HTTP on a single `/mcp` endpoint, hand-rolled
//! rather than pulled from the `rmcp` SDK. The SDK's server transport is a
//! `tower::Service` over `http` 1.x types, while redlib is on hyper 0.14 and
//! `http` 0.2, so using it would mean maintaining a request/body adapter
//! across an `http` major version -- more code, and more subtle failure
//! modes, than the four JSON-RPC methods a tools-only server actually needs.
//!
//! ## Protocol revision
//!
//! This targets the "legacy" era and reports `2025-11-25` by default. The
//! newer `2026-07-28` revision is a stateless redesign that removes
//! `initialize`, `notifications/initialized`, and session ids outright, and
//! the two eras are not mutually intelligible: announcing `2026-07-28` to a
//! legacy client is an unrecoverable failure, because legacy clients have no
//! fall-forward path. We therefore echo whatever revision the client asks for
//! when we can speak it, and otherwise answer with our default.
//!
//! Sessions and SSE are both omitted. The spec permits answering every request
//! with a single `application/json` body and declining the GET stream with
//! 405, which is all a request/response tools server needs.

pub mod reddit;
pub mod tools;

use hyper::body::HttpBody;
use hyper::{Body, Method, Request, Response, StatusCode};
use log::{debug, error, warn};
use serde_json::{json, Value};

use crate::config;

/// Revision we speak natively.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";

/// Revisions we will echo back if a client asks for them. All are legacy-era:
/// same handshake, same message shapes.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Bodies larger than this are rejected before parsing.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

// JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
	json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_result(id: Value, result: Value) -> Value {
	json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_response(status: StatusCode, body: &Value) -> Response<Body> {
	Response::builder()
		.status(status)
		.header("content-type", "application/json")
		.body(Body::from(body.to_string()))
		.unwrap_or_default()
}

/// Origins permitted to drive the endpoint from a browser context.
///
/// The spec requires validating `Origin` on every connection: without it, a
/// page on any site could have the victim's browser drive this server (DNS
/// rebinding). That matters more than usual here, because redlib is a public
/// web app rather than a localhost-only tool.
fn allowed_origins() -> Vec<String> {
	let mut origins: Vec<String> = config::get_setting("REDLIB_MCP_ALLOWED_ORIGINS")
		.unwrap_or_default()
		.split(',')
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty())
		.collect();

	// The instance's own origin is always acceptable.
	if let Some(redirect) = config::get_setting("REDLIB_OIDC_REDIRECT_URI") {
		if let Ok(url) = url::Url::parse(&redirect) {
			if let Some(host) = url.host_str() {
				let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
				origins.push(format!("{}://{host}{port}", url.scheme()));
			}
		}
	}

	origins
}

/// `None` means allowed. A non-browser client (curl, an MCP stdio bridge)
/// sends no `Origin` at all, which is not a rebinding risk and is permitted.
fn check_origin(req: &Request<Body>) -> Option<Response<Body>> {
	let origin = req.headers().get("origin").and_then(|v| v.to_str().ok())?;

	let allowed = allowed_origins();
	if allowed.iter().any(|a| a == origin) {
		return None;
	}

	warn!("MCP: rejecting request from disallowed origin {origin:?}");
	Some(json_response(
		StatusCode::FORBIDDEN,
		&json!({"error": "forbidden", "error_description": format!("origin {origin} is not allowed")}),
	))
}

/// Whether MCP is switched on.
pub fn enabled() -> bool {
	config::get_setting("REDLIB_MCP_ENABLED").map(|v| v == "on" || v == "true" || v == "1").unwrap_or(false)
}

/// `GET`/`DELETE` on the endpoint. The spec explicitly allows declining the
/// server-to-client SSE stream and session teardown with 405.
pub async fn handle_unsupported(_req: Request<Body>) -> Result<Response<Body>, String> {
	Ok(
		Response::builder()
			.status(StatusCode::METHOD_NOT_ALLOWED)
			.header("allow", "POST")
			.header("content-type", "application/json")
			.body(Body::from(
				json!({"error": "method_not_allowed", "error_description": "this MCP endpoint is POST-only; it offers no SSE stream or session teardown"}).to_string(),
			))
			.unwrap_or_default(),
	)
}

/// `POST /mcp` -- every client message arrives here.
pub async fn handle(req: Request<Body>) -> Result<Response<Body>, String> {
	if !enabled() {
		return Ok(json_response(
			StatusCode::NOT_FOUND,
			&json!({"error": "not_found", "error_description": "MCP is not enabled on this instance"}),
		));
	}

	if let Some(rejection) = check_origin(&req) {
		return Ok(rejection);
	}

	if req.method() != Method::POST {
		return handle_unsupported(req).await;
	}

	// Refuse oversized bodies before buffering them.
	if let Some(len) = req.body().size_hint().upper() {
		if len > MAX_BODY_BYTES {
			return Ok(rpc_response(rpc_error(Value::Null, INVALID_REQUEST, "request body too large")));
		}
	}

	let body = match hyper::body::to_bytes(req.into_body()).await {
		Ok(b) => b,
		Err(e) => {
			error!("MCP: could not read request body: {e}");
			return Ok(rpc_response(rpc_error(Value::Null, INTERNAL_ERROR, "could not read request body")));
		}
	};

	if body.len() as u64 > MAX_BODY_BYTES {
		return Ok(rpc_response(rpc_error(Value::Null, INVALID_REQUEST, "request body too large")));
	}

	let message: Value = match serde_json::from_slice(&body) {
		Ok(v) => v,
		Err(e) => {
			debug!("MCP: malformed JSON: {e}");
			return Ok(rpc_response(rpc_error(Value::Null, PARSE_ERROR, "invalid JSON")));
		}
	};

	// JSON-RPC batching was removed from MCP; a single object is the only
	// shape a current client sends.
	if message.is_array() {
		return Ok(rpc_response(rpc_error(Value::Null, INVALID_REQUEST, "batched requests are not supported")));
	}

	Ok(dispatch(&message).await)
}

fn rpc_response(body: Value) -> Response<Body> {
	json_response(StatusCode::OK, &body)
}

async fn dispatch(message: &Value) -> Response<Body> {
	let method = message.get("method").and_then(Value::as_str).unwrap_or_default();
	// A message with no `id` is a notification: acknowledge, never answer.
	let id = message.get("id").cloned();
	let params = message.get("params").cloned().unwrap_or(Value::Null);

	let Some(id) = id else {
		debug!("MCP: notification {method:?}");
		return Response::builder().status(StatusCode::ACCEPTED).body(Body::empty()).unwrap_or_default();
	};

	match method {
		"initialize" => rpc_response(rpc_result(id, initialize(&params))),
		"ping" => rpc_response(rpc_result(id, json!({}))),
		"tools/list" => rpc_response(rpc_result(id, json!({"tools": tools::definitions()}))),
		"tools/call" => match call_tool(&params).await {
			Ok(result) => rpc_response(rpc_result(id, result)),
			// A tool that does not exist is a protocol error; a tool that ran
			// and failed is reported inside a successful result so the model
			// can read the message and correct itself.
			Err(CallError::UnknownTool(name)) => rpc_response(rpc_error(id, INVALID_PARAMS, &format!("Unknown tool: {name}"))),
			Err(CallError::BadParams(msg)) => rpc_response(rpc_error(id, INVALID_PARAMS, &msg)),
		},
		"" => rpc_response(rpc_error(id, INVALID_REQUEST, "missing method")),
		other => rpc_response(rpc_error(id, METHOD_NOT_FOUND, &format!("Method not found: {other}"))),
	}
}

fn initialize(params: &Value) -> Value {
	// Echo the client's revision when we speak it, so a client on an older
	// legacy revision is not forced to downgrade or fail.
	let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(DEFAULT_PROTOCOL_VERSION);
	let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
		requested
	} else {
		debug!("MCP: client asked for unsupported revision {requested:?}; answering {DEFAULT_PROTOCOL_VERSION}");
		DEFAULT_PROTOCOL_VERSION
	};

	json!({
		"protocolVersion": version,
		"capabilities": {"tools": {"listChanged": false}},
		"serverInfo": {
			"name": "redlib-reddit",
			"title": "Reddit (via redlib)",
			"version": env!("CARGO_PKG_VERSION"),
		},
		"instructions": INSTRUCTIONS,
	})
}

/// Operating guidance handed to the model on every connection.
///
/// This is the only guidance channel that costs the model nothing to receive:
/// `prompts` are user-invoked slash commands and `resources` are
/// user-attached, so both require a deliberate action that a weak model will
/// not take. The spec says a client MAY fold this into the system prompt, and
/// the MCP project's own evaluation found it moves a small model far more than
/// a large one -- which is exactly who this text is for.
///
/// It is written as decision rules rather than prose, and deliberately does
/// not restate what `tools/list` already says. The failure modes it targets
/// are the ones a weak model actually hits: inventing a post id instead of
/// looking one up, picking a neighbouring tool, paging by guesswork, and
/// misreading a hidden score as a real zero.
const INSTRUCTIONS: &str = "\
Reddit, read-only. No account is signed in: voting, commenting, posting, subscribing, saved \
items, and inbox do not exist here and no tool performs them. Never state that you have voted, \
replied, or posted.

CHOOSING A TOOL
- User names a community -> browse_subreddit. Read several at once with '+': 'rust+golang'.
- No community named -> browse_frontpage.
- Looking for something specific -> search_posts. To find the community first -> search_subreddits.
- Reading the discussion on a post -> get_post.
- About a person -> get_user_overview. Use get_user only for karma and account age.
- Given a link and asked who discussed it -> lookup with url, or browse_domain for the whole site.

ORDER MATTERS
post_id and comment_id come from a previous result. Never invent or guess one. Call \
browse_subreddit, search_posts, or lookup first, take the 'id' field from an item, then pass it \
to get_post. A full Reddit URL works in place of an id. If you do not have an id, you are not \
ready to call get_post.

PAGING
Listings return 'after'. To get the next page, repeat the same call with 'after' set to that \
value. If 'after' is null, there are no more results; do not call again.

COST
The defaults (limit 25, max_depth 4) suit most questions. Raise limit only when the user asks \
for many items. Raise max_depth only when nested replies matter. Large values return a lot of \
text and are rarely needed.

READING RESULTS
- score_hidden true means Reddit is withholding the score; a score of 0 is not a real zero.
- An entry with type 'more' is a collapsed branch of replies. To read it, pass its comment_ids \
to get_more_comments.
- selftext is the author's original markdown and may be empty for link posts.

ON FAILURE
An error tells you what to fix. Correct the arguments and retry the same tool rather than \
switching to a different one. If you are unsure how to proceed, call reddit_guide.";

enum CallError {
	UnknownTool(String),
	BadParams(String),
}

/// Renders a tool result as the text the model will read.
///
/// A tool that already returns prose (the guide) must not be JSON-encoded, or
/// the model receives escaped `\n` sequences inside quotes instead of readable
/// markdown -- which defeats the point of the one tool whose entire job is to
/// be read.
fn render(value: &Value) -> String {
	match value {
		Value::String(text) => text.clone(),
		other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
	}
}

async fn call_tool(params: &Value) -> Result<Value, CallError> {
	let name = params
		.get("name")
		.and_then(Value::as_str)
		.ok_or_else(|| CallError::BadParams("missing tool name".to_string()))?;
	let args = params.get("arguments").cloned().unwrap_or(json!({}));

	if !tools::exists(name) {
		return Err(CallError::UnknownTool(name.to_string()));
	}

	debug!("MCP: calling tool {name} with {args}");

	match tools::call(name, &args).await {
		Ok(value) => Ok(json!({
			"content": [{"type": "text", "text": render(&value)}],
			"isError": false,
		})),
		Err(message) => {
			debug!("MCP: tool {name} failed: {message}");
			Ok(json!({
				"content": [{"type": "text", "text": message}],
				"isError": true,
			}))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn body_of(res: Response<Body>) -> Value {
		let bytes = futures_lite::future::block_on(hyper::body::to_bytes(res.into_body())).unwrap();
		serde_json::from_slice(&bytes).unwrap_or(Value::Null)
	}

	#[test]
	fn initialize_echoes_a_supported_client_revision() {
		let out = initialize(&json!({"protocolVersion": "2025-06-18"}));
		assert_eq!(out["protocolVersion"], "2025-06-18");
	}

	#[test]
	fn initialize_falls_back_for_an_unknown_revision() {
		// Notably this covers 2026-07-28, whose handshake we do not implement.
		let out = initialize(&json!({"protocolVersion": "2026-07-28"}));
		assert_eq!(out["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
	}

	#[test]
	fn initialize_declares_only_tools_and_names_itself() {
		let out = initialize(&json!({}));
		assert_eq!(out["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
		assert!(out["capabilities"]["tools"].is_object());
		assert!(out["capabilities"].get("resources").is_none(), "must not claim capabilities we do not implement");
		assert!(out["capabilities"].get("prompts").is_none());
		assert_eq!(out["serverInfo"]["name"], "redlib-reddit");
	}

	#[test]
	fn instructions_state_the_read_only_limitation() {
		let out = initialize(&json!({}));
		let text = out["instructions"].as_str().unwrap().to_lowercase();
		// An agent that does not know this will hallucinate voting tools.
		assert!(text.contains("voting") && text.contains("do not exist here"));
	}

	#[test]
	fn instructions_teach_the_ordering_constraint() {
		// The failure this targets: a weak model inventing a plausible-looking
		// post id instead of taking one from a listing.
		let text = INSTRUCTIONS.to_lowercase();
		assert!(text.contains("never invent"), "must forbid guessing ids");
		assert!(text.contains("get_post"), "must name the tool the rule applies to");
		assert!(text.contains("after"), "must explain pagination");
		assert!(text.contains("score_hidden"), "must warn that a hidden score is not zero");
	}

	#[test]
	fn instructions_point_at_the_fallback_tool() {
		// A client only MAY forward instructions, so the escape hatch has to be
		// discoverable from within them too.
		assert!(INSTRUCTIONS.contains("reddit_guide"));
	}

	#[test]
	fn instructions_stay_dense() {
		// Guidance long enough to be skimmed past is guidance that does not
		// work; the MCP project's advice is explicitly "don't write a manual".
		// The long form lives in the reddit_guide tool instead.
		assert!(
			INSTRUCTIONS.len() < 3000,
			"instructions grew to {} chars; move detail into the guide tool",
			INSTRUCTIONS.len()
		);
	}

	#[test]
	fn notifications_are_accepted_without_a_body() {
		let res = futures_lite::future::block_on(dispatch(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})));
		assert_eq!(res.status(), StatusCode::ACCEPTED);
	}

	#[test]
	fn prose_results_are_not_json_encoded() {
		// The guide is markdown meant to be read. Passing it through
		// to_string_pretty would wrap it in quotes and escape every newline.
		let text = render(&json!("# Heading\n\nbody"));
		assert_eq!(text, "# Heading\n\nbody");
		assert!(!text.starts_with('"'), "prose must not arrive JSON-quoted");
	}

	#[test]
	fn structured_results_are_still_pretty_printed() {
		let text = render(&json!({"count": 1}));
		assert!(text.contains("\n"), "objects should stay readable: {text}");
		assert!(text.contains("\"count\""));
	}

	#[test]
	fn ping_returns_an_empty_result() {
		let res = futures_lite::future::block_on(dispatch(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})));
		assert_eq!(body_of(res)["result"], json!({}));
	}

	#[test]
	fn unknown_method_is_method_not_found() {
		let res = futures_lite::future::block_on(dispatch(&json!({"jsonrpc": "2.0", "id": 7, "method": "resources/list"})));
		let b = body_of(res);
		assert_eq!(b["error"]["code"], METHOD_NOT_FOUND);
		assert_eq!(b["id"], 7);
	}

	#[test]
	fn unknown_tool_is_a_protocol_error_not_a_tool_failure() {
		let res = futures_lite::future::block_on(dispatch(&json!({
			"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": {"name": "definitely_not_a_tool", "arguments": {}}
		})));
		let b = body_of(res);
		assert_eq!(b["error"]["code"], INVALID_PARAMS);
		assert!(b["error"]["message"].as_str().unwrap().contains("Unknown tool"));
	}

	#[test]
	fn tools_list_is_non_empty_and_well_formed() {
		let res = futures_lite::future::block_on(dispatch(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})));
		let b = body_of(res);
		let tools = b["result"]["tools"].as_array().expect("tools array");
		assert!(tools.len() >= 15, "expected a full surface, got {}", tools.len());
		for t in tools {
			assert!(t["name"].is_string());
			assert!(t["description"].is_string());
			// A null inputSchema breaks clients; the spec requires an object.
			assert_eq!(t["inputSchema"]["type"], "object", "bad schema on {}", t["name"]);
		}
	}

	#[test]
	fn batched_requests_are_refused() {
		let msg = json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]);
		assert!(msg.is_array());
	}
}
