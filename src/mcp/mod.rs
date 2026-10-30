//! Tests for the MCP server's `mod.rs`, ported ahead of the implementation.
//!
//! The implementation lands in the next commit; until then this module is
//! not declared in `lib.rs`, so the build is unaffected.

#[cfg(test)]
mod tests {
	use super::*;

	fn body_of(res: Response<Body>) -> Value {
		let bytes = futures_lite::future::block_on(res.into_body().collect_bytes()).unwrap();
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
