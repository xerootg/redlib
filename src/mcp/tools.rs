//! Tests for the MCP server's `tools.rs`, ported ahead of the implementation.
//!
//! The implementation lands in the next commit; until then this module is
//! not declared in `lib.rs`, so the build is unaffected.

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashSet;

	#[test]
	fn every_defined_tool_is_dispatchable() {
		// Guards the catalogue and the match arms drifting apart, which would
		// otherwise only surface as a runtime "unimplemented tool".
		//
		// Needs a Tokio runtime rather than a bare block_on: the two tools
		// with no required arguments get far enough to reach the Reddit
		// client, which wants a reactor. Whether that call succeeds is
		// irrelevant here -- any outcome except the unimplemented sentinel
		// proves the arm exists -- so this stays valid offline.
		let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
		for t in definitions() {
			let name = t["name"].as_str().unwrap();
			if let Err(msg) = rt.block_on(call(name, &json!({}))) {
				assert!(!msg.starts_with("unimplemented tool"), "{name} is defined but not dispatched");
			}
		}
	}

	#[test]
	fn every_tool_is_annotated_read_only() {
		// destructiveHint and openWorldHint both default to TRUE in the spec,
		// so an unannotated tool is nominally destructive. Nothing here writes.
		for t in definitions() {
			let a = &t["annotations"];
			assert_eq!(a["readOnlyHint"], true, "{} is not marked read-only", t["name"]);
			assert_eq!(a["destructiveHint"], false, "{} is not marked non-destructive", t["name"]);
		}
	}

	#[test]
	fn the_guide_answers_without_touching_the_network() {
		// It must work when Reddit is unreachable -- that is partly when a
		// confused model will reach for it. No runtime, so a network call
		// would panic rather than merely fail.
		let out = futures_lite::future::block_on(call("reddit_guide", &json!({}))).expect("guide should always answer");
		let text = out.as_str().expect("guide returns text");
		assert!(text.contains("get_post"), "guide should name the tools");
		assert!(text.contains("score_hidden"), "guide should cover reading results");
	}

	#[test]
	fn the_guide_is_marked_as_not_reaching_the_network() {
		let guide = definitions().into_iter().find(|t| t["name"] == "reddit_guide").expect("guide tool");
		assert_eq!(guide["annotations"]["openWorldHint"], false);
	}

	#[test]
	fn failures_say_what_to_do_next() {
		// The spec has clients feed tool errors back to the model, so a message
		// that only names the problem wastes the one moment the model is
		// listening. Each of these should point at a next action.
		let cases = [
			("browse_subreddit", json!({}), "search_subreddits"),
			("get_user", json!({}), "search_users"),
			("get_post", json!({"post_id": "  "}), "browse_subreddit"),
			("get_more_comments", json!({"post_id": "abc"}), "more"),
			("lookup", json!({}), "ids"),
		];
		for (name, args, expected) in cases {
			let err = futures_lite::future::block_on(call(name, &args)).unwrap_err();
			assert!(err.contains(expected), "{name} error lacks a next step: {err}");
		}
	}

	#[test]
	fn get_more_comments_only_offers_the_cursor_path() {
		// api/morechildren is blocked for anonymous callers, and get_post only
		// emits cursor-based 'more' entries, so comment_ids can never work.
		let tool = definitions().into_iter().find(|t| t["name"] == "get_more_comments").expect("tool");
		assert!(tool["inputSchema"]["properties"].get("comment_ids").is_none());
		assert!(!tool["description"].as_str().unwrap().contains("comment_ids"));
		let err = futures_lite::future::block_on(call("get_more_comments", &json!({"post_id": "abc"}))).unwrap_err();
		assert!(err.contains("cursor") && !err.contains("comment_ids"), "{err}");
	}

	#[test]
	fn docs_do_not_mention_the_dead_morechildren_path() {
		let guide = futures_lite::future::block_on(call("reddit_guide", &json!({}))).unwrap();
		let guide = guide.as_str().unwrap();
		assert!(!guide.contains("comment_ids") && !guide.contains("morechildren"), "guide still documents the dead path");
		assert!(!super::super::INSTRUCTIONS.contains("comment_ids"), "server instructions still mention comment_ids");
	}

	#[test]
	fn get_subreddit_comments_says_it_is_blocked_instead_of_trying() {
		let tool = definitions().into_iter().find(|t| t["name"] == "get_subreddit_comments").expect("tool");
		assert!(
			tool["description"].as_str().unwrap().contains("blocks"),
			"description should warn that Reddit blocks this anonymously"
		);
		let err = futures_lite::future::block_on(call("get_subreddit_comments", &json!({"subreddit": "rust"}))).unwrap_err();
		assert!(
			err.contains("anonymous") && err.contains("browse_subreddit"),
			"error should explain and point at an alternative: {err}"
		);
	}

	#[test]
	fn invalid_enum_values_list_the_valid_ones() {
		let err = futures_lite::future::block_on(call("browse_subreddit", &json!({"subreddit": "rust", "sort": "sideways"}))).unwrap_err();
		assert!(err.contains("sideways") && err.contains("hot"), "unhelpful: {err}");
	}

	#[test]
	fn tool_names_are_unique_and_spec_legal() {
		let mut seen = HashSet::new();
		for t in definitions() {
			let name = t["name"].as_str().unwrap();
			assert!(seen.insert(name.to_string()), "duplicate tool name: {name}");
			assert!(!name.is_empty() && name.len() <= 128);
			assert!(
				name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'),
				"illegal character in tool name: {name}"
			);
		}
	}

	#[test]
	fn required_arguments_are_declared_as_properties() {
		for t in definitions() {
			let schema = &t["inputSchema"];
			let props = schema["properties"].as_object().unwrap();
			for r in schema["required"].as_array().unwrap() {
				let key = r.as_str().unwrap();
				assert!(props.contains_key(key), "{} requires {key} but does not define it", t["name"]);
			}
		}
	}

	#[test]
	fn enum_defaults_are_members_of_their_enum() {
		for t in definitions() {
			for (prop, spec) in t["inputSchema"]["properties"].as_object().unwrap() {
				if let (Some(values), Some(default)) = (spec.get("enum").and_then(Value::as_array), spec.get("default")) {
					assert!(values.contains(default), "{}.{prop} defaults to {default} which is not in its enum", t["name"]);
				}
			}
		}
	}

	#[test]
	fn missing_required_argument_is_a_clear_failure() {
		let err = futures_lite::future::block_on(call("browse_subreddit", &json!({}))).unwrap_err();
		assert!(err.contains("subreddit"), "unhelpful message: {err}");
	}

	#[test]
	fn exists_matches_the_catalogue() {
		assert!(exists("get_post"));
		assert!(!exists("delete_post"));
	}

	#[test]
	fn no_tool_implies_a_write_capability() {
		// The token is anonymous; advertising a mutating verb would invite the
		// model to attempt something that cannot work.
		for t in definitions() {
			let name = t["name"].as_str().unwrap();
			for forbidden in ["vote", "submit", "reply", "subscribe", "save", "delete", "edit", "send"] {
				assert!(!name.contains(forbidden), "{name} implies a write action this server cannot perform");
			}
		}
	}
}
