//! Tool catalogue and dispatch.
//!
//! Descriptions are written for a model choosing between tools, not for a
//! human reading docs: each says what it returns and when to prefer it over a
//! neighbouring tool, because vague descriptions are the usual cause of an
//! agent picking wrong.

use serde_json::{json, Value};

use super::reddit;

/// Shorthand for a string property with a description.
fn s(desc: &str) -> Value {
	json!({"type": "string", "description": desc})
}

/// Shorthand for a string property constrained to an enum.
fn s_enum(desc: &str, values: &[&str], default: &str) -> Value {
	json!({"type": "string", "description": desc, "enum": values, "default": default})
}

fn int(desc: &str, min: u64, max: u64, default: u64) -> Value {
	json!({"type": "integer", "description": desc, "minimum": min, "maximum": max, "default": default})
}

fn schema(props: Value, required: &[&str]) -> Value {
	json!({
		"type": "object",
		"properties": props,
		"required": required,
		// Rejecting unknown keys surfaces a typo'd argument as a clear error
		// rather than silently ignoring it.
		"additionalProperties": false,
	})
}

fn tool(name: &str, title: &str, description: &str, input_schema: Value) -> Value {
	json!({"name": name, "title": title, "description": description, "inputSchema": input_schema})
}

const LIMIT_DESC: &str = "Maximum items to return (1-100).";
const AFTER_DESC: &str = "Pagination cursor from a previous call's `after` field. Omit for the first page.";
const POST_ID_DESC: &str = "Post id, t3_ fullname, or full Reddit URL.";

/// The full catalogue, returned verbatim by `tools/list`.
pub fn definitions() -> Vec<Value> {
	vec![
		tool(
			"browse_subreddit",
			"Browse a subreddit",
			"List posts in one subreddit. Use this when the user names a specific community. Returns post metadata and self-post text, but not comments -- follow up with get_post for those.",
			schema(
				json!({
					"subreddit": s("Subreddit name. 'rust', 'r/rust', and '/r/rust' are all accepted."),
					"sort": s_enum("Listing order.", &reddit::LISTING_SORTS, "hot"),
					"time": s_enum("Time window. Only affects sort=top and sort=controversial.", &reddit::TIME_FILTERS, "day"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["subreddit"],
			),
		),
		tool(
			"browse_frontpage",
			"Browse r/popular or r/all",
			"List posts from Reddit's site-wide feeds. Use for 'what's trending on Reddit' when no specific community is named.",
			schema(
				json!({
					"feed": s_enum("Which site-wide feed. 'popular' is curated and excludes some NSFW communities, 'all' is unfiltered, 'best' is Reddit's ranked default feed.", &["popular", "all", "best"], "popular"),
					"sort": s_enum("Listing order.", &reddit::LISTING_SORTS, "hot"),
					"time": s_enum("Time window. Only affects sort=top and sort=controversial.", &reddit::TIME_FILTERS, "day"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&[],
			),
		),
		tool(
			"get_post",
			"Get a post with its comments",
			"Fetch one post's full text plus its comment tree. This is the tool for reading discussion. Deep or long threads are elided as entries with type 'more' carrying comment_ids -- pass those to get_more_comments to expand them.",
			schema(
				json!({
					"post_id": s(POST_ID_DESC),
					"comment_sort": s_enum("Comment ordering. 'confidence' is Reddit's default 'best'.", &reddit::COMMENT_SORTS, "confidence"),
					"limit": int("Maximum top-level comments.", 1, 100, 50),
					"max_depth": int("How many reply levels to descend. Deeper trees cost more tokens; replies beyond this are flagged with replies_truncated.", 0, 10, 4),
				}),
				&["post_id"],
			),
		),
		tool(
			"get_more_comments",
			"Expand elided comments",
			"Fetch comments hidden behind a 'more' node returned by get_post. Results are a flat list; reassemble the hierarchy using each comment's parent_id.",
			schema(
				json!({
					"post_id": s(POST_ID_DESC),
					"comment_ids": json!({
						"type": "array",
						"description": "The comment_ids array from a 'more' entry.",
						"items": {"type": "string"},
					}),
					"comment_sort": s_enum("Comment ordering.", &reddit::COMMENT_SORTS, "confidence"),
				}),
				&["post_id", "comment_ids"],
			),
		),
		tool(
			"search_posts",
			"Search for posts",
			"Full-text search over post titles and bodies. Omit `subreddit` to search all of Reddit, or set it to scope the search to one community.",
			schema(
				json!({
					"query": s("Search terms. Reddit's search syntax is supported, e.g. 'author:spez' or 'title:rust'."),
					"subreddit": s("Restrict to this subreddit. Omit to search site-wide."),
					"sort": s_enum("Result ordering.", &reddit::SEARCH_SORTS, "relevance"),
					"time": s_enum("Time window.", &reddit::TIME_FILTERS, "all"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["query"],
			),
		),
		tool(
			"search_subreddits",
			"Find subreddits",
			"Search for communities by name and description. Use this to discover where a topic is discussed before browsing.",
			schema(
				json!({
					"query": s("Topic or name to search for."),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["query"],
			),
		),
		tool(
			"search_users",
			"Find users",
			"Search for Reddit accounts by username.",
			schema(
				json!({
					"query": s("Username or partial username."),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["query"],
			),
		),
		tool(
			"get_user",
			"Get a user profile",
			"Fetch an account's karma, age, and bio. Returns profile metadata only -- use get_user_posts or get_user_comments for their activity.",
			schema(json!({"username": s("Username. 'spez', 'u/spez', and '/u/spez' are all accepted.")}), &["username"]),
		),
		tool(
			"get_user_posts",
			"Get a user's submissions",
			"List posts submitted by an account, newest first by default.",
			schema(
				json!({
					"username": s("Username."),
					"sort": s_enum("Ordering.", &["new", "hot", "top", "controversial"], "new"),
					"time": s_enum("Time window. Only affects top and controversial.", &reddit::TIME_FILTERS, "all"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["username"],
			),
		),
		tool(
			"get_user_comments",
			"Get a user's comments",
			"List comments written by an account, with the title of the post each replied to.",
			schema(
				json!({
					"username": s("Username."),
					"sort": s_enum("Ordering.", &["new", "hot", "top", "controversial"], "new"),
					"time": s_enum("Time window. Only affects top and controversial.", &reddit::TIME_FILTERS, "all"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["username"],
			),
		),
		tool(
			"get_user_overview",
			"Get a user's combined activity",
			"List an account's posts and comments interleaved in one timeline. Prefer this over separate calls when building a picture of someone's recent activity.",
			schema(
				json!({
					"username": s("Username."),
					"sort": s_enum("Ordering.", &["new", "hot", "top", "controversial"], "new"),
					"time": s_enum("Time window. Only affects top and controversial.", &reddit::TIME_FILTERS, "all"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["username"],
			),
		),
		tool(
			"get_user_gilded",
			"Get a user's awarded content",
			"List posts and comments by an account that received awards. A quick proxy for their best-received contributions.",
			schema(
				json!({
					"username": s("Username."),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["username"],
			),
		),
		tool(
			"get_subreddit_about",
			"Get subreddit details",
			"Fetch a community's description, subscriber count, and settings. Use this to judge how large or active a subreddit is before browsing it.",
			schema(json!({"subreddit": s("Subreddit name.")}), &["subreddit"]),
		),
		tool(
			"get_subreddit_rules",
			"Get subreddit rules",
			"Fetch a community's posted rules. Useful for judging whether content is on-topic or why something may have been removed.",
			schema(json!({"subreddit": s("Subreddit name.")}), &["subreddit"]),
		),
		// There is deliberately no moderator-list tool. `/about/moderators`
		// returns 403 for every subreddit under redlib's anonymous token, so
		// it could only ever fail; offering it would just invite the model to
		// waste a call and report a broken capability.
		tool(
			"get_subreddit_wiki",
			"Read a subreddit wiki",
			"Fetch a wiki page's markdown, or list available pages when `page` is omitted. Community FAQs and detailed rules usually live here.",
			schema(
				json!({
					"subreddit": s("Subreddit name."),
					"page": s("Wiki page path, e.g. 'index' or 'faq'. Omit to list all pages."),
				}),
				&["subreddit"],
			),
		),
		tool(
			"get_duplicates",
			"Find other discussions of a link",
			"Find other posts submitting the same URL, across subreddits. Use this to see how different communities reacted to the same article.",
			schema(
				json!({
					"post_id": s(POST_ID_DESC),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["post_id"],
			),
		),
		tool(
			"list_subreddits",
			"List subreddits by category",
			"Enumerate communities Reddit ranks as popular, newly created, or in its default set. Use for open-ended discovery; use search_subreddits when looking for a specific topic.",
			schema(
				json!({
					"kind": s_enum("Which catalogue to list.", &["popular", "new", "default"], "popular"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&[],
			),
		),
		tool(
			"get_subreddit_comments",
			"Get a subreddit's recent comments",
			"Stream the newest comments across an entire subreddit, independent of any single post. Use this to gauge what a community is actively discussing; use get_post when you care about one thread.",
			schema(
				json!({
					"subreddit": s("Subreddit name."),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["subreddit"],
			),
		),
		tool(
			"get_sticky_post",
			"Get a subreddit's pinned post",
			"Fetch a community's pinned post with its comments. These are usually megathreads, rules posts, or recurring discussion threads, so this is often the best starting point for a subreddit.",
			schema(
				json!({
					"subreddit": s("Subreddit name."),
					"num": int("Which sticky slot; a subreddit may pin two.", 1, 2, 1),
					"max_depth": int("How many reply levels to descend.", 0, 10, 4),
				}),
				&["subreddit"],
			),
		),
		tool(
			"get_comment_thread",
			"Get one comment and its replies",
			"Fetch a single comment, the replies beneath it, and optionally its parent chain. Use this to follow a specific subthread without pulling the whole post, and when someone links a comment permalink.",
			schema(
				json!({
					"post_id": s(POST_ID_DESC),
					"comment_id": s("Comment id, with or without the t1_ prefix."),
					"context": int("How many ancestors to include above the comment.", 0, 8, 2),
					"comment_sort": s_enum("Reply ordering.", &reddit::COMMENT_SORTS, "confidence"),
					"max_depth": int("How many reply levels to descend.", 0, 10, 4),
				}),
				&["post_id", "comment_id"],
			),
		),
		tool(
			"browse_domain",
			"Get posts linking to a domain",
			"List submissions across all of Reddit that link to a given site. Use this to find where an article or site has been discussed.",
			schema(
				json!({
					"domain": s("Domain such as 'github.com'. A full URL is accepted and reduced to its host."),
					"sort": s_enum("Listing order.", &reddit::LISTING_SORTS, "hot"),
					"time": s_enum("Time window. Only affects top and controversial.", &reddit::TIME_FILTERS, "all"),
					"limit": int(LIMIT_DESC, 1, 100, 25),
					"after": s(AFTER_DESC),
				}),
				&["domain"],
			),
		),
		tool(
			"lookup",
			"Look up items by id or URL",
			"Resolve posts, comments, or subreddits by fullname (t3_/t1_/t5_) in one batched call, or find the Reddit post that submitted a given URL. Cheaper than fetching each item separately.",
			schema(
				json!({
					"ids": json!({
						"type": "array",
						"description": "Fullnames such as ['t3_abc123', 't1_def456']. Mutually exclusive with url.",
						"items": {"type": "string"},
					}),
					"url": s("An external URL to find submissions of. Mutually exclusive with ids."),
				}),
				&[],
			),
		),
		tool(
			"get_user_trophies",
			"Get a user's trophies",
			"Fetch the awards and badges on an account's profile, such as cake day and moderator trophies.",
			schema(json!({"username": s("Username.")}), &["username"]),
		),
		tool(
			"get_user_moderated_subreddits",
			"Get subreddits a user moderates",
			"List the communities an account moderates. Note the reverse direction is not available: Reddit refuses to list a subreddit's moderators to an anonymous caller.",
			schema(json!({"username": s("Username.")}), &["username"]),
		),
		tool(
			"get_wiki_revisions",
			"Get wiki edit history",
			"List revisions to a subreddit's wiki, either across all pages or for one page. Use this to see when community rules or FAQs last changed.",
			schema(
				json!({
					"subreddit": s("Subreddit name."),
					"page": s("Restrict to one page, e.g. 'index'. Omit for all pages."),
					"limit": int(LIMIT_DESC, 1, 100, 25),
				}),
				&["subreddit"],
			),
		),
		tool(
			"reddit_api_raw",
			"Call a Reddit API path directly",
			"Escape hatch for read endpoints not covered by the other tools. Returns Reddit's unprojected JSON, which is far more verbose -- prefer a specific tool when one fits. Write endpoints are refused: this server authenticates anonymously and cannot act as any account.",
			schema(
				json!({
					"path": s("API path beginning with '/', e.g. '/r/rust/about/traffic.json'. Append raw_json=1 to avoid HTML-escaped body text."),
				}),
				&["path"],
			),
		),
	]
}

/// Whether a tool name is in the catalogue.
pub fn exists(name: &str) -> bool {
	definitions().iter().any(|t| t["name"] == name)
}

// --- argument helpers ------------------------------------------------------
//
// Missing-argument errors are returned as tool failures rather than protocol
// errors, so the model sees the message and can retry with corrected input.

fn req_str(args: &Value, key: &str) -> Result<String, String> {
	args
		.get(key)
		.and_then(Value::as_str)
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.map(ToString::to_string)
		.ok_or_else(|| format!("missing required argument: {key}"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
	args.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string)
}

fn str_or(args: &Value, key: &str, default: &str) -> String {
	opt_str(args, key).unwrap_or_else(|| default.to_string())
}

fn limit_of(args: &Value) -> u64 {
	reddit::clamp_limit(args.get("limit").and_then(Value::as_u64))
}

/// Executes a tool. `Err` is a tool-level failure, reported to the model with
/// `isError: true` rather than as a JSON-RPC error.
pub async fn call(name: &str, args: &Value) -> Result<Value, String> {
	let after = opt_str(args, "after");
	let after = after.as_deref();

	match name {
		"browse_subreddit" => {
			reddit::browse_subreddit(
				&req_str(args, "subreddit")?,
				&str_or(args, "sort", "hot"),
				Some(&str_or(args, "time", "day")),
				limit_of(args),
				after,
			)
			.await
		}
		"browse_frontpage" => {
			reddit::browse_frontpage(
				&str_or(args, "feed", "popular"),
				&str_or(args, "sort", "hot"),
				Some(&str_or(args, "time", "day")),
				limit_of(args),
				after,
			)
			.await
		}
		"get_post" => {
			let max_depth = args.get("max_depth").and_then(Value::as_u64).unwrap_or(4).min(10) as u32;
			reddit::get_post(&req_str(args, "post_id")?, &str_or(args, "comment_sort", "confidence"), limit_of(args), max_depth).await
		}
		"get_more_comments" => {
			let ids: Vec<String> = args
				.get("comment_ids")
				.and_then(Value::as_array)
				.map(|a| a.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
				.unwrap_or_default();
			reddit::get_more_comments(&req_str(args, "post_id")?, &ids, &str_or(args, "comment_sort", "confidence")).await
		}
		"search_posts" => {
			reddit::search_posts(
				&req_str(args, "query")?,
				opt_str(args, "subreddit").as_deref(),
				&str_or(args, "sort", "relevance"),
				&str_or(args, "time", "all"),
				limit_of(args),
				after,
			)
			.await
		}
		"search_subreddits" => reddit::search_subreddits(&req_str(args, "query")?, limit_of(args), after).await,
		"search_users" => reddit::search_users(&req_str(args, "query")?, limit_of(args), after).await,
		"get_user" => reddit::get_user(&req_str(args, "username")?).await,
		"get_user_posts" => {
			reddit::get_user_listing(
				&req_str(args, "username")?,
				"submitted",
				&str_or(args, "sort", "new"),
				&str_or(args, "time", "all"),
				limit_of(args),
				after,
			)
			.await
		}
		"get_user_comments" => {
			reddit::get_user_listing(
				&req_str(args, "username")?,
				"comments",
				&str_or(args, "sort", "new"),
				&str_or(args, "time", "all"),
				limit_of(args),
				after,
			)
			.await
		}
		"get_user_overview" => {
			reddit::get_user_listing(
				&req_str(args, "username")?,
				"overview",
				&str_or(args, "sort", "new"),
				&str_or(args, "time", "all"),
				limit_of(args),
				after,
			)
			.await
		}
		"get_subreddit_about" => reddit::get_subreddit_about(&req_str(args, "subreddit")?).await,
		"get_subreddit_rules" => reddit::get_subreddit_rules(&req_str(args, "subreddit")?).await,
		"get_subreddit_wiki" => reddit::get_wiki(&req_str(args, "subreddit")?, opt_str(args, "page").as_deref()).await,
		"get_duplicates" => reddit::get_duplicates(&req_str(args, "post_id")?, limit_of(args), after).await,
		"list_subreddits" => reddit::list_subreddits(&str_or(args, "kind", "popular"), limit_of(args), after).await,
		"get_subreddit_comments" => reddit::get_subreddit_comments(&req_str(args, "subreddit")?, limit_of(args), after).await,
		"get_sticky_post" => {
			let num = args.get("num").and_then(Value::as_u64).unwrap_or(1);
			let max_depth = args.get("max_depth").and_then(Value::as_u64).unwrap_or(4).min(10) as u32;
			reddit::get_sticky(&req_str(args, "subreddit")?, num, max_depth).await
		}
		"get_comment_thread" => {
			let context = args.get("context").and_then(Value::as_u64).unwrap_or(2);
			let max_depth = args.get("max_depth").and_then(Value::as_u64).unwrap_or(4).min(10) as u32;
			reddit::get_comment_thread(
				&req_str(args, "post_id")?,
				&req_str(args, "comment_id")?,
				context,
				&str_or(args, "comment_sort", "confidence"),
				max_depth,
			)
			.await
		}
		"browse_domain" => reddit::browse_domain(&req_str(args, "domain")?, &str_or(args, "sort", "hot"), &str_or(args, "time", "all"), limit_of(args), after).await,
		"lookup" => {
			let ids: Vec<String> = args
				.get("ids")
				.and_then(Value::as_array)
				.map(|a| a.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
				.unwrap_or_default();
			reddit::lookup(&ids, opt_str(args, "url").as_deref()).await
		}
		"get_user_trophies" => reddit::get_user_trophies(&req_str(args, "username")?).await,
		"get_user_moderated_subreddits" => reddit::get_user_moderated_subreddits(&req_str(args, "username")?).await,
		"get_user_gilded" => reddit::get_user_listing(&req_str(args, "username")?, "gilded", "new", "all", limit_of(args), after).await,
		"get_wiki_revisions" => reddit::get_wiki_revisions(&req_str(args, "subreddit")?, opt_str(args, "page").as_deref(), limit_of(args)).await,
		"reddit_api_raw" => reddit::raw_api(&req_str(args, "path")?).await,
		other => Err(format!("unimplemented tool: {other}")),
	}
}

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
