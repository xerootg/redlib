//! Reddit API projection layer for the MCP server.
//!
//! Everything here goes through [`crate::backends::json`], which is the
//! valuable part of redlib to reuse: it carries the spoofed-device OAuth
//! token, token refresh, rate-limit accounting, Reddit's quarantine handling,
//! and -- since Reddit blocks most of its anonymous JSON API -- the fallback
//! to GraphQL and the other backends, which answer in the JSON API's shape.
//!
//! What this layer deliberately does *not* reuse is [`crate::utils::parse_post`]
//! and the `Post`/`Comment` structs. Those exist to render HTML: they rewrite
//! reddit.com links to point back at this instance, proxy media through
//! `/img/` and `/vid/`, and pre-format numbers and timestamps for templates.
//! All of that is wrong for an agent, which wants the author's original
//! markdown and canonical URLs. Projecting straight from the API response
//! keeps the output honest and keeps MCP decoupled from the web UI.
//!
//! Note that redlib's OAuth token is anonymous -- it spoofs the Reddit mobile
//! app's device auth and is not tied to any account. Only public reads are
//! reachable; voting, commenting, subscribing, and inbox access are not.

use serde_json::{json, Map, Value};

use crate::backends::gql::MORE_QUERY;
use crate::backends::json as reddit_json;

/// Sorts valid for a subreddit or front-page listing.
pub const LISTING_SORTS: [&str; 5] = ["hot", "new", "top", "rising", "controversial"];
/// Time windows accepted by `top` and `controversial`.
pub const TIME_FILTERS: [&str; 6] = ["hour", "day", "week", "month", "year", "all"];
/// Sorts valid for a comment tree.
pub const COMMENT_SORTS: [&str; 6] = ["confidence", "top", "new", "controversial", "old", "qa"];
/// Sorts valid for search.
pub const SEARCH_SORTS: [&str; 5] = ["relevance", "hot", "top", "new", "comments"];

/// Reddit rejects anything above 100 outright; clamping is friendlier than
/// surfacing its error.
const MAX_LIMIT: u64 = 100;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn str_of(v: &Value, key: &str) -> Option<String> {
	v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(ToString::to_string)
}

fn num_of(v: &Value, key: &str) -> Option<i64> {
	v.get(key).and_then(Value::as_i64)
}

fn bool_of(v: &Value, key: &str) -> bool {
	v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Inserts only when present, so projected objects stay free of null noise.
fn put(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
	if let Some(value) = value {
		map.insert(key.to_string(), value);
	}
}

/// Validates a value against an allowed set, so a bad argument fails with a
/// useful message instead of a confusing Reddit error.
pub fn validate(name: &str, value: &str, allowed: &[&str]) -> Result<(), String> {
	if allowed.contains(&value) {
		Ok(())
	} else {
		Err(format!("invalid {name}: {value:?} (expected one of: {})", allowed.join(", ")))
	}
}

pub fn clamp_limit(limit: Option<u64>) -> u64 {
	limit.unwrap_or(25).clamp(1, MAX_LIMIT)
}

/// Normalises `r/rust`, `/r/rust`, and `rust` to `rust`.
pub fn normalize_subreddit(sub: &str) -> String {
	sub.trim().trim_start_matches('/').trim_start_matches("r/").trim_matches('/').to_string()
}

/// Normalises `u/spez`, `/u/spez`, and `spez` to `spez`.
pub fn normalize_username(user: &str) -> String {
	user
		.trim()
		.trim_start_matches('/')
		.trim_start_matches("u/")
		.trim_start_matches("user/")
		.trim_matches('/')
		.to_string()
}

/// Accepts a bare id (`1abc234`), a `t3_`-prefixed fullname, or any Reddit or
/// redlib permalink, and yields the bare id.
///
/// Agents paste whatever they have; making them pre-parse a URL is a pointless
/// round-trip.
pub fn extract_post_id(input: &str) -> Result<String, String> {
	let input = input.trim();
	if input.is_empty() {
		return Err(
			"post_id is empty. Post ids come from browse_subreddit, search_posts, or lookup -- take the \"id\" field of a result. A full Reddit URL also works.".to_string(),
		);
	}

	if let Some(rest) = input.strip_prefix("t3_") {
		return Ok(rest.to_string());
	}

	// Not a URL: treat as a bare id.
	if !input.contains('/') {
		return Ok(input.to_string());
	}

	// .../comments/<id>/<slug> is the canonical permalink shape.
	let segments: Vec<&str> = input.split(['/', '?', '#']).filter(|s| !s.is_empty()).collect();
	if let Some(pos) = segments.iter().position(|s| *s == "comments") {
		if let Some(id) = segments.get(pos + 1) {
			return Ok((*id).to_string());
		}
	}

	// Short links (redd.it/<id>, /r/<sub>/s/<id>) put the id last.
	segments.last().map(|s| (*s).to_string()).ok_or_else(|| format!("could not find a post id in {input:?}"))
}

/// Builds a query string, skipping empty values.
fn query(pairs: &[(&str, String)]) -> String {
	let parts: Vec<String> = pairs.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}={}", urlencode(v))).collect();
	parts.join("&")
}

fn urlencode(s: &str) -> String {
	// Percent-encodes everything outside the unreserved set. serde_urlencoded
	// would need a typed struct per call site for no benefit here.
	s.bytes()
		.map(|b| match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
			b' ' => "+".to_string(),
			_ => format!("%{b:02X}"),
		})
		.collect()
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

/// Projects a `t3` (link) into a compact post object.
pub fn project_post(thing: &Value) -> Value {
	let d = thing.get("data").unwrap_or(thing);
	let mut m = Map::new();

	put(&mut m, "id", str_of(d, "id").map(Value::from));
	put(&mut m, "fullname", str_of(d, "name").map(Value::from));
	put(&mut m, "title", str_of(d, "title").map(Value::from));
	put(&mut m, "author", str_of(d, "author").map(Value::from));
	put(&mut m, "subreddit", str_of(d, "subreddit").map(Value::from));
	put(&mut m, "created_utc", d.get("created_utc").and_then(Value::as_f64).map(|f| Value::from(f as i64)));
	put(&mut m, "permalink", str_of(d, "permalink").map(|p| Value::from(format!("https://www.reddit.com{p}"))));
	put(&mut m, "url", str_of(d, "url").map(Value::from));

	// Reddit hides scores on new posts; `score` is 0 then, which reads as a
	// real value unless the flag travels with it.
	put(&mut m, "score", num_of(d, "score").map(Value::from));
	m.insert("score_hidden".to_string(), Value::from(bool_of(d, "hide_score")));
	put(&mut m, "upvote_ratio", d.get("upvote_ratio").and_then(Value::as_f64).map(Value::from));
	put(&mut m, "num_comments", num_of(d, "num_comments").map(Value::from));

	// selftext is the author's original markdown -- exactly what an agent
	// wants, and what the HTML pipeline would have rewritten.
	put(&mut m, "selftext", str_of(d, "selftext").map(Value::from));

	m.insert("is_self".to_string(), Value::from(bool_of(d, "is_self")));
	m.insert("over_18".to_string(), Value::from(bool_of(d, "over_18")));
	m.insert("spoiler".to_string(), Value::from(bool_of(d, "spoiler")));
	m.insert("stickied".to_string(), Value::from(bool_of(d, "stickied")));
	m.insert("locked".to_string(), Value::from(bool_of(d, "locked")));
	put(&mut m, "flair", str_of(d, "link_flair_text").map(Value::from));
	put(&mut m, "post_hint", str_of(d, "post_hint").map(Value::from));
	put(&mut m, "domain", str_of(d, "domain").map(Value::from));
	// GraphQL-built posts carry only the parent's data, not its fullname.
	let crosspost_parent = str_of(d, "crosspost_parent").or_else(|| {
		d.get("crosspost_parent_list")
			.and_then(Value::as_array)
			.and_then(|l| l.first())
			.and_then(|p| str_of(p, "name"))
	});
	put(&mut m, "crosspost_parent", crosspost_parent.map(Value::from));

	// Gallery images, flattened to plain URLs.
	if let Some(meta) = d.get("media_metadata").and_then(Value::as_object) {
		let images: Vec<Value> = meta
			.values()
			.filter_map(|item| {
				item
					.get("s")
					.and_then(|s| s.get("u").or_else(|| s.get("gif")))
					.and_then(Value::as_str)
					.map(|u| Value::from(u.replace("&amp;", "&")))
			})
			.collect();
		if !images.is_empty() {
			m.insert("gallery_images".to_string(), Value::from(images));
		}
	}

	// Direct video, when Reddit hosts it.
	if let Some(v) = d
		.get("secure_media")
		.and_then(|sm| sm.get("reddit_video"))
		.or_else(|| d.get("media").and_then(|md| md.get("reddit_video")))
	{
		let mut vm = Map::new();
		put(&mut vm, "hls_url", str_of(v, "hls_url").map(Value::from));
		put(&mut vm, "fallback_url", str_of(v, "fallback_url").map(Value::from));
		put(&mut vm, "duration", num_of(v, "duration").map(Value::from));
		if !vm.is_empty() {
			m.insert("video".to_string(), Value::Object(vm));
		}
	}

	if let Some(poll) = d.get("poll_data") {
		m.insert("poll".to_string(), project_poll(poll));
	}

	Value::Object(m)
}

fn project_poll(poll: &Value) -> Value {
	let options: Vec<Value> = poll
		.get("options")
		.and_then(Value::as_array)
		.map(|opts| {
			opts
				.iter()
				.map(|o| {
					let mut om = Map::new();
					put(&mut om, "text", str_of(o, "text").map(Value::from));
					put(&mut om, "votes", num_of(o, "vote_count").map(Value::from));
					Value::Object(om)
				})
				.collect()
		})
		.unwrap_or_default();

	json!({
		"total_votes": num_of(poll, "total_vote_count"),
		"voting_end_timestamp": num_of(poll, "voting_end_timestamp"),
		"options": options,
	})
}

/// Marks a `get_more_comments` cursor that a non-GraphQL backend issued.
/// GraphQL cursors look like `commenttree:<hash>,...`, so a cursor starting
/// with this cannot be one of theirs.
const FOREIGN_CURSOR_PREFIX: &str = "redlib-more?";

/// The cursor handed to the model for a `more` node.
///
/// Only the backend that issued a cursor can load it, and the backend layer
/// tells them apart by the `more_query` sent alongside. GraphQL cursors, the
/// common case, are passed through unchanged, so they match what the backend
/// emits. The scraper's cursors only work together with their `more_query`,
/// so both travel inside one opaque string behind [`FOREIGN_CURSOR_PREFIX`].
fn encode_cursor(cursor: &str, more_query: Option<&str>) -> String {
	match more_query.filter(|q| !q.is_empty() && *q != MORE_QUERY) {
		None => cursor.to_string(),
		Some(more_query) => format!(
			"{FOREIGN_CURSOR_PREFIX}{}",
			url::form_urlencoded::Serializer::new(String::new())
				.append_pair("more_cursor", cursor)
				.append_pair("more_query", more_query)
				.finish()
		),
	}
}

/// The query parameters that make the backend layer load `cursor`.
fn cursor_query(cursor: &str) -> String {
	let cursor = cursor.trim();
	match cursor.strip_prefix(FOREIGN_CURSOR_PREFIX) {
		Some(query) => query.to_string(),
		None => url::form_urlencoded::Serializer::new(String::new())
			.append_pair("more_cursor", cursor)
			.append_pair("more_query", MORE_QUERY)
			.finish(),
	}
}

/// Projects a comment tree, recursively, up to `max_depth`.
///
/// Reddit represents elided branches as `kind: "more"` nodes. Those are
/// surfaced as `{"type": "more", ...}` entries rather than silently dropped,
/// so a caller can decide to fetch them via `get_more_comments`. Threads
/// loaded through GraphQL or scraping carry a `cursor` and the `more_query`
/// that names the backend able to load it, and no `children`; REST listings
/// carry child ids.
pub fn project_comments(listing: &Value, depth: u32, max_depth: u32) -> Vec<Value> {
	let Some(children) = listing.get("data").and_then(|d| d.get("children")).and_then(Value::as_array) else {
		return Vec::new();
	};

	children
		.iter()
		.filter_map(|child| {
			let kind = child.get("kind").and_then(Value::as_str)?;
			let d = child.get("data")?;

			match kind {
				"more" => {
					if d.get("children").is_none() {
						let cursor = str_of(d, "cursor")?;
						return Some(json!({
							"type": "more",
							"count": num_of(d, "count"),
							"parent_id": str_of(d, "parent_id"),
							"cursor": encode_cursor(&cursor, str_of(d, "more_query").as_deref()),
						}));
					}
					let ids: Vec<Value> = d.get("children").and_then(Value::as_array).map(|c| c.to_vec()).unwrap_or_default();
					// A count of 0 with no ids is Reddit's "continue this
					// thread" marker, which carries nothing useful.
					if ids.is_empty() {
						return None;
					}
					Some(json!({
						"type": "more",
						"count": num_of(d, "count"),
						"parent_id": str_of(d, "parent_id"),
						"comment_ids": ids,
					}))
				}
				"t1" => {
					let mut m = Map::new();
					m.insert("type".to_string(), Value::from("comment"));
					put(&mut m, "id", str_of(d, "id").map(Value::from));
					put(&mut m, "author", str_of(d, "author").map(Value::from));
					put(&mut m, "body", str_of(d, "body").map(Value::from));
					put(&mut m, "score", num_of(d, "score").map(Value::from));
					m.insert("score_hidden".to_string(), Value::from(bool_of(d, "score_hidden")));
					put(&mut m, "created_utc", d.get("created_utc").and_then(Value::as_f64).map(|f| Value::from(f as i64)));
					m.insert("is_submitter".to_string(), Value::from(bool_of(d, "is_submitter")));
					m.insert("stickied".to_string(), Value::from(bool_of(d, "stickied")));
					put(&mut m, "flair", str_of(d, "author_flair_text").map(Value::from));
					put(&mut m, "permalink", str_of(d, "permalink").map(|p| Value::from(format!("https://www.reddit.com{p}"))));

					// `replies` is "" rather than an object when there are none.
					if depth < max_depth {
						let replies = d.get("replies").map(|r| project_comments(r, depth + 1, max_depth)).unwrap_or_default();
						if !replies.is_empty() {
							m.insert("replies".to_string(), Value::from(replies));
						}
					} else if d.get("replies").and_then(|r| r.get("data")).is_some() {
						m.insert("replies_truncated".to_string(), Value::from(true));
					}

					Some(Value::Object(m))
				}
				_ => None,
			}
		})
		.collect()
}

/// Projects a `t5` (subreddit).
pub fn project_subreddit(thing: &Value) -> Value {
	let d = thing.get("data").unwrap_or(thing);
	let mut m = Map::new();

	put(&mut m, "name", str_of(d, "display_name").map(Value::from));
	put(&mut m, "title", str_of(d, "title").map(Value::from));
	put(&mut m, "url", str_of(d, "url").map(|u| Value::from(format!("https://www.reddit.com{u}"))));
	put(&mut m, "subscribers", num_of(d, "subscribers").map(Value::from));
	put(&mut m, "active_users", num_of(d, "accounts_active").map(Value::from));
	put(&mut m, "created_utc", d.get("created_utc").and_then(Value::as_f64).map(|f| Value::from(f as i64)));
	put(&mut m, "public_description", str_of(d, "public_description").map(Value::from));
	put(&mut m, "description", str_of(d, "description").map(Value::from));
	m.insert("over_18".to_string(), Value::from(bool_of(d, "over18")));
	m.insert("quarantined".to_string(), Value::from(bool_of(d, "quarantine")));
	put(&mut m, "subreddit_type", str_of(d, "subreddit_type").map(Value::from));

	Value::Object(m)
}

/// Projects a `t2` (account).
pub fn project_user(thing: &Value) -> Value {
	let d = thing.get("data").unwrap_or(thing);
	let mut m = Map::new();

	put(&mut m, "name", str_of(d, "name").map(Value::from));
	put(&mut m, "id", str_of(d, "id").map(Value::from));
	// GraphQL-built profiles only carry `created`, which is also UTC.
	let created = d.get("created_utc").or_else(|| d.get("created")).and_then(Value::as_f64);
	put(&mut m, "created_utc", created.map(|f| Value::from(f as i64)));
	put(&mut m, "link_karma", num_of(d, "link_karma").map(Value::from));
	put(&mut m, "comment_karma", num_of(d, "comment_karma").map(Value::from));
	put(&mut m, "total_karma", num_of(d, "total_karma").map(Value::from));
	m.insert("is_employee".to_string(), Value::from(bool_of(d, "is_employee")));
	m.insert("is_mod".to_string(), Value::from(bool_of(d, "is_mod")));
	m.insert("verified".to_string(), Value::from(bool_of(d, "verified")));
	put(&mut m, "profile_url", str_of(d, "name").map(|n| Value::from(format!("https://www.reddit.com/user/{n}"))));

	if let Some(sub) = d.get("subreddit") {
		put(&mut m, "bio", str_of(sub, "public_description").map(Value::from));
	}

	Value::Object(m)
}

/// Projects a mixed listing (posts and/or comments), as returned by a user's
/// overview.
fn project_mixed(children: &[Value]) -> Vec<Value> {
	children
		.iter()
		.filter_map(|child| match child.get("kind").and_then(Value::as_str)? {
			"t3" => Some(project_post(child)),
			"t1" => {
				let d = child.get("data")?;
				Some(json!({
					"type": "comment",
					"id": str_of(d, "id"),
					"author": str_of(d, "author"),
					"body": str_of(d, "body"),
					"score": num_of(d, "score"),
					"subreddit": str_of(d, "subreddit"),
					"link_title": str_of(d, "link_title"),
					"created_utc": d.get("created_utc").and_then(Value::as_f64).map(|f| f as i64),
					"permalink": str_of(d, "permalink").map(|p| format!("https://www.reddit.com{p}")),
				}))
			}
			"t5" => Some(project_subreddit(child)),
			"t2" => Some(project_user(child)),
			_ => None,
		})
		.collect()
}

/// Wraps projected items with the pagination cursor.
fn listing_result(res: &Value, items: Vec<Value>) -> Value {
	let after = res.get("data").and_then(|d| d.get("after")).and_then(Value::as_str).filter(|s| !s.is_empty());
	json!({
		"count": items.len(),
		"after": after,
		"items": items,
	})
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

/// Every path gets `raw_json=1`: without it Reddit HTML-escapes `&`, `<`, and
/// `>` inside body text, which corrupts markdown and code blocks.
async fn get(path: String, quarantine: bool) -> Result<Value, String> {
	reddit_json(path, quarantine).await.map_err(explain_blocked)
}

/// Appended when Reddit refuses an endpoint to logged-out callers.
const BLOCKED_HINT: &str = " Reddit refuses this endpoint to callers without an account and this instance has no session for it, so retrying or changing the arguments will not help. Use a different tool, or tell the user it is unavailable.";

/// The instructions tell the model to fix its arguments and retry after an
/// error. For a block that is wasted effort, so say so.
fn explain_blocked(error: String) -> String {
	if crate::backends::is_blocked_error(&error) {
		format!("{error}{BLOCKED_HINT}")
	} else {
		error
	}
}

/// The listing path for a subreddit, a `+`-combined feed, or r/all.
///
/// Reddit's JSON API only reads `a+b` as a combined feed when the `+` is
/// percent-encoded; a literal `+` gets the default front page instead,
/// which looks like a plausible answer. The web UI encodes it the same way.
fn subreddit_listing_path(sub: &str, sort: &str, query: &str) -> String {
	format!("/r/{}/{sort}.json?{query}", sub.replace('+', "%2B"))
}

/// The fullname Reddit pages by for a projected post or comment.
fn item_fullname(item: &Value) -> Option<String> {
	if let Some(fullname) = str_of(item, "fullname") {
		return Some(fullname);
	}
	let id = str_of(item, "id")?;
	(item["type"] == "comment").then(|| format!("t1_{id}"))
}

/// Like [`listing_result`], but holds a listing to the `limit` asked for,
/// and pages it locally when the backend ignores paging.
///
/// Some endpoints ignore `limit` and `after` altogether: r/all and a user's
/// gilded items come back as the same 25 entries whatever was asked. Extra
/// entries are dropped so the result is as small as requested, and `after`
/// moves to the last entry kept. When the requested `after` turns up inside
/// the page, the backend ignored it, so the page is continued from there,
/// and once it runs out `after` is null -- Reddit's own cursor would only
/// return the same page again, and a model following it would never stop.
fn limited_listing_result(res: &Value, mut items: Vec<Value>, limit: u64, requested_after: Option<&str>) -> Value {
	let limit = usize::try_from(limit).unwrap_or(usize::MAX);
	let mut ignored_after = false;
	if let Some(requested) = requested_after.filter(|a| !a.is_empty()) {
		if let Some(pos) = items.iter().position(|i| item_fullname(i).as_deref() == Some(requested)) {
			items.drain(..=pos);
			ignored_after = true;
		}
	}
	if items.len() <= limit && !ignored_after {
		return listing_result(res, items);
	}
	let after = if items.len() > limit {
		items.truncate(limit);
		items.last().and_then(item_fullname).map_or(Value::Null, Value::from)
	} else {
		Value::Null
	};
	json!({
		"count": items.len(),
		"after": after,
		"items": items,
	})
}

pub async fn browse_subreddit(sub: &str, sort: &str, time: Option<&str>, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("sort", sort, &LISTING_SORTS)?;
	let time = time.unwrap_or("day");
	validate("time", time, &TIME_FILTERS)?;

	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}

	let q = query(&[
		("limit", limit.to_string()),
		("t", if sort == "top" || sort == "controversial" { time.to_string() } else { String::new() }),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(subreddit_listing_path(&sub, sort, &q), true).await?;
	let items: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_post).collect())
		.unwrap_or_default();

	Ok(limited_listing_result(&res, items, limit, after))
}

pub async fn browse_frontpage(feed: &str, sort: &str, time: Option<&str>, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("feed", feed, &["popular", "all", "best"])?;

	// `best` is served from the root, not from a pseudo-subreddit, so it
	// cannot go through browse_subreddit like the other two.
	if feed == "best" {
		let q = query(&[
			("limit", limit.to_string()),
			("after", after.unwrap_or_default().to_string()),
			("raw_json", "1".to_string()),
		]);
		let res = get(format!("/best.json?{q}"), true).await?;
		return Ok(listing_result(&res, project_children(&res, project_post)));
	}

	browse_subreddit(feed, sort, time, limit, after).await
}

/// Applies a projection to a standard listing's `data.children`.
fn project_children(res: &Value, f: fn(&Value) -> Value) -> Vec<Value> {
	res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(f).collect())
		.unwrap_or_default()
}

/// Posts across all subreddits that link to a given domain.
pub async fn browse_domain(domain: &str, sort: &str, time: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("sort", sort, &LISTING_SORTS)?;
	validate("time", time, &TIME_FILTERS)?;

	let domain = domain
		.trim()
		.trim_start_matches("http://")
		.trim_start_matches("https://")
		.trim_start_matches("www.")
		.split('/')
		.next()
		.unwrap_or_default();
	if domain.is_empty() {
		return Err("domain is required. Pass a site such as \"github.com\".".to_string());
	}

	let q = query(&[
		("limit", limit.to_string()),
		("t", if sort == "top" || sort == "controversial" { time.to_string() } else { String::new() }),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/domain/{domain}/{sort}.json?{q}"), true).await?;
	Ok(listing_result(&res, project_children(&res, project_post)))
}

/// Recent comments across a whole subreddit.
///
/// Reddit answers /r/<sub>/comments.json with an HTML 403 to anonymous
/// callers, and nothing else exposes the stream: search ignores type=comment
/// and by_id only resolves posts. So this reports the block rather than
/// spending a request to learn it.
pub fn get_subreddit_comments(sub: &str) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}
	Err(format!(
		"Reddit blocks the recent-comments stream of r/{sub} for anonymous callers, and this server has no account. Call browse_subreddit with sort \"new\" for the newest posts, then get_post to read the discussion under one."
	))
}

/// Picks the `num`th stickied post (1-based, listing order) from a subreddit
/// listing. Reddit puts pinned posts first in hot, and allows at most two.
fn select_sticky(listing: &Value, num: u64) -> Option<&Value> {
	if !(1..=2).contains(&num) {
		return None;
	}
	listing
		.get("data")?
		.get("children")?
		.as_array()?
		.iter()
		.filter(|c| c.get("kind").and_then(Value::as_str) == Some("t3") && c.get("data").map(|d| bool_of(d, "stickied")).unwrap_or(false))
		.nth(num as usize - 1)
}

/// A subreddit's pinned post. `num` is 1 or 2 -- Reddit allows two.
pub async fn get_sticky(sub: &str, num: u64, max_depth: u32) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}
	if num != 1 && num != 2 {
		return Err(format!("invalid num: {num} (a subreddit has at most two stickies, so this must be 1 or 2)"));
	}

	// /about/sticky.json is 403 for anonymous callers, but pinned posts lead
	// the hot listing with stickied set. Most subreddits pin nothing, which is
	// an ordinary state, so say "there isn't one" rather than failing.
	let hot = get(format!("/r/{sub}/hot.json?limit=5&raw_json=1"), true).await?;
	let id = select_sticky(&hot, num)
		.and_then(|c| c.get("data"))
		.and_then(|d| str_of(d, "id"))
		.ok_or_else(|| format!("r/{sub} has no sticky post in slot {num}"))?;

	// Comments come from the same GraphQL path get_post uses.
	get_post(&id, "confidence", 50, max_depth).await
}

/// One comment plus the replies beneath it, and optionally its ancestors.
///
/// Reddit exposes this through the post endpoint with a `comment` parameter,
/// which is why this takes both ids.
pub async fn get_comment_thread(post_id: &str, comment_id: &str, context: u64, sort: &str, max_depth: u32) -> Result<Value, String> {
	validate("comment_sort", sort, &COMMENT_SORTS)?;
	let post = extract_post_id(post_id)?;
	let comment = comment_id.trim().trim_start_matches("t1_");
	if comment.is_empty() {
		return Err("comment_id is required. Take the \"id\" field of a comment returned by get_post.".to_string());
	}

	let q = query(&[("context", context.min(8).to_string()), ("sort", sort.to_string()), ("raw_json", "1".to_string())]);

	// The backend layer answers a comment permalink path with the [post,
	// comments] shape, from GraphQL when Reddit blocks the JSON API.
	let res = get(format!("/comments/{post}/_/{comment}.json?{q}"), true).await?;
	let arr = res.as_array().ok_or("unexpected response shape from Reddit")?;

	let post_obj = arr
		.first()
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.and_then(|c| c.first())
		.map(project_post);

	let comments = with_next_page(arr.get(1), project_comments_or_empty(arr.get(1), max_depth), &post);
	if comments.is_empty() {
		return Err(format!(
			"comment {comment} was not found on post {post}. Check that both ids came from the same post -- call get_post first and take a comment id from its result."
		));
	}

	Ok(json!({ "post": post_obj, "comments": comments }))
}

/// Most ids one lookup call will resolve.
const MAX_LOOKUP_IDS: usize = 20;

/// Splits requested fullnames into post ids that can be fetched and per-item
/// errors for the rest. Reddit blocks /api/info for anonymous callers and no
/// backend rebuilds it, while /by_id only resolves posts (t3_), so comments
/// and subreddits cannot be looked up by fullname.
fn plan_lookup(ids: &[String]) -> (Vec<String>, Vec<Value>) {
	let mut fetch: Vec<String> = Vec::new();
	let mut errors = Vec::new();
	for raw in ids {
		let id = raw.trim();
		if let Some(post) = id.strip_prefix("t3_").filter(|p| !p.is_empty()) {
			if fetch.iter().any(|f| f == post) {
				continue;
			}
			if fetch.len() >= MAX_LOOKUP_IDS {
				errors.push(json!({"id": id, "error": format!("not looked up: at most {MAX_LOOKUP_IDS} ids per call. Repeat the call with the rest.")}));
			} else {
				fetch.push(post.to_string());
			}
		} else if id.starts_with("t1_") {
			errors.push(json!({"id": id, "error": "Reddit blocks fullname lookup of comments for anonymous callers. Use get_comment_thread with the post id and this comment id."}));
		} else if id.starts_with("t5_") {
			errors.push(json!({"id": id, "error": "Reddit blocks fullname lookup of subreddits for anonymous callers. Use get_subreddit_about with the subreddit name."}));
		} else {
			errors.push(json!({"id": id, "error": "not a fullname. Expected t3_<id> (post), t1_<id> (comment) or t5_<id> (subreddit)."}));
		}
	}
	(fetch, errors)
}

/// Search path that finds submissions of a URL. The url is encoded because
/// it carries its own `?` and `&`.
fn lookup_search_path(url: &str) -> String {
	let q = query(&[("q", format!("url:{url}")), ("sort", "new".to_string()), ("raw_json", "1".to_string())]);
	format!("/search.json?{q}")
}

/// The one /by_id path that fetches every planned post.
///
/// Reddit's JSON API rejects multi-id /by_id for anonymous callers, but the
/// backend layer serves it from GraphQL's PostsByIds in a single request.
fn lookup_by_id_path(ids: &[String]) -> String {
	let fullnames: Vec<String> = ids.iter().map(|id| format!("t3_{id}")).collect();
	format!("/by_id/{}.json?raw_json=1", fullnames.join(","))
}

/// Looks things up by post fullname (`t3_abc`) or by URL.
///
/// Posts are fetched together with one /by_id request; other fullnames come
/// back as per-item errors, as do posts Reddit does not return. A URL is
/// resolved with a `url:` search.
pub async fn lookup(ids: &[String], url: Option<&str>) -> Result<Value, String> {
	if let Some(url) = url.map(str::trim).filter(|u| !u.is_empty()) {
		let res = get(lookup_search_path(url), true).await?;
		return Ok(listing_result(&res, project_children(&res, project_post)));
	}
	if ids.is_empty() {
		return Err("provide either ids or url. Use ids for fullnames like \"t3_abc123\", or url to find the post that submitted a link.".to_string());
	}

	let (fetch, mut errors) = plan_lookup(ids);
	let mut items = Vec::new();
	if !fetch.is_empty() {
		let res = get(lookup_by_id_path(&fetch), true).await?;
		let found = project_children(&res, project_post);
		// Keep the caller's order, and name the ids Reddit did not return.
		for id in &fetch {
			match found.iter().find(|p| p["id"] == id.as_str()) {
				Some(post) => items.push(post.clone()),
				None => errors.push(json!({"id": format!("t3_{id}"), "error": "post not found"})),
			}
		}
	}

	let mut out = json!({ "count": items.len(), "after": null, "items": items });
	if !errors.is_empty() {
		out["errors"] = Value::Array(errors);
	}
	Ok(out)
}

/// `kind` is popular / new / default.
pub async fn list_subreddits(kind: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("kind", kind, &["popular", "new", "default"])?;
	let q = query(&[
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);
	let res = get(format!("/subreddits/{kind}.json?{q}"), false).await?;
	Ok(listing_result(&res, project_children(&res, project_subreddit)))
}

pub async fn get_user_trophies(name: &str) -> Result<Value, String> {
	let name = normalize_username(name);
	if name.is_empty() {
		return Err("username is required. Pass an account name such as \"spez\", or call search_users to find one.".to_string());
	}

	let res = get(format!("/user/{name}/trophies.json?raw_json=1"), false).await?;
	let trophies: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("trophies"))
		.and_then(Value::as_array)
		.map(|ts| {
			ts.iter()
				.filter_map(|t| {
					let d = t.get("data")?;
					Some(json!({
						"name": str_of(d, "name"),
						"description": str_of(d, "description"),
						"granted_at": num_of(d, "granted_at"),
						"url": str_of(d, "url"),
					}))
				})
				.collect()
		})
		.unwrap_or_default();

	Ok(json!({ "username": name, "count": trophies.len(), "trophies": trophies }))
}

/// Subreddits an account moderates.
///
/// Note this works even though `/r/<sub>/about/moderators` does not: Reddit
/// permits the user-to-subreddit direction anonymously but not the reverse.
pub async fn get_user_moderated_subreddits(name: &str) -> Result<Value, String> {
	let name = normalize_username(name);
	if name.is_empty() {
		return Err("username is required. Pass an account name such as \"spez\", or call search_users to find one.".to_string());
	}

	let res = get(format!("/user/{name}/moderated_subreddits.json?raw_json=1"), false).await?;

	// `data` is a bare array here, not the usual listing-with-children.
	let subs: Vec<Value> = res
		.get("data")
		.and_then(Value::as_array)
		.map(|ss| {
			ss.iter()
				.map(|s| {
					json!({
						"name": str_of(s, "display_name"),
						"title": str_of(s, "title"),
						"url": str_of(s, "url").map(|u| format!("https://www.reddit.com{u}")),
						"subscribers": num_of(s, "subscribers"),
						"over_18": bool_of(s, "over_18"),
						"subreddit_type": str_of(s, "subreddit_type"),
					})
				})
				.collect()
		})
		.unwrap_or_default();

	Ok(json!({ "username": name, "count": subs.len(), "subreddits": subs }))
}

/// Edit history for a subreddit's wiki, either overall or for one page.
pub async fn get_wiki_revisions(sub: &str, page: Option<&str>, limit: u64) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}

	let path = match page.map(str::trim).filter(|p| !p.is_empty()) {
		Some(page) => format!("/r/{sub}/wiki/revisions/{page}.json?limit={limit}&raw_json=1"),
		None => format!("/r/{sub}/wiki/revisions.json?limit={limit}&raw_json=1"),
	};

	let res = get(path, true).await?;
	if let Some(reason) = str_of(&res, "reason") {
		return Err(format!("wiki revisions for r/{sub} are unavailable: {reason}"));
	}

	let revisions: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|rs| {
			rs.iter()
				.map(|r| {
					json!({
						"id": str_of(r, "id"),
						"page": str_of(r, "page"),
						"timestamp": num_of(r, "timestamp"),
						"reason": str_of(r, "reason"),
						"author": r.get("author").and_then(|a| a.get("data")).and_then(|d| str_of(d, "name")),
					})
				})
				.collect()
		})
		.unwrap_or_default();

	Ok(json!({ "subreddit": sub, "count": revisions.len(), "revisions": revisions }))
}

/// Fetches a post together with its comment tree.
pub async fn get_post(post_id: &str, sort: &str, limit: u64, max_depth: u32) -> Result<Value, String> {
	validate("comment_sort", sort, &COMMENT_SORTS)?;
	let id = extract_post_id(post_id)?;

	// Reddit 403s anonymous /comments/ JSON; the backend layer then loads the
	// same [post, comments] shape from GraphQL, which ignores limit (it
	// returns up to 200).
	let q = query(&[("sort", sort.to_string()), ("limit", limit.to_string()), ("raw_json", "1".to_string())]);
	let res = get(format!("/comments/{id}.json?{q}"), true).await?;

	// This endpoint returns a two-element array: the post, then the comments.
	let arr = res.as_array().ok_or("unexpected response shape from Reddit")?;
	let post = arr
		.first()
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.and_then(|c| c.first())
		.map(project_post)
		.ok_or("no post found with that id. Post ids come from browse_subreddit, search_posts, or lookup; they cannot be constructed by hand.")?;

	let comments = with_next_page(arr.get(1), project_comments_or_empty(arr.get(1), max_depth), &id);

	Ok(json!({ "post": post, "comments": comments }))
}

fn project_comments_or_empty(listing: Option<&Value>, max_depth: u32) -> Vec<Value> {
	listing.map(|l| project_comments(l, 0, max_depth)).unwrap_or_default()
}

/// GraphQL threads report the next page of top-level comments as the
/// listing's `after`; surface it as a `more` entry like any other branch.
fn with_next_page(listing: Option<&Value>, mut comments: Vec<Value>, post: &str) -> Vec<Value> {
	if let Some(after) = listing.and_then(|l| l.get("data")).and_then(|d| str_of(d, "after")).filter(|a| !a.is_empty()) {
		comments.push(json!({ "type": "more", "parent_id": format!("t3_{post}"), "cursor": after }));
	}
	comments
}

/// The thread path that loads the comments behind a `more` cursor.
///
/// The cursor itself says where it points, so this is the bare post path the
/// web UI's "more comments" links use, whatever the parent; the backend layer
/// routes it to the backend that issued the cursor.
fn more_comments_path(post: &str, cursor: &str, sort: &str) -> String {
	let q = query(&[("sort", sort.to_string()), ("raw_json", "1".to_string())]);
	format!("/comments/{post}.json?{}&{q}", cursor_query(cursor))
}

/// Fetches the comments behind a `more` cursor, as a tree.
///
/// `parent_id` is accepted for compatibility with clients that pass the whole
/// `more` entry back; the cursor alone identifies the branch.
pub async fn get_more_comments_cursor(post_id: &str, cursor: &str, _parent_id: Option<&str>, sort: &str, max_depth: u32) -> Result<Value, String> {
	validate("comment_sort", sort, &COMMENT_SORTS)?;
	let id = extract_post_id(post_id)?;
	let res = get(more_comments_path(&id, cursor, sort), true).await?;
	let arr = res.as_array().ok_or("unexpected response shape from Reddit")?;
	let comments = with_next_page(arr.get(1), project_comments_or_empty(arr.get(1), max_depth), &id);
	Ok(json!({ "comments": comments }))
}

pub async fn search_posts(q: &str, sub: Option<&str>, sort: &str, time: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("sort", sort, &SEARCH_SORTS)?;
	validate("time", time, &TIME_FILTERS)?;
	if q.trim().is_empty() {
		return Err("query is required. Pass the words to search for.".to_string());
	}

	let mut pairs = vec![
		("q", q.to_string()),
		("sort", sort.to_string()),
		("t", time.to_string()),
		("limit", limit.to_string()),
		("type", "link".to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	];

	let path = match sub.map(normalize_subreddit).filter(|s| !s.is_empty()) {
		Some(sub) => {
			// Without this Reddit widens a subreddit search to the whole site.
			pairs.push(("restrict_sr", "1".to_string()));
			format!("/r/{sub}/search.json?{}", query(&pairs))
		}
		None => format!("/search.json?{}", query(&pairs)),
	};

	let res = get(path, true).await?;
	let items: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_post).collect())
		.unwrap_or_default();

	Ok(listing_result(&res, items))
}

pub async fn search_subreddits(q: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	if q.trim().is_empty() {
		return Err("query is required. Pass the words to search for.".to_string());
	}
	let qs = query(&[
		("q", q.to_string()),
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);
	let res = get(format!("/subreddits/search.json?{qs}"), false).await?;
	let items: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_subreddit).collect())
		.unwrap_or_default();
	Ok(listing_result(&res, items))
}

pub async fn search_users(q: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	if q.trim().is_empty() {
		return Err("query is required. Pass the words to search for.".to_string());
	}
	let qs = query(&[
		("q", q.to_string()),
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);
	let res = get(format!("/users/search.json?{qs}"), false).await?;
	let items: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_user).collect())
		.unwrap_or_default();
	Ok(listing_result(&res, items))
}

pub async fn get_user(name: &str) -> Result<Value, String> {
	let name = normalize_username(name);
	if name.is_empty() {
		return Err("username is required. Pass an account name such as \"spez\", or call search_users to find one.".to_string());
	}
	let res = get(format!("/user/{name}/about.json?raw_json=1"), false).await?;
	Ok(project_user(&res))
}

/// `listing` is one of submitted / comments / overview.
pub async fn get_user_listing(name: &str, listing: &str, sort: &str, time: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("listing", listing, &["submitted", "comments", "overview", "gilded"])?;
	validate("sort", sort, &["hot", "new", "top", "controversial"])?;
	validate("time", time, &TIME_FILTERS)?;

	let name = normalize_username(name);
	if name.is_empty() {
		return Err("username is required. Pass an account name such as \"spez\", or call search_users to find one.".to_string());
	}

	let qs = query(&[
		("sort", sort.to_string()),
		("t", time.to_string()),
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/user/{name}/{listing}.json?{qs}"), false).await?;
	let children = res.get("data").and_then(|d| d.get("children")).and_then(Value::as_array).cloned().unwrap_or_default();
	// The JSON API's gilded listing ignores limit.
	Ok(limited_listing_result(&res, project_mixed(&children), limit, after))
}

pub async fn get_subreddit_about(sub: &str) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}
	let res = get(format!("/r/{sub}/about.json?raw_json=1"), true).await?;
	Ok(project_subreddit(&res))
}

pub async fn get_subreddit_rules(sub: &str) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}
	let res = get(format!("/r/{sub}/about/rules.json?raw_json=1"), true).await?;

	let rules: Vec<Value> = res
		.get("rules")
		.and_then(Value::as_array)
		.map(|rs| {
			rs.iter()
				.map(|r| {
					json!({
						"short_name": str_of(r, "short_name"),
						"description": str_of(r, "description"),
						"kind": str_of(r, "kind"),
						"violation_reason": str_of(r, "violation_reason"),
						"priority": num_of(r, "priority"),
					})
				})
				.collect()
		})
		.unwrap_or_default();

	Ok(json!({ "subreddit": sub, "count": rules.len(), "rules": rules }))
}

pub async fn get_wiki(sub: &str, page: Option<&str>) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required. Pass a community name such as \"rust\", or call search_subreddits to find one.".to_string());
	}

	match page.map(str::trim).filter(|p| !p.is_empty()) {
		Some(page) => {
			let res = get(format!("/r/{sub}/wiki/{page}.json?raw_json=1"), true).await?;

			// A missing page comes back 200 with {"message": "Not Found",
			// "reason": "PAGE_NOT_FOUND"} rather than an HTTP error. Without
			// this check the projection below would happily emit
			// content_md: null, which reads as "the page exists but is empty".
			if let Some(reason) = str_of(&res, "reason") {
				return Err(format!("wiki page {page:?} in r/{sub} is unavailable: {reason}"));
			}

			let d = res.get("data").unwrap_or(&res);
			let content = str_of(d, "content_md").ok_or_else(|| format!("wiki page {page:?} in r/{sub} returned no content"))?;

			Ok(json!({
				"subreddit": sub,
				"page": page,
				"content_md": content,
				"revision_date": num_of(d, "revision_date"),
			}))
		}
		None => {
			let res = get(format!("/r/{sub}/wiki/pages.json?raw_json=1"), true).await?;
			let pages = res.get("data").cloned().unwrap_or(Value::Array(Vec::new()));
			Ok(json!({ "subreddit": sub, "pages": pages }))
		}
	}
}

/// Other submissions of the same link -- Reddit's "other discussions".
pub async fn get_duplicates(post_id: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	let id = extract_post_id(post_id)?;
	let qs = query(&[
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/duplicates/{id}.json?{qs}"), true).await?;
	let arr = res.as_array().ok_or("unexpected response shape from Reddit")?;

	// Element 0 is the original post, element 1 the duplicates.
	let original = arr
		.first()
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.and_then(|c| c.first())
		.map(project_post);

	let dupes: Vec<Value> = arr
		.get(1)
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_post).collect())
		.unwrap_or_default();

	// Reddit's anonymous /duplicates answers with an empty list even when the
	// same link was submitted elsewhere. For a link post, fall back to the
	// url: search that lookup uses, so "nobody else posted this" is not
	// reported on Reddit's say-so alone.
	if dupes.is_empty() && after.is_none() {
		if let Some(url) = original.as_ref().filter(|p| p["is_self"] == false).and_then(|p| str_of(p, "url")) {
			let res = get(lookup_search_path(&url), true).await?;
			let found = other_submissions(project_children(&res, project_post), &id, limit);
			return Ok(json!({ "original": original, "count": found.len(), "duplicates": found }));
		}
	}

	Ok(json!({ "original": original, "count": dupes.len(), "duplicates": dupes }))
}

/// Search results for a post's link, without the post itself.
fn other_submissions(mut found: Vec<Value>, original_id: &str, limit: u64) -> Vec<Value> {
	found.retain(|p| p["id"] != original_id);
	found.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
	found
}

/// Escape hatch for endpoints this module does not model.
///
/// `/api/` read endpoints that work anonymously. `/api/info` and
/// `/api/morechildren` are deliberately absent: Reddit answers both with an
/// HTML 403, so allowing them would only produce parse errors.
const ALLOWED_API_READS: [&str; 2] = ["/api/subreddit_autocomplete", "/api/multi"];

/// Restricted to GET-shaped read paths. The token is anonymous so there is no
/// account to damage, but a stray call to a write endpoint would still be a
/// confusing failure, and Reddit's own `/api/` surface is mostly mutating.
pub async fn raw_api(path: &str) -> Result<Value, String> {
	let path = path.trim();
	if !path.starts_with('/') {
		return Err("path must start with '/'".to_string());
	}
	if path.contains("..") {
		return Err("path must not contain '..'".to_string());
	}

	// Allow the handful of /api/ read endpoints we know are safe; reject the
	// rest, which are all mutations.
	if path.starts_with("/api/") && !ALLOWED_API_READS.iter().any(|a| path.starts_with(a)) {
		return Err(format!(
			"refusing to call {path}: only read endpoints are permitted. Allowed /api/ paths: {}",
			ALLOWED_API_READS.join(", ")
		));
	}

	let res = get(path.to_string(), true).await?;

	// Some endpoints answer 200 with an error envelope instead of an HTTP
	// error -- the flair endpoints return {"json":{"errors":[["USER_REQUIRED",
	// ...]]}} for an anonymous token. Without this the caller would treat a
	// refusal as a successful empty result.
	if let Some(errors) = res.get("json").and_then(|j| j.get("errors")).and_then(Value::as_array) {
		if !errors.is_empty() {
			return Err(format!("Reddit refused {path}: {}", Value::Array(errors.clone())));
		}
	}

	Ok(res)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn normalizes_subreddit_forms() {
		for input in ["rust", "r/rust", "/r/rust", "/r/rust/"] {
			assert_eq!(normalize_subreddit(input), "rust", "input was {input:?}");
		}
	}

	#[test]
	fn normalizes_username_forms() {
		for input in ["spez", "u/spez", "/u/spez", "user/spez"] {
			assert_eq!(normalize_username(input), "spez", "input was {input:?}");
		}
	}

	#[test]
	fn extracts_post_id_from_every_accepted_form() {
		assert_eq!(extract_post_id("1abc234").unwrap(), "1abc234");
		assert_eq!(extract_post_id("t3_1abc234").unwrap(), "1abc234");
		assert_eq!(extract_post_id("https://www.reddit.com/r/rust/comments/1abc234/some_title/").unwrap(), "1abc234");
		assert_eq!(extract_post_id("/r/rust/comments/1abc234/some_title").unwrap(), "1abc234");
		assert_eq!(extract_post_id("https://redd.it/1abc234").unwrap(), "1abc234");
	}

	#[test]
	fn rejects_empty_post_id() {
		assert!(extract_post_id("   ").is_err());
	}

	#[test]
	fn clamps_limit_into_reddits_accepted_range() {
		assert_eq!(clamp_limit(None), 25);
		assert_eq!(clamp_limit(Some(0)), 1);
		assert_eq!(clamp_limit(Some(500)), 100);
		assert_eq!(clamp_limit(Some(50)), 50);
	}

	#[test]
	fn validate_reports_allowed_values() {
		assert!(validate("sort", "hot", &LISTING_SORTS).is_ok());
		let err = validate("sort", "bogus", &LISTING_SORTS).unwrap_err();
		assert!(err.contains("bogus") && err.contains("hot"), "unhelpful message: {err}");
	}

	#[test]
	fn raw_api_blocks_mutating_endpoints() {
		// These are the ones that would actually do damage with a user token,
		// and are nonsense with an anonymous one.
		for path in ["/api/vote", "/api/comment", "/api/submit", "/api/subscribe"] {
			assert!(futures_lite::future::block_on(raw_api(path)).is_err(), "{path} should be refused");
		}
	}

	#[test]
	fn raw_api_rejects_traversal_and_relative_paths() {
		assert!(futures_lite::future::block_on(raw_api("r/rust/hot.json")).is_err());
		assert!(futures_lite::future::block_on(raw_api("/r/../../etc/passwd")).is_err());
	}

	#[test]
	fn projects_score_hidden_distinctly_from_zero() {
		let post = json!({"data": {"id": "abc", "title": "t", "score": 0, "hide_score": true}});
		let p = project_post(&post);
		assert_eq!(p["score"], 0);
		assert_eq!(p["score_hidden"], true);
	}

	#[test]
	fn projects_more_nodes_and_drops_empty_ones() {
		let listing = json!({"data": {"children": [
			{"kind": "more", "data": {"count": 5, "parent_id": "t1_x", "children": ["a", "b"]}},
			{"kind": "more", "data": {"count": 0, "parent_id": "t1_y", "children": []}}
		]}});
		let out = project_comments(&listing, 0, 5);
		assert_eq!(out.len(), 1, "the empty continue-thread marker should be dropped");
		assert_eq!(out[0]["type"], "more");
		assert_eq!(out[0]["comment_ids"], json!(["a", "b"]));
	}

	#[test]
	fn projects_graphql_more_cursors() {
		// The shape the GraphQL backend gives a 'more' node: an empty id, the
		// cursor in its own field, and the more_query that names the backend.
		let listing = json!({"data": {"after": "next", "children": [
			{"kind": "more", "data": {"id": "", "count": 7, "parent_id": "t1_x", "cursor": "Y3Vyc29y", "more_query": "gql"}},
			{"kind": "more", "data": {"id": "", "count": 0, "parent_id": "t1_y", "cursor": "", "more_query": "gql"}}
		]}});
		let out = with_next_page(Some(&listing), project_comments(&listing, 0, 5), "abc");
		assert_eq!(out.len(), 2, "an empty cursor carries nothing to fetch");
		assert_eq!(out[0]["cursor"], "Y3Vyc29y", "GraphQL cursors pass through unchanged");
		assert_eq!(out[0]["parent_id"], "t1_x");
		assert_eq!(out[0]["count"], 7);
		assert_eq!(out[1], json!({"type": "more", "parent_id": "t3_abc", "cursor": "next"}));
	}

	#[test]
	fn graphql_cursors_load_through_the_graphql_backend() {
		let path = more_comments_path("abc", "Y3Vyc29y==", "top");
		assert!(path.starts_with("/comments/abc.json?"), "{path}");
		assert_eq!(crate::backends::Kind::of(&path), crate::backends::Kind::Comments);
		let query = format!("?{}", path.split_once('?').unwrap().1);
		assert_eq!(crate::utils::param(&query, "more_cursor").as_deref(), Some("Y3Vyc29y=="));
		assert_eq!(crate::utils::param(&query, "more_query").as_deref(), Some(MORE_QUERY));
		assert_eq!(crate::utils::param(&query, "sort").as_deref(), Some("top"));
	}

	#[test]
	fn live_shaped_graphql_cursors_are_not_mistaken_for_foreign_ones() {
		// Real GraphQL cursors contain ':' and arbitrary punctuation.
		let cursor = "commenttree:60fe9b44,::0:ex:,WaKUF47N':%BSS<JOa*5ac\\H57{At";
		let listing = json!({"data": {"children": [
			{"kind": "more", "data": {"id": "", "count": 9, "parent_id": "t3_abc", "cursor": cursor, "more_query": "gql"}}
		]}});
		assert_eq!(project_comments(&listing, 0, 5)[0]["cursor"], cursor);
		let path = more_comments_path("abc", cursor, "confidence");
		let query = format!("?{}", path.split_once('?').unwrap().1);
		assert_eq!(crate::utils::param(&query, "more_cursor").as_deref(), Some(cursor));
		assert_eq!(crate::utils::param(&query, "more_query").as_deref(), Some(MORE_QUERY));
	}

	#[test]
	fn scraped_cursors_keep_their_more_query() {
		// The scraper's cursors only load together with their more_query, so
		// the cursor handed out has to carry it back.
		let listing = json!({"data": {"children": [
			{"kind": "more", "data": {"id": "", "count": 40, "parent_id": "t3_abc", "cursor": "c=1&d", "more_query": "top-level=1&comments-remaining=40"}}
		]}});
		let out = project_comments(&listing, 0, 5);
		let cursor = out[0]["cursor"].as_str().unwrap();
		assert_ne!(cursor, "c=1&d");

		let path = more_comments_path("abc", cursor, "confidence");
		let query = format!("?{}", path.split_once('?').unwrap().1);
		assert_eq!(crate::utils::param(&query, "more_cursor").as_deref(), Some("c=1&d"));
		assert_eq!(crate::utils::param(&query, "more_query").as_deref(), Some("top-level=1&comments-remaining=40"));
	}

	#[test]
	fn selects_stickied_posts_in_listing_order() {
		let hot = json!({"data": {"children": [
			{"kind": "t3", "data": {"id": "first", "stickied": true}},
			{"kind": "t3", "data": {"id": "second", "stickied": true}},
			{"kind": "t3", "data": {"id": "plain", "stickied": false}},
			{"kind": "t3", "data": {"id": "late", "stickied": true}}
		]}});
		assert_eq!(select_sticky(&hot, 1).unwrap()["data"]["id"], "first");
		assert_eq!(select_sticky(&hot, 2).unwrap()["data"]["id"], "second");
		assert!(select_sticky(&hot, 3).is_none(), "only two sticky slots exist");

		let one = json!({"data": {"children": [
			{"kind": "t3", "data": {"id": "plain"}},
			{"kind": "t3", "data": {"id": "pinned", "stickied": true}}
		]}});
		assert_eq!(select_sticky(&one, 1).unwrap()["data"]["id"], "pinned");
		assert!(select_sticky(&one, 2).is_none());
		assert!(select_sticky(&json!({"data": {"children": []}}), 1).is_none());
	}

	#[test]
	fn plans_lookup_into_by_id_requests_and_per_item_errors() {
		let ids: Vec<String> = ["t3_abc", "t3_abc", "t1_def", "t5_ghi", "xyz", " t3_jkl "].iter().map(ToString::to_string).collect();
		let (fetch, errors) = plan_lookup(&ids);
		assert_eq!(fetch, vec!["abc", "jkl"], "t3 ids are deduplicated and stripped of the prefix");
		assert_eq!(errors.len(), 3);
		assert_eq!(errors[0]["id"], "t1_def");
		assert!(errors[0]["error"].as_str().unwrap().contains("anonymous"), "{}", errors[0]);
		assert_eq!(errors[1]["id"], "t5_ghi");
		assert_eq!(errors[2]["id"], "xyz");
		assert!(errors[2]["error"].as_str().unwrap().contains("fullname"), "{}", errors[2]);
	}

	#[test]
	fn plan_lookup_bounds_the_number_of_requests() {
		let ids: Vec<String> = (0..MAX_LOOKUP_IDS + 5).map(|i| format!("t3_id{i}")).collect();
		let (fetch, errors) = plan_lookup(&ids);
		assert_eq!(fetch.len(), MAX_LOOKUP_IDS);
		assert_eq!(errors.len(), 5);
		assert!(errors[0]["error"].as_str().unwrap().contains("at most"), "{}", errors[0]);
	}

	#[test]
	fn duplicate_fallback_leaves_out_the_original() {
		let found = vec![json!({"id": "a"}), json!({"id": "orig"}), json!({"id": "b"}), json!({"id": "c"})];
		let out = other_submissions(found, "orig", 2);
		assert_eq!(out, vec![json!({"id": "a"}), json!({"id": "b"})]);
	}

	#[test]
	fn user_age_falls_back_to_created() {
		let user = json!({"kind": "t2", "data": {"name": "spez", "created": 1118030400.0, "total_karma": 5}});
		let p = project_user(&user);
		assert_eq!(p["created_utc"], 1118030400_i64);
		assert_eq!(p["total_karma"], 5);
	}

	#[test]
	fn blocked_errors_tell_the_model_not_to_retry() {
		let blocked = "Reddit blocked this request (403 Forbidden): Reddit only serves this page to logged-in sessions. | /user/spez/trophies.json".to_string();
		let out = explain_blocked(blocked.clone());
		assert!(out.starts_with(&blocked));
		assert!(out.contains("will not help"), "{out}");
		assert_eq!(explain_blocked("private".to_string()), "private", "other errors pass through");
	}

	#[test]
	fn combined_feeds_encode_the_plus() {
		assert_eq!(subreddit_listing_path("rust+golang", "hot", "limit=3"), "/r/rust%2Bgolang/hot.json?limit=3");
		assert_eq!(subreddit_listing_path("rust", "new", "limit=3"), "/r/rust/new.json?limit=3");
		// r/all must keep its own route so the backend layer can serve it.
		assert_eq!(crate::backends::Kind::of(&subreddit_listing_path("all", "hot", "")), crate::backends::Kind::All);
	}

	#[test]
	fn listings_are_held_to_the_requested_limit() {
		let res = json!({"data": {"after": "t3_e", "children": []}});
		let items: Vec<Value> = ["a", "b", "c", "d", "e"].iter().map(|id| json!({"id": id, "fullname": format!("t3_{id}")})).collect();
		let out = limited_listing_result(&res, items.clone(), 3, None);
		assert_eq!(out["count"], 3);
		assert_eq!(out["after"], "t3_c", "the next page must start after the last post kept");
		let all = limited_listing_result(&res, items, 5, None);
		assert_eq!(all["count"], 5);
		assert_eq!(all["after"], "t3_e");
	}

	#[test]
	fn listings_that_ignore_after_are_paged_locally_and_end() {
		// Reddit answered with the same page although `after` was t3_b.
		let res = json!({"data": {"after": "t3_e", "children": []}});
		let items: Vec<Value> = ["a", "b", "c", "d", "e"].iter().map(|id| json!({"id": id, "fullname": format!("t3_{id}")})).collect();
		let next = limited_listing_result(&res, items.clone(), 2, Some("t3_b"));
		assert_eq!(next["items"], json!([items[2], items[3]]));
		assert_eq!(next["after"], "t3_d");
		let last = limited_listing_result(&res, items.clone(), 2, Some("t3_d"));
		assert_eq!(last["items"], json!([items[4]]));
		assert_eq!(last["after"], Value::Null, "Reddit's cursor would only repeat the page");
		// A backend that honoured `after` is left alone.
		let honoured = limited_listing_result(&res, items[..2].to_vec(), 2, Some("t3_z"));
		assert_eq!(honoured["after"], "t3_e");
	}

	#[test]
	fn held_mixed_listings_page_after_the_last_comment_kept() {
		let res = json!({"data": {"after": "t1_z", "children": []}});
		let items = vec![
			json!({"id": "p", "fullname": "t3_p"}),
			json!({"type": "comment", "id": "c"}),
			json!({"type": "comment", "id": "d"}),
		];
		assert_eq!(limited_listing_result(&res, items, 2, None)["after"], "t1_c");
	}

	#[test]
	fn lookup_fetches_every_post_in_one_by_id_request() {
		let ids = vec!["abc".to_string(), "jkl".to_string()];
		let path = lookup_by_id_path(&ids);
		assert_eq!(path, "/by_id/t3_abc,t3_jkl.json?raw_json=1");
		assert_eq!(crate::backends::Kind::of(&path), crate::backends::Kind::Post);
	}

	#[test]
	fn crosspost_parent_falls_back_to_the_parent_list() {
		let post = json!({"data": {"id": "abc", "crosspost_parent_list": [{"name": "t3_parent"}]}});
		assert_eq!(project_post(&post)["crosspost_parent"], "t3_parent");
	}

	#[test]
	fn url_lookup_goes_through_search() {
		let path = lookup_search_path("https://example.com/a?b=c&d=e");
		assert!(path.starts_with("/search.json?"), "{path}");
		assert!(path.contains("q=url%3A"), "{path}");
		assert!(!path.contains("b=c&d=e"), "the url must be encoded so its own & does not split the query: {path}");
	}

	#[test]
	fn raw_api_no_longer_allows_blocked_api_endpoints() {
		// Reddit answers these with an HTML 403 to anonymous callers, so
		// advertising them as allowed would only produce confusing parse errors.
		assert!(!ALLOWED_API_READS.contains(&"/api/morechildren"));
		assert!(!ALLOWED_API_READS.contains(&"/api/info"));
		for path in ["/api/morechildren.json", "/api/info.json?id=t3_abc"] {
			assert!(futures_lite::future::block_on(raw_api(path)).is_err(), "{path} should be refused");
		}
	}

	#[test]
	fn marks_truncation_at_max_depth_instead_of_silently_stopping() {
		let listing = json!({"data": {"children": [
			{"kind": "t1", "data": {"id": "p", "body": "parent",
				"replies": {"data": {"children": [
					{"kind": "t1", "data": {"id": "c", "body": "child"}}
				]}}}}
		]}});

		let deep = project_comments(&listing, 0, 5);
		assert!(deep[0]["replies"].is_array());

		let shallow = project_comments(&listing, 0, 0);
		assert!(shallow[0].get("replies").is_none());
		assert_eq!(shallow[0]["replies_truncated"], true);
	}

	#[test]
	fn omits_absent_fields_rather_than_emitting_null() {
		let post = json!({"data": {"id": "abc"}});
		let p = project_post(&post);
		assert!(p.get("title").is_none(), "absent fields should be omitted, got {p}");
		assert!(p.get("selftext").is_none());
	}
}
