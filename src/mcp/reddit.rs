//! Reddit API projection layer for the MCP server.
//!
//! Everything here goes through [`crate::client::json`], which is the valuable
//! part of redlib to reuse: it carries the spoofed-device OAuth token, token
//! refresh, rate-limit accounting, and Reddit's quarantine handling.
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

use crate::client::json as reddit_json;

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
		return Err("post id is empty".to_string());
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
	put(&mut m, "crosspost_parent", str_of(d, "crosspost_parent").map(Value::from));

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

/// Projects a comment tree, recursively, up to `max_depth`.
///
/// Reddit represents elided branches as `kind: "more"` nodes. Those are
/// surfaced as `{"type": "more", ...}` entries carrying their child ids rather
/// than silently dropped, so a caller can decide to fetch them via
/// `get_more_comments`.
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
	put(&mut m, "created_utc", d.get("created_utc").and_then(Value::as_f64).map(|f| Value::from(f as i64)));
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
	reddit_json(path, quarantine).await
}

pub async fn browse_subreddit(sub: &str, sort: &str, time: Option<&str>, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("sort", sort, &LISTING_SORTS)?;
	let time = time.unwrap_or("day");
	validate("time", time, &TIME_FILTERS)?;

	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required".to_string());
	}

	let q = query(&[
		("limit", limit.to_string()),
		("t", if sort == "top" || sort == "controversial" { time.to_string() } else { String::new() }),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/r/{sub}/{sort}.json?{q}"), true).await?;
	let items: Vec<Value> = res
		.get("data")
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.map(|c| c.iter().map(project_post).collect())
		.unwrap_or_default();

	Ok(listing_result(&res, items))
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
		return Err("domain is required".to_string());
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

/// Recent comments across a whole subreddit, newest first.
///
/// This is the comment firehose, unrelated to any single post -- useful for
/// gauging what a community is actively talking about.
pub async fn get_subreddit_comments(sub: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required".to_string());
	}

	let q = query(&[
		("limit", limit.to_string()),
		("after", after.unwrap_or_default().to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/r/{sub}/comments.json?{q}"), true).await?;
	let children = res.get("data").and_then(|d| d.get("children")).and_then(Value::as_array).cloned().unwrap_or_default();
	Ok(listing_result(&res, project_mixed(&children)))
}

/// A subreddit's pinned post. `num` is 1 or 2 -- Reddit allows two.
pub async fn get_sticky(sub: &str, num: u64, max_depth: u32) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required".to_string());
	}
	if num != 1 && num != 2 {
		return Err(format!("invalid num: {num} (a subreddit has at most two stickies, so this must be 1 or 2)"));
	}

	// Reddit answers 404 when the slot is empty, which is an ordinary state --
	// most subreddits pin nothing. Passing the raw HTTP error through would
	// read as a broken call rather than "there isn't one".
	let res = get(format!("/r/{sub}/about/sticky.json?num={num}&raw_json=1"), true).await.map_err(|e| {
		if e.contains("404") {
			format!("r/{sub} has no sticky post in slot {num}")
		} else {
			e
		}
	})?;

	// Same two-element [post, comments] shape as /comments/<id>.
	let arr = res.as_array().ok_or_else(|| format!("r/{sub} has no sticky post in slot {num}"))?;
	let post = arr
		.first()
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.and_then(|c| c.first())
		.map(project_post)
		.ok_or_else(|| format!("r/{sub} has no sticky post at position {num}"))?;

	let comments = arr.get(1).map(|l| project_comments(l, 0, max_depth)).unwrap_or_default();
	Ok(json!({ "post": post, "comments": comments }))
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
		return Err("comment_id is required".to_string());
	}

	let q = query(&[
		("comment", comment.to_string()),
		("context", context.min(8).to_string()),
		("sort", sort.to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/comments/{post}.json?{q}"), true).await?;
	let arr = res.as_array().ok_or("unexpected response shape from Reddit")?;

	let post_obj = arr
		.first()
		.and_then(|l| l.get("data"))
		.and_then(|d| d.get("children"))
		.and_then(Value::as_array)
		.and_then(|c| c.first())
		.map(project_post);

	let comments = arr.get(1).map(|l| project_comments(l, 0, max_depth)).unwrap_or_default();
	if comments.is_empty() {
		return Err(format!("comment {comment} was not found on post {post}"));
	}

	Ok(json!({ "post": post_obj, "comments": comments }))
}

/// Looks things up by fullname (`t3_abc`, `t1_def`, `t5_ghi`) or by URL.
///
/// The cheapest way to resolve a batch of ids in one call, and the only way to
/// go from an arbitrary link back to the post that submitted it.
pub async fn lookup(ids: &[String], url: Option<&str>) -> Result<Value, String> {
	let q = if let Some(url) = url.map(str::trim).filter(|u| !u.is_empty()) {
		query(&[("url", url.to_string()), ("raw_json", "1".to_string())])
	} else if !ids.is_empty() {
		query(&[("id", ids.join(",")), ("raw_json", "1".to_string())])
	} else {
		return Err("provide either ids or url".to_string());
	};

	let res = get(format!("/api/info.json?{q}"), true).await?;
	let children = res.get("data").and_then(|d| d.get("children")).and_then(Value::as_array).cloned().unwrap_or_default();
	Ok(listing_result(&res, project_mixed(&children)))
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
		return Err("username is required".to_string());
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
		return Err("username is required".to_string());
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
		return Err("subreddit is required".to_string());
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
		.ok_or("post not found")?;

	let comments = arr.get(1).map(|l| project_comments(l, 0, max_depth)).unwrap_or_default();

	Ok(json!({ "post": post, "comments": comments }))
}

/// Fetches comments elided behind a `more` node.
pub async fn get_more_comments(post_id: &str, comment_ids: &[String], sort: &str) -> Result<Value, String> {
	validate("comment_sort", sort, &COMMENT_SORTS)?;
	let id = extract_post_id(post_id)?;
	if comment_ids.is_empty() {
		return Err("comment_ids is empty".to_string());
	}

	// The api/morechildren endpoint needs a t3_ fullname for link_id.
	let q = query(&[
		("link_id", format!("t3_{id}")),
		("children", comment_ids.join(",")),
		("sort", sort.to_string()),
		("api_type", "json".to_string()),
		("raw_json", "1".to_string()),
	]);

	let res = get(format!("/api/morechildren.json?{q}"), true).await?;
	let things = res
		.get("json")
		.and_then(|j| j.get("data"))
		.and_then(|d| d.get("things"))
		.and_then(Value::as_array)
		.cloned()
		.unwrap_or_default();

	// morechildren returns a flat list, not a tree; callers reassemble via
	// parent_id if they need the hierarchy.
	let comments: Vec<Value> = things
		.iter()
		.filter(|t| t.get("kind").and_then(Value::as_str) == Some("t1"))
		.filter_map(|t| {
			let d = t.get("data")?;
			Some(json!({
				"type": "comment",
				"id": str_of(d, "id"),
				"parent_id": str_of(d, "parent_id"),
				"author": str_of(d, "author"),
				"body": str_of(d, "body"),
				"score": num_of(d, "score"),
				"created_utc": d.get("created_utc").and_then(Value::as_f64).map(|f| f as i64),
			}))
		})
		.collect();

	Ok(json!({ "count": comments.len(), "comments": comments }))
}

pub async fn search_posts(q: &str, sub: Option<&str>, sort: &str, time: &str, limit: u64, after: Option<&str>) -> Result<Value, String> {
	validate("sort", sort, &SEARCH_SORTS)?;
	validate("time", time, &TIME_FILTERS)?;
	if q.trim().is_empty() {
		return Err("query is required".to_string());
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
		return Err("query is required".to_string());
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
		return Err("query is required".to_string());
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
		return Err("username is required".to_string());
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
		return Err("username is required".to_string());
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
	Ok(listing_result(&res, project_mixed(&children)))
}

pub async fn get_subreddit_about(sub: &str) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required".to_string());
	}
	let res = get(format!("/r/{sub}/about.json?raw_json=1"), true).await?;
	Ok(project_subreddit(&res))
}

pub async fn get_subreddit_rules(sub: &str) -> Result<Value, String> {
	let sub = normalize_subreddit(sub);
	if sub.is_empty() {
		return Err("subreddit is required".to_string());
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
		return Err("subreddit is required".to_string());
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

	Ok(json!({ "original": original, "count": dupes.len(), "duplicates": dupes }))
}

/// Escape hatch for endpoints this module does not model.
///
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
	const ALLOWED_API_READS: [&str; 4] = ["/api/morechildren", "/api/info", "/api/subreddit_autocomplete", "/api/multi"];
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
