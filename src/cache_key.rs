//! Keys for the caches that sit in front of Reddit.
//!
//! The caches hold entries by count, and a thread page is megabytes, so a
//! visitor who can make up keys can fill the memory with copies of one page.
//! These functions leave a key only the parts that change what Reddit sends.

use std::collections::BTreeMap;

/// The longest path segment (between two slashes) that is looked up.
pub const MAX_SEGMENT_LEN: usize = 256;

/// Query parameters that change what Reddit sends, or what a backend makes of
/// it. A parameter that is not here is not sent to Reddit either.
const QUERY_KEYS: &[&str] = &[
	"after",
	"before",
	"context",
	"count",
	"depth",
	"geo_filter",
	"include_over_18",
	"limit",
	"more_cursor",
	"more_query",
	"post_types",
	"q",
	"raw_json",
	"restrict_sr",
	"sort",
	"t",
	"type",
];

/// The key for a fetch of `path` (a Reddit JSON API path with its query), or
/// `None` if a path segment is longer than `MAX_SEGMENT_LEN`. The key is
/// `path` with only the parameters in `QUERY_KEYS`, sorted by name and with
/// the last of any repeated one, as `utils::param` reads them.
pub fn fetch_key(path: &str) -> Option<String> {
	let (route, query) = path.split_once('?').unwrap_or((path, ""));
	if !segments_within_limit(route) {
		return None;
	}

	let mut kept = BTreeMap::new();
	for pair in query.split('&') {
		if let Some((key, value)) = pair.split_once('=') {
			if QUERY_KEYS.contains(&key) {
				kept.insert(key, value);
			}
		}
	}
	if kept.is_empty() {
		return Some(route.to_string());
	}
	let query: Vec<String> = kept.into_iter().map(|(key, value)| format!("{key}={value}")).collect();
	Some(format!("{route}?{}", query.join("&")))
}

/// Whether no segment of the path in `path` (up to any `?`) is longer than `MAX_SEGMENT_LEN`.
pub fn segments_within_limit(path: &str) -> bool {
	let route = path.split('?').next().unwrap_or_default();
	route.split('/').all(|segment| segment.len() <= MAX_SEGMENT_LEN)
}

#[cfg(test)]
mod tests {
	use super::*;

	// Audit finding #17: post::item passes the visitor's whole query string
	// into the fetch cache key, so ?a=1, ?a=2, ... are separate entries that
	// each hold the same thread (measured at 2.9 MB) and cost a Reddit request.
	#[test]
	fn test_unknown_query_parameters_leave_the_key() {
		let key = fetch_key("/r/rust/comments/abc.json?a=1&sort=top&raw_json=1").unwrap();
		assert_eq!(key, "/r/rust/comments/abc.json?raw_json=1&sort=top");
		for n in 0..50 {
			assert_eq!(fetch_key(&format!("/r/rust/comments/abc.json?x{n}={n}&sort=top&raw_json=1&utm_source=y")).unwrap(), key);
		}
	}

	#[test]
	fn test_parameter_order_and_repeats_do_not_matter() {
		let key = fetch_key("/r/rust/hot.json?after=t3_x&limit=5&raw_json=1").unwrap();
		assert_eq!(fetch_key("/r/rust/hot.json?raw_json=1&limit=5&after=t3_x"), Some(key.clone()));
		// the last one wins, as in utils::param
		assert_eq!(fetch_key("/r/rust/hot.json?after=t3_old&raw_json=1&limit=5&after=t3_x"), Some(key));
	}

	#[test]
	fn test_parameters_that_change_the_result_stay_in_the_key() {
		for query in [
			"sort=new",
			"t=week",
			"after=t3_abc",
			"before=t3_abc",
			"count=25",
			"limit=100",
			"q=rust+lang",
			"type=link",
			"restrict_sr=on",
			"post_types=image",
			"geo_filter=GLOBAL",
			"include_over_18=on",
			"depth=3",
			"context=2",
			"more_cursor=abc%3D&more_query=top",
			"raw_json=1",
		] {
			let key = fetch_key(&format!("/r/rust/search.json?{query}")).unwrap();
			assert!(key.ends_with(&format!("?{query}")), "{query}: {key}");
			assert_ne!(Some(key), fetch_key("/r/rust/search.json"));
		}
		assert_ne!(fetch_key("/r/rust/hot.json?after=t3_a"), fetch_key("/r/rust/hot.json?after=t3_b"));
	}

	#[test]
	fn test_key_without_query() {
		assert_eq!(fetch_key("/r/rust/about.json").as_deref(), Some("/r/rust/about.json"));
		assert_eq!(fetch_key("/r/rust/about.json?utm=1").as_deref(), Some("/r/rust/about.json"));
		assert_eq!(fetch_key("/r/rust/about.json?").as_deref(), Some("/r/rust/about.json"));
	}

	// Audit finding #17: canonical_path keyed a 1024-entry cache on
	// /r/<sub>/s/<id> with an unbounded <sub>.
	#[test]
	fn test_long_path_segments_are_refused() {
		let ok = "a".repeat(MAX_SEGMENT_LEN);
		let long = "a".repeat(MAX_SEGMENT_LEN + 1);
		assert!(fetch_key(&format!("/r/{ok}/hot.json")).is_some());
		assert_eq!(fetch_key(&format!("/r/{long}/hot.json")), None);
		assert_eq!(fetch_key(&format!("/user/{long}/about.json?raw_json=1")), None);
		assert!(segments_within_limit(&format!("/r/{ok}/s/abcdefgh")));
		assert!(!segments_within_limit(&format!("/r/{long}/s/abcdefgh")));
		assert!(!segments_within_limit(&format!("/u/{long}/s/abcdefgh")));
	}

	// The callers of the two caches must go through the keys above.
	#[test]
	fn test_fetch_and_canonical_path_refuse_long_segments_without_asking_reddit() {
		let long = "a".repeat(MAX_SEGMENT_LEN + 1);
		let fetched = crate::client::block_on_shared(crate::backends::fetch(format!("/r/{long}/hot.json?raw_json=1"), false));
		assert!(fetched.is_err_and(|e| e.contains("too long")));
		let canonical = crate::client::block_on_shared(crate::client::canonical_path(format!("/r/{long}/s/abcdefgh"), 3));
		assert_eq!(canonical, Ok(None));
	}
}
