//! Keys for the caches that sit in front of Reddit.
//!
//! The caches hold entries by count, and a thread page is megabytes, so a
//! visitor who can make up keys can fill the memory with copies of one page.
//! These functions leave a key only the parts that change what Reddit sends.

use std::collections::BTreeMap;
use url::form_urlencoded;

/// The longest path segment (between two slashes) that is looked up.
pub const MAX_SEGMENT_LEN: usize = 256;

/// The longest path of a fetch (without its query). A visitor's subscriptions
/// are one segment of 24 bytes each, so this is well above any real list.
pub const MAX_ROUTE_LEN: usize = 16 * 1024;

/// How a query parameter's value is checked. A value that fails is left out,
/// as Reddit ignores one it does not know, and so only the values it can tell
/// apart make entries.
enum Check {
	/// Any text
	Any,
	/// One of these (the empty string always is)
	OneOf(&'static [&'static str]),
	/// Up to this many digits
	Number(usize),
}

/// The parameters that a thread page (a path with a post id after `comments`)
/// reads. Reddit ignores the others there, and each value of one would be
/// another copy of the page.
const THREAD_KEYS: &[&str] = &["context", "depth", "limit", "more_cursor", "more_query", "raw_json", "sort"];

const FLAGS: &[&str] = &["on", "off", "1", "0", "true", "false"];

/// Query parameters that change what Reddit sends, or what a backend makes of
/// it, with what their values may be. A parameter that is not here is not sent
/// to Reddit either.
const QUERY_KEYS: &[(&str, Check)] = &[
	("after", Check::Any),
	("before", Check::Any),
	("context", Check::Number(1)),
	("count", Check::Number(4)),
	("depth", Check::Number(2)),
	("geo_filter", Check::Any),
	("include_over_18", Check::OneOf(FLAGS)),
	("limit", Check::Number(3)),
	("more_cursor", Check::Any),
	("more_query", Check::Any),
	("post_types", Check::OneOf(&["all", "text", "image", "video", "gif", "gallery", "link", "poll"])),
	("q", Check::Any),
	("raw_json", Check::OneOf(&["1", "0"])),
	("restrict_sr", Check::OneOf(FLAGS)),
	(
		"sort",
		Check::OneOf(&[
			"confidence",
			"best",
			"hot",
			"new",
			"top",
			"old",
			"controversial",
			"qa",
			"live",
			"num_comments",
			"relevance",
			"comments",
			"rising",
		]),
	),
	("t", Check::OneOf(&["hour", "day", "week", "month", "year", "all"])),
	(
		"type",
		Check::OneOf(&["link", "comment", "comments", "sr", "sr_user", "user", "posts", "media", "communities", "people"]),
	),
];

impl Check {
	fn accepts(&self, value: &str) -> bool {
		match self {
			Check::Any => true,
			Check::OneOf(allowed) => value.is_empty() || allowed.contains(&value),
			Check::Number(digits) => value.len() <= *digits && value.bytes().all(|b| b.is_ascii_digit()),
		}
	}
}

/// The key for a fetch of `path` (a Reddit JSON API path with its query), or
/// `None` if its route is longer than `MAX_ROUTE_LEN`. The key is
/// `path` with only the parameters in `QUERY_KEYS` that have a valid value,
/// sorted by name, with the last of any repeated one, as `utils::param` reads
/// them, and with their values written one way.
pub fn fetch_key(path: &str) -> Option<String> {
	let (route, query) = path.split_once('?').unwrap_or((path, ""));
	if route.len() > MAX_ROUTE_LEN {
		return None;
	}

	let thread = thread_at(&route.strip_suffix(".json").unwrap_or(route).split('/').collect::<Vec<_>>()).is_some();
	let mut kept = BTreeMap::new();
	for (key, value) in form_urlencoded::parse(query.as_bytes()) {
		if thread && !THREAD_KEYS.contains(&&*key) {
			continue;
		}
		if let Some((name, kind)) = QUERY_KEYS.iter().find(|(name, _)| *name == key) {
			if kind.accepts(&value) {
				kept.insert(*name, value);
			} else {
				// The last one is the one that is read, so an earlier valid one is not
				kept.remove(name);
			}
		}
	}
	if kept.is_empty() {
		return Some(route.to_string());
	}
	let query = form_urlencoded::Serializer::new(String::new()).extend_pairs(kept).finish();
	Some(format!("{route}?{query}"))
}

/// Where `comments` is in the segments of a thread's path, which is `/comments/<id>`
/// or `/r/<sub>/comments/<id>` (or `/user/<name>/...`). A sub, user or wiki
/// page can be named comments too.
fn thread_at<S: AsRef<str>>(segments: &[S]) -> Option<usize> {
	let at = match segments.get(1).map(AsRef::as_ref) {
		Some("comments") => 1,
		Some("r" | "user" | "u") if segments.get(3).is_some_and(|segment| segment.as_ref() == "comments") => 3,
		_ => return None,
	};
	segments.get(at + 1).filter(|id| !id.as_ref().is_empty()).map(|_| at)
}

/// The key of the cache entry for `path`, which `fetch_key` made: the same
/// thread or listing, as Reddit sends it, under any thread slug and any letter
/// case of the sub.
pub fn entry_key(path: &str) -> String {
	let (route, query) = path.split_once('?').map_or((path, None), |(route, query)| (route, Some(query)));
	let (route, json) = route.strip_suffix(".json").map_or((route, ""), |route| (route, ".json"));
	let mut segments: Vec<String> = route.split('/').map(str::to_string).collect();
	if segments.get(1).is_some_and(|first| first == "r") {
		if let Some(sub) = segments.get_mut(2) {
			*sub = sub.to_ascii_lowercase();
		}
	}
	// .../comments/<id>/<slug>/<comment id>
	if let Some(at) = thread_at(&segments) {
		let comment = segments.get(at + 3).filter(|comment| !comment.is_empty()).cloned();
		segments.truncate(at + 2);
		if let Some(comment) = comment {
			segments.extend(["_".to_string(), comment]);
		}
	}
	let mut key = format!("{}{json}", segments.join("/"));
	if let Some(query) = query {
		key.push('?');
		key.push_str(query);
	}
	key
}

/// Whether no segment of the path in `path` (up to any `?`) is longer than `MAX_SEGMENT_LEN`.
pub fn segments_within_limit(path: &str) -> bool {
	let route = path.split('?').next().unwrap_or_default();
	// post.rs adds .json to the visitor's last segment
	let route = route.strip_suffix(".json").unwrap_or(route);
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
		assert!(segments_within_limit(&format!("/r/{ok}/s/abcdefgh")));
		assert!(!segments_within_limit(&format!("/r/{long}/s/abcdefgh")));
		assert!(!segments_within_limit(&format!("/u/{long}/s/abcdefgh")));
	}

	// The caller of the canonical-path cache must go through the key above.
	#[test]
	fn test_canonical_path_refuses_long_segments_without_asking_reddit() {
		let long = "a".repeat(MAX_SEGMENT_LEN + 1);
		let canonical = crate::client::block_on_shared(crate::client::canonical_path(format!("/r/{long}/s/abcdefgh"), 3));
		assert_eq!(canonical, Ok(None));
	}
}

// Review of the fix for audit finding #17: the same thread, listing or search
// could still be made into many cache entries (and Reddit requests) by changing
// what the URL says but not what Reddit sends.
#[cfg(test)]
mod normalize_tests {
	use super::*;

	#[test]
	fn test_spellings_of_one_value_are_one_key() {
		let key = fetch_key("/r/rust/comments/abc.json?sort=top&raw_json=1");
		assert_eq!(fetch_key("/r/rust/comments/abc.json?sort=%74op&raw_json=1"), key);
		assert_eq!(fetch_key("/r/rust/comments/abc.json?sort=t%6Fp&raw_json=%31"), key);
		assert_eq!(fetch_key("/r/rust/search.json?q=a%20b&raw_json=1"), fetch_key("/r/rust/search.json?q=a+b&raw_json=1"));
		assert_eq!(fetch_key("/r/rust/hot.json?after=t3_a%3D").as_deref(), Some("/r/rust/hot.json?after=t3_a%3D"));
	}

	#[test]
	fn test_values_that_are_not_valid_leave_the_key() {
		let bare = fetch_key("/r/rust/comments/abc.json?raw_json=1");
		for query in [
			"sort=confidence1",
			"sort=confidence2",
			"sort=zzz",
			"context=12",
			"context=x",
			"limit=1000000",
			"limit=x",
			"depth=-1",
			"t=forever",
			"type=zzz",
			"raw_json=2",
			"restrict_sr=maybe",
		] {
			assert_eq!(fetch_key(&format!("/r/rust/comments/abc.json?{query}&raw_json=1")), bare, "{query}");
		}
		for query in [
			"sort=confidence",
			"sort=top",
			"context=3",
			"limit=100",
			"depth=5",
			"t=week",
			"type=link",
			"restrict_sr=on",
			"sort=",
			"t=",
		] {
			// a thread reads only some of them
			let path = if ["t=", "type=", "restrict_sr="].iter().any(|name| query.starts_with(name)) {
				"search"
			} else {
				"comments/abc"
			};
			let key = fetch_key(&format!("/r/rust/{path}.json?{query}&raw_json=1"));
			let bare = fetch_key(&format!("/r/rust/{path}.json?raw_json=1"));
			assert_ne!(key, bare, "{query}");
		}
	}

	// post.rs adds .json to the visitor's last segment, which is not the visitor's
	#[test]
	fn test_the_limit_on_a_segment_leaves_out_the_json_suffix() {
		let ok = "a".repeat(MAX_SEGMENT_LEN);
		assert!(segments_within_limit(&format!("/r/rust/comments/abc/{ok}.json?raw_json=1")));
		assert!(!segments_within_limit(&format!("/r/rust/comments/abc/{ok}a.json?raw_json=1")));
	}

	#[test]
	fn test_a_bare_parameter_is_kept_as_an_empty_one() {
		// utils::param reads `?include_over_18` as an empty value, and gql only asks if it is there
		assert_eq!(fetch_key("/r/rust/hot.json?include_over_18&utm=1").as_deref(), Some("/r/rust/hot.json?include_over_18="));
	}

	#[test]
	fn test_thread_slug_and_sub_case_leave_the_entry_key() {
		let key = entry_key("/r/rust/comments/abc/some_title.json?raw_json=1");
		assert_eq!(entry_key("/r/rust/comments/abc/other_title.json?raw_json=1"), key);
		assert_eq!(entry_key("/r/Rust/comments/abc/s3.json?raw_json=1"), key);
		assert_eq!(entry_key("/r/RUST/comments/abc.json?raw_json=1"), key);
		assert_eq!(entry_key("/r/rUst/comments/abc/.json?raw_json=1"), key);
		assert_ne!(entry_key("/r/rust/comments/abd/some_title.json?raw_json=1"), key);
		assert_ne!(entry_key("/r/rust/comments/abc/some_title.json?sort=top&raw_json=1"), key);
	}

	#[test]
	fn test_a_permalink_keeps_its_comment_in_the_entry_key() {
		let key = entry_key("/r/rust/comments/abc/title/def.json?raw_json=1");
		assert_eq!(entry_key("/r/Rust/comments/abc/another/def.json?raw_json=1"), key);
		assert_ne!(entry_key("/r/rust/comments/abc/title/ghi.json?raw_json=1"), key);
		assert_ne!(entry_key("/r/rust/comments/abc/title.json?raw_json=1"), key);
	}

	#[test]
	fn test_sub_case_leaves_the_entry_key_of_listings() {
		assert_eq!(entry_key("/r/Rust/hot.json?raw_json=1"), entry_key("/r/rust/hot.json?raw_json=1"));
		assert_eq!(entry_key("/r/RUST/search.json?q=Rust&raw_json=1"), entry_key("/r/rust/search.json?q=Rust&raw_json=1"));
		// not the search text, nor other kinds of name
		assert_ne!(entry_key("/r/rust/search.json?q=Rust"), entry_key("/r/rust/search.json?q=rust"));
		assert_ne!(entry_key("/r/rust/hot.json"), entry_key("/r/rust/new.json"));
		assert_ne!(entry_key("/r/rust/hot.json"), entry_key("/r/golang/hot.json"));
	}
}

// Second review of the fix for audit finding #17.
#[cfg(test)]
mod review_tests {
	use super::*;

	// The front page asks for /r/<sub1>%2B<sub2>%2B.../hot.json as one path
	// segment, which is over 256 bytes for about 18 subscriptions.
	#[test]
	fn test_a_long_list_of_subs_is_fetched() {
		let subs: Vec<String> = (0..40).map(|n| format!("subreddit{n:02}")).collect();
		let path = format!("/r/{}/hot.json?raw_json=1", subs.join("%2B"));
		assert!(path.split('/').nth(2).unwrap().len() > MAX_SEGMENT_LEN);
		assert_eq!(fetch_key(&path), Some(path));
	}

	// ... but the whole path of a fetch is still limited
	#[test]
	fn test_a_path_far_longer_than_any_list_of_subs_is_refused() {
		let long = "a".repeat(MAX_ROUTE_LEN);
		assert_eq!(fetch_key(&format!("/r/{long}/hot.json?raw_json=1")), None);
		let fetched = crate::client::block_on_shared(crate::backends::fetch(format!("/r/{long}/hot.json?raw_json=1"), false));
		assert!(fetched.is_err_and(|e| e.contains("too long")));
	}
}

// Second review of the fix for audit finding #17, minor points.
#[cfg(test)]
mod thread_tests {
	use super::*;

	// `comments` anywhere in the path was taken for a thread.
	#[test]
	fn test_a_sub_or_wiki_page_named_comments_is_not_a_thread() {
		assert_ne!(entry_key("/r/comments/comments/AAA.json"), entry_key("/r/comments/comments/BBB.json"));
		assert_ne!(entry_key("/r/comments/hot.json"), entry_key("/r/comments/new.json"));
		assert_ne!(entry_key("/r/rust/wiki/comments/x/y.json"), entry_key("/r/rust/wiki/comments/x/z.json"));
		assert_ne!(entry_key("/user/comments/about.json"), entry_key("/user/comments/submitted.json"));
		// the threads still are
		assert_eq!(entry_key("/r/comments/comments/AAA/one.json"), entry_key("/r/Comments/comments/AAA/two.json"));
		assert_eq!(entry_key("/comments/AAA/one.json"), entry_key("/comments/AAA/two.json"));
		assert_eq!(entry_key("/user/x/comments/AAA/one.json"), entry_key("/user/x/comments/AAA/two.json"));
	}

	// Reddit ignores these on a thread, and each value was a fetch of the page.
	#[test]
	fn test_a_thread_has_only_the_parameters_it_reads() {
		let bare = fetch_key("/r/rust/comments/abc.json?raw_json=1&sort=top");
		for n in 0..5 {
			for query in ["after", "before", "q", "geo_filter", "count"] {
				assert_eq!(fetch_key(&format!("/r/rust/comments/abc.json?raw_json=1&sort=top&{query}=v{n}")), bare, "{query}");
			}
		}
		assert_eq!(
			fetch_key("/comments/abc.json?raw_json=1&sort=top&after=1"),
			fetch_key("/comments/abc.json?raw_json=1&sort=top")
		);
		let kept = fetch_key("/r/rust/comments/abc.json?context=3&depth=5&limit=100&more_cursor=c&more_query=top&raw_json=1&sort=top");
		assert_eq!(
			kept.as_deref(),
			Some("/r/rust/comments/abc.json?context=3&depth=5&limit=100&more_cursor=c&more_query=top&raw_json=1&sort=top")
		);
		// listings keep them
		assert_ne!(fetch_key("/r/rust/hot.json?after=t3_a"), fetch_key("/r/rust/hot.json"));
		assert_ne!(fetch_key("/r/rust/comments.json?after=t1_a"), fetch_key("/r/rust/comments.json"));
	}

	// The duplicates page sorts by num_comments (duplicates.rs), which Reddit
	// then does not take for the default.
	#[test]
	fn test_the_duplicates_sort_is_kept() {
		assert_eq!(
			fetch_key("/duplicates/abc.json?sort=num_comments&raw_json=1").as_deref(),
			Some("/duplicates/abc.json?raw_json=1&sort=num_comments")
		);
	}
}
