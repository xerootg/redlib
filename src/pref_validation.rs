//! Allowlists for the values a user can store in preference cookies.
//!
//! A pref value is written into a `Set-Cookie` header and later read back into
//! Reddit API paths, query strings and templates. Nothing the browser sends
//! back can be trusted, so every value is checked against its known options
//! when it is read (`utils::setting`) and when it is written (`settings.rs`,
//! `subreddit.rs`). A value that fails the check counts as unset.

use crate::settings::GEO_FILTERS;
use crate::utils::ThemeAssets;
use regex::Regex;
use std::sync::LazyLock;

/// Longest subreddit name Reddit allows is 21 characters; leave some room.
static SUBREDDIT_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{1,50}$").unwrap());
/// User profiles show up in lists as `u_<name>`, and user names may contain `-`.
static USER_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^u_[A-Za-z0-9_-]{1,50}$").unwrap());

const ON_OFF_PREFS: [&str; 14] = [
	"wide",
	"blur_spoiler",
	"show_nsfw",
	"blur_nsfw",
	"use_hls",
	"hide_hls_notification",
	"autoplay_videos",
	"hide_sidebar_and_summary",
	"fixed_navbar",
	"hide_awards",
	"hide_score",
	"disable_visit_reddit_confirmation",
	"remove_default_feeds",
	"clean_urls",
];

/// Whether `name` is a single subreddit (or `u_<user>`) name that is safe to put in a cookie
/// and in a Reddit API path.
pub fn is_valid_subreddit_name(name: &str) -> bool {
	SUBREDDIT_NAME.is_match(name) || USER_NAME.is_match(name)
}

/// Keeps the valid names of a `+` separated list and drops empty and invalid ones.
fn sanitize_name_list(value: &str) -> String {
	value.split('+').filter(|name| is_valid_subreddit_name(name)).collect::<Vec<_>>().join("+")
}

/// A whole number from `min` to `max` written as plain digits.
fn is_number_in_range(value: &str, min: u32, max: u32) -> bool {
	value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u32>().is_ok_and(|n| (min..=max).contains(&n))
}

/// Whether `value` is an acceptable value for the pref `name`. Empty means unset and is always
/// acceptable, and names that aren't prefs are not checked.
pub fn is_valid_pref(name: &str, value: &str) -> bool {
	if value.is_empty() {
		return true;
	}
	match name {
		"theme" => value == "system" || ThemeAssets::get(&format!("{value}.css")).is_some(),
		"front_page" => value == "default" || value.split('+').all(is_valid_subreddit_name),
		"layout" => ["card", "clean", "compact"].contains(&value),
		"post_sort" => ["hot", "new", "top", "rising", "controversial"].contains(&value),
		"comment_sort" => ["confidence", "top", "new", "controversial", "old"].contains(&value),
		"video_quality" => ["best", "medium", "worst"].contains(&value),
		"geo_filter" => GEO_FILTERS.iter().any(|(code, _)| *code == value),
		"posts_per_page" => is_number_in_range(value, 1, 100),
		"max_comment_thread_depth" => is_number_in_range(value, 0, 1000),
		"subscriptions" | "filters" => value.split('+').all(|name| name.is_empty() || is_valid_subreddit_name(name)),
		_ if ON_OFF_PREFS.contains(&name) => value == "on" || value == "off",
		_ => true,
	}
}

/// The value to use for the pref `name` after reading it from a cookie or a form: `value` itself
/// if it is acceptable, otherwise an empty string (the pref counts as unset). `subscriptions` and
/// `filters` keep their valid names only.
pub fn sanitize_pref(name: &str, value: String) -> String {
	match name {
		"subscriptions" | "filters" => sanitize_name_list(&value),
		_ if is_valid_pref(name, &value) => value,
		_ => String::new(),
	}
}

#[cfg(test)]
mod validation_tests {
	use super::*;

	#[test]
	fn subreddit_names() {
		for ok in ["rust", "AskReddit", "a_b", "u_some-user", "u_x", &"a".repeat(50)] {
			assert!(is_valid_subreddit_name(ok), "{ok}");
		}
		for bad in ["", "a b", "a;b", "a/b", "a?b", "a=b", "a%2Fb", "..", "a-b", "u_a;b", "ünï", "a\r\nb", &"a".repeat(51)] {
			assert!(!is_valid_subreddit_name(bad), "{bad:?}");
		}
	}

	#[test]
	fn name_lists_keep_valid_names_only() {
		assert_eq!(sanitize_pref("subscriptions", "rust++linux+a;b+".to_string()), "rust+linux");
		assert_eq!(sanitize_pref("filters", "mod/about+u_x-y".to_string()), "u_x-y");
		assert!(is_valid_pref("subscriptions", "rust+linux+"));
		assert!(!is_valid_pref("subscriptions", "rust+a;b"));
	}

	#[test]
	fn scalar_prefs() {
		assert!(is_valid_pref("theme", "dracula") && is_valid_pref("theme", "system") && !is_valid_pref("theme", "nope"));
		assert!(is_valid_pref("front_page", "default") && is_valid_pref("front_page", "rust+linux") && !is_valid_pref("front_page", "a/b"));
		assert!(is_valid_pref("layout", "compact") && !is_valid_pref("layout", "grid"));
		assert!(is_valid_pref("wide", "on") && is_valid_pref("wide", "off") && !is_valid_pref("wide", "yes"));
		assert!(is_valid_pref("geo_filter", "GLOBAL") && is_valid_pref("geo_filter", "DE") && !is_valid_pref("geo_filter", "XX"));
		assert!(is_valid_pref("posts_per_page", "1") && is_valid_pref("posts_per_page", "100"));
		for bad in ["0", "101", "-1", "+5", "1e2", "1.5", " 5", "99999999999999999999"] {
			assert!(!is_valid_pref("posts_per_page", bad), "{bad}");
		}
		assert!(is_valid_pref("max_comment_thread_depth", "0") && !is_valid_pref("max_comment_thread_depth", "1001"));
		// Empty means unset, and unknown names are not prefs
		assert!(is_valid_pref("theme", "") && is_valid_pref("allow_quaran_x", "true"));
	}
}
