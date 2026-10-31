//! Regression tests for the audit's pref findings #10 (Set-Cookie attribute injection through
//! pref values) and #15 (unchecked `front_page` and `subscriptions` reaching the Reddit API path).

use crate::body::Body;
use crate::server::RequestExt;
use crate::utils::{get_filters, setting, Preferences};
use crate::{settings, subreddit};
use hyper::{Request, Response};
use route_recognizer::Params;

// The audit's payload: a `;Domain=` attribute smuggled through a pref value
const THEME_INJECTION: &str = "x%3BDomain%3Dthemissing.xyz";

fn request_with_cookies(cookies: &str) -> Request<Body> {
	Request::builder().uri("/").header("Cookie", cookies).body(Body::empty()).unwrap()
}

fn set_cookie_headers(response: &Response<Body>) -> Vec<String> {
	response.headers().get_all("Set-Cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect()
}

fn assert_no_injection(response: &Response<Body>) {
	for header in set_cookie_headers(response) {
		assert!(!header.to_lowercase().contains("themissing"), "attacker attribute reached Set-Cookie: {header}");
	}
}

fn get(uri: &str) -> Request<Body> {
	Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[test]
fn update_does_not_inject_cookie_attributes() {
	for name in ["theme", "layout", "post_sort", "front_page", "posts_per_page", "wide", "geo_filter"] {
		let response = crate::client::block_on_shared(settings::update(get(&format!("/settings/update?{name}={THEME_INJECTION}")))).unwrap();
		assert_no_injection(&response);
	}
	let response = crate::client::block_on_shared(settings::update(get(
		"/settings/update?subscriptions=rust%2Bx%3BDomain%3Dthemissing.xyz&filters=a%3BDomain%3Dthemissing.xyz",
	)))
	.unwrap();
	assert_no_injection(&response);
}

#[test]
fn restore_does_not_inject_cookie_attributes() {
	let response = crate::client::block_on_shared(settings::restore(get(&format!(
		"/settings/restore?theme={THEME_INJECTION}&subscriptions=rust%2Bx%3BDomain%3Dthemissing.xyz&filters=a%3BDomain%3Dthemissing.xyz"
	))))
	.unwrap();
	assert_no_injection(&response);
}

#[test]
fn settings_form_does_not_inject_cookie_attributes() {
	let request = Request::builder()
		.method("POST")
		.uri("/settings")
		.body(Body::from(format!("theme={THEME_INJECTION}&layout=card")))
		.unwrap();
	let response = crate::client::block_on_shared(settings::set(request)).unwrap();
	assert_no_injection(&response);
	// Valid values still make it through
	assert!(set_cookie_headers(&response).iter().any(|h| h.starts_with("layout=card;")));
}

#[test]
fn update_still_sets_valid_values() {
	let response = crate::client::block_on_shared(settings::update(get(
		"/settings/update?theme=dark&layout=compact&front_page=rust%2Blinux&post_sort=top&posts_per_page=50&wide=on&geo_filter=DE&subscriptions=rust%2Blinux",
	)))
	.unwrap();
	let headers = set_cookie_headers(&response);
	for expected in [
		"theme=dark;",
		"layout=compact;",
		"front_page=rust+linux;",
		"post_sort=top;",
		"posts_per_page=50;",
		"wide=on;",
		"geo_filter=DE;",
		"subscriptions=rust+linux;",
	] {
		assert!(headers.iter().any(|h| h.starts_with(expected)), "missing {expected} in {headers:?}");
	}
}

#[test]
fn quarantine_exception_does_not_inject_cookie_attributes() {
	let mut request = get("/r/x/quarantine?redir=%2F");
	let mut params = Params::new();
	params.insert("sub".to_string(), "x;Domain=themissing.xyz;".to_string());
	request.set_params(params);
	let response = crate::client::block_on_shared(subreddit::add_quarantine_exception(request));
	if let Ok(response) = response {
		assert_no_injection(&response);
	}
}

#[test]
fn subscribe_rejects_invalid_subreddit_names() {
	let mut request = Request::builder().method("POST").uri("/r/x/subscribe").body(Body::empty()).unwrap();
	let mut params = Params::new();
	params.insert("sub".to_string(), "x;Domain=themissing.xyz".to_string());
	request.set_params(params);
	let response = crate::client::block_on_shared(subreddit::subscriptions_filters(request));
	assert!(response.is_err(), "an invalid subreddit name must be refused");
}

#[test]
fn front_page_cookie_cannot_reach_the_api_path() {
	// The audit's payload: sends a GET to /r/mod/about/modqueue.json with the session
	let req = request_with_cookies("front_page=mod/about/modqueue.json?x=");
	assert_eq!(setting(&req, "front_page"), "");
	assert_eq!(Preferences::new(&req).front_page, "");

	for hostile in ["../r/all", "all/../mod", "a b", "r%2Fx", "a/b", "rust+mod/about"] {
		let req = request_with_cookies(&format!("front_page={hostile}"));
		assert_eq!(setting(&req, "front_page"), "", "{hostile}");
	}
}

#[test]
fn subscriptions_cookie_cannot_reach_the_api_path() {
	let req = request_with_cookies("subscriptions=rust+mod/about/modqueue.json?x=+linux+..%2Fall");
	assert_eq!(setting(&req, "subscriptions"), "rust+linux");
	assert_eq!(Preferences::new(&req).subscriptions, vec!["rust".to_string(), "linux".to_string()]);

	let req = request_with_cookies("filters=news+a/b+u_some-user+x?y");
	assert_eq!(get_filters(&req).len(), 2);
}

#[test]
fn subscriptions_split_over_numbered_cookies_are_kept() {
	let req = request_with_cookies("subscriptions=rust+linux+; subscriptions1=pics+all");
	assert_eq!(setting(&req, "subscriptions"), "rust+linux+pics+all");
}

#[test]
fn sort_and_numeric_cookies_cannot_inject_into_the_api_request() {
	let req =
		request_with_cookies("post_sort=hot/../../mod; comment_sort=top%26limit%3D1000; geo_filter=GLOBAL%26x%3D1; posts_per_page=1e9; max_comment_thread_depth=99999999999");
	let prefs = Preferences::new(&req);
	assert_eq!(prefs.post_sort, "");
	assert_eq!(prefs.comment_sort, "");
	assert_eq!(prefs.geo_filter, "GLOBAL");
	assert_eq!(prefs.posts_per_page, "");
	assert_eq!(prefs.max_comment_thread_depth, "");
}

#[test]
fn valid_cookies_are_unchanged() {
	let req = request_with_cookies(
		"theme=dracula; front_page=popular; layout=clean; wide=on; post_sort=new; comment_sort=old; video_quality=medium; geo_filter=US; posts_per_page=100; max_comment_thread_depth=3; subscriptions=rust+u_some-user; filters=a_b",
	);
	let prefs = Preferences::new(&req);
	assert_eq!(prefs.theme, "dracula");
	assert_eq!(prefs.front_page, "popular");
	assert_eq!(prefs.layout, "clean");
	assert_eq!(prefs.wide, "on");
	assert_eq!(prefs.post_sort, "new");
	assert_eq!(prefs.comment_sort, "old");
	assert_eq!(prefs.video_quality, "medium");
	assert_eq!(prefs.geo_filter, "US");
	assert_eq!(prefs.posts_per_page, "100");
	assert_eq!(prefs.max_comment_thread_depth, "3");
	assert_eq!(prefs.subscriptions, vec!["rust".to_string(), "u_some-user".to_string()]);
	assert_eq!(prefs.filters, vec!["a_b".to_string()]);
	assert_eq!(prefs.theme, setting(&req, "theme"));
}

#[test]
fn theme_cookie_must_name_an_installed_theme() {
	for hostile in ["x;Domain=themissing.xyz", "../x", "dark.css"] {
		let req = request_with_cookies(&format!("theme={hostile}"));
		assert_eq!(setting(&req, "theme"), "", "{hostile}");
	}
	assert_eq!(setting(&request_with_cookies("theme=system"), "theme"), "system");
}
