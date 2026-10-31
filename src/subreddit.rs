#![allow(clippy::cmp_owned)]

use crate::body::Body;
use crate::pref_validation::is_valid_subreddit_name;
use crate::utils::{
	build_rss_items, catch_random, clean_url, enable_rss, error, filter_posts, format_num, format_url, get_filters, info, is_account_only_subreddit, nsfw_landing, param,
	redirect, rewrite_urls, rss_page_link, rss_page_path, rss_response, setting, setting_or_default, should_be_nsfw_gated, template, val, Post, Preferences, Subreddit,
	ACCOUNT_ONLY_MSG, RSS_LISTING_SORTS,
};
use crate::utils::{local_path, redirect_local, reject_cross_site_post};
use crate::{backends::json, server::RequestExt, server::ResponseExt};
use askama::Template;
use cookie::Cookie;
use hyper::{Request, Response};
use rss::ChannelBuilder;
use time::{Duration, OffsetDateTime};

// STRUCTS
#[derive(Template)]
#[template(path = "subreddit.html")]
struct SubredditTemplate {
	sub: Subreddit,
	posts: Vec<Post>,
	sort: (String, String),
	ends: (String, String),
	prefs: Preferences,
	url: String,
	redirect_url: String,
	/// Whether the subreddit itself is filtered.
	is_filtered: bool,
	/// Whether all fetched posts are filtered (to differentiate between no posts fetched in the first place,
	/// and all fetched posts being filtered).
	all_posts_filtered: bool,
	/// Whether all posts were hidden because they are NSFW (and user has disabled show NSFW)
	all_posts_hidden_nsfw: bool,
	no_posts: bool,
	/// Whether the empty listing is because Reddit only serves this quarantined community to logged-in accounts.
	quarantine_empty: bool,
	/// Path of the multireddit being shown (eg. /user/kjoneslol/m/sfwpornnetwork), empty for subreddits.
	multi_root: String,
	/// Owner of the multireddit being shown, empty for subreddits.
	multi_owner: String,
}

#[derive(Template)]
#[template(path = "wiki.html")]
struct WikiTemplate {
	sub: String,
	wiki: String,
	page: String,
	prefs: Preferences,
	url: String,
}

#[derive(Template)]
#[template(path = "wall.html")]
struct WallTemplate {
	title: String,
	sub: String,
	msg: String,
	prefs: Preferences,
	url: String,
}

// SERVICES
pub async fn community(req: Request<Body>) -> Result<Response<Body>, String> {
	let prefs = Preferences::new(&req);
	// Build Reddit API path
	let root = req.uri().path() == "/";
	let subscribed = setting(&req, "subscriptions");
	let front_page = setting(&req, "front_page");
	let remove_default_feeds = setting(&req, "remove_default_feeds") == "on";
	let post_sort = setting_or_default(&req, "post_sort", "hot".to_string());
	let sort = req.param("sort").unwrap_or_else(|| req.param("id").unwrap_or(post_sort));

	let sub_name = req.param("sub").unwrap_or(if front_page == "default" || front_page.is_empty() {
		if subscribed.is_empty() {
			"popular".to_string()
		} else {
			subscribed.clone()
		}
	} else {
		front_page.clone()
	});

	if (sub_name == "popular" || sub_name == "all") && remove_default_feeds {
		if subscribed.is_empty() {
			return info(req, "Subscribe to some subreddits! (Default feeds disabled in settings)").await;
		} else {
			// If there are subscribed subs, but we get here, then the problem is that front_page pref is set to something besides default.
			// Tell user to go to settings and change front page to default.
			return info(
				req,
				"You have subscribed to some subreddits, but your front page is not set to default. Visit settings and change front page to default.",
			)
			.await;
		}
	}

	if is_account_only_subreddit(&sub_name) {
		return error(req, ACCOUNT_ONLY_MSG).await;
	}

	let quarantined = can_access_quarantine(&req, &sub_name) || root;

	// Handle random subreddits
	if let Ok(random) = catch_random(&sub_name, "").await {
		return Ok(random);
	}

	if req.param("sub").is_some() && sub_name.starts_with("u_") {
		return Ok(redirect(&["/user/", &sub_name[2..]].concat()));
	}

	// Request subreddit metadata
	let sub = if !sub_name.contains('+') && sub_name != subscribed && sub_name != "popular" && sub_name != "all" {
		// Regular subreddit
		subreddit(&sub_name, quarantined).await.unwrap_or_default()
	} else if sub_name == subscribed {
		// Subscription feed
		if req.uri().path().starts_with("/r/") {
			subreddit(&sub_name, quarantined).await.unwrap_or_default()
		} else {
			Subreddit::default()
		}
	} else {
		// Multireddit, all, popular
		Subreddit {
			name: sub_name.clone(),
			..Subreddit::default()
		}
	};

	let req_url = req.uri().to_string();
	// Return landing page if this post if this is NSFW community but the user
	// has disabled the display of NSFW content or if the instance is SFW-only.
	if sub.nsfw && should_be_nsfw_gated(&req, &req_url) {
		return Ok(nsfw_landing(req, req_url).await.unwrap_or_default());
	}

	let mut params = String::from("&raw_json=1");
	if sub_name == "popular" {
		params.push_str(&format!("&geo_filter={}", prefs.geo_filter));
	}

	let posts_per_page: u32 = setting(&req, "posts_per_page").parse().unwrap_or(25).clamp(1, 100);
	if posts_per_page != 25 {
		params.push_str(&format!("&limit={}", posts_per_page));
	}

	let path = format!("/r/{}/{sort}.json?{}{params}", sub_name.replace('+', "%2B"), req.uri().query().unwrap_or_default());
	let url = String::from(req.uri().path_and_query().map_or("", |val| val.as_str()));
	let redirect_url = url[1..].replace('?', "%3F").replace('&', "%26").replace('+', "%2B");
	let filters = get_filters(&req);

	// If all requested subs are filtered, we don't need to fetch posts.
	if sub_name.split('+').all(|s| filters.contains(s)) {
		Ok(template(&SubredditTemplate {
			sub,
			posts: Vec::new(),
			sort: (sort, param(&path, "t").unwrap_or_default()),
			ends: (param(&path, "after").unwrap_or_default(), String::new()),
			prefs,
			url,
			redirect_url,
			is_filtered: true,
			all_posts_filtered: false,
			all_posts_hidden_nsfw: false,
			no_posts: false,
			quarantine_empty: false,
			multi_root: String::new(),
			multi_owner: String::new(),
		}))
	} else {
		match Post::fetch(&path, quarantined).await {
			Ok((mut posts, after)) => {
				let clean_urls = setting(&req, "clean_urls");
				if clean_urls == "on".to_owned() {
					posts.iter_mut().for_each(|post| post.media.url = clean_url(post.media.url.clone()));
				}
				let listing_empty = posts.is_empty();
				let (_, all_posts_filtered) = filter_posts(&mut posts, &filters);
				let no_posts = posts.is_empty();
				let all_posts_hidden_nsfw = !no_posts && (posts.iter().all(|p| p.flags.nsfw) && setting(&req, "show_nsfw") != "on");
				if sort == "new" {
					posts.sort_by_key(|post| std::cmp::Reverse(post.created_ts));
					posts.sort_by_key(|post| std::cmp::Reverse(post.flags.stickied));
				}
				Ok(template(&SubredditTemplate {
					sub,
					posts,
					sort: (sort, param(&path, "t").unwrap_or_default()),
					ends: (param(&path, "after").unwrap_or_default(), after),
					prefs: Preferences::new(&req),
					url,
					redirect_url,
					is_filtered: false,
					all_posts_filtered,
					all_posts_hidden_nsfw,
					no_posts,
					quarantine_empty: quarantine_empty(listing_empty, quarantined, root, &path),
					multi_root: String::new(),
					multi_owner: String::new(),
				}))
			}
			Err(msg) => match msg.as_str() {
				"quarantined" | "gated" => Ok(quarantine(&req, sub_name, &msg)),
				"private" => error(req, &format!("r/{sub_name} is a private community")).await,
				"banned" => error(req, &format!("r/{sub_name} has been banned from Reddit")).await,
				_ => error(req, &msg).await,
			},
		}
	}
}

/// Reddit only returns quarantined posts to logged-in accounts: after opting in, anonymous
/// requests get an empty listing. That is the case when the first page of an opted-in
/// community (not the front page) comes back empty.
fn quarantine_empty(listing_empty: bool, quarantined: bool, root: bool, path: &str) -> bool {
	listing_empty && quarantined && !root && param(path, "after").is_none()
}

/// Builds the Reddit API path for a user's multireddit listing.
fn multi_api_path(name: &str, multi: &str, sort: &str, query: &str) -> Result<String, String> {
	let valid_name = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
	if !valid_name(name) || !valid_name(multi) {
		return Err("Invalid multireddit".to_string());
	}
	if !["hot", "new", "top", "rising", "controversial"].contains(&sort) {
		return Err(format!("Invalid sort: {sort}"));
	}
	Ok(format!("/user/{name}/m/{multi}/{sort}.json?{query}&raw_json=1"))
}

// /user/:name/m/:multi[/:sort]
pub async fn multi(req: Request<Body>) -> Result<Response<Body>, String> {
	let name = req.param("name").unwrap_or_default();
	let multi = req.param("multi").unwrap_or_default();
	let post_sort = setting_or_default(&req, "post_sort", "hot".to_string());
	let sort = req.param("sort").unwrap_or(post_sort);

	let path = match multi_api_path(&name, &multi, &sort, req.uri().query().unwrap_or_default()) {
		Ok(path) => path,
		Err(msg) => return error(req, &msg).await,
	};
	let url = String::from(req.uri().path_and_query().map_or("", |val| val.as_str()));
	let redirect_url = url[1..].replace('?', "%3F").replace('&', "%26").replace('+', "%2B");
	let filters = get_filters(&req);

	match Post::fetch(&path, false).await {
		Ok((mut posts, after)) => {
			let (_, all_posts_filtered) = filter_posts(&mut posts, &filters);
			let no_posts = posts.is_empty();
			let all_posts_hidden_nsfw = !no_posts && (posts.iter().all(|p| p.flags.nsfw) && setting(&req, "show_nsfw") != "on");
			if sort == "new" {
				posts.sort_by_key(|post| std::cmp::Reverse(post.created_ts));
			}
			Ok(template(&SubredditTemplate {
				sub: Subreddit {
					title: format!("m/{multi}"),
					..Subreddit::default()
				},
				posts,
				sort: (sort, param(&path, "t").unwrap_or_default()),
				ends: (param(&path, "after").unwrap_or_default(), after),
				prefs: Preferences::new(&req),
				url,
				redirect_url,
				is_filtered: false,
				all_posts_filtered,
				all_posts_hidden_nsfw,
				no_posts,
				multi_root: format!("/user/{name}/m/{multi}"),
				multi_owner: name,
				quarantine_empty: false,
			}))
		}
		Err(msg) => error(req, &msg).await,
	}
}

pub fn quarantine(req: &Request<Body>, sub: String, restriction: &str) -> Response<Body> {
	let wall = WallTemplate {
		title: format!("r/{sub} is {restriction}"),
		msg: "Please click the button below to continue to this subreddit.".to_string(),
		url: req.uri().to_string(),
		sub,
		prefs: Preferences::new(req),
	};

	Response::builder()
		.status(403)
		.header("content-type", "text/html; charset=utf-8")
		.body(wall.render().unwrap_or_default().into())
		.unwrap_or_default()
}

pub async fn add_quarantine_exception(req: Request<Body>) -> Result<Response<Body>, String> {
	if let Some(res) = reject_cross_site_post(&req) {
		return Ok(res);
	}
	let subreddit = req.param("sub").ok_or("Invalid URL")?;
	if !is_valid_subreddit_name(&subreddit) {
		return Err("Invalid URL".to_string());
	}
	let redir = param(&format!("?{}", req.uri().query().unwrap_or_default()), "redir").ok_or("Invalid URL")?;
	let mut response = redirect_local(&redir);
	response.insert_cookie(
		Cookie::build((&format!("allow_quaran_{}", subreddit.to_lowercase()), "true"))
			.path("/")
			.http_only(true)
			.expires(cookie::Expiration::Session)
			.into(),
	);
	Ok(response)
}

pub fn can_access_quarantine(req: &Request<Body>, sub: &str) -> bool {
	// Determine if the subreddit can be accessed
	setting(req, &format!("allow_quaran_{}", sub.to_lowercase())).parse().unwrap_or_default()
}

// Join items in chunks of 4000 bytes in length for cookies
pub fn join_until_size_limit<T: std::fmt::Display>(vec: &[T]) -> Vec<std::string::String> {
	let mut result = Vec::new();
	let mut list = String::new();
	let mut current_size = 0;

	for item in vec {
		// Size in bytes
		let item_size = item.to_string().len();
		// Use 4000 bytes to leave us some headroom because the name and options of the cookie count towards the 4096 byte cap
		if current_size + item_size > 4000 {
			// If last item add a seperator on the end of the list so it's interpreted properly in tanden with the next cookie
			list.push('+');

			// Push current list to result vector
			result.push(list);

			// Reset the list variable so we can continue with only new items
			list = String::new();
		}
		// Add separator if not the first item
		if !list.is_empty() {
			list.push('+');
		}
		// Add current item to list
		list.push_str(&item.to_string());
		current_size = list.len() + item_size;
	}
	// Make sure to push whatever the remaining subreddits are there into the result vector
	result.push(list);

	// Return resulting vector
	result
}

/// Where to send the user after subscribing or filtering: back to the subreddit
/// or, when unsubscribing/unfiltering from outside the sidebar, to the `redirect` parameter
fn subscription_redirect(sub: &str, query: &str) -> String {
	match param(&format!("?{query}"), "redirect").as_deref().and_then(local_path) {
		Some(path) => path,
		None => format!("/r/{sub}"),
	}
}

// Sub, filter, unfilter, or unsub by setting subscription cookie using response "Set-Cookie" header
pub async fn subscriptions_filters(req: Request<Body>) -> Result<Response<Body>, String> {
	if let Some(res) = reject_cross_site_post(&req) {
		return Ok(res);
	}

	let sub = req.param("sub").unwrap_or_default();
	let action: Vec<String> = req.uri().path().split('/').map(String::from).collect();

	// Handle random subreddits
	if sub == "random" || sub == "randnsfw" {
		if action.contains(&"filter".to_string()) || action.contains(&"unfilter".to_string()) {
			return Err("Can't filter random subreddit!".to_string());
		}
		return Err("Can't subscribe to random subreddit!".to_string());
	}

	// The names end up in a Reddit API path and in a cookie
	if !sub.split('+').filter(|part| !part.is_empty()).all(is_valid_subreddit_name) {
		return Err("Invalid subreddit name".to_string());
	}

	let query = req.uri().query().unwrap_or_default().to_string();

	let preferences = Preferences::new(&req);
	let mut sub_list = preferences.subscriptions;
	let mut filters = preferences.filters;

	// Retrieve list of posts for these subreddits to extract display names

	let posts = json(format!("/r/{sub}/hot.json?raw_json=1"), true).await;
	let display_lookup: Vec<(String, &str)> = match &posts {
		Ok(posts) => posts["data"]["children"]
			.as_array()
			.map(|list| {
				list
					.iter()
					.map(|post| {
						let display_name = post["data"]["subreddit"].as_str().unwrap_or_default();
						(display_name.to_lowercase(), display_name)
					})
					.collect::<Vec<_>>()
			})
			.unwrap_or_default(),
		Err(_) => vec![],
	};

	// Find each subreddit name (separated by '+') in sub parameter
	for part in sub.split('+').filter(|x| x != &"") {
		// Retrieve display name for the subreddit
		let display;
		let part = if part.starts_with("u_") {
			part
		} else if let Some(&(_, display)) = display_lookup.iter().find(|x| x.0 == part.to_lowercase()) {
			// This is already known, doesn't require separate request
			display
		} else {
			// This subreddit display name isn't known, retrieve it
			let path: String = format!("/r/{part}/about.json?raw_json=1");
			display = json(path, true).await;
			match &display {
				Ok(display) => display["data"]["display_name"].as_str(),
				Err(_) => None,
			}
			.unwrap_or(part)
		};

		// The display name comes from the API; it still has to be safe to store in a cookie
		if !is_valid_subreddit_name(part) {
			continue;
		}

		// Modify sub list based on action
		if action.contains(&"subscribe".to_string()) && !sub_list.contains(&part.to_owned()) {
			// Add each sub name to the subscribed list
			sub_list.push(part.to_owned());
			filters.retain(|s| s.to_lowercase() != part.to_lowercase());
			// Reorder sub names alphabetically
			sub_list.sort_by_key(|a| a.to_lowercase());
			filters.sort_by_key(|a| a.to_lowercase());
		} else if action.contains(&"unsubscribe".to_string()) {
			// Remove sub name from subscribed list
			sub_list.retain(|s| s.to_lowercase() != part.to_lowercase());
		} else if action.contains(&"filter".to_string()) && !filters.contains(&part.to_owned()) {
			// Add each sub name to the filtered list
			filters.push(part.to_owned());
			sub_list.retain(|s| s.to_lowercase() != part.to_lowercase());
			// Reorder sub names alphabetically
			filters.sort_by_key(|a| a.to_lowercase());
			sub_list.sort_by_key(|a| a.to_lowercase());
		} else if action.contains(&"unfilter".to_string()) {
			// Remove sub name from filtered list
			filters.retain(|s| s.to_lowercase() != part.to_lowercase());
		}
	}

	let mut response = redirect(&subscription_redirect(&sub, &query));

	// If sub_list is empty remove all subscriptions cookies, otherwise update them and remove old ones
	if sub_list.is_empty() {
		// Remove subscriptions cookie
		response.remove_cookie("subscriptions".to_string());

		// Start with first numbered subscriptions cookie
		let mut subscriptions_number = 1;

		// While whatever subscriptionsNUMBER cookie we're looking at has a value
		while req.cookie(&format!("subscriptions{subscriptions_number}")).is_some() {
			// Remove that subscriptions cookie
			response.remove_cookie(format!("subscriptions{subscriptions_number}"));

			// Increment subscriptions cookie number
			subscriptions_number += 1;
		}
	} else {
		// Start at 0 to keep track of what number we need to start deleting old subscription cookies from
		let mut subscriptions_number_to_delete_from = 0;

		// Starting at 0 so we handle the subscription cookie without a number first
		for (subscriptions_number, list) in join_until_size_limit(&sub_list).into_iter().enumerate() {
			let subscriptions_cookie = if subscriptions_number == 0 {
				"subscriptions".to_string()
			} else {
				format!("subscriptions{subscriptions_number}")
			};

			response.insert_cookie(
				Cookie::build((subscriptions_cookie, list))
					.path("/")
					.http_only(true)
					.expires(OffsetDateTime::now_utc() + Duration::weeks(52))
					.into(),
			);

			subscriptions_number_to_delete_from += 1;
		}

		// While whatever subscriptionsNUMBER cookie we're looking at has a value
		while req.cookie(&format!("subscriptions{subscriptions_number_to_delete_from}")).is_some() {
			// Remove that subscriptions cookie
			response.remove_cookie(format!("subscriptions{subscriptions_number_to_delete_from}"));

			// Increment subscriptions cookie number
			subscriptions_number_to_delete_from += 1;
		}
	}

	// If filters is empty remove all filters cookies, otherwise update them and remove old ones
	if filters.is_empty() {
		// Remove filters cookie
		response.remove_cookie("filters".to_string());

		// Start with first numbered filters cookie
		let mut filters_number = 1;

		// While whatever filtersNUMBER cookie we're looking at has a value
		while req.cookie(&format!("filters{filters_number}")).is_some() {
			// Remove that filters cookie
			response.remove_cookie(format!("filters{filters_number}"));

			// Increment filters cookie number
			filters_number += 1;
		}
	} else {
		// Start at 0 to keep track of what number we need to start deleting old filters cookies from
		let mut filters_number_to_delete_from = 0;

		for (filters_number, list) in join_until_size_limit(&filters).into_iter().enumerate() {
			let filters_cookie = if filters_number == 0 {
				"filters".to_string()
			} else {
				format!("filters{filters_number}")
			};

			response.insert_cookie(
				Cookie::build((filters_cookie, list))
					.path("/")
					.http_only(true)
					.expires(OffsetDateTime::now_utc() + Duration::weeks(52))
					.into(),
			);

			filters_number_to_delete_from += 1;
		}

		// While whatever filtersNUMBER cookie we're looking at has a value
		while req.cookie(&format!("filters{filters_number_to_delete_from}")).is_some() {
			// Remove that filters cookie
			response.remove_cookie(format!("filters{filters_number_to_delete_from}"));

			// Increment filters cookie number
			filters_number_to_delete_from += 1;
		}
	}

	Ok(response)
}

fn wiki_html(response: &serde_json::Value, page: &str) -> String {
	let missing = if page == "index" {
		"<h3>This subreddit has no wiki pages</h3>"
	} else {
		"<h3>Wiki page not found</h3>"
	};
	rewrite_urls(response["data"]["content_html"].as_str().unwrap_or(missing))
}

pub async fn wiki(req: Request<Body>) -> Result<Response<Body>, String> {
	let sub = req.param("sub").unwrap_or_else(|| "reddit.com".to_string());
	let quarantined = can_access_quarantine(&req, &sub);
	// Handle random subreddits
	if let Ok(random) = catch_random(&sub, "/wiki").await {
		return Ok(random);
	}

	let page = req.param("page").unwrap_or_else(|| "index".to_string());
	let path: String = format!("/r/{sub}/wiki/{page}.json?raw_json=1");
	let url = req.uri().to_string();

	match json(path, quarantined).await {
		Ok(response) => Ok(template(&WikiTemplate {
			wiki: wiki_html(&response, &page),
			sub,
			page,
			prefs: Preferences::new(&req),
			url,
		})),
		Err(msg) => {
			if msg == "quarantined" || msg == "gated" {
				Ok(quarantine(&req, sub, &msg))
			} else {
				error(req, &msg).await
			}
		}
	}
}

pub async fn sidebar(req: Request<Body>) -> Result<Response<Body>, String> {
	let sub = req.param("sub").unwrap_or_else(|| "reddit.com".to_string());
	let quarantined = can_access_quarantine(&req, &sub);

	// Handle random subreddits
	if let Ok(random) = catch_random(&sub, "/about/sidebar").await {
		return Ok(random);
	}

	// Build the Reddit JSON API url
	let path: String = format!("/r/{sub}/about.json?raw_json=1");
	let url = req.uri().to_string();

	// Send a request to the url
	match json(path, quarantined).await {
		// If success, receive JSON in response
		Ok(response) => Ok(template(&WikiTemplate {
			wiki: rewrite_urls(&val(&response, "description_html")),
			// wiki: format!(
			// 	"{}<hr><h1>Moderators</h1><br><ul>{}</ul>",
			// 	rewrite_urls(&val(&response, "description_html"),
			// 	moderators(&sub, quarantined).await.unwrap_or(vec!["Could not fetch moderators".to_string()]).join(""),
			// ),
			sub,
			page: "Sidebar".to_string(),
			prefs: Preferences::new(&req),
			url,
		})),
		Err(msg) => {
			if msg == "quarantined" || msg == "gated" {
				Ok(quarantine(&req, sub, &msg))
			} else {
				error(req, &msg).await
			}
		}
	}
}

// pub async fn moderators(sub: &str, quarantined: bool) -> Result<Vec<String>, String> {
// 	// Retrieve and format the html for the moderators list
// 	Ok(
// 		moderators_list(sub, quarantined)
// 			.await?
// 			.iter()
// 			.map(|m| format!("<li><a style=\"color: var(--accent)\" href=\"/u/{name}\">{name}</a></li>", name = m))
// 			.collect(),
// 	)
// }

// async fn moderators_list(sub: &str, quarantined: bool) -> Result<Vec<String>, String> {
// 	// Build the moderator list URL
// 	let path: String = format!("/r/{}/about/moderators.json?raw_json=1", sub);

// 	// Retrieve response
// 	json(path, quarantined).await.map(|response| {
// 		// Traverse json tree and format into list of strings
// 		response["data"]["children"]
// 			.as_array()
// 			.unwrap_or(&Vec::new())
// 			.iter()
// 			.filter_map(|moderator| {
// 				let name = moderator["name"].as_str().unwrap_or_default();
// 				if name.is_empty() {
// 					None
// 				} else {
// 					Some(name.to_string())
// 				}
// 			})
// 			.collect::<Vec<_>>()
// 	})
// }

// SUBREDDIT
async fn subreddit(sub: &str, quarantined: bool) -> Result<Subreddit, String> {
	// Build the Reddit JSON API url
	let path: String = format!("/r/{sub}/about.json?raw_json=1");

	// Send a request to the url
	let res = json(path, quarantined).await?;

	// Metadata regarding the subreddit
	let members: i64 = res["data"]["subscribers"].as_u64().unwrap_or_default() as i64;
	let active: i64 = res["data"]["accounts_active"].as_u64().unwrap_or_default() as i64;

	// Fetch subreddit icon either from the community_icon or icon_img value
	let community_icon: &str = res["data"]["community_icon"].as_str().unwrap_or_default();
	let icon = if community_icon.is_empty() { val(&res, "icon_img") } else { community_icon.to_string() };

	Ok(Subreddit {
		name: val(&res, "display_name"),
		title: val(&res, "title"),
		description: val(&res, "public_description"),
		info: rewrite_urls(&val(&res, "description_html")),
		// moderators: moderators_list(sub, quarantined).await.unwrap_or_default(),
		icon: format_url(&icon),
		members: format_num(members),
		active: format_num(active),
		wiki: res["data"]["wiki_enabled"].as_bool().unwrap_or_default(),
		nsfw: res["data"]["over18"].as_bool().unwrap_or_default(),
	})
}

/// Feed for a subreddit, multireddit or the front page, built from the JSON API.
/// Mirrors Reddit's feed URLs: `/r/rust.rss`, `/r/rust/top.rss?t=year`, `/r/rust/comments.rss`, `/top.rss`.
pub async fn rss(req: Request<Body>) -> Result<Response<Body>, String> {
	if !enable_rss() {
		return Ok(error(req, "RSS is disabled on this instance.").await.unwrap_or_default());
	}

	// Front page feeds have no subreddit: the sort is the whole path (`/top.rss`)
	let (sub, sort) = match req.param("sub") {
		Some(sub) => (sub, req.param("sort")),
		None => {
			let front_page = setting(&req, "front_page");
			let subscribed = setting(&req, "subscriptions");
			let sub = if !front_page.is_empty() && front_page != "default" {
				front_page
			} else if !subscribed.is_empty() {
				subscribed
			} else {
				"popular".to_string()
			};
			let sort = rss_page_path(&req).trim_start_matches('/').to_string();
			(sub, Some(sort).filter(|s| !s.is_empty()))
		}
	};
	let sort = sort.unwrap_or_else(|| Some(setting(&req, "post_sort")).filter(|s| !s.is_empty()).unwrap_or_else(|| "hot".to_string()));
	if sort != "comments" && !RSS_LISTING_SORTS.contains(&sort.as_str()) {
		return error(req, "Unknown feed sort").await;
	}

	// Only real subreddits have metadata; multireddits, r/all and r/popular don't
	let subreddit = if sub.contains('+') || sub == "all" || sub == "popular" {
		Subreddit {
			name: sub.clone(),
			title: format!("r/{sub}"),
			..Subreddit::default()
		}
	} else {
		subreddit(&sub, false).await?
	};
	if subreddit.nsfw && crate::utils::sfw_only() {
		return error(req, "NSFW content is disabled on this instance.").await;
	}

	let mut params = String::from("&raw_json=1");
	if sub == "popular" {
		params.push_str(&format!("&geo_filter={}", Preferences::new(&req).geo_filter));
	}
	let path = format!("/r/{}/{sort}.json?{}{params}", sub.replace('+', "%2B"), req.uri().query().unwrap_or_default());
	let (posts, _) = Post::fetch(&path, false).await?;

	let title = match sort.as_str() {
		"comments" => format!("Comments in {}", subreddit.title),
		_ => subreddit.title.clone(),
	};
	let channel = ChannelBuilder::default()
		.title(title)
		.description(&subreddit.description)
		.link(rss_page_link(&req))
		.items(build_rss_items(&posts))
		.build();

	Ok(rss_response(&channel))
}

/// Audit finding #16: the quarantine wall is HTML and must declare its charset.
#[cfg(test)]
mod quarantine_charset_tests {
	use super::quarantine;
	use crate::body::Body;
	use hyper::Request;

	#[test]
	fn quarantine_wall_declares_charset() {
		let req = Request::builder().uri("/r/test").body(Body::empty()).unwrap();
		let res = quarantine(&req, "test".to_string(), "quarantined");
		assert_eq!(res.headers().get("content-type").and_then(|v| v.to_str().ok()), Some("text/html; charset=utf-8"));
	}
}

#[cfg(test)]
mod redirect_tests {
	use super::*;
	use crate::utils::redirect_test_support::{assert_local_redirect, OFFSITE_PAYLOADS};
	use futures_lite::future::block_on;

	#[test]
	fn subscription_redirect_stays_on_the_instance() {
		for payload in OFFSITE_PAYLOADS {
			let path = subscription_redirect("rust", &format!("redirect={payload}"));
			assert_local_redirect(&redirect(&path), payload);
		}
	}

	#[test]
	fn subscription_redirect_keeps_the_in_app_forms() {
		assert_eq!(subscription_redirect("rust", ""), "/r/rust");
		assert_eq!(subscription_redirect("rust", "redirect=settings"), "/settings");
		assert_eq!(subscription_redirect("rust", "redirect=r/news%3Fsort%3Dtop"), "/r/news?sort=top");
	}

	fn quarantine_request(query: &str) -> Request<Body> {
		let mut req = Request::builder().method("POST").uri(format!("/r/foo?{query}")).body(Body::empty()).unwrap();
		let mut params = route_recognizer::Params::new();
		params.insert("sub".to_string(), "foo".to_string());
		req.set_params(params);
		req
	}

	#[test]
	fn quarantine_opt_in_redirect_stays_on_the_instance() {
		for payload in OFFSITE_PAYLOADS {
			let res = block_on(add_quarantine_exception(quarantine_request(&format!("redir={payload}")))).unwrap();
			assert_local_redirect(&res, payload);
		}
	}

	#[test]
	fn quarantine_opt_in_keeps_a_local_path() {
		let res = block_on(add_quarantine_exception(quarantine_request("redir=/r/foo/hot"))).unwrap();
		assert_eq!(res.headers()["location"], "/r/foo/hot");
	}
}

/// POSTs that change subscriptions, filters or quarantine opt-ins must come from a page on
/// this instance (audit finding #9)
#[cfg(test)]
mod origin_tests {
	use super::*;
	use futures_lite::future::block_on;

	fn post(uri: &str, sub: &str, headers: &[(&str, &str)]) -> Request<Body> {
		let mut builder = Request::builder().method("POST").uri(uri).header("host", "redlib.example");
		for (name, value) in headers {
			builder = builder.header(*name, *value);
		}
		let mut req = builder.body(Body::empty()).unwrap();
		let mut params = route_recognizer::Params::new();
		params.insert("sub".to_string(), sub.to_string());
		req.set_params(params);
		req
	}

	const CROSS_SITE: [&[(&str, &str)]; 4] = [
		&[("sec-fetch-site", "cross-site")],
		&[("sec-fetch-site", "same-site")],
		&[("origin", "https://evil.example")],
		&[("origin", "null")],
	];

	#[test]
	fn quarantine_opt_in_refuses_cross_site_requests() {
		for headers in CROSS_SITE {
			let res = block_on(add_quarantine_exception(post("/r/foo?redir=/r/foo", "foo", headers))).unwrap();
			assert_eq!(res.status(), 403, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}: opted in");
		}
	}

	#[test]
	fn quarantine_opt_in_accepts_same_origin_requests() {
		for headers in [&[][..], &[("sec-fetch-site", "same-origin")][..], &[("origin", "https://redlib.example")][..]] {
			let res = block_on(add_quarantine_exception(post("/r/foo?redir=/r/foo", "foo", headers))).unwrap();
			assert_eq!(res.status(), 302, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_some(), "{headers:?}");
		}
	}

	#[test]
	fn subscribe_and_filter_refuse_cross_site_requests() {
		// `random` makes the handler fail before it would call Reddit, if the request got that far
		for action in ["subscribe", "unsubscribe", "filter", "unfilter"] {
			for headers in CROSS_SITE {
				let res = block_on(subscriptions_filters(post(&format!("/r/random/{action}"), "random", headers)));
				assert_eq!(res.as_ref().map(Response::status).ok(), Some(hyper::StatusCode::FORBIDDEN), "{action} {headers:?}");
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn empty_listing(quarantine_empty: bool) -> String {
		SubredditTemplate {
			sub: Subreddit::default(),
			posts: Vec::new(),
			sort: ("hot".to_string(), String::new()),
			ends: (String::new(), String::new()),
			prefs: Preferences::default(),
			url: "/r/TheRedPill".to_string(),
			redirect_url: "r/TheRedPill".to_string(),
			is_filtered: false,
			all_posts_filtered: false,
			all_posts_hidden_nsfw: false,
			no_posts: true,
			multi_root: String::new(),
			multi_owner: String::new(),
			quarantine_empty,
		}
		.render()
		.unwrap()
	}

	#[test]
	fn empty_quarantined_listing_explains_login_requirement() {
		let html = empty_listing(true);
		assert!(html.contains("only shows quarantined communities to logged-in accounts"));
		assert!(!html.contains("No posts were found."));
	}

	#[test]
	fn empty_regular_listing_keeps_generic_message() {
		let html = empty_listing(false);
		assert!(html.contains("No posts were found."));
		assert!(!html.contains("logged-in accounts"));
	}

	#[test]
	fn test_quarantine_empty_on_first_page_of_opted_in_community() {
		assert!(quarantine_empty(true, true, false, "/r/TheRedPill/hot.json?&raw_json=1"));
	}

	#[test]
	fn test_quarantine_not_empty_otherwise() {
		let path = "/r/TheRedPill/hot.json?&raw_json=1";
		// Posts came back, or the visitor has not opted in, or this is the front page
		assert!(!quarantine_empty(false, true, false, path));
		assert!(!quarantine_empty(true, false, false, path));
		assert!(!quarantine_empty(true, true, true, path));
		// A later page running out is not a login problem
		assert!(!quarantine_empty(true, true, false, "/r/TheRedPill/hot.json?after=t3_abc&raw_json=1"));
	}

	#[test]
	fn test_multi_api_path() {
		assert_eq!(
			multi_api_path("kjoneslol", "sfwpornnetwork", "hot", "").unwrap(),
			"/user/kjoneslol/m/sfwpornnetwork/hot.json?&raw_json=1"
		);
		assert_eq!(
			multi_api_path("kjoneslol", "sfwpornnetwork", "top", "t=week&after=t3_abc").unwrap(),
			"/user/kjoneslol/m/sfwpornnetwork/top.json?t=week&after=t3_abc&raw_json=1"
		);
		for sort in ["hot", "new", "top", "rising", "controversial"] {
			assert!(multi_api_path("a", "b", sort, "").is_ok(), "{sort} should be accepted");
		}
	}

	#[test]
	fn test_multi_api_path_rejects_bad_input() {
		assert!(multi_api_path("a", "b", "bogus", "").is_err());
		assert!(multi_api_path("a", "b", "hot/../x", "").is_err());
		assert!(multi_api_path("a/b", "c", "hot", "").is_err());
		assert!(multi_api_path("a", "b?c", "hot", "").is_err());
		assert!(multi_api_path("", "b", "hot", "").is_err());
	}

	#[test]
	fn test_multi_template_header() {
		let html = SubredditTemplate {
			sub: Subreddit {
				title: "m/sfwpornnetwork".to_string(),
				..Subreddit::default()
			},
			posts: Vec::new(),
			sort: ("hot".to_string(), String::new()),
			ends: (String::new(), String::new()),
			prefs: Preferences::default(),
			url: String::new(),
			redirect_url: String::new(),
			is_filtered: false,
			all_posts_filtered: false,
			all_posts_hidden_nsfw: false,
			no_posts: false,
			multi_root: "/user/kjoneslol/m/sfwpornnetwork".to_string(),
			multi_owner: "kjoneslol".to_string(),
			quarantine_empty: false,
		}
		.render()
		.unwrap();
		assert!(html.contains("href=\"/user/kjoneslol/m/sfwpornnetwork/new\""), "sort links must stay inside the multi");
		assert!(html.contains("u/kjoneslol"), "header must name the owner");
		assert!(html.contains("sfwpornnetwork"), "header must name the multi");
	}

	#[test]
	fn test_wiki_html() {
		let missing = serde_json::json!({ "reason": "PAGE_NOT_CREATED" });
		assert_eq!(wiki_html(&missing, "index"), "<h3>This subreddit has no wiki pages</h3>");
		assert_eq!(wiki_html(&missing, "rules"), "<h3>Wiki page not found</h3>");
		let page = serde_json::json!({ "data": { "content_html": "<p>hi</p>" } });
		assert_eq!(wiki_html(&page, "index"), "<p>hi</p>");
	}

	#[test]
	fn test_fetching_subreddit() {
		crate::client::block_on_shared(async {
			let subreddit = subreddit("rust", false).await;
			assert!(subreddit.is_ok());
		});
	}

	#[test]
	fn test_gated_and_quarantined() {
		crate::client::block_on_shared(async {
			let quarantined = subreddit("edgy", true).await;
			assert!(quarantined.is_ok());
			let gated = subreddit("drugs", true).await;
			assert!(gated.is_ok());
		});
	}
}
