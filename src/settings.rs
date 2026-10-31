#![allow(clippy::cmp_owned)]

use std::collections::HashMap;

// CRATES
use crate::body::{Body, CollectError};
use crate::server::ResponseExt;
use crate::subreddit::join_until_size_limit;
use crate::utils::{deflate_decompress, local_path, redirect, reject_cross_site_post, template, Preferences};
use askama::Template;
use cookie::Cookie;
use hyper::{Method, Request, Response};
use time::{Duration, OffsetDateTime};
use url::form_urlencoded;

// STRUCTS
#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
	prefs: Preferences,
	url: String,
	return_url: String,
}

/// Shown instead of changing cookies when a settings link was followed from another site
#[derive(Template)]
#[template(path = "confirm_settings.html")]
struct ConfirmSettingsTemplate {
	prefs: Preferences,
	url: String,
	restore: bool,
}

// CONSTANTS

/// Largest `POST /settings` form accepted: a few dozen short values.
const MAX_SETTINGS_BODY_LEN: usize = 64 * 1024;
/// Largest `POST /settings/encoded-restore` body accepted. A settings code is
/// base2048 text, which form-encoding turns into about six bytes per character.
const MAX_ENCODED_RESTORE_BODY_LEN: usize = 256 * 1024;

const PREFS: [&str; 23] = [
	"theme",
	"front_page",
	"layout",
	"wide",
	"comment_sort",
	"post_sort",
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
	"video_quality",
	"remove_default_feeds",
	"geo_filter",
	"clean_urls",
	"posts_per_page",
	"max_comment_thread_depth",
];

pub static GEO_FILTERS: [(&str, &str); 250] = [
	("GLOBAL", "🌐 Global"),
	("AF", "🇦🇫 Afghanistan"),
	("AX", "🇦🇽 Åland Islands"),
	("AL", "🇦🇱 Albania"),
	("DZ", "🇩🇿 Algeria"),
	("AS", "🇦🇸 American Samoa"),
	("AD", "🇦🇩 Andorra"),
	("AO", "🇦🇴 Angola"),
	("AI", "🇦🇮 Anguilla"),
	("AQ", "🇦🇶 Antarctica"),
	("AG", "🇦🇬 Antigua and Barbuda"),
	("AR", "🇦🇷 Argentina"),
	("AM", "🇦🇲 Armenia"),
	("AW", "🇦🇼 Aruba"),
	("AU", "🇦🇺 Australia"),
	("AT", "🇦🇹 Austria"),
	("AZ", "🇦🇿 Azerbaijan"),
	("BS", "🇧🇸 Bahamas"),
	("BH", "🇧🇭 Bahrain"),
	("BD", "🇧🇩 Bangladesh"),
	("BB", "🇧🇧 Barbados"),
	("BY", "🇧🇾 Belarus"),
	("BE", "🇧🇪 Belgium"),
	("BZ", "🇧🇿 Belize"),
	("BJ", "🇧🇯 Benin"),
	("BM", "🇧🇲 Bermuda"),
	("BT", "🇧🇹 Bhutan"),
	("BO", "🇧🇴 Bolivia"),
	("BA", "🇧🇦 Bosnia and Herzegovina"),
	("BW", "🇧🇼 Botswana"),
	("BV", "🇧🇻 Bouvet Island"),
	("BR", "🇧🇷 Brazil"),
	("IO", "🇮🇴 British Indian Ocean Territory"),
	("VG", "🇻🇬 British Virgin Islands"),
	("BN", "🇧🇳 Brunei"),
	("BG", "🇧🇬 Bulgaria"),
	("BF", "🇧🇫 Burkina Faso"),
	("BI", "🇧🇮 Burundi"),
	("KH", "🇰🇭 Cambodia"),
	("CM", "🇨🇲 Cameroon"),
	("CA", "🇨🇦 Canada"),
	("CV", "🇨🇻 Cape Verde"),
	("BQ", "🇧🇶 Caribbean Netherlands"),
	("KY", "🇰🇾 Cayman Islands"),
	("CF", "🇨🇫 Central African Republic"),
	("TD", "🇹🇩 Chad"),
	("CL", "🇨🇱 Chile"),
	("CN", "🇨🇳 China"),
	("CX", "🇨🇽 Christmas Island"),
	("CC", "🇨🇨 Cocos (Keeling) Islands"),
	("CO", "🇨🇴 Colombia"),
	("KM", "🇰🇲 Comoros"),
	("CG", "🇨🇬 Congo"),
	("CK", "🇨🇰 Cook Islands"),
	("CR", "🇨🇷 Costa Rica"),
	("CI", "🇨🇮 Côte d'Ivoire"),
	("HR", "🇭🇷 Croatia"),
	("CU", "🇨🇺 Cuba"),
	("CW", "🇨🇼 Curaçao"),
	("CY", "🇨🇾 Cyprus"),
	("CZ", "🇨🇿 Czechia"),
	("DK", "🇩🇰 Denmark"),
	("DJ", "🇩🇯 Djibouti"),
	("DM", "🇩🇲 Dominica"),
	("DO", "🇩🇴 Dominican Republic"),
	("CD", "🇨🇩 DR Congo"),
	("EC", "🇪🇨 Ecuador"),
	("EG", "🇪🇬 Egypt"),
	("SV", "🇸🇻 El Salvador"),
	("GQ", "🇬🇶 Equatorial Guinea"),
	("ER", "🇪🇷 Eritrea"),
	("EE", "🇪🇪 Estonia"),
	("SZ", "🇸🇿 Eswatini"),
	("ET", "🇪🇹 Ethiopia"),
	("FK", "🇫🇰 Falkland Islands"),
	("FO", "🇫🇴 Faroe Islands"),
	("FJ", "🇫🇯 Fiji"),
	("FI", "🇫🇮 Finland"),
	("FR", "🇫🇷 France"),
	("GF", "🇬🇫 French Guiana"),
	("PF", "🇵🇫 French Polynesia"),
	("TF", "🇹🇫 French Southern Territories"),
	("GA", "🇬🇦 Gabon"),
	("GM", "🇬🇲 Gambia"),
	("GE", "🇬🇪 Georgia"),
	("DE", "🇩🇪 Germany"),
	("GH", "🇬🇭 Ghana"),
	("GI", "🇬🇮 Gibraltar"),
	("GR", "🇬🇷 Greece"),
	("GL", "🇬🇱 Greenland"),
	("GD", "🇬🇩 Grenada"),
	("GP", "🇬🇵 Guadeloupe"),
	("GU", "🇬🇺 Guam"),
	("GT", "🇬🇹 Guatemala"),
	("GG", "🇬🇬 Guernsey"),
	("GN", "🇬🇳 Guinea"),
	("GW", "🇬🇼 Guinea-Bissau"),
	("GY", "🇬🇾 Guyana"),
	("HT", "🇭🇹 Haiti"),
	("HM", "🇭🇲 Heard & McDonald Islands"),
	("HN", "🇭🇳 Honduras"),
	("HK", "🇭🇰 Hong Kong"),
	("HU", "🇭🇺 Hungary"),
	("IS", "🇮🇸 Iceland"),
	("IN", "🇮🇳 India"),
	("ID", "🇮🇩 Indonesia"),
	("IR", "🇮🇷 Iran"),
	("IQ", "🇮🇶 Iraq"),
	("IE", "🇮🇪 Ireland"),
	("IM", "🇮🇲 Isle of Man"),
	("IL", "🇮🇱 Israel"),
	("IT", "🇮🇹 Italy"),
	("JM", "🇯🇲 Jamaica"),
	("JP", "🇯🇵 Japan"),
	("JE", "🇯🇪 Jersey"),
	("JO", "🇯🇴 Jordan"),
	("KZ", "🇰🇿 Kazakhstan"),
	("KE", "🇰🇪 Kenya"),
	("KI", "🇰🇮 Kiribati"),
	("KW", "🇰🇼 Kuwait"),
	("KG", "🇰🇬 Kyrgyzstan"),
	("LA", "🇱🇦 Laos"),
	("LV", "🇱🇻 Latvia"),
	("LB", "🇱🇧 Lebanon"),
	("LS", "🇱🇸 Lesotho"),
	("LR", "🇱🇷 Liberia"),
	("LY", "🇱🇾 Libya"),
	("LI", "🇱🇮 Liechtenstein"),
	("LT", "🇱🇹 Lithuania"),
	("LU", "🇱🇺 Luxembourg"),
	("MO", "🇲🇴 Macao"),
	("MG", "🇲🇬 Madagascar"),
	("MW", "🇲🇼 Malawi"),
	("MY", "🇲🇾 Malaysia"),
	("MV", "🇲🇻 Maldives"),
	("ML", "🇲🇱 Mali"),
	("MT", "🇲🇹 Malta"),
	("MH", "🇲🇭 Marshall Islands"),
	("MQ", "🇲🇶 Martinique"),
	("MR", "🇲🇷 Mauritania"),
	("MU", "🇲🇺 Mauritius"),
	("YT", "🇾🇹 Mayotte"),
	("MX", "🇲🇽 Mexico"),
	("FM", "🇫🇲 Micronesia"),
	("MD", "🇲🇩 Moldova"),
	("MC", "🇲🇨 Monaco"),
	("MN", "🇲🇳 Mongolia"),
	("ME", "🇲🇪 Montenegro"),
	("MS", "🇲🇸 Montserrat"),
	("MA", "🇲🇦 Morocco"),
	("MZ", "🇲🇿 Mozambique"),
	("MM", "🇲🇲 Myanmar"),
	("NA", "🇳🇦 Namibia"),
	("NR", "🇳🇷 Nauru"),
	("NP", "🇳🇵 Nepal"),
	("NL", "🇳🇱 Netherlands"),
	("NC", "🇳🇨 New Caledonia"),
	("NZ", "🇳🇿 New Zealand"),
	("NI", "🇳🇮 Nicaragua"),
	("NE", "🇳🇪 Niger"),
	("NG", "🇳🇬 Nigeria"),
	("NU", "🇳🇺 Niue"),
	("NF", "🇳🇫 Norfolk Island"),
	("KP", "🇰🇵 North Korea"),
	("MK", "🇲🇰 North Macedonia"),
	("MP", "🇲🇵 Northern Mariana Islands"),
	("NO", "🇳🇴 Norway"),
	("OM", "🇴🇲 Oman"),
	("PK", "🇵🇰 Pakistan"),
	("PW", "🇵🇼 Palau"),
	("PS", "🇵🇸 Palestine"),
	("PA", "🇵🇦 Panama"),
	("PG", "🇵🇬 Papua New Guinea"),
	("PY", "🇵🇾 Paraguay"),
	("PE", "🇵🇪 Peru"),
	("PH", "🇵🇭 Philippines"),
	("PN", "🇵🇳 Pitcairn"),
	("PL", "🇵🇱 Poland"),
	("PT", "🇵🇹 Portugal"),
	("PR", "🇵🇷 Puerto Rico"),
	("QA", "🇶🇦 Qatar"),
	("RE", "🇷🇪 Réunion"),
	("RO", "🇷🇴 Romania"),
	("RU", "🇷🇺 Russia"),
	("RW", "🇷🇼 Rwanda"),
	("BL", "🇧🇱 Saint Barthélemy"),
	("SH", "🇸🇭 Saint Helena"),
	("KN", "🇰🇳 Saint Kitts and Nevis"),
	("LC", "🇱🇨 Saint Lucia"),
	("MF", "🇲🇫 Saint Martin"),
	("PM", "🇵🇲 Saint Pierre and Miquelon"),
	("VC", "🇻🇨 Saint Vincent and the Grenadines"),
	("WS", "🇼🇸 Samoa"),
	("SM", "🇸🇲 San Marino"),
	("ST", "🇸🇹 Sao Tome and Principe"),
	("SA", "🇸🇦 Saudi Arabia"),
	("SN", "🇸🇳 Senegal"),
	("RS", "🇷🇸 Serbia"),
	("SC", "🇸🇨 Seychelles"),
	("SL", "🇸🇱 Sierra Leone"),
	("SG", "🇸🇬 Singapore"),
	("SX", "🇸🇽 Sint Maarten"),
	("SK", "🇸🇰 Slovakia"),
	("SI", "🇸🇮 Slovenia"),
	("SB", "🇸🇧 Solomon Islands"),
	("SO", "🇸🇴 Somalia"),
	("ZA", "🇿🇦 South Africa"),
	("GS", "🇬🇸 South Georgia and the South Sandwich Islands"),
	("KR", "🇰🇷 South Korea"),
	("SS", "🇸🇸 South Sudan"),
	("ES", "🇪🇸 Spain"),
	("LK", "🇱🇰 Sri Lanka"),
	("SD", "🇸🇩 Sudan"),
	("SR", "🇸🇷 Suriname"),
	("SJ", "🇸🇯 Svalbard and Jan Mayen"),
	("SE", "🇸🇪 Sweden"),
	("CH", "🇨🇭 Switzerland"),
	("SY", "🇸🇾 Syria"),
	("TW", "🇹🇼 Taiwan"),
	("TJ", "🇹🇯 Tajikistan"),
	("TZ", "🇹🇿 Tanzania"),
	("TH", "🇹🇭 Thailand"),
	("TL", "🇹🇱 Timor-Leste"),
	("TG", "🇹🇬 Togo"),
	("TK", "🇹🇰 Tokelau"),
	("TO", "🇹🇴 Tonga"),
	("TT", "🇹🇹 Trinidad and Tobago"),
	("TN", "🇹🇳 Tunisia"),
	("TR", "🇹🇷 Türkiye"),
	("TM", "🇹🇲 Turkmenistan"),
	("TC", "🇹🇨 Turks and Caicos Islands"),
	("TV", "🇹🇻 Tuvalu"),
	("UM", "🇺🇲 U.S. Outlying Islands"),
	("VI", "🇻🇮 U.S. Virgin Islands"),
	("UG", "🇺🇬 Uganda"),
	("UA", "🇺🇦 Ukraine"),
	("AE", "🇦🇪 United Arab Emirates"),
	("GB", "🇬🇧 United Kingdom"),
	("US", "🇺🇸 United States"),
	("UY", "🇺🇾 Uruguay"),
	("UZ", "🇺🇿 Uzbekistan"),
	("VU", "🇻🇺 Vanuatu"),
	("VA", "🇻🇦 Vatican City"),
	("VE", "🇻🇪 Venezuela"),
	("VN", "🇻🇳 Vietnam"),
	("WF", "🇼🇫 Wallis and Futuna"),
	("EH", "🇪🇭 Western Sahara"),
	("YE", "🇾🇪 Yemen"),
	("ZM", "🇿🇲 Zambia"),
	("ZW", "🇿🇼 Zimbabwe"),
];

// FUNCTIONS

/// The answer to a request body that exceeds its limit.
fn payload_too_large() -> Response<Body> {
	Response::builder()
		.status(413)
		.header("content-type", "text/plain")
		.body("Request body too large".into())
		.unwrap_or_default()
}

/// Retrieve cookies from request "Cookie" header
pub async fn get(req: Request<Body>) -> Result<Response<Body>, String> {
	let url = req.uri().to_string();
	let form = url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes()).collect::<HashMap<_, _>>();
	Ok(template(&SettingsTemplate {
		prefs: Preferences::new(&req),
		url,
		return_url: form.get("return_to").and_then(|url| local_path(url)).unwrap_or_default(),
	}))
}

/// Set cookies using response "Set-Cookie" header
pub async fn set(req: Request<Body>) -> Result<Response<Body>, String> {
	if let Some(res) = reject_cross_site_post(&req) {
		return Ok(res);
	}

	// Split the body into parts
	let (parts, body) = req.into_parts();

	// Grab existing cookies
	let _cookies: Vec<Cookie<'_>> = parts
		.headers
		.get_all("Cookie")
		.iter()
		.filter_map(|header| Cookie::parse(header.to_str().unwrap_or_default()).ok())
		.collect();

	// Aggregate the body...
	let body_bytes = match body.collect_bytes_limited(MAX_SETTINGS_BODY_LEN).await {
		Ok(bytes) => bytes,
		Err(CollectError::TooLarge) => return Ok(payload_too_large()),
		Err(e) => return Err(e.to_string()),
	};

	let form = url::form_urlencoded::parse(&body_bytes).collect::<HashMap<_, _>>();

	let mut response = match form.get("return_to") {
		Some(value) => {
			if value.is_empty() {
				redirect("/settings")
			} else {
				redirect(&local_path(value).unwrap_or_else(|| "/settings".to_string()))
			}
		}
		None => redirect("/settings"),
	};

	for &name in &PREFS {
		match form.get(name) {
			Some(value) => response.insert_cookie(
				Cookie::build((name.to_owned(), value.clone()))
					.path("/")
					.http_only(true)
					.expires(OffsetDateTime::now_utc() + Duration::weeks(52))
					.into(),
			),
			None => response.remove_cookie(name.to_string()),
		};
	}

	Ok(response)
}

fn set_cookies_method(req: Request<Body>, remove_cookies: bool) -> Response<Body> {
	// A link (on another site, in a Reddit comment, in a chat message) must not wipe or change
	// settings, so a GET only shows what would change and a button that POSTs the same URL back.
	if req.method() != Method::POST {
		// The action is a fixed route, not the request URI: routing normalises the path (`//`,
		// `%2F`) but the handler sees it raw, and `//settings//restore` would be a protocol-relative URL
		let route = if remove_cookies { "/settings/restore" } else { "/settings/update" };
		let url = match req.uri().query() {
			Some(query) => format!("{route}?{query}"),
			None => route.to_string(),
		};
		return template(&ConfirmSettingsTemplate {
			prefs: Preferences::new(&req),
			url,
			restore: remove_cookies,
		});
	}
	if let Some(res) = reject_cross_site_post(&req) {
		return res;
	}

	apply_settings(req, remove_cookies)
}

/// Sets the cookies for the settings in the query string of `req`
fn apply_settings(req: Request<Body>, remove_cookies: bool) -> Response<Body> {
	// Split the body into parts
	let (parts, _) = req.into_parts();

	// Grab existing cookies
	let _cookies: Vec<Cookie<'_>> = parts
		.headers
		.get_all("Cookie")
		.iter()
		.filter_map(|header| Cookie::parse(header.to_str().unwrap_or_default()).ok())
		.collect();

	let query = parts.uri.query().unwrap_or_default().as_bytes();

	let form = url::form_urlencoded::parse(query).collect::<HashMap<_, _>>();

	let path = match form.get("redirect") {
		Some(value) => {
			let value = value.replace("%26", "&").replace("%23", "#");
			local_path(&value).unwrap_or_else(|| "/".to_string())
		}
		None => "/".to_string(),
	};

	let mut response = redirect(&path);

	for name in PREFS {
		match form.get(name) {
			Some(value) => response.insert_cookie(
				Cookie::build((name.to_owned(), value.clone()))
					.path("/")
					.http_only(true)
					.expires(OffsetDateTime::now_utc() + Duration::weeks(52))
					.into(),
			),
			None => {
				if remove_cookies {
					response.remove_cookie(name.to_string());
				}
			}
		};
	}

	// Get subscriptions/filters to restore from query string
	let subscriptions = form.get("subscriptions");
	let filters = form.get("filters");

	// We can't search through the cookies directly like in subreddit.rs, so instead we have to make a string out of the request's headers to search through
	let cookies_string = parts
		.headers
		.get("cookie")
		.map(|hv| hv.to_str().unwrap_or("").to_string()) // Return String
		.unwrap_or_else(String::new); // Return an empty string if None

	// If there are subscriptions to restore set them and delete any old subscriptions cookies, otherwise delete them all
	if let Some(subscriptions) = subscriptions {
		let sub_list: Vec<String> = subscriptions.split('+').map(str::to_string).collect();

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

		// While subscriptionsNUMBER= is in the string of cookies add a response removing that cookie
		while cookies_string.contains(&format!("subscriptions{subscriptions_number_to_delete_from}=")) {
			// Remove that subscriptions cookie
			response.remove_cookie(format!("subscriptions{subscriptions_number_to_delete_from}"));

			// Increment subscriptions cookie number
			subscriptions_number_to_delete_from += 1;
		}
	} else if remove_cookies {
		// Remove unnumbered subscriptions cookie
		response.remove_cookie("subscriptions".to_string());

		// Starts at one to deal with the first numbered subscription cookie and onwards
		let mut subscriptions_number_to_delete_from = 1;

		// While subscriptionsNUMBER= is in the string of cookies add a response removing that cookie
		while cookies_string.contains(&format!("subscriptions{subscriptions_number_to_delete_from}=")) {
			// Remove that subscriptions cookie
			response.remove_cookie(format!("subscriptions{subscriptions_number_to_delete_from}"));

			// Increment subscriptions cookie number
			subscriptions_number_to_delete_from += 1;
		}
	}

	// If there are filters to restore set them and delete any old filters cookies, otherwise delete them all
	if let Some(filters) = filters {
		let filters_list: Vec<String> = filters.split('+').map(str::to_string).collect();

		// Start at 0 to keep track of what number we need to start deleting old subscription cookies from
		let mut filters_number_to_delete_from = 0;

		// Starting at 0 so we handle the subscription cookie without a number first
		for (filters_number, list) in join_until_size_limit(&filters_list).into_iter().enumerate() {
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

		// While filtersNUMBER= is in the string of cookies add a response removing that cookie
		while cookies_string.contains(&format!("filters{filters_number_to_delete_from}=")) {
			// Remove that filters cookie
			response.remove_cookie(format!("filters{filters_number_to_delete_from}"));

			// Increment filters cookie number
			filters_number_to_delete_from += 1;
		}
	} else if remove_cookies {
		// Remove unnumbered filters cookie
		response.remove_cookie("filters".to_string());

		// Starts at one to deal with the first numbered subscription cookie and onwards
		let mut filters_number_to_delete_from = 1;

		// While filtersNUMBER= is in the string of cookies add a response removing that cookie
		while cookies_string.contains(&format!("filters{filters_number_to_delete_from}=")) {
			// Remove that sfilters cookie
			response.remove_cookie(format!("filters{filters_number_to_delete_from}"));

			// Increment filters cookie number
			filters_number_to_delete_from += 1;
		}
	}

	response
}

/// Set cookies using response "Set-Cookie" header
pub async fn restore(req: Request<Body>) -> Result<Response<Body>, String> {
	Ok(set_cookies_method(req, true))
}

pub async fn update(req: Request<Body>) -> Result<Response<Body>, String> {
	Ok(set_cookies_method(req, false))
}

pub async fn encoded_restore(req: Request<Body>) -> Result<Response<Body>, String> {
	if let Some(res) = reject_cross_site_post(&req) {
		return Ok(res);
	}

	let (parts, body) = req.into_parts();
	let cookies = parts.headers.get_all("cookie").iter().cloned().collect::<Vec<_>>();
	let body = match body.collect_bytes_limited(MAX_ENCODED_RESTORE_BODY_LEN).await {
		Ok(bytes) => bytes,
		Err(CollectError::TooLarge) => return Ok(payload_too_large()),
		Err(e) => return Err(e.to_string()),
	};

	let encoded_prefs = form_urlencoded::parse(&body)
		.find(|(key, _)| key == "encoded_prefs")
		.map(|(_, value)| value)
		.ok_or_else(|| "encoded_prefs parameter not found in request body".to_string())?;

	let bytes = base2048::decode(&encoded_prefs).ok_or_else(|| "Failed to decode base2048 encoded preferences".to_string())?;

	let out = deflate_decompress(bytes)?;

	let mut prefs: Preferences = Preferences::from_bincode(&out).map_err(|e| format!("Failed to deserialize bytes into Preferences struct: {e}"))?;

	prefs.available_themes = vec![];

	// Already a same-origin POST, so apply the settings here rather than redirecting to a GET link
	let url = format!("/settings/restore/?{}", prefs.to_urlencoded()?);
	let mut restore = Request::builder().uri(url);
	for cookie in cookies {
		restore = restore.header("cookie", cookie);
	}

	Ok(apply_settings(restore.body(Body::empty()).map_err(|e| e.to_string())?, true))
}

#[cfg(test)]
mod redirect_tests {
	use super::*;
	use crate::utils::redirect_test_support::{assert_local_redirect, OFFSITE_PAYLOADS};
	use futures_lite::future::block_on;

	fn post(path: &str, body: String) -> Request<Body> {
		Request::builder().method("POST").uri(path).body(Body::from(body)).unwrap()
	}

	fn get_request(uri: String) -> Request<Body> {
		Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap()
	}

	// Settings links only change anything when posted back from the confirmation page
	fn post_request(uri: String) -> Request<Body> {
		Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap()
	}

	#[test]
	fn settings_post_return_to_stays_on_the_instance() {
		for payload in OFFSITE_PAYLOADS {
			let res = block_on(set(post("/settings", format!("theme=dark&return_to={payload}")))).unwrap();
			assert_local_redirect(&res, payload);
		}
	}

	#[test]
	fn settings_post_return_to_keeps_a_local_path() {
		let res = block_on(set(post("/settings", "return_to=%2Fr%2Frust%3Fsort%3Dtop".to_string()))).unwrap();
		assert_eq!(res.headers()["location"], "/r/rust?sort=top");
	}

	/// The `return_to` value the settings form would send back
	fn prefilled_return_to(uri: String) -> String {
		let res = block_on(get(get_request(uri))).unwrap();
		let body = String::from_utf8(block_on(res.into_body().collect_bytes()).unwrap().to_vec()).unwrap();
		let field = regex::Regex::new(r#"value="([^"]*)" name="return_to""#).unwrap();
		field.captures(&body).expect("settings form has a return_to field")[1].to_string()
	}

	#[test]
	fn settings_get_does_not_prefill_an_offsite_return_to() {
		for payload in OFFSITE_PAYLOADS {
			assert_eq!(prefilled_return_to(format!("/settings?return_to={payload}")), "", "{payload}: prefilled the form");
		}
	}

	#[test]
	fn settings_get_prefills_a_local_return_to() {
		assert_eq!(prefilled_return_to("/settings?return_to=/r/rust".to_string()), "/r/rust");
	}

	#[test]
	fn settings_restore_redirect_stays_on_the_instance() {
		for payload in OFFSITE_PAYLOADS {
			let res = block_on(restore(post_request(format!("/settings/restore?redirect={payload}")))).unwrap();
			assert_local_redirect(&res, payload);
		}
	}

	#[test]
	fn settings_update_redirect_stays_on_the_instance() {
		for payload in OFFSITE_PAYLOADS {
			let res = block_on(update(post_request(format!("/settings/update?theme=dark&redirect={payload}")))).unwrap();
			assert_local_redirect(&res, payload);
		}
	}

	#[test]
	fn settings_update_redirect_keeps_a_local_path() {
		// The in-app links pass the current path, with or without the leading slash
		let res = block_on(update(post_request("/settings/update?use_hls=on&redirect=/r/rust/comments/abc".to_string()))).unwrap();
		assert_eq!(res.headers()["location"], "/r/rust/comments/abc");
		let res = block_on(update(post_request("/settings/update?use_hls=on&redirect=r/rust".to_string()))).unwrap();
		assert_eq!(res.headers()["location"], "/r/rust");
	}
}

/// POSTs that change preferences must come from a page on this instance (audit finding #9)
#[cfg(test)]
mod confirm_page_tests {
	use super::*;
	use futures_lite::future::block_on;

	fn get(uri: &str) -> Request<Body> {
		Request::builder().method("GET").uri(uri).header("host", "redlib.example").body(Body::empty()).unwrap()
	}

	fn body_of(res: Response<Body>) -> String {
		String::from_utf8(block_on(res.into_body().collect_bytes()).unwrap().to_vec()).unwrap()
	}

	/// Routing collapses `//` in the path before a handler runs, but the handler sees the raw URI:
	/// the form action must not be taken from it, or `//settings//restore` becomes a
	/// protocol-relative URL pointing at another host.
	#[test]
	fn form_action_is_a_fixed_route_with_the_query() {
		for uri in [
			"//settings//restore?theme=light",
			"/settings%2Frestore?theme=light",
			"/settings/restore/?theme=light",
			"/settings/restore?theme=light",
		] {
			let body = body_of(block_on(restore(get(uri))).unwrap());
			assert!(body.contains("method=\"post\" action=\"/settings/restore?theme=light\""), "{uri}: {body}");
		}
		for uri in ["//settings//update?theme=light", "/settings/update/?theme=light"] {
			let body = body_of(block_on(update(get(uri))).unwrap());
			assert!(body.contains("method=\"post\" action=\"/settings/update?theme=light\""), "{uri}: {body}");
		}
	}

	#[test]
	fn update_page_does_not_claim_to_restore() {
		let update_page = body_of(block_on(update(get("/settings/update?theme=light"))).unwrap());
		assert!(!update_page.contains("Restoring replaces"), "{update_page}");
		let restore_page = body_of(block_on(restore(get("/settings/restore?theme=light"))).unwrap());
		assert!(restore_page.contains("Restoring replaces all of your settings"), "{restore_page}");
	}
}

#[cfg(test)]
mod origin_tests {
	use super::*;
	use futures_lite::future::block_on;

	fn post(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
		let mut builder = Request::builder().method("POST").uri(uri).header("host", "redlib.example");
		for (name, value) in headers {
			builder = builder.header(*name, *value);
		}
		builder.body(Body::from("theme=dark&return_to=%2Fr%2Frust")).unwrap()
	}

	const CROSS_SITE: [&[(&str, &str)]; 6] = [
		&[("sec-fetch-site", "cross-site")],
		&[("sec-fetch-site", "same-site")],
		&[("sec-fetch-site", "none")],
		&[("origin", "https://evil.example")],
		&[("origin", "null")],
		&[("origin", "https://redlib.example.evil.example")],
	];

	const SAME_ORIGIN: [&[(&str, &str)]; 5] = [
		// curl, scripts, anything that is not a browser
		&[],
		&[("sec-fetch-site", "same-origin")],
		&[("origin", "https://redlib.example")],
		&[("origin", "http://REDLIB.example")],
		// Behind a proxy that rewrites Host
		&[("origin", "https://front.example"), ("x-forwarded-host", "front.example")],
	];

	#[test]
	fn settings_post_refuses_cross_site_requests() {
		for headers in CROSS_SITE {
			let res = block_on(set(post("/settings", headers))).unwrap();
			assert_eq!(res.status(), 403, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}: changed settings");
		}
	}

	#[test]
	fn settings_post_accepts_same_origin_requests() {
		for headers in SAME_ORIGIN {
			let res = block_on(set(post("/settings", headers))).unwrap();
			assert_eq!(res.status(), 302, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_some(), "{headers:?}");
		}
	}

	#[test]
	fn encoded_restore_refuses_cross_site_requests() {
		for headers in CROSS_SITE {
			let res = block_on(encoded_restore(post("/settings/encoded-restore", headers))).unwrap();
			assert_eq!(res.status(), 403, "{headers:?}");
		}
	}
}

/// /settings/restore and /settings/update change cookies, so a GET (a link, which anyone can put
/// on a page, in a Reddit comment or in a chat message) must not be able to trigger them
/// (audit finding #7). Only a same-origin POST does.
#[cfg(test)]
mod navigation_tests {
	use super::*;
	use futures_lite::future::block_on;

	fn request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
		let mut builder = Request::builder()
			.method(method)
			.uri(uri)
			.header("host", "redlib.example")
			.header("cookie", "theme=dark; subscriptions=rust+news; filters=memes");
		for (name, value) in headers {
			builder = builder.header(*name, *value);
		}
		builder.body(Body::empty()).unwrap()
	}

	// Every way a GET can arrive: from another site, from a Reddit comment rendered by this
	// instance, from an email or chat app, typed in, or from something that is not a browser
	const ANY_GET: [&[(&str, &str)]; 6] = [
		&[],
		&[("sec-fetch-site", "cross-site")],
		&[("sec-fetch-site", "same-site")],
		&[("sec-fetch-site", "same-origin")],
		&[("sec-fetch-site", "none")],
		&[("sec-fetch-user", "?1"), ("sec-fetch-site", "none")],
	];

	const SAME_ORIGIN: [&[(&str, &str)]; 3] = [&[("sec-fetch-site", "same-origin")], &[("origin", "https://redlib.example")], &[]];

	const CROSS_SITE: [&[(&str, &str)]; 4] = [
		&[("sec-fetch-site", "cross-site")],
		&[("sec-fetch-site", "same-site")],
		&[("sec-fetch-site", "none")],
		&[("origin", "https://evil.example")],
	];

	fn body_of(res: Response<Body>) -> String {
		String::from_utf8(block_on(res.into_body().collect_bytes()).unwrap().to_vec()).unwrap()
	}

	fn cookies_of(res: &Response<Body>) -> Vec<String> {
		res.headers().get_all("set-cookie").iter().map(|c| c.to_str().unwrap().to_string()).collect()
	}

	#[test]
	fn restore_by_get_does_not_touch_cookies() {
		for headers in ANY_GET {
			let res = block_on(restore(request("GET", "/settings/restore?redirect=/", headers))).unwrap();
			assert_eq!(res.status(), 200, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}: wiped or changed cookies");
			assert!(res.headers().get("location").is_none(), "{headers:?}");
		}
	}

	#[test]
	fn update_by_get_does_not_touch_cookies() {
		for headers in ANY_GET {
			let res = block_on(update(request("GET", "/settings/update?theme=light&redirect=/", headers))).unwrap();
			assert_eq!(res.status(), 200, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}: changed cookies");
			assert!(res.headers().get("location").is_none(), "{headers:?}");
		}
	}

	#[test]
	fn link_gets_a_page_that_continues_with_a_post() {
		// Restore links are meant to be shared, so they still work: one click on the page continues
		let res = block_on(restore(request(
			"GET",
			"/settings/restore/?theme=light&subscriptions=a+b&redirect=/r/a",
			&[("sec-fetch-site", "cross-site")],
		)))
		.unwrap();
		let body = body_of(res);
		assert!(
			body.contains("method=\"post\" action=\"/settings/restore?theme=light&#38;subscriptions=a+b&#38;redirect=/r/a\""),
			"{body}"
		);
	}

	#[test]
	fn restore_by_post_works() {
		for headers in SAME_ORIGIN {
			let res = block_on(restore(request("POST", "/settings/restore?theme=light&redirect=/r/rust", headers))).unwrap();
			assert_eq!(res.status(), 302, "{headers:?}");
			assert_eq!(res.headers()["location"], "/r/rust", "{headers:?}");
			let cookies = cookies_of(&res);
			assert!(cookies.iter().any(|c| c.starts_with("theme=light")), "{headers:?}: {cookies:?}");
			assert!(
				cookies.iter().any(|c| c.starts_with("subscriptions=;")),
				"{headers:?}: restore removes what the link does not carry: {cookies:?}"
			);
		}
	}

	#[test]
	fn update_by_post_works() {
		for headers in SAME_ORIGIN {
			let res = block_on(update(request("POST", "/settings/update?use_hls=on&redirect=/r/rust", headers))).unwrap();
			assert_eq!(res.status(), 302, "{headers:?}");
			assert_eq!(res.headers()["location"], "/r/rust", "{headers:?}");
			let cookies = cookies_of(&res);
			assert!(cookies.iter().any(|c| c.starts_with("use_hls=on")), "{headers:?}: {cookies:?}");
			assert!(!cookies.iter().any(|c| c.starts_with("subscriptions=;")), "{headers:?}: update keeps the rest: {cookies:?}");
		}
	}

	#[test]
	fn restore_and_update_by_cross_site_post_are_refused() {
		for headers in CROSS_SITE {
			let res = block_on(restore(request("POST", "/settings/restore?redirect=/", headers))).unwrap();
			assert_eq!(res.status(), 403, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}");
			let res = block_on(update(request("POST", "/settings/update?theme=light", headers))).unwrap();
			assert_eq!(res.status(), 403, "{headers:?}");
			assert!(res.headers().get("set-cookie").is_none(), "{headers:?}");
		}
	}

	#[tokio::test]
	async fn encoded_restore_applies_the_settings_without_another_click() {
		let prefs = Preferences {
			theme: "light".to_string(),
			..Preferences::default()
		};
		let form = form_urlencoded::Serializer::new(String::new())
			.append_pair("encoded_prefs", &prefs.to_bincode_str().unwrap())
			.finish();
		let mut req = request("POST", "/settings/encoded-restore", &[("sec-fetch-site", "same-origin")]);
		*req.body_mut() = Body::from(form);
		let res = encoded_restore(req).await.unwrap();
		assert_eq!(res.status(), 302);
		assert_eq!(res.headers()["location"], "/");
		let cookies = cookies_of(&res);
		assert!(cookies.iter().any(|c| c.starts_with("theme=light")), "{cookies:?}");
		assert!(cookies.iter().any(|c| c.starts_with("subscriptions=;")), "{cookies:?}");
	}

	/// Links in Redlib's own pages must not be GETs to the settings routes: those only show a
	/// confirmation page.
	#[test]
	fn templates_do_not_link_to_the_settings_routes() {
		for (name, template) in [
			("utils.html", include_str!("../templates/utils.html")),
			("nsfwlanding.html", include_str!("../templates/nsfwlanding.html")),
		] {
			assert!(!template.contains("href=\"/settings/update"), "{name} links to /settings/update");
			assert!(!template.contains("href=\"/settings/restore"), "{name} links to /settings/restore");
		}
	}
}

/// Hostile settings codes and request bodies (audit findings 3, 4, 5).
#[cfg(test)]
mod bounds_tests {
	use super::*;
	use crate::utils::deflate_compress;

	fn post(body: impl Into<Body>) -> Request<Body> {
		Request::builder().method("POST").body(body.into()).unwrap()
	}

	/// Form body carrying `bytes` as a base2048(deflate(..)) settings code.
	fn code_body(bytes: Vec<u8>) -> String {
		let code = base2048::encode(&deflate_compress(bytes).unwrap());
		form_urlencoded::Serializer::new(String::new()).append_pair("encoded_prefs", &code).finish()
	}

	/// The process must survive and answer with an error.
	async fn assert_rejected(body: impl Into<Body>) {
		let res = encoded_restore(post(body)).await;
		assert!(res.is_err(), "hostile code was accepted: {:?}", res.map(|r| r.status()));
	}

	/// The audit's 12-byte payload: base2048(deflate(u64le(2^50))). Legacy bincode
	/// takes the 2^50 as a String length and allocates it.
	#[tokio::test]
	async fn legacy_code_with_huge_length_prefix_is_rejected() {
		assert_rejected("encoded_prefs=%D2%B4%C3%98%C2%BA%C8%A0%D2%99%E0%BC%8D").await;
		assert_rejected(code_body((1u64 << 46).to_le_bytes().iter().copied().chain([b'x'; 16]).collect())).await;
	}

	/// 0xFF, revision 2, empty `available_themes`, then a `theme` length of 2^46
	/// (revision varint: 0xFD marker + u64le). Allocated before any byte is read.
	#[tokio::test]
	async fn revisioned_code_with_huge_length_prefix_is_rejected() {
		let mut bytes = vec![0xFF, 0x02, 0x00, 0xFD];
		bytes.extend((1u64 << 46).to_le_bytes());
		assert_rejected(code_body(bytes)).await;
		// The same for the Vec length of available_themes.
		let mut bytes = vec![0xFF, 0x02, 0xFD];
		bytes.extend((1u64 << 46).to_le_bytes());
		assert_rejected(code_body(bytes)).await;
	}

	/// A code that inflates far past anything a real settings code needs.
	#[tokio::test]
	async fn decompression_bomb_is_rejected() {
		let bomb = deflate_compress(vec![0u8; 8 * 1024 * 1024]).unwrap();
		assert!(bomb.len() < 64 * 1024, "the bomb must fit the body limit to reach the inflater");
		assert!(deflate_decompress(bomb).is_err());
		assert_rejected(code_body(vec![0u8; 8 * 1024 * 1024])).await;
	}

	#[tokio::test]
	async fn oversize_bodies_get_413() {
		let res = set(post(vec![b'a'; 300 * 1024])).await.unwrap();
		assert_eq!(res.status(), 413);
		let res = encoded_restore(post(vec![b'a'; 2 * 1024 * 1024])).await.unwrap();
		assert_eq!(res.status(), 413);
	}

	#[tokio::test]
	async fn a_normal_code_still_restores() {
		let body = form_urlencoded::Serializer::new(String::new())
			.append_pair("encoded_prefs", &Preferences::default().to_bincode_str().unwrap())
			.finish();
		let res = encoded_restore(post(body)).await.unwrap();
		assert_eq!(res.status(), 302);
		let res = set(post("theme=dark&layout=compact")).await.unwrap();
		assert_eq!(res.status(), 302);
	}
}
