//! Tests for the MCP server's `reddit.rs`, ported ahead of the implementation.
//!
//! The implementation lands in the next commit; until then this module is
//! not declared in `lib.rs`, so the build is unaffected.

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
