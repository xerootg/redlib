#[cfg(test)]
mod tests {
	use super::*;
	use hyper::header::HeaderValue;
	use sealed_test::prelude::*;

	fn net(s: &str) -> IpNet {
		s.parse().unwrap()
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
		let mut map = HeaderMap::new();
		for (name, value) in pairs {
			map.append(*name, HeaderValue::from_str(value).unwrap());
		}
		map
	}

	fn xff(value: &str) -> HeaderMap {
		headers(&[("x-forwarded-for", value)])
	}

	fn location(res: &Response<Body>) -> String {
		res.headers().get("location").unwrap().to_str().unwrap().to_string()
	}

	fn body_text(res: Response<Body>) -> String {
		let bytes = futures_lite::future::block_on(res.into_body().collect_bytes()).unwrap();
		String::from_utf8(bytes.to_vec()).unwrap()
	}

	const BROWSER: (&str, &str) = ("accept", "text/html,application/xhtml+xml,*/*;q=0.8");
	const OUTSIDE: &str = "203.0.113.9";

	// --- Ported from the original module ------------------------------------

	#[test]
	fn parses_cidrs_and_bare_addresses() {
		let parsed = parse_cidrs(Some("192.168.0.0/16, 10.42.0.0/16 ,203.0.113.5".to_string()), "test");
		assert_eq!(parsed, vec![net("192.168.0.0/16"), net("10.42.0.0/16"), net("203.0.113.5/32")]);
	}

	#[test]
	fn skips_unparseable_cidrs() {
		let parsed = parse_cidrs(Some("192.168.0.0/16,not-an-ip,10.0.0.0/8".to_string()), "test");
		assert_eq!(parsed, vec![net("192.168.0.0/16"), net("10.0.0.0/8")]);
	}

	#[test]
	fn canonicalises_ipv4_mapped_addresses() {
		// redlib listens on `[::]`, so this is how a real IPv4 client from the
		// pod network actually arrives. It must match an IPv4 CIDR.
		assert_eq!(canonical(ip("::ffff:10.42.0.5")), ip("10.42.0.5"));
		// Genuine IPv6 must be left alone.
		assert_eq!(canonical(ip("fd12::1")), ip("fd12::1"));

		let nets = [net("10.42.0.0/16")];
		let mapped = canonical(ip("::ffff:10.42.0.5"));
		assert!(nets.iter().any(|n| n.contains(&mapped)), "IPv4-mapped peer must match an IPv4 bypass CIDR");
	}

	// The original tests re-implemented the selection logic next to the
	// tests; these call the same function the gate uses, with an explicit
	// proxy list instead of the global config.

	#[test]
	fn mapped_peer_is_recognised_as_a_trusted_proxy() {
		// Same trap one layer up: the proxy check must see through the mapping,
		// or XFF would be ignored and every client would look like the proxy.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("::ffff:10.42.0.7"), &xff("203.0.113.9"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn ignores_forwarded_header_from_untrusted_peer() {
		// The spoofing case: a direct client claims to be on the LAN.
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("203.0.113.9"), &xff("192.168.1.5"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn takes_rightmost_untrusted_hop_from_trusted_peer() {
		let trusted = [net("10.42.0.0/16")];
		// Client prepended a forged entry; the real address is on the right.
		let got = resolve_with(&trusted, ip("10.42.0.7"), &xff("192.168.1.5, 203.0.113.9"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn skips_trusted_hops_in_the_chain() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), &xff("203.0.113.9, 10.42.0.3"));
		assert_eq!(got, ip("203.0.113.9"));
	}

	#[test]
	fn falls_back_to_peer_when_chain_is_all_trusted() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), &xff("10.42.0.3"));
		assert_eq!(got, ip("10.42.0.7"));
	}

	#[test]
	fn falls_back_to_peer_without_forwarded_header() {
		let trusted = [net("10.42.0.0/16")];
		let got = resolve_with(&trusted, ip("10.42.0.7"), &HeaderMap::new());
		assert_eq!(got, ip("10.42.0.7"));
	}

	#[test]
	fn bypass_matching_covers_v4_and_v6() {
		let nets = [net("192.168.0.0/16"), net("fd00::/8")];
		assert!(nets.iter().any(|n| n.contains(&ip("192.168.4.20"))));
		assert!(nets.iter().any(|n| n.contains(&ip("fd12::1"))));
		assert!(!nets.iter().any(|n| n.contains(&ip("203.0.113.1"))));
	}

	// --- Pure helpers -------------------------------------------------------

	#[test]
	fn login_redirect_only_accepts_local_paths() {
		assert_eq!(redirect_target(Some("redirect=%2Fr%2Frust")), "/r/rust");
		assert_eq!(redirect_target(Some("x=1&redirect=/u/spez")), "/u/spez");
		// Anything that could leave this instance is replaced by the front page.
		assert_eq!(redirect_target(Some("redirect=https%3A%2F%2Fevil.example")), "/");
		assert_eq!(redirect_target(Some("redirect=%2F%2Fevil.example")), "/");
		assert_eq!(redirect_target(Some("redirect=evil.example")), "/");
		assert_eq!(redirect_target(Some("")), "/");
		assert_eq!(redirect_target(None), "/");
	}

	#[test]
	fn login_path_is_percent_encoded() {
		assert_eq!(urlencoding_path("/r/rust/comments/abc"), "%2Fr%2Frust%2Fcomments%2Fabc");
	}

	#[test]
	fn browsers_are_told_apart_from_programmatic_clients() {
		assert!(wants_html(&headers(&[BROWSER])));
		assert!(!wants_html(&headers(&[("accept", "application/json")])));
		assert!(!wants_html(&headers(&[("accept", "*/*")])));
		assert!(!wants_html(&HeaderMap::new()));
	}

	#[test]
	fn cookies_are_secure_unless_running_over_plain_http() {
		assert_eq!(cookie_attrs(true, 60), "Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure");
		assert_eq!(cookie_attrs(false, 0), "Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
	}

	#[test]
	fn cookie_value_finds_the_named_cookie_only() {
		let h = headers(&[("cookie", "a=1; redlib_session=tok; b=2"), ("cookie", "redlib_oidc_tx=tx")]);
		assert_eq!(cookie_value(&h, "redlib_session").as_deref(), Some("tok"));
		assert_eq!(cookie_value(&h, "redlib_oidc_tx").as_deref(), Some("tx"));
		assert_eq!(cookie_value(&h, "redlib"), None);
	}

	// --- Configuration ------------------------------------------------------

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "on")])]
	fn enabled_without_required_settings_names_what_is_missing() {
		let cfg = AuthConfig::load_unchecked();
		assert!(cfg.enabled);
		assert_eq!(
			cfg.missing_required(),
			vec!["REDLIB_OIDC_ISSUER", "REDLIB_OIDC_CLIENT_ID", "REDLIB_OIDC_CLIENT_SECRET", "REDLIB_OIDC_REDIRECT_URI"]
		);
	}

	#[test]
	#[sealed_test]
	fn settings_are_read_from_redlib_toml() {
		std::fs::write(
			"redlib.toml",
			"REDLIB_OIDC_ENABLED = true\n\
			REDLIB_OIDC_ISSUER = \"https://idp.example/application/o/redlib/\"\n\
			REDLIB_OIDC_CLIENT_ID = \"id\"\n\
			REDLIB_OIDC_CLIENT_SECRET = \"secret\"\n\
			REDLIB_OIDC_REDIRECT_URI = \"https://redlib.example/oidc/callback\"\n\
			REDLIB_OIDC_SESSION_TTL = 3600\n\
			REDLIB_OIDC_ALLOWED_GROUPS = \"admins, readers\"\n\
			REDLIB_AUTH_BYPASS_CIDRS = \"192.168.0.0/16,100.64.0.0/10\"\n\
			REDLIB_TRUSTED_PROXIES = \"10.42.0.0/16\"\n",
		)
		.unwrap();
		let cfg = AuthConfig::load_unchecked();
		// A TOML boolean arrives as "on", which must count as enabled.
		assert!(cfg.enabled);
		assert!(cfg.missing_required().is_empty());
		// The trailing slash is dropped so discovery URLs don't get `//`.
		assert_eq!(cfg.issuer, "https://idp.example/application/o/redlib");
		assert_eq!(cfg.scopes, DEFAULT_SCOPES);
		assert_eq!(cfg.session_ttl, 3600);
		assert_eq!(cfg.allowed_groups, vec!["admins", "readers"]);
		assert_eq!(cfg.bypass_cidrs, vec![net("192.168.0.0/16"), net("100.64.0.0/10")]);
		assert_eq!(cfg.trusted_proxies, vec![net("10.42.0.0/16")]);
	}

	#[test]
	#[sealed_test(env = [("REDLIB_OIDC_ENABLED", "off"), ("REDLIB_OIDC_ISSUER", "https://idp.example")])]
	fn only_on_true_or_1_enable_auth() {
		assert!(!AuthConfig::load_unchecked().enabled);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_CLIENT_SECRET", "client-secret-value"),
		("REDLIB_OIDC_SESSION_SECRET", "session-secret-value"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.77.0/24"),
		("REDLIB_TRUSTED_PROXIES", "10.99.0.0/16"),
	])]
	fn secrets_and_network_layout_never_reach_info_json() {
		// `/info.json` serializes the whole config.
		let json = serde_json::to_string(&crate::config::Config::load()).unwrap();
		for leaked in ["client-secret-value", "session-secret-value", "192.168.77.0", "10.99.0.0"] {
			assert!(!json.contains(leaked), "{leaked} is in /info.json");
		}
	}

	// --- The gate, against the real global config ---------------------------

	#[test]
	#[sealed_test]
	fn gate_is_open_when_disabled() {
		assert!(gate(ip(OUTSIDE), "/", &headers(&[BROWSER])).is_none());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_redirects_browsers_to_login() {
		let res = gate(ip(OUTSIDE), "/r/rust/comments/abc", &headers(&[BROWSER])).expect("must be gated");
		assert_eq!(res.status(), StatusCode::FOUND);
		assert_eq!(location(&res), "/oidc/login?redirect=%2Fr%2Frust%2Fcomments%2Fabc");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_answers_programmatic_clients_with_401_json() {
		let res = gate(ip(OUTSIDE), "/r/rust", &headers(&[("accept", "application/json")])).expect("must be gated");
		assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
		assert_eq!(res.headers()["www-authenticate"], "Bearer realm=\"https://idp.example/application/o/redlib\"");
		assert_eq!(res.headers()["content-type"], "application/json");
		assert_eq!(body_text(res), r#"{"error":"unauthorized","error_description":"Authentication required."}"#);
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_never_blocks_its_own_endpoints() {
		for path in ["/oidc/login", "/oidc/callback", "/oidc/logout"] {
			assert!(gate(ip(OUTSIDE), path, &headers(&[BROWSER])).is_none(), "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_covers_every_other_path() {
		// Only `/oidc/` is exempt, as in the original. Health checks, static
		// files and `/mcp` all need a session, a bypass address or (once
		// configured) the bearer token.
		for path in ["/", "/healthz", "/healthz/reddit", "/healthz/reddit.json", "/style.css", "/info.json", "/mcp", "/oidc"] {
			let res = gate(ip(OUTSIDE), path, &HeaderMap::new()).unwrap_or_else(|| panic!("{path} must be gated"));
			assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
		}
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.0.0/16,127.0.0.0/8"),
		("REDLIB_TRUSTED_PROXIES", "10.42.0.0/16"),
	])]
	fn gate_lets_bypass_addresses_through() {
		assert!(gate(ip("192.168.1.20"), "/", &headers(&[BROWSER])).is_none());
		// Dual-stack sockets report IPv4 clients as mapped IPv6.
		assert!(gate(ip("::ffff:127.0.0.1"), "/", &headers(&[BROWSER])).is_none());
		// Through the trusted proxy, the forwarded address decides.
		assert!(gate(ip("10.42.0.7"), "/", &xff("192.168.1.20")).is_none());
		assert!(gate(ip("10.42.0.7"), "/", &xff(OUTSIDE)).is_some());
		// The proxy itself is not a bypass address.
		assert!(gate(ip("10.42.0.7"), "/", &HeaderMap::new()).is_some());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
		("REDLIB_AUTH_BYPASS_CIDRS", "192.168.0.0/16"),
	])]
	fn gate_ignores_forged_forwarded_for_without_trusted_proxies() {
		let res = gate(ip(OUTSIDE), "/", &xff("192.168.1.20"));
		assert_eq!(res.expect("forged XFF must not bypass").status(), StatusCode::UNAUTHORIZED);
	}

	fn session(exp: u64) -> Session {
		Session {
			sub: "user-1".into(),
			username: "user".into(),
			email: String::new(),
			groups: vec![],
			exp,
			iat: now(),
		}
	}

	fn session_cookie(token: &str) -> HeaderMap {
		headers(&[("cookie", &format!("theme=dark; {SESSION_COOKIE}={token}")), BROWSER])
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_accepts_a_valid_session_cookie() {
		let token = sign(&session(now() + 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&token)).is_none());
		assert_eq!(session_from(&session_cookie(&token)).unwrap().sub, "user-1");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn gate_rejects_expired_tampered_and_foreign_sessions() {
		// Expired beyond jsonwebtoken's default 60 s leeway.
		let expired = sign(&session(now() - 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&expired)).is_some(), "expired");

		// Payload swapped under an existing signature.
		let valid = sign(&session(now() + 3600)).unwrap();
		let mut parts: Vec<&str> = valid.split('.').collect();
		let forged_claims = URL_SAFE_NO_PAD.encode(
			serde_json::to_vec(&Session {
				sub: "admin".into(),
				..session(now() + 3600)
			})
			.unwrap(),
		);
		parts[1] = &forged_claims;
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&parts.join("."))).is_some(), "tampered");

		// Signed with a different key.
		let foreign = encode(&Header::new(Algorithm::HS256), &session(now() + 3600), &EncodingKey::from_secret(b"other")).unwrap();
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&foreign)).is_some(), "foreign key");

		// `alg: none` must never be accepted.
		let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
		let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&session(now() + 3600)).unwrap());
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&format!("{header}.{claims}."))).is_some(), "alg none");
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
		("REDLIB_OIDC_SESSION_SECRET", "test-session-secret"),
	])]
	fn login_transaction_cookie_is_not_a_session() {
		// Both are signed with the same key; the claim shapes must keep them apart.
		let tx = sign(&LoginTx {
			state: "s".into(),
			nonce: "n".into(),
			verifier: "v".into(),
			redirect_to: "/".into(),
			exp: now() + TX_TTL,
		})
		.unwrap();
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&tx)).is_some());
	}

	#[test]
	#[sealed_test(env = [
		("REDLIB_OIDC_ENABLED", "on"),
		("REDLIB_OIDC_ISSUER", "https://idp.example/application/o/redlib/"),
		("REDLIB_OIDC_CLIENT_ID", "id"),
		("REDLIB_OIDC_CLIENT_SECRET", "secret"),
		("REDLIB_OIDC_REDIRECT_URI", "https://redlib.example/oidc/callback"),
	])]
	fn sessions_still_work_with_an_ephemeral_key() {
		let token = sign(&session(now() + 3600)).unwrap();
		assert!(gate(ip(OUTSIDE), "/", &session_cookie(&token)).is_none());
	}
}
