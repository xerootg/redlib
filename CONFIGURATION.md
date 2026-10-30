# Configuration

You can configure Redlib further using environment variables. For example:

```bash
REDLIB_DEFAULT_SHOW_NSFW=on redlib
```

```bash
REDLIB_DEFAULT_WIDE=on REDLIB_DEFAULT_THEME=dark redlib -r
```

You can also configure Redlib with a configuration file named `redlib.toml`. For example:

```toml
REDLIB_DEFAULT_WIDE = "on"
REDLIB_DEFAULT_USE_HLS = "on"
REDLIB_SCRAPE_COMMENT_PREFETCH = 0
```

Numbers and booleans work as well as strings; `true`/`false` mean `on`/`off`.

> [!NOTE]
> If you're deploying Redlib using the **Docker CLI or Docker Compose**, environment variables can be defined in a [`.env` file](https://docs.docker.com/compose/environment-variables/set-environment-variables/), allowing you to centralize and manage configuration in one place.
>
> To configure Redlib using a `.env` file, copy the `.env.example` file to `.env` and edit it accordingly.
>
> If using the Docker CLI, add ` --env-file .env` to the command that runs Redlib. For example:
>
> ```bash
> docker run -d --name redlib -p 8080:8080 --env-file .env ghcr.io/nachtalb/redlib:latest
> ```
>
> If using Docker Compose, no changes are needed as the `.env` file is already referenced in `compose.yaml` via the `env_file: .env` line.

## Command Line Flags

Redlib supports the following command line flags. They take precedence over environment variables and `redlib.toml`; environment variables in turn take precedence over `redlib.toml`.

- `-4`, `--ipv4-only`: Listen on IPv4 only.
- `-6`, `--ipv6-only`: Listen on IPv6 only.
- `-r`, `--redirect-https`: Redirect all HTTP requests to HTTPS (no longer functional).
- `-a`, `--address <ADDRESS>`: Sets address to listen on. Default is `[::]`.
- `-p`, `--port <PORT>`: Port to listen on. Default is `8080`.
- `-H`, `--hsts <EXPIRE_TIME>`: HSTS header to tell browsers that this site should only be accessed over HTTPS. Default is `604800`.

## Instance settings

Assign a default value for each instance-specific setting by passing environment variables to Redlib in the format `REDLIB_{X}`. Replace `{X}` with the setting name (see list below) in capital letters.

| Name                      | Possible values | Default value                          | Description                                                                                               |
|---------------------------|-----------------|----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `SFW_ONLY`                | `["on", "off"]` | `off`                                  | Enables SFW-only mode for the instance, i.e. all NSFW content is filtered.                                |
| `BANNER`                  | String          | (empty)                                | Allows the server to set a banner to be displayed. Currently this is displayed on the instance info page. |
| `ROBOTS_DISABLE_INDEXING` | `["on", "off"]` | `off`                                  | Disables indexing of the instance by search engines.                                                      |
| `PUSHSHIFT_FRONTEND`      | String          | `undelete.pullpush.io`                 | Allows the server to set the Pushshift frontend to be used with "removed" links.                          |
| `PORT`                    | Integer 0-65535 | `8080`                                 | The **internal** port Redlib listens on.                                                                  |
| `ENABLE_RSS`              | `["on", "off"]` | `off`                                  | Enables RSS feed generation.                                                                              |
| `ENABLE_REDGIFS`          | `["on", "off"]` | `on`                                   | Proxies RedGifs videos and plays them inline. Set to `off` to leave RedGifs as plain links.               |
| `ENABLE_GIPHY`            | `["on", "off"]` | `on`                                   | Proxies GIPHY GIFs in comments and plays them inline. Set to `off` to leave them as plain links.          |
| `FULL_URL`                | String          | (empty)                                | Allows for proper URLs (for now, only needed by RSS)                                                      |
| `SOURCE_URL`              | String          | `https://github.com/Nachtalb/redlib`   | Link to the source code for this instance. The update check on error pages compares against this GitHub repository's `main` branch. |
| `ENABLE_SCRAPE_FALLBACK`  | `["on", "off"]` | `on`                                   | Allows the `scraped` backend: comments scraped from Reddit's HTML. See [Scrape fallback](#scrape-fallback). |
| `ENABLE_GQL`              | `["on", "off"]` | `on`                                   | Allows the `gql` backend: Reddit's GraphQL API. `off` never contacts it. |
| `ENDPOINTS`, `ENDPOINTS_<KIND>` | List      | per kind                               | Which backends load Reddit data, in which order. See [Backend order](#backend-order). |
| `SCRAPE_COMMENT_PREFETCH` | Integer         | `0`                                    | Extra requests a scraped post page makes to load more comments up front. See [Scrape fallback](#scrape-fallback). |
| `GQL_FEED_REQUESTS`       | Integer         | `2`                                    | Requests the `gql` backend makes to fill one r/all page. Reddit sends only about 8 posts for the first. |
| `REDDIT_COOKIE`           | String          | (empty)                                | Logged-in `reddit_session` cookies, `|`-separated, for the `cookied-json` and `obscura-cookied-json` backends. Use throwaway accounts. See [Reddit session](#reddit-session). |
| `REDDIT_COOKIE_FILE`      | String          | (empty)                                | File with more sessions, one per line, reread while running. See [Reddit session](#reddit-session). |
| `LISTEN_PORT`             | Integer         | `8080`                                 | Port to listen on. `-p` and the `PORT` environment variable take precedence. |
| `LISTEN_ADDRESS`          | String          | `[::]`                                 | Address to listen on. `-a` takes precedence. |
| `HSTS`                    | Integer         | `604800`                               | `max-age` of the HSTS header in seconds. `-H` takes precedence. |
| `IPV4_ONLY`               | `["on", "off"]` | `off`                                  | Listens on IPv4 only, like `-4` or `IPV4_ONLY`. |
| `IPV6_ONLY`               | `["on", "off"]` | `off`                                  | Listens on IPv6 only, like `-6` or `IPV6_ONLY`. |
| `OIDC_ENABLED`            | `["on", "off"]` | `off`                                  | Requires a login through an OpenID Connect provider. See [OIDC login](#oidc-login). |
| `OIDC_ISSUER`             | String          | (empty)                                | Issuer URL of the provider. Required with `OIDC_ENABLED`. |
| `OIDC_CLIENT_ID`          | String          | (empty)                                | Client ID registered with the provider. Required with `OIDC_ENABLED`. |
| `OIDC_CLIENT_SECRET`      | String          | (empty)                                | Client secret. Required with `OIDC_ENABLED`. **Secret.** |
| `OIDC_REDIRECT_URI`       | String          | (empty)                                | This instance's `/oidc/callback` URL, exactly as registered with the provider. Required with `OIDC_ENABLED`. |
| `OIDC_SCOPES`             | String          | `openid profile email`                 | Space-separated scopes to request. |
| `OIDC_SESSION_SECRET`     | String          | (random per start)                     | Key that signs session cookies, at least 32 bytes. Set it, or every restart logs everyone out. **Secret.** |
| `OIDC_SESSION_TTL`        | Integer         | `86400`                                | Session lifetime in seconds. |
| `OIDC_ALLOWED_GROUPS`     | List            | (empty)                                | Comma-separated groups; when set, a login must carry one of them. |
| `AUTH_BYPASS_CIDRS`       | List            | (empty)                                | Comma-separated CIDRs or addresses that skip the login. |
| `TRUSTED_PROXIES`         | List            | (empty)                                | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` is believed. |
| `MCP_TOKEN`               | String          | (empty)                                | Bearer token that passes the login on any path, for clients that can't hold a cookie. **Secret.** |

### Reddit session

Reddit only serves post pages to logged-in sessions. Set `REDLIB_REDDIT_COOKIE` to the `reddit_session` cookie of a logged-in reddit.com browser (DevTools → Application → Cookies); no other cookie is needed. Separate several sessions with `|` to rotate between them:

```bash
REDLIB_REDDIT_COOKIE="reddit_session=...|reddit_session=..."
```

The `reddit_session=` prefix is optional. A whole `Cookie` header works too, as long as it has `reddit_session` in it. Sessions whose `reddit_session` has expired (it lasts about six months) are skipped with a warning in the log.

To add or remove sessions without a restart, put them in a file and point `REDLIB_REDDIT_COOKIE_FILE` at it. Each line is one session in the same form, lines starting with `#` are comments. Redlib checks the file for changes every 10 seconds; if it can't be read, the sessions read last stay in use. Both settings can be combined.

```bash
# /etc/redlib/sessions.txt
# throwaway 1
reddit_session=...
# throwaway 2
reddit_session=...
```

With Docker, mount the file read-only, e.g. `-v ./sessions.txt:/sessions.txt:ro` with `REDLIB_REDDIT_COOKIE_FILE=/sessions.txt`. Mount its directory instead if your editor replaces the file when saving: a single-file mount keeps showing the old one.

**Use a throwaway account**, never your main one: the instance's traffic runs through it and Reddit may ban it. Keep the value secret. Pressing "Log out" on reddit.com ends the session.

The `ghcr.io/nachtalb/redlib:latest-obscura` image (amd64 only, or `cargo build --release --features obscura`) can also send a session's requests through the embedded [Obscura](https://github.com/h4ckf0r0day/obscura) headless browser: the `obscura-cookied-json` backend. `latest` and default builds don't have it.

### Scrape fallback

When the backends before it fail, the `scraped` backend loads a post page's comments from the HTML Reddit serves logged-out visitors. It shows Reddit's first batch; "More comments" and "More replies" fetch more when clicked. To load more up front, set `REDLIB_SCRAPE_COMMENT_PREFETCH` to the number of extra requests per page, e.g. `5`.

Scraped pages cost Reddit extra requests and may break when Reddit changes its pages. Set `REDLIB_ENABLE_SCRAPE_FALLBACK=off` to show the block error instead.

### Backend order

<details>
<summary>Which backend loads what, and how to change the order</summary>

Redlib tries backends one after another until one returns the page or Reddit gives a real answer (not found, private, banned). Set the order per kind of request with `REDLIB_ENDPOINTS_<KIND>`, or for all kinds with `REDLIB_ENDPOINTS`. Backends left out are never used; ones without a session, or not in the build, are skipped. The log lists each kind's order at startup.

```bash
REDLIB_ENDPOINTS_COMMENTS="cookied-json,gql,scraped"
```

While running, Redlib reorders the listed backends by how often each worked in the last half hour or so, counting session backends as twice as expensive (they use up the account's request budget). Your order is where it starts after a restart, and where a backend drifts back to once its failures are old, so a blocked backend gets tried again later. `/info` shows the current order and each backend's score.

`json` is Reddit's API without an account, `cookied-json` the same with a session from `REDLIB_REDDIT_COOKIE`, `gql` Reddit's GraphQL API (what the Android app uses), `scraped` comments from the HTML Reddit serves logged-out visitors, and `obscura-cookied-json` a session through Obscura (`latest-obscura` only).

| `<KIND>`     | `json`     | `cookied-json` | `gql` | `scraped` | `obscura-cookied-json` | Default order |
| ------------ | ---------- | -------------- | ----- | --------- | ---------------------- | ------------- |
| `POST`       | ✅         | ✅             | ✅    | ❌        | ✅                     | gql, json, cookied-json, obscura-cookied-json |
| `COMMENTS`   | ⚠️ blocked | ✅             | ✅    | ✅        | ✅                     | gql, cookied-json, obscura-cookied-json, scraped, json |
| `LISTING`    | ✅         | ✅             | ⚠️¹   | ❌        | ✅                     | json, gql, cookied-json, obscura-cookied-json |
| `ALL`        | ✅²        | ✅²            | ⚠️³   | ❌        | ✅²                    | json, gql, cookied-json, obscura-cookied-json |
| `SUBREDDIT`  | ✅         | ✅             | ✅    | ❌        | ✅                     | gql, json, cookied-json, obscura-cookied-json |
| `USER`       | ⚠️ blocked | ✅             | ✅    | ❌        | ✅                     | gql, cookied-json, obscura-cookied-json |
| `SEARCH`     | ✅         | ✅             | ✅    | ❌        | ✅                     | gql, json, cookied-json, obscura-cookied-json |
| `WIKI`       | ✅         | ✅             | ❌    | ❌        | ✅                     | json, cookied-json, obscura-cookied-json |
| `DUPLICATES` | ✅         | ✅             | ❌    | ❌        | ✅                     | json, cookied-json, obscura-cookied-json |

¹ Skipped without a request for feeds of several subreddits (`r/a+b`, the front page of your subscriptions).

² Reddit [retired r/all](https://www.reddit.com/r/reddithelp/comments/1rfmh8h/a_helpful_link_to_rall/) and answers `/r/all.json` with 403, but still serves the same feed as `/r/all+.json`, which is requested instead.

³ The old GraphQL feed sends about 8 posts per request, so a page takes up to `REDLIB_GQL_FEED_REQUESTS` requests.

</details>

### OIDC login

With `REDLIB_OIDC_ENABLED=on`, every page needs a login through an OpenID Connect provider such as authentik, Keycloak or Authelia. Register a confidential client with the redirect URI `https://<your instance>/oidc/callback`, then set:

```bash
REDLIB_OIDC_ENABLED=on
REDLIB_OIDC_ISSUER=https://auth.example.com/application/o/redlib/
REDLIB_OIDC_CLIENT_ID=...
REDLIB_OIDC_CLIENT_SECRET=...
REDLIB_OIDC_REDIRECT_URI=https://redlib.example.com/oidc/callback
REDLIB_OIDC_SESSION_SECRET=<at least 32 random bytes, e.g. from openssl rand -hex 32>
```

Redlib won't start if OIDC is on and any of the issuer, client ID, client secret or redirect URI is missing, or if the session secret is shorter than 32 bytes.

`REDLIB_OIDC_ENABLED` accepts `on`, `true`, `yes` or `1` to turn the login on and `off`, `false`, `no` or `0` to turn it off, in any case. Unset means off. Any other value, including an empty one, stops Redlib at startup instead of being read as off. If OIDC is off but the issuer, client ID, client secret or session secret is set, Redlib logs a warning, since that usually means the switch was forgotten.

- Browsers without a session are sent to `/oidc/login`, and back to the page they asked for afterwards. Other clients (no `text/html` in `Accept`) get `401` with `{"error":"unauthorized","error_description":"Authentication required."}`.
- `/oidc/login`, `/oidc/callback` and `/oidc/logout` are the only paths without a login. Health checks (`/healthz`, `/healthz/reddit`) and `/mcp` need one too, so point probes at the instance from an address in `REDLIB_AUTH_BYPASS_CIDRS`.
- ID tokens must be signed with RS256, or with the asymmetric algorithm the provider's signing key declares in its JWKS `alg`, and must carry `iss`, `aud`, `exp` and `iat`. With more than one audience, `azp` must be the client ID.
- `/oidc/logout` ends the session and then the provider's session, if the provider offers that.
- Sessions are signed cookies; Redlib stores nothing. They can't be revoked one by one: changing `REDLIB_OIDC_SESSION_SECRET` ends all of them.
- Clients in `REDLIB_AUTH_BYPASS_CIDRS` skip the login, e.g. `192.168.0.0/16,100.64.0.0/10`. Behind a reverse proxy, list the proxy in `REDLIB_TRUSTED_PROXIES`: `X-Forwarded-For` is read only when the connection comes from one of those, right to left, skipping the proxies. Every `X-Forwarded-For` line counts, in order, and the walk stops at the first entry that isn't a plain IPv4 or IPv6 address (IPv6 may be in brackets; a port is not allowed). If a proxy sends no `X-Forwarded-For`, one that lists only proxies, or one with an entry that can't be read, the client counts as unknown: it gets no bypass, even if the proxy's own address is in a bypass range, but can still log in. From anywhere else the header is ignored and the connecting address is the client, so a client can't claim a bypass address. IPv4 clients on Redlib's dual-stack `[::]` socket match IPv4 ranges.
- `REDLIB_MCP_TOKEN` lets clients that can't hold a cookie in with `Authorization: Bearer <token>`, on any path.

The secrets, the bypass ranges and the proxy list never show on `/info`.

## Default user settings

Assign a default value for each user-modifiable setting by passing environment variables to Redlib in the format `REDLIB_DEFAULT_{Y}`. Replace `{Y}` with the setting name (see list below) in capital letters.

| Name                                | Possible values                                                                                                                                                                                                                 | Default value |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| `THEME`                             | `["system", "light", "dark", "black", "dracula", "nord", "laserwave", "violet", "gold", "rosebox", "gruvboxdark", "gruvboxlight", "tokyoNight", "icebergDark", "doomone", "libredditBlack", "libredditDark", "libredditLight", "catppuccinLatte", "catppuccinFrappe", "catppuccinMacchiato", "catppuccinMocha"]` | `system`      |
| `FRONT_PAGE`                        | `["default", "popular", "all"]`                                                                                                                                                                                                 | `default`     |
| `LAYOUT`                            | `["card", "clean", "compact"]`                                                                                                                                                                                                  | `card`        |
| `WIDE`                              | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `POST_SORT`                         | `["hot", "new", "top", "rising", "controversial"]`                                                                                                                                                                              | `hot`         |
| `COMMENT_SORT`                      | `["confidence", "top", "new", "controversial", "old"]`                                                                                                                                                                          | `confidence`  |
| `BLUR_SPOILER`                      | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `SHOW_NSFW`                         | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `BLUR_NSFW`                         | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `USE_HLS`                           | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `HIDE_HLS_NOTIFICATION`             | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `AUTOPLAY_VIDEOS`                   | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `SUBSCRIPTIONS`                     | `+`-delimited list of subreddits (`sub1+sub2+sub3+...`)                                                                                                                                                                         | _(none)_      |
| `HIDE_AWARDS`                       | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `DISABLE_VISIT_REDDIT_CONFIRMATION` | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `HIDE_SCORE`                        | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `HIDE_SIDEBAR_AND_SUMMARY`          | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `FIXED_NAVBAR`                      | `["on", "off"]`                                                                                                                                                                                                                 | `on`          |
| `REMOVE_DEFAULT_FEEDS`              | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `CLEAN_URLS`                        | `["on", "off"]`                                                                                                                                                                                                                 | `off`         |
| `POSTS_PER_PAGE`                    | Integer 1-100                                                                                                                                                                                                                   | 25            |
| `MAX_COMMENT_THREAD_DEPTH`          | Unsigned integer (0 = unlimited/Reddit default)                                                                                                                                                                                 | 0             |

## Forward proxies

Redlib's HTTP client, [wreq](https://docs.rs/wreq/latest/wreq/#proxies), uses the standard proxy variables, so all Reddit traffic can go through a proxy. Set `ALL_PROXY` for everything, or `HTTP_PROXY` / `HTTPS_PROXY` per scheme, and `NO_PROXY` for hosts to reach directly. The Obscura build's browser uses them too.

```bash
ALL_PROXY=socks5h://user:pass@proxy.example:1080 redlib
```

Schemes: `http://`, `https://`, `socks4://`, `socks4a://`, `socks5://` and `socks5h://` (DNS through the proxy).
