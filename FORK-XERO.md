# xerootg/redlib

This fork runs [Nachtalb/redlib](https://github.com/Nachtalb/redlib) with a
few changes carried on top. Nachtalb's fork is the base because it still
reaches Reddit without an account: since October 2026 Reddit answers
anonymous JSON API requests with 403, and Nachtalb's backend layer serves
the same data from the Android app's GraphQL API instead. Everything in
[FORK.md](FORK.md) describes Nachtalb's changes; this file describes ours.

## Branches

| Branch | Based on | What it is |
|---|---|---|
| `nachtalb-base` | `Nachtalb/redlib` `main` | Untouched mirror of the base. |
| `deploy` | `nachtalb-base` | What runs in production: the base with every carried branch merged in. Pushing it builds the image. |
| `port-ci` | `nachtalb-base` | `.github/workflows/fork-container.yml`: gates on fmt, clippy and offline tests, then builds amd64 and arm64 images. |
| `port-oidc` | `nachtalb-base` | Native OIDC login (`src/oidc.rs`), with the auth bypass CIDRs and the `/mcp` bearer token. |
| `harden-oidc` | `port-oidc` | Fixes from a security review of the OIDC gate: redirect validation, fail-closed config parsing, X-Forwarded-For handling, ID-token checks, `__Host-` cookies, bearer token limited to `/mcp`, IdP timeouts. |
| `port-mcp` | `nachtalb-base` | Model Context Protocol server at `/mcp` (`src/mcp/`), reading Reddit through the backend layer. |
| `port-feat-multireddit` | `nachtalb-base` | `/user/<name>/m/<multi>` pages. |
| `port-fix-video-playsinline` | `nachtalb-base` | `playsinline` on every `<video>`, so iOS doesn't force fullscreen. |
| `port-fix-gallery-redirect` | `nachtalb-base` | `/gallery/<id>` redirects to the post. |
| `port-fix-account-only-errors` | `nachtalb-base` | A clear message for saved, upvoted, downvoted, hidden, r/friends and r/mod, which need an account. |
| `port-fix-hidden-profile-notice` | `nachtalb-base` | Explains empty profiles of users who hide their history. |
| `port-fix-download-audio` | `nachtalb-base` | Labels video downloads that have no audio track. |
| `port-fix-missing-comment-notice` | `nachtalb-base` | Explains permalinks to removed or missing comments. |
| `port-fix-quarantine-access` | `nachtalb-base` | Explains why quarantined subreddits are empty without an account. |
| `gate-exact-paths` | `harden-oidc` | The gate exempts exactly `/oidc/login`, `/oidc/callback`, `/oidc/logout` and `/healthz`, not every `/oidc/` path. |
| `feat-read-token` | `gate-exact-paths` | `REDLIB_READ_TOKEN`: a bearer token for in-cluster readers (mcp-reddit), GET/HEAD only, never `/settings`, `/mcp` or `/oidc`. |
| `fix-oidc-observability` | `gate-exact-paths` | Logs gate denials (rate-limited) and first passes per client, and keeps the query string across login. |
| `fix-compress-dos` | `nachtalb-base` | No memoised Accept-Encoding, digest cache keys, brotli off the async worker at quality 5. |
| `fix-settings-bounds` | `nachtalb-base` | Bounded settings-code decoding, capped inflate, a request body limit. |
| `fix-safe-redirects` | `nachtalb-base` | One same-origin redirect check everywhere, settings links confirm before acting, cross-site POSTs refused. |
| `fix-pref-validation` | `nachtalb-base` | Allowlisted preference values and subreddit names, so cookies can't carry attributes or odd API paths. |
| `fix-user-listing-allowlist` | `nachtalb-base` | Account-only listings never reach a backend. Known gap: non-ASCII spellings of `mod`/`friends` (only matters with a Reddit session). |
| `fix-proxy-hardening` | `nachtalb-base` | Media proxy host allowlist, outbound timeouts, redirect hop limit, header allowlist. |
| `fix-info-allowlist` | `nachtalb-base` | `/info` and `/info.json` show an explicit allowlist of settings, so new fields stay private by default. |
| `fix-html-charset` | `nachtalb-base` | `charset=utf-8` on every HTML response, `<meta charset>` first. |
| `fix-robustness` | `nachtalb-base` | Byte-bounded fetch cache with normalised keys, no `process::exit` on OAuth refresh failure, assorted panics and parsing fixes. |
| `fix-ci-supply-chain` | `port-ci` | Actions and base images pinned by digest, Dependabot, `cargo deny check advisories` in CI. |
| `port-docs` | `nachtalb-base` | This file. |

Not merged yet: `fix-cookie-parse` (numbered-cookie parsing; its review found remaining linear work and a flaky test).

Every carried branch is one or more pairs of commits: a test that fails
without the change, then the change. Keep it that way, so a branch can be
dropped, rebased or offered upstream on its own.

## Syncing with Nachtalb

```bash
git fetch nachtalb main
git branch -f nachtalb-base nachtalb/main
git switch deploy
git merge nachtalb-base          # resolve, then run the checks below
```

When a carried branch conflicts badly, rebase that branch onto the new
`nachtalb-base` and re-merge it instead of fixing it inside the merge.
If Nachtalb adopts one of our changes, drop the branch and record it here.

Turn on `git config rerere.enabled true`: the same conflicts come back on
every sync, and rerere replays the earlier resolution.

Conventions that keep merges small:

- Put new tests for a carried change in their own `#[cfg(test)]` module
  (or at least not at the very end of an existing one). Appending to the
  end of the same test module from two branches is the most common
  conflict.
- Add new settings in their own block in `src/config.rs`, not between
  Nachtalb's.
- Don't reformat or refactor Nachtalb's code in a carried branch.

## Checks

The same gate CI runs before it builds an image:

```bash
cargo +stable fmt --all -- --check
cargo +stable clippy --locked --all-targets -- -D warnings
cargo +stable test --locked -- --skip live_tests::
```

The `live_tests` module calls Reddit and is skipped in CI, because Reddit
captchas GitHub's runners. Run it locally after a sync:
`cargo +stable test --locked live_tests::`.

Use the stable toolchain: `sealed_test` doesn't build on nightly.

## Deploying

1. Push `deploy`. The "Fork container build" workflow runs the checks and
   publishes `ghcr.io/xerootg/redlib:sha-<short>`.
2. Pin the image digest in the cluster's GitOps repo
   (`configs/redlib/deployment.yaml`); Argo CD rolls it out.
3. Check the instance: `/healthz` (process up) and `/healthz/reddit`
   (whether Reddit is still answering).

## Secrets

The OIDC client secret, the session secret and `REDLIB_MCP_TOKEN` come
from a Kubernetes Secret, never from the image or the repository. They
are never serialized: `/info.json` serializes the whole config, so every
credential field must carry `#[serde(skip_serializing)]` and a test that
checks it stays out of `/info.json`. An earlier build of this fork
published all three there; treat any new credential setting the same way.

## Outlook

Reddit has announced it is moving to logged-in-only access. The GraphQL
route depends on Reddit not enforcing app attestation for anonymous
tokens, and on the persisted query hashes Nachtalb tracks. When it stops
working, `/healthz/reddit` reports it before users do.
