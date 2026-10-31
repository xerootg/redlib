pub mod backends;
pub mod body;
pub mod client;
pub mod config;
pub mod duplicates;
pub mod instance_info;
pub mod mcp;
pub mod oauth;
pub mod oauth_resources;
pub mod oidc;
pub mod post;
pub mod pref_validation;
pub mod reddit_health;
pub mod redgifs;
pub mod search;
pub mod server;
pub mod settings;
pub mod subreddit;
pub mod user;
pub mod utils;

#[cfg(test)]
mod pref_validation_tests;
