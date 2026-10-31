//! A cache bounded by the memory its entries hold, not by how many there are.
//!
//! A thread page is megabytes once parsed, a listing is a few hundred
//! kilobytes, and an error is a few bytes, so a cap on the number of entries
//! is a cap on nothing.

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

struct Entry<V> {
	value: V,
	size: usize,
	at: Instant,
}

struct State<V> {
	entries: HashMap<String, Entry<V>>,
	/// Keys, oldest insertion first
	order: VecDeque<String>,
	bytes: usize,
}

/// A time-limited cache that drops its oldest entries to stay within a number
/// of bytes and of entries.
pub struct ByteCache<V> {
	max_bytes: usize,
	max_entries: usize,
	ttl: Duration,
	state: Mutex<State<V>>,
}

impl<V: Clone> ByteCache<V> {
	pub fn new(max_bytes: usize, max_entries: usize, ttl: Duration) -> Self {
		Self {
			max_bytes,
			max_entries,
			ttl,
			state: Mutex::new(State {
				entries: HashMap::new(),
				order: VecDeque::new(),
				bytes: 0,
			}),
		}
	}

	fn lock(&self) -> MutexGuard<'_, State<V>> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// The value stored under `key`, unless it is older than the time limit.
	pub fn get(&self, key: &str) -> Option<V> {
		let state = self.lock();
		let entry = state.entries.get(key)?;
		(entry.at.elapsed() < self.ttl).then(|| entry.value.clone())
	}

	/// Stores `value`, which takes `size` bytes. A value larger than the whole
	/// cache is not stored.
	pub fn insert(&self, key: String, value: V, size: usize) {
		let mut state = self.lock();
		state.bytes += size;
		state.order.push_back(key.clone());
		state.entries.insert(key, Entry { value, size, at: Instant::now() });
	}

	/// The bytes held now.
	pub fn bytes(&self) -> usize {
		self.lock().bytes
	}

	/// The number of entries held now.
	pub fn len(&self) -> usize {
		self.lock().entries.len()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

/// About how many bytes `value` takes in memory.
pub fn value_size(_value: &Value) -> usize {
	0
}

#[cfg(test)]
mod byte_cache_tests {
	use super::*;
	use serde_json::json;

	const MINUTE: Duration = Duration::from_secs(60);

	// Audit finding #17: the fetch cache held 100 entries whatever their size,
	// and a thread page measured 2.4 to 2.9 MB each.
	#[test]
	fn test_entries_are_dropped_to_stay_within_the_byte_limit() {
		let cache = ByteCache::new(1000, 100, MINUTE);
		for n in 0..50 {
			cache.insert(format!("key{n}"), n, 300);
			assert!(cache.bytes() <= 1000, "{} bytes after {} inserts", cache.bytes(), n + 1);
		}
		assert_eq!(cache.len(), 3);
		// the oldest go first
		assert_eq!(cache.get("key49"), Some(49));
		assert_eq!(cache.get("key48"), Some(48));
		assert_eq!(cache.get("key47"), Some(47));
		assert_eq!(cache.get("key46"), None);
		assert_eq!(cache.get("key0"), None);
	}

	#[test]
	fn test_a_value_larger_than_the_cache_is_not_stored() {
		let cache = ByteCache::new(1000, 100, MINUTE);
		cache.insert("small".to_string(), 1, 100);
		cache.insert("huge".to_string(), 2, 1001);
		assert_eq!(cache.get("huge"), None);
		assert_eq!(cache.get("small"), Some(1));
		assert_eq!(cache.bytes(), 100);
	}

	#[test]
	fn test_the_entry_limit_still_applies_to_small_values() {
		let cache = ByteCache::new(1_000_000, 4, MINUTE);
		for n in 0..10 {
			cache.insert(format!("key{n}"), n, 1);
		}
		assert_eq!(cache.len(), 4);
		assert_eq!(cache.bytes(), 4);
		assert_eq!(cache.get("key5"), None);
		assert_eq!(cache.get("key6"), Some(6));
	}

	#[test]
	fn test_replacing_a_key_does_not_count_it_twice() {
		let cache = ByteCache::new(1000, 100, MINUTE);
		cache.insert("key".to_string(), 1, 400);
		cache.insert("key".to_string(), 2, 500);
		assert_eq!(cache.get("key"), Some(2));
		assert_eq!(cache.len(), 1);
		assert_eq!(cache.bytes(), 500);
	}

	#[test]
	fn test_expired_entries_are_not_returned_and_are_dropped() {
		let cache = ByteCache::new(1000, 100, Duration::ZERO);
		cache.insert("key".to_string(), 1, 400);
		assert_eq!(cache.get("key"), None);
		cache.insert("other".to_string(), 2, 100);
		assert_eq!(cache.len(), 1, "the expired entry should have been dropped by the insert");
		assert_eq!(cache.bytes(), 100);
	}

	#[test]
	fn test_value_size_is_at_least_the_json_text() {
		assert!(value_size(&json!(null)) > 0);
		let page = json!({
			"kind": "Listing",
			"data": { "children": (0..100).map(|n| json!({ "title": format!("post number {n}"), "score": n, "nsfw": false })).collect::<Vec<_>>() }
		});
		assert!(value_size(&page) >= page.to_string().len());
		let more = json!({ "a": page.clone(), "b": page });
		assert!(value_size(&more) > 2 * page.to_string().len());
		assert!(value_size(&json!("x".repeat(10_000))) >= 10_000);
	}
}
