use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use http_body::{Frame, SizeHint};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full, StreamBody};
use std::{
	pin::Pin,
	task::{Context, Poll},
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct Body(UnsyncBoxBody<Bytes, BoxError>);

impl Body {
	pub fn new<B>(body: B) -> Self
	where
		B: http_body::Body<Data = Bytes> + Send + 'static,
		B::Error: Into<BoxError>,
	{
		Self(body.map_err(Into::into).boxed_unsync())
	}

	pub fn empty() -> Self {
		Self::new(Empty::<Bytes>::new())
	}

	pub fn from_stream<S, E>(stream: S) -> Self
	where
		S: Stream<Item = Result<Bytes, E>> + Send + 'static,
		E: Into<BoxError>,
	{
		Self::new(StreamBody::new(stream.map(|chunk| chunk.map(Frame::data).map_err(Into::into))))
	}

	pub async fn collect_bytes(self) -> Result<Bytes, BoxError> {
		Ok(self.0.collect().await?.to_bytes())
	}
}

/// Why [`Body::collect_bytes_limited`] gave up.
#[derive(Debug)]
pub enum CollectError {
	/// The body is larger than the limit.
	TooLarge,
	Other(BoxError),
}

impl std::fmt::Display for CollectError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::TooLarge => write!(f, "Request body too large"),
			Self::Other(e) => write!(f, "Failed to get bytes from request body: {e}"),
		}
	}
}

impl Body {
	/// Like `collect_bytes`, but stops reading once the body exceeds `limit` bytes.
	/// For bodies a client sends; never buffer those unbounded.
	///
	/// Written as a frame loop rather than `http_body_util::Limited`: its error
	/// conversion trips a rustc higher-ranked-lifetime bug inside the route closures.
	pub async fn collect_bytes_limited(mut self, limit: usize) -> Result<Bytes, CollectError> {
		let mut collected = Vec::new();
		while let Some(frame) = self.0.frame().await {
			if let Ok(data) = frame.map_err(CollectError::Other)?.into_data() {
				if data.len() > limit - collected.len() {
					return Err(CollectError::TooLarge);
				}
				collected.extend_from_slice(&data);
			}
		}
		Ok(collected.into())
	}
}

impl Default for Body {
	fn default() -> Self {
		Self::empty()
	}
}

impl http_body::Body for Body {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		Pin::new(&mut self.0).poll_frame(cx)
	}

	fn is_end_stream(&self) -> bool {
		self.0.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.0.size_hint()
	}
}

impl From<Bytes> for Body {
	fn from(bytes: Bytes) -> Self {
		Self::new(Full::new(bytes))
	}
}

impl From<Vec<u8>> for Body {
	fn from(v: Vec<u8>) -> Self {
		Bytes::from(v).into()
	}
}

impl From<String> for Body {
	fn from(s: String) -> Self {
		Bytes::from(s).into()
	}
}

impl From<&'static str> for Body {
	fn from(s: &'static str) -> Self {
		Bytes::from_static(s.as_bytes()).into()
	}
}

impl From<&'static [u8]> for Body {
	fn from(s: &'static [u8]) -> Self {
		Bytes::from_static(s).into()
	}
}

impl From<std::borrow::Cow<'static, [u8]>> for Body {
	fn from(c: std::borrow::Cow<'static, [u8]>) -> Self {
		match c {
			std::borrow::Cow::Borrowed(b) => b.into(),
			std::borrow::Cow::Owned(v) => v.into(),
		}
	}
}

#[cfg(test)]
mod limit_tests {
	use super::*;
	use futures_lite::future::block_on;

	#[test]
	fn limited_collect_passes_bodies_within_the_limit() {
		assert_eq!(block_on(Body::from("hello").collect_bytes_limited(5)).unwrap(), Bytes::from_static(b"hello"));
	}

	#[test]
	fn limited_collect_stops_at_the_limit() {
		assert!(matches!(block_on(Body::from("hello!").collect_bytes_limited(5)), Err(CollectError::TooLarge)));
		// A stream is cut off after the chunk that crosses the limit, not read to the end.
		let chunks = futures_lite::stream::iter((0..1000).map(|_| Ok::<_, std::io::Error>(Bytes::from_static(&[0u8; 1024]))));
		assert!(matches!(block_on(Body::from_stream(chunks).collect_bytes_limited(4096)), Err(CollectError::TooLarge)));
	}

	#[test]
	fn limited_collect_reports_body_errors_as_other() {
		let chunks = futures_lite::stream::iter(vec![Err::<Bytes, _>(std::io::Error::other("boom"))]);
		assert!(matches!(block_on(Body::from_stream(chunks).collect_bytes_limited(16)), Err(CollectError::Other(_))));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures_lite::future::block_on;

	#[test]
	fn full_body_round_trips_and_reports_exact_size() {
		let body = Body::from("hello world".to_string());
		assert_eq!(http_body::Body::size_hint(&body).exact(), Some(11));
		assert_eq!(block_on(body.collect_bytes()).unwrap(), Bytes::from_static(b"hello world"));
	}

	#[test]
	fn empty_body_is_empty() {
		let body = Body::default();
		assert!(http_body::Body::is_end_stream(&body));
		assert!(block_on(body.collect_bytes()).unwrap().is_empty());
	}

	#[test]
	fn stream_body_concatenates_chunks() {
		let chunks = futures_lite::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cd"))]);
		assert_eq!(block_on(Body::from_stream(chunks).collect_bytes()).unwrap(), Bytes::from_static(b"abcd"));
	}
}
