//! The transport has a deadline.
//!
//! Before `Config::request_timeout` the client's `reqwest` transport had no
//! timeout at all, so a host that accepted the connection and then stopped
//! answering blocked the caller **forever** rather than failing it. These
//! tests pin the two halves of that: a silent host fails, and a host that
//! answers in time is untouched.

use std::time::Duration;

use httpmock::prelude::*;
use polymarket_client_sdk_v2::clob::{Client, Config, DEFAULT_REQUEST_TIMEOUT};

/// A host that accepts and then says nothing must fail the call.
///
/// Discriminant, run 2026-09-22: drop `.timeout(config.request_timeout)` from
/// `Client::new` and this goes RED — the call waits out the mock's own 60 s
/// delay, so both assertions fail (the response arrives, and the wait is far
/// past the bound). Against a host that never answers at all it would not go
/// red, it would never finish; the mock's delay is what turns "forever" into
/// something a test can observe.
#[tokio::test]
async fn a_host_that_never_answers_fails_instead_of_blocking_forever() -> anyhow::Result<()> {
    let server = MockServer::start_async().await;
    let _silent = server
        .mock_async(|when, then| {
            when.any_request();
            // Far longer than the deadline below, so the deadline is what ends
            // the call rather than the response arriving.
            then.status(200)
                .delay(Duration::from_secs(60))
                .body("\"ok\"");
        })
        .await;

    let config = Config::builder()
        .request_timeout(Duration::from_millis(250))
        .build();
    let client = Client::new(&server.base_url(), config)?;

    let started = std::time::Instant::now();
    let answered = client.ok().await;
    let waited = started.elapsed();

    assert!(
        answered.is_err(),
        "a host that never answers must not produce Ok"
    );
    assert!(
        waited < Duration::from_secs(10),
        "the call must end at its own deadline, not at the response; waited {waited:?}"
    );
    Ok(())
}

/// And a host that answers within the deadline is not disturbed by it.
///
/// Without this the first test passes for a client whose timeout is so short
/// that nothing ever succeeds.
#[tokio::test]
async fn a_host_that_answers_in_time_is_untouched() -> anyhow::Result<()> {
    let server = MockServer::start_async().await;
    let _prompt = server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200).body("\"ok\"");
        })
        .await;

    let config = Config::builder()
        .request_timeout(Duration::from_secs(5))
        .build();
    let client = Client::new(&server.base_url(), config)?;

    assert_eq!(client.ok().await?, "ok");
    Ok(())
}

/// The default is the number the measurement chose, and it is what a caller
/// that sets nothing gets.
#[test]
fn the_default_request_timeout_is_the_measured_one() {
    assert_eq!(
        DEFAULT_REQUEST_TIMEOUT,
        Duration::from_secs(15),
        "15 s: comfortably above public CLOB reads measured 2026-09-22 \
         (p50 768 ms, p90 1.22 s, p99 2.16 s over 60 samples), so a merely slow \
         venue does not fail, while nothing waits forever. Changing it invalidates \
         that reading."
    );
}
