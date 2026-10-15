#![cfg(all(feature = "clob", feature = "heartbeats", feature = "bridge"))]
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{U256, address},
    signers::{Signer, local::PrivateKeySigner},
    sol_types::SolStruct,
};
use base64::{Engine, engine::general_purpose::URL_SAFE};
use hmac::{Hmac, Mac};
use polymarket_client_sdk_v2::{
    auth::Credentials,
    bridge::{Client as Bridge, types::StatusRequest},
    clob::{
        Client, Config,
        types::{OrderPayload, OrderType, OrderV2, SignableOrder, SignatureType},
    },
};
use serde_json::{Value, json};
use sha2::Sha256;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(socket: &mut tokio::net::TcpStream) -> (String, Vec<(String, String)>, String) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(raw[..i].to_vec()).unwrap();
            let mut lines = head.lines();
            let line = lines.next().unwrap().to_owned();
            let headers: Vec<_> = lines
                .map(|line| {
                    let (k, v) = line.split_once(':').unwrap();
                    (k.to_ascii_lowercase(), v.trim().to_owned())
                })
                .collect();
            let length: usize = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            if raw.len() >= i + 4 + length {
                return (
                    line,
                    headers,
                    String::from_utf8(raw[i + 4..i + 4 + length].to_vec()).unwrap(),
                );
            }
        }
    }
}
async fn response(socket: &mut tokio::net::TcpStream, status: u16, body: Value) {
    let body = body.to_string();
    socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
}
fn signer() -> PrivateKeySigner {
    PrivateKeySigner::from_str(&format!("{:064x}", 1))
        .unwrap()
        .with_chain_id(Some(137))
}
fn credentials() -> Credentials {
    Credentials::new(
        uuid::Uuid::nil(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        "test".into(),
    )
}

#[tokio::test]
async fn heartbeat_recovers_expected_id_with_fresh_body_auth_and_only_success_marks_ack() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("http://{}", listener.local_addr().unwrap());
    let expected = "11111111-1111-4111-8111-111111111111";
    let ack = "22222222-2222-4222-8222-222222222222";
    let (invalid_tx, invalid_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut invalid_tx = Some(invalid_tx);
        let mut release_rx = Some(release_rx);
        for i in 0..3 {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let (line, headers, body) = request(&mut socket).await;
            assert_eq!(line, "POST /v1/heartbeats HTTP/1.1");
            assert_eq!(
                serde_json::from_str::<Value>(&body).unwrap()["heartbeat_id"],
                if i == 0 { Value::Null } else { json!(expected) }
            );
            let header = |key: &str| headers.iter().find(|(k, _)| k == key).unwrap().1.as_str();
            let mut mac = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
            mac.update(format!("{}POST/v1/heartbeats{body}", header("poly_timestamp")).as_bytes());
            assert_eq!(
                header("poly_signature"),
                URL_SAFE.encode(mac.finalize().into_bytes())
            );
            if i == 0 {
                response(
                    &mut socket,
                    400,
                    json!({"error_msg":"Invalid Heartbeat ID","heartbeat_id":expected}),
                )
                .await;
            } else if i == 1 {
                response(
                    &mut socket,
                    400,
                    json!({"error_msg":"Invalid Heartbeat ID","heartbeat_id":"garbage"}),
                )
                .await;
                invalid_tx.take().unwrap().send(()).unwrap();
            } else {
                release_rx.take().unwrap().await.unwrap();
                response(&mut socket, 200, json!({"heartbeat_id":ack})).await;
            }
        }
    });
    let mut client = Client::new(
        &host,
        Config::builder()
            .heartbeat_interval(Duration::from_millis(80))
            .build(),
    )
    .unwrap()
    .authentication_builder(&signer())
    .credentials(credentials())
    .authenticate()
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), invalid_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.last_heartbeat_ack_ms(), None);
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.last_heartbeat_ack_ms().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(client.last_heartbeat_ack_ms().unwrap() > 1_700_000_000_000);
    client.stop_heartbeats().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn explicit_domain_preserves_eoa_and_poly1271_order_hashes() {
    let signer = signer();
    for signature_type in [SignatureType::Eoa, SignatureType::Poly1271] {
        let maker = if signature_type == SignatureType::Eoa {
            signer.address()
        } else {
            address!("1111111111111111111111111111111111111111")
        };
        let unauth = Client::new("http://127.0.0.1:1", Config::default()).unwrap();
        let auth = unauth
            .authentication_builder(&signer)
            .credentials(credentials())
            .signature_type(signature_type);
        let auth = if signature_type == SignatureType::Poly1271 {
            auth.funder(maker)
        } else {
            auth
        };
        let mut client = auth.authenticate().await.unwrap();
        let mut order = OrderV2::default();
        order.maker = maker;
        order.signer = maker;
        order.tokenId = U256::from(1234);
        order.signatureType = signature_type as u8;
        order.makerAmount = U256::from(2_000_000);
        order.takerAmount = U256::from(4_000_000);
        let signable = SignableOrder::builder()
            .payload(OrderPayload::new(order.clone(), U256::ZERO))
            .order_type(OrderType::GTC)
            .build();
        let domain = Eip712Domain {
            name: Some("Polymarket CTF Exchange".into()),
            version: Some("3".into()),
            chain_id: Some(U256::from(137)),
            verifying_contract: Some(address!("e3333700cA9d93003F00f0F71f8515005F6c00Aa")),
            ..Default::default()
        };
        let signed = client
            .sign_with_domain(&signer, signable.clone(), domain.clone())
            .await
            .unwrap();
        if signature_type == SignatureType::Eoa {
            assert_eq!(
                signed.signature.to_string(),
                signer
                    .sign_hash(&order.eip712_signing_hash(&domain))
                    .await
                    .unwrap()
                    .to_string()
            );
        } else {
            let raw = alloy::hex::decode(signed.signature.to_string()).unwrap();
            assert_eq!(&raw[65..97], domain.hash_struct().as_slice());
            assert_eq!(&raw[97..129], order.eip712_hash_struct().as_slice());
        }
        let mut wrong = domain;
        wrong.chain_id = Some(U256::from(80002));
        assert!(
            client
                .sign_with_domain(&signer, signable, wrong)
                .await
                .is_err()
        );
        client.stop_heartbeats().await.unwrap();
    }
}

#[tokio::test]
async fn bridge_exposes_opaque_cursor_and_rejects_omitted_terminal_field() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (line, _, _) = request(&mut socket).await;
        let url = url::Url::parse(&format!(
            "http://local{}",
            line.split_whitespace().nth(1).unwrap()
        ))
        .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["cursor"], "opaque+/=");
        assert_eq!(q["limit"], "100");
        response(
            &mut socket,
            200,
            json!({"transactions":[],"nextCursor":"next+/="}),
        )
        .await;
    });
    let bridge = Bridge::new(&host).unwrap();
    let response = bridge
        .status(
            &StatusRequest::builder()
                .address("test")
                .limit(100)
                .cursor("opaque+/=")
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(response.next_cursor.as_deref(), Some("next+/="));
    server.await.unwrap();
    assert!(
        serde_json::from_value::<polymarket_client_sdk_v2::bridge::types::StatusResponse>(
            json!({"transactions":[]})
        )
        .is_err()
    );
    assert!(
        bridge
            .status(&StatusRequest::builder().address("test").limit(101).build())
            .await
            .is_err()
    );
}
