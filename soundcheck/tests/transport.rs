//! Stage 5: wire protocol and authorized serving over two loopback nodes.

mod common;

use common::*;
use ed25519_dalek::Signature;
use p2p_sync_poc::chunker::chunk_bytes;
use p2p_sync_poc::clock::Hlc;
use p2p_sync_poc::crypto::chunk_hash;
use p2p_sync_poc::gossip::SyncMessage;
use p2p_sync_poc::manifest::FileManifest;
use p2p_sync_poc::protocol::{
    self, ErrorCode, Request, Response, REQUEST_FRAME_LIMIT, RESPONSE_FRAME_LIMIT,
};
use p2p_sync_poc::transport::{get_chunk, get_manifest, request, ServerMetrics, TransportError};

struct Fixture {
    server: TestNode,
    client: TestNode,
    doc: Doc,
    manifest: FileManifest,
}

/// A server holding one committed file of `doc`, and a client that knows
/// the server's address.
async fn fixture() -> Fixture {
    let server = TestNode::spawn().await;
    let client = TestNode::spawn().await;
    let doc = Doc::new();
    server.sync.add_document(doc.id, doc.owner_pub);
    client.know(&server);

    let payload = chunk_bytes("dir/file.bin", &test_data(1, 100_000)).expect("chunk");
    for (r, bytes) in payload.iter() {
        server.store.put_chunk(r.hash, bytes.clone()).expect("put");
    }
    let manifest = payload.manifest.clone();
    let version = SyncMessage::NewVersion {
        doc_id: doc.id,
        manifest_id: manifest.id(),
        parent: None,
        hlc: Hlc::new(1, 0),
        author: server.id_bytes(),
        token: doc.token(server.id_bytes(), true, true),
        signature: Signature::from_bytes(&[0u8; 64]),
    };
    server
        .store
        .commit_version(&doc.id, &manifest, &version, None, true)
        .expect("commit");
    Fixture {
        server,
        client,
        doc,
        manifest,
    }
}

fn remote_code(err: TransportError) -> ErrorCode {
    match err {
        TransportError::Remote(code) => code,
        other => panic!("expected a remote error code, got {other:?}"),
    }
}

#[tokio::test]
async fn authorized_client_fetches_chunk_and_manifest() {
    let f = fixture().await;
    let token = f.doc.token(f.client.id_bytes(), true, false);
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();

    let m = with_timeout(get_manifest(&conn, &token, f.doc.id, f.manifest.id()))
        .await
        .unwrap();
    assert_eq!(m, f.manifest);
    assert_eq!(m.id(), f.manifest.id());

    for r in &f.manifest.chunks {
        let bytes = with_timeout(get_chunk(&conn, &token, f.doc.id, r.hash))
            .await
            .unwrap();
        assert_eq!(bytes.len(), r.length as usize);
        assert_eq!(chunk_hash(&bytes), r.hash);
    }
    let metrics = f.server.sync.metrics();
    assert_eq!(
        ServerMetrics::get(&metrics.chunks_served),
        f.manifest.chunks.len() as u64
    );
    assert_eq!(ServerMetrics::get(&metrics.manifests_served), 1);
    assert_eq!(ServerMetrics::get(&metrics.connections_accepted), 1);
    f.client.shutdown().await;
    f.server.shutdown().await;
}

/// SEC-1: a token from a key other than the document owner is refused, and
/// so is an expired token from the right owner. No chunk bytes are served.
#[tokio::test]
async fn sec1_forged_issuer_and_expired_tokens_are_unauthorized() {
    let f = fixture().await;
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    let hash = f.manifest.chunks[0].hash;

    let attacker = Doc::new();
    let mut forged = attacker.token(f.client.id_bytes(), true, true);
    forged.claims.doc_id = f.doc.id;
    // Re-sign the altered claims with the attacker's key so the token is
    // internally consistent but from the wrong issuer.
    let forged = p2p_sync_poc::capabilities::CapabilityToken::issue(forged.claims, &attacker.owner);
    let err = with_timeout(get_chunk(&conn, &forged, f.doc.id, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Unauthorized);

    let expired = f
        .doc
        .token_with_window(f.client.id_bytes(), true, false, 1_000, 2_000);
    let err = with_timeout(get_chunk(&conn, &expired, f.doc.id, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Unauthorized);

    let not_yet = f
        .doc
        .token_with_window(f.client.id_bytes(), true, false, u64::MAX / 2, u64::MAX);
    let err = with_timeout(get_chunk(&conn, &not_yet, f.doc.id, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Unauthorized);

    let metrics = f.server.sync.metrics();
    assert_eq!(ServerMetrics::get(&metrics.unauthorized), 3);
    assert_eq!(ServerMetrics::get(&metrics.chunks_served), 0);
    f.client.shutdown().await;
    f.server.shutdown().await;
}

/// SEC-2: a valid token bound to another node is refused when presented
/// from this connection.
#[tokio::test]
async fn sec2_token_bound_to_another_node_is_forbidden() {
    let f = fixture().await;
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    let stolen = f.doc.token([0x42u8; 32], true, true);
    let err = with_timeout(get_chunk(
        &conn,
        &stolen,
        f.doc.id,
        f.manifest.chunks[0].hash,
    ))
    .await
    .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Forbidden);
    let err = with_timeout(get_manifest(&conn, &stolen, f.doc.id, f.manifest.id()))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Forbidden);
    let metrics = f.server.sync.metrics();
    assert_eq!(ServerMetrics::get(&metrics.forbidden), 2);
    assert_eq!(ServerMetrics::get(&metrics.chunks_served), 0);
    assert_eq!(ServerMetrics::get(&metrics.manifests_served), 0);
    f.client.shutdown().await;
    f.server.shutdown().await;
}

/// SEC-3: a token for another document is refused, and a chunk that is in
/// the store but not registered for the document is not served. An unknown
/// document is `Unauthorized`.
#[tokio::test]
async fn sec3_document_scope_is_enforced() {
    let f = fixture().await;
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    let hash = f.manifest.chunks[0].hash;

    // Same owner, second document: the token names the other document.
    let other_doc_id = p2p_sync_poc::crypto::random_bytes32();
    f.server.sync.add_document(other_doc_id, f.doc.owner_pub);
    let mut claims = f.doc.token(f.client.id_bytes(), true, false).claims;
    claims.doc_id = other_doc_id;
    let other_token = p2p_sync_poc::capabilities::CapabilityToken::issue(claims, &f.doc.owner);
    let err = with_timeout(get_chunk(&conn, &other_token, f.doc.id, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Forbidden);

    // A valid token for the other document cannot read this document's
    // chunk through the other document either: it is not registered there.
    let err = with_timeout(get_chunk(&conn, &other_token, other_doc_id, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::NotFound);

    // A chunk in the store but registered for no document.
    let orphan = test_data(9, 5_000);
    let orphan_hash = chunk_hash(&orphan);
    f.server.store.put_chunk(orphan_hash, orphan).unwrap();
    let token = f.doc.token(f.client.id_bytes(), true, false);
    let err = with_timeout(get_chunk(&conn, &token, f.doc.id, orphan_hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::NotFound);

    // Unknown document.
    let unknown = p2p_sync_poc::crypto::random_bytes32();
    let mut claims = token.claims.clone();
    claims.doc_id = unknown;
    let unknown_token = p2p_sync_poc::capabilities::CapabilityToken::issue(claims, &f.doc.owner);
    let err = with_timeout(get_chunk(&conn, &unknown_token, unknown, hash))
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Unauthorized);

    assert_eq!(
        ServerMetrics::get(&f.server.sync.metrics().chunks_served),
        0
    );
    f.client.shutdown().await;
    f.server.shutdown().await;
}

/// SEC-7: an oversize request frame is refused without a response and the
/// connection keeps serving. SEC-10: a malformed frame gets a bare
/// `BadRequest` code.
#[tokio::test]
async fn sec7_oversize_frame_is_reset_and_server_keeps_serving() {
    let f = fixture().await;
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();

    // Announce a 4 KiB request (limit is 1 KiB) and send the bytes.
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let len = (REQUEST_FRAME_LIMIT * 4) as u32;
    send.write_all(&len.to_be_bytes()).await.unwrap();
    let body = vec![0xAAu8; REQUEST_FRAME_LIMIT * 4];
    // The server may reset before we finish writing; either outcome is fine.
    let _ = send.write_all(&body).await;
    let _ = send.finish();
    // Either the server reset the stream (an error here) or it finished it
    // without writing anything. Both mean no response was sent.
    if let Ok(bytes) = with_timeout(recv.read_to_end(RESPONSE_FRAME_LIMIT)).await {
        assert!(
            bytes.is_empty(),
            "no response expected, got {} bytes",
            bytes.len()
        );
    }
    let metrics = f.server.sync.metrics();
    assert_eq!(ServerMetrics::get(&metrics.oversize_frames), 1);
    assert_eq!(ServerMetrics::get(&metrics.requests), 0);

    // Garbage inside the limit: a coarse BadRequest, nothing else.
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    protocol::write_frame(&mut send, &[0xFFu8; 40], REQUEST_FRAME_LIMIT)
        .await
        .unwrap();
    send.finish().unwrap();
    let frame = with_timeout(protocol::read_frame(&mut recv, RESPONSE_FRAME_LIMIT))
        .await
        .unwrap();
    let response: Response = protocol::decode(&frame, RESPONSE_FRAME_LIMIT).unwrap();
    assert_eq!(response, Response::Error(ErrorCode::BadRequest));

    // The same connection still serves a valid request.
    let token = f.doc.token(f.client.id_bytes(), true, false);
    let bytes = with_timeout(get_chunk(
        &conn,
        &token,
        f.doc.id,
        f.manifest.chunks[0].hash,
    ))
    .await
    .unwrap();
    assert_eq!(chunk_hash(&bytes), f.manifest.chunks[0].hash);
    assert_eq!(ServerMetrics::get(&metrics.connections_accepted), 1);
    f.client.shutdown().await;
    f.server.shutdown().await;
}

#[tokio::test]
async fn fifty_concurrent_requests_over_one_connection_succeed() {
    let f = fixture().await;
    let conn = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    let token = f.doc.token(f.client.id_bytes(), true, false);
    let mut set = tokio::task::JoinSet::new();
    for i in 0..50usize {
        let conn = conn.clone();
        let token = token.clone();
        let r = f.manifest.chunks[i % f.manifest.chunks.len()];
        let doc_id = f.doc.id;
        set.spawn(async move {
            let bytes = get_chunk(&conn, &token, doc_id, r.hash).await?;
            assert_eq!(chunk_hash(&bytes), r.hash);
            Ok::<(), TransportError>(())
        });
    }
    with_timeout(async {
        while let Some(res) = set.join_next().await {
            res.unwrap().unwrap();
        }
    })
    .await;
    let metrics = f.server.sync.metrics();
    assert_eq!(ServerMetrics::get(&metrics.chunks_served), 50);
    assert_eq!(ServerMetrics::get(&metrics.connections_accepted), 1);
    f.client.shutdown().await;
    f.server.shutdown().await;
}

#[tokio::test]
async fn pool_reuses_connection_and_raw_request_round_trips() {
    let f = fixture().await;
    let c1 = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    let c2 = with_timeout(f.client.pool.connect(f.server.id()))
        .await
        .unwrap();
    assert_eq!(c1.stable_id(), c2.stable_id());
    let token = f.doc.token(f.client.id_bytes(), true, false);
    let req = Request::GetManifest {
        token,
        doc_id: f.doc.id,
        manifest_id: f.manifest.id(),
    };
    let response = with_timeout(request(&c1, &req)).await.unwrap();
    assert_eq!(response, Response::Manifest(f.manifest.clone()));
    f.client.shutdown().await;
    f.server.shutdown().await;
}
