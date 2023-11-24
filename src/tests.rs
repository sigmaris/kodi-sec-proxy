use super::*;
use std::sync::Once;
use test_case::{test_case, test_matrix};

static INIT: Once = Once::new();

#[test_matrix([b":9090", b""], [b":8080", b""], [b"http", b"https", b"moz-extension"])]
#[tokio::test]
async fn test_handle_conn_good_ws_from_browser(
    host_port: &[u8],
    origin_port: &[u8],
    protocol: &[u8],
) {
    INIT.call_once(|| env_logger::init());
    let (mut our_front_end, other_front_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let (mut our_back_end, other_back_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let task = tokio::spawn(handle_conn(
        other_front_end,
        SocketAddr::V4("127.0.0.1:54321".parse().unwrap()),
        async move { Ok(other_back_end) },
    ));
    let mut request = BytesMut::new();
    request.extend_from_slice(b"GET /jsonrpc HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: kodi.server");
    request.extend_from_slice(host_port);
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(b"Upgrade: websocket\r\n");
    request.extend_from_slice(b"Connection: Upgrade\r\n");
    request.extend_from_slice(b"Origin: ");
    request.extend_from_slice(protocol);
    request.extend_from_slice(b"://kodi.server");
    request.extend_from_slice(origin_port);
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n\r\n");
    our_front_end
        .write_all(&request)
        .await
        .expect("Can write request");
    let mut read_back = BytesMut::with_capacity(request.len());
    while read_back.len() < request.len() {
        let read = our_back_end
            .read_buf(&mut read_back)
            .await
            .expect("Can read from backend socket");
        assert!(read > 0);
    }
    assert_eq!(request, read_back);
    our_front_end
        .shutdown()
        .await
        .expect("Can shutdown frontend connection");
    assert_eq!(
        our_back_end
            .read(&mut [0u8; 1])
            .await
            .expect("Can read EOF from backend"),
        0
    );
    our_back_end
        .shutdown()
        .await
        .expect("Can shutdown backend connection");
    task.await.expect("handle_conn finished successfully");
}

#[test_matrix([b":9090", b""], [b":8080", b""])]
#[tokio::test]
async fn test_handle_conn_bad_ws_from_browser(host_port: &[u8], origin_port: &[u8]) {
    INIT.call_once(|| env_logger::init());
    let (mut our_front_end, other_front_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let (mut our_back_end, other_back_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let task = tokio::spawn(handle_conn(
        other_front_end,
        SocketAddr::V4("127.0.0.1:54321".parse().unwrap()),
        async move { Ok(other_back_end) },
    ));
    let mut request = BytesMut::new();
    request.extend_from_slice(b"GET /jsonrpc HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: kodi.server");
    request.extend_from_slice(host_port);
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(b"Upgrade: websocket\r\n");
    request.extend_from_slice(b"Connection: Upgrade\r\n");
    request.extend_from_slice(b"Origin: http://bad.website");
    request.extend_from_slice(origin_port);
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n\r\n");
    our_front_end
        .write_all(&request)
        .await
        .expect("Can write request");
    our_front_end
        .shutdown()
        .await
        .expect("Can shutdown frontend connection");
    assert_eq!(
        our_back_end
            .read(&mut [0u8; 1])
            .await
            .expect("Can read EOF from backend"),
        0
    );
    task.await.expect("handle_conn finished successfully");
}

#[test_matrix([true, false])]
#[tokio::test]
async fn test_forwards_notifications(client_closes_first: bool) {
    INIT.call_once(|| env_logger::init());
    let (mut our_front_end, other_front_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let (mut our_back_end, other_back_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let task = tokio::spawn(handle_conn(
        other_front_end,
        SocketAddr::V4("127.0.0.1:54321".parse().unwrap()),
        async move { Ok(other_back_end) },
    ));
    let jsonrpc = br#"{"jsonrpc":"2.0","method":"Player.OnAVStart","params":{"data":{"item":{"id":1,"type":"song"},"player":{"playerid":0,"speed":1}},"sender":"xbmc"}}"#;
    our_back_end
        .write_all(jsonrpc)
        .await
        .expect("Can write JSON-RPC notification");
    let mut read_notif = BytesMut::with_capacity(jsonrpc.len());
    while read_notif.len() < jsonrpc.len() {
        let read = our_front_end
            .read_buf(&mut read_notif)
            .await
            .expect("Can read JSON-RPC notification");
        assert!(read > 0);
    }
    assert_eq!(jsonrpc, read_notif.as_ref());
    if client_closes_first {
        our_front_end
            .shutdown()
            .await
            .expect("Can shutdown frontend connection");
        assert_eq!(
            our_back_end
                .read(&mut [0u8; 1])
                .await
                .expect("Can read EOF from backend"),
            0
        );
    } else {
        our_back_end
            .shutdown()
            .await
            .expect("Can shutdown backend connection");
        assert_eq!(
            our_front_end
                .read(&mut [0u8; 1])
                .await
                .expect("Can read EOF from backend"),
            0
        );
    }
    task.await.expect("handle_conn finished successfully");
}

#[test_case(br#"{"jsonrpc":"2.0","method":"Input.ShowPlayerProcessInfo","params":[],"id":1}"# ; "one call")]
#[test_case(br#"[{"jsonrpc":"2.0","method":"Input.ShowPlayerProcessInfo","params":[],"id":2}]"# ; "one call in array")]
#[test_case(br#"[{"jsonrpc":"2.0","method":"Input.ShowPlayerProcessInfo","params":[],"id":3},{"jsonrpc":"2.0","method":"Input.ShowCodec","params":[],"id":4}]"# ; "two calls in array")]
#[tokio::test]
async fn test_handle_conn_good_plain_jsonrpc(jsonrpc: &[u8]) {
    INIT.call_once(|| env_logger::init());
    let (mut our_front_end, other_front_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let (mut our_back_end, other_back_end) =
        tokio::net::UnixStream::pair().expect("Can create socketpair");
    let task = tokio::spawn(handle_conn(
        other_front_end,
        SocketAddr::V4("127.0.0.1:54321".parse().unwrap()),
        async move { Ok(other_back_end) },
    ));
    our_front_end
        .write_all(jsonrpc)
        .await
        .expect("Can write JSON-RPC call");
    let mut read_back = BytesMut::with_capacity(jsonrpc.len());
    while read_back.len() < jsonrpc.len() {
        let read = our_back_end
            .read_buf(&mut read_back)
            .await
            .expect("Can read from backend socket");
        assert!(read > 0);
    }
    assert_eq!(jsonrpc, read_back);
    our_front_end
        .shutdown()
        .await
        .expect("Can shutdown frontend connection");
    assert_eq!(
        our_back_end
            .read(&mut [0u8; 1])
            .await
            .expect("Can read EOF from backend"),
        0
    );
    our_back_end
        .shutdown()
        .await
        .expect("Can shutdown backend connection");
    task.await.expect("handle_conn finished successfully");
}
