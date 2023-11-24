use bytes::BytesMut;
use httparse::Status;
use listenfd::ListenFd;
use log::{debug, error, info, warn};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{tcp, unix, TcpListener, TcpStream, UnixStream};
use tokio::signal;
use tokio::sync::mpsc;
use url::Url;

#[cfg(target_os = "linux")]
use systemd_journal_logger::{connected_to_journal, JournalLog};

#[cfg(target_os = "linux")]
trait SpliceableStream: tokio_splice::Stream + Send + Unpin + Debug {
    type OwnedReadHalf: Send + Unpin + AsyncRead;
    type OwnedWriteHalf: Send + Unpin + AsyncWrite + 'static;
    type ReuniteError: Debug;
    fn into_split(self) -> (Self::OwnedReadHalf, Self::OwnedWriteHalf);
    fn reunite(r: Self::OwnedReadHalf, w: Self::OwnedWriteHalf) -> Result<Self, Self::ReuniteError>
    where
        Self: Sized;
}

#[cfg(not(target_os = "linux"))]
trait SpliceableStream: AsyncReadExt + AsyncWriteExt + Send + Unpin + Debug {
    type OwnedReadHalf: Send + Unpin + AsyncRead;
    type OwnedWriteHalf: Send + Unpin + AsyncWrite + 'static;
    type ReuniteError: Debug;
    fn into_split(self) -> (Self::OwnedReadHalf, Self::OwnedWriteHalf);
    fn reunite(r: Self::OwnedReadHalf, w: Self::OwnedWriteHalf) -> Result<Self, Self::ReuniteError>
    where
        Self: Sized;
}

impl SpliceableStream for TcpStream {
    type OwnedReadHalf = tcp::OwnedReadHalf;
    type OwnedWriteHalf = tcp::OwnedWriteHalf;
    type ReuniteError = tcp::ReuniteError;
    fn into_split(self) -> (tcp::OwnedReadHalf, tcp::OwnedWriteHalf) {
        self.into_split()
    }
    fn reunite(
        r: Self::OwnedReadHalf,
        w: Self::OwnedWriteHalf,
    ) -> Result<Self, Self::ReuniteError> {
        r.reunite(w)
    }
}
impl SpliceableStream for UnixStream {
    type OwnedReadHalf = unix::OwnedReadHalf;
    type OwnedWriteHalf = unix::OwnedWriteHalf;
    type ReuniteError = unix::ReuniteError;
    fn into_split(self) -> (unix::OwnedReadHalf, unix::OwnedWriteHalf) {
        self.into_split()
    }
    fn reunite(
        r: Self::OwnedReadHalf,
        w: Self::OwnedWriteHalf,
    ) -> Result<Self, Self::ReuniteError> {
        r.reunite(w)
    }
}

enum ConnState {
    Accepted,
    Rejected,
    Closed,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "linux"))]
    env_logger::init();

    #[cfg(target_os = "linux")]
    if connected_to_journal() {
        use log::LevelFilter;
        use std::str::FromStr;
        // If the output streams of this process are directly connected to the
        // systemd journal log directly to the journal to preserve structured
        // log entries (e.g. proper multiline messages, metadata fields, etc.)
        JournalLog::new()
            .unwrap()
            .with_syslog_identifier("kodi-sec-proxy".to_string())
            .install()
            .unwrap();
        match std::env::var("RUST_LOG").map(|s| LevelFilter::from_str(&s)) {
            Ok(Ok(level)) => log::set_max_level(level),
            _ => log::set_max_level(LevelFilter::Info),
        }
    } else {
        // Otherwise fall back to logging to standard error.
        env_logger::init();
    }

    let connect_addr = std::env::var("CONNECT_ADDR").unwrap_or("127.0.0.1:9090".to_owned());
    let mut listenfd = ListenFd::from_env();

    let tcp_listener = if let Some(std_sock) = listenfd.take_tcp_listener(0).ok().flatten() {
        debug!("Using passed TCP socket {:?}", std_sock);
        std_sock.set_nonblocking(true)?;
        TcpListener::from_std(std_sock)?
    } else {
        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or("::0:9999".to_owned());
        debug!("Listening on TCP {}", listen_addr);
        TcpListener::bind(listen_addr).await?
    };

    loop {
        tokio::select! {
            new = tcp_listener.accept() => {
                match new {
                    Ok((new_conn, src)) => {
                        let connect_clone = connect_addr.clone();
                        tokio::spawn(handle_conn(new_conn, src, async move {
                        TcpStream::connect(&connect_clone).await.map_err(|e| {
                            error!("Could not connect to backend '{}': {}", connect_clone, e);
                            e
                        })
                    }));}
                    Err(e) => warn!("Error accepting new connection: {}", e)
                }
            }
            _ = signal::ctrl_c() => {
                info!("Exiting on Ctrl-C.");
                break
            }
        }
    }
    Ok(())
}

fn parse_origin(origin_hdr: &[u8]) -> Result<(String, String, u16), Box<dyn Error>> {
    let origin_str = std::str::from_utf8(origin_hdr)?;
    let url = Url::parse(origin_str)?;
    let host = url.host_str().ok_or(io::Error::new(
        ErrorKind::InvalidInput,
        "Origin missing Host component",
    ))?;
    let default_port: u16 = match url.scheme() {
        "http" => 80,
        "https" => 443,
        "moz-extension" => 80,
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Invalid URL scheme",
        ))?,
    };
    let port = url.port().unwrap_or(default_port);
    Ok((url.scheme().to_owned(), host.to_owned(), port))
}

fn parse_host(host_hdr: &[u8], is_secure: bool) -> Result<(&str, u16), Box<dyn Error>> {
    let host_str = std::str::from_utf8(host_hdr)?;
    let default_port: u16 = if is_secure { 443 } else { 80 };
    let (host, port_res) = host_str
        .split_once(':')
        .map(|(h, p)| (h, p.parse::<u16>()))
        .unwrap_or((host_str, Ok(default_port)));
    Ok((host, port_res?))
}

#[cfg(not(target_os = "linux"))]
async fn splice_to_backend(
    mut buffer: BytesMut,
    conn: &mut impl SpliceableStream,
    backend: &mut impl SpliceableStream,
) -> std::io::Result<()> {
    use tokio::io::copy_bidirectional;
    debug!("Writing {} bytes to buffer", buffer.len());
    backend.write_all_buf(&mut buffer).await?;
    debug!("Entering copy_bidirectional({:?}, {:?})", conn, backend);
    copy_bidirectional(conn, backend).await?;
    debug!("Finished copy_bidirectional({:?}, {:?})", conn, backend);
    Ok(())
}

#[cfg(target_os = "linux")]
async fn splice_to_backend(
    mut buffer: BytesMut,
    conn: &mut impl SpliceableStream,
    backend: &mut impl SpliceableStream,
) -> std::io::Result<()> {
    use tokio_splice::zero_copy_bidirectional;
    debug!("Writing {} bytes to buffer", buffer.len());
    backend.write_all_buf(&mut buffer).await?;
    debug!(
        "Entering zero_copy_bidirectional({:?}, {:?})",
        conn, backend
    );
    zero_copy_bidirectional(conn, backend).await?;
    debug!(
        "Finished zero_copy_bidirectional({:?}, {:?})",
        conn, backend
    );
    Ok(())
}

fn request_is_ok(src: &SocketAddr, req: &httparse::Request, is_secure: bool) -> bool {
    if req.method.unwrap_or_default() != "GET" || req.version.unwrap_or_default() < 1 {
        warn!(
            "Invalid request {:?} {:?} v.{:?} in handshake from {}",
            req.method, req.path, req.version, src
        );
    }
    let mut origin_hdr = None;
    let mut host_hdr = None;
    let mut upgrade_websocket = false;
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("origin") {
            origin_hdr = parse_origin(header.value)
                .map_err(|e| {
                    warn!(
                        "Couldn't parse Origin header {} from {}: {}",
                        String::from_utf8_lossy(header.value),
                        src,
                        e
                    )
                })
                .ok();
        } else if header.name.eq_ignore_ascii_case("host") {
            host_hdr = parse_host(header.value, is_secure)
                .map_err(|e| {
                    warn!(
                        "Couldn't parse Host header {} from {}: {}",
                        String::from_utf8_lossy(header.value),
                        src,
                        e
                    )
                })
                .ok();
        } else if header.name.eq_ignore_ascii_case("upgrade") && header.value == b"websocket" {
            upgrade_websocket = true
        }
    }
    if upgrade_websocket {
        match (origin_hdr, host_hdr) {
            (Some(origin), Some(host)) => {
                if origin.0 == "moz-extension" {
                    debug!("Accepted browser extension websocket from {}", src);
                    true
                } else if origin.1 == host.0 {
                    debug!(
                        "Accepted Websocket from {} with Origin={:?} Host={:?}",
                        src, origin, host
                    );
                    true
                } else {
                    warn!(
                        "Websocket from {} with Origin<>Host header! All headers: {:?}",
                        src, req.headers
                    );
                    false
                }
            }
            (Some(origin), None) => {
                warn!(
                    "Websocket from {} with origin={:?} but no Host header! All headers: {:?}",
                    src, origin, req.headers
                );
                false
            }
            (None, _) => {
                debug!("Websocket upgrade from {} with no Origin", src);
                true
            }
        }
    } else {
        debug!(
            "Non-Websocket HTTP request from {} with Origin {:?}",
            src, origin_hdr
        );
        false
    }
}

async fn transfer_notifications<T: AsyncWriteExt + Unpin, B: SpliceableStream>(
    mut to_client: T,
    mut backend: B,
    mut stop: mpsc::Receiver<()>,
    backend_closed: mpsc::Sender<()>,
) -> Result<(T, B), io::Error> {
    let mut buf = BytesMut::with_capacity(512);
    loop {
        tokio::select! {
            _ = stop.recv() => break Ok((to_client, backend)),
            read = backend.read_buf(&mut buf) => {
                match read {
                    Ok(0) => {
                        debug!("Backend closed connection in transfer_notifications");
                        to_client.shutdown().await.ok();
                        backend_closed.send(()).await.expect("sending backend_closed");
                        break Err(io::Error::new(
                            ErrorKind::BrokenPipe,
                            "Backend closed connection",
                        ));
                    }
                    Ok(_) => {
                        if let Err(e) = to_client.write_all_buf(&mut buf).await {
                            backend.shutdown().await.ok();
                            backend_closed.send(()).await.expect("sending backend_closed");
                            to_client.shutdown().await.ok();
                            break Err(e);
                        }
                        buf.clear();
                    }
                    Err(e) => {
                        backend.shutdown().await.ok();
                        backend_closed.send(()).await.expect("sending backend_closed");
                        to_client.shutdown().await.ok();
                        break Err(e)
                    }
                }
            }
        }
    }
}

async fn handle_conn<C: SpliceableStream + 'static>(
    mut conn: C,
    src: SocketAddr,
    backend_factory: impl Future<Output = io::Result<C>>,
) {
    info!("Incoming connection from {}", src);
    // Secure sockets not (yet?) supported
    let is_secure = false;

    // Start forwarding notifications one way only, from backend to client, for clients that only listen
    let (stop_notifications_tx, stop_notifications_rx) = mpsc::channel(1);
    let (backend_closed_tx, mut backend_closed_rx) = mpsc::channel(1);
    let backend = match backend_factory.await {
        Ok(backend) => backend,
        Err(_) => {
            conn.shutdown().await.ok();
            return;
        }
    };
    let (mut read_half, write_half) = conn.into_split();
    let join_notifs = tokio::spawn(transfer_notifications(
        write_half,
        backend,
        stop_notifications_rx,
        backend_closed_tx,
    ));

    // First try parsing as a HTTP (upgrade to WebSocket) request
    let mut buffer = BytesMut::with_capacity(512);
    let state = loop {
        tokio::select! {
            from_client = read_half.read_buf(&mut buffer) => {match from_client {
                Ok(read) => {
                    if read == 0 && buffer.len() < buffer.capacity() {
                        info!("End of stream from {}", src);
                        break ConnState::Closed;
                    }
                    if buffer.starts_with(b"{") || buffer.starts_with(b"[") {
                        debug!("Raw JSON-RPC connection from {}", src);
                        break ConnState::Accepted;
                    }
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut req = httparse::Request::new(&mut headers);
                    match req.parse(&buffer) {
                        Ok(Status::Partial) => {
                            debug!(
                                "Partially parsed HTTP {} request from {} - {}",
                                req.method.unwrap_or("(unknown method)"),
                                src,
                                String::from_utf8_lossy(&buffer),
                            );
                            // If all header slots are filled, that's too many to parse
                            if !req.headers.iter().any(|h| *h == httparse::EMPTY_HEADER) {
                                warn!(
                                    "Too many headers to parse (>{}), dropping connection from {}",
                                    req.headers.len(),
                                    src
                                );
                                break ConnState::Rejected;
                            }
                        }
                        Ok(Status::Complete(_)) => {
                            if request_is_ok(&src, &req, is_secure) {
                                break ConnState::Accepted;
                            } else {
                                break ConnState::Rejected;
                            }
                        }
                        Err(parse) => {
                            debug!(
                                "HTTP parse error '{}' for buffer: {}",
                                parse,
                                String::from_utf8_lossy(&buffer)
                            );
                            // If it's not HTTP, it's probably a raw JSON-RPC over TCP/IP connection
                            break ConnState::Accepted;
                        }
                    }
                    if buffer.len() >= buffer.capacity() {
                        if buffer.len() < 1024 * 1024 {
                            buffer.reserve(512);
                        } else {
                            warn!("Rejecting HTTP request larger than 1MiB from {}", src);
                            break ConnState::Rejected;
                        }
                    }
                }
                Err(e) => {
                    warn!("Read error on connection from {}: {}", src, e);
                    break ConnState::Closed;
                }
            }}
            _ = backend_closed_rx.recv() => {break ConnState::Closed}
        }
    };
    debug!("Cancelling notification forwarding to {}", src);
    stop_notifications_tx.send(()).await.ok();
    match join_notifs.await {
        Ok(Ok((write_half, mut backend))) => {
            let mut conn = C::reunite(read_half, write_half).unwrap();
            debug!("Reunited connection from {}", src);
            match state {
                ConnState::Accepted => {
                    if let Err(e) = splice_to_backend(buffer, &mut conn, &mut backend).await {
                        warn!("Error splicing connection from {} to backend: {}", src, e);
                        backend.shutdown().await.ok();
                        conn.shutdown().await.ok();
                    }
                }
                ConnState::Rejected => {
                    warn!("Closing unaccepted connection from {}", src);
                    backend.shutdown().await.ok();
                    conn.shutdown().await.ok();
                }
                ConnState::Closed => {
                    backend.shutdown().await.ok();
                    conn.shutdown().await.ok();
                }
            }
        }
        Ok(Err(io_err)) => warn!("Error while forwarding notifications: {}", io_err),
        Err(join_err) => warn!("transfer_notifications task panicked: {}", join_err),
    }
}

#[cfg(test)]
mod tests;
