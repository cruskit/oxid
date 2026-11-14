//! The TLS listeners.
//!
//! Two listeners serve the same routes. The public one never asks for a
//! client certificate, so browsers are not prompted for one. The mTLS one
//! requests a certificate and is advertised through `mtls_endpoint_aliases`
//! for the token, PAR and `UserInfo` endpoints.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::http::{self, ConnInfo};
use crate::state::{AppState, certificate_names};
use crate::tls::{self, ClientCert, ClientCertPolicy, TlsIdentity};
use crate::util::Clock;

/// How long a client has to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long in-flight requests get to finish on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// How often expired state is swept.
const PURGE_INTERVAL: Duration = Duration::from_secs(30);
/// How often an idle HTTP/2 connection is pinged, and how long the client
/// has to answer before the connection is closed.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent requests on one HTTP/2 connection.
const H2_MAX_CONCURRENT_STREAMS: u32 = 64;

/// What bounds a listener's connections, so that a client cannot hold
/// resources indefinitely.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// Time allowed for an HTTP/1 request's headers, and for an idle
    /// keep-alive connection.
    pub header_read_timeout: Duration,
    /// Time allowed for one request, body included.
    pub request_timeout: Duration,
    /// Connections held open at once.
    pub max_connections: usize,
}

impl ConnectionLimits {
    pub fn from_config(config: &crate::config::ServerConfig) -> Self {
        Self {
            header_read_timeout: Duration::from_secs(config.header_read_timeout),
            request_timeout: Duration::from_secs(config.request_timeout),
            max_connections: config.max_connections,
        }
    }
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self::from_config(&crate::config::ServerConfig::default())
    }
}

/// Configures and starts a [`Server`].
#[derive(Debug)]
pub struct ServerBuilder {
    config: Config,
    clock: Option<Arc<dyn Clock>>,
    listeners: Option<(std::net::TcpListener, std::net::TcpListener)>,
}

impl ServerBuilder {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            clock: None,
            listeners: None,
        }
    }

    /// Use a custom clock (tests).
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Serve on already-bound sockets instead of the configured addresses.
    /// Lets tests bind port 0 first and put the real ports in the issuer.
    #[must_use]
    pub fn listeners(mut self, public: std::net::TcpListener, mtls: std::net::TcpListener) -> Self {
        self.listeners = Some((public, mtls));
        self
    }

    pub async fn start(self) -> Result<Server> {
        let config = self.config;
        let state = AppState::start(&config, self.clock).await?;

        let identity =
            if let (Some(cert), Some(key)) = (&config.server.tls_cert, &config.server.tls_key) {
                TlsIdentity::from_pem_files(cert, key)?
            } else {
                tracing::warn!(
                    "server.tls_cert is not set: using an ephemeral self-signed certificate \
                 (development only)"
                );
                TlsIdentity::self_signed(certificate_names(&config))?
            };
        let client_policy = match &config.server.client_ca {
            Some(path) => ClientCertPolicy::from_ca_file(path)?,
            None => ClientCertPolicy::AnyProven,
        };
        let public_tls = tls::server_config(&identity, ClientCertPolicy::None)?;
        let mtls_tls = tls::server_config(&identity, client_policy)?;

        let (public, mtls) = match self.listeners {
            Some((public, mtls)) => (from_std(public)?, from_std(mtls)?),
            None => (
                bind(config.server.listen).await?,
                bind(config.server.mtls_listen).await?,
            ),
        };
        let public_addr = public.local_addr()?;
        let mtls_addr = mtls.local_addr()?;

        let router = http::router(state.clone());
        let limits = ConnectionLimits::from_config(&config.server);
        let (shutdown, _) = watch::channel(false);
        let tasks = vec![
            tokio::spawn(accept_loop(
                public,
                public_tls,
                router.clone(),
                limits,
                shutdown.subscribe(),
            )),
            tokio::spawn(accept_loop(
                mtls,
                mtls_tls,
                router,
                limits,
                shutdown.subscribe(),
            )),
            tokio::spawn(purge_loop(state.clone(), shutdown.subscribe())),
        ];
        tracing::info!(issuer = %state.issuer, %public_addr, %mtls_addr, "oxID is listening");

        Ok(Server {
            public_addr,
            mtls_addr,
            certificate: identity.certs[0].clone(),
            state,
            shutdown,
            tasks,
        })
    }
}

/// Serve `router` over TLS on `listener` until the returned sender is
/// dropped or sent `true`. The request extension [`ConnInfo`] carries the
/// client certificate, if `tls` asks for one.
///
/// This is the provider's own connection handling, exposed so that other
/// HTTPS services (in tests, a stand-in for the ConnectID registry) behave
/// the same way.
pub fn spawn_tls(
    listener: std::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    router: Router,
) -> Result<(watch::Sender<bool>, JoinHandle<()>)> {
    let listener = from_std(listener)?;
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(accept_loop(
        listener,
        tls,
        router,
        ConnectionLimits::default(),
        receiver,
    ));
    Ok((shutdown, task))
}

fn from_std(listener: std::net::TcpListener) -> Result<TcpListener> {
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener).context("adopting listener")
}

async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))
}

/// A running provider.
#[derive(Debug)]
pub struct Server {
    public_addr: SocketAddr,
    mtls_addr: SocketAddr,
    certificate: CertificateDer<'static>,
    state: AppState,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Server {
    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    pub fn mtls_addr(&self) -> SocketAddr {
        self.mtls_addr
    }

    /// The server's leaf certificate, so tests can trust a generated one.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Stop accepting connections, let in-flight requests finish, and wait.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

async fn purge_loop(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(PURGE_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(error) = state.store.purge(state.now()).await {
                    tracing::warn!(%error, "purging expired state failed");
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

/// Answer with `503` when a request takes longer than `limit`.
async fn request_timeout(limit: Duration, request: Request, next: Next) -> Response {
    if let Ok(response) = tokio::time::timeout(limit, next.run(request)).await {
        response
    } else {
        tracing::warn!(?limit, "request timed out");
        (StatusCode::SERVICE_UNAVAILABLE, "request timed out").into_response()
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    router: Router,
    limits: ConnectionLimits,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let request_limit = limits.request_timeout;
    let router = router.layer(middleware::from_fn(move |request, next| {
        request_timeout(request_limit, request, next)
    }));
    loop {
        // Take a connection slot before accepting, so that at the limit
        // further clients wait in the kernel's queue rather than in memory.
        let permit = tokio::select! {
            permit = Arc::clone(&slots).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            _ = shutdown.changed() => break,
        };
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(error) => {
                    // Typically file-descriptor exhaustion; back off briefly.
                    tracing::warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let session = tls.get_ref().1;
            let client_cert = session
                .peer_certificates()
                .and_then(<[CertificateDer<'_>]>::first)
                .map(|cert| ClientCert::from_der(cert.as_ref()));
            // The protocol is settled by ALPN in the handshake, so each
            // connection is served by one protocol's builder with its own
            // timeouts. (Sniffing the protocol from the first bytes would
            // wait for them with no timeout at all.)
            let is_h2 = session.alpn_protocol() == Some(b"h2");

            let service =
                TowerToHyperService::new(router.layer(Extension(ConnInfo { client_cert })));
            let io = TokioIo::new(tls);
            let result = if is_h2 {
                let mut builder = http2::Builder::new(TokioExecutor::new());
                builder
                    .timer(TokioTimer::new())
                    .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
                    .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
                    .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
                watcher.watch(builder.serve_connection(io, service)).await
            } else {
                let mut builder = http1::Builder::new();
                builder
                    .timer(TokioTimer::new())
                    .header_read_timeout(limits.header_read_timeout);
                watcher.watch(builder.serve_connection(io, service)).await
            };
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "connection ended with an error");
            }
        });
    }

    drop(listener);
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("shutdown grace period elapsed with connections still open");
    }
}

#[cfg(test)]
mod tests;
