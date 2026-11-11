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
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::watch;
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
        let state = match self.clock {
            Some(clock) => AppState::from_config_with_clock(&config, clock)?,
            None => AppState::from_config(&config)?,
        };

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
        let (shutdown, _) = watch::channel(false);
        let tasks = vec![
            tokio::spawn(accept_loop(
                public,
                public_tls,
                router.clone(),
                shutdown.subscribe(),
            )),
            tokio::spawn(accept_loop(mtls, mtls_tls, router, shutdown.subscribe())),
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
            _ = ticker.tick() => state.store.purge(state.now()),
            _ = shutdown.changed() => return,
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let graceful = GracefulShutdown::new();
    loop {
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
            let client_cert = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[CertificateDer<'_>]>::first)
                .map(|cert| ClientCert::from_der(cert.as_ref()));

            let service =
                TowerToHyperService::new(router.layer(Extension(ConnInfo { client_cert })));
            let builder = Builder::new(TokioExecutor::new());
            let connection = builder.serve_connection(TokioIo::new(tls), service);
            if let Err(error) = watcher.watch(connection.into_owned()).await {
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
