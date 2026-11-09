use crate::app::App;
use crate::routes;
use crate::web::{self, Resp};
use http::{Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

async fn serve_io<I>(app: Arc<App>, io: I, peer: SocketAddr)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let app = app.clone();
        async move { Ok::<Resp, Infallible>(routes::handle(app, req, peer).await) }
    });
    let _ = Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
}

/// Someone typed http:// while --secure is on: send them to https://.
async fn serve_redirect(app: Arc<App>, stream: TcpStream) {
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let app = app.clone();
        async move {
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|h| h.to_string())
                .unwrap_or_else(|| format!("{}:{}", app.selected_ip(), app.port));
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let mut r = web::redirect(&format!("https://{}{}", host, path));
            *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
            Ok::<Resp, Infallible>(web::finish(r))
        }
    });
    let _ = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), svc)
        .await;
}

async fn handle_conn(app: Arc<App>, stream: TcpStream, peer: SocketAddr, tls: Option<TlsAcceptor>) {
    let _ = stream.set_nodelay(true);
    match tls {
        None => serve_io(app, TokioIo::new(stream), peer).await,
        Some(acceptor) => {
            let mut first = [0u8; 1];
            let looks_tls = match tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut first)).await {
                Ok(Ok(n)) if n > 0 => first[0] == 0x16,
                _ => return,
            };
            if !looks_tls {
                serve_redirect(app, stream).await;
                return;
            }
            match tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => serve_io(app, TokioIo::new(tls_stream), peer).await,
                _ => {}
            }
        }
    }
}

pub async fn run(app: Arc<App>, listener: TcpListener, tls: Option<TlsAcceptor>) {
    let mut shutdown = app.subscribe_shutdown();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let app = app.clone();
                        let tls = tls.clone();
                        tokio::spawn(handle_conn(app, stream, peer, tls));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}
