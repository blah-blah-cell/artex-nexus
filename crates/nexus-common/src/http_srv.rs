use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::Value;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};

pub struct HttpRequest {
    pub method: Method,
    pub uri: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn text(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: msg.into().into_bytes(),
        }
    }

    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body: body.into().into_bytes(),
        }
    }

    pub fn json(status: u16, val: &Value) -> Self {
        Self {
            status,
            headers: vec![(
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )],
            body: val.to_string().into_bytes(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.headers.push((name.into(), val.into()));
        self
    }

    fn into_hyper(self, strip_body: bool) -> Response<Full<Bytes>> {
        let mut builder = Response::builder()
            .status(StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        for (k, v) in self.headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                builder = builder.header(hn, hv);
            }
        }
        let payload = if strip_body {
            Bytes::new()
        } else {
            Bytes::from(self.body)
        };
        builder
            .body(Full::new(payload))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub max_body_bytes: usize,
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    pub request_timeout: Duration,
    pub max_concurrent: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            header_read_timeout: Duration::from_secs(10),
            body_read_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            max_concurrent: 64,
        }
    }
}

pub struct RunningServer {
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RunningServer {
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn process_request<F>(
    req: Request<Incoming>,
    cfg: Arc<ServerConfig>,
    sem: Arc<Semaphore>,
    handler: Arc<F>,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    let _permit = match sem.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return Ok(HttpResponse::text(503, "Service Busy").into_hyper(false)),
    };

    let (parts, body) = req.into_parts();
    let is_head = parts.method == Method::HEAD;

    let collected = match tokio::time::timeout(
        cfg.body_read_timeout,
        Limited::new(body, cfg.max_body_bytes).collect(),
    )
    .await
    {
        Ok(Ok(c)) => c.to_bytes().to_vec(),
        Ok(Err(e)) => {
            if e.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(HttpResponse::text(413, "Payload Too Large").into_hyper(is_head));
            }
            return Ok(HttpResponse::text(400, "Bad Request").into_hyper(is_head));
        }
        Err(_) => return Ok(HttpResponse::text(408, "Request Timeout").into_hyper(is_head)),
    };

    let uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let hreq = HttpRequest {
        method: parts.method,
        uri,
        headers: parts.headers,
        body: collected,
    };

    let h_clone = Arc::clone(&handler);
    let out = match tokio::time::timeout(
        cfg.request_timeout,
        tokio::task::spawn_blocking(move || h_clone(hreq)),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => HttpResponse::text(500, "Internal Server Error"),
        Err(_) => HttpResponse::text(504, "Gateway Timeout"),
    };
    Ok(out.into_hyper(is_head))
}

async fn run_accept_loop<F>(
    listener: TcpListener,
    cfg: ServerConfig,
    handler: F,
    mut shutdown_rx: oneshot::Receiver<()>,
) where
    F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    let cfg = Arc::new(cfg);
    let handler = Arc::new(handler);
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accept_res = listener.accept() => {
                let (stream, _) = match accept_res {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let cfg_c = Arc::clone(&cfg);
                let sem_c = Arc::clone(&sem);
                let h_c = Arc::clone(&handler);
                let header_timeout = cfg.header_read_timeout;

                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        process_request(req, Arc::clone(&cfg_c), Arc::clone(&sem_c), Arc::clone(&h_c))
                    });
                    let mut conn = http1::Builder::new();
                    conn.timer(TokioTimer::new())
                        .header_read_timeout(header_timeout)
                        .max_headers(100)
                        .keep_alive(false);
                    let _ = conn.serve_connection(io, svc).await;
                });
            }
        }
    }
}

pub fn spawn_http_server<F>(bind_addr: &str, cfg: ServerConfig, handler: F) -> Result<RunningServer>
where
    F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    let std_listener =
        std::net::TcpListener::bind(bind_addr).with_context(|| format!("binding {bind_addr}"))?;
    std_listener.set_nonblocking(true)?;
    let addr = std_listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("building tokio runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("converting listener");
            run_accept_loop(listener, cfg, handler, shutdown_rx).await;
        });
    });

    Ok(RunningServer {
        addr,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    })
}

pub fn serve_http_blocking<F>(bind_addr: &str, cfg: ServerConfig, handler: F) -> Result<()>
where
    F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    let std_listener =
        std::net::TcpListener::bind(bind_addr).with_context(|| format!("binding {bind_addr}"))?;
    std_listener.set_nonblocking(true)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let (_tx, rx) = oneshot::channel();
    rt.block_on(async move {
        let listener = TcpListener::from_std(std_listener)?;
        run_accept_loop(listener, cfg, handler, rx).await;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn enforces_max_body_bytes_and_header_timeout() {
        let cfg = ServerConfig {
            max_body_bytes: 32,
            header_read_timeout: Duration::from_millis(250),
            body_read_timeout: Duration::from_millis(250),
            request_timeout: Duration::from_secs(2),
            max_concurrent: 8,
        };
        let mut srv =
            spawn_http_server("127.0.0.1:0", cfg, |_req| HttpResponse::text(200, "ok")).unwrap();

        // Oversized body must get 413.
        let mut s1 = TcpStream::connect(srv.addr).unwrap();
        let big = "x".repeat(64);
        write!(
            s1,
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            big.len(),
            big
        )
        .unwrap();
        let mut resp1 = String::new();
        let _ = s1.read_to_string(&mut resp1);
        assert!(
            resp1.starts_with("HTTP/1.1 413"),
            "expected 413, got: {resp1}"
        );

        // Stalled incomplete headers must be closed by header_read_timeout.
        let mut s2 = TcpStream::connect(srv.addr).unwrap();
        s2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(s2, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n").unwrap();
        let mut buf = [0u8; 64];
        let n = s2.read(&mut buf).unwrap_or(0);
        assert_eq!(
            n, 0,
            "expected stalled connection to close after header timeout"
        );

        srv.stop();
    }
}
