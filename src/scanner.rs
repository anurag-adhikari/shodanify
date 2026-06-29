use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

const USER_AGENT: &str = "Shodanify-Healthcheck/1.0 (+defensive security outreach)";
const HTTPS_PORTS: &[u16] = &[443, 8443, 9443, 4443, 10443];

static TITLE_RE: OnceLock<Regex> = OnceLock::new();

fn title_re() -> &'static Regex {
    TITLE_RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap())
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn scheme_for_port(port: u16) -> &'static str {
    if HTTPS_PORTS.contains(&port) { "https" } else { "http" }
}

fn build_url(host: &str, port: u16, scheme: &str) -> String {
    let is_default = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    if is_default {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    }
}

async fn tcp_check(ip: &str, port: u16, connect_timeout: Duration) -> (bool, Option<u64>) {
    let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
        Ok(a) => a,
        Err(_) => return (false, None),
    };
    let start = Instant::now();
    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => (true, Some(start.elapsed().as_millis() as u64)),
        _ => (false, None),
    }
}

async fn reverse_dns(ip: String) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&ip.parse().ok()?).ok()
    })
    .await
    .ok()
    .flatten()
}

async fn http_check(host: &str, port: u16, read_timeout: Duration) -> Value {
    let scheme = scheme_for_port(port);
    let url = build_url(host, port, scheme);

    let client = match reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .timeout(read_timeout)
        .redirect(reqwest::redirect::Policy::limited(10))
        .user_agent(USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({
            "http_status": null, "http_ok": false, "server": null, "title": null,
            "final_url": null, "redirected": false, "http_ms": null,
            "scheme": scheme, "url": url, "http_error": e.to_string(),
        }),
    };

    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16() as i64;
            let http_ok = (200..400).contains(&(status as u16));
            let server = resp.headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let final_url = resp.url().to_string();
            let redirected = final_url.trim_end_matches('/') != url.trim_end_matches('/');

            // Read first 20KB of body for title extraction
            let body = match resp.bytes().await {
                Ok(b) => {
                    let slice = if b.len() > 20000 { &b[..20000] } else { &b[..] };
                    String::from_utf8_lossy(slice).to_string()
                }
                Err(_) => String::new(),
            };

            let ms = start.elapsed().as_millis() as u64;
            let title = title_re()
                .captures(&body)
                .and_then(|c| c.get(1))
                .map(|m| {
                    let t = m.as_str().trim();
                    let t = if t.len() > 200 {
                        let mut idx = 200;
                        while idx > 0 && !t.is_char_boundary(idx) { idx -= 1; }
                        &t[..idx]
                    } else { t };
                    t.to_string()
                });

            json!({
                "http_status": status,
                "http_ok": http_ok,
                "server": server,
                "title": title,
                "final_url": final_url,
                "redirected": redirected,
                "http_ms": ms,
                "scheme": scheme,
                "url": url,
            })
        }
        Err(e) => {
            let ms = start.elapsed().as_millis() as u64;
            // Check if it's an HTTP error with a status code
            if let Some(status) = e.status() {
                let code = status.as_u16() as i64;
                json!({
                    "http_status": code,
                    "http_ok": false,
                    "server": null, "title": null,
                    "final_url": url, "redirected": false,
                    "http_ms": ms, "scheme": scheme, "url": url,
                })
            } else {
                let err_str = e.to_string();
                let short_err = if err_str.len() > 160 { err_str[..160].to_string() } else { err_str };
                json!({
                    "http_status": null, "http_ok": false, "server": null, "title": null,
                    "final_url": null, "redirected": false,
                    "http_ms": ms, "scheme": scheme, "url": url,
                    "http_error": short_err,
                })
            }
        }
    }
}

pub async fn check_target(
    ip: &str,
    port: u16,
    hostname: Option<&str>,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Value {
    let host_for_http = hostname.unwrap_or(ip);
    let scheme = scheme_for_port(port);
    let url = build_url(host_for_http, port, scheme);

    let (tcp_open, tcp_ms) = tcp_check(ip, port, connect_timeout).await;
    let rdns = reverse_dns(ip.to_string()).await;

    let mut result = json!({
        "ip": ip,
        "port": port,
        "hostname": hostname,
        "rdns": rdns,
        "tcp_open": tcp_open,
        "tcp_ms": tcp_ms,
        "scanned_at": now_iso(),
    });

    let http_result = if tcp_open {
        http_check(host_for_http, port, read_timeout).await
    } else {
        json!({
            "http_status": null, "http_ok": false,
            "scheme": scheme, "url": url,
        })
    };

    if let (Some(obj), Some(http_obj)) = (result.as_object_mut(), http_result.as_object()) {
        for (k, v) in http_obj {
            obj.insert(k.clone(), v.clone());
        }
    }

    result
}

pub async fn scan_targets(
    targets: Vec<(String, u16, Option<String>)>,
    workers: usize,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Vec<Value> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(workers));
    let mut futs = FuturesUnordered::new();

    for (ip, port, hostname) in targets {
        let sem = semaphore.clone();
        let ct = connect_timeout;
        let rt = read_timeout;
        futs.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            check_target(&ip, port, hostname.as_deref(), ct, rt).await
        }));
    }

    let mut results = Vec::new();
    while let Some(res) = futs.next().await {
        if let Ok(v) = res {
            results.push(v);
        }
    }
    results
}
