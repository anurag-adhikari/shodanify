use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

const USER_AGENT: &str = "Shodanify-Healthcheck/1.0 (+defensive security outreach)";

// Ports that are unambiguously one scheme.
const HTTP_ONLY:  &[u16] = &[80, 8080, 3000, 5000, 8000, 8888];
const HTTPS_ONLY: &[u16] = &[443, 8443, 9443, 4443, 10443];

static TITLE_RE: OnceLock<Regex> = OnceLock::new();

fn title_re() -> &'static Regex {
    TITLE_RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap())
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
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

// Returns true if the error is a transport/protocol mismatch (e.g. sent HTTPS to an
// HTTP server) rather than a network or application-level error.
fn is_scheme_mismatch(err: &reqwest::Error) -> bool {
    // No status code means it failed before getting an HTTP response.
    if err.status().is_some() { return false; }
    let s = err.to_string().to_lowercase();
    // TLS handshake failure when server speaks plain HTTP, or an unexpected EOF/reset
    // when a plain-HTTP client connects to a TLS port.
    s.contains("tls") || s.contains("handshake") || s.contains("corrupt")
        || s.contains("eof") || s.contains("connection reset")
        || s.contains("record overflow") || s.contains("illegal parameter")
}

// Make a single HTTP request with the given scheme; returns the result JSON.
async fn try_scheme(client: &reqwest::Client, host: &str, port: u16, scheme: &str) -> Value {
    let url = build_url(host, port, scheme);
    let start = Instant::now();

    match client.get(url.as_str()).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16() as i64;
            let http_ok = (200..400).contains(&(status as u16));
            let server = resp.headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let final_url = resp.url().to_string();
            let redirected = final_url.trim_end_matches('/') != url.trim_end_matches('/');

            let body = match resp.bytes().await {
                Ok(b) => {
                    let slice = if b.len() > 20_000 { &b[..20_000] } else { &b[..] };
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
            if let Some(status) = e.status() {
                json!({
                    "http_status": status.as_u16() as i64,
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
                    "_scheme_mismatch": is_scheme_mismatch(&e),
                })
            }
        }
    }
}

// Tries the canonical scheme for the port; if that fails with a protocol mismatch
// (e.g. HTTPS port that happens to serve plain HTTP) it retries with the other scheme.
// For unambiguous ports (80, 443, etc.) it never retries.
async fn http_check(client: &reqwest::Client, host: &str, port: u16) -> Value {
    let primary = if HTTP_ONLY.contains(&port) {
        "http"
    } else if HTTPS_ONLY.contains(&port) {
        "https"
    } else {
        // Ambiguous port: default to https (more common for non-standard ports in Shodan data),
        // fall back to http if we get a TLS-level error.
        "https"
    };

    let result = try_scheme(client, host, port, primary).await;

    // Only retry for genuinely ambiguous ports — avoid double-requesting known ports.
    let is_ambiguous = !HTTP_ONLY.contains(&port) && !HTTPS_ONLY.contains(&port);
    if is_ambiguous {
        let mismatch = result
            .get("_scheme_mismatch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if mismatch {
            let fallback = if primary == "https" { "http" } else { "https" };
            let alt = try_scheme(client, host, port, fallback).await;
            // Use fallback only if it actually got an HTTP-level response.
            if alt.get("http_status").map(|v| !v.is_null()).unwrap_or(false) {
                return alt;
            }
        }
    }

    // Strip the internal helper field before returning.
    if let Some(obj) = result.as_object() {
        let mut clean: serde_json::Map<String, Value> = obj.clone();
        clean.remove("_scheme_mismatch");
        return Value::Object(clean);
    }
    result
}

pub async fn check_target(
    client: &reqwest::Client,
    ip: &str,
    port: u16,
    hostname: Option<&str>,
    connect_timeout: Duration,
) -> Value {
    let host_for_http = hostname.unwrap_or(ip);

    // TCP connect and rDNS are independent — run them concurrently.
    let ((tcp_open, tcp_ms), rdns) = tokio::join!(
        tcp_check(ip, port, connect_timeout),
        reverse_dns(ip.to_string()),
    );

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
        http_check(client, host_for_http, port).await
    } else {
        let scheme = if HTTPS_ONLY.contains(&port) { "https" } else { "http" };
        json!({
            "http_status": null, "http_ok": false,
            "scheme": scheme,
            "url": build_url(host_for_http, port, scheme),
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

    let client = std::sync::Arc::new(
        reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .timeout(read_timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build HTTP client"),
    );

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(workers));
    let mut futs = FuturesUnordered::new();

    for (ip, port, hostname) in targets {
        let sem = semaphore.clone();
        let c = client.clone();
        futs.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            check_target(&c, &ip, port, hostname.as_deref(), connect_timeout).await
        }));
    }

    let mut results = Vec::with_capacity(futs.len());
    while let Some(res) = futs.next().await {
        if let Ok(v) = res { results.push(v); }
    }
    results
}
