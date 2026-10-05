use std::{collections::HashSet, net::{IpAddr, SocketAddr}, sync::{OnceLock, Arc}, time::{Duration, Instant}};
use futures_util::StreamExt;

use anyhow::{anyhow, Context, Result};
use http_body_util::BodyExt;
use reqwest::{header, Client, StatusCode};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;
use url::Url;
use vercel_runtime::{run, service_fn, Error, Request, Response, ResponseBody};

const MAX_REDIRECTS: usize = 5;
const MAX_BYTES: usize = 12 * 1024 * 1024;
const MAX_TEXT: usize = 1_500_000;
const MAX_URL_LEN: usize = 4096;
const FETCH_TIMEOUT_SECS: u64 = 14;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const USER_AGENT: &str = "ArixAI-WebIntelligence/1.0";
const MAX_INPUT_BYTES: usize = 16 * 1024;

static CONCURRENCY: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct CrawlRequest { url: String, #[serde(default)] max_text: Option<usize> }

#[derive(Debug, Serialize)]
struct CrawlResponse {
    ok: bool,
    url: String,
    final_url: Option<String>,
    title: Option<String>,
    description: Option<String>,
    language: Option<String>,
    content_type: Option<String>,
    text: Option<String>,
    ai_context: Option<String>,
    word_count: usize,
    quality: u8,
    method: String,
    latency_ms: u128,
    stages: Stages,
    warnings: Vec<String>,
    error: Option<Failure>,
}

#[derive(Debug, Default, Serialize)]
struct Stages {
    validation_ms: u128,
    dns_ms: u128,
    fetch_ms: u128,
    parse_ms: u128,
    extraction_ms: u128,
    audit_ms: u128,
}

#[derive(Debug, Serialize)]
struct Failure { code: String, message: String, retryable: bool }

#[derive(Debug)]
struct SafeTarget { url: Url, ip: IpAddr }

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

async fn handler(req: Request) -> Result<Response<ResponseBody>, Error> {
    let started = Instant::now();
    if req.method() == http::Method::OPTIONS {
        return Ok(Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "POST, OPTIONS")
            .header("access-control-allow-headers", "content-type")
            .body(ResponseBody::empty())?);
    }
    if req.method() != http::Method::POST {
        return json_response(405, &serde_json::json!({"ok": false, "error": {"code": "METHOD_NOT_ALLOWED"}}));
    }
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return json_response(400, &serde_json::json!({"ok":false,"error":{"code":"INVALID_BODY","message":"Could not read request body"}})),
    };
    if body.len() > MAX_INPUT_BYTES {
        return json_response(413, &serde_json::json!({"ok":false,"error":{"code":"REQUEST_TOO_LARGE","message":"Request body is too large"}}));
    }
    let input: CrawlRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_response(400, &serde_json::json!({"ok":false,"error":{"code":"INVALID_JSON","message":"Send JSON: { url: string }"}})),
    };
    let max_text = input.max_text.unwrap_or(MAX_TEXT).min(MAX_TEXT).max(1000);
    let gate = CONCURRENCY.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(16))).clone();
    let _permit = match gate.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return json_response(429, &serde_json::json!({"ok":false,"error":{"code":"CRAWLER_BUSY","message":"Crawler capacity is temporarily full. Retry shortly.","retryable":true}})),
    };
    let result = crawl(&input.url, max_text).await;
    match result {
        Ok(mut out) => { out.latency_ms = started.elapsed().as_millis(); json_response(200, &out) }
        Err(e) => json_response(502, &serde_json::json!({
            "ok": false,
            "url": input.url,
            "latency_ms": started.elapsed().as_millis(),
            "error": {"code":"CRAWL_FAILED","message":safe_error(&e),"retryable":false}
        }))
    }
}

fn json_response<T: Serialize>(status: u16, value: &T) -> Result<Response<ResponseBody>, Error> {
    let status = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = serde_json::to_vec(value)?;
    Ok(Response::builder()
        .status(status)
        .header("access-control-allow-origin", "*")
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(ResponseBody::from(bytes))?)
}

async fn crawl(raw: &str, max_text: usize) -> Result<CrawlResponse> {
    let mut stages = Stages::default();
    let mut warnings = Vec::new();
    let validation = Instant::now();
    if raw.len() > MAX_URL_LEN { return Err(anyhow!("URL_TOO_LONG")); }
    let mut target = validate_target(raw).await?;
    stages.validation_ms = validation.elapsed().as_millis();

    let mut visited = HashSet::new();
    let mut redirect_count = 0;
    let response = loop {
        if !visited.insert(target.url.to_string()) { return Err(anyhow!("REDIRECT_LOOP")); }
        let dns = Instant::now();
        target = validate_target(target.url.as_str()).await?;
        stages.dns_ms += dns.elapsed().as_millis();

        let fetch = Instant::now();
        let client = build_client_for(&target)?;
        let req = client.get(target.url.clone()).header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, "text/html,application/xhtml+xml,application/json;q=0.8,text/plain;q=0.5")
            .header(header::ACCEPT_LANGUAGE, "en-US,en;q=0.8");
        let r = req.send().await.context("FETCH_FAILED")?;
        stages.fetch_ms += fetch.elapsed().as_millis();

        if r.status().is_redirection() {
            if redirect_count >= MAX_REDIRECTS { return Err(anyhow!("REDIRECT_LIMIT")); }
            let loc = r.headers().get(header::LOCATION).ok_or_else(|| anyhow!("REDIRECT_WITHOUT_LOCATION"))?.to_str().context("BAD_LOCATION")?;
            let next = target.url.join(loc).context("INVALID_REDIRECT")?;
            target = validate_target(next.as_str()).await?;
            redirect_count += 1;
            continue;
        }
        break r;
};
    let status = response.status();
    let final_url = target.url.to_string();
    let ctype = response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    if status == StatusCode::TOO_MANY_REQUESTS { return Err(anyhow!("RATE_LIMITED_429")); }
    if status == StatusCode::UNAUTHORIZED { return Err(anyhow!("AUTHENTICATION_REQUIRED")); }
    if status == StatusCode::FORBIDDEN { return Err(anyhow!("FORBIDDEN_OR_BOT_PROTECTION")); }
    if status.is_client_error() { return Err(anyhow!("HTTP_{}", status.as_u16())); }
    if status.is_server_error() { return Err(anyhow!("UPSTREAM_{}", status.as_u16())); }

    if !(ctype.contains("text/html") || ctype.contains("application/xhtml+xml") || ctype.is_empty()) {
        return Err(anyhow!("UNSUPPORTED_CONTENT_TYPE:{}", ctype));
    }

    let declared_len = response.content_length();
    if declared_len.is_some_and(|n| n > MAX_BYTES as u64) { return Err(anyhow!("RESPONSE_TOO_LARGE")); }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(declared_len.unwrap_or(0).min(MAX_BYTES as u64) as usize);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("BODY_READ_FAILED")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES { return Err(anyhow!("RESPONSE_TOO_LARGE")); }
        bytes.extend_from_slice(&chunk);
    }

    let parse = Instant::now();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    let doc = Html::parse_document(&html);
    stages.parse_ms = parse.elapsed().as_millis();

    let extract = Instant::now();
    let (title, description, language, text, score, extra_warnings) = extract_content(&doc, max_text);
    warnings.extend(extra_warnings);
    stages.extraction_ms = extract.elapsed().as_millis();

    let audit = Instant::now();
    let words = text.split_whitespace().count();
    let lower = text.to_ascii_lowercase();
    let mut quality = score;
    if words < 30 { quality = quality.min(35); warnings.push("very_little_meaningful_text".into()); }
    if lower.contains("sign in") && words < 120 { warnings.push("possible_auth_wall".into()); quality = quality.min(45); }
    if lower.contains("enable javascript") || lower.contains("checking your browser") { warnings.push("possible_js_or_bot_challenge".into()); quality = quality.min(25); }
    stages.audit_ms = audit.elapsed().as_millis();

    if quality < 40 {
        return Err(anyhow!("LOW_CONFIDENCE_EXTRACTION"));
    }

    let ai_context = format!("SOURCE: {}\nTITLE: {}\nQUALITY: {}/100\n\n{}", final_url, title.as_deref().unwrap_or("Untitled"), quality, text);

    Ok(CrawlResponse {
        ok: true, url: raw.to_string(), final_url: Some(final_url), title, description, language,
        content_type: Some(ctype), text: Some(text.clone()), ai_context: Some(ai_context), word_count: words, quality, method: "static-html".into(),
        latency_ms: 0, stages, warnings, error: None,
    })
}

fn build_client_for(target: &SafeTarget) -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .pool_max_idle_per_host(8)
        .pool_idle_timeout(Duration::from_secs(30))
        .http2_adaptive_window(true)
        .gzip(true).brotli(true).deflate(true).zstd(true)
        .user_agent(USER_AGENT)
        .resolve(target.url.host_str().ok_or_else(|| anyhow!("MISSING_HOST"))?, SocketAddr::new(target.ip, target.url.port_or_known_default().unwrap_or(443)))
        .build()?)
}

async fn validate_target(raw: &str) -> Result<SafeTarget> {
    let u = Url::parse(raw).context("INVALID_URL")?;
    if u.scheme() != "http" && u.scheme() != "https" { return Err(anyhow!("UNSUPPORTED_SCHEME")); }
    if u.username() != "" || u.password().is_some() { return Err(anyhow!("USERINFO_NOT_ALLOWED")); }
    let host = u.host_str().ok_or_else(|| anyhow!("MISSING_HOST"))?.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") || host.ends_with(".internal") { return Err(anyhow!("PRIVATE_HOST")); }
    let port = u.port_or_known_default().ok_or_else(|| anyhow!("BAD_PORT"))?;
    if port == 0 || port > 65535 { return Err(anyhow!("BAD_PORT")); }

    let ip = match u.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => {
            let mut addrs = lookup_host((host.as_str(), port)).await.context("DNS_FAILED")?;
            let mut chosen = None;
            while let Some(sa) = addrs.next() {
                if is_public_ip(sa.ip()) { chosen = Some(sa.ip()); break; }
            }
            chosen.ok_or_else(|| anyhow!("NO_PUBLIC_IP"))?
        }
    };
    if !is_public_ip(ip) { return Err(anyhow!("PRIVATE_OR_RESERVED_IP")); }
    Ok(SafeTarget { url: u, ip })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_documentation()
              || o[0] == 0 || (o[0] == 100 && (64..=127).contains(&o[1])) || (o[0] == 198 && (18..=19).contains(&o[1]))
              || o[0] >= 224)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() { return is_public_ip(IpAddr::V4(v4)); }
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_multicast())
        }
    }
}

fn extract_content(doc: &Html, max_text: usize) -> (Option<String>, Option<String>, Option<String>, String, u8, Vec<String>) {
    let mut warnings = Vec::new();
    let title = Selector::parse("title").ok().and_then(|s| doc.select(&s).next()).map(|n| clean(n.text().collect::<Vec<_>>().join(" "))).filter(|x| !x.is_empty());
    let description = Selector::parse("meta[name='description'], meta[property='og:description']").ok().and_then(|s| doc.select(&s).next()).and_then(|n| n.value().attr("content")).map(|s| clean(s.to_string())).filter(|x| !x.is_empty());
    let language = Selector::parse("html").ok().and_then(|s| doc.select(&s).next()).and_then(|n| n.value().attr("lang")).map(|s| s.to_string());

    let selectors = [
        ("article", 30), ("main", 28), ("[role='main']", 26),
        ("section", 12), ("div", 0), ("body", -10)
    ];
    let mut best = String::new();
    let mut best_score = 0i64;
    for (sel, bonus) in selectors {
        let Ok(selector) = Selector::parse(sel) else { continue };
        for node in doc.select(&selector).take(120) {
            let text = visible_text(node);
            let t = clean(text);
            if t.len() < 80 { continue; }
            let score = content_score(node, &t, bonus);
            if score > best_score { best_score = score; best = t; }
        }
    }
    if best.is_empty() {
        warnings.push("no_strong_content_region".into());
        best = visible_text(doc.root_element());
        best = clean(best);
    }
    let text = normalize_and_cap(&best, max_text);
    let quality = ((best_score.clamp(0, 100)) as u8).max(if text.len() > 500 { 70 } else { 30 });
    (title, description, language, text, quality, warnings)
}

fn visible_text(node: scraper::ElementRef<'_>) -> String {
    let mut out = String::new();
    for child in node.children() {
        if let Some(el) = scraper::ElementRef::wrap(child) {
            let tag = el.value().name();
            if matches!(tag, "script" | "style" | "noscript" | "template" | "svg" | "canvas" | "iframe" | "object" | "embed" | "form") { continue; }
            out.push(' ');
            out.push_str(&visible_text(el));
        } else if let Some(text) = child.value().as_text() {
            out.push(' ');
            out.push_str(text);
        }
    }
    out
}

fn content_score(node: scraper::ElementRef<'_>, text: &str, bonus: i32) -> i64 {
    let value = node.value();
    let attrs = format!("{} {}", value.id().unwrap_or(""), value.attr("class").unwrap_or("" )).to_ascii_lowercase();
    let words = text.split_whitespace().count() as i64;
    let links = Selector::parse("a").ok().map(|s| node.select(&s).count() as i64).unwrap_or(0);
    let paragraphs = Selector::parse("p").ok().map(|s| node.select(&s).count() as i64).unwrap_or(0);
    let headings = Selector::parse("h1,h2,h3").ok().map(|s| node.select(&s).count() as i64).unwrap_or(0);
    let bad = ["nav", "menu", "footer", "sidebar", "cookie", "consent", "advert", "sponsor", "newsletter", "social", "login", "signup"];
    let penalty = bad.iter().filter(|x| attrs.contains(**x)).count() as i64 * 18;
    let link_penalty = if words > 0 { ((links * 100) / words).min(45) } else { 45 };
    (words.min(5000) / 25) + paragraphs.min(60) * 2 + headings.min(15) * 3 + bonus as i64 - penalty - link_penalty
}

fn normalize_and_cap(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    let mut last_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() { if !last_space { out.push(' '); last_space = true; } }
        else { out.push(ch); last_space = false; }
        if out.len() >= max { break; }
    }
    out.trim().to_string()
}

fn clean(s: String) -> String { normalize_and_cap(&s, MAX_TEXT) }
fn safe_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    if s.len() > 180 { s[..180].to_string() } else { s }
}
