use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use futures_util::{stream, StreamExt};
use http_body_util::BodyExt;
use reqwest::{header, Client, StatusCode};
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use tokio::{net::lookup_host, sync::Semaphore};
use url::Url;
use vercel_runtime::{run, service_fn, Error, Request, Response, ResponseBody};

const MAX_REDIRECTS: usize = 8;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT: usize = 1_500_000;
const MAX_URL_LEN: usize = 4096;
const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_URLS_PER_REQUEST: usize = 40;
const SCHEDULER_CEILING: usize = 2000;
const FETCH_TIMEOUT_SECS: u64 = 14;
const CONNECT_TIMEOUT_SECS: u64 = 4;
const USER_AGENT: &str = "ArixAI-WebIntelligence/2.0";
const MAX_REDIRECT_TARGETS: usize = 8;
const MAX_CANDIDATES: usize = 180;
const MAX_CHILDREN_SCAN: usize = 20000;

static GLOBAL_GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct CrawlRequest {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default)]
    max_text: Option<usize>,
}

#[derive(Debug, Serialize, Clone)]
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

#[derive(Debug, Default, Serialize, Clone)]
struct Stages {
    validation_ms: u128,
    dns_ms: u128,
    fetch_ms: u128,
    redirect_ms: u128,
    parse_ms: u128,
    extraction_ms: u128,
    audit_ms: u128,
}

#[derive(Debug, Serialize, Clone)]
struct Failure {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Debug, Serialize)]
struct BatchResponse {
    ok: bool,
    count: usize,
    succeeded: usize,
    failed: usize,
    latency_ms: u128,
    scheduler: SchedulerInfo,
    results: Vec<CrawlResponse>,
}

#[derive(Debug, Serialize)]
struct SchedulerInfo {
    requested: usize,
    max_urls_per_request: usize,
    concurrency_ceiling: usize,
    strategy: &'static str,
}

#[derive(Debug)]
struct SafeTarget {
    url: Url,
    ip: IpAddr,
}

#[derive(Debug)]
struct FetchResult {
    response: reqwest::Response,
    final_target: SafeTarget,
    redirect_count: usize,
    redirect_ms: u128,
    dns_ms: u128,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

async fn handler(req: Request) -> Result<Response<ResponseBody>, Error> {
    if req.method() == http::Method::OPTIONS {
        return Ok(Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "POST, OPTIONS")
            .header("access-control-allow-headers", "content-type")
            .header("cache-control", "no-store")
            .body(ResponseBody::from(""))?);
    }

    if req.method() != http::Method::POST {
        return json_response(405, &serde_json::json!({
            "ok": false,
            "error": {"code": "METHOD_NOT_ALLOWED"}
        }));
    }

    let started = Instant::now();
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json_response(400, &serde_json::json!({
                "ok": false,
                "error": {"code": "INVALID_BODY", "message": "Could not read request body"}
            }))
        }
    };

    if body.len() > MAX_INPUT_BYTES {
        return json_response(413, &serde_json::json!({
            "ok": false,
            "error": {"code": "REQUEST_TOO_LARGE", "message": "Request body is too large"}
        }));
    }

    let input: CrawlRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return json_response(400, &serde_json::json!({
                "ok": false,
                "error": {
                    "code": "INVALID_JSON",
                    "message": "Send JSON: { url: string } or { urls: string[] }"
                }
            }))
        }
    };

    let mut urls = input.urls.unwrap_or_default();
    if let Some(u) = input.url {
        if !u.trim().is_empty() {
            urls.push(u);
        }
    }

    let mut normalized = Vec::with_capacity(urls.len().min(MAX_URLS_PER_REQUEST));
    let mut seen = HashSet::new();
    for raw in urls {
        let u = raw.trim().to_string();
        if u.is_empty() || u.len() > MAX_URL_LEN {
            continue;
        }
        if seen.insert(u.clone()) {
            normalized.push(u);
        }
    }

    if normalized.is_empty() {
        return json_response(400, &serde_json::json!({
            "ok": false,
            "error": {"code": "NO_URLS", "message": "Provide at least one HTTP(S) URL"}
        }));
    }

    if normalized.len() > MAX_URLS_PER_REQUEST {
        return json_response(413, &serde_json::json!({
            "ok": false,
            "error": {
                "code": "TOO_MANY_URLS",
                "message": format!("Maximum {} URLs per request", MAX_URLS_PER_REQUEST)
            }
        }));
    }

    let max_text = input.max_text.unwrap_or(MAX_TEXT).min(MAX_TEXT).max(1000);
    let requested = normalized.len();

    // 2,000 is the scheduler ceiling, not a promise that Vercel will allocate
    // 2,000 sockets. For this endpoint the request itself is limited to 40 URLs.
    let gate = GLOBAL_GATE
        .get_or_init(|| Arc::new(Semaphore::new(SCHEDULER_CEILING)))
        .clone();

    let results = stream::iter(normalized.into_iter().map(|u| {
        let gate = gate.clone();
        async move {
            let _permit = match gate.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    return failed_response(
                        u,
                        "CRAWLER_SHUTDOWN",
                        "Crawler scheduler is unavailable",
                        false,
                    )
                }
            };
            crawl_one(&u, max_text).await
        }
    }))
    .buffer_unordered(SCHEDULER_CEILING)
    .collect::<Vec<_>>()
    .await;

    let succeeded = results.iter().filter(|r| r.ok).count();
    let failed = results.len().saturating_sub(succeeded);

    json_response(200, &BatchResponse {
        ok: failed == 0,
        count: results.len(),
        succeeded,
        failed,
        latency_ms: started.elapsed().as_millis(),
        scheduler: SchedulerInfo {
            requested,
            max_urls_per_request: MAX_URLS_PER_REQUEST,
            concurrency_ceiling: SCHEDULER_CEILING,
            strategy: "bounded async fan-out; fail-safe per-page isolation",
        },
        results,
    })
}

async fn crawl_one(raw: &str, max_text: usize) -> CrawlResponse {
    let started = Instant::now();
    match crawl(raw, max_text).await {
        Ok(mut out) => {
            out.latency_ms = started.elapsed().as_millis();
            out
        }
        Err(e) => failed_response(
            raw.to_string(),
            "CRAWL_FAILED",
            &safe_error(&e),
            is_retryable_error(&e),
        ),
    }
}

fn failed_response(url: String, code: &str, message: &str, retryable: bool) -> CrawlResponse {
    CrawlResponse {
        ok: false,
        url,
        final_url: None,
        title: None,
        description: None,
        language: None,
        content_type: None,
        text: None,
        ai_context: None,
        word_count: 0,
        quality: 0,
        method: "failed-safe".into(),
        latency_ms: 0,
        stages: Stages::default(),
        warnings: Vec::new(),
        error: Some(Failure {
            code: code.into(),
            message: message.into(),
            retryable,
        }),
    }
}

fn json_response<T: Serialize>(
    status: u16,
    value: &T,
) -> Result<Response<ResponseBody>, Error> {
    let status = http::StatusCode::from_u16(status)
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
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
    if raw.len() > MAX_URL_LEN {
        return Err(anyhow!("URL_TOO_LONG"));
    }
    let initial = validate_target(raw).await?;
    stages.validation_ms = validation.elapsed().as_millis();

    let fetch = Instant::now();
    let fetched = fetch_with_safe_redirects(initial).await?;
    stages.fetch_ms = fetch.elapsed().as_millis();
    stages.dns_ms = fetched.dns_ms;
    stages.redirect_ms = fetched.redirect_ms;

    let status = fetched.response.status();
    let final_url = fetched.final_target.url.to_string();
    let ctype = fetched
        .response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(anyhow!("RATE_LIMITED_429"));
    }
    if status == StatusCode::UNAUTHORIZED {
        return Err(anyhow!("AUTHENTICATION_REQUIRED"));
    }
    if status == StatusCode::FORBIDDEN {
        return Err(anyhow!("FORBIDDEN_OR_BOT_PROTECTION"));
    }
    if status.is_client_error() {
        return Err(anyhow!("HTTP_{}", status.as_u16()));
    }
    if status.is_server_error() {
        return Err(anyhow!("UPSTREAM_{}", status.as_u16()));
    }

    let is_html = ctype.contains("text/html")
        || ctype.contains("application/xhtml+xml")
        || ctype.is_empty();
    if !is_html {
        return Err(anyhow!("UNSUPPORTED_CONTENT_TYPE:{}", ctype));
    }

    let declared_len = fetched.response.content_length();
    if declared_len.is_some_and(|n| n > MAX_BYTES as u64) {
        return Err(anyhow!("RESPONSE_TOO_LARGE"));
    }

    let mut stream = fetched.response.bytes_stream();
    let mut bytes = Vec::with_capacity(
        declared_len.unwrap_or(0).min(MAX_BYTES as u64) as usize
    );
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("BODY_READ_FAILED")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(anyhow!("RESPONSE_TOO_LARGE"));
        }
        bytes.extend_from_slice(&chunk);
    }

    let parse = Instant::now();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    let doc = Html::parse_document(&html);
    stages.parse_ms = parse.elapsed().as_millis();

    let extract = Instant::now();
    let extracted = extract_content(&doc, max_text);
    stages.extraction_ms = extract.elapsed().as_millis();

    let title = extracted.0;
    let description = extracted.1;
    let language = extracted.2;
    let text = extracted.3;
    let mut quality = extracted.4;
    warnings.extend(extracted.5);

    let audit = Instant::now();
    let words = text.split_whitespace().count();
    let lower = text.to_ascii_lowercase();

    if words < 30 {
        quality = quality.min(35);
        warnings.push("very_little_meaningful_text".into());
    }
    if lower.contains("enable javascript")
        || lower.contains("checking your browser")
        || lower.contains("verify you are human")
        || lower.contains("just a moment")
    {
        warnings.push("possible_js_or_bot_challenge".into());
        quality = quality.min(25);
    }
    if lower.contains("sign in") && words < 120 {
        warnings.push("possible_auth_wall".into());
        quality = quality.min(45);
    }

    // Static HTML cannot execute JavaScript. If the page exposes useful
    // noscript/SSR/JSON-LD text it is already visible to this extractor;
    // otherwise we report the limitation instead of fabricating rendered text.
    if html_indicates_dynamic_shell(&doc, words) {
        warnings.push("dynamic_shell_detected_static_content_only".into());
    }

    stages.audit_ms = audit.elapsed().as_millis();

    if quality < 40 {
        return Err(anyhow!("LOW_CONFIDENCE_EXTRACTION"));
    }

    let ai_context = format!(
        "SOURCE: {}\nTITLE: {}\nQUALITY: {}/100\n\n{}",
        final_url,
        title.as_deref().unwrap_or("Untitled"),
        quality,
        text
    );

    Ok(CrawlResponse {
        ok: true,
        url: raw.to_string(),
        final_url: Some(final_url),
        title,
        description,
        language,
        content_type: Some(ctype),
        text: Some(text),
        ai_context: Some(ai_context),
        word_count: words,
        quality,
        method: "static-html-fast".into(),
        latency_ms: 0,
        stages,
        warnings,
        error: None,
    })
}

async fn fetch_with_safe_redirects(mut target: SafeTarget) -> Result<FetchResult> {
    let mut visited = HashSet::new();
    let mut redirect_count = 0usize;
    let mut redirect_ms = 0u128;
    let mut dns_ms = 0u128;

    loop {
        if !visited.insert(target.url.to_string()) {
            return Err(anyhow!("REDIRECT_LOOP"));
        }
        if visited.len() > MAX_REDIRECT_TARGETS {
            return Err(anyhow!("REDIRECT_TARGET_LIMIT"));
        }

        let dns = Instant::now();
        target = validate_target(target.url.as_str()).await?;
        dns_ms += dns.elapsed().as_millis();

        let client = build_client_for(&target)?;
        let request = client
            .get(target.url.clone())
            .header(header::USER_AGENT, USER_AGENT)
            .header(
                header::ACCEPT,
                "text/html,application/xhtml+xml;q=0.95,text/plain;q=0.5,*/*;q=0.1",
            )
            .header(header::ACCEPT_LANGUAGE, "en-US,en;q=0.8")
            .header(header::ACCEPT_ENCODING, "gzip, br, deflate, zstd")
            .header("cache-control", "no-cache");

        let redirect_timer = Instant::now();
        let response = request.send().await.context("FETCH_FAILED")?;
        redirect_ms += redirect_timer.elapsed().as_millis();

        if !response.status().is_redirection() {
            return Ok(FetchResult {
                response,
                final_target: target,
                redirect_count,
                redirect_ms,
                dns_ms,
            });
        }

        if redirect_count >= MAX_REDIRECTS {
            return Err(anyhow!("REDIRECT_LIMIT"));
        }

        let location = response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| anyhow!("REDIRECT_WITHOUT_LOCATION"))?
            .to_str()
            .context("BAD_LOCATION")?;

        let next = target.url.join(location).context("INVALID_REDIRECT")?;
        target = validate_target(next.as_str()).await?;
        redirect_count += 1;
    }
}

fn build_client_for(target: &SafeTarget) -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(45))
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(1024 * 1024)
        .http2_initial_connection_window_size(4 * 1024 * 1024)
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .zstd(true)
        .user_agent(USER_AGENT)
        .resolve(
            target.url.host_str().ok_or_else(|| anyhow!("MISSING_HOST"))?,
            SocketAddr::new(
                target.ip,
                target.url.port_or_known_default().unwrap_or(443),
            ),
        )
        .build()?)
}

async fn validate_target(raw: &str) -> Result<SafeTarget> {
    let u = Url::parse(raw).context("INVALID_URL")?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(anyhow!("UNSUPPORTED_SCHEME"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(anyhow!("USERINFO_NOT_ALLOWED"));
    }

    let host = u
        .host_str()
        .ok_or_else(|| anyhow!("MISSING_HOST"))?
        .to_ascii_lowercase();

    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
    {
        return Err(anyhow!("PRIVATE_HOST"));
    }

    let port = u.port_or_known_default().ok_or_else(|| anyhow!("BAD_PORT"))?;
    if port == 0 || port > 65535 {
        return Err(anyhow!("BAD_PORT"));
    }

    let ip = match u.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => {
            let mut addrs = lookup_host((host.as_str(), port))
                .await
                .context("DNS_FAILED")?;
            let mut chosen = None;
            while let Some(sa) = addrs.next() {
                if is_public_ip(sa.ip()) {
                    chosen = Some(sa.ip());
                    break;
                }
            }
            chosen.ok_or_else(|| anyhow!("NO_PUBLIC_IP"))?
        }
    };

    if !is_public_ip(ip) {
        return Err(anyhow!("PRIVATE_OR_RESERVED_IP"));
    }

    Ok(SafeTarget { url: u, ip })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && (18..=19).contains(&o[1]))
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast())
        }
    }
}

fn extract_content(
    doc: &Html,
    max_text: usize,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    u8,
    Vec<String>,
) {
    let mut warnings = Vec::new();

    let title = select_first_text(doc, "title");
    let description = Selector::parse("meta[name='description'],meta[property='og:description']")
        .ok()
        .and_then(|s| doc.select(&s).next())
        .and_then(|n| n.value().attr("content"))
        .map(|s| clean(s.to_string()))
        .filter(|x| !x.is_empty());

    let language = Selector::parse("html")
        .ok()
        .and_then(|s| doc.select(&s).next())
        .and_then(|n| n.value().attr("lang"))
        .map(str::to_string);

    // Candidate scoring is deliberately multi-pass: strong semantic regions
    // first, then useful descendants, while noisy regions are excluded early.
    let selectors = [
        ("article", 42),
        ("main", 38),
        ("[role='main']", 36),
        ("[itemprop='articleBody']", 45),
        (".article-body", 44),
        (".article-content", 42),
        (".post-content", 40),
        (".entry-content", 40),
        ("section", 10),
        ("body", -8),
    ];

    let mut best = String::new();
    let mut best_score = i64::MIN;

    for (selector_text, bonus) in selectors {
        let Ok(selector) = Selector::parse(selector_text) else {
            continue;
        };

        for node in doc.select(&selector).take(MAX_CANDIDATES) {
            let text = visible_text(node, MAX_CHILDREN_SCAN);
            let normalized = clean(text);
            if normalized.len() < 80 {
                continue;
            }
            let score = content_score(node, &normalized, bonus);
            if score > best_score {
                best_score = score;
                best = normalized;
            }
        }
    }

    if best.is_empty() {
        warnings.push("no_strong_content_region".into());
        if let Some(root) = doc.root_element().value().name().is_empty().then_some(()) {
            let _ = root;
        }
        if let Some(body) = Selector::parse("body")
            .ok()
            .and_then(|s| doc.select(&s).next())
        {
            best = clean(visible_text(body, MAX_CHILDREN_SCAN));
        }
    }

    // Preserve the existing output cap so batch responses remain bounded.
    let text = normalize_and_cap(&best, max_text);
    let words = text.split_whitespace().count() as i64;
    let length_score = (words.min(5000) / 25) as i64;
    let raw = best_score.max(0);
    let quality = ((raw + length_score).clamp(0, 100)) as u8;

    if text.len() >= max_text {
        warnings.push("text_cap_reached".into());
    }

    let quality = quality.max(if text.len() > 500 { 70 } else { 30 });
    (title, description, language, text, quality, warnings)
}

fn select_first_text(doc: &Html, selector_text: &str) -> Option<String> {
    Selector::parse(selector_text)
        .ok()
        .and_then(|s| doc.select(&s).next())
        .map(|n| clean(n.text().collect::<Vec<_>>().join(" ")))
        .filter(|x| !x.is_empty())
}

fn visible_text(node: ElementRef<'_>, budget: usize) -> String {
    fn walk(node: ElementRef<'_>, out: &mut String, seen: &mut usize) {
        if *seen >= MAX_CHILDREN_SCAN {
            return;
        }

        let tag = node.value().name();
        if is_noise_tag(tag) || has_noise_class_or_id(&node) {
            return;
        }

        *seen += 1;

        for child in node.children() {
            if *seen >= MAX_CHILDREN_SCAN {
                break;
            }

            if let Some(el) = ElementRef::wrap(child) {
                walk(el, out, seen);
            } else if let Some(text) = child.value().as_text() {
                out.push(' ');
                out.push_str(text);
            }
        }
    }

    let mut out = String::with_capacity(budget.min(128 * 1024));
    let mut seen = 0usize;
    walk(node, &mut out, &mut seen);
    if out.len() > budget {
        out.truncate(budget);
    }
    out
}

fn is_noise_tag(tag: &str) -> bool {
    matches!(
        tag,
        "script"
            | "style"
            | "noscript"
            | "template"
            | "svg"
            | "canvas"
            | "iframe"
            | "object"
            | "embed"
            | "form"
            | "nav"
            | "footer"
    )
}

fn has_noise_class_or_id(node: &ElementRef<'_>) -> bool {
    let v = node.value();
    let attrs = format!(
        "{} {}",
        v.id().unwrap_or(""),
        v.attr("class").unwrap_or("")
    )
    .to_ascii_lowercase();

    const BAD: [&str; 15] = [
        "cookie",
        "consent",
        "advert",
        "ads-",
        "sponsor",
        "newsletter",
        "social",
        "sidebar",
        "breadcrumb",
        "share",
        "popup",
        "modal",
        "login",
        "signup",
        "paywall",
    ];

    BAD.iter().any(|x| attrs.contains(x))
}

fn content_score(node: ElementRef<'_>, text: &str, bonus: i32) -> i64 {
    let value = node.value();
    let attrs = format!(
        "{} {}",
        value.id().unwrap_or(""),
        value.attr("class").unwrap_or("")
    )
    .to_ascii_lowercase();

    let words = text.split_whitespace().count() as i64;
    let links = Selector::parse("a")
        .ok()
        .map(|s| node.select(&s).count() as i64)
        .unwrap_or(0);
    let paragraphs = Selector::parse("p")
        .ok()
        .map(|s| node.select(&s).count() as i64)
        .unwrap_or(0);
    let headings = Selector::parse("h1,h2,h3,h4")
        .ok()
        .map(|s| node.select(&s).count() as i64)
        .unwrap_or(0);

    let bad = [
        "nav",
        "menu",
        "footer",
        "sidebar",
        "cookie",
        "consent",
        "advert",
        "sponsor",
        "newsletter",
        "social",
        "login",
        "signup",
        "breadcrumb",
        "share",
    ];
    let penalty = bad.iter().filter(|x| attrs.contains(**x)).count() as i64 * 20;
    let link_penalty = if words > 0 {
        ((links * 100) / words).min(55)
    } else {
        55
    };

    (words.min(12000) / 20)
        + paragraphs.min(100) * 3
        + headings.min(20) * 4
        + bonus as i64
        - penalty
        - link_penalty
}

fn html_indicates_dynamic_shell(doc: &Html, words: usize) -> bool {
    if words > 80 {
        return false;
    }

    let selectors = [
        "[id*='root']",
        "[id*='app']",
        "[id*='__next']",
        "[id*='svelte']",
        "script[type='application/ld+json']",
    ];

    selectors.iter().any(|s| {
        Selector::parse(s)
            .ok()
            .is_some_and(|sel| doc.select(&sel).next().is_some())
    })
}

fn normalize_and_cap(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    let mut last_space = false;

    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }

        if out.len() >= max {
            break;
        }
    }

    out.trim().to_string()
}

fn clean(s: String) -> String {
    normalize_and_cap(&s, MAX_TEXT)
}

fn is_retryable_error(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    s.contains("FETCH_FAILED")
        || s.contains("DNS_FAILED")
        || s.contains("BODY_READ_FAILED")
        || s.contains("UPSTREAM_")
        || s.contains("RATE_LIMITED")
}

fn safe_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    if s.len() > 180 {
        s[..180].to_string()
    } else {
        s
    }
}
