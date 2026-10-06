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

// IMPORTANT: these are safety bounds, not text-extraction truncation limits.
// The extractor reads the entire response up to MAX_HTML_BYTES, then walks the
// entire DOM without a MAX_TEXT/character cutoff.
const MAX_REDIRECTS: usize = 8;
const MAX_HTML_BYTES: usize = 64 * 1024 * 1024;
const MAX_URL_LEN: usize = 4096;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_URLS_PER_REQUEST: usize = 100;
const SCHEDULER_CEILING: usize = 2000;
const FETCH_TIMEOUT_SECS: u64 = 14;
const CONNECT_TIMEOUT_SECS: u64 = 4;
const USER_AGENT: &str = "ArixAI-WebIntelligence/3.0-Full";

// Per-process gate. The HTTP request itself is still capped at 40 URLs, but
// the scheduler can safely accommodate many callers without a hard-coded
// 16-request bottleneck from the earlier version.
static GLOBAL_GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct CrawlRequest {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default)]
    max_text: Option<usize>,
    #[serde(default)]
    include_ai_context: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_context: Option<String>,
    word_count: usize,
    character_count: usize,
    source_html_bytes: usize,
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
    read_ms: u128,
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

#[derive(Debug, Default)]
struct ExtractionStats {
    emitted_blocks: usize,
    emitted_words: usize,
    skipped_noise_nodes: usize,
    hidden_nodes: usize,
    paragraphs: usize,
    headings: usize,
    links: usize,
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
            .body(ResponseBody::from(Vec::new()))?);
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

    let mut urls = Vec::new();
    for entry in input.urls.unwrap_or_default() {
        split_url_field(&entry, &mut urls);
    }
    if let Some(u) = input.url {
        split_url_field(&u, &mut urls);
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

    // max_text is now optional rather than a hidden default truncation. If a
    // caller explicitly asks for a cap, honor it. Otherwise extraction is full.
    let max_text = input.max_text;
    let include_ai_context = input.include_ai_context;
    let requested = normalized.len();

    let gate = GLOBAL_GATE
        .get_or_init(|| Arc::new(Semaphore::new(SCHEDULER_CEILING)))
        .clone();

    eprintln!(
        "{{\"event\":\"batch_start\",\"requested\":{},\"ceiling\":{},\"elapsed_ms\":{}}}",
        requested,
        SCHEDULER_CEILING,
        started.elapsed().as_millis()
    );

    let concurrency = requested.min(SCHEDULER_CEILING).max(1);
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
            crawl_one(&u, max_text, include_ai_context).await
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;

    let succeeded = results.iter().filter(|r| r.ok).count();
    let failed = results.len().saturating_sub(succeeded);

    eprintln!(
        "{{\"event\":\"batch_end\",\"requested\":{},\"succeeded\":{},\"failed\":{},\"latency_ms\":{}}}",
        requested,
        succeeded,
        failed,
        started.elapsed().as_millis()
    );

    json_response(
        200,
        &BatchResponse {
            ok: failed == 0,
            count: results.len(),
            succeeded,
            failed,
            latency_ms: started.elapsed().as_millis(),
            scheduler: SchedulerInfo {
                requested,
                max_urls_per_request: MAX_URLS_PER_REQUEST,
                concurrency_ceiling: SCHEDULER_CEILING,
                strategy: "parallel async fan-out with per-page isolation",
            },
            results,
        },
    )
}

async fn crawl_one(raw: &str, max_text: Option<usize>, include_ai_context: bool) -> CrawlResponse {
    let started = Instant::now();
    match crawl(raw, max_text, include_ai_context).await {
        Ok(mut out) => {
            out.latency_ms = started.elapsed().as_millis();
            eprintln!(
                "{{\"event\":\"page_complete\",\"url\":{},\"ok\":true,\"latency_ms\":{},\"fetch_ms\":{},\"read_ms\":{},\"parse_ms\":{},\"extraction_ms\":{},\"quality\":{},\"characters\":{},\"words\":{},\"source_html_bytes\":{}}}",
                serde_json::to_string(raw).unwrap_or_else(|_| "\"?\"".into()),
                out.latency_ms,
                out.stages.fetch_ms,
                out.stages.read_ms,
                out.stages.parse_ms,
                out.stages.extraction_ms,
                out.quality,
                out.character_count,
                out.word_count,
                out.source_html_bytes
            );
            out
        }
        Err(e) => {
            let retryable = is_retryable_error(&e);
            let message = safe_error(&e);
            eprintln!(
                "{{\"event\":\"page_complete\",\"url\":{},\"ok\":false,\"latency_ms\":{},\"error\":{}}}",
                serde_json::to_string(raw).unwrap_or_else(|_| "\"?\"".into()),
                started.elapsed().as_millis(),
                serde_json::to_string(&message).unwrap_or_else(|_| "\"CRAWL_FAILED\"".into())
            );
            failed_response_with_latency(raw.to_string(), "CRAWL_FAILED", &message, retryable, started.elapsed().as_millis())
        }
    }
}

fn failed_response(url: String, code: &str, message: &str, retryable: bool) -> CrawlResponse {
    failed_response_with_latency(url, code, message, retryable, 0)
}

fn failed_response_with_latency(
    url: String,
    code: &str,
    message: &str,
    retryable: bool,
    latency_ms: u128,
) -> CrawlResponse {
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
        character_count: 0,
        source_html_bytes: 0,
        quality: 0,
        method: "failed-safe".into(),
        latency_ms,
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

async fn crawl(raw: &str, max_text: Option<usize>, include_ai_context: bool) -> Result<CrawlResponse> {
    let total = Instant::now();
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

    // Keep text-like HTML/XHTML pages on the fast static path. A missing
    // Content-Type is allowed because many public pages misconfigure it.
    let is_html = ctype.contains("text/html")
        || ctype.contains("application/xhtml+xml")
        || ctype.is_empty();
    if !is_html {
        return Err(anyhow!("UNSUPPORTED_CONTENT_TYPE:{}", ctype));
    }

    let declared_len = fetched.response.content_length();
    if declared_len.is_some_and(|n| n > MAX_HTML_BYTES as u64) {
        return Err(anyhow!("RESPONSE_TOO_LARGE"));
    }

    let read = Instant::now();
    let mut body_stream = fetched.response.bytes_stream();
    let mut bytes = Vec::with_capacity(
        declared_len.unwrap_or(0).min(MAX_HTML_BYTES as u64) as usize,
    );
    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.context("BODY_READ_FAILED")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_HTML_BYTES {
            return Err(anyhow!("RESPONSE_TOO_LARGE"));
        }
        bytes.extend_from_slice(&chunk);
    }
    stages.read_ms = read.elapsed().as_millis();

    let parse = Instant::now();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    let doc = Html::parse_document(&html);
    stages.parse_ms = parse.elapsed().as_millis();

    let extract = Instant::now();
    let (title, description, language, mut text, stats, extra_warnings) = extract_full_document(&doc);
    stages.extraction_ms = extract.elapsed().as_millis();
    warnings.extend(extra_warnings);

    // A requested cap is explicit caller behavior, never an implicit crawler
    // limit. The boundary is applied only here, after complete extraction.
    if let Some(cap) = max_text {
        let cap = cap.max(1000);
        if text.len() > cap {
            text = truncate_utf8_safely(&text, cap);
            warnings.push("explicit_max_text_cap_applied".into());
        }
    }

    // Fail-safe fallback: if our noise-aware walk unexpectedly finds very
    // little useful text on a page whose body clearly contains lots of text,
    // do one complete raw-visible-text walk instead of returning a half page.
    let filtered_words = text.split_whitespace().count();
    if filtered_words < 80 && stats.emitted_words > filtered_words.saturating_mul(3) {
        let fallback = extract_raw_visible_document(&doc);
        if fallback.len() > text.len() {
            text = fallback;
            warnings.push("noise_filter_fallback_to_full_visible_text".into());
        }
    }

    let audit = Instant::now();
    let words = text.split_whitespace().count();
    let lower = text.to_ascii_lowercase();
    let mut quality = quality_score(words, &stats, text.len());

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
    if html_indicates_dynamic_shell(&doc, words) {
        warnings.push("dynamic_shell_detected_static_content_only".into());
    }

    stages.audit_ms = audit.elapsed().as_millis();

    // Unlike the previous implementation, low quality does not destroy a
    // complete extraction. The response carries the text plus warnings so the
    // caller can decide whether the page was blocked/dynamic instead of losing
    // the useful portion of the page.
    if quality < 40 {
        warnings.push("low_confidence_but_content_preserved".into());
    }

    let ai_context = include_ai_context.then(|| {
        format!(
            "SOURCE: {}\nTITLE: {}\nQUALITY: {}/100\n\n{}",
            final_url,
            title.as_deref().unwrap_or("Untitled"),
            quality,
            text
        )
    });

    let character_count = text.chars().count();
    let total_ms = total.elapsed().as_millis();
    eprintln!(
        "{{\"event\":\"page_audit\",\"url\":{},\"total_ms\":{},\"characters\":{},\"words\":{},\"quality\":{},\"nodes_skipped\":{},\"hidden_nodes\":{},\"paragraphs\":{},\"headings\":{},\"links\":{}}}",
        serde_json::to_string(&final_url).unwrap_or_else(|_| "\"?\"".into()),
        total_ms,
        character_count,
        words,
        quality,
        stats.skipped_noise_nodes,
        stats.hidden_nodes,
        stats.paragraphs,
        stats.headings,
        stats.links
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
        ai_context,
        word_count: words,
        character_count,
        source_html_bytes: bytes.len(),
        quality,
        method: "full-static-dom-fast".into(),
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

        let dns = Instant::now();
        target = validate_target(target.url.as_str()).await?;
        dns_ms += dns.elapsed().as_millis();

        let client = build_client_for(&target)?;
        let request = client
            .get(target.url.clone())
            .header(header::USER_AGENT, USER_AGENT)
            .header(
                header::ACCEPT,
                "text/html,application/xhtml+xml;q=0.98,text/plain;q=0.6,*/*;q=0.1",
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

fn split_url_field(value: &str, out: &mut Vec<String>) {
    // The UI/API accepts URLs separated by spaces, commas, or newlines.
    // Public HTTP URLs cannot contain raw spaces, so this is unambiguous for
    // the intended input format.
    for token in value.split(|c: char| c == ',' || c == '\n' || c == '\r' || c.is_whitespace()) {
        let token = token.trim();
        if !token.is_empty() {
            out.push(token.to_string());
        }
    }
}

fn extract_full_document(
    doc: &Html,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    ExtractionStats,
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

    let root = Selector::parse("body")
        .ok()
        .and_then(|s| doc.select(&s).next())
        .or_else(|| Some(doc.root_element()));

    let mut out = String::new();
    let mut stats = ExtractionStats::default();

    if let Some(root) = root {
        walk_complete(root, &mut out, &mut stats);
    }

    let text = normalize_document_text(&out);
    if text.is_empty() {
        warnings.push("no_visible_text_found".into());
    }
    if stats.skipped_noise_nodes > 0 {
        warnings.push(format!(
            "filtered_{}_obvious_noise_nodes",
            stats.skipped_noise_nodes
        ));
    }
    if stats.hidden_nodes > 0 {
        warnings.push(format!(
            "ignored_{}_hidden_or_aria_hidden_nodes",
            stats.hidden_nodes
        ));
    }

    (title, description, language, text, stats, warnings)
}

fn walk_complete(node: ElementRef<'_>, out: &mut String, stats: &mut ExtractionStats) {
    let value = node.value();
    let tag = value.name();

    if should_skip_entire_node(&node) {
        stats.skipped_noise_nodes = stats.skipped_noise_nodes.saturating_add(1);
        return;
    }
    if is_hidden_element(&node) {
        stats.hidden_nodes = stats.hidden_nodes.saturating_add(1);
        return;
    }

    let is_block = is_block_tag(tag);
    if is_block && !out.is_empty() {
        out.push_str("\n\n");
    }

    match tag {
        "p" => stats.paragraphs = stats.paragraphs.saturating_add(1),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            stats.headings = stats.headings.saturating_add(1)
        }
        "a" => stats.links = stats.links.saturating_add(1),
        _ => {}
    }

    let mut had_text = false;
    for child in node.children() {
        if let Some(el) = ElementRef::wrap(child) {
            walk_complete(el, out, stats);
        } else if let Some(text) = child.value().as_text() {
            let t = text.trim();
            if !t.is_empty() {
                if !out.is_empty() && !ends_with_separator(out) {
                    out.push(' ');
                }
                out.push_str(t);
                stats.emitted_words = stats
                    .emitted_words
                    .saturating_add(t.split_whitespace().count());
                had_text = true;
            }
        }
    }

    if is_block && (had_text || ends_with_non_separator(out)) {
        out.push_str("\n\n");
        stats.emitted_blocks = stats.emitted_blocks.saturating_add(1);
    }
}

fn extract_raw_visible_document(doc: &Html) -> String {
    let root = Selector::parse("body")
        .ok()
        .and_then(|s| doc.select(&s).next())
        .or_else(|| Some(doc.root_element()));
    let Some(root) = root else {
        return String::new();
    };

    let mut out = String::new();
    walk_raw(root, &mut out);
    normalize_document_text(&out)
}

fn walk_raw(node: ElementRef<'_>, out: &mut String) {
    let tag = node.value().name();
    if matches!(tag, "script" | "style" | "template" | "svg" | "canvas" | "iframe" | "object" | "embed" | "form") {
        return;
    }
    if is_hidden_element(&node) {
        return;
    }

    if is_block_tag(tag) && !out.is_empty() {
        out.push_str("\n\n");
    }

    for child in node.children() {
        if let Some(el) = ElementRef::wrap(child) {
            walk_raw(el, out);
        } else if let Some(text) = child.value().as_text() {
            let t = text.trim();
            if !t.is_empty() {
                if !out.is_empty() && !ends_with_separator(out) {
                    out.push(' ');
                }
                out.push_str(t);
            }
        }
    }
}

fn should_skip_entire_node(node: &ElementRef<'_>) -> bool {
    let tag = node.value().name();
    if matches!(tag, "script" | "style" | "template" | "svg" | "canvas" | "iframe" | "object" | "embed" | "form" | "nav" | "footer") {
        return true;
    }

    let attrs = format!(
        "{} {}",
        node.value().id().unwrap_or(""),
        node.value().attr("class").unwrap_or("")
    )
    .to_ascii_lowercase();

    const STRONG_NOISE: [&str; 18] = [
        "cookie-banner",
        "cookie-consent",
        "consent-banner",
        "consent-manager",
        "advertisement",
        "ad-container",
        "ad-slot",
        "adsbygoogle",
        "sponsored-content",
        "newsletter-signup",
        "newsletter-form",
        "social-share",
        "share-tools",
        "breadcrumb",
        "login-modal",
        "signup-modal",
        "paywall",
        "modal-overlay",
    ];

    STRONG_NOISE.iter().any(|marker| attrs.contains(marker))
}

fn is_hidden_element(node: &ElementRef<'_>) -> bool {
    let v = node.value();
    if v.attr("aria-hidden") == Some("true") {
        return true;
    }
    let style = v.attr("style").unwrap_or("").to_ascii_lowercase();
    style.contains("display:none")
        || style.contains("display: none")
        || style.contains("visibility:hidden")
        || style.contains("visibility: hidden")
        || style.contains("content-visibility:hidden")
        || style.contains("content-visibility: hidden")
}

fn is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "caption"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tbody"
            | "td"
            | "tfoot"
            | "th"
            | "thead"
            | "tr"
            | "ul"
            | "details"
            | "summary"
    )
}

fn select_first_text(doc: &Html, selector_text: &str) -> Option<String> {
    Selector::parse(selector_text)
        .ok()
        .and_then(|s| doc.select(&s).next())
        .map(|n| clean(n.text().collect::<Vec<_>>().join(" ")))
        .filter(|x| !x.is_empty())
}

fn quality_score(words: usize, stats: &ExtractionStats, chars: usize) -> u8 {
    if words == 0 {
        return 0;
    }

    let mut score = 45i64;
    score += (words.min(12000) / 120) as i64;
    score += (stats.paragraphs.min(80) / 4) as i64;
    score += stats.headings.min(12) as i64 * 2;
    if chars > 1000 {
        score += 10;
    }
    if chars > 10000 {
        score += 10;
    }
    score.clamp(0, 100) as u8
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

fn normalize_document_text(s: &str) -> String {
    // Keep paragraph/block boundaries produced by the DOM walk while
    // collapsing incidental HTML whitespace. No character/word ceiling is
    // applied here.
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    let mut pending_breaks = 0usize;

    for ch in s.chars() {
        if ch == '\n' || ch == '\r' {
            pending_breaks = (pending_breaks + 1).min(2);
            pending_space = false;
            continue;
        }

        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }

        if pending_breaks > 0 {
            while out.ends_with(' ') {
                out.pop();
            }
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            pending_breaks = 0;
            pending_space = false;
        } else if pending_space && !out.is_empty() && !out.ends_with(' ') && !out.ends_with('\n') {
            out.push(' ');
            pending_space = false;
        }

        out.push(ch);
    }

    out.trim().to_string()
}

fn ends_with_separator(s: &str) -> bool {
    s.as_bytes().last().is_some_and(|b| *b == b' ' || *b == b'\n' || *b == b'\r' || *b == b'\t')
}

fn ends_with_non_separator(s: &str) -> bool {
    !s.is_empty() && !ends_with_separator(s)
}

fn truncate_utf8_safely(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn clean(s: String) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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
