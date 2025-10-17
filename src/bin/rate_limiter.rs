// Rate limiting proxy - Limits requests per IP address
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::prelude::*;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limiting configuration
#[derive(Clone)]
pub struct RateLimit {
    requests_per_minute: u32,
    window_duration: Duration,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            requests_per_minute: 10,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Request count tracking
#[derive(Debug, Clone)]
struct RequestCount {
    count: u32,
    window_start: Instant,
}

/// Context for rate limiting
pub struct RateLimitCtx {
    client_ip: Option<IpAddr>,
    allowed: bool,
}

/// Rate limiting proxy service
pub struct RateLimitProxy {
    // In-memory store for request counts per IP
    request_counts: Arc<DashMap<IpAddr, RequestCount>>,
    rate_limit: RateLimit,
    backend: String,
}

impl RateLimitProxy {
    pub fn new(backend: String) -> Self {
        Self {
            request_counts: Arc::new(DashMap::new()),
            rate_limit: RateLimit::default(),
            backend,
        }
    }
    
    pub fn with_rate_limit(mut self, requests_per_minute: u32, window_seconds: u64) -> Self {
        self.rate_limit = RateLimit {
            requests_per_minute,
            window_duration: Duration::from_secs(window_seconds),
        };
        self
    }
    
    fn get_client_ip(&self, session: &Session) -> Option<IpAddr> {
        // Try to get real IP from headers first (for reverse proxies)
        if let Some(forwarded_for) = session.req_header().headers.get("X-Forwarded-For") {
            if let Ok(ip_str) = std::str::from_utf8(forwarded_for.as_bytes()) {
                if let Some(first_ip) = ip_str.split(',').next() {
                    if let Ok(ip) = IpAddr::from_str(first_ip.trim()) {
                        return Some(ip);
                    }
                }
            }
        }
        
        // For demo purposes, use a default IP when real IP extraction is complex
        // In production, you'd implement proper socket address parsing
        Some(IpAddr::from_str("127.0.0.1").unwrap())
    }
    
    fn is_rate_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        
        // Get or create entry for this IP
        let mut entry = self.request_counts.entry(ip).or_insert_with(|| RequestCount {
            count: 0,
            window_start: now,
        });
        
        // Check if we need to reset the window
        if now.duration_since(entry.window_start) >= self.rate_limit.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }
        
        // Increment counter and check limit
        entry.count += 1;
        
        let exceeded = entry.count > self.rate_limit.requests_per_minute;
        
        if exceeded {
            println!("🚫 Rate limit exceeded for {}: {}/{} requests", 
                    ip, entry.count, self.rate_limit.requests_per_minute);
        } else {
            println!("✅ Request allowed for {}: {}/{} requests", 
                    ip, entry.count, self.rate_limit.requests_per_minute);
        }
        
        exceeded
    }
    
    // Cleanup old entries (should be called periodically)
    pub fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let cleanup_threshold = self.rate_limit.window_duration * 2;
        
        self.request_counts.retain(|_ip, entry| {
            now.duration_since(entry.window_start) < cleanup_threshold
        });
    }
}

#[async_trait]
impl ProxyHttp for RateLimitProxy {
    type CTX = RateLimitCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        RateLimitCtx {
            client_ip: None,
            allowed: false,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        let client_ip = self.get_client_ip(session);
        ctx.client_ip = client_ip;
        
        if let Some(ip) = client_ip {
            if self.is_rate_limited(ip) {
                // Return rate limit error
                let mut resp = pingora::http::ResponseHeader::build(429, None)?;
                resp.insert_header("Content-Type", "application/json")?;
                resp.insert_header("X-Rate-Limit-Exceeded", "true")?;
                resp.insert_header("Retry-After", "60")?;
                
                let body = serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": format!("Too many requests from {}. Limit: {} requests per {} seconds", 
                                     ip, 
                                     self.rate_limit.requests_per_minute,
                                     self.rate_limit.window_duration.as_secs()),
                    "retry_after": 60
                });
                
                session.set_keepalive(None);
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(body.to_string().into()), true).await?;
                
                ctx.allowed = false;
                return Ok(false); // Don't continue to upstream
            }
        }
        
        ctx.allowed = true;
        Ok(true) // Continue to upstream
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        if !ctx.allowed {
            return Err(pingora::Error::new_str("Request not allowed").into());
        }
        
        let peer = Box::new(HttpPeer::new(&self.backend, false, "".to_string()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // Add rate limiting headers
        upstream_request.insert_header("X-Rate-Limited", "false")?;
        
        if let Some(ip) = ctx.client_ip {
            upstream_request.insert_header("X-Client-IP", &ip.to_string())?;
            
            // Add current rate limit status
            if let Some(entry) = self.request_counts.get(&ip) {
                upstream_request.insert_header("X-Current-Requests", &entry.count.to_string())?;
                upstream_request.insert_header("X-Rate-Limit", &self.rate_limit.requests_per_minute.to_string())?;
            }
        }
        
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // Add rate limiting info to response headers
        upstream_response.insert_header("X-Rate-Limiter", "pingora-rate-limiter")?;
        upstream_response.insert_header("X-Rate-Limit", &self.rate_limit.requests_per_minute.to_string())?;
        upstream_response.insert_header("X-Rate-Window", &self.rate_limit.window_duration.as_secs().to_string())?;
        
        if let Some(ip) = ctx.client_ip {
            if let Some(entry) = self.request_counts.get(&ip) {
                let remaining = self.rate_limit.requests_per_minute.saturating_sub(entry.count);
                upstream_response.insert_header("X-Rate-Limit-Remaining", &remaining.to_string())?;
            }
        }
        
        println!("📥 Response sent to {:?}", ctx.client_ip);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Starting Pingora Rate Limiting Proxy...");
    println!("⚡ Rate Limit: 10 requests per 60 seconds per IP");
    
    // Create rate limiting proxy
    let rate_limiter = RateLimitProxy::new("httpbin.org:80".to_string())
        .with_rate_limit(10, 60); // 10 requests per 60 seconds
    
    // Spawn cleanup task
    let cleanup_store = rate_limiter.request_counts.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        loop {
            interval.tick().await;
            let now = Instant::now();
            cleanup_store.retain(|_ip, entry| {
                now.duration_since(entry.window_start) < Duration::from_secs(300)
            });
            println!("🧹 Cleaned up old rate limit entries");
        }
    });
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), rate_limiter);
    proxy.add_tcp("127.0.0.1:6190");
    
    println!("🌐 Rate limiter listening on http://127.0.0.1:6190");
    println!("✨ Try these commands:");
    println!("   # Test normal requests");
    println!("   curl http://127.0.0.1:6190/get");
    println!("   # Test rate limiting (run quickly)");
    println!("   for i in {{1..15}}; do curl -w \"Status: %{{response_code}}\\n\" http://127.0.0.1:6190/get; done");
    println!("   # Check rate limit headers");
    println!("   curl -v http://127.0.0.1:6190/get 2>&1 | grep 'X-Rate'");
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}