use async_trait::async_trait;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::prelude::*;
use std::env;

/// Simple proxy context
pub struct CorsCtx;

/// CORS Proxy service that handles Cross-Origin Resource Sharing
pub struct CorsProxy {
    upstream_addr: String,
    allowed_origin: Option<String>,
    use_tls: bool,
}

impl CorsProxy {
    pub fn new() -> anyhow::Result<Self> {
        // Read configuration from environment variables
        let upstream_addr = env::var("UPSTREAM_ADDR")
            .unwrap_or_else(|_| "httpbin.org:80".to_string());
        
        let allowed_origin = env::var("ALLOWED_ORIGIN").ok();
        
        // Determine if we should use TLS
        let use_tls = Self::determine_tls_usage(&upstream_addr);
        
        println!("🔧 CORS Proxy Configuration:");
        println!("   Upstream: {}", upstream_addr);
        println!("   Use TLS: {}", use_tls);
        println!("   Allowed Origin: {:?}", allowed_origin);
        
        Ok(Self {
            upstream_addr,
            allowed_origin,
            use_tls,
        })
    }
    
    /// Determine if TLS should be used based on upstream address and environment
    fn determine_tls_usage(upstream_addr: &str) -> bool {
        // Check explicit TLS configuration first
        if let Ok(tls_env) = env::var("UPSTREAM_TLS") {
            return tls_env.to_lowercase() == "true" || tls_env == "1";
        }
        
        // Auto-detect based on port (common HTTPS ports)
        if upstream_addr.ends_with(":443") || 
           upstream_addr.ends_with(":8443") || 
           upstream_addr.ends_with(":9443") {
            return true;
        }
        
        // Check if address suggests HTTPS (contains common HTTPS indicators)
        if upstream_addr.contains("https") {
            return true;
        }
        
        false
    }
    
    /// Get TLS configuration for this proxy
    fn should_use_tls(&self) -> bool {
        self.use_tls
    }
    
    /// Extract hostname from upstream address for SNI
    fn extract_hostname(&self) -> String {
        // Handle different address formats:
        // - hostname:port (e.g., api.github.com:443)
        // - hostname (e.g., api.github.com)
        // - ip:port (e.g., 192.168.1.1:443)
        
        let addr = &self.upstream_addr;
        
        // Split by colon to separate hostname from port
        if let Some(colon_pos) = addr.rfind(':') {
            let hostname = &addr[..colon_pos];
            // Check if it's an IPv4 address (contains only digits and dots)
            if hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
                // For IP addresses, don't use SNI
                return "".to_string();
            }
            hostname.to_string()
        } else {
            // No port specified, use the whole address as hostname
            // unless it looks like an IP address
            if addr.chars().all(|c| c.is_ascii_digit() || c == '.') {
                "".to_string()
            } else {
                addr.to_string()
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for CorsProxy {
    type CTX = CorsCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        CorsCtx
    }

    /// Select upstream peer for each request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        // Check if upstream should use TLS based on address format or explicit config
        let use_tls = self.should_use_tls();
        
        // Extract hostname from upstream address for SNI
        let sni_hostname = self.extract_hostname();
        
        println!("🔧 Creating peer for {} (TLS: {}, SNI: {})", 
            self.upstream_addr, use_tls, &sni_hostname);
        
        let mut peer = HttpPeer::new(
            &self.upstream_addr,
            use_tls,
            sni_hostname.clone()
        );
        
        // Configure TLS options for HTTPS connections
        if use_tls {
            // Minimal TLS configuration - let Pingora handle most of it
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
            
            // Try shorter timeouts in case that's the issue
            peer.options.connection_timeout = Some(std::time::Duration::from_secs(5));
            peer.options.total_connection_timeout = Some(std::time::Duration::from_secs(10));
            
            // Keep it simple - just disable cert verification
            
            println!("🔒 TLS peer configured - cert_verify: {}, hostname_verify: {}, timeout: {:?}", 
                peer.options.verify_cert, peer.options.verify_hostname, peer.options.connection_timeout);
        }
        
        println!("🔗 Peer created successfully for upstream: {}", self.upstream_addr);
            
        Ok(Box::new(peer))
    }
    

    /// Modify request before sending to upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        // Add proxy identification headers
        upstream_request.insert_header("x-proxy-added", "cors-proxy")?;
        
        // Ensure proper Host header for upstream
        let hostname = self.extract_hostname();
        if !hostname.is_empty() {
            upstream_request.insert_header("host", &hostname)?;
        }
        
        println!("📤 Proxying {} {} to {} (Host: {}) with Origin: {:?}", 
            session.req_header().method, 
            session.req_header().uri,
            self.upstream_addr,
            hostname,
            session.req_header().headers.get("origin")
        );
        
        Ok(())
    }
    

    /// Modify response before sending to client - this is where CORS magic happens
    async fn response_filter(
        &self, 
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        // Step 1: Clean existing Access-Control-Allow-Origin response header
        upstream_response.remove_header("access-control-allow-origin");
        
        // Step 2: Check if request has origin header and if it matches our allowed origin
        if let Some(request_origin) = session.req_header().headers.get("origin") {
            if let Some(allowed_origin) = &self.allowed_origin {
                // Convert header value to string for comparison
                if let Ok(origin_str) = request_origin.to_str() {
                    if origin_str == allowed_origin {
                        // Origin matches - set it as Access-Control-Allow-Origin
                        upstream_response.insert_header("access-control-allow-origin", origin_str)?;
                        println!("✅ CORS: Origin {} allowed", origin_str);
                    } else {
                        println!("❌ CORS: Origin {} not allowed (expected: {})", origin_str, allowed_origin);
                    }
                }
            }
        }
        
        // Add proxy identification
        upstream_response.insert_header("x-cors-proxy", "rust-pingora")?;
        
        println!("📤 Response status: {} with CORS headers applied", upstream_response.status);
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    println!("🚀 Starting CORS Proxy Server...");
    
    // Create CORS proxy service
    let cors_proxy = CorsProxy::new()?;
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), cors_proxy);
    
    // Get port from environment or use default
    let port = env::var("PROXY_PORT").unwrap_or_else(|_| "6189".to_string());
    let bind_addr = format!("127.0.0.1:{}", port);
    
    proxy.add_tcp(&bind_addr);
    
    println!("🌐 CORS Proxy listening on http://{}", bind_addr);
    println!("✨ Environment variables:");
    println!("   UPSTREAM_ADDR - Target service address (default: httpbin.org:80)");
    println!("   UPSTREAM_TLS - Force TLS usage (true/false, auto-detected if not set)");
    println!("   ALLOWED_ORIGIN - Origin to allow CORS for (e.g., https://example.com)");
    println!("   PROXY_PORT - Port to listen on (default: 6189)");
    println!();
    println!("📝 Example usage:");
    println!("   # HTTP upstream");
    println!("   UPSTREAM_ADDR=httpbin.org:80 ALLOWED_ORIGIN=https://example.com cargo run --bin cors-proxy");
    println!("   # HTTPS upstream (auto-detected by port 443)");
    println!("   UPSTREAM_ADDR=api.github.com:443 ALLOWED_ORIGIN=https://example.com cargo run --bin cors-proxy");
    println!("   # HTTPS upstream (explicit TLS)");
    println!("   UPSTREAM_ADDR=secure-api.com:8080 UPSTREAM_TLS=true ALLOWED_ORIGIN=https://example.com cargo run --bin cors-proxy");
    println!();
    println!("🔒 TLS Auto-detection:");
    println!("   - Ports 443, 8443, 9443 automatically use TLS");
    println!("   - Addresses containing 'https' use TLS");
    println!("   - Override with UPSTREAM_TLS=true/false");
    println!();
    println!("🧪 Test commands:");
    println!("   # Request without origin header");
    println!("   curl -v http://{}/get", bind_addr);
    println!("   # Request with allowed origin");
    println!("   curl -v -H 'Origin: https://example.com' http://{}/get", bind_addr);
    println!("   # Request with disallowed origin");
    println!("   curl -v -H 'Origin: https://malicious.com' http://{}/get", bind_addr);
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}