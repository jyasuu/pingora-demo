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
    use_tls: bool,
    allowed_headers: String,
    allow_any_headers: bool,
}

impl CorsProxy {
    pub fn new() -> anyhow::Result<Self> {
        // Read configuration from environment variables
        let upstream_addr = env::var("UPSTREAM_ADDR")
            .unwrap_or_else(|_| "httpbin.org:80".to_string());
        
        // Determine if we should use TLS
        let use_tls = Self::determine_tls_usage(&upstream_addr);
        
        // Configure CORS headers policy
        let (allowed_headers, allow_any_headers) = Self::configure_cors_headers();
        
        println!("🔧 CORS Proxy Configuration:");
        println!("   Upstream: {}", upstream_addr);
        println!("   Use TLS: {}", use_tls);
        println!("   CORS Policy: Allow all origins (*)");
        println!("   Allowed Headers: {}", if allow_any_headers { "*" } else { &allowed_headers });
        
        Ok(Self {
            upstream_addr,
            use_tls,
            allowed_headers,
            allow_any_headers,
        })
    }
    
    /// Configure CORS headers policy based on environment variables
    fn configure_cors_headers() -> (String, bool) {
        // Check if we should allow any headers (wildcard)
        let allow_any = env::var("CORS_ALLOW_ANY_HEADERS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        if allow_any {
            return ("*".to_string(), true);
        }
        
        // Get custom headers from environment, or use comprehensive defaults
        let default_headers = vec![
            // Standard headers
            "origin", "content-type", "accept", "authorization", "x-requested-with",
            // MCP specific headers (fixes the TODO.md issue)
            "mcp-session-id", "mcp-client-version", "mcp-protocol-version",
            // Common custom headers
            "x-api-key", "x-client-id", "x-session-id", "x-correlation-id",
            "x-request-id", "x-trace-id", "x-user-id", "x-tenant-id",
            // Authentication headers
            "x-auth-token", "x-access-token", "x-refresh-token",
            // Cache and conditional headers
            "if-match", "if-none-match", "if-modified-since", "if-unmodified-since",
            "cache-control", "pragma",
            // Content headers
            "content-encoding", "content-language", "content-range",
            // CORS extension headers
            "access-control-request-headers", "access-control-request-method"
        ].join(", ");
        
        let headers = env::var("CORS_ALLOWED_HEADERS")
            .unwrap_or(default_headers);
            
        (headers, false)
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
        _session: &mut Session,
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
    

    /// Handle preflight OPTIONS requests locally
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> where Self: Sized {
        // Check if this is a CORS preflight request (OPTIONS with specific headers)
        if session.req_header().method == "OPTIONS" {
            if let Some(_origin) = session.req_header().headers.get("origin") {
                // This is a preflight request - handle it locally
                println!("🔄 Handling CORS preflight OPTIONS request locally");
                
                // Create response with CORS headers
                let mut response = ResponseHeader::build(200, None)?;
                response.insert_header("access-control-allow-origin", "*")?;
                response.insert_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD")?;
                
                // Use configurable headers policy
                if self.allow_any_headers {
                    response.insert_header("access-control-allow-headers", "*")?;
                } else {
                    response.insert_header("access-control-allow-headers", &self.allowed_headers)?;
                }
                
                response.insert_header("access-control-max-age", "86400")?; // 24 hours
                response.insert_header("content-length", "0")?;
                response.insert_header("x-cors-proxy", "rust-pingora")?;
                
                // Send the response immediately
                session.write_response_header(Box::new(response), false).await?;
                session.finish_body().await?;
                
                // Return true to indicate we handled the request
                return Ok(true);
            }
        }
        
        // Continue with normal processing
        Ok(false)
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
        // Step 1: Remove ALL existing CORS headers to prevent duplicates
        upstream_response.remove_header("access-control-allow-origin");
        upstream_response.remove_header("access-control-allow-methods");
        upstream_response.remove_header("access-control-allow-headers");
        upstream_response.remove_header("access-control-allow-credentials");
        upstream_response.remove_header("access-control-max-age");
        upstream_response.remove_header("access-control-expose-headers");
        
        // Step 2: Always add CORS headers to allow all origins
        // This fixes the duplicate header issue by ensuring only one is set
        upstream_response.insert_header("access-control-allow-origin", "*")?;
        upstream_response.insert_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD")?;
        
        // Use configurable headers policy
        if self.allow_any_headers {
            upstream_response.insert_header("access-control-allow-headers", "*")?;
        } else {
            upstream_response.insert_header("access-control-allow-headers", &self.allowed_headers)?;
        }
        
        upstream_response.insert_header("access-control-max-age", "86400")?; // 24 hours
        
        // Log the origin for debugging
        if let Some(request_origin) = session.req_header().headers.get("origin") {
            if let Ok(origin_str) = request_origin.to_str() {
                println!("✅ CORS: Allowing origin {} with wildcard policy", origin_str);
            }
        } else {
            println!("✅ CORS: No origin header, wildcard policy applied");
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
    let bind_addr = format!("0.0.0.0:{}", port);
    
    proxy.add_tcp(&bind_addr);
    
    println!("🌐 CORS Proxy listening on http://{}", bind_addr);
    println!("✨ Environment variables:");
    println!("   UPSTREAM_ADDR - Target service address (default: httpbin.org:80)");
    println!("   UPSTREAM_TLS - Force TLS usage (true/false, auto-detected if not set)");
    println!("   PROXY_PORT - Port to listen on (default: 6189)");
    println!("   CORS_ALLOWED_HEADERS - Custom allowed headers (comma-separated)");
    println!("   CORS_ALLOW_ANY_HEADERS - Allow any headers with wildcard (true/false)");
    println!();
    println!("🛡️  CORS Policy:");
    println!("   - Access-Control-Allow-Origin: * (allows all origins)");
    println!("   - Handles preflight OPTIONS requests locally");
    println!("   - Prevents duplicate CORS headers by cleaning upstream headers");
    println!("   - Supports MCP headers (mcp-session-id, mcp-client-version, etc.)");
    println!("   - Includes common custom headers (x-api-key, x-session-id, etc.)");
    println!("   - Configurable via environment variables");
    println!();
    println!("📝 Example usage:");
    println!("   # HTTP upstream");
    println!("   UPSTREAM_ADDR=httpbin.org:80 cargo run --bin cors-proxy");
    println!("   # HTTPS upstream (auto-detected by port 443)");
    println!("   UPSTREAM_ADDR=api.github.com:443 cargo run --bin cors-proxy");
    println!("   # GitHub MCP Server (the specific use case from TODO.md)");
    println!("   UPSTREAM_ADDR=api.githubcopilot.com:443 cargo run --bin cors-proxy");
    println!("   # HTTPS upstream (explicit TLS)");
    println!("   UPSTREAM_ADDR=secure-api.com:8080 UPSTREAM_TLS=true cargo run --bin cors-proxy");
    println!("   # Allow any headers (wildcard - most permissive)");
    println!("   CORS_ALLOW_ANY_HEADERS=true cargo run --bin cors-proxy");
    println!("   # Custom headers only");
    println!("   CORS_ALLOWED_HEADERS=\"content-type,authorization,mcp-session-id\" cargo run --bin cors-proxy");
    println!();
    println!("🔒 TLS Auto-detection:");
    println!("   - Ports 443, 8443, 9443 automatically use TLS");
    println!("   - Addresses containing 'https' use TLS");
    println!("   - Override with UPSTREAM_TLS=true/false");
    println!();
    println!("🧪 Test commands:");
    println!("   # Request without origin header");
    println!("   curl -v http://{}/get", bind_addr);
    println!("   # Request with origin header (any origin allowed)");
    println!("   curl -v -H 'Origin: https://example.com' http://{}/get", bind_addr);
    println!("   # CORS preflight request (handled locally)");
    println!("   curl -v -X OPTIONS -H 'Origin: https://example.com' -H 'Access-Control-Request-Method: POST' http://{}/", bind_addr);
    println!("   # GitHub MCP Server test (reproduces TODO.md scenario)");
    println!("   curl -v -H 'Origin: https://example.com' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' \\");
    println!("        --data '{{\"jsonrpc\":\"2.0\",\"id\":\"test\",\"method\":\"initialize\"}}' http://{}/mcp/", bind_addr);
    println!("   # MCP preflight with mcp-session-id header (fixes TODO.md issue)");
    println!("   curl -v -X OPTIONS -H 'Origin: https://example.com' -H 'Access-Control-Request-Method: POST' \\");
    println!("        -H 'Access-Control-Request-Headers: mcp-session-id,content-type,authorization' http://{}/", bind_addr);
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}
