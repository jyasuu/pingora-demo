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
}

impl CorsProxy {
    pub fn new() -> anyhow::Result<Self> {
        // Read configuration from environment variables
        let upstream_addr = env::var("UPSTREAM_ADDR")
            .unwrap_or_else(|_| "httpbin.org:80".to_string());
        
        let allowed_origin = env::var("ALLOWED_ORIGIN").ok();
        
        println!("🔧 CORS Proxy Configuration:");
        println!("   Upstream: {}", upstream_addr);
        println!("   Allowed Origin: {:?}", allowed_origin);
        
        Ok(Self {
            upstream_addr,
            allowed_origin,
        })
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
        let peer = Box::new(HttpPeer::new(
            self.upstream_addr.clone(),
            false,
            "".to_string()
        ));
        Ok(peer)
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
        
        println!("📤 Proxying {} {} with Origin: {:?}", 
            session.req_header().method, 
            session.req_header().uri,
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
    println!("   ALLOWED_ORIGIN - Origin to allow CORS for (e.g., https://example.com)");
    println!("   PROXY_PORT - Port to listen on (default: 6189)");
    println!();
    println!("📝 Example usage:");
    println!("   UPSTREAM_ADDR=httpbin.org:80 ALLOWED_ORIGIN=https://example.com cargo run --bin cors-proxy");
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