// Path-based routing proxy - Routes requests based on URL paths
use async_trait::async_trait;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::prelude::*;

/// Context for storing routing information
pub struct RouterCtx {
    selected_backend: String,
}

/// Path-based router proxy service
pub struct PathRouter {
    // Backend pools for different services
    api_backends: Vec<String>,
    static_backends: Vec<String>,
    default_backends: Vec<String>,
}

impl PathRouter {
    pub fn new() -> Self {
        Self {
            api_backends: vec![
                "jsonplaceholder.typicode.com:80".to_string(),
                "httpbin.org:80".to_string(),
            ],
            static_backends: vec![
                "cdn.jsdelivr.net:80".to_string(),
                "unpkg.com:80".to_string(),
            ],
            default_backends: vec![
                "example.com:80".to_string(),
                "httpbin.org:80".to_string(),
            ],
        }
    }
    
    fn select_backend_pool(&self, path: &str) -> &[String] {
        match path {
            p if p.starts_with("/api/") => &self.api_backends,
            p if p.starts_with("/static/") || p.starts_with("/assets/") => &self.static_backends,
            p if p.starts_with("/cdn/") => &self.static_backends,
            _ => &self.default_backends,
        }
    }
    
    fn select_backend_from_pool<'a>(&self, pool: &'a [String], session_id: u64) -> &'a str {
        let index = (session_id as usize) % pool.len();
        &pool[index]
    }
}

#[async_trait]
impl ProxyHttp for PathRouter {
    type CTX = RouterCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        RouterCtx {
            selected_backend: String::new(),
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        let path = session.req_header().uri.path();
        let session_id = std::ptr::addr_of!(*session) as u64; // Use session address as ID
        
        // Select backend pool based on path
        let pool = self.select_backend_pool(path);
        let backend = self.select_backend_from_pool(pool, session_id);
        
        // Store selection in context for logging
        ctx.selected_backend = backend.to_string();
        
        println!("🎯 Route: {} → {} (from pool: {:?})", 
                path, backend, pool);
        
        let peer = Box::new(HttpPeer::new(backend, false, "".to_string()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        let path = session.req_header().uri.path();
        
        // Add routing information headers
        upstream_request.insert_header("X-Router", "path-based")?;
        upstream_request.insert_header("X-Original-Path", path)?;
        upstream_request.insert_header("X-Selected-Backend", &ctx.selected_backend)?;
        
        // Add service type header based on path
        let service_type = match path {
            p if p.starts_with("/api/") => "api",
            p if p.starts_with("/static/") || p.starts_with("/assets/") => "static",
            p if p.starts_with("/cdn/") => "cdn",
            _ => "default",
        };
        upstream_request.insert_header("X-Service-Type", service_type)?;
        
        println!("📤 Routing {} {} to {} ({})", 
                session.req_header().method, 
                path, 
                ctx.selected_backend,
                service_type);
        
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // Add routing information to response
        upstream_response.insert_header("X-Routed-By", "pingora-path-router")?;
        upstream_response.insert_header("X-Backend-Used", &ctx.selected_backend)?;
        
        // Add cache headers for static content
        if let Some(service_type) = upstream_response.headers.get("X-Service-Type") {
            if service_type == "static" || service_type == "cdn" {
                upstream_response.insert_header("Cache-Control", "public, max-age=3600")?;
            }
        }
        
        println!("📥 Response from {} - Status: {}", 
                ctx.selected_backend, upstream_response.status);
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Starting Pingora Path-Based Router...");
    println!("📋 Routing Rules:");
    println!("   /api/* → API backends (jsonplaceholder, httpbin)");
    println!("   /static/*, /assets/*, /cdn/* → CDN backends");
    println!("   /* → Default backends (example.com, httpbin)");
    
    // Create path router service
    let router = PathRouter::new();
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), router);
    proxy.add_tcp("127.0.0.1:6189");
    
    println!("🌐 Path router listening on http://127.0.0.1:6189");
    println!("✨ Try these commands:");
    println!("   curl http://127.0.0.1:6189/api/posts/1");
    println!("   curl http://127.0.0.1:6189/static/style.css");
    println!("   curl http://127.0.0.1:6189/");
    println!("   curl -v http://127.0.0.1:6189/api/users | grep 'X-'");
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}