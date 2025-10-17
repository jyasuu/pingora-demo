use async_trait::async_trait;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use pingora_proxy::prelude::*;
use std::sync::Arc;

/// Simple proxy context (required by ProxyHttp trait)
pub struct MyCtx;

/// Our Load Balancer proxy service  
pub struct LB {
    lb: Arc<LoadBalancer<RoundRobin>>,
}

impl LB {
    pub fn new(lb: LoadBalancer<RoundRobin>) -> Self {
        Self { lb: Arc::new(lb) }
    }
}

#[async_trait]
impl ProxyHttp for LB {
    type CTX = MyCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        MyCtx
    }

    /// Core function: select upstream peer for each request
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        // Select a backend from LoadBalancer (round-robin)
        let upstream = self.lb
            .select(b"", 256) // key and hash don't matter for round-robin
            .unwrap();
            
        println!("🎯 Selected upstream: {}", upstream.addr);
        
        let peer = Box::new(HttpPeer::new(upstream, false, "".to_string()));
        Ok(peer)
    }

    /// Modify request before sending to upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        // Add custom headers to upstream request
        upstream_request.insert_header("x-proxy-added", "pingora-demo")?;
        upstream_request.insert_header("x-forwarded-by", "rust-pingora")?;
        
        println!("📤 Proxying {} {}", session.req_header().method, session.req_header().uri);
        Ok(())
    }

    /// Modify response before sending to client
    async fn response_filter(
        &self, 
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        // Add custom response headers
        upstream_response.insert_header("x-proxy", "pingora-demo")?;
        upstream_response.insert_header("x-load-balancer", "rust-implementation")?;
        
        // Remove sensitive backend info
        upstream_response.remove_header("server");
        
        println!("📤 Response status: {}", upstream_response.status);
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    println!("🚀 Starting Pingora Load Balancer Demo...");
    
    // Create backends for load balancing
    let backends = vec![
        "httpbin.org:80",     // HTTPBin for testing HTTP requests
        "example.com:80",     // Example.com
        "jsonplaceholder.typicode.com:80", // JSON placeholder API
    ];
    
    println!("📋 Configuring backends: {:?}", backends);
    
    // Create LoadBalancer with RoundRobin selection
    let mut lb = LoadBalancer::try_from_iter(backends)?;
    
    // Set health check (optional)
    lb.set_health_check(pingora_load_balancing::health_check::TcpHealthCheck::new());
    lb.health_check_frequency = Some(std::time::Duration::from_secs(30));
    
    // Create our proxy service
    let lb_service = LB::new(lb);
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), lb_service);
    
    // Bind to a TCP port for external connections
    proxy.add_tcp("127.0.0.1:6188");
    
    println!("🌐 Load balancer listening on http://127.0.0.1:6188");
    println!("✨ Try these commands:");
    println!("   curl -v http://127.0.0.1:6188/");
    println!("   curl -H 'Host: httpbin.org' http://127.0.0.1:6188/get");
    println!("   curl -H 'Host: example.com' http://127.0.0.1:6188/");
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}
