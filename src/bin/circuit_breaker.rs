// Circuit breaker proxy - Prevents cascading failures by monitoring backend health
use async_trait::async_trait;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::prelude::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Circuit is open, rejecting requests
    HalfOpen, // Testing if backend has recovered
}

/// Circuit breaker configuration
#[derive(Clone)]
pub struct CircuitConfig {
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    half_open_max_calls: u32,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            half_open_max_calls: 3,
        }
    }
}

/// Circuit breaker metrics
pub struct CircuitMetrics {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
    half_open_calls: AtomicU32,
    total_requests: AtomicU64,
    total_failures: AtomicU64,
}

impl CircuitMetrics {
    pub fn new() -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            half_open_calls: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }
    
    fn now_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Context for circuit breaker
pub struct CircuitCtx {
    request_allowed: bool,
    start_time: Instant,
}

/// Circuit breaker proxy service
pub struct CircuitBreakerProxy {
    backend: String,
    backup_backend: Option<String>,
    config: CircuitConfig,
    metrics: Arc<CircuitMetrics>,
    state: Arc<std::sync::RwLock<CircuitState>>,
}

impl CircuitBreakerProxy {
    pub fn new(backend: String) -> Self {
        Self {
            backend,
            backup_backend: None,
            config: CircuitConfig::default(),
            metrics: Arc::new(CircuitMetrics::new()),
            state: Arc::new(std::sync::RwLock::new(CircuitState::Closed)),
        }
    }
    
    pub fn with_backup(mut self, backup_backend: String) -> Self {
        self.backup_backend = Some(backup_backend);
        self
    }
    
    pub fn with_config(mut self, config: CircuitConfig) -> Self {
        self.config = config;
        self
    }
    
    fn get_state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }
    
    fn should_allow_request(&self) -> bool {
        let state = self.get_state();
        
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has passed
                let last_failure = self.metrics.last_failure_time.load(Ordering::Relaxed);
                let now = CircuitMetrics::now_timestamp();
                
                if now.saturating_sub(last_failure) >= self.config.timeout.as_secs() {
                    // Transition to half-open
                    {
                        let mut state_lock = self.state.write().unwrap();
                        *state_lock = CircuitState::HalfOpen;
                    }
                    self.metrics.half_open_calls.store(0, Ordering::Relaxed);
                    println!("🔄 Circuit breaker transitioning to HALF-OPEN");
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                let calls = self.metrics.half_open_calls.load(Ordering::Relaxed);
                calls < self.config.half_open_max_calls
            }
        }
    }
    
    fn record_success(&self) {
        let state = self.get_state();
        
        match state {
            CircuitState::Closed => {
                self.metrics.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let success_count = self.metrics.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                
                if success_count >= self.config.success_threshold {
                    // Transition back to closed
                    {
                        let mut state_lock = self.state.write().unwrap();
                        *state_lock = CircuitState::Closed;
                    }
                    self.metrics.failure_count.store(0, Ordering::Relaxed);
                    self.metrics.success_count.store(0, Ordering::Relaxed);
                    println!("✅ Circuit breaker transitioning to CLOSED (recovered)");
                }
            }
            CircuitState::Open => {
                // Should not happen
            }
        }
    }
    
    fn record_failure(&self) {
        let state = self.get_state();
        self.metrics.last_failure_time.store(CircuitMetrics::now_timestamp(), Ordering::Relaxed);
        self.metrics.total_failures.fetch_add(1, Ordering::Relaxed);
        
        match state {
            CircuitState::Closed => {
                let failure_count = self.metrics.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                
                if failure_count >= self.config.failure_threshold {
                    // Transition to open
                    {
                        let mut state_lock = self.state.write().unwrap();
                        *state_lock = CircuitState::Open;
                    }
                    println!("🚫 Circuit breaker transitioning to OPEN (failures: {})", failure_count);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                {
                    let mut state_lock = self.state.write().unwrap();
                    *state_lock = CircuitState::Open;
                }
                self.metrics.success_count.store(0, Ordering::Relaxed);
                println!("🚫 Circuit breaker back to OPEN (half-open failure)");
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }
    
    fn is_error_response(&self, status: u16) -> bool {
        status >= 500 || status == 429 // 5xx errors or rate limiting
    }
    
    fn create_circuit_breaker_response(&self) -> Result<(), Box<pingora::Error>> {
        // This would be handled in request_filter in a real implementation
        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for CircuitBreakerProxy {
    type CTX = CircuitCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        CircuitCtx {
            request_allowed: false,
            start_time: Instant::now(),
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if !self.should_allow_request() {
            // Circuit is open, reject request
            let state = self.get_state();
            
            let mut resp = pingora::http::ResponseHeader::build(503, None)?;
            resp.insert_header("Content-Type", "application/json")?;
            resp.insert_header("X-Circuit-Breaker-State", &format!("{:?}", state))?;
            resp.insert_header("Retry-After", &self.config.timeout.as_secs().to_string())?;
            
            let body = serde_json::json!({
                "error": "Service Unavailable",
                "message": "Circuit breaker is open due to backend failures",
                "state": format!("{:?}", state),
                "retry_after": self.config.timeout.as_secs()
            });
            
            session.set_keepalive(None);
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(body.to_string().into()), true).await?;
            
            println!("🚫 Request rejected - Circuit breaker is {:?}", state);
            ctx.request_allowed = false;
            return Ok(false);
        }
        
        // Increment half-open calls if in half-open state
        if self.get_state() == CircuitState::HalfOpen {
            self.metrics.half_open_calls.fetch_add(1, Ordering::Relaxed);
        }
        
        ctx.request_allowed = true;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        if !ctx.request_allowed {
            return Err(pingora::Error::new_str("Circuit breaker rejected request").into());
        }
        
        let backend = match self.get_state() {
            CircuitState::Open if self.backup_backend.is_some() => {
                // Use backup backend when circuit is open
                self.backup_backend.as_ref().unwrap()
            }
            _ => &self.backend,
        };
        
        println!("🎯 Routing to {} (Circuit: {:?})", backend, self.get_state());
        
        let peer = Box::new(HttpPeer::new(backend, false, "".to_string()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        let state = self.get_state();
        
        upstream_request.insert_header("X-Circuit-Breaker", "pingora-circuit-breaker")?;
        upstream_request.insert_header("X-Circuit-State", &format!("{:?}", state))?;
        upstream_request.insert_header("X-Request-Time", &ctx.start_time.elapsed().as_millis().to_string())?;
        
        Ok(())
    }


    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> where Self: Sized {
        let response_time = ctx.start_time.elapsed();
        let status = upstream_response.status;
        
        // Record success or failure based on response
        if self.is_error_response(status.as_u16()) || response_time > Duration::from_secs(10) {
            self.record_failure();
            println!("❌ Backend failure recorded - Status: {}, Time: {:?}", status, response_time);
        } else {
            self.record_success();
            println!("✅ Backend success recorded - Status: {}, Time: {:?}", status, response_time);
        }
        
        let state = self.get_state();
        
        // Add circuit breaker info to response
        upstream_response.insert_header("X-Circuit-Breaker", "pingora-circuit-breaker")?;
        upstream_response.insert_header("X-Circuit-State", &format!("{:?}", state))?;
        
        let failure_count = self.metrics.failure_count.load(Ordering::Relaxed);
        let total_failures = self.metrics.total_failures.load(Ordering::Relaxed);
        let total_requests = self.metrics.total_requests.load(Ordering::Relaxed);
        
        upstream_response.insert_header("X-Failure-Count", &failure_count.to_string())?;
        upstream_response.insert_header("X-Total-Failures", &total_failures.to_string())?;
        upstream_response.insert_header("X-Total-Requests", &total_requests.to_string())?;
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Starting Pingora Circuit Breaker Proxy...");
    println!("⚡ Configuration:");
    println!("   - Failure threshold: 5 failures");
    println!("   - Recovery threshold: 3 successes");
    println!("   - Open timeout: 30 seconds");
    println!("   - Half-open test calls: 3");
    
    // Create circuit breaker proxy
    let circuit_breaker = CircuitBreakerProxy::new("httpbin.org:80".to_string())
        .with_backup("example.com:80".to_string())
        .with_config(CircuitConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            half_open_max_calls: 3,
        });
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), circuit_breaker);
    proxy.add_tcp("127.0.0.1:6191");
    
    println!("🌐 Circuit breaker listening on http://127.0.0.1:6191");
    println!("✨ Try these commands:");
    println!("   # Normal requests");
    println!("   curl http://127.0.0.1:6191/get");
    println!("   # Trigger failures (use invalid endpoint)");
    println!("   for i in {{1..6}}; do curl http://127.0.0.1:6191/status/500; done");
    println!("   # Test circuit breaker response");
    println!("   curl -v http://127.0.0.1:6191/get");
    println!("   # Check circuit breaker headers");
    println!("   curl -v http://127.0.0.1:6191/get 2>&1 | grep 'X-Circuit'");
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}