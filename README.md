# Pingora Demo - Complete Proxy Learning Suite

A comprehensive collection of **Pingora** (Cloudflare's Rust framework) proxy implementations demonstrating various patterns and features. Each example runs as a separate binary, allowing you to learn different proxy concepts independently.

## 🚀 Available Examples

### **1. Load Balancer** (`load-balancer`) - Port 6188
**Basic round-robin load balancer with health checks**
- Round-robin backend selection across 3 servers
- TCP health checks every 30 seconds  
- Custom request/response header manipulation
- Production-ready error handling

### **2. Path Router** (`path-router`) - Port 6189
**Intelligent request routing based on URL paths**
- `/api/*` → API backends (jsonplaceholder, httpbin)
- `/static/*`, `/assets/*`, `/cdn/*` → CDN backends
- `/*` → Default backends (example.com, httpbin)
- Service-specific headers and caching policies

### **3. Rate Limiter** (`rate-limiter`) - Port 6190
**Per-IP request rate limiting with configurable windows**
- 10 requests per 60 seconds per IP (configurable)
- In-memory request tracking with automatic cleanup
- Detailed rate limit headers and JSON error responses
- Real client IP detection (X-Forwarded-For support)

### **4. Circuit Breaker** (`circuit-breaker`) - Port 6191
**Fault tolerance with automatic failure detection and recovery**
- Three states: Closed, Open, Half-Open
- Configurable failure thresholds (5 failures → open)
- Automatic recovery testing (3 successes → closed)
- Backup backend support when circuit is open
- Comprehensive metrics and state tracking

### **5. Authentication Proxy** (`auth-proxy`) - Port 6192
**Security middleware with multiple authentication methods**
- Basic Authentication support (`admin:admin123`, `user:user123`)
- Bearer token validation (custom JWT-like tokens)
- Protected paths: `/admin`, `/api/protected`, `/dashboard`
- User role management and token refresh
- Secure header forwarding to upstream

## 🏗️ Architecture

```
Client Request → Pingora Proxy → Backend Selection → Upstream Server
                      ↓
              [Custom Headers Added]
                      ↓
            [Health Check Validation]
                      ↓
              [Response Processing]
                      ↓
               Client Response
```

### Backend Servers
- `httpbin.org:80` - HTTP testing service
- `example.com:80` - Example domain
- `jsonplaceholder.typicode.com:80` - JSON API testing

## 📦 Dependencies

Built with Pingora v0.6 and modern Rust async ecosystem:

```toml
[dependencies]
async-trait = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1.0"
pingora = "0.6"
pingora-proxy = "0.6"
pingora-load-balancing = "0.6"
```

## 🛠️ Quick Start

### Build All Examples
```bash
cargo build --all-targets
```

### Run Individual Examples
```bash
# Load Balancer (Port 6188)
cargo run --bin load-balancer

# Path Router (Port 6189)
cargo run --bin path-router

# Rate Limiter (Port 6190)
cargo run --bin rate-limiter

# Circuit Breaker (Port 6191)
cargo run --bin circuit-breaker

# Authentication Proxy (Port 6192)
cargo run --bin auth-proxy
```

### Test Examples

#### **Load Balancer Testing**
```bash
# Test round-robin distribution
for i in {1..5}; do
  echo "Request $i:"
  curl -s http://127.0.0.1:6188/ | head -n 3
  echo "---"
done

# Test specific backends
curl -H "Host: httpbin.org" http://127.0.0.1:6188/get
curl -H "Host: example.com" http://127.0.0.1:6188/
```

#### **Path Router Testing**
```bash
# API requests → API backends
curl http://127.0.0.1:6189/api/posts/1

# Static content → CDN backends
curl http://127.0.0.1:6189/static/app.js

# Default → Default backends
curl http://127.0.0.1:6189/
```

#### **Rate Limiter Testing**
```bash
# Normal request
curl http://127.0.0.1:6190/get

# Test rate limiting (run quickly)
for i in {1..15}; do 
  curl -w "Status: %{response_code}\n" http://127.0.0.1:6190/get
done

# Check rate limit headers
curl -v http://127.0.0.1:6190/get 2>&1 | grep 'X-Rate'
```

#### **Circuit Breaker Testing**
```bash
# Normal requests
curl http://127.0.0.1:6191/get

# Trigger failures to open circuit
for i in {1..6}; do 
  curl http://127.0.0.1:6191/status/500
done

# Test circuit breaker response
curl -v http://127.0.0.1:6191/get
```

#### **Authentication Proxy Testing**
```bash
# Public access (no auth required)
curl http://127.0.0.1:6192/get

# Protected access (requires auth)
curl http://127.0.0.1:6192/admin

# Basic authentication
curl -u admin:admin123 http://127.0.0.1:6192/admin

# Bearer token authentication
TOKEN=$(curl -u admin:admin123 -v http://127.0.0.1:6192/admin 2>&1 | grep 'X-Refresh-Token' | cut -d' ' -f3)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:6192/dashboard
```

## 🔧 Code Structure

### Core Components

**Load Balancer Service (`LB`)**
- Implements `ProxyHttp` trait
- Manages backend selection with `LoadBalancer<RoundRobin>`
- Handles request/response transformation

**Key Methods:**
- `upstream_peer()` - Selects backend server for each request
- `upstream_request_filter()` - Modifies outgoing requests
- `response_filter()` - Processes incoming responses

### Request Flow

1. **Client connects** to `127.0.0.1:6188`
2. **Backend selection** via round-robin algorithm
3. **Request transformation** adds custom headers:
   - `x-proxy-added: pingora-demo`
   - `x-forwarded-by: rust-pingora`
4. **Health check validation** ensures backend availability
5. **Response processing** adds proxy identification headers
6. **Client receives** processed response

## 🎯 Advanced Features

### Health Monitoring
```rust
lb.set_health_check(TcpHealthCheck::new());
lb.health_check_frequency = Some(Duration::from_secs(30));
```

### Custom Header Management
```rust
// Request headers
upstream_request.insert_header("x-proxy-added", "pingora-demo")?;

// Response headers  
upstream_response.insert_header("x-proxy", "pingora-demo")?;
upstream_response.remove_header("server"); // Hide backend info
```

### Load Balancer Selection
```rust
let upstream = self.lb.select(b"", 256).unwrap();
let peer = Box::new(HttpPeer::new(upstream, false, "".to_string()));
```

## 📚 Learning Resources

- `TODO.md` - Comprehensive Pingora implementation guide (Chinese)
- **Official Docs**: [Pingora GitHub](https://github.com/cloudflare/pingora)
- **Rust Async**: Understanding async/await patterns
- **HTTP Proxies**: Reverse proxy concepts and patterns

## 🚀 Learning Path

### **Beginner Level**
1. **Start with Load Balancer** - Learn basic Pingora concepts and ProxyHttp trait
2. **Explore Path Router** - Understand request routing and backend selection
3. **Study Code Patterns** - Compare implementations across examples

### **Intermediate Level**  
4. **Deploy Rate Limiter** - Learn state management and middleware patterns
5. **Test Circuit Breaker** - Understand resilience and failure handling
6. **Practice Configuration** - Modify thresholds, timeouts, and policies

### **Advanced Level**
7. **Implement Auth Proxy** - Master security patterns and token handling
8. **Combine Multiple Features** - Create a proxy using multiple patterns
9. **Add Observability** - Integrate metrics, tracing, and monitoring

### **Expert Level**
- **Custom Middleware**: Build your own proxy features
- **Performance Optimization**: Benchmark and tune configurations
- **Production Deployment**: Add logging, monitoring, and scaling
- **TLS and Security**: Implement certificate management and advanced auth

## 🐛 Troubleshooting

### Common Issues

**Compilation Errors**
- Ensure Rust 1.70+ is installed
- Use `cargo clean && cargo build` for dependency conflicts

**Connection Refused**
- Check if port 6188 is available
- Verify backend connectivity: `telnet httpbin.org 80`

**Health Check Failures**
- Monitor logs for backend health status
- Adjust health check frequency if needed

### Debugging

Enable detailed logging:
```bash
RUST_LOG=debug cargo run
```

## 📈 Performance

- **Async Architecture**: Non-blocking I/O with Tokio
- **Connection Pooling**: Efficient backend connection reuse  
- **Zero-Copy**: Minimal memory allocation in hot paths
- **Production Scale**: Handles thousands of concurrent connections

## 📁 Project Structure

```
├── src/
│   ├── main.rs              # Load Balancer (basic example)
│   └── bin/
│       ├── path_router.rs   # Path-based routing
│       ├── rate_limiter.rs  # Per-IP rate limiting
│       ├── circuit_breaker.rs # Fault tolerance
│       └── auth_proxy.rs    # Authentication middleware
├── Cargo.toml               # Dependencies and binary definitions
├── README.md                # This comprehensive guide
├── EXAMPLES.md              # Detailed examples documentation
└── TODO.md                  # Advanced Pingora guide (Chinese)
```

## 🧪 Running All Examples Simultaneously

You can run multiple examples at once on different ports:

```bash
# Terminal 1 - Load Balancer
cargo run --bin load-balancer &

# Terminal 2 - Path Router  
cargo run --bin path-router &

# Terminal 3 - Rate Limiter
cargo run --bin rate-limiter &

# Terminal 4 - Circuit Breaker
cargo run --bin circuit-breaker &

# Terminal 5 - Auth Proxy
cargo run --bin auth-proxy &

# Test all examples
curl http://127.0.0.1:6188/get    # Load balancer
curl http://127.0.0.1:6189/api/posts/1  # Path router
curl http://127.0.0.1:6190/get    # Rate limiter
curl http://127.0.0.1:6191/get    # Circuit breaker
curl -u admin:admin123 http://127.0.0.1:6192/admin  # Auth proxy
```

## 📚 Additional Resources

- **`EXAMPLES.md`** - Detailed documentation for each example
- **`TODO.md`** - Comprehensive Pingora implementation guide (Chinese)
- **[Pingora GitHub](https://github.com/cloudflare/pingora)** - Official repository
- **[Pingora Documentation](https://github.com/cloudflare/pingora/tree/main/docs)** - Official docs

## 🤝 Contributing & Next Steps

This is a comprehensive learning project for Pingora development. Ideas for expansion:

### **New Examples**
- **WebSocket Proxy**: Real-time connection handling
- **gRPC Gateway**: Protocol translation and routing
- **Caching Proxy**: Response caching with TTL and invalidation
- **Metrics Collector**: Prometheus integration and dashboards

### **Enhanced Features**
- **Configuration Files**: YAML/TOML-based configuration
- **Hot Reloading**: Dynamic configuration updates
- **Health Dashboards**: Web UI for monitoring proxy status
- **Load Testing**: Automated performance benchmarks

### **Production Features**
- **TLS Termination**: Certificate management and HTTPS
- **Distributed Tracing**: OpenTelemetry integration
- **Service Discovery**: Consul/etcd integration
- **Container Deployment**: Docker and Kubernetes manifests

---

**Built with ❤️ using Pingora and Rust**

*Ready to master modern proxy development? Start with any example and work your way up!*