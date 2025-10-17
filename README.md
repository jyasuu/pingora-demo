# Pingora Demo - HTTP Load Balancer

A production-ready HTTP reverse proxy and load balancer built with **Pingora** (Cloudflare's Rust framework).

## 🚀 Features

- **Round-Robin Load Balancing**: Distributes requests across multiple backend servers
- **Health Checks**: Automatic TCP health monitoring every 30 seconds
- **Request/Response Filtering**: Custom header manipulation and transformation
- **High Performance**: Built on Pingora's async Rust foundation
- **Production Ready**: Handles connection pooling, error handling, and graceful operations

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

## 🛠️ Usage

### Start the Load Balancer
```bash
cargo run
```

The server will start on `http://127.0.0.1:6188`

### Test Load Balancing
```bash
# Test round-robin distribution
for i in {1..5}; do
  echo "Request $i:"
  curl -s http://127.0.0.1:6188/ | head -n 3
  echo "---"
done
```

### Test Specific Backends
```bash
# HTTPBin testing
curl -H "Host: httpbin.org" http://127.0.0.1:6188/get

# Example.com
curl -H "Host: example.com" http://127.0.0.1:6188/

# JSON API
curl -H "Host: jsonplaceholder.typicode.com" http://127.0.0.1:6188/posts/1
```

### Inspect Custom Headers
```bash
# View proxy-added headers
curl -v http://127.0.0.1:6188/ 2>&1 | grep -E "(x-proxy|x-load-balancer|x-forwarded-by)"
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

## 🚀 Next Steps & Practice Ideas

### Beginner
- **Path-based routing**: Route `/api/*` to different backends
- **Request logging**: Add structured logging with `tracing`
- **Configuration**: Load backends from config file

### Intermediate  
- **Rate limiting**: Implement per-IP request throttling
- **Circuit breaker**: Handle failing backend gracefully
- **Weighted load balancing**: Assign different weights to backends

### Advanced
- **TLS termination**: Handle HTTPS connections
- **Authentication**: Add JWT or basic auth middleware
- **Metrics**: Integrate Prometheus monitoring
- **Dynamic configuration**: Hot-reload backend changes

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

## 🤝 Contributing

This is a learning project for Pingora development. Feel free to:

- Add new load balancing algorithms
- Implement additional middleware
- Enhance monitoring and observability
- Create performance benchmarks

---

**Built with ❤️ using Pingora and Rust**