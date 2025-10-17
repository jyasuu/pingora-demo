# Pingora Examples - Multiple Proxy Implementations

This project contains multiple Pingora proxy implementations, each demonstrating different features and patterns. Each example runs as a separate binary on different ports.

## 🚀 Available Examples

### 1. **Load Balancer** (`load-balancer`)
**Port**: `6188` | **File**: `src/main.rs`

Basic round-robin load balancer with health checks.

**Features**:
- Round-robin backend selection
- TCP health checks every 30 seconds
- Custom request/response headers
- Three backend servers (httpbin.org, example.com, jsonplaceholder)

**Usage**:
```bash
cargo run --bin load-balancer
curl http://127.0.0.1:6188/get
```

### 2. **Path Router** (`path-router`)
**Port**: `6189` | **File**: `src/bin/path_router.rs`

Routes requests to different backend pools based on URL paths.

**Features**:
- Path-based routing rules
- Different backend pools for API, static content, and default
- Service type detection and headers
- Cache headers for static content

**Routing Rules**:
- `/api/*` → API backends (jsonplaceholder, httpbin)
- `/static/*`, `/assets/*`, `/cdn/*` → CDN backends
- `/*` → Default backends (example.com, httpbin)

**Usage**:
```bash
cargo run --bin path-router
curl http://127.0.0.1:6189/api/posts/1     # Routes to API backend
curl http://127.0.0.1:6189/static/app.js   # Routes to CDN backend
curl http://127.0.0.1:6189/                # Routes to default backend
```

### 3. **Rate Limiter** (`rate-limiter`)
**Port**: `6190` | **File**: `src/bin/rate_limiter.rs`

Implements per-IP rate limiting with configurable windows.

**Features**:
- 10 requests per 60 seconds per IP (configurable)
- In-memory request tracking with automatic cleanup
- Rate limit headers in responses
- JSON error responses with retry information
- Real client IP detection (X-Forwarded-For support)

**Usage**:
```bash
cargo run --bin rate-limiter

# Test normal requests
curl http://127.0.0.1:6190/get

# Test rate limiting (run quickly)
for i in {1..15}; do 
  curl -w "Status: %{response_code}\n" http://127.0.0.1:6190/get
done

# Check rate limit headers
curl -v http://127.0.0.1:6190/get 2>&1 | grep 'X-Rate'
```

### 4. **Circuit Breaker** (`circuit-breaker`)
**Port**: `6191` | **File**: `src/bin/circuit_breaker.rs`

Prevents cascading failures by monitoring backend health and implementing circuit breaker pattern.

**Features**:
- Three states: Closed, Open, Half-Open
- Configurable failure thresholds and timeouts
- Backup backend support when circuit is open
- Detailed metrics and state tracking
- Automatic recovery testing

**Configuration**:
- Failure threshold: 5 failures
- Recovery threshold: 3 successes
- Open timeout: 30 seconds
- Half-open test calls: 3

**Usage**:
```bash
cargo run --bin circuit-breaker

# Normal requests
curl http://127.0.0.1:6191/get

# Trigger failures to open circuit
for i in {1..6}; do 
  curl http://127.0.0.1:6191/status/500
done

# Test circuit breaker response
curl -v http://127.0.0.1:6191/get

# Check circuit breaker headers
curl -v http://127.0.0.1:6191/get 2>&1 | grep 'X-Circuit'
```

### 5. **Authentication Proxy** (`auth-proxy`)
**Port**: `6192` | **File**: `src/bin/auth_proxy.rs`

Validates authentication for protected endpoints using Basic Auth and Bearer tokens.

**Features**:
- Basic Authentication support
- Bearer token validation (custom JWT-like tokens)
- Protected path configuration
- User role management
- Token refresh mechanism
- Secure header forwarding

**Protected Paths**: `/admin`, `/api/protected`, `/dashboard`

**Test Users**:
- `admin:admin123` (roles: admin, user)
- `user:user123` (roles: user)

**Usage**:
```bash
cargo run --bin auth-proxy

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

## 🛠️ Build and Run

### Build All Examples
```bash
cargo build --release
```

### Run Specific Examples
```bash
# Load balancer
cargo run --bin load-balancer

# Path router
cargo run --bin path-router

# Rate limiter
cargo run --bin rate-limiter

# Circuit breaker
cargo run --bin circuit-breaker

# Authentication proxy
cargo run --bin auth-proxy
```

### Run Multiple Examples Simultaneously
```bash
# Terminal 1
cargo run --bin load-balancer &

# Terminal 2
cargo run --bin path-router &

# Terminal 3
cargo run --bin rate-limiter &

# Terminal 4
cargo run --bin circuit-breaker &

# Terminal 5
cargo run --bin auth-proxy &
```

## 🧪 Testing All Examples

### Comprehensive Test Script
```bash
#!/bin/bash

echo "🧪 Testing all Pingora examples..."

# Test load balancer
echo "📊 Testing Load Balancer (port 6188)..."
curl -s http://127.0.0.1:6188/get | head -n 3

# Test path router
echo "🛤️  Testing Path Router (port 6189)..."
curl -s http://127.0.0.1:6189/api/posts/1 | head -n 3

# Test rate limiter
echo "⚡ Testing Rate Limiter (port 6190)..."
curl -s http://127.0.0.1:6190/get | head -n 3

# Test circuit breaker
echo "🔄 Testing Circuit Breaker (port 6191)..."
curl -s http://127.0.0.1:6191/get | head -n 3

# Test auth proxy
echo "🔐 Testing Auth Proxy (port 6192)..."
curl -u admin:admin123 -s http://127.0.0.1:6192/admin | head -n 3

echo "✅ All tests completed!"
```

## 📚 Learning Path

### Beginner
1. Start with **Load Balancer** - understand basic Pingora concepts
2. Explore **Path Router** - learn request routing patterns
3. Study the code structure and ProxyHttp trait implementation

### Intermediate
4. Implement **Rate Limiter** - understand state management and middleware
5. Build **Circuit Breaker** - learn failure handling and resilience patterns
6. Practice modifying configurations and thresholds

### Advanced
7. Deploy **Authentication Proxy** - understand security patterns
8. Combine multiple patterns in a single proxy
9. Add monitoring, metrics, and observability

## 🔧 Configuration

Each example can be extended with:

- **Custom configurations** via environment variables
- **Database integration** for persistent state
- **Metrics collection** with Prometheus
- **Distributed tracing** with OpenTelemetry
- **TLS termination** and certificate management
- **Dynamic configuration** reloading

## 🚀 Next Steps

- **Combine Features**: Create a proxy that uses multiple patterns
- **Add Monitoring**: Integrate Prometheus metrics
- **Performance Testing**: Benchmark different configurations
- **Production Deployment**: Add logging, monitoring, and scaling
- **Custom Middleware**: Implement your own proxy features

---

**Built with ❤️ using Pingora and Rust**