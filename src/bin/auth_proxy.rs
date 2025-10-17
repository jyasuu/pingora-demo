// Authentication proxy - Validates JWT tokens and basic auth
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Authentication context
pub struct AuthCtx {
    authenticated: bool,
    user_id: Option<String>,
    auth_method: Option<String>,
}

/// User database (in production, use a real database)
#[derive(Clone)]
pub struct UserStore {
    users: HashMap<String, UserInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserInfo {
    username: String,
    password_hash: String,
    roles: Vec<String>,
}

impl UserStore {
    pub fn new() -> Self {
        let mut users = HashMap::new();
        
        // Add some test users (passwords are hashed with SHA256)
        users.insert("admin".to_string(), UserInfo {
            username: "admin".to_string(),
            password_hash: sha256_hash("admin123"), // admin:admin123
            roles: vec!["admin".to_string(), "user".to_string()],
        });
        
        users.insert("user".to_string(), UserInfo {
            username: "user".to_string(),
            password_hash: sha256_hash("user123"), // user:user123
            roles: vec!["user".to_string()],
        });
        
        Self { users }
    }
    
    pub fn verify_user(&self, username: &str, password: &str) -> Option<&UserInfo> {
        if let Some(user) = self.users.get(username) {
            if user.password_hash == sha256_hash(password) {
                return Some(user);
            }
        }
        None
    }
}

/// Simple JWT-like token structure (in production, use a proper JWT library)
#[derive(Serialize, Deserialize)]
pub struct AuthToken {
    username: String,
    roles: Vec<String>,
    exp: u64, // expiration timestamp
}

/// Authentication proxy service
pub struct AuthProxy {
    backend: String,
    user_store: UserStore,
    jwt_secret: String,
    protected_paths: Vec<String>,
}

impl AuthProxy {
    pub fn new(backend: String) -> Self {
        Self {
            backend,
            user_store: UserStore::new(),
            jwt_secret: "super-secret-key".to_string(), // In production, use proper secret management
            protected_paths: vec![
                "/admin".to_string(),
                "/api/protected".to_string(),
                "/dashboard".to_string(),
            ],
        }
    }
    
    pub fn with_protected_paths(mut self, paths: Vec<String>) -> Self {
        self.protected_paths = paths;
        self
    }
    
    fn is_protected_path(&self, path: &str) -> bool {
        self.protected_paths.iter().any(|protected| path.starts_with(protected))
    }
    
    fn parse_basic_auth(&self, auth_header: &str) -> Option<(String, String)> {
        if !auth_header.starts_with("Basic ") {
            return None;
        }
        
        let encoded = &auth_header[6..];
        if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
            if let Ok(credentials) = String::from_utf8(decoded) {
                if let Some((username, password)) = credentials.split_once(':') {
                    return Some((username.to_string(), password.to_string()));
                }
            }
        }
        None
    }
    
    fn parse_bearer_token(&self, auth_header: &str) -> Option<String> {
        if auth_header.starts_with("Bearer ") {
            Some(auth_header[7..].to_string())
        } else {
            None
        }
    }
    
    fn verify_token(&self, token: &str) -> Option<AuthToken> {
        // Simple token verification (in production, use proper JWT verification)
        // For demo purposes, we'll use base64 encoded JSON
        if let Ok(decoded) = general_purpose::STANDARD.decode(token) {
            if let Ok(json_str) = String::from_utf8(decoded) {
                if let Ok(auth_token) = serde_json::from_str::<AuthToken>(&json_str) {
                    // Check expiration
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    
                    if auth_token.exp > now {
                        return Some(auth_token);
                    }
                }
            }
        }
        None
    }
    
    fn generate_token(&self, user: &UserInfo) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour expiration
        
        let token = AuthToken {
            username: user.username.clone(),
            roles: user.roles.clone(),
            exp,
        };
        
        let json = serde_json::to_string(&token).unwrap();
        general_purpose::STANDARD.encode(json)
    }
}

fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[async_trait]
impl ProxyHttp for AuthProxy {
    type CTX = AuthCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        AuthCtx {
            authenticated: false,
            user_id: None,
            auth_method: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        let path = session.req_header().uri.path().to_string();
        
        // Check if path requires authentication
        if !self.is_protected_path(&path) {
            ctx.authenticated = true;
            return Ok(true); // Allow public paths
        }
        
        // Check for authentication header
        if let Some(auth_header) = session.req_header().headers.get("Authorization") {
            if let Ok(auth_str) = std::str::from_utf8(auth_header.as_bytes()) {
                
                // Try Basic Auth first
                if let Some((username, password)) = self.parse_basic_auth(auth_str) {
                    if let Some(user) = self.user_store.verify_user(&username, &password) {
                        ctx.authenticated = true;
                        ctx.user_id = Some(user.username.clone());
                        ctx.auth_method = Some("Basic".to_string());
                        
                        println!("✅ Basic auth successful for user: {}", username);
                        return Ok(true);
                    }
                }
                
                // Try Bearer Token
                if let Some(token) = self.parse_bearer_token(auth_str) {
                    if let Some(auth_token) = self.verify_token(&token) {
                        ctx.authenticated = true;
                        ctx.user_id = Some(auth_token.username.clone());
                        ctx.auth_method = Some("Bearer".to_string());
                        
                        println!("✅ Token auth successful for user: {}", auth_token.username);
                        return Ok(true);
                    }
                }
            }
        }
        
        // Authentication failed - return 401
        let mut resp = pingora::http::ResponseHeader::build(401, None)?;
        resp.insert_header("Content-Type", "application/json")?;
        resp.insert_header("WWW-Authenticate", "Basic realm=\"Protected Area\"")?;
        resp.insert_header("WWW-Authenticate", "Bearer realm=\"Protected Area\"")?;
        
        let body = serde_json::json!({
            "error": "Authentication Required",
            "message": "This endpoint requires authentication",
            "supported_methods": ["Basic", "Bearer"],
            "example_users": {
                "admin": "admin123",
                "user": "user123"
            }
        });
        
        println!("🚫 Authentication failed for path: {}", path);
        
        session.set_keepalive(None);
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body.to_string().into()), true).await?;
        ctx.authenticated = false;
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        if !ctx.authenticated {
            return Err(pingora::Error::new_str("Authentication required").into());
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
        // Add authentication info to upstream request
        upstream_request.insert_header("X-Authenticated", "true")?;
        
        if let Some(user_id) = &ctx.user_id {
            upstream_request.insert_header("X-User-ID", user_id)?;
        }
        
        if let Some(auth_method) = &ctx.auth_method {
            upstream_request.insert_header("X-Auth-Method", auth_method)?;
        }
        
        // Remove original Authorization header for security
        upstream_request.remove_header("Authorization");
        
        println!("📤 Forwarding authenticated request for user: {:?}", ctx.user_id);
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // Add authentication info to response
        upstream_response.insert_header("X-Auth-Proxy", "pingora-auth")?;
        
        if ctx.authenticated {
            upstream_response.insert_header("X-Authenticated", "true")?;
            
            if let Some(user_id) = &ctx.user_id {
                // Generate a new token for the response (token refresh)
                if let Some(user) = self.user_store.users.get(user_id) {
                    let new_token = self.generate_token(user);
                    upstream_response.insert_header("X-Refresh-Token", &new_token)?;
                }
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Starting Pingora Authentication Proxy...");
    println!("🔐 Protected paths: /admin, /api/protected, /dashboard");
    println!("👥 Test users:");
    println!("   - admin:admin123 (roles: admin, user)");
    println!("   - user:user123 (roles: user)");
    
    // Create auth proxy
    let auth_proxy = AuthProxy::new("httpbin.org:80".to_string())
        .with_protected_paths(vec![
            "/admin".to_string(),
            "/api/protected".to_string(),
            "/dashboard".to_string(),
        ]);
    
    // Create pingora http proxy service
    let mut proxy = pingora_proxy::http_proxy_service(&Default::default(), auth_proxy);
    proxy.add_tcp("127.0.0.1:6192");
    
    println!("🌐 Auth proxy listening on http://127.0.0.1:6192");
    println!("✨ Try these commands:");
    println!("   # Public access (no auth required)");
    println!("   curl http://127.0.0.1:6192/get");
    println!("   # Protected access (auth required)");
    println!("   curl http://127.0.0.1:6192/admin");
    println!("   # Basic auth");
    println!("   curl -u admin:admin123 http://127.0.0.1:6192/admin");
    println!("   # Bearer token (get from X-Refresh-Token header)");
    println!("   TOKEN=$(curl -u admin:admin123 -v http://127.0.0.1:6192/admin 2>&1 | grep 'X-Refresh-Token' | cut -d' ' -f3)");
    println!("   curl -H \"Authorization: Bearer $TOKEN\" http://127.0.0.1:6192/dashboard");
    
    // Create Server instance, register service, and start
    let mut server = Server::new(None)?;
    server.add_service(proxy);
    server.run_forever()
}