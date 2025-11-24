use crate::model::Step;
use uuid::Uuid;

pub const MODERN_API_STEPS: &[(&str, &str)] = &[
    (
        "API Discovery & Attack Surface Mapping",
        r#"OBJECTIVE: Systematically discover and map API endpoints, GraphQL schemas, and REST API structures to establish comprehensive attack surface visibility.

STEP-BY-STEP:
1. **API Endpoint Discovery**: Use automated tools (gobuster api, ffuf, dirsearch) with custom wordlists for API paths (/api/v1/, /graphql, /rest, /swagger)
2. **GraphQL Schema Introspection**: Test for enabled introspection queries via /graphql?query={__schema} and extract full schema documentation
3. **OpenAPI/Swagger Enumeration**: Locate /swagger.json, /api-docs, /openapi.json endpoints and parse for exposed endpoints and parameters
4. **API Versioning Analysis**: Identify multiple API versions (v1, v2, v3) and test for deprecated endpoints with weaker security controls
5. **Subdomain API Hunting**: Use subdomain enumeration tools to discover API-specific subdomains (api.example.com, dev-api.example.com)
6. **JavaScript API Client Analysis**: Extract API endpoints from SPA bundles, mobile apps, and client-side JavaScript for hidden endpoints
7. **CORS Configuration Testing**: Test Cross-Origin Resource Sharing headers for API endpoint accessibility from unauthorized origins
8. **Rate Limiting Discovery**: Probe endpoint rate limits using burst requests and identify bypass opportunities

DETECTION:
- Look for 200 OK responses on API endpoint discovery
- GraphQL introspection returns structured schema data
- OpenAPI documents contain endpoint definitions
- CORS headers reveal cross-origin access policies

REMEDIATION:
- Disable GraphQL introspection in production
- Implement API authentication on all endpoints
- Restrict CORS to specific allowed origins
- Apply consistent rate limiting across API versions

TOOLS:
- gobuster with API mode
- ffuf for endpoint fuzzing
- GraphQL introspection queries
- CORS testing tools"#,
    ),
    (
        "OWASP API Top 10 2023 - BOLA & Mass Assignment",
        r#"OBJECTIVE: Test for Broken Object Property Level Authorization (BOLA/API01) and Mass Assignment vulnerabilities following OWASP API Top 10 2023 guidelines.

STEP-BY-STEP:
1. **Object ID Manipulation**: Extract object IDs from legitimate responses and test accessing other users' data by modifying IDs in API calls
2. **Sequential ID Testing**: Test sequential object IDs (1, 2, 3...) to discover unauthorized data access patterns
3. **UUID Enumeration**: Test predictable UUID patterns and attempt access to unauthorized resources
4. **Mass Assignment Discovery**: Send JSON payloads with additional parameters not expected by the endpoint to test for parameter injection
5. **Property Privilege Escalation**: Attempt to update privileged fields (role, isAdmin, status) through API endpoints designed for non-privileged updates
6. **Nested Object Testing**: Test nested object structures for authorization bypasses in complex data models
7. **Batch Operation Abuse**: Test batch endpoints for authorization bypasses when processing multiple objects
8. **HTTP Method Bypass**: Test if PUT/PATCH can bypass GET-only authorization controls

DETECTION:
- Unauthorized data access returns 200 OK instead of 403/404
- Mass assignment accepts unexpected parameters
- Privilege escalation through object property updates
- Batch operations process unauthorized objects

REMEDIATION:
- Implement proper authorization checks for all object accesses
- Validate and whitelist allowed parameters for mass assignment
- Apply principle of least privilege to API endpoints
- Use indirect object references instead of exposing IDs

TOOLS:
- Burp Suite with BOLA checks
- OWASP ZAP API security scan
- Custom scripts for ID manipulation
- Postman collections for authorization testing"#,
    ),
    (
        "GraphQL Query Injection & Abuse",
        r#"OBJECTIVE: Identify and exploit GraphQL-specific vulnerabilities including query depth abuse, query injection, and denial of service through complex queries.

STEP-BY-STEP:
1. **Query Depth Testing**: Craft deeply nested GraphQL queries to test for depth limits and potential DoS conditions
2. **Query Cost Analysis**: Test query complexity limits by creating expensive queries with multiple fields and nested relationships
3. **GraphQL Injection Testing**: Test for injection vulnerabilities in GraphQL arguments and variables
4. **Batch Query Abuse**: Use GraphQL aliases to execute multiple queries in single request for rate limit bypass
5. **Introspection Bypass**: Attempt to bypass disabled introspection using alternative queries and mutations
6. **Field Enumeration**: Use brute force to discover hidden fields and types in the GraphQL schema
7. **Mutation Authorization Testing**: Test mutations for unauthorized data modification and privilege escalation
8. **Subscription Abuse**: Test GraphQL subscriptions for unauthorized data access and resource exhaustion

DETECTION:
- Deep queries cause server timeouts or errors
- Batch queries execute without rate limiting
- Hidden fields accessible through enumeration
- Mutations allow unauthorized data changes

REMEDIATION:
- Implement query depth and complexity limits
- Disable introspection in production environments
- Apply authorization checks to all mutations
- Monitor for abusive query patterns

TOOLS:
- GraphQL-specific testing tools (GraphQLmap, Altair)
- Burp Suite with GraphQL extension
- Custom query injection scripts
- GraphQL playground for query crafting"#,
    ),
];

pub const JWT_SPA_STEPS: &[(&str, &str)] = &[
    (
        "JWT Token Analysis & Manipulation",
        r#"OBJECTIVE: Analyze JWT tokens for cryptographic weaknesses, algorithm confusion attacks, and privilege escalation opportunities.

STEP-BY-STEP:
1. **Token Extraction**: Capture JWT tokens from authentication flows, cookies, localStorage, and authorization headers
2. **Header Analysis**: Examine JWT header for algorithm specification (alg, typ) and identify potential algorithm confusion vulnerabilities
3. **Payload Decoding**: Decode JWT payload to analyze claims (iss, sub, aud, exp, nbf, iat, jti) and identify privilege escalation opportunities
4. **Algorithm Confusion Testing**: Test alg=None attacks and RS256/HS256 algorithm swapping to bypass signature verification
5. **Secret Key Cracking**: Use brute force and dictionary attacks on weak JWT secrets and common passwords
6. **Token Tampering**: Modify claims (role, admin, permissions) and test server-side validation
7. **Expiration Bypass**: Test token expiration validation and attempt to use expired tokens
8. **Key Rotation Vulnerabilities**: Test for improper key rotation and acceptance of old signing keys

DETECTION:
- alg=None tokens accepted without signature
- Weak secrets crackable with common tools
- Modified claims accepted by server
- Expired tokens still valid

REMEDIATION:
- Use strong asymmetric algorithms (RS256, ES256)
- Reject alg=None and algorithm swapping
- Implement proper token expiration validation
- Use cryptographically strong secrets

TOOLS:
- jwt-cracker for secret brute force
- Burp Suite JWT analyzer
- jwt.io for token decoding
- Custom token manipulation scripts"#,
    ),
    (
        "Single Page Application Security Testing",
        r#"OBJECTIVE: Test SPA applications for client-side security vulnerabilities, API endpoint exposure, and authentication bypasses.

STEP-BY-STEP:
1. **Bundle Analysis**: Deobfuscate and analyze JavaScript bundles for exposed API endpoints, secrets, and authentication logic
2. **Client-Side Routing**: Test client-side routes for authorization bypasses and unprotected functionality
3. **Local Storage Inspection**: Examine localStorage, sessionStorage, and IndexedDB for sensitive data and authentication tokens
4. **CORS Misconfiguration**: Test Cross-Origin Resource Sharing policies for unauthorized API access
5. **Authentication Flow Testing**: Analyze client-side authentication logic for bypass opportunities and token handling flaws
6. **API Endpoint Discovery**: Extract API endpoints from client-side code and test for authentication requirements
7. **State Management Analysis**: Test client-side state management (Redux, Vuex) for security-relevant data exposure
8. **Browser Security Headers**: Test for missing security headers (CSP, HSTS, X-Frame-Options) in SPA responses

DETECTION:
- API endpoints exposed in client-side code
- Sensitive data stored in browser storage
- CORS policies allow unauthorized origins
- Missing security headers

REMEDIATION:
- Remove sensitive data from client-side bundles
- Implement proper server-side authorization
- Restrict CORS to specific origins
- Apply comprehensive security headers

TOOLS:
- Chrome DevTools for bundle analysis
- Burp Suite for SPA traffic analysis
- LocalStorage inspector tools
- CORS testing utilities"#,
    ),
    (
        "OAuth 2.0 & OpenID Connect Abuse",
        r#"OBJECTIVE: Test OAuth 2.0 and OIDC implementations for redirect URI manipulation, scope abuse, and token injection vulnerabilities.

STEP-BY-STEP:
1. **Redirect URI Manipulation**: Test for open redirectors and redirect URI validation bypasses in OAuth flows
2. **Scope Elevation Testing**: Attempt to obtain elevated scopes through parameter manipulation and state confusion
3. **PKCE Bypass Testing**: Test Proof Key for Code Exchange implementation for bypass opportunities
4. **Token Injection**: Test for token injection vulnerabilities and token substitution attacks
5. **State Parameter Abuse**: Test state parameter validation for CSRF protection bypasses
6. **Implicit Flow Vulnerabilities**: Test deprecated implicit flow for token leakage and redirect abuses
7. **Client Authentication Testing**: Test client authentication methods for bypass opportunities
8. **Token Revocation Testing**: Test token revocation and refresh token security

DETECTION:
- Redirect URI accepts arbitrary URLs
- Scope elevation successful through manipulation
- PKCE can be bypassed or disabled
- State parameter validation weak

REMEDIATION:
- Implement strict redirect URI validation
- Enforce scope limitations and consent
- Use PKCE for public clients
- Validate state parameter properly

TOOLS:
- OAuth2 proxy for testing
- Burp Suite OAuth extension
- Custom redirect URI testing scripts
- OIDC debugging tools"#,
    ),
];

pub const WEBSOCKET_GRPC_STEPS: &[(&str, &str)] = &[
    (
        "WebSocket Enumeration & Reconnaissance",
        r#"OBJECTIVE: Discover WebSocket endpoints, analyze message protocols, and map real-time communication channels for security testing.

STEP-BY-STEP:
1. **WebSocket Discovery**: Use automated tools and manual analysis to find WebSocket endpoints (ws://, wss://) in JavaScript code and network traffic
2. **Protocol Analysis**: Capture and analyze WebSocket handshake process, including Upgrade headers and Sec-WebSocket-Key
3. **Message Format Discovery**: Reverse-engineer WebSocket message formats, protocols, and data structures
4. **Channel Enumeration**: Identify different WebSocket channels, rooms, or subscription topics
5. **Authentication Testing**: Test WebSocket authentication mechanisms and token validation
6. **Authorization Analysis**: Test authorization controls for different WebSocket operations and channels
7. **Rate Limiting Discovery**: Test for rate limiting and abuse prevention on WebSocket connections
8. **Cross-Origin Testing**: Test WebSocket cross-origin policies and same-origin restrictions

DETECTION:
- WebSocket endpoints discovered in application
- Message patterns reverse-engineered
- Authentication/authorization weaknesses found
- Rate limiting bypasses identified

REMEDIATION:
- Secure WebSocket endpoint discovery
- Implement proper authentication on connections
- Apply authorization checks to all operations
- Implement rate limiting and abuse prevention

TOOLS:
- WebSocket testing tools (wscat, websocat)
- Burp Suite with WebSocket support
- Chrome DevTools WebSocket inspector
- Custom WebSocket client scripts"#,
    ),
    (
        "WebSocket Message Injection & Manipulation",
        r#"OBJECTIVE: Test WebSocket message handling for injection vulnerabilities, protocol abuse, and unauthorized operations.

STEP-BY-STEP:
1. **Message Injection Testing**: Test for SQL injection, XSS, and command injection in WebSocket message content
2. **Protocol Abuse**: Test protocol-specific vulnerabilities and message format manipulation
3. **Authorization Bypass**: Test unauthorized operations through WebSocket message manipulation
4. **Message Replay**: Test message replay attacks and state manipulation through repeated messages
5. **Denial of Service**: Test for DoS conditions through message flooding, large messages, and malformed data
6. **Race Condition Testing**: Test for race conditions in concurrent WebSocket message handling
7. **Channel Hijacking**: Test for unauthorized channel access and message interception
8. **Data Exfiltration**: Test for data exfiltration through WebSocket channels

DETECTION:
- Injection vulnerabilities in message handling
- Unauthorized operations through message manipulation
- DoS conditions triggered by malformed messages
- Data exfiltration through WebSocket channels

REMEDIATION:
- Validate and sanitize all WebSocket messages
- Implement proper authorization for all operations
- Apply rate limiting and message size limits
- Monitor for abusive message patterns

TOOLS:
- WebSocket client libraries for custom testing
- Burp Suite WebSocket extension
- Message injection testing frameworks
- Custom WebSocket manipulation scripts"#,
    ),
    (
        "gRPC & Protocol Buffer Security Testing",
        r#"OBJECTIVE: Test gRPC services for authentication bypasses, authorization flaws, and protocol buffer manipulation vulnerabilities.

STEP-BY-STEP:
1. **gRPC Service Discovery**: Discover gRPC endpoints through service enumeration and reflection attacks
2. **Proto File Analysis**: Extract and analyze Protocol Buffer definitions for service interfaces and message structures
3. **Reflection Attack Testing**: Test gRPC reflection service for service discovery and method enumeration
4. **Authentication Bypass**: Test gRPC authentication mechanisms and token validation
5. **Authorization Testing**: Test authorization controls for different gRPC services and methods
6. **Message Manipulation**: Test Protocol Buffer message manipulation for injection and bypass opportunities
7. **TLS Configuration Testing**: Test gRPC TLS configuration for security weaknesses
8. **Rate Limiting Testing**: Test for rate limiting and abuse prevention on gRPC services

DETECTION:
- gRPC services discovered through reflection
- Authentication/authorization bypasses found
- Message manipulation vulnerabilities
- TLS configuration weaknesses

REMEDIATION:
- Disable gRPC reflection in production
- Implement proper authentication and authorization
- Validate all Protocol Buffer messages
- Secure TLS configuration for gRPC

TOOLS:
- grpcurl for gRPC service testing
- grpcui for interactive gRPC testing
- Protocol Buffer analysis tools
- Custom gRPC client implementations"#,
    ),
];

pub fn get_modern_api_steps() -> Vec<Step> {
    MODERN_API_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "api".to_string(),
                    "graphql".to_string(),
                    "owasp".to_string(),
                ],
            )
        })
        .collect()
}

pub fn get_jwt_spa_steps() -> Vec<Step> {
    JWT_SPA_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "authentication".to_string(),
                    "jwt".to_string(),
                    "spa".to_string(),
                ],
            )
        })
        .collect()
}

pub fn get_websocket_grpc_steps() -> Vec<Step> {
    WEBSOCKET_GRPC_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "real-time".to_string(),
                    "websocket".to_string(),
                    "grpc".to_string(),
                ],
            )
        })
        .collect()
}
