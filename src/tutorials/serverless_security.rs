/// Serverless Security tutorial phase
///
/// This module provides comprehensive serverless security tutorials,
/// covering AWS Lambda, Azure Functions, GCP Cloud Functions, event trigger
/// abuse, cold-start timing attacks, environment variable exposure, IAM
/// misconfiguration, and CI/CD security for serverless functions.
use crate::model::{QuizStep, Step};
use crate::quiz::parse_question_file;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DOMAIN_SERVERLESS_SECURITY: &str = "Serverless Security";
const QUIZ_FILE_PATH: &str = "data/serverless_security/serverless-security-quiz.txt";

pub const SERVERLESS_SECURITY_PHASE: &str = "Serverless Security";

pub const SERVERLESS_FUNCTION_STEPS: &[(&str, &str)] = &[
    (
        "Serverless Function Fundamentals",
        "OBJECTIVE: Understand serverless function architecture and identify potential security boundaries.

ACADEMIC BACKGROUND:
Serverless functions (FaaS) execute code in ephemeral containers managed by cloud providers. According to OWASP, serverless applications introduce unique security challenges due to their event-driven nature, shared infrastructure, and limited visibility.

Key Serverless Concepts:
- Function as a Service (FaaS): Code execution without managing servers
- Event triggers: HTTP requests, scheduled events, message queues, file uploads
- Runtime environments: Node.js, Python, Java, .NET, Go
- Cold starts: Initial execution latency when function is not cached
- Stateless execution: Functions should not rely on local state

STEP-BY-STEP:

1. ANALYZE FUNCTION ARCHITECTURE:

   a) Examine function deployment packages:
   ```bash
   # AWS Lambda - check deployment package contents
   aws lambda get-function --function-name my-function --query 'Code.Location'
   unzip -l deployment-package.zip

   # Azure Functions - examine function app structure
   az functionapp deployment source show --name myapp --resource-group mygroup

   # GCP Cloud Functions - inspect function source
   gcloud functions describe my-function --region=us-central1
   ```

   b) Review function configurations:
   ```bash
   # Check runtime, memory, timeout settings
   aws lambda get-function-configuration --function-name my-function
   az functionapp config show --name myapp --resource-group mygroup
   gcloud functions describe my-function --region=us-central1
   ```

2. IDENTIFY EVENT TRIGGERS:

   a) Map all function triggers:
   ```bash
   # AWS - list Lambda triggers
   aws lambda list-event-source-mappings --function-name my-function

   # Azure - check function bindings
   az functionapp config appsettings list --name myapp --resource-group mygroup

   # GCP - examine Cloud Function triggers
   gcloud functions event-types list
   ```

   b) Test trigger validation:
   ```bash
   # Send test events to functions
   aws lambda invoke --function-name my-function --payload '{\"test\":\"data\"}' response.json
   ```

WHAT TO LOOK FOR:
- Large deployment packages with unnecessary dependencies
- Functions with excessive memory/timeout allocations
- Unauthenticated HTTP triggers exposed to internet
- Functions triggered by sensitive events (S3 bucket changes, database updates)
- Runtime versions that are end-of-life or unpatched

COMMON PITFALLS:
- Avoid storing sensitive data in function code or environment variables
- Implement proper input validation for all event triggers
- Use least privilege IAM roles for function execution
- Monitor function execution logs and metrics
- Implement proper error handling to avoid information disclosure
- Consider function cold start impacts on security controls",
    ),
    (
        "Environment Variable & Secret Management",
        "OBJECTIVE: Identify and exploit environment variable exposure and secret management weaknesses.

ACADEMIC BACKGROUND:
Serverless functions commonly use environment variables for configuration, but these can leak sensitive information. Research from Cloud Security Alliance shows that misconfigured environment variables are a top serverless security risk.

Environment Variable Risks:
- API keys, database credentials, encryption keys
- Internal service URLs and ports
- Debug flags that enable verbose logging
- Configuration overrides that bypass security controls

STEP-BY-STEP:

1. ENUMERATE ENVIRONMENT VARIABLES:

   a) Check function environment configurations:
   ```bash
   # AWS Lambda environment variables
   aws lambda get-function-configuration --function-name my-function --query 'Environment.Variables'

   # Azure Functions app settings
   az functionapp config appsettings list --name myapp --resource-group mygroup

   # GCP Cloud Functions environment variables
   gcloud functions describe my-function --region=us-central1 --format='value(environmentVariables)'
   ```

   b) Review function logs for variable exposure:
   ```bash
   # AWS CloudWatch logs
   aws logs filter-log-events --log-group-name /aws/lambda/my-function --filter-pattern 'API_KEY|SECRET|PASSWORD'

   # Azure Application Insights
   az monitor app-insights query --app myapp --analytics-query 'traces | where message contains \"API_KEY\"'

   # GCP Cloud Logging
   gcloud logging read 'resource.type=cloud_function AND textPayload:(API_KEY OR SECRET)'
   ```

2. TEST VARIABLE INJECTION ATTACKS:

   a) Attempt environment variable override:
   ```bash
   # Test if client can override environment variables
   curl -X POST https://api.example.com/function \\
     -H 'X-Custom-Header: DEBUG=true' \\
     -d '{\"input\":\"test\"}'
   ```

   b) Check for variable leakage in error responses:
   ```bash
   # Trigger errors to see if environment variables are exposed
   curl -X POST https://api.example.com/function \\
     -d '{\"input\":\"invalid_data_to_cause_error\"}'
   ```

3. ASSESS SECRET MANAGEMENT:

   b) Check for hardcoded secrets in function code:
   ```bash
   # Scan deployment packages for secrets
   grep -r 'API_KEY\\|SECRET\\|PASSWORD' deployment-package/
   ```

   b) Verify secret rotation and access controls:
   ```bash
   # AWS Secrets Manager/Secrets Manager access
   aws secretsmanager list-secrets
   aws kms list-keys

   # Azure Key Vault
   az keyvault secret list --vault-name myvault

   # GCP Secret Manager
   gcloud secrets list
   ```

WHAT TO LOOK FOR:
- Environment variables containing sensitive data (API keys, passwords, tokens)
- Functions logging sensitive environment variables
- Client-controllable headers overriding environment variables
- Hardcoded secrets in function source code
- Missing encryption for sensitive environment variables
- Overly permissive IAM policies for secret access

COMMON PITFALLS:
- Never store secrets in plaintext environment variables
- Use cloud provider secret management services (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- Implement proper key rotation policies
- Avoid logging sensitive environment variables
- Use environment variable encryption at rest
- Implement least privilege access to secrets",
    ),
    (
        "IAM Misconfiguration & Privilege Escalation",
        "OBJECTIVE: Identify IAM misconfigurations that allow privilege escalation in serverless environments.

ACADEMIC BACKGROUND:
Serverless functions execute with IAM roles that can be overly permissive. According to AWS security research, misconfigured Lambda execution roles are responsible for 80% of serverless breaches.

IAM Security Concepts:
- Execution roles: Permissions granted to functions during execution
- Resource policies: Permissions on resources that functions can access
- Cross-account access: Functions accessing resources in other accounts
- Service roles vs. user roles: Different permission models

STEP-BY-STEP:

1. ANALYZE EXECUTION ROLE PERMISSIONS:

   a) Examine function execution roles:
   ```bash
   # AWS Lambda execution role
   aws lambda get-function-configuration --function-name my-function --query 'Role'
   aws iam list-attached-role-policies --role-name lambda-execution-role

   # Azure Functions managed identity
   az functionapp identity show --name myapp --resource-group mygroup
   az role assignment list --assignee my-identity-id

   # GCP Cloud Functions service account
   gcloud functions describe my-function --region=us-central1 --format='value(serviceAccountEmail)'
   gcloud iam service-accounts get-iam-policy my-service-account@project.iam.gserviceaccount.com
   ```

   b) Test privilege escalation paths:
   ```bash
   # Check if function can assume other roles
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/other-role --role-session-name test

   # Test cross-account access
   aws sts assume-role --role-arn arn:aws:iam::other-account:role/cross-account-role
   ```

2. REVIEW RESOURCE POLICIES:

   a) Check resource-based policies:
   ```bash
   # Lambda resource policies
   aws lambda get-policy --function-name my-function

   # S3 bucket policies allowing Lambda access
   aws s3api get-bucket-policy --bucket my-bucket

   # API Gateway resource policies
   aws apigateway get-rest-api --rest-api-id my-api --query 'policy'
   ```

   b) Test policy bypass techniques:
   ```bash
   # Attempt to invoke functions with overly permissive policies
   aws lambda invoke --function-name restricted-function --payload '{}' output.json
   ```

3. ASSESS CROSS-SERVICE ACCESS:

   a) Map service interactions:
   ```bash
   # Check VPC configurations for network isolation
   aws lambda get-function-configuration --function-name my-function --query 'VpcConfig'

   # Verify security groups and NACLs
   aws ec2 describe-security-groups --group-ids sg-12345
   ```

WHAT TO LOOK FOR:
- Execution roles with wildcard (*) permissions
- Functions that can assume high-privilege roles
- Resource policies allowing public access
- Missing VPC configurations for sensitive functions
- Cross-account IAM trust relationships
- Service accounts with domain-wide delegation (GCP)

COMMON PITFALLS:
- Use least privilege principle for execution roles
- Avoid wildcard permissions in IAM policies
- Implement resource-based policies for fine-grained access control
- Use IAM condition keys to restrict resource access
- Regularly audit and rotate access keys
- Implement multi-factor authentication for privileged operations",
    ),
    (
        "Event Trigger Abuse & Injection Attacks",
        "OBJECTIVE: Identify and exploit vulnerabilities in serverless event triggers and injection vectors.

ACADEMIC BACKGROUND:
Serverless functions are triggered by various events, creating attack surfaces for injection and abuse. Research shows that event-driven attacks account for 60% of serverless security incidents.

Event Trigger Types:
- HTTP API triggers (REST APIs, GraphQL)
- Message queue triggers (SQS, EventBridge, Service Bus)
- Storage triggers (S3, Blob Storage, Cloud Storage)
- Database triggers (DynamoDB, Cosmos DB, Firestore)
- Scheduled/cron triggers

STEP-BY-STEP:

1. MAP EVENT SOURCES:

   a) Enumerate all function triggers:
   ```bash
   # AWS Event sources
   aws lambda list-event-source-mappings
   aws events list-rules --query 'Rules[?State==`ENABLED`]'

   # Azure Event Grid subscriptions
   az eventgrid event-subscription list --topic-name mytopic

   # GCP Eventarc triggers
   gcloud eventarc triggers list
   ```

   b) Test trigger validation:
   ```bash
   # Send malformed events
   aws lambda invoke --function-name my-function \\
     --payload '{\"malicious\":\"<script>alert(1)</script>\"}' response.json
   ```

2. TEST INJECTION ATTACKS:

   a) SQL injection in database triggers:
   ```sql
   -- Test for SQL injection in DynamoDB streams
   INSERT INTO users (name, email) VALUES ('admin''--', 'hacker@example.com');
   ```

   b) XSS in HTTP triggers:
   ```bash
   # Test XSS in API Gateway
   curl -X POST https://api.example.com/function \\
     -d '{\"input\":\"<img src=x onerror=alert(1)>\"}'
   ```

   c) Command injection in processing functions:
   ```bash
   # Test command injection
   curl -X POST https://api.example.com/process \\
     -d '{\"filename\":\"../../../etc/passwd\"}'
   ```

3. ASSESS RATE LIMITING & DOS:

   a) Test function concurrency limits:
   ```bash
   # AWS Lambda concurrency
   aws lambda get-function-concurrency --function-name my-function

   # Flood function with requests
   for i in {1..1000}; do
     curl -X POST https://api.example.com/function -d '{}' &
   done
   ```

WHAT TO LOOK FOR:
- Unauthenticated API endpoints accepting arbitrary input
- Missing input validation and sanitization
- Functions processing untrusted event data
- Missing rate limiting on HTTP triggers
- Database triggers vulnerable to injection
- Event sources allowing cross-account access

COMMON PITFALLS:
- Implement strict input validation for all event data
- Use parameterized queries for database operations
- Sanitize HTML content in web-facing functions
- Implement rate limiting and request throttling
- Use API gateways with built-in security features
- Validate event source authenticity",
    ),
    (
        "Cold Start Timing Attacks & Side Channels",
        "OBJECTIVE: Exploit timing differences in serverless cold starts for information disclosure.

ACADEMIC BACKGROUND:
Cold starts occur when serverless functions execute for the first time or after inactivity. Research from USENIX Security shows timing differences can leak sensitive information through side channels.

Cold Start Characteristics:
- Initialization time: Loading runtime, dependencies, and code
- Container provisioning: Creating isolated execution environment
- Network latency: Establishing connections to external services
- Cache warming: Loading frequently accessed data

STEP-BY-STEP:

1. MEASURE COLD START TIMING:

   a) Monitor function execution times:
   ```bash
   # AWS CloudWatch metrics
   aws cloudwatch get-metric-statistics \\
     --namespace AWS/Lambda \\
     --metric-name Duration \\
     --dimensions Name=FunctionName,Value=my-function \\
     --start-time 2024-01-01T00:00:00Z \\
     --end-time 2024-01-02T00:00:00Z \\
     --period 3600 \\
     --statistics Average

   # Azure Application Insights
   az monitor metrics list \\
     --resource /subscriptions/.../functionapp/myapp \\
     --metric 'FunctionExecutionTime'
   ```

   b) Force cold starts and measure timing:
   ```bash
   # AWS - wait for function to become cold
   sleep 3600  # Wait for cold start
   time aws lambda invoke --function-name my-function --payload '{}' response.json

   # Measure multiple invocations
   for i in {1..10}; do
     time curl -X POST https://api.example.com/function -d '{}' -o /dev/null -w '%{time_total}\n'
     sleep 300  # Wait between requests
   done
   ```

2. EXPLOIT TIMING DIFFERENCES:

   a) Test conditional timing attacks:
   ```bash
   # Test timing differences based on input
   time curl -X POST https://api.example.com/auth \\
     -d '{\"username\":\"admin\",\"password\":\"wrong\"}'

   time curl -X POST https://api.example.com/auth \\
     -d '{\"username\":\"wrong\",\"password\":\"wrong\"}'
   ```

   b) Measure cache-based timing:
   ```bash
   # Test if function caches results
   time curl -X GET https://api.example.com/cache-test?key=known_value
   time curl -X GET https://api.example.com/cache-test?key=unknown_value
   ```

3. ANALYZE RESOURCE CONTENTION:

   a) Test concurrent execution timing:
   ```bash
   # Flood function to test resource limits
   for i in {1..50}; do
     curl -X POST https://api.example.com/function -d '{}' &
   done

   # Monitor execution times during high load
   aws lambda get-function-concurrency --function-name my-function
   ```

WHAT TO LOOK FOR:
- Significant timing differences between cold and warm starts
- Timing variations based on input validation results
- Cache hit/miss timing differences
- Resource exhaustion during concurrent execution
- Memory/CPU allocation affecting execution time
- Network latency variations in external service calls

COMMON PITFALLS:
- Avoid using execution time as a security control
- Implement consistent response times for authentication
- Use proper caching strategies to reduce cold start impact
- Monitor and alert on unusual timing patterns
- Implement request deduplication to prevent timing attacks
- Use provisioned concurrency for latency-sensitive functions",
    ),
    (
        "CI/CD Pipeline Security for Functions",
        "OBJECTIVE: Identify vulnerabilities in serverless deployment pipelines and supply chain attacks.

ACADEMIC BACKGROUND:
Serverless deployment pipelines can introduce security risks through compromised build processes, malicious dependencies, and insecure configurations. SolarWinds and Codecov incidents demonstrate the risks of supply chain attacks.

CI/CD Security Risks:
- Compromised build agents and runners
- Malicious dependencies in deployment packages
- Exposed deployment credentials
- Insecure artifact storage and distribution
- Lack of code signing and integrity checks

STEP-BY-STEP:

1. ANALYZE DEPLOYMENT PIPELINES:

   a) Review CI/CD configurations:
   ```bash
   # GitHub Actions workflows
   cat .github/workflows/deploy.yml

   # AWS CodePipeline
   aws codepipeline get-pipeline --name my-pipeline

   # Azure DevOps pipelines
   az pipelines show --name my-pipeline --organization https://dev.azure.com/myorg
   ```

   b) Check deployment credentials:
   ```bash
   # AWS IAM roles for deployment
   aws iam list-roles --query 'Roles[?RoleName==`lambda-deployment-role`]'

   # Check for exposed secrets
   grep -r 'AWS_ACCESS_KEY\\|AZURE_CLIENT_SECRET' .github/
   ```

2. INSPECT DEPENDENCY SECURITY:

   a) Scan for vulnerable dependencies:
   ```bash
   # Use dependency scanners
   npm audit
   pip-audit
   safety check

   # Check for malicious packages
   grep -r 'malicious-package' package.json requirements.txt
   ```

   b) Verify code signing:
   ```bash
   # AWS Lambda code signing
   aws lambda get-code-signing-config --code-signing-config-arn arn:aws:lambda:region:account:code-signing-config:my-config

   # Check signature verification
   aws lambda get-function --function-name my-function --query 'Code.SigningProfileVersionArn'
   ```

3. TEST SUPPLY CHAIN ATTACKS:

   a) Check artifact integrity:
   ```bash
   # Verify checksums
   sha256sum deployment-package.zip
   aws s3api head-object --bucket my-artifacts --key deployment-package.zip --query 'Metadata.sha256'

   # Test dependency confusion
   npm install @myorg/internal-package@latest  # Check if external package overrides internal
   ```

WHAT TO LOOK FOR:
- Hardcoded credentials in CI/CD configurations
- Use of untrusted third-party actions/workflows
- Missing dependency vulnerability scanning
- Unsigned deployment artifacts
- Overly permissive deployment roles
- Lack of multi-stage pipeline approvals

COMMON PITFALLS:
- Use secret management for deployment credentials
- Implement dependency scanning in CI/CD pipelines
- Sign and verify all deployment artifacts
- Use infrastructure as code for repeatable deployments
- Implement manual approval gates for production deployments
- Regularly rotate deployment credentials and tokens",
    ),
];

pub const SERVERLESS_QUIZ_STEPS: &[(&str, &str)] = &[
    (
        "Serverless Security Quiz",
        "Test your knowledge of serverless security concepts, vulnerabilities, and best practices across AWS Lambda, Azure Functions, and GCP Cloud Functions.",
    ),
];

/// Create serverless security quiz step from file
pub fn create_serverless_security_quiz_step() -> Result<Step, Box<dyn std::error::Error>> {
    let path = Path::new(QUIZ_FILE_PATH);
    let content = fs::read_to_string(path)?;
    let questions = parse_question_file(&content)?;

    let quiz_step = QuizStep::new(
        Uuid::new_v4(),
        "Serverless Security Quiz".to_string(),
        DOMAIN_SERVERLESS_SECURITY.to_string(),
        questions,
    );

    Ok(Step::new_quiz(
        Uuid::new_v4(),
        "Serverless Security Quiz".to_string(),
        vec![
            "quiz".to_string(),
            "serverless".to_string(),
            "lambda".to_string(),
            "functions".to_string(),
        ],
        quiz_step,
    ))
}

/// Build Serverless Security steps with quiz
pub fn get_serverless_security_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // Add serverless function steps
    for (title, description) in SERVERLESS_FUNCTION_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "serverless".to_string(),
                "security".to_string(),
                "lambda".to_string(),
                "functions".to_string(),
            ],
        ));
    }

    // Add quiz step
    match create_serverless_security_quiz_step() {
        Ok(quiz_step) => steps.push(quiz_step),
        Err(err) => eprintln!("Warning: Failed to load Serverless Security quiz: {err}"),
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverless_security_quiz_file_exists() {
        let path = Path::new(QUIZ_FILE_PATH);
        assert!(path.exists(), "Serverless security quiz file should exist");
    }

    #[test]
    fn test_serverless_security_quiz_minimum_questions() {
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
    fn test_get_serverless_security_steps_returns_steps() {
        let steps = get_serverless_security_steps();

        // Should have tutorial steps + quiz step
        assert!(
            steps.len() >= 7, // 6 tutorial + 1 quiz
            "Should have at least 7 steps (6 tutorial + 1 quiz), found {}",
            steps.len()
        );
    }

    #[test]
    fn test_quiz_step_creation() {
        let quiz_result = create_serverless_security_quiz_step();
        assert!(quiz_result.is_ok(), "Quiz step creation should succeed");

        let quiz_step = quiz_result.unwrap();
        assert!(quiz_step.is_quiz(), "Quiz step should have quiz data");
        }
        }
