/// Cloud & Identity Security Fundamentals tutorial phase
///
/// This module provides foundational cloud security and identity testing methodology,
/// covering IAM privilege escalation, cloud storage misconfigurations, and SSO/OAuth/Federation attacks.
///
/// Content focuses on modern cloud environments (AWS, Azure, GCP) and identity protocols
/// (OAuth 2.0, OIDC, SAML).
use crate::model::{QuizStep, Step};
use crate::quiz::parse_question_file;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DOMAIN_CLOUD_IDENTITY: &str = "Cloud & Identity Security";
const QUIZ_FILE_PATH: &str = "data/cloud_identity/cloud-iam-quiz.txt";

pub const CLOUD_IDENTITY_STEPS: &[(&str, &str)] = &[
    (
        "Cloud IAM Abuse 101",
        "OBJECTIVE: Understand cloud Identity and Access Management (IAM) principles and identify common privilege escalation patterns across AWS, Azure, and GCP.

ACADEMIC BACKGROUND:
Cloud IAM systems control access to resources through policies that define who can perform which actions on what resources. According to MITRE ATT&CK Cloud Matrix, privilege escalation via IAM misconfigurations is one of the most common cloud attack vectors (T1078 - Valid Accounts, T1548 - Abuse Elevation Control Mechanism).

The principle of least privilege is often violated in cloud environments due to:
- Over-permissive wildcard policies (Resource: *, Action: *)
- Misuse of administrative roles for routine tasks
- Lack of conditional access controls (MFA, IP restrictions)
- Excessive trust relationships between accounts/subscriptions

STEP-BY-STEP PROCESS:

1. IAM FUNDAMENTALS BY CLOUD PROVIDER:

   a) AWS IAM Core Concepts:
      - Users: Permanent identities with credentials
      - Roles: Temporary credentials assumed by users/services
      - Policies: JSON documents defining permissions
      - Groups: Collections of users inheriting policies
      - STS (Security Token Service): Issues temporary credentials
      
      Key Actions for Privilege Escalation:
      - iam:PassRole → Pass privileged role to services (Lambda, EC2)
      - iam:CreatePolicyVersion → Modify existing policies
      - iam:AttachUserPolicy → Grant yourself new permissions
      - sts:AssumeRole → Switch to more privileged role
      - iam:PutUserPolicy → Add inline policy to user
      
      Example:
      ```bash
      # Enumerate your current permissions
      aws iam get-user --profile audit
      aws iam list-attached-user-policies --user-name analyst
      
      # List all roles and their trust relationships
      aws iam list-roles | jq '.Roles[] | {Name: .RoleName, AssumeRolePolicyDocument}'
      
      # Check if you can assume a privileged role
      aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AdminRole --role-session-name test
      ```

   b) Azure IAM (RBAC) Core Concepts:
      - Azure AD: Cloud-native identity provider
      - Service Principals: Application identities
      - Managed Identities: System/user-assigned identities for Azure resources
      - Role Definitions: Sets of permissions (Owner, Contributor, Reader, custom)
      - Role Assignments: Binds principals to roles at scopes (subscription, resource group, resource)
      
      Key Actions for Privilege Escalation:
      - Microsoft.Authorization/roleAssignments/write → Grant roles
      - Microsoft.Authorization/roleDefinitions/write → Create custom roles
      - Microsoft.Compute/virtualMachines/extensions/write → Run code on VMs
      - Microsoft.ManagedIdentity/userAssignedIdentities/assign/action → Assume identities
      
      Example:
      ```bash
      # Check your current identity and subscriptions
      az account show
      az account list --all
      
      # List role assignments for yourself
      az role assignment list --assignee $(az ad signed-in-user show --query objectId -o tsv)
      
      # Search for high-privilege assignments
      az role assignment list --all | jq '[.[] | select(.roleDefinitionName==\"Owner\")]'
      ```

   c) GCP IAM Core Concepts:
      - Projects: Primary resource container and billing unit
      - Service Accounts: Bot identities with keys
      - Roles: Collections of permissions (primitive, predefined, custom)
      - IAM Bindings: Attach members to roles at resource hierarchy (org, folder, project, resource)
      
      Key Actions for Privilege Escalation:
      - iam.serviceAccounts.actAs → Impersonate service accounts
      - iam.serviceAccountKeys.create → Create keys for privileged accounts
      - resourcemanager.projects.setIamPolicy → Grant yourself owner
      - iam.roles.update → Modify custom role permissions
      
      Example:
      ```bash
      # Check your current identity and projects
      gcloud auth list
      gcloud projects list
      
      # Get IAM policy for a project
      gcloud projects get-iam-policy PROJECT_ID
      
      # Check service accounts you can impersonate
      gcloud iam service-accounts list
      ```

2. DANGEROUS PERMISSION PATTERNS:

   AWS Examples:
   ```json
   {
     \"Effect\": \"Allow\",
     \"Action\": \"*\",
     \"Resource\": \"*\"
   }
   → Full administrative access
   
   {
     \"Effect\": \"Allow\",
     \"Action\": \"iam:PassRole\",
     \"Resource\": \"*\"
   }
   → Can pass any role to services, potential for privilege escalation
   
   {
     \"Effect\": \"Allow\",
     \"Action\": \"sts:AssumeRole\",
     \"Resource\": \"*\"
   }
   → Can assume any role without MFA or IP restrictions
   ```

   Azure Examples:
   - Custom role with Microsoft.Authorization/* → Can manage all RBAC
   - Owner at subscription scope → Full control including role assignments
   - User Access Administrator → Can grant roles without resource permissions

   GCP Examples:
   - roles/owner at project level → Complete control
   - iam.serviceAccountKeys.create + actAs → Create keys for privileged accounts
   - Bindings with allUsers or allAuthenticatedUsers → Public access

3. ENUMERATION METHODOLOGY:

   AWS Reconnaissance:
   ```bash
   # Install ScoutSuite for multi-cloud auditing
   pip install scoutsuite
   scout aws --profile audit-profile
   
   # Or use Prowler for AWS-specific checks
   prowler aws -f us-east-1
   
   # Manual enumeration
   aws iam get-account-authorization-details > aws-iam-full.json
   aws iam generate-credential-report
   aws iam get-credential-report --decode > credential-report.csv
   ```

   Azure Reconnaissance:
   ```bash
   # Use AzureHound for AD enumeration
   . ./azurehound.ps1
   Invoke-AzureHound -Verbose
   
   # Or az CLI for targeted queries
   az ad user list --query \"[].{UPN:userPrincipalName, ObjectId:objectId}\"
   az role assignment list --all --include-inherited > azure-rbac.json
   az ad sp list --all --query \"[].{DisplayName:displayName, AppId:appId}\"
   ```

   GCP Reconnaissance:
   ```bash
   # Enumerate projects and their IAM
   for project in $(gcloud projects list --format=\"value(projectId)\"); do
     echo \"Project: $project\"
     gcloud projects get-iam-policy $project > iam_$project.json
   done
   
   # List service accounts across projects
   gcloud iam service-accounts list --project PROJECT_ID
   ```

4. PRIVILEGE ESCALATION PATHS:

   Common Escalation Chains:
   
   a) AWS: Lambda Privilege Escalation
      - User has iam:PassRole + lambda:CreateFunction
      - Create Lambda with privileged role
      - Execute Lambda to perform admin actions
      
   b) Azure: Managed Identity Abuse
      - User has VM Contributor on a VM with Managed Identity
      - Access VM metadata endpoint from within VM
      - Obtain token for Managed Identity with higher privileges
      
   c) GCP: Service Account Key Creation
      - User has iam.serviceAccountKeys.create on privileged SA
      - Create key for service account with Owner role
      - Authenticate as service account and gain full access

5. LAB SCENARIO - Safe Privilege Escalation Testing:

   Prerequisites:
   - Isolated cloud account/project for testing
   - Written authorization and documented test boundaries
   - Audit logging enabled (CloudTrail, Azure Monitor, Cloud Logging)
   - Ability to restore original state

   Step-by-Step Lab:
   
   1. Setup:
      ```bash
      # AWS: Create test role with escalation path
      aws iam create-role --role-name TestRole --assume-role-policy-document file://trust-policy.json
      aws iam attach-role-policy --role-name TestRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
      
      # Create analyst user with sts:AssumeRole
      aws iam create-user --user-name test-analyst
      aws iam attach-user-policy --user-name test-analyst --policy-arn arn:aws:iam::aws:policy/SecurityAudit
      ```
   
   2. Enumerate from analyst perspective:
      ```bash
      aws iam list-roles --profile test-analyst > roles.json
      jq '.Roles[] | select(.AssumeRolePolicyDocument | contains(\"test-analyst\"))' roles.json
      ```
   
   3. Attempt escalation:
      ```bash
      aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TestRole --role-session-name PoC --profile test-analyst
      # If successful, export credentials and test admin actions
      ```
   
   4. Validate detection:
      ```bash
      aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=test-analyst
      # Confirm AssumeRole event was logged
      ```
   
   5. Cleanup:
      ```bash
      aws iam delete-user --user-name test-analyst
      aws iam delete-role --role-name TestRole
      ```

6. DETECTION AND DEFENSE:

   Monitoring:
   - AWS: CloudTrail for iam:*, sts:AssumeRole, policy modifications
   - Azure: Azure AD Audit Logs for role assignments, PIM activations
   - GCP: Cloud Logging for serviceAccount.keys.create, setIamPolicy
   
   Prevention:
   - Enforce least privilege with regular access reviews
   - Require MFA for sensitive operations (AWS IAM Conditions, Azure Conditional Access)
   - Use SCPs/Azure Policies/Org Policies to deny dangerous actions
   - Implement break-glass procedures for true emergencies
   - Enable just-in-time access (AWS SSO, Azure PIM, GCP temporary grants)

TOOLS AND RESOURCES:
- ScoutSuite: Multi-cloud security auditing (https://github.com/nccgroup/ScoutSuite)
- Prowler: AWS security assessment (https://github.com/prowler-cloud/prowler)
- Pacu: AWS exploitation framework (https://github.com/RhinoSecurityLabs/pacu)
- AzureHound: Azure AD enumeration for BloodHound (https://github.com/BloodHoundAD/AzureHound)
- CloudSplaining: AWS IAM assessment (https://github.com/salesforce/cloudsplaining)
- IAM-Viz: Visualize IAM policies (https://github.com/duo-labs/iamviz)

REFERENCES:
- Rhino Security Labs: AWS Privilege Escalation Methods (https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- MITRE ATT&CK Cloud Matrix: (https://attack.mitre.org/matrices/enterprise/cloud/)
- AWS IAM Security Best Practices: (https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- Azure RBAC Best Practices: (https://learn.microsoft.com/azure/role-based-access-control/best-practices)
- GCP IAM Security Guide: (https://cloud.google.com/iam/docs/using-iam-securely)

For hands-on lab instructions and automated tooling, refer to the 'cloud-iam-priv-esc-playbook' in the Tool Instructions panel."
    ),
    (
        "Cloud Storage Misconfigurations",
        "OBJECTIVE: Identify and safely validate exposed cloud storage resources (AWS S3, Azure Blob, Google Cloud Storage) while documenting impact without causing data loss.

ACADEMIC BACKGROUND:
Cloud object storage services are designed for scalability and programmatic access, which often leads to security misconfiguration. According to the Cloud Security Alliance, misconfigured storage is among the top cloud threats due to:
- Default-public or overly permissive access controls
- Confusion between authenticated-user and public access
- Lack of encryption at rest
- Public listing enabling reconnaissance

MITRE ATT&CK maps storage enumeration to:
- T1580: Cloud Infrastructure Discovery
- T1530: Data from Cloud Storage Object
- T1213: Data from Information Repositories

STEP-BY-STEP PROCESS:

1. CLOUD STORAGE FUNDAMENTALS:

   a) AWS S3 (Simple Storage Service):
      - Buckets: Global namespace containers (must be unique)
      - Objects: Files stored in buckets with keys (paths)
      - ACLs: Legacy access control lists (per-bucket or per-object)
      - Bucket Policies: JSON policies similar to IAM
      - Block Public Access: Org/account/bucket-level overrides
      - Signed URLs: Time-limited presigned URLs for temporary access
      
      Permission Levels:
      - FULL_CONTROL: All permissions
      - READ: List objects
      - WRITE: Create/overwrite objects
      - READ_ACP/WRITE_ACP: Read/modify ACLs
      
      Common Misconfigurations:
      - Principal: * in bucket policy
      - Public READ permission via ACL
      - Block Public Access disabled
      - Objects individually set to public

   b) Azure Blob Storage:
      - Storage Accounts: Parent resource
      - Containers: Collections of blobs (similar to S3 buckets)
      - Blobs: Block, Append, or Page blobs
      - Access Tiers: Hot, Cool, Archive
      - SAS (Shared Access Signature): Delegated access tokens
      
      Access Levels:
      - Private: No anonymous access
      - Blob: Public read access to blobs only
      - Container: Public read access to container and blobs
      
      Common Misconfigurations:
      - Container set to public access
      - Overly permissive SAS tokens with long expiry
      - Allow Blob Public Access enabled at storage account level

   c) Google Cloud Storage:
      - Buckets: Globally unique containers
      - Objects: Files with metadata
      - IAM: Unified permission model
      - ACLs: Legacy (not recommended)
      - Signed URLs: Time-limited access
      - Uniform bucket-level access: Disables ACLs, enforces IAM only
      
      Special Members:
      - allUsers: Anyone on the internet
      - allAuthenticatedUsers: Any authenticated Google account
      
      Common Misconfigurations:
      - Bindings with allUsers or allAuthenticatedUsers
      - Legacy ACLs with public access
      - Uniform bucket-level access not enabled

2. ENUMERATION TECHNIQUES:

   a) Passive Reconnaissance:
      ```bash
      # Certificate Transparency for storage domains
      curl -s \"https://crt.sh/?q=%.target.com&output=json\" | jq -r '.[].name_value' | grep -E 's3|blob|storage'
      
      # Google dorking
      site:s3.amazonaws.com \"target\"
      site:blob.core.windows.net \"target\"
      site:storage.googleapis.com \"target\"
      
      # GitHub code search
      org:target \"s3.amazonaws.com\" OR \"blob.core.windows.net\"
      ```

   b) DNS Enumeration:
      ```bash
      # Check for S3 bucket DNS records
      dig target-backups.s3.amazonaws.com
      dig target-logs.s3-us-west-2.amazonaws.com
      
      # Check Azure storage endpoints
      dig targetdata.blob.core.windows.net
      
      # Check GCS buckets
      dig storage.googleapis.com
      # Note: GCS uses storage.googleapis.com/bucket-name URL pattern
      ```

   c) Active Probing:
      ```bash
      # Install cloud storage scanners
      pip install s3scanner
      go install github.com/sa7mon/S3Scanner@latest
      
      # Test S3 bucket access
      aws s3 ls s3://target-bucket --no-sign-request
      aws s3api get-bucket-acl --bucket target-bucket
      
      # Test Azure blob container
      az storage blob list --account-name targetaccount --container-name public --auth-mode login
      
      # Test GCS bucket
      gsutil ls gs://target-bucket
      gsutil ls -L -b gs://target-bucket  # Get bucket metadata
      ```

3. MISCONFIGURATION DETECTION:

   AWS S3 Tests:
   ```bash
   # Check if bucket allows listing without credentials
   aws s3 ls s3://target-bucket --no-sign-request
   
   # Get bucket ACL
   aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
   
   # Get bucket policy
   aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
   
   # Check block public access settings
   aws s3api get-public-access-block --bucket target-bucket
   
   # Attempt to list objects
   curl -I https://target-bucket.s3.amazonaws.com/
   
   # Try to access known object
   curl -I https://target-bucket.s3.amazonaws.com/config.json
   ```

   Azure Blob Tests:
   ```bash
   # Check container public access (unauthenticated)
   curl -I https://targetaccount.blob.core.windows.net/public?restype=container&comp=list
   
   # Try to list blobs
   az storage blob list --account-name targetaccount --container-name public --auth-mode key
   
   # Check storage account properties
   az storage account show --name targetaccount --resource-group targetrg
   ```

   GCS Tests:
   ```bash
   # Attempt unauthenticated listing
   curl -I https://storage.googleapis.com/target-bucket/
   
   # Get bucket IAM policy
   gsutil iam get gs://target-bucket
   
   # Check for allUsers or allAuthenticatedUsers
   gsutil iam ch allUsers:objectViewer gs://target-bucket  # This would grant access (don't run on real targets!)
   ```

4. SAFE VALIDATION METHODOLOGY:

   Authorization Requirements:
   - Written permission to test specific buckets/containers
   - Documented scope (read-only vs. read-write testing)
   - Approval to download sample files for evidence
   - Agreement on data handling and destruction

   Read-Only Testing:
   ```bash
   # List objects without downloading
   aws s3api list-objects-v2 --bucket target-bucket --max-items 10 --no-sign-request
   
   # Get object metadata only
   aws s3api head-object --bucket target-bucket --key path/to/file.txt --no-sign-request
   
   # Count objects
   aws s3 ls s3://target-bucket --recursive --no-sign-request | wc -l
   ```

   Evidence Collection:
   ```bash
   # Screenshot CLI output
   script -c 'aws s3 ls s3://target-bucket --no-sign-request' evidence_s3_listing.txt
   
   # Download benign sample files only if authorized
   aws s3 cp s3://target-bucket/README.md ./evidence/ --no-sign-request
   
   # Generate hash for reference
   sha256sum evidence/README.md > evidence/file-hashes.txt
   ```

5. IMPACT ASSESSMENT:

   Data Classification:
   - Public: No sensitivity (marketing materials, public docs)
   - Internal: Not public but low sensitivity (internal docs)
   - Confidential: Business-critical data (financials, strategies)
   - Restricted: PII, PHI, PCI data requiring compliance

   Risk Matrix:
   | Data Type | Public Read | Public Write | Risk Level |
   |-----------|-------------|--------------|------------|
   | Public    | Expected    | High         | Low/Medium |
   | Internal  | High        | Critical     | Medium/High|
   | Confidential | Critical | Critical     | High       |
   | Restricted | Critical   | Critical     | Critical   |

   Example Findings:
   - S3 bucket with 10,000 objects, 500 containing PII → Critical
   - Azure container with backups of production database → High
   - GCS bucket with public marketing images → Low (if intended)

6. LAB SCENARIO - Controlled Storage Exposure Test:

   Setup:
   ```bash
   # Create intentionally misconfigured S3 bucket in lab account
   aws s3 mb s3://lab-public-test-$RANDOM
   aws s3api put-bucket-acl --bucket lab-public-test --acl public-read
   
   # Upload sample data
   echo \"Lab Test Data - Not Sensitive\" > lab-sample.txt
   aws s3 cp lab-sample.txt s3://lab-public-test/
   ```

   Testing:
   ```bash
   # Test from different network without credentials
   aws s3 ls s3://lab-public-test --no-sign-request
   
   # Validate anonymous access
   curl https://lab-public-test.s3.amazonaws.com/lab-sample.txt
   ```

   Remediation:
   ```bash
   # Enable block public access
   aws s3api put-public-access-block --bucket lab-public-test --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   
   # Remove public ACL
   aws s3api put-bucket-acl --bucket lab-public-test --acl private
   
   # Verify closure
   aws s3 ls s3://lab-public-test --no-sign-request  # Should fail
   ```

   Cleanup:
   ```bash
   aws s3 rb s3://lab-public-test --force
   ```

7. REMEDIATION GUIDANCE:

   AWS S3:
   - Enable Block Public Access at account and bucket levels
   - Use bucket policies with explicit principals (not *)
   - Enable access logging to track who accessed what
   - Use S3 Access Analyzer to identify publicly accessible buckets
   - Implement least-privilege IAM policies
   - Enable versioning and MFA delete for critical buckets

   Azure Blob:
   - Set containers to private access
   - Disable \"Allow Blob Public Access\" at storage account level
   - Use short-lived SAS tokens with minimal permissions
   - Enable storage account logging
   - Implement network restrictions (firewall, VNet service endpoints)
   - Enable soft delete for recovery

   GCS:
   - Enable uniform bucket-level access (disables ACLs)
   - Remove allUsers and allAuthenticatedUsers bindings
   - Use signed URLs with short expiry
   - Enable Cloud Storage audit logging
   - Implement Organization Policies to enforce security
   - Use customer-managed encryption keys (CMEK)

TOOLS AND RESOURCES:
- S3Scanner: https://github.com/sa7mon/S3Scanner
- cloud_enum: https://github.com/initstring/cloud_enum
- ScoutSuite: Multi-cloud security auditing
- Prowler: AWS-specific checks including S3
- Azure Storage Explorer: GUI tool for Azure storage
- gsutil: Google Cloud Storage CLI

REFERENCES:
- AWS S3 Security Best Practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- Azure Storage Security Guide: https://learn.microsoft.com/azure/storage/blobs/security-recommendations
- GCP Cloud Storage Security: https://cloud.google.com/storage/docs/best-practices
- OWASP Cloud Security: https://owasp.org/www-project-cloud-security/

For detailed workflow and automation scripts, refer to the 'cloud-storage-misconfig-playbook' in the Tool Instructions panel."
    ),
    (
        "SSO, OAuth 2.0 & OIDC Misconfigurations",
        "OBJECTIVE: Test modern authentication protocols (OAuth 2.0, OpenID Connect, SAML) for common misconfigurations including redirect URI validation, token handling, scope abuse, and session management issues.

ACADEMIC BACKGROUND:
Single Sign-On (SSO) and federated authentication enable users to access multiple applications with one set of credentials. The two dominant protocols are:
- OAuth 2.0: Authorization framework for API access
- OpenID Connect (OIDC): Identity layer on top of OAuth 2.0
- SAML 2.0: XML-based federation protocol (covered in federation-attack-scenarios)

According to the OAuth 2.0 Threat Model (RFC 6819) and OWASP, common vulnerabilities include:
- Open redirects via redirect_uri parameter
- Missing or weak state parameter (CSRF)
- Token leakage through referrer headers
- Insufficient scope validation
- Missing PKCE (Proof Key for Code Exchange) for mobile apps

MITRE ATT&CK mappings:
- T1078: Valid Accounts (stolen tokens)
- T1550: Use Alternate Authentication Material (OAuth tokens)
- T1539: Steal Web Session Cookie

STEP-BY-STEP PROCESS:

1. OAUTH 2.0 & OIDC FUNDAMENTALS:

   Key Terminology:
   - Resource Owner: User who owns the data
   - Client: Application requesting access
   - Authorization Server: Issues tokens (Auth0, Okta, Azure AD)
   - Resource Server: API that requires access token
   - Scope: Permissions requested (read, write, admin)

   OAuth 2.0 Flows:
   
   a) Authorization Code Flow (most secure):
      1. Client redirects user to Authorization Server with client_id, redirect_uri, scope, state
      2. User authenticates and consents
      3. Authorization Server redirects back with authorization code
      4. Client exchanges code for access token (+ refresh token)
      5. Client uses access token to call Resource Server
   
   b) Implicit Flow (deprecated, less secure):
      - Access token returned directly in URL fragment
      - No client authentication
      - Vulnerable to token leakage
   
   c) Client Credentials Flow:
      - Service-to-service authentication
      - No user involvement
      - Client authenticates with client_id and client_secret

   OpenID Connect Additions:
   - ID Token: JWT containing user identity claims (sub, name, email)
   - UserInfo Endpoint: Returns additional user claims
   - Standard scopes: openid, profile, email

2. CRITICAL PARAMETERS AND THEIR SECURITY IMPLICATIONS:

   redirect_uri:
   - MUST be validated against pre-registered list
   - Common attack: Manipulate to attacker-controlled domain
   - Exploitation: Steal authorization code or access token
   
   state:
   - Random value to prevent CSRF
   - Must be unique per request and validated on callback
   - Missing state allows attacker to initiate login on victim's behalf
   
   nonce:
   - Used in OIDC to bind ID token to client request
   - Prevents token replay attacks
   - Should be random and validated
   
   scope:
   - Defines requested permissions
   - Should be minimal (least privilege)
   - Dangerous scopes: offline_access (refresh tokens), admin, write
   
   response_type:
   - Determines which flow is used
   - code: Authorization code flow (secure)
   - token: Implicit flow (vulnerable to leakage)
   - id_token: OIDC implicit flow
   
   PKCE (Proof Key for Code Exchange):
   - code_challenge: SHA-256 hash of random code_verifier
   - code_verifier: Sent during token exchange
   - Prevents authorization code interception
   - REQUIRED for public clients (mobile, SPA)

3. ENUMERATION AND RECONNAISSANCE:

   Discovery:
   ```bash
   # OIDC Discovery Document
   curl https://idp.example.com/.well-known/openid-configuration | jq
   
   # Key fields:
   # - issuer: Identity provider identifier
   # - authorization_endpoint: Where to send auth requests
   # - token_endpoint: Where to exchange code for token
   # - jwks_uri: Public keys for token verification
   # - scopes_supported: Available scopes
   # - grant_types_supported: Supported OAuth flows
   ```

   Manual Testing Setup:
   ```bash
   # Install Burp Suite or OWASP ZAP
   # Configure browser to use proxy (localhost:8080)
   # Enable SSL interception with proxy CA certificate
   
   # Perform baseline login and capture traffic:
   # 1. Authorization request
   # 2. User authentication
   # 3. Authorization response (callback)
   # 4. Token exchange
   # 5. API requests with access token
   ```

4. COMMON VULNERABILITIES AND TESTING:

   a) Open Redirect via redirect_uri:
      
      Attack Scenario:
      ```
      Original:
      https://idp.example.com/authorize?
        client_id=app123&
        redirect_uri=https://app.example.com/callback&
        response_type=code&state=xyz
      
      Manipulated:
      https://idp.example.com/authorize?
        client_id=app123&
        redirect_uri=https://attacker.com/callback&
        response_type=code&state=xyz
      ```
      
      Expected Behavior: Authorization server rejects non-registered redirect_uri
      Vulnerable Behavior: Authorization server accepts attacker URI, sends code to attacker
      
      Testing:
      ```bash
      # Try subdomain variations
      redirect_uri=https://evil.app.example.com/callback
      
      # Try path traversal
      redirect_uri=https://app.example.com/callback/../../../attacker.com
      
      # Try open redirect chains
      redirect_uri=https://app.example.com/redirect?url=https://attacker.com
      ```

   b) Missing or Weak state Parameter:
      
      Attack: CSRF on OAuth login
      1. Attacker initiates OAuth flow and gets authorization URL with state=abc
      2. Victim clicks attacker's link (without completing auth)
      3. Victim ends up logged in as attacker
      
      Testing:
      ```bash
      # Remove state parameter
      https://idp.example.com/authorize?client_id=app123&redirect_uri=...&response_type=code
      
      # Replay old state value
      # Use same state across multiple requests
      
      # Check if state is validated on callback
      # Manipulate state in callback URL
      ```

   c) Token Leakage:
      
      Implicit Flow Token in URL:
      ```
      https://app.example.com/callback#access_token=SECRET&token_type=Bearer
      ```
      - Tokens in URL fragments are visible in browser history
      - Can be leaked via Referer header if app navigates
      - Vulnerable to XSS attacks
      
      Testing:
      - Check if app uses implicit flow (response_type=token)
      - Inspect browser history for access tokens
      - Check if tokens appear in server logs (they shouldn't)

   d) Insufficient Scope Validation:
      
      Attack: Request excessive scopes
      ```bash
      # Normal request
      scope=openid profile email
      
      # Escalation attempt
      scope=openid profile email admin offline_access
      ```
      
      Testing:
      - Request additional scopes not normally available
      - Check if consent screen shows all scopes
      - Verify Resource Server validates token scopes
      - Test scope downgrade (remove expected scopes)

   e) Missing PKCE (Public Clients):
      
      Attack: Authorization code interception
      - Attacker intercepts code from mobile app
      - Exchanges code for access token
      
      Testing:
      ```bash
      # Check if PKCE is used
      # Authorization request should include:
      code_challenge=BASE64URL(SHA256(random_string))
      code_challenge_method=S256
      
      # Token exchange should include:
      code_verifier=random_string
      
      # Test if server enforces PKCE
      # Try omitting code_challenge or using mismatched verifier
      ```

5. ID TOKEN AND ACCESS TOKEN ANALYSIS:

   JWT Structure:
   - Header: Algorithm, token type
   - Payload: Claims (sub, iss, aud, exp, iat, nonce)
   - Signature: Cryptographic signature

   Analysis Tools:
   ```bash
   # Install JWT tools
   pip install pyjwt jwt_tool
   
   # Decode ID token
   python3 jwt_tool.py id_token.jwt
   
   # Verify signature
   python3 jwt_tool.py id_token.jwt -V -pk public_key.pem
   ```

   Key Checks:
   ```bash
   # Validate issuer (iss claim)
   # Should match expected identity provider
   
   # Validate audience (aud claim)
   # Should match your application's client_id
   
   # Check expiration (exp claim)
   # Tokens should have short lifetimes (minutes to hours)
   
   # Verify algorithm (alg in header)
   # Should be RS256 or ES256, NOT HS256 for ID tokens
   # NEVER \"none\" algorithm
   ```

   Common JWT Vulnerabilities:
   - Algorithm confusion (RS256 → HS256)
   - None algorithm accepted
   - Weak signing key
   - Missing expiration validation
   - Audience not validated

6. SESSION MANAGEMENT TESTING:

   Cookie Security:
   ```bash
   # Check session cookie attributes
   Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict
   
   # Required flags:
   # - Secure: Only sent over HTTPS
   # - HttpOnly: Not accessible via JavaScript (XSS protection)
   # - SameSite: CSRF protection
   ```

   Logout Testing:
   ```bash
   # Capture access token and refresh token
   # Trigger logout
   # Attempt to use tokens after logout
   # Expected: Tokens should be invalidated
   
   # Test single logout vs. global logout
   # Check if logout revokes refresh tokens
   # Verify logout redirects are validated
   ```

7. LAB SCENARIO - OAuth Misconfiguration Testing:

   Setup Lab Environment:
   ```bash
   # Use OAuth testing playground
   # Option 1: https://oauth.com/playground/
   # Option 2: Deploy local Keycloak
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
   
   # Configure test client with intentional misconfigurations
   # - Allow http:// redirect URIs
   # - Enable implicit flow
   # - Disable PKCE requirement
   ```

   Testing Workflow:
   ```bash
   # 1. Baseline OAuth flow
   # Capture complete auth code flow in Burp/ZAP
   
   # 2. Test redirect_uri validation
   # Modify redirect_uri parameter to attacker.com
   # Try subdomain variations
   
   # 3. Test state validation
   # Remove state parameter
   # Replay old state value
   
   # 4. Test PKCE enforcement
   # Omit code_challenge
   # Use mismatched code_verifier
   
   # 5. Test token handling
   # Decode JWT tokens
   # Check expiration times
   # Attempt token replay
   
   # 6. Test logout
   # Verify token revocation
   # Test refresh token invalidation
   ```

8. REMEDIATION BEST PRACTICES:

   Authorization Server:
   - Strict redirect_uri validation (exact match, no wildcards)
   - Require state and nonce parameters
   - Enforce PKCE for all public clients
   - Issue short-lived access tokens (15 minutes)
   - Implement refresh token rotation
   - Validate token audience and issuer
   - Use RS256 or ES256 for token signing
   - Implement rate limiting on token endpoint

   Client Application:
   - Use authorization code flow with PKCE
   - Validate state and nonce on callback
   - Verify token signatures
   - Check token expiration
   - Store tokens securely (not in localStorage for SPAs)
   - Implement token refresh logic
   - Validate redirect destinations on logout
   - Set proper cookie flags

TOOLS AND RESOURCES:
- Burp Suite: Web proxy with OAuth extensions
- OWASP ZAP: Free alternative to Burp
- jwt_tool: JWT manipulation and analysis (https://github.com/ticarpi/jwt_tool)
- OAuth 2.0 Playground: https://www.oauth.com/playground/
- Keycloak: Open-source identity provider for labs

REFERENCES:
- OAuth 2.0 RFC 6749: https://tools.ietf.org/html/rfc6749
- OAuth 2.0 Threat Model RFC 6819: https://tools.ietf.org/html/rfc6819
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- PKCE RFC 7636: https://tools.ietf.org/html/rfc7636
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Security_Cheat_Sheet.html
- PortSwigger OAuth Testing: https://portswigger.net/web-security/oauth

For detailed testing methodology and automation scripts, refer to the 'sso-oauth-oidc-misconfig-playbook' and 'federation-attack-scenarios' in the Tool Instructions panel."
    ),
];

/// Build all Cloud & Identity Security steps, including the quiz step if available.
pub fn get_cloud_identity_steps() -> Vec<Step> {
    let mut steps: Vec<Step> = CLOUD_IDENTITY_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                (*title).to_string(),
                (*description).to_string(),
                vec!["cloud".to_string(), "identity".to_string()],
            )
        })
        .collect();

    match create_cloud_identity_quiz_step() {
        Ok(quiz_step) => steps.push(quiz_step),
        Err(err) => eprintln!("Warning: Failed to load Cloud & Identity quiz: {err}"),
    }

    steps
}

fn create_cloud_identity_quiz_step() -> Result<Step, String> {
    let path = Path::new(QUIZ_FILE_PATH);
    if !path.exists() {
        return Err(format!("Quiz file not found: {}", path.display()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read quiz file {}: {}", path.display(), e))?;

    let questions = parse_question_file(&content)
        .map_err(|e| format!("Failed to parse quiz file {}: {}", path.display(), e))?;

    if questions.len() < 5 {
        return Err(format!(
            "Quiz file {} must contain at least 5 questions",
            path.display()
        ));
    }

    let quiz_step = QuizStep::new(
        Uuid::new_v4(),
        "Cloud & Identity Security Quiz".to_string(),
        DOMAIN_CLOUD_IDENTITY.to_string(),
        questions,
    );

    Ok(Step::new_quiz(
        Uuid::new_v4(),
        "Cloud & Identity Security Quiz".to_string(),
        vec![
            "quiz".to_string(),
            "cloud".to_string(),
            "identity".to_string(),
        ],
        quiz_step,
    ))
}
