pub const CLOUD_ASSET_DISCOVERY_STEPS: &[(&str, &str)] = &[
    (
        "Cloud asset discovery",
        "OBJECTIVE: Identify cloud-hosted assets including storage buckets, compute instances, databases, and serverless functions that may contain sensitive data or misconfigurations.

STEP-BY-STEP PROCESS:

1. S3 BUCKET ENUMERATION (AWS):
   ```bash
   # S3Scanner (bucket discovery and permissions)
   python3 s3scanner.py --list bucket-names.txt

   # Test public access
   aws s3 ls s3://target-company-backup --no-sign-request

   # Common naming patterns
   for name in backup dev staging prod logs assets; do
       aws s3 ls s3://target-$name --no-sign-request 2>&1
   done

   # Cloud_enum (multi-cloud discovery)
   python3 cloud_enum.py -k target-company
   ```

2. AZURE AND GCP ENUMERATION:
   ```bash
   # Azure storage enumeration
   python3 MicroBurst.py -d target.com

   # GCP bucket scanning
   python3 GCPBucketBrute.py -k target-company

   # Check common patterns
   curl https://target-backup.storage.googleapis.com/
   curl https://targetstorageaccount.blob.core.windows.net/
   ```

3. CLOUD SERVICE IDENTIFICATION:
   ```bash
   # Check for cloud metadata endpoints
   curl http://169.254.169.254/latest/meta-data/ # AWS
   curl -H \"Metadata:true\" http://169.254.169.254/metadata/instance # Azure

   # Identify cloud functions
   curl https://us-central1-project-id.cloudfunctions.net/function-name
   ```

WHAT TO LOOK FOR:
- Publicly accessible storage buckets
- Exposed API keys and credentials
- Misconfigured permissions (public read/write)
- Development/staging cloud resources
- Unencrypted data at rest

SECURITY IMPLICATIONS:
- Public S3 buckets can leak sensitive data
- Writable buckets enable malware hosting
- Exposed cloud functions may execute arbitrary code
- Metadata endpoints reveal infrastructure details
- Misconfigured IAM policies grant excessive permissions

COMMON PITFALLS:
- Some buckets are intentionally public (CDN assets)
- Cloud providers rate-limit enumeration attempts
- Bucket names may not follow predictable patterns
- Regional differences affect accessibility
- Authentication may be required for full enumeration

TOOLS REFERENCE:
- cloud_enum: https://github.com/initstring/cloud_enum
- S3Scanner: https://github.com/sa7mon/S3Scanner
- MicroBurst: https://github.com/NetSPI/MicroBurst (Azure)
- GCPBucketBrute: https://github.com/RhinoSecurityLabs/GCPBucketBrute"
    ),
];