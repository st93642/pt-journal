/// Cloud Native Security tutorial phases
///
/// This module provides comprehensive tutorials for modern cloud-native security threats:
/// - Container Breakout Playbook: Escaping containerized environments
/// - Kubernetes Pod-to-Cluster attacks: Privilege escalation in K8s clusters
/// - CI-CD Pipeline Attacks: Compromising build and deployment pipelines
///
/// Each phase follows the OBJECTIVE/PROCESS/LOOK-FOR format for structured learning.
use crate::model::Step;
use uuid::Uuid;

/// Container Breakout Playbook phase
pub fn container_breakout_phase() -> Step {
    {
        let tags = vec![
            "tutorial".to_string(),
            "cloud-native".to_string(),
            "container".to_string(),
            "breakout".to_string(),
        ];

        let parts = vec![
            ("Container Isolation Fundamentals".to_string(),
             "OBJECTIVE: Understand container isolation mechanisms and potential breakout vectors\n\nSTEP-BY-STEP PROCESS:\n1. Examine Docker container filesystem isolation using 'docker run --rm -it alpine sh'\n2. Check process namespace isolation with 'ps aux' inside vs outside container\n3. Analyze network namespace separation using 'ip link show'\n4. Review capability restrictions with 'capsh --print'\n5. Test volume mount escape vectors\n\nWHAT TO LOOK FOR:\n- Host filesystem access via volume mounts\n- Privileged container capabilities\n- Host PID namespace sharing\n- Weak AppArmor/SELinux profiles\n- Docker socket mounting".to_string()),
            ("Privileged Container Attacks".to_string(),
             "OBJECTIVE: Exploit privileged containers to achieve host-level access\n\nSTEP-BY-STEP PROCESS:\n1. Deploy privileged container: 'docker run --privileged -it ubuntu bash'\n2. Mount host filesystem: 'mount /dev/sda1 /mnt/host'\n3. Access host processes via /proc\n4. Modify host iptables rules\n5. Install persistent backdoors\n\nWHAT TO LOOK FOR:\n- CAP_SYS_ADMIN capability presence\n- Host device access (/dev/*)\n- Full root filesystem access\n- Network interface manipulation\n- Kernel module loading".to_string()),
            ("Docker Socket Exploitation".to_string(),
             "OBJECTIVE: Leverage Docker socket mounting for container escape\n\nSTEP-BY-STEP PROCESS:\n1. Mount Docker socket: 'docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker sh'\n2. Use Docker API to create privileged containers\n3. Execute commands on host via sibling containers\n4. Mount host directories in new containers\n5. Establish persistent access\n\nWHAT TO LOOK FOR:\n- Docker socket file access\n- API endpoint exploitation\n- Sibling container creation\n- Host volume mounting\n- Docker daemon compromise".to_string()),
            ("Kernel Vulnerability Chains".to_string(),
             "OBJECTIVE: Chain kernel vulnerabilities with container misconfigurations\n\nSTEP-BY-STEP PROCESS:\n1. Identify kernel version: 'uname -a'\n2. Search for known CVEs affecting container isolation\n3. Test Dirty COW (CVE-2016-5195) exploitation\n4. Attempt Dirty Pipe (CVE-2022-0847) attacks\n5. Chain with capability escalation\n\nWHAT TO LOOK FOR:\n- Vulnerable kernel versions\n- Memory corruption primitives\n- File permission bypasses\n- Namespace escape techniques\n- Rootkit installation".to_string()),
            ("Runtime-Based Escapes".to_string(),
             "OBJECTIVE: Exploit container runtime vulnerabilities for breakout\n\nSTEP-BY-STEP PROCESS:\n1. Test containerd/CRI-O socket access\n2. Exploit runc vulnerabilities (CVE-2019-5736)\n3. Abuse systemd in containers\n4. Leverage cgroups for privilege escalation\n5. Attack container orchestration APIs\n\nWHAT TO LOOK FOR:\n- Runtime socket exposure\n- Binary replacement attacks\n- Service exploitation\n- Resource limit bypasses\n- Orchestrator API access".to_string()),
        ];

        let description = parts
            .iter()
            .map(|(title, body)| format!("{}\n{}", title, body))
            .collect::<Vec<String>>()
            .join("\n\n---\n\n");

        Step::new_tutorial(
            Uuid::new_v4(),
            "Container Breakout Playbook".to_string(),
            description,
            tags,
        )
    }
}

/// Kubernetes Pod-to-Cluster attacks phase
pub fn kubernetes_attacks_phase() -> Step {
    {
        let tags = vec![
            "tutorial".to_string(),
            "cloud-native".to_string(),
            "kubernetes".to_string(),
            "privilege-escalation".to_string(),
        ];

        let parts = vec![
            ("Service Account Exploitation".to_string(),
             "OBJECTIVE: Exploit Kubernetes service account tokens for cluster access\n\nSTEP-BY-STEP PROCESS:\n1. Locate service account token: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'\n2. Check token permissions: 'kubectl auth can-i --as=system:serviceaccount:default:default get pods'\n3. Use token for API access: 'curl -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc/api/v1/pods'\n4. Enumerate cluster resources\n5. Escalate privileges via token\n\nWHAT TO LOOK FOR:\n- Auto-mounted service account tokens\n- Over-privileged service accounts\n- Token secret exposure\n- API server access\n- Cluster-admin bindings".to_string()),
            ("RBAC Privilege Escalation".to_string(),
             "OBJECTIVE: Leverage RBAC misconfigurations for unauthorized access\n\nSTEP-BY-STEP PROCESS:\n1. Enumerate cluster roles: 'kubectl get clusterroles'\n2. Check role bindings: 'kubectl get clusterrolebindings'\n3. Test privilege escalation paths\n4. Abuse wildcard permissions (*)\n5. Chain role assumptions\n\nWHAT TO LOOK FOR:\n- Over-permissive ClusterRoles\n- Wildcard resource permissions\n- Verb escalation (get → create)\n- Namespace isolation bypasses\n- Cluster-admin role bindings".to_string()),
            ("Pod Security Bypass".to_string(),
             "OBJECTIVE: Bypass pod security contexts for container escape\n\nSTEP-BY-STEP PROCESS:\n1. Check pod security context: 'kubectl describe pod malicious-pod'\n2. Test privileged pod creation\n3. Exploit hostPath volumes\n4. Abuse hostPID/hostNetwork\n5. Bypass AppArmor/SELinux\n\nWHAT TO LOOK FOR:\n- Privileged pod deployments\n- Host filesystem access\n- Host process visibility\n- Network interface access\n- Security policy evasion".to_string()),
            ("API Server Exploitation".to_string(),
             "OBJECTIVE: Attack Kubernetes API server for cluster compromise\n\nSTEP-BY-STEP PROCESS:\n1. Test unauthenticated API access\n2. Exploit SSRF in webhooks\n3. Abuse admission controllers\n4. Attack etcd via API\n5. Compromise control plane components\n\nWHAT TO LOOK FOR:\n- Exposed API server endpoints\n- Webhook misconfigurations\n- Admission controller bypasses\n- Etcd data access\n- Control plane vulnerabilities".to_string()),
            ("Cluster Lateral Movement".to_string(),
             "OBJECTIVE: Move laterally within Kubernetes clusters\n\nSTEP-BY-STEP PROCESS:\n1. Pod-to-pod communication abuse\n2. Service account token theft\n3. ConfigMap/Secret exploitation\n4. Node compromise via pods\n5. Cross-namespace attacks\n\nWHAT TO LOOK FOR:\n- East-west traffic interception\n- Credential harvesting\n- Configuration theft\n- Node-level access\n- Namespace boundary breaches".to_string()),
        ];

        let description = parts
            .iter()
            .map(|(title, body)| format!("{}\n{}", title, body))
            .collect::<Vec<String>>()
            .join("\n\n---\n\n");

        Step::new_tutorial(
            Uuid::new_v4(),
            "Kubernetes Pod-to-Cluster Attacks".to_string(),
            description,
            tags,
        )
    }
}

/// CI-CD Pipeline Attacks phase
pub fn cicd_pipeline_attacks_phase() -> Step {
    {
        let tags = vec![
            "tutorial".to_string(),
            "cloud-native".to_string(),
            "cicd".to_string(),
            "pipeline".to_string(),
        ];

        let parts = vec![
            ("Source Code Poisoning".to_string(),
             "OBJECTIVE: Inject malicious code into CI/CD pipelines via source repositories\n\nSTEP-BY-STEP PROCESS:\n1. Identify pipeline trigger mechanisms\n2. Inject malicious code into build scripts\n3. Modify dependency files (package.json, requirements.txt)\n4. Abuse git hooks and automation\n5. Compromise build artifacts\n\nWHAT TO LOOK FOR:\n- Weak repository access controls\n- Untrusted dependency inclusion\n- Build script injection points\n- Artifact tampering\n- Supply chain attacks".to_string()),
            ("Build Environment Attacks".to_string(),
             "OBJECTIVE: Attack CI/CD build environments for persistent access\n\nSTEP-BY-STEP PROCESS:\n1. Exploit vulnerable build agents\n2. Abuse shared build caches\n3. Compromise container registries\n4. Attack build orchestration systems\n5. Establish persistence in pipelines\n\nWHAT TO LOOK FOR:\n- Outdated build agent software\n- Shared state contamination\n- Registry access compromise\n- Orchestrator vulnerabilities\n- Pipeline job hijacking".to_string()),
            ("Artifact Integrity Attacks".to_string(),
             "OBJECTIVE: Modify build artifacts during CI/CD processes\n\nSTEP-BY-STEP PROCESS:\n1. Intercept artifact storage\n2. Modify binaries during build\n3. Inject malicious dependencies\n4. Tamper with package registries\n5. Attack deployment manifests\n\nWHAT TO LOOK FOR:\n- Insecure artifact storage\n- Build process injection\n- Dependency confusion attacks\n- Registry poisoning\n- Manifest manipulation".to_string()),
            ("Deployment Pipeline Attacks".to_string(),
             "OBJECTIVE: Compromise deployment pipelines for production access\n\nSTEP-BY-STEP PROCESS:\n1. Attack deployment automation\n2. Exploit configuration management\n3. Abuse infrastructure as code\n4. Compromise secrets management\n5. Attack canary/blue-green deployments\n\nWHAT TO LOOK FOR:\n- Deployment script vulnerabilities\n- Configuration drift exploitation\n- IaC template injection\n- Secret leakage\n- Deployment strategy abuse".to_string()),
            ("Pipeline Persistence Techniques".to_string(),
             "OBJECTIVE: Maintain access after successful pipeline compromise\n\nSTEP-BY-STEP PROCESS:\n1. Establish backdoors in deployed applications\n2. Compromise monitoring and logging\n3. Attack backup and recovery systems\n4. Abuse CI/CD for lateral movement\n5. Maintain access through updates\n\nWHAT TO LOOK FOR:\n- Application backdoors\n- Log tampering\n- Backup system compromise\n- Update mechanism abuse\n- Persistent access vectors".to_string()),
        ];

        let description = parts
            .iter()
            .map(|(title, body)| format!("{}\n{}", title, body))
            .collect::<Vec<String>>()
            .join("\n\n---\n\n");

        Step::new_tutorial(
            Uuid::new_v4(),
            "CI-CD Pipeline Attacks".to_string(),
            description,
            tags,
        )
    }
}

/// Get all cloud native security tutorial phases
pub fn get_cloud_native_phases() -> Vec<Step> {
    vec![
        container_breakout_phase(),
        kubernetes_attacks_phase(),
        cicd_pipeline_attacks_phase(),
    ]
}