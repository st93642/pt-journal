# CEH v12 Missing Topics - Online Research Summary

**Research Date**: November 2, 2025  
**Purpose**: Identify and document emerging cybersecurity topics for CEH v12 that are not fully covered in the available textbooks

---

## Overview

This document consolidates research on cutting-edge topics that should be included in the CEH v12 curriculum, particularly focusing on AI/ML security, container/cloud security, and emerging attack surfaces.

---

## 1. AI & Machine Learning Security

### Key Findings from OWASP ML Security Top 10

The OWASP Machine Learning Security Top 10 (2023) identifies critical risks in AI systems:

#### ML01: Input Manipulation Attack (Adversarial Attacks)

- **Definition**: Crafting malicious inputs designed to cause ML models to make incorrect predictions
- **Examples**:
  - Adding imperceptible noise to images to misclassify objects
  - Adversarial patches that fool facial recognition systems
  - Evasion attacks against spam filters and malware detectors
- **Tools to Cover**:
  - Foolbox (adversarial attack library)
  - CleverHans (TensorFlow-based adversarial examples)
  - Adversarial Robustness Toolbox (ART)

#### ML02: Data Poisoning Attack

- **Definition**: Injecting malicious data into training datasets to corrupt model behavior
- **Examples**:
  - Backdoor attacks (trigger-based misclassification)
  - Label flipping in training data
  - Feature collision attacks
- **Real-world Impact**: Microsoft's Tay chatbot (2016) - poisoned via Twitter interactions

#### ML03: Model Inversion Attack

- **Definition**: Exploiting model outputs to reconstruct sensitive training data
- **Privacy Risk**: Extracting personal information (faces, medical records) from models
- **Example**: Reconstructing faces from facial recognition model predictions

#### ML04: Membership Inference Attack

- **Definition**: Determining if a specific data point was used in model training
- **Privacy Risk**: GDPR violations, exposing sensitive records in training data
- **Tools**: ML Privacy Meter

#### ML05: Model Theft

- **Definition**: Extracting or replicating proprietary ML models through query access
- **Techniques**:
  - Model extraction via prediction API queries
  - Functionality stealing attacks
  - Hyperparameter theft
- **Business Impact**: Intellectual property theft, competitive advantage loss

#### ML06: AI Supply Chain Attacks

- **Definition**: Compromising AI systems through dependencies
- **Attack Vectors**:
  - Malicious pre-trained models (Hugging Face, Model Zoo)
  - Poisoned datasets (ImageNet, CIFAR-10 variants)
  - Compromised ML frameworks (backdoored TensorFlow packages)
  - Dependency confusion attacks on PyPI/npm

#### ML07: Transfer Learning Attack

- **Definition**: Exploiting vulnerabilities in pre-trained models used as starting points
- **Risk**: Hidden backdoors in foundation models (BERT, GPT, ResNet)

#### ML08: Model Skewing

- **Definition**: Manipulating model behavior through controlled drift or bias injection
- **Examples**: Gradual poisoning in online learning systems

#### ML09: Output Integrity Attack

- **Definition**: Manipulating model outputs or predictions post-inference
- **Techniques**: Man-in-the-middle attacks on prediction APIs

#### ML10: Model Poisoning

- **Definition**: Corruption of deployed models through update mechanisms
- **Vectors**: Federated learning attacks, online learning exploitation

### MITRE ATLAS Framework

**ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) provides a knowledge base with:

- **15 Tactics**: Reconnaissance, Resource Development, Initial Access, ML Model Access, Execution, Persistence, Defense Evasion, Discovery, Collection, ML Attack Staging, Exfiltration, Impact
- **130 Techniques**: Comprehensive adversary techniques against AI systems
- **26 Mitigations**: Defense strategies
- **33 Case Studies**: Real-world AI attacks

**Key ATLAS Techniques to Cover**:

- AML.T0043: Craft Adversarial Data
- AML.T0020: Poison Training Data
- AML.T0024: Exfiltration via ML Inference API
- AML.T0040: ML Model Inference API Access
- AML.T0015: Evade ML Model

### Emerging AI Security Topics

1. **Deepfake Detection & Creation**
   - GANs (Generative Adversarial Networks)
   - Deepfake generation tools (DeepFaceLab, Faceswap)
   - Detection techniques (forensic analysis, blockchain verification)

2. **Large Language Model (LLM) Security**
   - Prompt injection attacks
   - Jailbreaking (bypassing safety guardrails)
   - Data extraction from LLMs
   - Context poisoning
   - OWASP Top 10 for LLM Applications

3. **AI-Powered Phishing & Social Engineering**
   - Voice cloning (Resemble.ai, play.ht)
   - Automated spear-phishing with GPT models
   - Deepfake video calls for CEO fraud

4. **Automated Vulnerability Discovery**
   - AI-assisted fuzzing (Google's OSS-Fuzz with ML)
   - Neural network-based exploit generation
   - Automated pentesting tools (AutoSploit + ML)

---

## 2. Container & Kubernetes Security

### OWASP Kubernetes Top 10 (2022)

#### K01: Insecure Workload Configurations

- **Issues**: Running containers as root, privileged containers, excessive capabilities
- **Tools**: kube-bench, Polaris, Checkov

#### K02: Supply Chain Vulnerabilities

- **Risks**: Malicious container images, vulnerable base images, compromised registries
- **Tools**: Trivy, Grype, Snyk, Docker Bench Security

#### K03: Overly Permissive RBAC Configurations

- **Problem**: Excessive ClusterRole bindings, wildcard permissions
- **Tools**: kubectl-who-can, rbac-police, KubiScan

#### K04: Lack of Centralized Policy Enforcement

- **Solutions**: Open Policy Agent (OPA), Kyverno, Gatekeeper
- **Use Cases**: Pod Security Standards enforcement, admission control

#### K05: Inadequate Logging and Monitoring

- **Gaps**: Missing audit logs, no runtime security monitoring
- **Tools**: Falco, Sysdig, Prometheus, EFK stack

#### K06: Broken Authentication Mechanisms

- **Issues**: Weak service account tokens, missing OIDC integration
- **Best Practices**: Workload Identity, pod-level authentication

#### K07: Missing Network Segmentation Controls

- **Problems**: Flat networks, no NetworkPolicies
- **Tools**: Calico, Cilium, Istio service mesh

#### K08: Secrets Management Failures

- **Risks**: Secrets in environment variables, unencrypted etcd
- **Solutions**: HashiCorp Vault, Sealed Secrets, External Secrets Operator

#### K09: Misconfigured Cluster Components

- **Issues**: Exposed API server, insecure etcd, kubelet misconfigurations
- **Tools**: kube-hunter, kubeaudit

#### K10: Outdated and Vulnerable Kubernetes Components

- **Risks**: Unpatched CVEs, end-of-life versions
- **Tools**: Kubernetes CVE database, Pluto (deprecated API detection)

### Container Escape Techniques

1. **Privileged Container Escape**
   - Mounting host filesystem (`/proc`, `/dev`)
   - cgroups manipulation
   - Breakout via `/var/run/docker.sock`

2. **Kernel Exploits**
   - Dirty COW (CVE-2016-5195)
   - runc vulnerability (CVE-2019-5736)

3. **Docker API Exploitation**
   - Exposed Docker daemon (port 2375/2376)
   - Docker socket mounting

4. **Kubernetes-Specific Attacks**
   - Service account token theft
   - etcd database access
   - API server exploitation
   - kubelet API abuse

### Docker/Container Security Tools

- **Scanning**: Trivy, Clair, Anchore
- **Runtime Security**: Falco, Aqua Security, Sysdig Secure
- **Compliance**: Docker Bench, CIS Kubernetes Benchmark
- **Forensics**: Dive (image layer analysis), Skopeo

---

## 3. Cloud Security Enhancements

### Multi-Cloud Attack Surfaces

#### AWS-Specific Attacks

- **S3 Bucket Misconfiguration**: Public bucket enumeration, ACL exploitation
- **IAM Privilege Escalation**: 21 AWS privilege escalation paths
- **Lambda Function Exploitation**: Event injection, cold start abuse
- **EC2 Metadata Service (IMDS)**: SSRF to credential theft (v1 vs v2)
- **Tools**: Pacu (AWS exploitation framework), ScoutSuite, Prowler, CloudMapper

#### Azure-Specific Attacks

- **Storage Account Enumeration**: Blob/file share misconfigurations
- **Managed Identity Exploitation**: IMDS abuse in Azure VMs
- **Azure AD Abuse**: Password spray, consent phishing
- **Tools**: MicroBurst, Stormspotter, ROADtools

#### GCP-Specific Attacks

- **Service Account Key Theft**: JSON key files in repositories
- **GCS Bucket Enumeration**: Public bucket scanning
- **Compute Engine Metadata**: Credential extraction
- **Tools**: GCPBucketBrute, GCP-IAM-Privilege-Escalation

### Cloud-Native Application Protection

1. **Serverless Security**
   - Function-as-a-Service (FaaS) vulnerabilities
   - Event injection attacks
   - Secrets in Lambda environment variables
   - Cold start timing attacks

2. **API Gateway Exploitation**
   - Rate limit bypass
   - Authentication flaws in API Gateway
   - Lambda authorizer vulnerabilities

3. **Infrastructure as Code (IaC) Security**
   - Terraform misconfiguration detection (tfsec, Checkov)
   - CloudFormation template analysis
   - Secrets in IaC repos (GitGuardian, TruffleHog)

---

## 4. IoT & OT Security Expansions

### Industrial Control Systems (ICS)

1. **SCADA Security**
   - Modbus protocol exploitation
   - DNP3 vulnerabilities
   - SCADA network reconnaissance
   - Tools: Metasploit ICS modules, SCADA Shutdown Tool

2. **PLC Hacking**
   - Siemens S7 exploitation
   - Rockwell Allen-Bradley attacks
   - Ladder logic manipulation
   - Tools: PLCinject, PLCSCAN

3. **ICS Protocols**
   - OPC UA security
   - EtherNet/IP vulnerabilities
   - Profinet attacks

### IoT Device Security

1. **Firmware Analysis**
   - Firmware extraction (binwalk, firmware-mod-kit)
   - Reverse engineering (Ghidra, Radare2)
   - Vulnerability hunting in embedded systems

2. **Hardware Hacking**
   - UART/JTAG interface exploitation
   - Side-channel attacks (power analysis, timing)
   - Chip-off attacks for data extraction

3. **IoT Communication Protocols**
   - MQTT security issues
   - CoAP vulnerabilities
   - Zigbee/Z-Wave attacks
   - BLE (Bluetooth Low Energy) exploitation

4. **IoT Cloud Platform Attacks**
   - AWS IoT Core exploitation
   - Azure IoT Hub security
   - MQTT broker hijacking

---

## 5. DevSecOps & CI/CD Pipeline Security

### CI/CD Pipeline Attacks

1. **Source Code Repository Compromise**
   - GitHub Actions abuse
   - GitLab CI runner exploitation
   - Repository secrets theft

2. **Build Process Poisoning**
   - Dependency confusion attacks
   - Malicious build scripts
   - Compromised build agents

3. **Artifact Repository Attacks**
   - Docker registry manipulation
   - npm/PyPI package poisoning
   - Maven Central exploits

4. **Deployment Stage Exploitation**
   - Kubernetes deployment manifest injection
   - Helm chart vulnerabilities
   - CD tool compromise (ArgoCD, Flux)

### DevSecOps Tools

- **SAST**: SonarQube, Semgrep, Checkmarx
- **DAST**: OWASP ZAP, Burp Suite Enterprise
- **SCA**: Snyk, WhiteSource, Dependabot
- **Infrastructure Scanning**: Terraform Cloud, Bridgecrew
- **Container Scanning**: Trivy, Clair, Aqua
- **Secret Detection**: GitGuardian, TruffleHog, detect-secrets

---

## 6. Blockchain & Web3 Security

### Smart Contract Vulnerabilities

1. **Reentrancy Attacks**
   - Example: The DAO hack (2016, $60M stolen)
   - Prevention: Checks-Effects-Interactions pattern

2. **Integer Overflow/Underflow**
   - Solidity <0.8.0 vulnerabilities
   - SafeMath library usage

3. **Access Control Issues**
   - Missing function modifiers
   - Delegate call vulnerabilities

4. **Front-Running**
   - MEV (Miner Extractable Value) exploitation
   - Sandwich attacks on DEXs

### Web3 Attack Vectors

- **Wallet Attacks**: MetaMask phishing, seed phrase theft
- **NFT Exploits**: Metadata manipulation, contract vulnerabilities
- **DeFi Hacks**: Flash loan attacks, oracle manipulation
- **Bridge Exploits**: Cross-chain bridge vulnerabilities

### Tools

- **Analysis**: Slither, Mythril, Manticore
- **Auditing**: MythX, Echidna (fuzzing)
- **Testing**: Hardhat, Foundry

---

## 7. 5G & Mobile Network Security

### 5G-Specific Vulnerabilities

1. **Network Slicing Attacks**
   - Slice isolation bypass
   - Resource exhaustion

2. **gNodeB Exploitation**
   - Base station vulnerabilities
   - Open RAN security issues

3. **SUCI (Subscription Concealed Identifier) Attacks**
   - IMSI catching evolution
   - Privacy attacks

### Mobile Application Security

- **OWASP MASVS** (Mobile Application Security Verification Standard)
- **Static Analysis**: MobSF, Qark
- **Dynamic Analysis**: Frida, Objection
- **iOS Jailbreak Detection Bypass**
- **Android Root Detection Bypass**
- **Certificate Pinning Bypass**: Objection, SSL Kill Switch

---

## 8. Zero Trust Architecture

### Core Principles

1. **Verify Explicitly**: Continuous authentication
2. **Least Privilege Access**: Just-in-time access
3. **Assume Breach**: Micro-segmentation

### Implementation Components

- **Identity-Based Access**: BeyondCorp, Okta, Azure AD
- **Network Segmentation**: Software-Defined Perimeter (SDP)
- **Endpoint Security**: EDR/XDR solutions
- **Micro-segmentation**: Illumio, VMware NSX

---

## 9. Quantum Computing & Post-Quantum Cryptography

### Quantum Threats

1. **Shor's Algorithm**: Breaks RSA, ECC, DH
2. **Grover's Algorithm**: Reduces symmetric key strength by half

### Post-Quantum Algorithms (NIST Standards)

- **CRYSTALS-Kyber**: Key encapsulation
- **CRYSTALS-Dilithium**: Digital signatures
- **FALCON**: Lattice-based signatures
- **SPHINCS+**: Hash-based signatures

### Migration Strategy

- Crypto-agility planning
- Hybrid classical-quantum systems
- Quantum-safe VPNs

---

## 10. Privacy-Enhancing Technologies (PETs)

### Techniques

1. **Differential Privacy**: Adding noise to protect individual records
2. **Homomorphic Encryption**: Computation on encrypted data
3. **Secure Multi-Party Computation (SMPC)**: Collaborative computation without data sharing
4. **Federated Learning**: Distributed ML training without centralized data

### Tools & Frameworks

- **Google's Differential Privacy Library**
- **Microsoft SEAL** (homomorphic encryption)
- **PySyft** (federated learning)

---

## Integration into CEH Modules

### Recommended Module Additions

1. **Module 18 (IoT & OT Hacking)**: Add ICS/SCADA, PLC hacking, 5G security
2. **Module 19 (Cloud Computing)**: Expand with container security, Kubernetes attacks, serverless security, IaC scanning
3. **Module 20 (Cryptography)**: Add post-quantum cryptography, quantum threats
4. **NEW Module 21: AI/ML Security**:
   - Adversarial attacks
   - Model poisoning
   - Privacy attacks (membership inference, model inversion)
   - LLM security
   - MITRE ATLAS framework

### Question Writing Priority

**High Priority** (20-30 questions each):

1. AI/ML Security Fundamentals
2. Container & Kubernetes Security
3. Cloud-Native Security (serverless, IaC)

**Medium Priority** (15-20 questions each):

1. DevSecOps & CI/CD Pipeline Security
2. Advanced IoT/OT (ICS/SCADA)
3. Blockchain & Web3 Security

**Low Priority** (5-10 questions each):

1. 5G Network Security
2. Zero Trust Architecture
3. Quantum Computing Threats

---

## Tools Reference Matrix

### AI/ML Security

| Tool | Purpose | Module |
|------|---------|--------|
| Foolbox | Adversarial attacks | 21 |
| CleverHans | TensorFlow adversarial examples | 21 |
| ART | Adversarial Robustness Toolbox | 21 |
| ML Privacy Meter | Membership inference | 21 |

### Container Security

| Tool | Purpose | Module |
|------|---------|--------|
| Trivy | Container vulnerability scanning | 19 |
| Falco | Runtime security monitoring | 19 |
| kube-bench | CIS Kubernetes benchmark | 19 |
| kube-hunter | Kubernetes penetration testing | 19 |
| Docker Bench | Docker security auditing | 19 |

### Cloud Security

| Tool | Purpose | Module |
|------|---------|--------|
| Pacu | AWS exploitation framework | 19 |
| ScoutSuite | Multi-cloud security auditing | 19 |
| Prowler | AWS security assessment | 19 |
| MicroBurst | Azure security testing | 19 |
| CloudMapper | AWS network visualization | 19 |

### IoT/OT Security

| Tool | Purpose | Module |
|------|---------|--------|
| binwalk | Firmware extraction | 18 |
| Metasploit ICS | SCADA exploitation | 18 |
| PLCSCAN | PLC reconnaissance | 18 |
| Wireshark (ICS plugins) | Protocol analysis | 18 |

### DevSecOps

| Tool | Purpose | Module |
|------|---------|--------|
| GitGuardian | Secret detection in repos | 19 |
| Semgrep | SAST for multiple languages | 04 |
| tfsec | Terraform security scanner | 19 |
| Checkov | IaC security scanning | 19 |

---

## Sources & References

1. **OWASP ML Security Top 10**: <https://mltop10.info/>
2. **MITRE ATLAS**: <https://atlas.mitre.org/>
3. **OWASP Kubernetes Top 10**: <https://owasp.org/www-project-kubernetes-top-ten/>
4. **Kubernetes Security Docs**: <https://kubernetes.io/docs/concepts/security/>
5. **EC-Council CEH AI**: <https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/>
6. **NIST Post-Quantum Cryptography**: <https://csrc.nist.gov/projects/post-quantum-cryptography>
7. **Cloud Security Alliance**: <https://cloudsecurityalliance.org/>

---

## Next Steps

1. **Create Module 21: AI/ML Security** (50 questions covering OWASP ML Top 10 + MITRE ATLAS)
2. **Enhance Module 18**: Add 20 questions on ICS/SCADA/PLC hacking
3. **Enhance Module 19**: Add 30 questions on Kubernetes, containers, serverless, IaC security
4. **Enhance Module 20**: Add 10 questions on post-quantum cryptography
5. **Update Module 14 (Web Applications)**: Add 10 questions on Web3/blockchain security
6. **Update Module 04 (Enumeration)**: Add cloud service enumeration techniques

**Total Additional Questions Needed**: ~150-170 questions to bring CEH v12 fully up-to-date with 2025 threat landscape.

---

*Research completed: November 2, 2025*  
*Last updated: November 2, 2025*
