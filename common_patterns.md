# Common Security Patterns

Shared prompt-time rules for every CloudSentinel scan. Service skill files should add service-specific detection logic, not restate these baselines.

## 1. Universal Contract

### Input Interpretation
- `PRIMARY SERVICE` = full audit scope. Analyze all resources in that section.
- `DEPENDENCY CONTEXT` = supporting evidence only.
- Do not perform standalone audits of dependency services.
- Do not invent resources, permissions, trust relationships, or reachability.
- Missing data is not proof of security or insecurity. State what could not be validated.

### Output Rules
- Return valid JSON only.
- `findings[].severity` must be `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `findings[].status` must be `TRUE` or `NEEDS_REVIEW`.
- Never emit false findings.
- `attack_paths[]` are only for evidence-backed multi-hop chains.

## 2. Severity Baselines

Apply the service skill base severity, then modify using this order:
- Public, attached, running, and reachable resources: raise severity.
- Stopped or unreachable resources: lower one level when appropriate.
- Unattached or orphaned resources: cap at `MEDIUM` unless direct public exposure still matters.
- Production tags or names (`prod`, `production`, `live`, `payment`, `api`, `db`, `auth`, `customer`, `critical`, `pci`, `pii`): raise one level.
- Dev/test/lab/sandbox indicators: lower one level when risk is not externally reachable.
- Findings that participate in a confirmed attack path: raise one level.
- Shared resources affecting many workloads: mention amplified blast radius.
- Internet-facing resources with logging disabled: mention that attacks may go undetected.

## 3. Cross-Service Detection Baselines

### Public Exposure
- Admin or database ports exposed to `0.0.0.0/0` or `::/0`: `CRITICAL`.
- `IpProtocol: -1` from the internet on in-use resources: `CRITICAL`.
- `Principal: "*"` or equivalent public access on sensitive resources: `CRITICAL`.
- Public snapshots: `CRITICAL`.
- Public AMIs: usually `HIGH`, raise if sensitive internal content is implied.
- `PubliclyAccessible: true` only becomes severe when combined with real internet reachability.

### Encryption
- Unencrypted data at rest: `MEDIUM`.
- Unencrypted sensitive or production data: `HIGH`.
- Unencrypted backups or snapshots: `MEDIUM`, raise if sensitive.
- Missing TLS or insecure transport on reachable services: `HIGH`.
- SSE-S3 instead of SSE-KMS is not a finding unless the scan or policy context makes CMK usage important.

### Logging and Monitoring
- Logging disabled on internet-facing resources: `HIGH`.
- Logging disabled on sensitive internal resources: usually `MEDIUM`.
- If another serious finding exists and visibility is missing, mention compounded risk in the narrative.

### Least Privilege
- `Action: *` with `Resource: *`: `CRITICAL`.
- Wildcard on sensitive actions like `iam:PassRole`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `sts:AssumeRole`: `HIGH`.
- `iam:PassRole` plus compute creation rights: `CRITICAL`.
- `iam:CreatePolicyVersion` plus `iam:SetDefaultPolicyVersion`: `CRITICAL`.
- Inline policies are a finding only when they materially weaken auditability or privilege scope.

### Hygiene and Staleness
- Missing key tags (`Name`, `Environment`, `Owner`): `LOW`.
- Orphaned key pairs, empty security groups, detached storage, stale images, idle elastic IPs: usually `LOW`.
- Cost-only findings should not outrank security findings.

## 4. False Positive Controls

Suppress or downgrade these unless other evidence makes them risky:
- Port 80 or 443 open on legitimate internet-facing web entry points.
- Public HTTPS by itself.
- Internal RFC1918 traffic between app tiers.
- Default security groups with only self-referencing rules.
- Broad outbound rules on non-sensitive workloads.
- Public AMIs that appear intentionally published base images: use `NEEDS_REVIEW` if intent is unclear.
- Cross-account access with strong conditions and clear intended scope: lower severity or use `NEEDS_REVIEW`.

## 5. Dependency Boundaries

- Dependency context exists to validate attack paths, explain blast radius, and prioritize remediation.
- Dependency context must not become a separate audit of that service.
- Only reference dependency misconfigurations when they are necessary to explain a primary-service finding or chain.
- If dependency context is incomplete, do not extend the chain beyond what the evidence supports.

### Typical Dependency Use
- EC2: IAM, S3, Lambda, Secrets Manager, SSM, VPC
- S3: IAM, CloudTrail, EC2, Lambda
- IAM: EC2, S3, Lambda, Secrets Manager, STS
- VPC: EC2, IAM, RDS, ELB
- RDS: EC2, VPC, IAM, KMS, Secrets Manager
- EBS: EC2, IAM, KMS
- AMI: EC2, IAM, Auto Scaling
- ELB: EC2, ACM, WAF, S3, IAM

## 6. Attack Path Standards

- Minimum two confirmed hops per formal attack path.
- Maximum one unexplained inferred hop.
- One confirmed hop plus multiple inferred hops is too weak: keep it as a normal finding.
- `CONFIRMED` means the scan directly proves the hop.
- `INFERRED` means the hop is plausible from evidence but not fully proven; explain what would confirm it.
- Formal paths must use real resources from the scan and end in a realistic attacker outcome such as code execution, credential theft, privilege escalation, lateral movement, or data access.

## 7. Remediation Prioritization

Break chains in this order:
1. Remove the entry point.
2. Remove the key pivot.
3. Reduce blast radius.
4. Improve logging and monitoring.
5. Clean up hygiene or cost issues.
