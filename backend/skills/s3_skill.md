# S3 Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **S3-specific** patterns only.

## Service Overview

S3 is the primary data storage surface in most AWS accounts. A single bucket misconfiguration can expose customer data, backups, audit logs, application secrets, or infrastructure state to the internet or to unauthorized cross-account access. S3 findings should not be evaluated by a single signal like `Principal: *` — always evaluate the full access path.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: S3 ===
list-buckets, get-public-access-block (account-level via s3control),
get-public-access-block (per bucket), get-bucket-policy (per bucket),
get-bucket-policy-status (per bucket), get-bucket-acl (per bucket),
get-bucket-encryption (per bucket), get-bucket-versioning (per bucket),
get-bucket-logging (per bucket), get-bucket-tagging (per bucket),
get-bucket-website (per bucket), get-bucket-ownership-controls (per bucket),
get-bucket-replication (per bucket), get-bucket-notification-configuration (per bucket)

=== DEPENDENCY CONTEXT: IAM ===
list-roles, get-role, list-attached-role-policies, get-policy-version, list-users

=== DEPENDENCY CONTEXT: CLOUDTRAIL ===
describe-trails, get-trail-status, get-event-selectors

=== DEPENDENCY CONTEXT: EC2 ===
describe-instances (instances with roles that access S3)

=== DEPENDENCY CONTEXT: LAMBDA ===
list-functions (functions with roles that access S3)
```

---

## 2. Relationship Mapping (Do This First)

### S3 Resource Maps
- **Bucket → Public Access Block**: account-level and bucket-level settings (all four flags)
- **Bucket → Policy**: parsed policy statements with principals, actions, resources, and conditions
- **Bucket → ACL**: grantee URIs (AllUsers, AuthenticatedUsers, specific accounts)
- **Bucket → Effective Public Status**: combining access block + policy + ACL to determine real exposure
- **Bucket → Encryption**: SSE-S3, SSE-KMS, or none
- **Bucket → Versioning**: enabled, suspended, or not configured
- **Bucket → Logging**: logging target bucket or not enabled
- **Bucket → Website Hosting**: enabled or not
- **Bucket → Ownership Controls**: BucketOwnerEnforced, BucketOwnerPreferred, or ObjectWriter
- **Bucket → Sensitivity Classification**: inferred from name, tags, and controls (see Sensitive Bucket Heuristics)
- **Bucket → Replication**: cross-region or cross-account replication configured

### Access Evaluation Order (Per Bucket)
Evaluate in this sequence to determine real exposure:
1. Account-level Public Access Block → blocks all public access if enabled
2. Bucket-level Public Access Block → blocks public access for this bucket if enabled
3. Explicit Deny in bucket policy → overrides allows
4. Allow statements in bucket policy → check principals, actions, conditions
5. ACL grants → AllUsers, AuthenticatedUsers
6. IAM permissions for authenticated principals (from dependency context)
7. Conditions → VPC endpoint, SourceIp, SourceArn, SourceAccount, OrgID restrictions

**A bucket is meaningfully public only when**: account-level controls do not block it, bucket-level controls do not block it, AND policy or ACL grants access to unauthenticated or overly broad principals.

### Dependency Maps
- **IAM Roles/Users → S3 Permissions**: which identities can read/write/delete/admin specific buckets
- **IAM Roles on EC2 Instances → S3 Access**: which running instances can access which buckets (and whether those instances are public)
- **IAM Roles on Lambda Functions → S3 Access**: which functions can access which buckets
- **CloudTrail → S3 Data Events**: whether S3 object-level access is logged

### Derived Relationships
- **Publicly Accessible Sensitive Buckets**: public exposure + sensitive name/tags
- **Write-Exposed Buckets**: broad principals with PutObject/DeleteObject/PutBucketPolicy
- **Unmonitored Exposed Buckets**: public or broadly accessible + no logging + no CloudTrail data events
- **Instance-to-Bucket Chains**: public EC2 instances whose roles can access sensitive buckets

---

## 3. S3 Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### S3-ACCOUNT-PAB: Account-Level Public Access Block Disabled
| Field | Value |
|-------|-------|
| Detection | `s3control get-public-access-block` fails or all four settings are `false` |
| Category | `access_control` |
| Base severity | CRITICAL |
| Blast radius | Account-wide — every bucket loses this safety net |
| Fix | `aws s3control put-public-access-block --account-id {account-id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` |
| Attack path role | Enabler for all public exposure chains |

### S3-BUCKET-PUBLIC-READ: Bucket Publicly Readable
| Field | Value |
|-------|-------|
| Detection | `get-bucket-policy-status` shows `IsPublic: true` with read actions, OR policy/ACL grants `s3:GetObject` to `Principal: *` without restrictive conditions, AND access blocks do not neutralize |
| Category | `data_exposure` |
| Base severity | CRITICAL (sensitive bucket), HIGH (intentional website/static), LOW (clearly intentional public hosting) |
| Status rule | `NEEDS_REVIEW` when bucket appears intentionally public but content safety can't be proven |
| Fix | Enable bucket-level public access block, or restrict policy principal |
| Attack path role | Direct data exfiltration endpoint — no compromise chain needed |

### S3-BUCKET-PUBLIC-WRITE: Bucket Publicly Writable
| Field | Value |
|-------|-------|
| Detection | Policy grants `s3:PutObject`, `s3:DeleteObject`, `s3:PutBucketPolicy`, `s3:PutObjectAcl`, or `s3:*` to `Principal: *` or broad principals without restrictive conditions |
| Category | `data_exposure` |
| Base severity | CRITICAL |
| Fix | Remove broad write permissions, restrict to specific principals |
| Attack path role | Write access enables data destruction, content injection, and persistence |

### S3-PUBLIC-ACL: Public ACL Grants Access
| Field | Value |
|-------|-------|
| Detection | ACL grantee URI includes `AllUsers` or `AuthenticatedUsers` |
| Category | `data_exposure` |
| Base severity | CRITICAL (if access block doesn't neutralize), LOW (if account/bucket settings fully ignore public ACLs) |
| Fix | `aws s3api put-bucket-acl --bucket {bucket} --acl private` |
| Attack path role | Alternative public exposure path bypassing policy review |

### S3-BROAD-PRINCIPAL: Bucket Policy Uses Broad Principal Without Restrictive Conditions
| Field | Value |
|-------|-------|
| Detection | `"Principal": "*"` or wildcard AWS principals with no meaningful Condition (no VPC endpoint, SourceIp, OrgID, SourceArn) |
| Category | `access_control` |
| Base severity | CRITICAL (broad read on sensitive / broad write on any), HIGH (broad read on low-sensitivity) |
| Fix | Replace wildcard principals with specific principals, accounts, roles, or restrictive conditions |

### S3-CROSS-ACCOUNT: Cross-Account Access Without Tight Conditions
| Field | Value |
|-------|-------|
| Detection | Bucket policy grants access to external AWS accounts, roles, or roots without strong conditions |
| Category | `access_control` |
| Base severity | HIGH (weakly scoped), CRITICAL (external broad access + sensitive bucket) |
| Status rule | `NEEDS_REVIEW` when cross-account appears intentional but guardrails can't be validated |
| Fix | Scope to exact role ARNs, add `aws:PrincipalArn`, `aws:PrincipalOrgID`, `aws:SourceArn`, or prefix restrictions |

### S3-BUCKET-PAB: Bucket-Level Public Access Block Disabled
| Field | Value |
|-------|-------|
| Detection | `get-public-access-block` missing or all four flags `false` |
| Category | `access_control` |
| Base severity | HIGH (raise if policy/ACL already broad, lower if intentional public website) |
| Fix | `aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` |

### S3-NO-ENCRYPTION: Default Encryption Not Configured
| Field | Value |
|-------|-------|
| Detection | `get-bucket-encryption` returns `ServerSideEncryptionConfigurationNotFoundError` |
| Category | `encryption` |
| Base severity | HIGH (sensitive buckets), MEDIUM (general production) |
| Fix | `aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'` |
| Note | SSE-S3 is acceptable baseline; SSE-KMS is stronger for auditability and key control |

### S3-SSE-S3-ONLY: Encryption Uses SSE-S3 Instead of SSE-KMS
| Field | Value |
|-------|-------|
| Detection | Encryption configuration uses `AES256` |
| Category | `encryption` |
| Base severity | LOW (general), MEDIUM (sensitive/regulated buckets) |
| Fix | Consider migrating sensitive buckets to SSE-KMS with customer-managed keys |

### S3-NO-VERSIONING: Versioning Not Enabled
| Field | Value |
|-------|-------|
| Detection | `get-bucket-versioning` is empty or not `Enabled` |
| Category | `backup_recovery` |
| Base severity | MEDIUM (production/backup/logs/audit), LOW (temporary/static content) |
| Fix | `aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled` |

### S3-NO-MFA-DELETE: MFA Delete Not Enabled on Important Versioned Buckets
| Field | Value |
|-------|-------|
| Detection | Versioning enabled but `MFADelete` missing or not enabled |
| Category | `backup_recovery` |
| Base severity | MEDIUM (raise to HIGH for critical backups or irreplaceable data) |
| Fix note | Requires root account credentials and operational care |

### S3-NO-LOGGING: Logging Not Enabled
| Field | Value |
|-------|-------|
| Detection | `get-bucket-logging` returns no `LoggingEnabled` |
| Category | `logging_monitoring` |
| Base severity | MEDIUM (sensitive/internet-accessible), LOW (low-risk buckets) |
| Fix | `aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"{log-bucket}","TargetPrefix":"{bucket}/"}}'` |

### S3-OWNERSHIP-NOT-ENFORCED: Object Ownership Not Enforced
| Field | Value |
|-------|-------|
| Detection | `get-bucket-ownership-controls` missing or not `BucketOwnerEnforced` |
| Category | `access_control` |
| Base severity | MEDIUM |
| Fix | `aws s3api put-bucket-ownership-controls --bucket {bucket} --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'` |

### S3-WEBSITE-RISKY: Static Website Hosting on Non-Public-Controlled Bucket
| Field | Value |
|-------|-------|
| Detection | `get-bucket-website` succeeds on a bucket that lacks clear public-read intent or safe controls |
| Category | `data_exposure` |
| Base severity | LOW (intentional website), HIGH (sensitive bucket with inconsistent website mode) |
| Status rule | `NEEDS_REVIEW` when website hosting appears intentional but safe content can't be proven |

### S3-NO-REPLICATION: No Replication on Critical Data Buckets
| Field | Value |
|-------|-------|
| Detection | `get-bucket-replication` missing for obvious backup/audit/critical buckets |
| Category | `backup_recovery` |
| Base severity | LOW–MEDIUM depending on bucket importance |

### S3-NO-TAGS: Missing Tags on Production-Relevant Buckets
| Field | Value |
|-------|-------|
| Detection | `get-bucket-tagging` missing or empty |
| Category | `resource_hygiene` |
| Base severity | LOW |

---

## 4. S3 Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Public Sensitive Bucket Direct Data Breach
**Category**: `data_exfiltration`
**Chain**: Internet → Public Bucket Policy/ACL → Read Sensitive Data
| Hop | Evidence |
|-----|----------|
| 1. Account-level PAB disabled | CONFIRMED required |
| 2. Bucket-level PAB disabled | CONFIRMED required |
| 3. Public read via policy or ACL (`s3:GetObject` to `Principal: *`) | CONFIRMED required |
| 4. Bucket name/tags suggest sensitive content | CONFIRMED or INFERRED |

**Minimum**: Hops 2 and 3 must be CONFIRMED. Hop 1 strengthens but not strictly required if bucket-level controls are the relevant gap.
**Impact**: Any internet user can download objects. Data breach if bucket contains customer data, backups, credentials, or secrets.
**Break chain**: (1) Enable bucket-level PAB, (2) Enable account-level PAB, (3) Remove public principal, (4) Audit contents for leaked credentials.

### AP-REF-02: Public Write Access — Ransomware and Content Injection
**Category**: `data_exfiltration` + `lateral_movement`
**Chain**: Internet → Public Write to Bucket → Object Overwrite / Malicious Upload / Policy Tampering
| Hop | Evidence |
|-----|----------|
| 1. PAB does not prevent write access | CONFIRMED required |
| 2. Policy grants `s3:PutObject`/`s3:DeleteObject`/`s3:PutBucketPolicy`/`s3:*` to `Principal: *` | CONFIRMED required |
| 3. Versioning disabled → overwrites destroy originals | CONFIRMED |
| 4. Logging disabled → attack goes undetected | CONFIRMED |

**Impact**: Ransomware-style overwrite, malicious content hosting, policy tampering, or persistence. Without versioning, data unrecoverable.
**Break chain**: (1) Remove public write permissions, (2) Enable PAB, (3) Enable versioning, (4) Enable logging.

### AP-REF-03: Cross-Account Bucket Access to Data Exfiltration
**Category**: `data_exfiltration`
**Chain**: External Account → Cross-Account Bucket Policy → Read/Copy Sensitive Data
| Hop | Evidence |
|-----|----------|
| 1. Bucket policy shows external account ID in principal | CONFIRMED required |
| 2. Missing or weak conditions (no ExternalId, OrgID, SourceArn) | CONFIRMED required |
| 3. Allowed actions include `s3:GetObject`/`s3:ListBucket` or broader | CONFIRMED required |
| 4. Bucket contains sensitive data (name/tag heuristics) | CONFIRMED or INFERRED |

**Break chain**: (1) Add restrictive conditions (OrgID, specific role ARN, ExternalId), (2) Scope actions, (3) Enable logging, (4) Validate need.

### AP-REF-04: EC2 Instance Role to S3 Data Exfiltration (Cross-Service)
**Category**: `data_exfiltration` + `credential_access`
**Chain**: Compromised EC2 Instance → IAM Role → S3 Read/Write → Data Exfiltration
| Hop | Evidence |
|-----|----------|
| 1. EC2 instance internet-reachable (public IP + open SG, from dependency context) | CONFIRMED required |
| 2. Host compromise | INFERRED (standard from internet exposure) |
| 3. Instance role has S3 actions on target buckets (from IAM dependency) | CONFIRMED required |
| 4. Target bucket exists in primary S3 scan | CONFIRMED required |

**Note**: Uses EC2/IAM dependency context for entry and pivot; core target is S3 bucket (primary scope).
**Break chain**: (1) Scope role S3 permissions, (2) Restrict EC2 exposure, (3) Enable bucket logging + CloudTrail S3 data events, (4) Enable versioning.

### AP-REF-05: Lambda Function Role to S3 Data Access (Cross-Service)
**Category**: `credential_access`
**Chain**: Lambda Function → Execution Role → S3 Read/Write → Data Access
| Hop | Evidence |
|-----|----------|
| 1. Lambda function exists with execution role (from Lambda dependency) | CONFIRMED required |
| 2. Role has S3 actions on target buckets (from IAM dependency) | CONFIRMED required |
| 3. Target bucket exists and is sensitive (from primary S3 scan) | CONFIRMED required |
| 4. Function invokable by broad principals or has public trigger | CONFIRMED or INFERRED |

**Break chain**: (1) Restrict Lambda invoke permissions, (2) Scope execution role S3 permissions, (3) Enable logging.

### AP-REF-06: Website Bucket Content Injection (Supply Chain)
**Category**: `lateral_movement`
**Chain**: Writable Website Bucket → Inject Malicious Content → End Users Served Malicious Content
| Hop | Evidence |
|-----|----------|
| 1. `get-bucket-website` succeeds | CONFIRMED required |
| 2. Policy allows `s3:PutObject` to broad principals | CONFIRMED required |
| 3. Website content actively served | CONFIRMED or INFERRED |
| 4. Supply chain impact (injected JS/HTML reaches users) | INFERRED |

**Impact**: Credential theft, malware delivery, or brand damage via injected content.
**Break chain**: (1) Remove broad write permissions, (2) Restrict PutObject to deployment pipelines, (3) Enable versioning, (4) Enable logging.

### AP-REF-07: Public Bucket + No Logging = Undetected Exfiltration
**Category**: `data_exfiltration`
**Chain**: Public/Broadly Accessible Bucket → No Logging → No CloudTrail S3 Data Events → Undetected Access
| Hop | Evidence |
|-----|----------|
| 1. Bucket is publicly/broadly accessible | CONFIRMED required |
| 2. S3 server access logging not enabled | CONFIRMED required |
| 3. CloudTrail does not capture S3 object-level events | CONFIRMED or INFERRED |
| 4. Exfiltration leaves no audit trail | INFERRED |

**Break chain**: (1) Enable S3 logging, (2) Enable CloudTrail S3 data events, (3) Fix public access.

### AP-REF-08: Broad Write + No Versioning = Destructive Attack
**Category**: `data_exfiltration`
**Chain**: Broad Write Access → Overwrite/Delete Objects → No Versioning → Permanent Data Loss
| Hop | Evidence |
|-----|----------|
| 1. Policy grants write/delete to broad principals | CONFIRMED required |
| 2. Versioning disabled or suspended | CONFIRMED required |
| 3. Data destruction | INFERRED |

**Impact**: Permanent data loss — critical for backup buckets, audit logs, production data.
**Break chain**: (1) Enable versioning, (2) Restrict write permissions, (3) Consider MFA Delete, (4) Enable logging.

### AP-REF-09: Bucket Policy Tampering via PutBucketPolicy
**Category**: `self_escalation`
**Chain**: Broad PutBucketPolicy Access → Policy Replacement → Persistent Access
| Hop | Evidence |
|-----|----------|
| 1. Policy grants `s3:PutBucketPolicy` to broad principals | CONFIRMED required |
| 2. Policy replacement (standard exploitation technique) | INFERRED |
| 3. Persistent access follows from policy control | INFERRED |

**Note**: If only Hop 1 is CONFIRMED, keep as CRITICAL finding with escalation risk in impact. Elevate to formal path only if a second hop is also confirmed (e.g., no PAB to prevent new policy, or no logging to detect change).
**Break chain**: (1) Remove `s3:PutBucketPolicy` from broad principals, (2) Enable logging, (3) Use SCP to restrict policy modifications.

### AP-REF-10: Account PAB Disabled + Multiple Exposed Buckets = Account-Wide Data Risk
**Category**: `data_exfiltration`
**Chain**: Account-Level PAB Disabled → Multiple Buckets with Public Policies/ACLs → Wide Data Exposure
| Hop | Evidence |
|-----|----------|
| 1. Account-level PAB disabled | CONFIRMED required |
| 2. Two or more buckets have public policies or ACLs | CONFIRMED required |
| 3. At least one exposed bucket appears sensitive | CONFIRMED or INFERRED |

**Impact**: Systemic misconfiguration — data breach risk spans the entire account.
**Break chain**: (1) Enable account-level PAB, (2) Fix each individually exposed bucket, (3) Audit contents.

### AP-REF-11: Sensitive Bucket Accessible via Overprivileged IAM Role
**Category**: `credential_access`
**Chain**: Overprivileged IAM Role → S3 Wildcard Access → Sensitive Bucket Data
| Hop | Evidence |
|-----|----------|
| 1. IAM role has `s3:*` or broad S3 actions on `Resource: *` (from IAM dependency) | CONFIRMED required |
| 2. Role assumable by broad principals or attached to exposed EC2 | CONFIRMED or INFERRED |
| 3. Sensitive buckets exist in primary S3 scan | CONFIRMED required |
| 4. Data access via overprivileged role | INFERRED |

**Break chain**: (1) Scope role S3 permissions to specific buckets/actions, (2) Tighten trust policy, (3) Add bucket-level denials.

### AP-REF-12: CloudTrail Log Bucket Tampering
**Category**: `self_escalation`
**Chain**: Broad Access to CloudTrail Log Bucket → Delete/Overwrite Logs → Cover Attack Tracks
| Hop | Evidence |
|-----|----------|
| 1. CloudTrail dependency shows trail with S3 bucket name | CONFIRMED required |
| 2. Bucket policy (from primary scan) shows write/delete for non-service principals | CONFIRMED required |
| 3. Log destruction to cover tracks | INFERRED |

**Impact**: Forensic-destruction path — makes it impossible to reconstruct attack timeline.
**Break chain**: (1) Restrict write/delete to CloudTrail service principal only, (2) Enable versioning + MFA Delete, (3) Enable log file validation.

---

## 5. Sensitive Bucket Heuristics

Use bucket names, tags, and context to tune severity.

**Raise concern** if bucket names contain:
`prod`, `production`, `customer`, `userdata`, `billing`, `invoice`, `finance`, `hr`, `backup`, `db`, `database`, `private`, `internal`, `audit`, `security`, `logs`, `cloudtrail`, `config`, `terraform`, `state`, `pii`, `medical`, `legal`, `secret`, `credential`, `key`

**Lower concern** if bucket names contain:
`static`, `assets`, `public`, `cdn`, `website`, `www`, `media`, `images`

Do not treat name-only heuristics as proof of sensitivity, but use them to prioritize review and severity.

---

## 6. S3-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are S3-specific additions:

- **Intentional public content** → `NEEDS_REVIEW` or lower severity when: bucket name suggests static/assets/public/cdn/website, website hosting enabled, access limited to `s3:GetObject`, no broad write/delete, no signs of sensitive content
- **Service principal access** (`cloudtrail.amazonaws.com`, `logging.s3.amazonaws.com`, `delivery.logs.amazonaws.com`) → NOT public exposure
- **Condition-restricted `Principal: *`** (VPC endpoint, OrgID, SourceArn, tight SourceIp) → `NEEDS_REVIEW`, not automatic CRITICAL
- **ACL neutralized by PAB** → focus on config hygiene, not real exposure

---

## 7. Remediation Playbooks

### Enable Account-Level Public Access Block
1. Verify no buckets require public access (or document exceptions)
2. Enable all four flags at account level
3. Monitor for application breakage
4. For intentional public buckets, use bucket-level overrides only after confirming need

### Fix Publicly Accessible Bucket
1. Enable bucket-level public access block
2. Remove `Principal: *` from bucket policy
3. Set ACL to private
4. Audit bucket contents for leaked credentials
5. Enable logging and versioning

### Secure Cross-Account Access
1. Identify all cross-account principals in bucket policies
2. Add restrictive conditions (OrgID, specific role ARN, external ID)
3. Scope actions to minimum required
4. Enable logging for cross-account access monitoring

### Protect Against Destructive Attacks
1. Enable versioning on all production and sensitive buckets
2. Enable MFA Delete on critical backup/audit buckets
3. Restrict write/delete permissions to specific principals
4. Enable logging for forensic visibility

### Improve S3 Monitoring
1. Enable S3 server access logging on all sensitive and exposed buckets
2. Enable CloudTrail S3 data events for high-value buckets
3. Set up alerts for unusual access patterns
4. Review log retention and access controls

---

## 8. Coverage Checklist

### Direct Findings
- [ ] Account-level public access block
- [ ] Bucket-level public access block (per bucket)
- [ ] Public bucket policies (Principal: *)
- [ ] Public ACL grants (AllUsers, AuthenticatedUsers)
- [ ] Broad write/delete permissions
- [ ] Cross-account access without tight conditions
- [ ] Default encryption configuration
- [ ] Encryption type (SSE-S3 vs SSE-KMS)
- [ ] Versioning status
- [ ] MFA Delete on critical buckets
- [ ] Logging status
- [ ] Object ownership controls
- [ ] Website hosting on non-public-intended buckets
- [ ] Replication on critical buckets
- [ ] Tagging hygiene

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Public sensitive bucket data breach
- [ ] AP-REF-02: Public write ransomware/injection
- [ ] AP-REF-03: Cross-account data exfiltration
- [ ] AP-REF-04: EC2 instance role to S3 exfiltration
- [ ] AP-REF-05: Lambda function role to S3 access
- [ ] AP-REF-06: Website bucket content injection
- [ ] AP-REF-07: Public bucket undetected exfiltration
- [ ] AP-REF-08: Broad write + no versioning destruction
- [ ] AP-REF-09: Bucket policy tampering via PutBucketPolicy
- [ ] AP-REF-10: Account PAB disabled + multiple exposures
- [ ] AP-REF-11: Overprivileged IAM role to sensitive bucket
- [ ] AP-REF-12: CloudTrail log bucket tampering
