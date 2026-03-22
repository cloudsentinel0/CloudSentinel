# IAM Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **IAM-specific** patterns only.

## Service Overview

IAM is the control plane for the AWS account. A serious IAM misconfiguration can bypass or neutralize every other security control. Treat IAM findings based on blast radius: root-level or organization-wide exposure is an account-compromise problem.

### Analysis Priorities
1. **Who can authenticate** (console users, access keys, MFA)
2. **Who can gain privilege** (escalation paths, wildcards, PassRole)
3. **Who can assume roles or act cross-account** (trust policies, STS)
4. **Whether compromise would be visible** (logging, monitoring gaps)

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: IAM ===
get-account-summary, get-account-authorization-details,
get-credential-report, get-account-password-policy,
list-users, list-roles, list-groups, list-policies (Scope=Local),
list-mfa-devices, list-access-keys, get-access-key-last-used,
list-attached-user-policies, list-user-policies,
list-attached-role-policies, list-role-policies,
get-policy-version, get-role-policy, get-user-policy,
list-groups-for-user, list-attached-group-policies,
get-role (includes trust policy)

=== DEPENDENCY CONTEXT: EC2 ===
describe-instances (instance profiles, public IPs, states),
describe-security-groups (internet exposure)

=== DEPENDENCY CONTEXT: S3 ===
list-buckets, get-bucket-policy, get-public-access-block

=== DEPENDENCY CONTEXT: LAMBDA ===
list-functions (names, roles, runtimes)

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
list-secrets

=== DEPENDENCY CONTEXT: STS ===
get-caller-identity
```

---

## 2. Relationship Mapping (Do This First)

### IAM Identity Maps
- **Users → Console Access**: login profiles (console passwords)
- **Users → MFA Status**: MFA devices per console user
- **Users → Access Keys**: key IDs, creation dates, last-used, active/inactive
- **Users → Policies**: attached managed + inline + group-inherited
- **Users → Groups**: memberships and each group's policies
- **Roles → Trust Policies**: who/what can assume (principals, services, conditions)
- **Roles → Permission Policies**: attached managed + inline
- **Roles → Classification**: service role / human-assumable / workload / break-glass / service-linked
- **Policies → Actions/Resources**: allowed actions and resource scopes

### Privilege Escalation Maps
- **PassRole Holders**: `iam:PassRole` + compute creation (`ec2:RunInstances`, `lambda:CreateFunction`, `ecs:RunTask`, `glue:CreateJob`, `cloudformation:CreateStack`)
- **Policy Version Manipulators**: `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`
- **Policy Attachers**: `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy`
- **Role Assumers**: broad `sts:AssumeRole` (wildcard or targeting admin roles)
- **Trust Policy Editors**: `iam:UpdateAssumeRolePolicy`
- **Secret Accessors**: `secretsmanager:GetSecretValue` or `ssm:GetParameter*` on wildcard

### Dependency Maps
- **EC2 Instances Using IAM Roles**: which roles are on running/public instances
- **S3 Buckets Referenced in Policies**: whether target buckets exist
- **Lambda Functions**: execution roles, invokable functions
- **Secrets**: accessible secrets list

### Derived Relationships
- **Admin-Equivalent Identities**: `*:*`, `AdministratorAccess`, or escalation paths to admin
- **Internet-Reachable Role Users**: roles on public EC2 instances
- **Cross-Account Trust Targets**: roles assumable from external accounts
- **Dormant Privileged Identities**: admin users with stale credentials

---

## 3. IAM Misconfiguration Patterns

### IAM-ROOT-KEYS: Root Account Has Active Access Keys
| Field | Value |
|-------|-------|
| Detection | `get-account-summary` shows root access keys present |
| Category | `credential_risk` |
| Base severity | CRITICAL (account-wide blast radius) |
| Fix | Delete root access keys; move automation to scoped IAM roles |
| Attack path role | Ultimate escalation target; standalone critical finding |

### IAM-ROOT-NO-MFA: Root Account Missing MFA
| Field | Value |
|-------|-------|
| Detection | Account summary or credential report: root MFA disabled |
| Category | `credential_risk` |
| Base severity | CRITICAL (account-wide) |
| Fix | Enable MFA on root immediately; restrict root to break-glass |

### IAM-USER-NO-MFA: Console User Without MFA
| Field | Value |
|-------|-------|
| Detection | User has login profile but no MFA device |
| Category | `credential_risk` |
| Base severity | HIGH (admin privileges → CRITICAL, read-only → MEDIUM) |
| Fix | Enforce deny-unless-MFA policy; onboard MFA devices |
| Attack path role | Entry point for credential-based chains |

### IAM-ADMIN-USER: AdministratorAccess on Human User
| Field | Value |
|-------|-------|
| Detection | `AdministratorAccess` or `*:*` on user identity (direct or inherited) |
| Category | `access_control` |
| Base severity | HIGH (no MFA or stale creds → CRITICAL) |
| Fix | Replace with least-privilege role assumption |
| Attack path role | High-value target; chain terminus for escalation |

### IAM-KEY-OLD: Access Key >90 Days
| Field | Value |
|-------|-------|
| Detection | Key age >90 days from creation date |
| Category | `credential_risk` |
| Base severity | HIGH (>90d), CRITICAL (>180d) |
| Fix | Rotate key, validate workloads, disable and delete old key |
| Note | Flag strongly even on production automation; note operational caution |

### IAM-KEY-UNUSED: Access Key Never Used
| Field | Value |
|-------|-------|
| Detection | Key exists, last-used absent or null |
| Category | `credential_risk` |
| Base severity | LOW (recent), MEDIUM (>90d), HIGH (privileged + dormant) |
| Fix | Disable first, verify no dependency, then delete |

### IAM-PASSWORD-POLICY: Weak or Missing Password Policy
| Field | Value |
|-------|-------|
| Detection | No policy, short minimum length, missing complexity, no reuse prevention |
| Category | `access_control` |
| Base severity | MEDIUM (HIGH if many console users without MFA) |
| Fix | Update to strong defaults (min 14 chars, complexity, reuse prevention) |

### IAM-INLINE-POLICY: Inline Policies on Users or Roles
| Field | Value |
|-------|-------|
| Detection | Inline policies attached directly to identities |
| Category | `access_control` |
| Base severity | MEDIUM (HIGH if contains wildcards or escalation actions) |
| Fix | Migrate to customer-managed policies |

### IAM-WILDCARD-ADMIN: Action:* on Resource:*
| Field | Value |
|-------|-------|
| Detection | Admin-style wildcard in customer-managed or inline policy |
| Category | `access_control` |
| Base severity | HIGH (CRITICAL if on user without MFA or cross-account role) |
| Status rule | `NEEDS_REVIEW` if appears to be documented break-glass role |
| Fix | Replace with scoped policies; use controlled role assumption for admin |

### IAM-SENSITIVE-WILDCARD: Wildcard Resource on Sensitive Actions
| Field | Value |
|-------|-------|
| Detection | `iam:PassRole`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `sts:AssumeRole` on `Resource: *` |
| Category | `access_control` |
| Base severity | HIGH (CRITICAL if combined with compute creation) |
| Fix | Scope to specific resource ARNs |
| Attack path role | Key pivot in escalation and lateral movement chains |

### IAM-PASSROLE-COMPUTE: PassRole + Compute Creation
| Field | Value |
|-------|-------|
| Detection | `iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction` / `ecs:RunTask` / `glue:CreateJob` / `cloudformation:CreateStack` |
| Category | `access_control` |
| Base severity | CRITICAL |
| Fix | Restrict passable roles by ARN; scope compute creation |
| Attack path role | Core escalation mechanism — new compute with chosen role |

### IAM-POLICY-VERSION-ABUSE: Policy Version Manipulation
| Field | Value |
|-------|-------|
| Detection | `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` |
| Category | `access_control` |
| Base severity | CRITICAL (if policy attached to stronger identity), HIGH otherwise |
| Fix | Remove version-management rights from non-admin principals |
| Attack path role | Silent escalation — modifies existing policy |

### IAM-TRUST-WILDCARD: Trust Policy with Wildcard Principal
| Field | Value |
|-------|-------|
| Detection | Trust policy with `Principal: *` or very broad principal, weak/no conditions |
| Category | `access_control` |
| Base severity | CRITICAL |
| Fix | Restrict trusted principals; require strong conditions |
| Attack path role | Entry point — any AWS principal worldwide can assume |

### IAM-CROSS-ACCOUNT: Cross-Account Trust Without Constraints
| Field | Value |
|-------|-------|
| Detection | External account trusted with no external ID, weak conditions, broad trust |
| Category | `access_control` |
| Base severity | HIGH (CRITICAL if role is admin-equivalent) |
| Status rule | `NEEDS_REVIEW` if trust appears intentional but can't validate constraints |
| Fix | Add external ID, scope to specific role ARNs, add org conditions |

### IAM-DORMANT-ADMIN: Dormant Privileged User
| Field | Value |
|-------|-------|
| Detection | Privileged user, stale console login + key use (>90 days inactive) |
| Category | `credential_risk` |
| Base severity | MEDIUM (HIGH if no MFA or broad admin) |
| Fix | Disable credentials, verify need, convert to break-glass if retained |

### IAM-DIRECT-PERMISSIONS: Users with Direct Policy Attachments
| Field | Value |
|-------|-------|
| Detection | Multiple users have policies attached directly instead of via groups/roles |
| Category | `access_control` |
| Base severity | MEDIUM |
| Fix | Move to group- or role-based access model |

---

## 4. IAM Attack Path Catalog

Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Console Phishing → Account Takeover
**Category**: `credential_access`
**Chain**: Console User → No MFA → Admin Permissions → Full Account Control
| Hop | Evidence |
|-----|----------|
| 1. Login profile exists | CONFIRMED required |
| 2. No MFA device | CONFIRMED required |
| 3. Admin-equivalent permissions | CONFIRMED required |
| 4. Account takeover | INFERRED |

**Break chain**: (1) Enable MFA, (2) Move admin to role assumption, (3) Deploy deny-unless-MFA policy.

### AP-REF-02: Old Key Leak → Persistent API Compromise
**Category**: `credential_access`
**Chain**: Key >90d → Active → Privileged Permissions → Data/Resource Access
| Hop | Evidence |
|-----|----------|
| 1. Key >90 days old | CONFIRMED required |
| 2. Key status Active | CONFIRMED required |
| 3. Broad/sensitive permissions | CONFIRMED required |
| 4. Reachable targets (S3/secrets) | CONFIRMED or INFERRED |

**Break chain**: (1) Rotate key, (2) Scope permissions, (3) Audit CloudTrail.

### AP-REF-03: PassRole Privilege Escalation via Compute
**Category**: `new_passrole`
**Chain**: Limited Principal → `iam:PassRole` → Compute Creation → Stronger Role
| Hop | Evidence |
|-----|----------|
| 1. Principal's policies in scan | CONFIRMED required |
| 2. `iam:PassRole` action (note resource scope) | CONFIRMED required |
| 3. Compute creation action | CONFIRMED required |
| 4. Passed role's permissions | CONFIRMED or INFERRED |

**Impact**: Creates compute with admin role → steal credentials → full account access. Most common IAM escalation.
**Break chain**: (1) Restrict PassRole to specific role ARNs, (2) Scope compute creation, (3) SCP guardrails.

### AP-REF-04: Policy Version Manipulation Escalation
**Category**: `self_escalation`
**Chain**: Limited Principal → `CreatePolicyVersion` → `SetDefaultPolicyVersion` → Inject Admin
| Hop | Evidence |
|-----|----------|
| 1. `iam:CreatePolicyVersion` | CONFIRMED required |
| 2. `iam:SetDefaultPolicyVersion` | CONFIRMED required |
| 3. Target policy attached to higher-privilege identity | CONFIRMED or INFERRED |

**Impact**: Silently replaces existing policy with admin-equivalent. Hard to detect.
**Break chain**: (1) Remove version management from non-admin, (2) SCP restriction, (3) Monitor CloudTrail.

### AP-REF-05: Wildcard AssumeRole → Admin Lateral Movement
**Category**: `lateral_movement`
**Chain**: `sts:AssumeRole` (wildcard) → Admin Role → Account Control
| Hop | Evidence |
|-----|----------|
| 1. `sts:AssumeRole` with wildcard/broad scope | CONFIRMED required |
| 2. Admin role exists + trust policy allows principal | CONFIRMED required |
| 3. Escalation outcome | INFERRED |

**Break chain**: (1) Scope AssumeRole to specific ARNs, (2) Tighten admin trust policies, (3) Require MFA conditions.

### AP-REF-06: Cross-Account Trust Chain
**Category**: `lateral_movement`
**Chain**: External Account → Assume Role (weak trust) → Internal Resources
| Hop | Evidence |
|-----|----------|
| 1. Trust policy shows external account | CONFIRMED required |
| 2. Missing external ID / overly broad trust | CONFIRMED required |
| 3. Role has meaningful permissions | CONFIRMED required |
| 4. Target resources exist | CONFIRMED or INFERRED |

**Break chain**: (1) Add external ID conditions, (2) Scope trusted principals, (3) Reduce role permissions.

### AP-REF-07: Wildcard Trust → World-Assumable Role
**Category**: `principal_access`
**Chain**: `Principal: *` → Any AWS Principal Assumes → Role Permissions
| Hop | Evidence |
|-----|----------|
| 1. Trust policy shows `"Principal": "*"` with no/weak conditions | CONFIRMED required |
| 2. Assumption capability | INFERRED |
| 3. Role has meaningful permissions | CONFIRMED required |

**Impact**: Any AWS user worldwide can assume the role. Effectively public access.
**Break chain**: (1) Restrict trust to specific accounts/principals, (2) Add conditions, (3) Reduce permissions.

### AP-REF-08: Dormant Admin Credential Reactivation
**Category**: `credential_access`
**Chain**: Dormant User → Credentials Still Active → Admin Privileges → Takeover
| Hop | Evidence |
|-----|----------|
| 1. >90 days dormancy (credential report) | CONFIRMED required |
| 2. Credentials in Active status | CONFIRMED required |
| 3. Admin-equivalent permissions | CONFIRMED required |
| 4. Credential compromise | INFERRED |

**Break chain**: (1) Disable credentials, (2) Verify need with owner, (3) Enforce MFA if retained.

### AP-REF-09: Secret Access → Lateral Movement
**Category**: `credential_access` + `lateral_movement`
**Chain**: Compromised Identity → `secretsmanager:GetSecretValue` → DB/API Creds → Lateral Access
| Hop | Evidence |
|-----|----------|
| 1. Identity compromise vector confirmed (old key, no MFA, public instance role) | CONFIRMED required |
| 2. Policy shows secret access actions | CONFIRMED required |
| 3. Secrets exist (from dependency context) | CONFIRMED or INFERRED |
| 4. Lateral access via secret content | INFERRED |

**Break chain**: (1) Fix identity compromise vector, (2) Scope secret access to ARNs, (3) Enable rotation.

### AP-REF-10: Policy Attachment Self-Elevation
**Category**: `self_escalation`
**Chain**: Limited Principal → `iam:AttachUserPolicy`/`iam:PutUserPolicy` → Self-Attach Admin
| Hop | Evidence |
|-----|----------|
| 1. Policy shows attachment actions | CONFIRMED required |
| 2. Self-elevation | INFERRED |
| 3. Account control | INFERRED |

**Note**: May only have 1 CONFIRMED hop. Keep as CRITICAL finding unless a second hop (current limited scope or admin policy availability) is also confirmed.
**Break chain**: (1) Remove policy attachment from non-admin, (2) SCP restriction, (3) Monitor CloudTrail.

### AP-REF-11: EC2 Instance Role → Account Escalation (Cross-Service)
**Category**: `self_escalation` + `network_entry`
**Chain**: Public EC2 → IAM Role → IAM Write → Create Backdoor
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG (from EC2 dependency context) | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. Role has IAM write actions (primary IAM scan) | CONFIRMED required |
| 4. Account escalation | INFERRED |

**Note**: Entry point is from EC2 context, but the core finding is the IAM role permissions (primary scope). Valid cross-service path.
**Break chain**: (1) Remove IAM write from EC2 role, (2) Restrict instance exposure, (3) Enforce IMDSv2.

### AP-REF-12: Weak Password Policy + Mass Console Users
**Category**: `credential_access`
**Chain**: Weak Policy → Many Console Users → No MFA → Credential Compromise
| Hop | Evidence |
|-----|----------|
| 1. Weak/missing password policy | CONFIRMED required |
| 2. Multiple console users | CONFIRMED required |
| 3. Users without MFA | CONFIRMED required |
| 4. Credential compromise | INFERRED |

**Impact**: Depends on privileges of vulnerable users — if any are admin, becomes account-takeover path.
**Break chain**: (1) Enforce MFA on all, (2) Strengthen password policy, (3) Deploy deny-unless-MFA.

---

## 5. IAM-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are IAM-specific:

**Treat as `NEEDS_REVIEW`**:
- One tightly controlled break-glass admin with MFA, strong naming, no stale keys
- Externally assumable role for vetted third-party integration with narrow trust
- CI/CD principal with long-lived credentials that is isolated and recently rotated
- Service-linked or infrastructure deployment role with expected broad permissions

**Do NOT flag as MFA issues**:
- Workload roles, service roles, programmatic-only identities without console access

### Identity Classification (informs severity)
| Type | Priority checks |
|------|----------------|
| Human user | MFA, console posture, admin rights |
| Automation user | Key age, scope, role migration opportunities |
| Workload role | Trust policy, PassRole interactions, secret access |
| Break-glass admin | Acceptable only with tight controls, MFA, rare use |
| Service-linked role | Usually not a finding unless trust/permissions unexpectedly changed |

---

## 6. Remediation Playbooks

### Enforce MFA for Console Users
1. Identify all console-enabled human users
2. Deploy deny-unless-MFA guardrail policy
3. Notify owners, enroll MFA devices
4. Disable non-compliant users after deadline

### Remove Long-Lived Access Keys
1. Create replacement auth (prefer role, then scoped fresh key)
2. Update workloads, validate
3. Set old key inactive → monitor → delete

### Contain Privilege Escalation Paths
1. Find `iam:PassRole`, `sts:AssumeRole`, policy version management, attach/put policy rights
2. Restrict to approved admin automation only
3. Scope passable roles by ARN, block broad assumption

### Migrate to Role-Based Access
1. Remove direct user policies
2. Create job-function roles/groups
3. Move humans to role assumption for elevated access
4. Keep break-glass minimal and audited

### Secure Cross-Account Trust
1. Identify roles with external trust principals
2. Add external ID conditions
3. Scope to specific role ARNs
4. Reduce permissions to minimum
5. Monitor CloudTrail for external AssumeRole

---

## 7. Coverage Checklist

### Direct Findings
- [ ] Root access keys
- [ ] Root MFA
- [ ] Console users without MFA
- [ ] AdministratorAccess on human users
- [ ] Old access keys (>90d)
- [ ] Unused access keys
- [ ] Password policy strength
- [ ] Inline policies with broad permissions
- [ ] Wildcard admin policies (`*:*`)
- [ ] Sensitive actions on wildcard resources
- [ ] PassRole + compute creation
- [ ] Policy version manipulation
- [ ] Wildcard trust policies
- [ ] Cross-account trust without constraints
- [ ] Dormant privileged users
- [ ] Direct user policy attachments

### Attack Paths
- [ ] AP-REF-01: Console phishing → account takeover
- [ ] AP-REF-02: Old key leak → API compromise
- [ ] AP-REF-03: PassRole escalation via compute
- [ ] AP-REF-04: Policy version manipulation
- [ ] AP-REF-05: Wildcard AssumeRole lateral movement
- [ ] AP-REF-06: Cross-account trust chain
- [ ] AP-REF-07: Wildcard trust world-assumable role
- [ ] AP-REF-08: Dormant admin reactivation
- [ ] AP-REF-09: Secret access → lateral movement
- [ ] AP-REF-10: Policy attachment self-elevation
- [ ] AP-REF-11: EC2 role → account escalation
- [ ] AP-REF-12: Weak password + mass console users
