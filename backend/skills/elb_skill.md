# ELB Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **ELB-specific** patterns only.

## Service Overview

Load balancers are the exposure brokers for many AWS applications. ELB findings should not stop at "the listener is public." The important question is what the listener exposes, how traffic is protected, what targets sit behind it, and whether the load balancer turns a private backend into an externally reachable service.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: ELB ===
elbv2 describe-load-balancers, elbv2 describe-listeners (per ALB/NLB),
elbv2 describe-rules (per ALB listener), elbv2 describe-target-groups,
elbv2 describe-target-health (per target group),
elbv2 describe-load-balancer-attributes (per ALB/NLB),
elbv2 describe-target-group-attributes (per target group),
elbv2 describe-tags (per LB/TG),
elb describe-load-balancers, elb describe-load-balancer-attributes (per Classic),
elb describe-load-balancer-policies (per Classic listener), elb describe-tags

=== DEPENDENCY CONTEXT: EC2 ===
describe-security-groups, describe-subnets, describe-route-tables,
describe-instances (targets behind public LBs)

=== DEPENDENCY CONTEXT: WAFV2 ===
get-web-acl-for-resource (per ALB ARN)

=== DEPENDENCY CONTEXT: ACM ===
describe-certificate (per listener certificate ARN)

=== DEPENDENCY CONTEXT: IAM ===
list-instance-profiles, get-role, list-attached-role-policies,
get-policy-version (per EC2 target role)
```

---

## 2. Relationship Mapping (Do This First)

### Load Balancer Resource Maps
- **LB → Type and Scheme**: ALB, NLB, or Classic ELB; `internet-facing` vs `internal`
- **LB → Subnets / VPC**: where the LB lives and whether the subnets are public
- **LB → Listener Set**: protocols, ports, certificates, SSL/TLS policies
- **LB → Rules**: listener rule conditions and forwarding actions
- **LB → Target Groups**: protocol, port, target type, and health
- **LB → Attributes**: access logs, deletion protection, HTTP hardening attributes
- **LB → Tags**: sensitivity and business context indicators

### Dependency Maps
- **LB → Security Groups**: for ALB and Classic ELB, inbound sources and ports
- **LB → Public Subnet Intent**: whether the LB is actually in IGW-routed subnets
- **Target Group → EC2 Targets**: which instances sit behind public listeners
- **Target EC2 → IAM Role**: what cloud permissions target instances carry
- **ALB → WAF**: whether a web ACL is attached
- **Listener → ACM Certificate**: certificate metadata where HTTPS/TLS exists

### Derived Relationships
- **Direct Internet Exposure**: internet-facing scheme + public subnet + exposed listener
- **Sensitive Service Exposure**: public listener forwards to admin or data-service ports
- **Web-to-Cloud Pivot Path**: public ALB → EC2 targets → attached IAM role
- **Undetected Exposure**: public listener + access logs disabled
- **Weak Front Door**: public HTTP-only or outdated TLS policy

---

## 3. ELB Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### ELB-PUBLIC-SENSITIVE-PORT: Internet-Facing Listener Exposes Admin or Data Port
| Field | Value |
|-------|-------|
| Detection | Internet-facing ALB/NLB/CLB listener on ports 22, 3389, 3306, 5432, 1433, 1521, 2379, 9200, 5601, 8080 admin, or other non-public service ports |
| Category | `network_exposure` |
| Base severity | CRITICAL |
| Fix | Restrict/remove listener, move service behind private LB, or add stronger controls |
| Attack path role | Direct entry point for host or data-service compromise |

### ELB-HTTP-ONLY: Internet-Facing Web LB Uses HTTP Without Strong HTTPS Enforcement
| Field | Value |
|-------|-------|
| Detection | Public ALB/CLB serves HTTP on port 80 without a proven HTTPS listener and redirect |
| Category | `access_control` |
| Base severity | MEDIUM (login/auth/admin/customer naming → HIGH, HTTP only redirects → LOW or no finding) |
| Fix | Add HTTPS/TLS listener and redirect HTTP to HTTPS |

### ELB-WEAK-TLS-POLICY: Public HTTPS/TLS Listener Uses Outdated Security Policy
| Field | Value |
|-------|-------|
| Detection | Public HTTPS/TLS listener uses outdated or weak SSL/TLS policy |
| Category | `compliance` |
| Base severity | HIGH |
| Status rule | `NEEDS_REVIEW` if policy name visible but exact cipher/TLS implications can't be mapped |
| Fix | `aws elbv2 modify-listener --listener-arn {listener-arn} --ssl-policy {modern-policy}` |

### ELB-NO-WAF: Public ALB Missing WAF Association
| Field | Value |
|-------|-------|
| Detection | Internet-facing ALB with HTTP/HTTPS listeners, no WAF in dependency context |
| Category | `access_control` |
| Base severity | MEDIUM (public admin/customer-facing → HIGH) |
| Status rule | `NEEDS_REVIEW` when ALB fronts low-risk site or non-browser workload |
| Fix | `aws wafv2 associate-web-acl --web-acl-arn {web-acl-arn} --resource-arn {lb-arn}` |

### ELB-NO-ACCESS-LOGS: Access Logging Disabled on Public or Important LB
| Field | Value |
|-------|-------|
| Detection | Access logs disabled on internet-facing or important LB |
| Category | `logging_monitoring` |
| Base severity | MEDIUM (internet-facing + sensitive → HIGH) |
| Fix (v2) | `aws elbv2 modify-load-balancer-attributes --load-balancer-arn {lb-arn} --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value={log-bucket}` |
| Fix (Classic) | `aws elb modify-load-balancer-attributes --load-balancer-name {lb-name} --load-balancer-attributes AccessLog={Enabled=true,S3BucketName={log-bucket},EmitInterval=5}` |

### ELB-DELETION-PROTECTION-OFF: Deletion Protection Disabled on Important LB
| Field | Value |
|-------|-------|
| Detection | Deletion protection disabled on public or production LB |
| Category | `resource_hygiene` |
| Base severity | LOW (public or production → MEDIUM) |
| Fix | `aws elbv2 modify-load-balancer-attributes --load-balancer-arn {lb-arn} --attributes Key=deletion_protection.enabled,Value=true` |

### ELB-ALB-SG-BROAD-NONWEB: ALB/CLB Security Group Broadly Open on Non-Web Ports
| Field | Value |
|-------|-------|
| Detection | SG attached to ALB/CLB allows `0.0.0.0/0` or `::/0` on non-standard web ports exposing admin/backend |
| Category | `network_exposure` |
| Base severity | HIGH (listener also forwards same sensitive port → CRITICAL) |
| Fix | `aws elbv2 set-security-groups --load-balancer-arn {lb-arn} --security-groups {approved-sg-list}` |

### ELB-PUBLIC-TO-SENSITIVE-TARGET: Public Listener Forwards to Sensitive Backend
| Field | Value |
|-------|-------|
| Detection | Listener rule or target group forwards public traffic to admin, database, or sensitive backend ports/paths |
| Category | `network_exposure` |
| Base severity | CRITICAL |
| Fix | Move target behind private LB or restrict listener/rule to approved sources and paths |
| Attack path role | Direct path from internet to sensitive backend |

### ELB-HTTP-HARDENING-WEAK: HTTP Header / Desync Hardening Attributes Disabled
| Field | Value |
|-------|-------|
| Detection | ALB attributes show weak values for `routing.http.drop_invalid_header_fields.enabled` or desync mitigation |
| Category | `compliance` |
| Base severity | LOW |
| Status rule | `NEEDS_REVIEW` when exact attribute set is incomplete |
| Fix | Update ALB attributes to stronger recommended values |

---

## 4. ELB Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Internet to Sensitive Backend Port Through Public LB
**Category**: `network_entry`
**Chain**: Internet → Public LB Listener → Admin/Data Service Port
| Hop | Evidence |
|-----|----------|
| 1. LB is internet-facing | CONFIRMED required |
| 2. Listener exposes a sensitive port | CONFIRMED required |
| 3. Target group/backend serves the sensitive service | CONFIRMED required |

**Impact**: LB creates direct external path to admin or data-bearing backend.
**Break chain**: (1) Remove/restrict public listener, (2) Move service behind private LB, (3) Restrict backend SGs.

### AP-REF-02: Internet to Database Service via Public NLB/CLB
**Category**: `network_entry` + `data_exfiltration`
**Chain**: Internet → Public LB → Database Port → Direct Data Access
| Hop | Evidence |
|-----|----------|
| 1. LB is internet-facing | CONFIRMED required |
| 2. Listener exposes DB port (3306, 5432, 1433, 1521) | CONFIRMED required |
| 3. Target indicates database-style service | CONFIRMED required |

**Impact**: LB turns a database into an internet-facing endpoint.
**Break chain**: (1) Remove public DB listeners, (2) Move behind private connectivity, (3) Restrict to app-tier sources.

### AP-REF-03: Public ALB to EC2 Target to IAM Role Pivot
**Category**: `credential_access`
**Chain**: Internet → Public ALB → EC2 Target → IAM Role → Cloud Access
| Hop | Evidence |
|-----|----------|
| 1. ALB is public with web listener | CONFIRMED required |
| 2. Target group contains EC2 instances | CONFIRMED required |
| 3. Application compromise | INFERRED |
| 4. Target instance has attached IAM role with meaningful permissions (dependency) | CONFIRMED required |

**Minimum**: Hops 1, 2, and 4 must be CONFIRMED.
**Impact**: Web compromise at LB edge becomes cloud compromise through target instance role.
**Break chain**: (1) Add WAF + tighten exposure, (2) Reduce target IAM permissions, (3) Harden metadata settings.

### AP-REF-04: Public ALB Rule Exposes Admin Path
**Category**: `network_entry`
**Chain**: Internet → Public ALB → Path/Host Rule → Admin Target
| Hop | Evidence |
|-----|----------|
| 1. ALB is internet-facing | CONFIRMED required |
| 2. Rule forwards traffic for admin-looking path or host | CONFIRMED required |
| 3. Rule points to admin/internal/privileged target group | CONFIRMED required |

**Impact**: Path or host rule exposes internal admin surface to the internet.
**Break chain**: (1) Remove/restrict public rule, (2) Move admin behind private access, (3) Validate target alignment.

### AP-REF-05: Public LB + No Access Logs = Undetected Exposure
**Category**: `network_entry`
**Chain**: Internet-Facing LB → Sensitive Exposure → No Access Logs
| Hop | Evidence |
|-----|----------|
| 1. LB is internet-facing | CONFIRMED required |
| 2. Sensitive listener/rule/target path | CONFIRMED required |
| 3. Access logs disabled | CONFIRMED required |

**Impact**: Abuse of exposed service is harder to investigate or detect.
**Break chain**: (1) Break exposure path first, (2) Enable access logs, (3) Ensure retention and monitoring.

### AP-REF-06: Public ALB Without WAF Protects High-Risk Web Surface
**Category**: `network_entry`
**Chain**: Internet → Public ALB → No WAF → App Target
| Hop | Evidence |
|-----|----------|
| 1. Internet-facing ALB serves HTTP/HTTPS | CONFIRMED required |
| 2. No web ACL attached (dependency) | CONFIRMED required |
| 3. ALB forwards to EC2/IP targets hosting application | CONFIRMED required |

**Impact**: Application-facing edge lacks common app-layer filtering.
**Break chain**: (1) Attach WAF ACL, (2) Tighten listeners/rules, (3) Review backend hardening.

### AP-REF-07: Public NLB to Private Target Bypasses Intended Isolation
**Category**: `network_entry`
**Chain**: Internet → Public NLB → Private Subnet Target → Internal Service Becomes Public
| Hop | Evidence |
|-----|----------|
| 1. NLB is internet-facing | CONFIRMED required |
| 2. Targets in private subnets or intended to be internal (dependency) | CONFIRMED required |
| 3. Listener exposes those targets publicly | CONFIRMED required |

**Impact**: NLB turns privately placed service into externally reachable endpoint.
**Break chain**: (1) Move behind internal LB, (2) Restrict listener, (3) Recheck SGs and route intent.

### AP-REF-08: Public ALB to EC2 Target to S3/Secrets Through Instance Role
**Category**: `credential_access` + `data_exfiltration`
**Chain**: Internet → Public ALB → EC2 Target → IAM Role → Sensitive AWS Service
| Hop | Evidence |
|-----|----------|
| 1. Public ALB with web listener | CONFIRMED required |
| 2. Target group contains EC2 instances | CONFIRMED required |
| 3. Application compromise | INFERRED |
| 4. Target role has S3, Secrets Manager, or IAM write access (dependency) | CONFIRMED required |

**Minimum**: Hops 1, 2, and 4 must be CONFIRMED.
**Impact**: LB is front door for a path ending in cloud-level data access or privilege escalation.
**Break chain**: (1) Reduce exposure + add WAF, (2) Remove sensitive permissions from target roles, (3) Harden metadata.

---

## 5. ELB-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are ELB-specific additions:

- **Public ALB on 80/443 for a legitimate website** → expected by itself, not a finding
- **Internal LBs with broad private-source access** → often architectural, not automatic finding
- **No WAF on non-HTTP LBs** → not applicable
- **NLB TLS pass-through** → don't assume weak TLS if backend legitimately terminates encryption
- **HTTP listener that only redirects to HTTPS** → lower severity or no finding when redirect is proven

---

## 6. Remediation Playbooks

### Remove Public Exposure to Sensitive Services
1. Inventory internet-facing listeners and ports
2. Remove listeners that expose admin or data ports
3. Move sensitive services behind internal load balancers
4. Restrict target access to approved upstream tiers only

### Harden the Public Web Edge
1. Ensure HTTP redirects to HTTPS where appropriate
2. Upgrade listener TLS policies
3. Validate certificate coverage and rotation
4. Attach WAF to public ALBs

### Improve Edge Visibility
1. Enable access logs for public and important load balancers
2. Confirm log destination ownership and retention
3. Monitor for unexpected listener or rule changes

### Reduce Backend Cloud Blast Radius
1. Identify public LBs fronting EC2 targets with IAM roles
2. Reduce target-role permissions to least privilege
3. Harden target instances and metadata settings
4. Separate internet-facing and internal workload roles

---

## 7. Coverage Checklist

### Direct Findings
- [ ] Internet-facing listeners on admin or data-service ports
- [ ] Public HTTP-only listeners without strong HTTPS enforcement
- [ ] Weak TLS policies on public listeners
- [ ] Public ALBs without WAF
- [ ] Access logging on public or important load balancers
- [ ] Deletion protection on important ALB/NLB
- [ ] Broad ALB/CLB SG exposure on non-web ports
- [ ] Public listeners forwarding to sensitive backend targets
- [ ] HTTP hardening attributes where available

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Public LB to sensitive backend port
- [ ] AP-REF-02: Public LB to database service
- [ ] AP-REF-03: Public ALB to EC2 target to IAM role pivot
- [ ] AP-REF-04: Public ALB admin-path exposure
- [ ] AP-REF-05: Public exposure + no access logs
- [ ] AP-REF-06: Public ALB without WAF on app surface
- [ ] AP-REF-07: Public NLB to private target isolation bypass
- [ ] AP-REF-08: Public ALB to EC2 target to sensitive AWS service via role
