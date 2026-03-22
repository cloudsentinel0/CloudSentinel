# VPC Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **VPC-specific** patterns only.

## Service Overview

VPC defines network segmentation, routing intent, and reachability boundaries across the AWS account. VPC findings should not be treated as isolated configuration issues. The real question is whether the network design creates unintended reachability, weak segmentation, poor visibility, or easy lateral movement after compromise. This skill should reason about VPCs as architecture, not just as resource lists.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: VPC ===
describe-vpcs, describe-subnets, describe-route-tables,
describe-network-acls, describe-internet-gateways,
describe-nat-gateways, describe-vpc-endpoints,
describe-vpc-peering-connections, describe-flow-logs,
describe-egress-only-internet-gateways,
describe-transit-gateway-attachments, describe-vpc-endpoint-services

=== DEPENDENCY CONTEXT: EC2 ===
describe-instances, describe-security-groups, describe-network-interfaces

=== DEPENDENCY CONTEXT: IAM ===
list-instance-profiles, get-role

=== DEPENDENCY CONTEXT: RDS ===
describe-db-instances

=== DEPENDENCY CONTEXT: ELB ===
describe-load-balancers
```

---

## 2. Relationship Mapping (Do This First)

### VPC Resource Maps
- **VPC → Default or Custom**: whether each VPC is `IsDefault: true`
- **VPC → Flow Log Coverage**: whether flow logs exist for each VPC
- **VPC → Subnets**: all subnets per VPC
- **VPC → Internet Gateways**: IGW attachments per VPC
- **VPC → NAT Gateways**: NAT gateway placements per VPC
- **VPC → Endpoints**: VPC endpoints per VPC (gateway and interface)
- **VPC → Peering Connections**: active peering connections per VPC

### Subnet Classification (Use Route Tables as Source of Truth)
- **Subnet → Route Table**: which route table is associated (explicit or main)
- **Subnet → Classification**:
  - **Public**: default route (`0.0.0.0/0` or `::/0`) to `igw-*`
  - **Private**: default route to `nat-*` or no internet route
  - **Isolated**: no default internet route at all
- **Subnet → MapPublicIpOnLaunch**: auto-assign public IP setting
- **Subnet → Tags/Name**: intended purpose from naming (public, private, app, db, mgmt, etc.)
- **Subnet → Intent Match**: compare route-based classification to name/tag intent

### Network Control Maps
- **NACL → Subnets**: which NACLs are associated with which subnets
- **NACL → Rule Analysis**: whether NACLs provide meaningful segmentation or are effectively allow-all
- **Peering → Direction and Scope**: same-account vs cross-account, accepted status, route scopes

### Dependency Maps
- **EC2 Instances per Subnet**: which instances are running where, public IPs, instance profiles
- **Security Groups per VPC**: SG rules showing actual port exposure
- **RDS Instances per Subnet**: database instances, public accessibility flags
- **Load Balancers per Subnet**: internet-facing vs internal schemes
- **IAM Roles on Instances**: what roles are attached to instances in each subnet

### Derived Relationships
- **Active VPCs**: VPCs with running instances, ENIs, load balancers, or RDS instances
- **Sensitive Subnets**: subnets tagged/named for db, mgmt, admin, backup, security, or containing RDS instances
- **Intent Mismatches**: subnets named "private" but routed to IGW
- **Blind Spots**: active VPCs without flow logs

---

## 3. Network Classification Logic

### Determine Subnet Type (Route Tables First)
- **Public subnet**: default route to IGW or equivalent direct internet path
- **Private subnet**: default route to NAT gateway/instance but not to IGW
- **Isolated subnet**: no default internet route

### Determine Exposure Context
Increase concern if subnet or attached resources appear to be: prod/production, db/database, mgmt/admin/bastion, backup/archive, security tooling, internal-only applications.

### Determine Activity Level
Raise severity when VPC/subnet has (from dependency context): running instances, active ENIs, load balancers, RDS instances, EKS/ECS context if visible through tags. Lower severity for empty or clearly dormant networks.

---

## 4. VPC Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### VPC-FLOWLOG-DISABLED: VPC Flow Logs Disabled on Active VPC
| Field | Value |
|-------|-------|
| Detection | No flow logs for a VPC that has workloads (confirmed via dependency context or subnet/ENI presence) |
| Category | `logging_monitoring` |
| Base severity | HIGH (empty/non-prod → MEDIUM, sensitive + broad exposure → CRITICAL) |
| Fix | Enable flow logs to CloudWatch Logs or S3 with correct IAM role and retention |
| Attack path role | Amplifies all attack paths — compromise and movement go undetected |

### VPC-DEFAULT-IN-USE: Default VPC Used for Real Workloads
| Field | Value |
|-------|-------|
| Detection | `IsDefault: true` with attached subnets/resources in use (from dependency context) |
| Category | `resource_hygiene` |
| Base severity | MEDIUM (raise to HIGH if sensitive/production workloads, especially with public IP auto-assign) |
| Fix | Migrate to purpose-built VPC architecture and retire default VPC usage |

### VPC-SUBNET-AUTO-PUBLIC: Subnet Auto-Assigns Public IP Unexpectedly
| Field | Value |
|-------|-------|
| Detection | `MapPublicIpOnLaunch: true` |
| Category | `network_exposure` |
| Base severity | MEDIUM (private/internal/db/mgmt/prod tags → HIGH, clearly intended public web → LOW) |
| Fix | `aws ec2 modify-subnet-attribute --subnet-id {subnet-id} --no-map-public-ip-on-launch` |
| Attack path role | Creates unintended internet exposure for new workloads |

### VPC-PRIVATE-IGW-ROUTE: IGW Route on Supposedly Private Subnet
| Field | Value |
|-------|-------|
| Detection | Subnet named/tagged private/internal but associated route table has `0.0.0.0/0` to `igw-*` |
| Category | `network_exposure` |
| Base severity | HIGH (CRITICAL if subnet hosts db/admin/sensitive + broad SG context) |
| Fix | Replace IGW route with NAT or remove default internet route entirely |
| Attack path role | Core misclassification that enables unexpected exposure |

### VPC-NACL-ALLOW-ALL: Broad Allow-All NACL on Active Subnet
| Field | Value |
|-------|-------|
| Detection | NACL rules broadly allow all traffic from/to `0.0.0.0/0` with permissive low rule numbers |
| Category | `network_exposure` |
| Base severity | HIGH (sensitive/active subnets), MEDIUM (routine public tiers), LOW (empty networks) |
| Fix | Create targeted allows and explicit deny posture where architecture requires segmentation |
| Note | Default allow-all NACLs are common; key issue is whether stronger segmentation was expected |
| Attack path role | Removes a network defense layer, amplifying SG misconfigurations |

### VPC-NO-ENDPOINTS: Missing VPC Endpoints for High-Use AWS Services
| Field | Value |
|-------|-------|
| Detection | No S3/DynamoDB endpoints in VPCs that appear to use those services |
| Category | `network_exposure` |
| Base severity | MEDIUM (raise to HIGH if security-sensitive workloads move large traffic through NAT/internet) |
| Fix | Deploy gateway or interface endpoints with restrictive policies |

### VPC-ENDPOINT-BROAD-POLICY: Endpoint Policy Too Broad
| Field | Value |
|-------|-------|
| Detection | Interface/gateway endpoint exists but policy allows overly broad principals/actions/resources |
| Category | `access_control` |
| Base severity | MEDIUM–HIGH depending on exposed service/data sensitivity |
| Fix | Scope endpoint policy to approved principals, buckets, prefixes, or actions |

### VPC-IGW-UNUSED: Unused Internet Gateway
| Field | Value |
|-------|-------|
| Detection | IGW exists but not attached or attached VPC has no subnets using it |
| Category | `resource_hygiene` |
| Base severity | LOW |
| Fix | Remove unused IGW after dependency validation |

### VPC-NAT-UNUSED: Unused NAT Gateway
| Field | Value |
|-------|-------|
| Detection | NAT gateway exists but no route tables reference it |
| Category | `cost` |
| Base severity | MEDIUM (NAT gateways are expensive) |
| Fix | Remove unused NAT gateway after dependency validation |

### VPC-PEERING-CROSS-ACCOUNT: Cross-Account VPC Peering
| Field | Value |
|-------|-------|
| Detection | Peering connection owner IDs differ from requester/accepter |
| Category | `network_exposure` |
| Base severity | MEDIUM (raise to HIGH/CRITICAL if peer reaches sensitive/admin/db tiers with minimal filtering) |
| Status rule | `NEEDS_REVIEW` until business need, scope, and filtering validated |
| Fix | Validate business need, narrow routes, add subnet/NACL/SG segmentation |

### VPC-PEERING-BROAD-ROUTES: Overly Broad Peering Routes
| Field | Value |
|-------|-------|
| Detection | Large CIDR routes to peering connection covering many subnets or sensitive ranges |
| Category | `network_exposure` |
| Base severity | HIGH |
| Fix | Narrow route scopes and isolate sensitive subnets from peer-reachable ranges |

### VPC-NO-SEGMENTATION: No Meaningful Segmentation Between Tiers
| Field | Value |
|-------|-------|
| Detection | Public, app, and db subnets share broad routing/NACL posture with little network separation |
| Category | `network_exposure` |
| Base severity | HIGH (CRITICAL if sensitive prod tiers reachable from internet-facing zones + poor visibility) |
| Fix | Redesign subnet/route/NACL boundaries and tighten east-west controls |
| Attack path role | Enables lateral movement from any compromised instance |

### VPC-IPV6-UNCONTROLLED: Internet-Reachable IPv6 Path Not Considered
| Field | Value |
|-------|-------|
| Detection | `::/0` route to IGW or egress path with weak matching NACL/SG controls |
| Category | `network_exposure` |
| Base severity | HIGH if workloads are IPv6-addressable and sensitive |
| Fix | Review IPv6 route intent and ensure SG/NACL controls match IPv4 hardening |

---

## 5. VPC Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Broken Private Subnet → Unintended Internet Exposure
**Category**: `network_entry`
**Chain**: "Private" Subnet with IGW Route → Public IP Auto-Assign → Sensitive Instance Exposed
| Hop | Evidence |
|-----|----------|
| 1. Subnet named/tagged private but route table has `0.0.0.0/0` to IGW | CONFIRMED required |
| 2. `MapPublicIpOnLaunch: true` OR instances have public IPs | CONFIRMED required |
| 3. Running instances with sensitive tags/roles (from EC2 dependency) | CONFIRMED or INFERRED |
| 4. SGs on those instances allow inbound from `0.0.0.0/0` (from EC2 dependency) | CONFIRMED or INFERRED |

**Impact**: Workloads intended to be private are directly internet-reachable.
**Break chain**: (1) Replace IGW route with NAT, (2) Disable public IP auto-assign, (3) Tighten SG rules.

### AP-REF-02: Public Subnet + Auto-Assign Public IP + Broad SG = Default Internet Exposure
**Category**: `network_entry`
**Chain**: Public Subnet → Auto Public IP → Broad SG → Every New Instance Internet-Reachable
| Hop | Evidence |
|-----|----------|
| 1. Route table has `0.0.0.0/0` to IGW | CONFIRMED required |
| 2. `MapPublicIpOnLaunch: true` | CONFIRMED required |
| 3. Default or widely-used SG allows inbound from `0.0.0.0/0` on sensitive ports | CONFIRMED or INFERRED |
| 4. New instances inherit exposure automatically | INFERRED |

**Break chain**: (1) Disable auto-assign public IP, (2) Tighten SG rules, (3) Review whether subnet should be public.

### AP-REF-03: No Flow Logs + Broad NACL + Active Workloads = Blind Lateral Movement
**Category**: `lateral_movement`
**Chain**: Active VPC → No Flow Logs → Allow-All NACL → Compromise and Movement Undetectable
| Hop | Evidence |
|-----|----------|
| 1. VPC has running workloads (from dependency context) | CONFIRMED required |
| 2. No flow log configuration for this VPC | CONFIRMED required |
| 3. NACLs are allow-all or near allow-all | CONFIRMED required |
| 4. SGs allow broad internal communication (from EC2 dependency) | CONFIRMED or INFERRED |

**Minimum**: Hops 1, 2, and 3 must be CONFIRMED.
**Impact**: Attacker moves laterally without network barriers and without detection. Incident response severely hampered.
**Break chain**: (1) Enable VPC flow logs, (2) Tighten NACLs, (3) Tighten SG east-west rules.

### AP-REF-04: Cross-Account Peering + Broad Routes + Weak Segmentation
**Category**: `lateral_movement`
**Chain**: Cross-Account Peering → Broad Routes → Sensitive Subnet Reachable from Peer
| Hop | Evidence |
|-----|----------|
| 1. Active peering with different owner account | CONFIRMED required |
| 2. Broad CIDR routes to peering connection covering sensitive subnets | CONFIRMED required |
| 3. NACLs on sensitive subnets don't restrict peering traffic | CONFIRMED required |
| 4. Sensitive workloads (db, admin) in reachable subnets (from dependency) | CONFIRMED or INFERRED |

**Minimum**: Hops 1, 2, and 3 must be CONFIRMED.
**Break chain**: (1) Narrow peering routes, (2) Add NACL restrictions, (3) Validate peering need, (4) Isolate sensitive subnets.

### AP-REF-05: Default VPC + Production Workloads + Weak Controls
**Category**: `network_entry`
**Chain**: Default VPC → Production Instances → Public Subnets → Weak SG/NACL → Insecure by Default
| Hop | Evidence |
|-----|----------|
| 1. `IsDefault: true` | CONFIRMED required |
| 2. Production-tagged instances (from dependency) | CONFIRMED or INFERRED |
| 3. Default subnets have IGW routes + `MapPublicIpOnLaunch: true` | CONFIRMED required |
| 4. No flow logs, allow-all NACLs, broad SGs | CONFIRMED |

**Minimum**: Hops 1 and 3 must be CONFIRMED, plus either Hop 2 or 4.
**Break chain**: (1) Migrate to purpose-built VPC, (2) Disable auto-assign public IP, (3) Enable flow logs, (4) Tighten controls.

### AP-REF-06: No Segmentation Between Web and Database Tiers
**Category**: `lateral_movement`
**Chain**: Internet-Facing Subnet → Flat Network → Database Subnet → Direct DB Access After Web Compromise
| Hop | Evidence |
|-----|----------|
| 1. Internet-facing subnet with web-serving instances (from dependency) | CONFIRMED required |
| 2. No meaningful NACL/route separation between web and db subnets | CONFIRMED required |
| 3. Subnet contains RDS or db-tagged EC2 instances (from dependency) | CONFIRMED or INFERRED |
| 4. SGs allow database port from web subnet (from dependency) | CONFIRMED or INFERRED |

**Minimum**: Hops 1 and 2 must be CONFIRMED, plus Hop 3.
**Break chain**: (1) Create dedicated db-tier NACLs, (2) Restrict db SGs to app-tier only, (3) Move databases to isolated subnets.

### AP-REF-07: Transit/Peering Hub with Weak Filtering → Multi-VPC Blast Radius
**Category**: `lateral_movement`
**Chain**: Transit Gateway/Peering Hub → Multiple VPCs Reachable → Compromise Spreads Across VPCs
| Hop | Evidence |
|-----|----------|
| 1. Transit gateway attachments or multiple peering connections | CONFIRMED required |
| 2. Broad cross-VPC routes | CONFIRMED required |
| 3. NACLs don't restrict inter-VPC traffic | CONFIRMED required |
| 4. Multi-VPC impact | INFERRED |

**Minimum**: Hops 1, 2, and 3 must be CONFIRMED.
**Break chain**: (1) Narrow cross-VPC routes, (2) NACL segmentation at boundaries, (3) TGW route table segmentation, (4) Flow logs on all VPCs.

### AP-REF-08: IPv6 Exposure Bypass
**Category**: `network_entry`
**Chain**: IPv4 Hardened → IPv6 Route to IGW → IPv6-Addressable Instance Exposed
| Hop | Evidence |
|-----|----------|
| 1. Subnet has no IPv4 IGW route or instances lack IPv4 public IPs | CONFIRMED required |
| 2. Route table has `::/0` route to IGW | CONFIRMED required |
| 3. Instances have IPv6 addresses (from dependency) | CONFIRMED or INFERRED |
| 4. NACLs/SGs don't restrict IPv6 equivalently to IPv4 | CONFIRMED or INFERRED |

**Minimum**: Hops 1 and 2 must be CONFIRMED, plus Hop 3 or 4.
**Break chain**: (1) Match IPv6 SG/NACL rules to IPv4 hardening, (2) Remove IPv6 IGW route if not needed, (3) Disable IPv6 on unnecessary subnets.

### AP-REF-09: Database in Public Subnet
**Category**: `network_entry` + `data_exfiltration`
**Chain**: Public Subnet → RDS/DB Instance → Public Accessibility → Direct Database Exposure
| Hop | Evidence |
|-----|----------|
| 1. Subnet route table has `0.0.0.0/0` to IGW | CONFIRMED required |
| 2. RDS or database EC2 in the subnet (from dependency) | CONFIRMED required |
| 3. RDS `PubliclyAccessible: true` or EC2 has public IP | CONFIRMED required |
| 4. SG allows database port from `0.0.0.0/0` (from dependency) | CONFIRMED or INFERRED |

**Minimum**: Hops 1, 2, and 3 must be CONFIRMED.
**Impact**: Database directly accessible from the internet — credential brute force, vulnerability exploitation, data exfiltration.
**Break chain**: (1) Move database to private subnet, (2) Disable `PubliclyAccessible`, (3) Restrict SG to app-tier only.

### AP-REF-10: VPC Endpoint Abuse via Broad Policy
**Category**: `credential_access`
**Chain**: VPC Endpoint → Broad Policy → Unauthorized Service Access via Private Path
| Hop | Evidence |
|-----|----------|
| 1. VPC endpoint exists | CONFIRMED required |
| 2. Endpoint policy allows `*` principal or `*` action or `*` resource | CONFIRMED required |
| 3. Any principal in VPC can access service without restriction | INFERRED |
| 4. Endpoint connects to service with sensitive data | CONFIRMED or INFERRED |

**Minimum**: Hops 1 and 2 must be CONFIRMED plus at least one additional confirmed hop.
**Break chain**: (1) Scope endpoint policy, (2) Add bucket/service policies restricting endpoint access, (3) Monitor via flow logs.

### AP-REF-11: NAT Gateway as Sole Egress Control + No Flow Logs
**Category**: `data_exfiltration`
**Chain**: Private Subnet → NAT Gateway → Unrestricted Outbound → No Flow Logs → Undetected Exfiltration
| Hop | Evidence |
|-----|----------|
| 1. Subnet is private (NAT route, no IGW) | CONFIRMED required |
| 2. NAT gateway exists and is referenced by route | CONFIRMED required |
| 3. NACLs + SGs allow all outbound | CONFIRMED required |
| 4. No flow logs for this VPC | CONFIRMED required |

**Impact**: Compromised instance exfiltrates data through NAT without detection.
**Break chain**: (1) Enable VPC flow logs, (2) Add outbound NACL/SG restrictions, (3) Deploy VPC endpoints to reduce NAT dependence.

### AP-REF-12: Peering with Sensitive Subnet Reachability + Stale Connection
**Category**: `lateral_movement`
**Chain**: Stale/Unused Peering → Still Active Routes → Sensitive Subnets Reachable → Unnecessary Attack Surface
| Hop | Evidence |
|-----|----------|
| 1. Active peering connection (`active` status) | CONFIRMED required |
| 2. No active traffic justification visible | INFERRED |
| 3. Route table has routes to peering connection | CONFIRMED required |
| 4. Sensitive subnets within routed CIDR range | CONFIRMED required |

**Minimum**: Hops 1, 3, and 4 must be CONFIRMED.
**Impact**: Unused peering with active routes — unnecessary attack surface. Peer compromise reaches sensitive subnets.
**Break chain**: (1) Validate need, (2) Remove routes if not required, (3) Delete peering if unnecessary, (4) Narrow routes if still needed.

---

## 6. VPC-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are VPC-specific additions:

- **Public web-tier subnets routing to IGW** → expected architecture, not a finding
- **NAT gateways in active private architectures** → expected, not a finding
- **Missing VPC endpoints in tiny low-risk dev environments** → only flag if traffic profile suggests value
- **Default NACL allow-all in simple environments** → only flag if stronger segmentation intent exists
- **Cross-account peering** → `NEEDS_REVIEW` if may be legitimate organizational design
- **Unclear subnet naming/tags** → `NEEDS_REVIEW` if route intent can't be confidently inferred

---

## 7. Remediation Playbooks

### Fix Broken Private Subnet Design
1. Identify subnets labeled private/internal but routed to IGW
2. Move default route to NAT if outbound internet needed
3. Remove direct IGW path
4. Validate no public IP auto-assign remains
5. Recheck SG and NACL containment

### Improve Network Visibility
1. Enable flow logs on all active VPCs
2. Send logs to central destination with retention and access control
3. Prioritize production and sensitive VPCs first
4. Validate log delivery role and coverage

### Reduce Lateral Movement Risk
1. Identify broad NACLs, broad peering routes, and weak SG boundaries
2. Separate public, app, and data tiers clearly
3. Tighten route scopes and subnet accessibility
4. Apply stronger controls to db/admin/backup/security tiers

### Reduce Internet Path Dependence
1. Identify private workloads using NAT/public paths for AWS services
2. Add VPC endpoints for S3/DynamoDB and critical interface endpoints
3. Restrict endpoint policies to intended usage
4. Reassess cost and traffic reduction

### Secure Cross-Network Connectivity
1. Audit all peering connections and transit gateway attachments
2. Validate business need for each connection
3. Narrow routes to specific required CIDRs
4. Add NACL segmentation at network boundaries
5. Enable flow logs for cross-network visibility

---

## 8. Coverage Checklist

### Direct Findings
- [ ] Flow log coverage on active VPCs
- [ ] Default VPC usage for production workloads
- [ ] Subnet public IP auto-assign on non-public subnets
- [ ] IGW routes on subnets with private/internal intent
- [ ] NACL effectiveness (allow-all vs meaningful segmentation)
- [ ] Missing VPC endpoints for high-use AWS services
- [ ] Endpoint policy broadness
- [ ] Unused IGWs and NAT gateways
- [ ] Cross-account peering connections
- [ ] Broad peering routes
- [ ] Tier segmentation (web/app/db/admin separation)
- [ ] IPv6 exposure control
- [ ] Transit gateway and hub connectivity

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Broken private subnet exposure
- [ ] AP-REF-02: Public subnet auto-exposure
- [ ] AP-REF-03: Blind lateral movement
- [ ] AP-REF-04: Cross-account peering to sensitive subnets
- [ ] AP-REF-05: Default VPC production risk
- [ ] AP-REF-06: No segmentation between web and db tiers
- [ ] AP-REF-07: Multi-VPC blast radius via transit/peering
- [ ] AP-REF-08: IPv6 exposure bypass
- [ ] AP-REF-09: Database in public subnet
- [ ] AP-REF-10: VPC endpoint abuse
- [ ] AP-REF-11: NAT egress without detection
- [ ] AP-REF-12: Stale peering with sensitive reachability
