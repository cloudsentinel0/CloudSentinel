# RDS Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **RDS-specific** patterns only.

## Service Overview

RDS is the primary relational data surface in many AWS accounts. A weak RDS configuration can create direct internet exposure, silent data theft through snapshots, broken recoverability, or application-to-database compromise paths that bypass the expectation that databases remain private.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: RDS ===
describe-db-instances, describe-db-clusters,
describe-db-subnet-groups, describe-db-snapshots (manual),
describe-db-cluster-snapshots (manual),
describe-db-snapshot-attributes (per snapshot),
describe-db-cluster-snapshot-attributes (per cluster snapshot),
describe-db-parameters (per parameter group),
describe-db-cluster-parameters (per cluster parameter group),
list-tags-for-resource (per instance/cluster/snapshot),
describe-certificates

=== DEPENDENCY CONTEXT: EC2 ===
describe-security-groups, describe-subnets,
describe-route-tables, describe-vpcs,
describe-instances (same VPCs or referenced by DB SG rules)

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
list-secrets, describe-secret (per managed credential)

=== DEPENDENCY CONTEXT: KMS ===
describe-key (per referenced KMS key)
```

---

## 2. Relationship Mapping (Do This First)

### RDS Resource Maps
- **DB Instance/Cluster → Engine and Version**: engine family, version, endpoint type
- **DB Instance/Cluster → PubliclyAccessible**: whether endpoint is intended to be internet-routable
- **DB Instance/Cluster → VPC and Subnet Group**: where the database lives
- **DB Instance/Cluster → Security Groups**: which SGs protect the endpoint
- **DB Instance/Cluster → Encryption**: `StorageEncrypted`, `KmsKeyId`, snapshot encryption state
- **DB Instance/Cluster → Backup Posture**: backup retention period, automated backups
- **DB Instance/Cluster → Deletion Protection**: enabled or not
- **DB Instance/Cluster → Log Exports**: `EnabledCloudwatchLogsExports` and engine-appropriate logging
- **DB Instance/Cluster → Parameter Groups**: DB and cluster parameter groups
- **DB Instance/Cluster → Tags**: production and sensitivity indicators
- **Snapshot → Source DB/Cluster**: which DB created the snapshot
- **Snapshot → Sharing**: public (`all`) vs named external accounts
- **Snapshot → Encryption**: encrypted or plaintext

### Parameter Interpretation Rules
- **PostgreSQL / Aurora PostgreSQL**: `rds.force_ssl=1` = strong TLS enforcement evidence
- **MySQL / MariaDB / Aurora MySQL**: `require_secure_transport=ON` = strong TLS enforcement evidence
- **SQL Server / Oracle**: only claim TLS enforcement if a collected parameter clearly proves it
- If engine-specific parameter is absent from collected data, do not guess. Use `NEEDS_REVIEW` only when remaining evidence strongly suggests control may be missing.

### Dependency Maps
- **Security Group → Inbound Rules**: DB port reachable from `0.0.0.0/0`, `::/0`, broad private CIDRs, or specific app SGs
- **Subnet Group → Route Intent**: whether member subnets are public, private, or mixed
- **EC2 Instances → Same VPC/SG Reference**: which public/sensitive EC2 instances can reach the DB
- **Secrets Manager → Master Credential Secret**: whether master secret management is visible and scoped
- **KMS Key → Key State**: enabled, disabled, pending deletion, AWS-managed vs customer-managed

### Derived Relationships
- **Direct Internet-Reachable DB**: `PubliclyAccessible=true` + SG allows engine port from `0.0.0.0/0`
- **Architecturally Misplaced DB**: subnet group contains IGW-routed subnets or mixed intent
- **Offline Data Exposure**: public or broad snapshot sharing + snapshot copy/restore path
- **App-to-DB Pivot Path**: public EC2 + reachable DB SG path + sensitive DB target
- **Recovery Weakness**: short/no backups + no deletion protection on important DBs

---

## 3. RDS Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### RDS-PUBLIC-ENDPOINT: Publicly Accessible Database Endpoint
| Field | Value |
|-------|-------|
| Detection | `PubliclyAccessible: true` on DB instance or cluster member |
| Category | `network_exposure` |
| Base severity | HIGH (SG allows DB port from `0.0.0.0/0` → CRITICAL, prod/sensitive → raise, SG restricted to corporate/VPN CIDRs → HIGH not CRITICAL) |
| Fix | `aws rds modify-db-instance --db-instance-identifier {db-id} --no-publicly-accessible --apply-immediately` |
| Attack path role | Common entry point for direct DB access paths |

### RDS-SG-INTERNET: Database Security Group Open to the Internet
| Field | Value |
|-------|-------|
| Detection | Attached SG allows inbound from `0.0.0.0/0` or `::/0` on engine/admin ports (3306, 5432, 1433, 1521, 2484) |
| Category | `network_exposure` |
| Base severity | CRITICAL (private DB + broad internal RFC1918 only → HIGH or `NEEDS_REVIEW`) |
| Fix | `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {db-port} --cidr 0.0.0.0/0` |
| Attack path role | Direct entry for data access and brute-force/exploit attempts |

### RDS-SUBNET-PUBLIC: DB Subnet Group Uses Public or Mixed-Intent Subnets
| Field | Value |
|-------|-------|
| Detection | Subnet group contains subnets with route tables pointing `0.0.0.0/0` to IGW, or mixed naming/route intent |
| Category | `network_exposure` |
| Base severity | MEDIUM (publicly accessible or internet-open SG → HIGH, sensitive/prod → HIGH) |
| Fix | Move DB to dedicated private subnets and update subnet group |
| Attack path role | Architectural enabler for exposure and lateral movement |

### RDS-NO-ENCRYPTION: Storage Encryption Disabled
| Field | Value |
|-------|-------|
| Detection | `StorageEncrypted: false` |
| Category | `encryption` |
| Base severity | HIGH (prod/sensitive), MEDIUM (otherwise) |
| Fix | Snapshot → copy/restore to new encrypted instance or cluster → cut over |
| Attack path role | Amplifies snapshot or backup exposure |

### RDS-SNAPSHOT-PUBLIC: Manual Snapshot Shared Publicly
| Field | Value |
|-------|-------|
| Detection | Snapshot attributes include group `all` |
| Category | `data_exposure` |
| Base severity | CRITICAL |
| Fix | `aws rds modify-db-snapshot-attribute --db-snapshot-identifier {snapshot-id} --attribute-name restore --values-to-remove all` |
| Fix (cluster) | `aws rds modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier {snapshot-id} --attribute-name restore --values-to-remove all` |
| Attack path role | Direct offline data theft — no host compromise needed |

### RDS-SNAPSHOT-CROSS-ACCOUNT: Snapshot Shared to External Account
| Field | Value |
|-------|-------|
| Detection | Snapshot attributes include specific external AWS account IDs |
| Category | `access_control` |
| Base severity | HIGH (sensitive/prod source → raise, no encryption → CRITICAL) |
| Status rule | `NEEDS_REVIEW` when sharing appears to be controlled DR/backup workflow |
| Fix | Remove unnecessary account IDs from snapshot restore attribute |

### RDS-BACKUP-WEAK: Backup Retention Disabled or Too Low
| Field | Value |
|-------|-------|
| Detection | `BackupRetentionPeriod` is `0` or clearly low for important DB |
| Category | `backup_recovery` |
| Base severity | MEDIUM (prod/customer/auth/financial → HIGH, combined with no deletion protection → HIGH) |
| Fix | `aws rds modify-db-instance --db-instance-identifier {db-id} --backup-retention-period {days} --apply-immediately` |

### RDS-DELETION-PROTECTION-OFF: Deletion Protection Disabled on Important Database
| Field | Value |
|-------|-------|
| Detection | `DeletionProtection: false` |
| Category | `resource_hygiene` |
| Base severity | MEDIUM (prod/critical → HIGH, dev/test → LOW) |
| Fix | `aws rds modify-db-instance --db-instance-identifier {db-id} --deletion-protection --apply-immediately` |

### RDS-NO-LOG-EXPORTS: Database Log Exports Not Enabled
| Field | Value |
|-------|-------|
| Detection | `EnabledCloudwatchLogsExports` empty or missing for engines with security-relevant exports |
| Category | `logging_monitoring` |
| Base severity | MEDIUM (publicly accessible/internet-open → HIGH, prod/regulated → HIGH) |
| Fix | `aws rds modify-db-instance --db-instance-identifier {db-id} --cloudwatch-logs-export-configuration EnableLogTypes=[...] --apply-immediately` |

### RDS-TLS-NOT-ENFORCED: Parameter Group Does Not Enforce Secure Transport
| Field | Value |
|-------|-------|
| Detection | Collected engine-specific parameters clearly show TLS/SSL enforcement disabled or absent |
| Category | `access_control` |
| Base severity | HIGH |
| Status rule | `NEEDS_REVIEW` if engine supports different controls and collected parameters incomplete |
| Fix | Update DB/cluster parameter group to require secure transport; apply/reboot if needed |
| Attack path role | Amplifies public/broad exposure by allowing plaintext connections |

---

## 4. RDS Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Direct Internet Access to Public RDS
**Category**: `network_entry` + `data_exfiltration`
**Chain**: Internet → SG Open on DB Port → Public RDS Endpoint
| Hop | Evidence |
|-----|----------|
| 1. SG allows DB port from `0.0.0.0/0` or `::/0` (dependency) | CONFIRMED required |
| 2. DB is `PubliclyAccessible=true` | CONFIRMED required |
| 3. Sensitive/production DB (tags/name/context) | CONFIRMED or INFERRED |

**Impact**: Direct internet access to database listener — credential attacks, protocol exploits, data access.
**Break chain**: (1) Remove internet SG access, (2) Disable public accessibility, (3) Move to private subnets.

### AP-REF-02: Public RDS + No TLS Enforcement
**Category**: `network_entry`
**Chain**: Internet → Public RDS → Non-Enforced Secure Transport
| Hop | Evidence |
|-----|----------|
| 1. SG allows DB port from internet | CONFIRMED required |
| 2. `PubliclyAccessible=true` | CONFIRMED required |
| 3. Parameter group shows TLS enforcement disabled | CONFIRMED required |

**Impact**: Direct exposure worsened by weak transport — plaintext/downgraded connections, credential risk.
**Break chain**: (1) Remove internet reachability, (2) Enforce TLS in parameter group, (3) Rotate credentials.

### AP-REF-03: Public Manual Snapshot Offline Data Theft
**Category**: `data_exfiltration`
**Chain**: Public Snapshot → Copy/Restore → Offline Database Extraction
| Hop | Evidence |
|-----|----------|
| 1. Manual snapshot shared with `all` | CONFIRMED required |
| 2. Public sharing proves restore path | CONFIRMED required |
| 3. Source DB is production/sensitive | CONFIRMED or INFERRED |

**Impact**: Any AWS account copies snapshot and inspects database offline.
**Break chain**: (1) Remove public sharing, (2) Review all snapshots from same source, (3) Rotate stored credentials.

### AP-REF-04: Cross-Account Snapshot Restore Outside Intended Boundary
**Category**: `data_exfiltration`
**Chain**: External Account Snapshot Share → Restore → Data Exposure
| Hop | Evidence |
|-----|----------|
| 1. External account IDs in snapshot attributes | CONFIRMED required |
| 2. External account can restore/copy | CONFIRMED required |
| 3. Source DB contains important data | CONFIRMED or INFERRED |

**Break chain**: (1) Remove unnecessary external sharing, (2) Validate DR/backup requirements, (3) Keep only scoped encrypted shares.

### AP-REF-05: Public EC2 App Tier to Reachable RDS Pivot
**Category**: `lateral_movement`
**Chain**: Internet → Public EC2 → Reachable RDS SG Path → Database Target
| Hop | Evidence |
|-----|----------|
| 1. Internet-reachable EC2 instance (dependency) | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. DB SG allows traffic from EC2 instance SG/subnet CIDR (dependency) | CONFIRMED required |
| 4. Important DB exists behind reachable path | CONFIRMED required |

**Minimum**: Hops 1, 3, and 4 must be CONFIRMED.
**Impact**: Public app-tier compromise creates proven network path to database tier.
**Break chain**: (1) Restrict EC2 exposure, (2) Restrict DB SGs to exact app SGs, (3) Segment tiers.

### AP-REF-06: Public Subnet Group + Public Endpoint = Architecture-Driven Exposure
**Category**: `network_entry`
**Chain**: IGW-Routed DB Subnets → Publicly Accessible DB → Direct Exposure
| Hop | Evidence |
|-----|----------|
| 1. DB subnet group contains public/mixed-intent subnets (route analysis) | CONFIRMED required |
| 2. DB is publicly accessible | CONFIRMED required |
| 3. SG permits DB port from broad sources | CONFIRMED required |

**Impact**: Network architecture and endpoint config align to expose rather than protect the database.
**Break chain**: (1) Move DB to private subnets, (2) Disable public accessibility, (3) Remove broad SG rules.

### AP-REF-07: Public RDS + No Log Exports = Undetected Direct Access
**Category**: `network_entry`
**Chain**: Internet-Reachable DB → Weak Monitoring → Direct Breach Hard to Investigate
| Hop | Evidence |
|-----|----------|
| 1. DB is internet-reachable (public + SG) | CONFIRMED required |
| 2. Security-relevant log exports not enabled | CONFIRMED required |
| 3. Important DB | CONFIRMED or INFERRED |

**Impact**: Direct access attempts and misuse are harder to investigate or detect quickly.
**Break chain**: (1) Break direct exposure, (2) Enable log exports, (3) Ensure retention and monitoring.

### AP-REF-08: Public Snapshot + No Encryption = Plaintext Offline Breach
**Category**: `data_exfiltration`
**Chain**: Shared Snapshot → Plaintext Restore → Offline Data Exposure
| Hop | Evidence |
|-----|----------|
| 1. Snapshot is public or externally shared | CONFIRMED required |
| 2. Snapshot/source storage is unencrypted | CONFIRMED required |
| 3. Snapshot maps to important DB | CONFIRMED or INFERRED |

**Impact**: Data restored and inspected offline without encryption protections.
**Break chain**: (1) Remove sharing, (2) Rebuild on encrypted storage, (3) Review historical snapshots.

### AP-REF-09: Public Cluster Writer or Reader Endpoint Exposure
**Category**: `network_entry` + `data_exfiltration`
**Chain**: Internet → Open SG → Public Aurora/Cluster Endpoint
| Hop | Evidence |
|-----|----------|
| 1. SG exposes cluster port to broad sources | CONFIRMED required |
| 2. Cluster members/endpoints are publicly accessible | CONFIRMED required |
| 3. Writer and reader endpoints expose same data plane | CONFIRMED |

**Impact**: Both write and read access paths exposed, increasing blast radius.
**Break chain**: (1) Remove internet SG access, (2) Make cluster members private, (3) Review all endpoints.

### AP-REF-10: Weak Backups + No Deletion Protection = Destructive Attack Outcome
**Category**: `data_exfiltration`
**Chain**: Reachable DB → No Deletion Protection → Poor Recovery
| Hop | Evidence |
|-----|----------|
| 1. DB is directly exposed or reachable from public app tier | CONFIRMED required |
| 2. Deletion protection disabled | CONFIRMED required |
| 3. Backups disabled or clearly too weak | CONFIRMED required |

**Impact**: Compromise shifts from data access to destructive deletion/corruption with poor recovery.
**Break chain**: (1) Break reachable path, (2) Enable deletion protection, (3) Raise backup retention.

---

## 5. RDS-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are RDS-specific additions:

- **`PubliclyAccessible=true` with SG limited to narrow corporate/VPN CIDR** → still a finding but not automatic CRITICAL
- **Cross-account snapshot to dedicated backup/DR account** → `NEEDS_REVIEW` unless evidence shows broad/unnecessary sharing
- **Read replicas, migration DBs, temporary cutover systems** → lower severity when lifespan/scope clearly limited
- **Subnet-group public placement without public accessibility and without broad SG** → architecture weakness, not proof of direct exposure
- **TLS parameter checks on engines with incomplete parameter collection** → do not claim enforcement missing unless parameter data proves it
- **Missing log exports on engines that don't support the same export set** → evaluate engine capabilities before escalating

---

## 6. Remediation Playbooks

### Remove Direct Database Exposure
1. Identify public DB instances and clusters
2. Revoke SG access from `0.0.0.0/0` and `::/0` on DB ports
3. Disable public accessibility
4. Verify DB subnet groups use private subnets only
5. Re-test application reachability from approved app tiers

### Secure Manual Snapshots
1. Inventory all manual and cluster snapshots
2. Remove public sharing immediately
3. Review all named external account shares
4. Recreate/copy snapshots with encryption where required
5. Rotate credentials stored in the data

### Enforce Encryption and Secure Transport
1. Prioritize production and customer-data DBs
2. Plan encrypted restore/cutover for unencrypted databases
3. Update parameter groups to enforce secure transport
4. Schedule reboots/maintenance windows where parameter family requires it

### Improve Recoverability
1. Raise backup retention on important DBs
2. Enable deletion protection on production databases
3. Validate snapshot/restore procedures
4. Review who can create, share, and restore snapshots

### Improve Detection and Investigation
1. Enable engine-appropriate CloudWatch log exports
2. Confirm log group retention and access controls
3. Prioritize public or app-reachable DBs first
4. Correlate DB visibility with network exposure findings

---

## 7. Coverage Checklist

### Direct Findings
- [ ] Publicly accessible DB instances or cluster members
- [ ] Internet-open SG rules on DB/admin ports
- [ ] DB subnet groups using public or mixed-intent subnets
- [ ] Storage encryption disabled
- [ ] Public manual snapshots
- [ ] Cross-account snapshot sharing
- [ ] Snapshot encryption posture
- [ ] Backup retention weakness
- [ ] Deletion protection disabled on important DBs
- [ ] Missing CloudWatch log exports
- [ ] TLS / secure-transport enforcement in parameter groups

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Direct internet access to public RDS
- [ ] AP-REF-02: Public RDS + no TLS enforcement
- [ ] AP-REF-03: Public snapshot offline theft
- [ ] AP-REF-04: Cross-account snapshot restore path
- [ ] AP-REF-05: Public EC2 app tier to reachable RDS pivot
- [ ] AP-REF-06: Architecture-driven exposure from public subnets
- [ ] AP-REF-07: Public RDS + no log exports
- [ ] AP-REF-08: Shared snapshot + no encryption
- [ ] AP-REF-09: Public cluster endpoint exposure
- [ ] AP-REF-10: Weak backups + no deletion protection destructive path
