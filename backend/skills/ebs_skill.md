# EBS Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **EBS-specific** patterns only.

## Service Overview

EBS is the primary block-storage persistence layer for EC2-backed workloads. The highest-value EBS risks are usually not about live network access. They are about what happens when volumes or snapshots can be copied, restored, mounted elsewhere, or left unencrypted.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: EBS ===
describe-volumes, describe-snapshots (owner self),
describe-snapshot-attribute (createVolumePermission per snapshot),
get-ebs-encryption-by-default, get-ebs-default-kms-key-id,
get-snapshot-block-public-access-state

=== DEPENDENCY CONTEXT: EC2 ===
describe-instances, describe-images (snapshots backing owned AMIs)

=== DEPENDENCY CONTEXT: KMS ===
describe-key (per referenced KMS key)
```

---

## 2. Relationship Mapping (Do This First)

### EBS Resource Maps
- **Volume → Attachment State**: attached instance, device name, or unattached
- **Volume → Encryption**: encrypted or not, `KmsKeyId` if present
- **Volume → Snapshot Lineage**: source snapshot when visible
- **Volume → Size / Type / Tags**: production and sensitivity indicators
- **Snapshot → Source Volume**: snapshot lineage and source workload
- **Snapshot → Sharing**: public (`all`) vs named external accounts
- **Snapshot → Encryption**: encrypted or plaintext
- **Region → Encryption by Default**: on or off
- **Region → Default KMS Key**: AWS-managed or customer-managed key ID
- **Region → Snapshot Block Public Access**: block state or disabled

### Dependency Maps
- **Volume → EC2 Instance**: which instance the volume is attached to, whether that instance is public, production, database, or high value
- **Snapshot → AMI**: whether a snapshot backs an owned AMI
- **KMS Key → Key State**: enabled, disabled, pending deletion

### Derived Relationships
- **Active Sensitive Volume**: attached to a production or sensitive instance
- **Offline Breach Path**: snapshot sharing proves restore/copy path outside the workload boundary
- **Image Supply Path**: snapshot backs an owned AMI, increasing blast radius
- **Regional Guardrail Gap**: encryption-by-default disabled or snapshot public block disabled

---

## 3. EBS Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### EBS-VOLUME-UNENCRYPTED: Unencrypted EBS Volume
| Field | Value |
|-------|-------|
| Detection | `Encrypted: false` on a volume |
| Category | `encryption` |
| Base severity | MEDIUM (prod/db/auth/customer-data instance → HIGH, detached test → LOW) |
| Fix | Snapshot → encrypted copy → new encrypted volume → replace |
| Attack path role | Amplifies the impact of snapshot exposure |

### EBS-SNAPSHOT-PUBLIC: Snapshot Shared Publicly
| Field | Value |
|-------|-------|
| Detection | `createVolumePermission` includes group `all` |
| Category | `data_exposure` |
| Base severity | CRITICAL |
| Fix | `aws ec2 modify-snapshot-attribute --snapshot-id {snapshot-id} --attribute createVolumePermission --operation-type remove --group-names all` |
| Attack path role | Direct offline data theft path |

### EBS-SNAPSHOT-CROSS-ACCOUNT: Snapshot Shared to External Account
| Field | Value |
|-------|-------|
| Detection | `createVolumePermission` includes external AWS account IDs |
| Category | `access_control` |
| Base severity | HIGH (sensitive/prod source → raise, unencrypted → CRITICAL) |
| Status rule | `NEEDS_REVIEW` when sharing appears to be controlled backup/DR workflow |
| Fix | `aws ec2 modify-snapshot-attribute --snapshot-id {snapshot-id} --attribute createVolumePermission --operation-type remove --user-ids {account-id}` |

### EBS-SNAPSHOT-UNENCRYPTED: Snapshot Not Encrypted
| Field | Value |
|-------|-------|
| Detection | `Encrypted: false` on a snapshot |
| Category | `encryption` |
| Base severity | MEDIUM (public/shared → CRITICAL, prod/sensitive source → HIGH) |
| Fix | `aws ec2 copy-snapshot --source-region {region} --source-snapshot-id {snapshot-id} --encrypted --kms-key-id {kms-key-id}` |
| Attack path role | Amplifies snapshot-sharing exposure |

### EBS-ENCRYPTION-DEFAULT-OFF: EBS Encryption by Default Disabled
| Field | Value |
|-------|-------|
| Detection | `get-ebs-encryption-by-default` returns disabled |
| Category | `encryption` |
| Base severity | HIGH |
| Fix | `aws ec2 enable-ebs-encryption-by-default` |
| Attack path role | Governance weakness allowing future plaintext storage |

### EBS-SNAPSHOT-BLOCK-PUBLIC-OFF: Snapshot Block Public Access Disabled
| Field | Value |
|-------|-------|
| Detection | `get-snapshot-block-public-access-state` is absent, permissive, or not blocking |
| Category | `access_control` |
| Base severity | HIGH |
| Fix | `aws ec2 enable-snapshot-block-public-access --state block-all-sharing` |
| Attack path role | Account-wide enabler for snapshot exposure |

### EBS-KMS-KEY-RISK: Referenced CMK Disabled or Pending Deletion
| Field | Value |
|-------|-------|
| Detection | Dependency context shows referenced CMK is disabled or pending deletion |
| Category | `compliance` |
| Base severity | MEDIUM |
| Status rule | `NEEDS_REVIEW` when key state visible but effect on workloads can't be validated |
| Fix | Re-enable KMS key or re-encrypt on a healthy key |

### EBS-VOLUME-STALE: Detached Volume Appears Stale
| Field | Value |
|-------|-------|
| Detection | Volume is unattached and tags/age suggest not part of active workflow |
| Category | `resource_hygiene` |
| Base severity | LOW (large + unencrypted → MEDIUM, prod/sensitive name/tags → MEDIUM) |
| Fix | Validate ownership; attach, snapshot/archive, or delete |

### EBS-SNAPSHOT-STALE: Snapshot Appears Unused and Unowned
| Field | Value |
|-------|-------|
| Detection | No clear current owner, AMI linkage, or workload relationship |
| Category | `resource_hygiene` |
| Base severity | LOW (raise if unencrypted or externally shared) |
| Fix | Validate ownership; delete or migrate to approved backup policy |

---

## 4. EBS Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Public Snapshot Offline Data Theft
**Category**: `data_exfiltration`
**Chain**: Public Snapshot → Copy → New Volume → Offline Mount
| Hop | Evidence |
|-----|----------|
| 1. Snapshot is public (`createVolumePermission: all`) | CONFIRMED required |
| 2. Public sharing proves any AWS account can copy/create volume | CONFIRMED required |
| 3. Snapshot maps to a sensitive volume or instance | CONFIRMED or INFERRED |

**Impact**: Attacker restores snapshot in their account and inspects filesystem, databases, keys offline.
**Break chain**: (1) Remove public sharing, (2) Review all snapshots from same source, (3) Rotate credentials on disk.

### AP-REF-02: Cross-Account Snapshot Restore Outside Intended Boundary
**Category**: `data_exfiltration`
**Chain**: External Account Share → Copy/Restore → Data Leaves Account
| Hop | Evidence |
|-----|----------|
| 1. Snapshot shared with named external accounts | CONFIRMED required |
| 2. Named accounts can create volumes from snapshot | CONFIRMED required |
| 3. Snapshot maps to an important workload | CONFIRMED or INFERRED |

**Break chain**: (1) Remove unnecessary external shares, (2) Validate backup-account requirements, (3) Keep only justified sharing.

### AP-REF-03: Public Snapshot + No Encryption = Plaintext Offline Breach
**Category**: `data_exfiltration`
**Chain**: Public Snapshot → Plaintext Restore → Offline Data Extraction
| Hop | Evidence |
|-----|----------|
| 1. Snapshot is public | CONFIRMED required |
| 2. Snapshot is unencrypted | CONFIRMED required |
| 3. Snapshot maps to an important workload | CONFIRMED or INFERRED |

**Impact**: Public exposure + plaintext makes offline data extraction straightforward.
**Break chain**: (1) Remove public sharing, (2) Replace with encrypted copies, (3) Review historical copies.

### AP-REF-04: Shared Snapshot Backing an Owned AMI
**Category**: `data_exfiltration`
**Chain**: Exposed Snapshot → Backing AMI → Wider Image Blast Radius
| Hop | Evidence |
|-----|----------|
| 1. Snapshot is public or externally shared | CONFIRMED required |
| 2. `describe-images` dependency maps snapshot to an AMI | CONFIRMED required |
| 3. AMI is in active use | CONFIRMED or INFERRED |

**Impact**: Snapshot exposure leaks not just one volume, but a base image used by multiple systems.
**Break chain**: (1) Remove snapshot sharing, (2) Review AMI and derived images, (3) Rebuild on encrypted private storage.

### AP-REF-05: Sensitive Attached Volume → Snapshot Exposure → Offline Data Theft
**Category**: `data_exfiltration`
**Chain**: Production Volume → Public/Shared Snapshot → Data Breach
| Hop | Evidence |
|-----|----------|
| 1. Attached volume belongs to production/sensitive instance (dependency) | CONFIRMED required |
| 2. Snapshot from that volume is public or externally shared | CONFIRMED required |
| 3. Snapshot can be copied/restored outside the account | CONFIRMED required |

**Impact**: Data from active high-value workload extracted offline without compromising the instance.
**Break chain**: (1) Remove snapshot exposure, (2) Review all recent snapshots, (3) Rotate secrets on disk.

### AP-REF-06: Snapshot Block Public Access Disabled + Public Snapshot
**Category**: `data_exfiltration`
**Chain**: Missing Guardrail → Public Snapshot Exists → Repeated Exposure Risk
| Hop | Evidence |
|-----|----------|
| 1. Snapshot block public access not enforced | CONFIRMED required |
| 2. At least one snapshot is public | CONFIRMED required |
| 3. Same mistake can recur for future snapshots | INFERRED |

**Impact**: Account lacks both preventive guardrail and already has live public exposure.
**Break chain**: (1) Enable snapshot block public access, (2) Remove all current public shares, (3) Review snapshot automation.

### AP-REF-07: Encryption by Default Disabled → Future Plaintext Volume Creation
**Category**: `data_exfiltration`
**Chain**: No Regional Encryption Default → New Volumes/Copies May Be Plaintext
| Hop | Evidence |
|-----|----------|
| 1. Encryption by default disabled | CONFIRMED required |
| 2. One or more current volumes/snapshots are unencrypted | CONFIRMED required |
| 3. Future assets may inherit the same weakness | INFERRED |

**Impact**: No preventive control — plaintext storage can continue through human error or automation drift.
**Break chain**: (1) Enable encryption by default, (2) Migrate sensitive unencrypted assets, (3) Review pipelines.

---

## 5. EBS-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are EBS-specific additions:

- **Snapshot shares to a dedicated backup account** → `NEEDS_REVIEW` unless sharing is broad/public/unjustified
- **Detached lab or migration volumes** → LOW unless evidence shows sensitive data
- **Archive snapshots** → stale hygiene, not critical by itself
- **KMS key state warnings** → do not convert into attack paths unless key issue materially changes a confirmed chain

---

## 6. Remediation Playbooks

### Remove Snapshot Exposure
1. Inventory all public and externally shared snapshots
2. Remove public sharing immediately
3. Remove unnecessary external account shares
4. Review whether same source volume has additional snapshots
5. Rotate credentials likely stored on exposed disks

### Enforce Encryption Guardrails
1. Enable EBS encryption by default
2. Validate the default KMS key
3. Recreate sensitive snapshots as encrypted copies
4. Rebuild critical unencrypted volumes onto encrypted storage

### Prevent Future Public Sharing
1. Enable snapshot block public access
2. Audit image and backup automation
3. Alert on `ModifySnapshotAttribute` and public-sharing attempts

### Clean Up Stale Storage Safely
1. Identify detached volumes and orphaned snapshots
2. Confirm ownership before deletion
3. Archive securely if retention is required
4. Remove stale assets from active regions when no longer needed

---

## 7. Coverage Checklist

### Direct Findings
- [ ] Unencrypted attached volumes
- [ ] Public snapshots
- [ ] Cross-account shared snapshots
- [ ] Unencrypted snapshots
- [ ] EBS encryption by default
- [ ] Default KMS key posture
- [ ] Snapshot block public access state
- [ ] Stale detached volumes
- [ ] Stale or orphaned snapshots
- [ ] Snapshot-to-AMI linkage for broader blast radius

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Public snapshot offline theft
- [ ] AP-REF-02: Cross-account snapshot restore path
- [ ] AP-REF-03: Public snapshot + no encryption
- [ ] AP-REF-04: Exposed snapshot backing an AMI
- [ ] AP-REF-05: Sensitive attached volume to exposed snapshot
- [ ] AP-REF-06: Missing public-sharing guardrail + live public snapshot
- [ ] AP-REF-07: Encryption-by-default disabled with plaintext assets
