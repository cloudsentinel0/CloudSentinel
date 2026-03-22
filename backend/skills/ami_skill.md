# AMI Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **AMI-specific** patterns only.

## Service Overview

AMI is the image-distribution layer for EC2-based workloads. The most important AMI risks are broad launch permissions, exposed backing snapshots, unsafe instance defaults baked into the image, and stale or over-shared golden images that spread weak posture across many hosts.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: AMI ===
describe-images (owners self),
describe-image-attribute (launchPermission per image),
describe-image-attribute (imdsSupport per image),
describe-image-attribute (deregistrationProtection per image)

=== DEPENDENCY CONTEXT: EC2 ===
describe-snapshots (backing snapshots for owned AMIs),
describe-snapshot-attribute (createVolumePermission per backing snapshot),
describe-instances (instances launched from owned AMIs),
describe-launch-templates, describe-launch-template-versions

=== DEPENDENCY CONTEXT: AUTOSCALING ===
describe-auto-scaling-groups (groups using owned AMIs)
```

---

## 2. Relationship Mapping (Do This First)

### AMI Resource Maps
- **AMI → Launch Permission**: private, public, or shared to named accounts
- **AMI → IMDS Support**: `v2.0` or not enforced
- **AMI → Deregistration Protection**: enabled or not
- **AMI → Backing Snapshots**: snapshot IDs from block device mappings
- **AMI → Age / Creation Date**: used for stale-image review
- **AMI → Tags / Name / Description**: sensitivity and purpose indicators (`golden`, `base`, `prod`, `internal`, `customer`, `payments`)
- **AMI → State / Deprecation**: available, deprecated where visible

### Dependency Maps
- **AMI → Backing Snapshot Exposure**: whether backing snapshots are public, shared, or unencrypted
- **AMI → Running Instances**: how many active instances still use the AMI
- **AMI → Launch Templates**: whether the AMI is the active template source
- **AMI → Auto Scaling Groups**: whether the image is feeding a fleet

### Derived Relationships
- **Public Internal Image**: public launch permission + internal/golden/prod naming
- **Image Supply Blast Radius**: AMI referenced by launch templates or ASGs
- **Snapshot-Backed Exposure**: backing snapshots are public/shared or unencrypted
- **Default Credential-Risk Multiplier**: IMDSv2 not required on a heavily used image

---

## 3. AMI Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### AMI-PUBLIC: AMI Shared Publicly
| Field | Value |
|-------|-------|
| Detection | Launch permissions include group `all` |
| Category | `data_exposure` |
| Base severity | HIGH (internal/prod/golden/app/auth/customer naming → CRITICAL, backing snapshots public/unencrypted → CRITICAL) |
| Fix | `aws ec2 modify-image-attribute --image-id {ami-id} --launch-permission "Remove=[{Group=all}]"` |
| Attack path role | Direct image-cloning exposure path |

### AMI-CROSS-ACCOUNT: AMI Shared to External Account
| Field | Value |
|-------|-------|
| Detection | Launch permissions include named external AWS account IDs |
| Category | `access_control` |
| Base severity | HIGH (golden/internal/prod → raise, backing snapshots broadly exposed → CRITICAL) |
| Status rule | `NEEDS_REVIEW` when image appears part of controlled org-wide sharing |
| Fix | `aws ec2 modify-image-attribute --image-id {ami-id} --launch-permission "Remove=[{UserId={account-id}}]"` |

### AMI-BACKING-SNAPSHOT-PUBLIC: Backing Snapshot Shared Publicly
| Field | Value |
|-------|-------|
| Detection | One or more block-device snapshots for the AMI are public |
| Category | `data_exposure` |
| Base severity | CRITICAL |
| Fix | Remove public sharing from backing snapshot and rebuild image if necessary |
| Attack path role | Stronger offline exposure than AMI sharing alone |

### AMI-BACKING-SNAPSHOT-UNENCRYPTED: Backing Snapshot Not Encrypted
| Field | Value |
|-------|-------|
| Detection | One or more backing snapshots have `Encrypted: false` |
| Category | `encryption` |
| Base severity | MEDIUM (public/shared snapshot → CRITICAL, golden/internal/prod → HIGH) |
| Fix | Rebuild AMI from encrypted snapshot copies |

### AMI-IMDSV2-NOT-REQUIRED: AMI Does Not Require IMDSv2
| Field | Value |
|-------|-------|
| Detection | `imdsSupport` is absent or not `v2.0` |
| Category | `credential_risk` |
| Base severity | MEDIUM (active launch templates/ASGs → HIGH, base image for public web fleets → HIGH) |
| Fix | `aws ec2 modify-image-attribute --image-id {ami-id} --imds-support v2.0` |
| Attack path role | Multiplies future credential-theft exposure across fleets |

### AMI-DEREG-PROTECTION-OFF: Deregistration Protection Disabled on Critical Image
| Field | Value |
|-------|-------|
| Detection | `deregistrationProtection` disabled on a golden or actively used image |
| Category | `resource_hygiene` |
| Base severity | LOW (active launch templates/ASGs or golden/base/prod → MEDIUM) |
| Fix | `aws ec2 enable-image-deregistration-protection --image-id {ami-id}` |

### AMI-STALE-UNUSED: Old Unused AMI Retained Without Clear Ownership
| Field | Value |
|-------|-------|
| Detection | AMI is old, not referenced by instances/templates/ASGs, ownership unclear |
| Category | `resource_hygiene` |
| Base severity | LOW |
| Fix | Validate ownership; deprecate or `aws ec2 deregister-image --image-id {ami-id}` |

### AMI-OLD-IN-USE: Old Image Still Drives Active Fleet
| Field | Value |
|-------|-------|
| Detection | Old creation date + still used by active instances/templates/ASGs |
| Category | `compliance` |
| Base severity | MEDIUM |
| Status rule | `NEEDS_REVIEW` unless age clearly represents unmaintained baseline |
| Fix | Validate image pipeline, rebuild current base, roll forward safely |

---

## 4. AMI Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: Public AMI Clone of Internal Stack
**Category**: `data_exfiltration`
**Chain**: Public AMI → External Launch → Internal Stack Exposure
| Hop | Evidence |
|-----|----------|
| 1. AMI is public | CONFIRMED required |
| 2. Name/tags/description indicate internal or production use | CONFIRMED or INFERRED |
| 3. Public launch permission proves external launch capability | CONFIRMED required |

**Impact**: Attackers launch image in their account, inspect internal app stack, agents, configuration, software versions.
**Break chain**: (1) Remove public launch permission, (2) Check backing snapshots, (3) Rotate embedded secrets.

### AP-REF-02: Cross-Account Shared AMI Outside Intended Boundary
**Category**: `data_exfiltration`
**Chain**: External Account AMI Share → Unauthorized Launch → Internal Image Exposure
| Hop | Evidence |
|-----|----------|
| 1. AMI shared with external account IDs | CONFIRMED required |
| 2. Shared accounts can launch the image | CONFIRMED required |
| 3. Image appears internal/golden/production | CONFIRMED or INFERRED |

**Break chain**: (1) Remove unnecessary external shares, (2) Keep only org-approved sharing, (3) Review dependent teams.

### AP-REF-03: Public AMI + Public Backing Snapshot
**Category**: `data_exfiltration`
**Chain**: Public AMI → Public Snapshot → Strong Offline Extraction Path
| Hop | Evidence |
|-----|----------|
| 1. AMI is public or broadly shared | CONFIRMED required |
| 2. One or more backing snapshots are public | CONFIRMED required |
| 3. Exposed snapshot provides direct filesystem extraction | CONFIRMED required |

**Impact**: Attackers don't need AMI launch path — they can restore filesystem directly from snapshot.
**Break chain**: (1) Remove public AMI + snapshot sharing, (2) Rebuild on private encrypted storage, (3) Review derivatives.

### AP-REF-04: Shared AMI + Unencrypted Backing Snapshot
**Category**: `data_exfiltration`
**Chain**: External Image Share → Plaintext Snapshot Layer → Broader Data Exposure
| Hop | Evidence |
|-----|----------|
| 1. AMI is public or externally shared | CONFIRMED required |
| 2. Backing snapshot is unencrypted | CONFIRMED required |
| 3. Image is internal or in active use | CONFIRMED or INFERRED |

**Break chain**: (1) Remove image sharing, (2) Rebuild on encrypted snapshots, (3) Retire exposed image IDs.

### AP-REF-05: Golden AMI Without IMDSv2 Drives Fleet-Wide Credential Risk
**Category**: `credential_access`
**Chain**: Weak Image Default → Launch Templates/ASGs Use It → Instances Inherit IMDSv1 Risk
| Hop | Evidence |
|-----|----------|
| 1. AMI does not require IMDSv2 (`imdsSupport` not `v2.0`) | CONFIRMED required |
| 2. Launch templates or ASGs reference the AMI (dependency) | CONFIRMED required |
| 3. New instances inherit weak metadata posture | INFERRED |

**Impact**: Image pipeline spreads weaker metadata-security default across current and future instances.
**Break chain**: (1) Enforce IMDSv2 at image level, (2) Roll forward templates/ASGs, (3) Validate instance-level overrides.

### AP-REF-06: Public Internal Image in Active Use
**Category**: `data_exfiltration`
**Chain**: Public AMI → Running Instances Use Same Image → Live and Cloneable Environment
| Hop | Evidence |
|-----|----------|
| 1. AMI is public | CONFIRMED required |
| 2. Running instances use the AMI (dependency) | CONFIRMED required |
| 3. External attackers can launch environment close to running fleet | INFERRED |

**Impact**: Attackers clone close approximation of production baseline for recon and tooling.
**Break chain**: (1) Remove public launch permission, (2) Review image contents, (3) Rotate sensitive baselines.

### AP-REF-07: Shared AMI Feeds Auto Scaling Fleet
**Category**: `data_exfiltration`
**Chain**: Broad Image Share → ASG Uses Image → Wide Deployment Blast Radius
| Hop | Evidence |
|-----|----------|
| 1. AMI is public or externally shared | CONFIRMED required |
| 2. Auto Scaling groups use the AMI (dependency) | CONFIRMED required |
| 3. Same weak/exposed baseline multiplied across fleet | CONFIRMED or INFERRED |

**Impact**: Exposure or unsafe defaults propagate across multiple instances, not a single host.
**Break chain**: (1) Remove unnecessary sharing, (2) Roll forward ASGs to hardened image, (3) Retire exposed image.

---

## 5. AMI-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are AMI-specific additions:

- **Intentional marketplace or public base images** → `NEEDS_REVIEW` unless naming/tags show proprietary or sensitive
- **Organization-approved cross-account golden-image sharing** → `NEEDS_REVIEW` unless broader than intended
- **Old images kept for controlled rollback** → hygiene finding, not critical unless also shared or actively used unsafely
- **IMDSv2 image setting without usage data** → lower severity when AMI is clearly dormant

---

## 6. Remediation Playbooks

### Remove Broad AMI Sharing
1. Inventory public and cross-account shared images
2. Remove public launch permissions immediately
3. Remove unnecessary external account permissions
4. Revalidate org-approved golden-image sharing

### Secure Backing Snapshots
1. Map each AMI to its backing snapshots
2. Remove public/unnecessary external sharing from those snapshots
3. Rebuild images on encrypted private snapshots where needed
4. Review historical copies and derivative images

### Harden Image Defaults
1. Enforce IMDSv2 at the image level
2. Update launch templates and ASGs to hardened image
3. Validate instance-level metadata settings don't override hardening

### Retire Stale Images Safely
1. Identify images with no active usage
2. Validate rollback requirements
3. Deprecate or deregister stale images
4. Clean up backing snapshots when retention no longer required

---

## 7. Coverage Checklist

### Direct Findings
- [ ] Public AMIs
- [ ] Cross-account shared AMIs
- [ ] Public backing snapshots
- [ ] Unencrypted backing snapshots
- [ ] IMDSv2 not required
- [ ] Deregistration protection on critical images
- [ ] Old unused images
- [ ] Old images still driving active fleets

### Attack Paths (via dependency context)
- [ ] AP-REF-01: Public AMI clone of internal stack
- [ ] AP-REF-02: Cross-account shared AMI path
- [ ] AP-REF-03: Public AMI + public backing snapshot
- [ ] AP-REF-04: Shared AMI + unencrypted backing snapshot
- [ ] AP-REF-05: Golden AMI without IMDSv2 in fleet usage
- [ ] AP-REF-06: Public internal image in active use
- [ ] AP-REF-07: Shared AMI feeding Auto Scaling fleet
