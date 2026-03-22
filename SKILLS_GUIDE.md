# CloudSentinel — Skill Files Architecture Guide

## What Are Skills in CloudSentinel?

Skills are **supplementary knowledge files** that the analyzer loads alongside the main `CLAUDE.md` system prompt to give the AI deeper, service-specific expertise. Think of it like this:

- **CLAUDE.md** = the AI's general security analyst brain (always loaded)
- **Skill files** = specialized training modules for specific AWS services (loaded per-scan)

The AI uses CLAUDE.md as its core operating instructions, but when analyzing EC2 output, it also loads the EC2 skill file which contains EC2-specific patterns, attack scenarios, compliance mappings, and remediation playbooks that make the analysis sharper.

---

## Why Skills Matter


Claude is already very capable at AWS security analysis. But skills make it:

1. **More consistent** — Without skills, the AI might catch an issue in one scan but miss it in another. Skills provide a checklist it always follows.
2. **More thorough** — Skills encode rare edge cases and advanced attack patterns that the AI might not think of on its own.
3. **More actionable** — Skills contain pre-built remediation commands and step-by-step fix procedures for known issues.
4. **More accurate** — Skills teach the AI what is and isn't a real problem for each service, reducing false positives.
5. **Domain-expert level** — Skills can encode knowledge from CIS benchmarks, AWS Well-Architected Framework, and real-world incident patterns.

---

## Skill File Structure

```
cloudsentinel/
├── analyzer/
│   ├── CLAUDE.md                    # Core system prompt (always loaded)
│   └── skills/
│       ├── ec2_skill.md             # EC2 deep analysis patterns
│       ├── s3_skill.md              # S3 deep analysis patterns
│       ├── iam_skill.md             # IAM deep analysis patterns
│       ├── vpc_skill.md             # VPC deep analysis patterns
│       ├── rds_skill.md             # (future) RDS patterns
│       ├── lambda_skill.md          # (future) Lambda patterns
│       └── common_patterns.md       # Cross-service patterns (always loaded)
```

---

## How Skills Are Loaded

The `analyzer.py` module handles skill loading. Here's the flow:

```
1. User triggers scan for "ec2"
2. Scanner runs → produces output file
3. Analyzer loads:
   a. CLAUDE.md (always)
   b. common_patterns.md (always)
   c. ec2_skill.md (service-specific)
4. System prompt = CLAUDE.md content
5. User message = skill content + raw scanner output
6. Send to Claude API → get structured findings
```

In code, the loading logic would look like:

```python
def build_prompt(service: str, scanner_output: str) -> tuple[str, str]:
    """Returns (system_prompt, user_message) for the Claude API call."""
    
    # Always load the core prompt
    system_prompt = read_file("analyzer/CLAUDE.md")
    
    # Build user message with skills + data
    parts = []
    
    # Always load common patterns
    common_skill = read_file("analyzer/skills/common_patterns.md")
    if common_skill:
        parts.append(f"<common_patterns>\n{common_skill}\n</common_patterns>")
    
    # Load service-specific skill
    service_skill = read_file(f"analyzer/skills/{service}_skill.md")
    if service_skill:
        parts.append(f"<service_skill>\n{service_skill}\n</service_skill>")
    
    # Add the actual scan data
    parts.append(f"<scan_output>\n{scanner_output}\n</scan_output>")
    
    user_message = "\n\n".join(parts)
    return system_prompt, user_message
```

---

## Skill File Template

Every skill file follows this structure:

```markdown
# {Service} Security Analysis Skill

## Service Overview
Brief description of what this AWS service does and why it matters for security.

## Key Resources to Analyze
List of resource types this service manages and what to look for in each.

## Common Misconfigurations
### Pattern: {Name}
- **What it looks like in CLI output:** (specific JSON patterns or field values)
- **Why it's dangerous:** (concrete attack scenario)
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Fix command:** (actual AWS CLI command with placeholder resource IDs)
- **CIS Benchmark reference:** (if applicable)

## Attack Chains
Combinations of findings that together create a more severe risk.

## False Positive Patterns
Things that LOOK like issues but aren't, and how to distinguish them.

## Remediation Playbooks
Step-by-step fix procedures for complex issues that need more than one command.

## Service-Specific Output Patterns
How to interpret specific fields in this service's CLI output.
```

---

## Example: EC2 Skill File

Here's a condensed example of what `ec2_skill.md` would contain:

```markdown
# EC2 Security Analysis Skill

## Service Overview
EC2 provides virtual servers. Security concerns center on network exposure
(security groups), data protection (EBS encryption, snapshot access),
and instance configuration (key pairs, metadata service).

## Key Resources to Analyze
- **Security Groups**: Inbound/outbound rules, attached instances
- **EBS Volumes**: Encryption status, attachment state
- **Snapshots**: Public sharing, encryption
- **AMIs**: Public sharing, age
- **Key Pairs**: Usage, orphaned keys
- **Elastic IPs**: Association status
- **Instances**: IMDSv2 enforcement, public IP assignment

## Common Misconfigurations

### Pattern: Open SSH to World
- **CLI output signature:** IngressRule with CidrIp "0.0.0.0/0" and FromPort 22
- **Why dangerous:** Enables brute-force attacks from any internet IP
- **Severity:** CRITICAL
- **Fix:** `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port 22 --cidr 0.0.0.0/0`
- **CIS:** 5.2 — Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

### Pattern: IMDSv1 Still Enabled
- **CLI output signature:** MetadataOptions.HttpTokens = "optional"
- **Why dangerous:** SSRF attacks can steal instance credentials via IMDSv1
- **Severity:** HIGH
- **Fix:** `aws ec2 modify-instance-metadata-options --instance-id {id} --http-tokens required --http-endpoint enabled`
- **CIS:** 5.6

## Attack Chains
- Open SG + IMDSv1 + IAM role with broad permissions = full credential theft via SSRF
- Public snapshot + unencrypted = data exfiltration without account access

## False Positive Patterns
- Port 80/443 open on security groups attached to ALBs/ELBs → Expected, not a finding
- Port 443 open from 0.0.0.0/0 on a web server → Expected for HTTPS traffic
- Stopped instances with open SGs → Lower severity since instance is not running
```

---

## Skill Files to Create (Priority Order)

### Phase 1 — Matches Current Scanners (build these now)
1. `iam_skill.md` — Console users, MFA, access keys, policies, password policy, root account
2. `ec2_skill.md` — Security groups, snapshots, AMIs, volumes, key pairs, metadata
3. `s3_skill.md` — ACLs, bucket policies, encryption, public access, versioning, logging
4. `vpc_skill.md` — Flow logs, NACLs, peering, IGWs, route tables, subnets, endpoints
5. `common_patterns.md` — Cross-service patterns (tagging, encryption everywhere, logging everywhere)

### Phase 2 — Future Services (build when scanner is added)
6. `rds_skill.md` — Public access, encryption, backups, Multi-AZ, parameter groups
7. `lambda_skill.md` — Execution roles, env var secrets, VPC config, timeouts, layers
8. `ecs_skill.md` — Task roles, network mode, secrets, image scanning
9. `cloudtrail_skill.md` — Multi-region, log validation, S3 bucket security
10. `cloudwatch_skill.md` — Alarm coverage, log retention, metric filters

---

## How to Create a New Skill File

### Step 1: Research
- Read the AWS documentation for the service
- Review the CIS AWS Benchmark sections for that service
- Look at common CVEs and security incidents involving the service
- Review what CLI commands the scanner runs (check the scanner file)

### Step 2: Map CLI Output to Findings
- Run each scanner command manually or review sample output
- Identify which JSON fields indicate misconfigurations
- Map each field pattern to a severity level

### Step 3: Write the Skill
- Follow the template above
- Focus on CONCRETE patterns, not abstract advice
- Every misconfiguration pattern should have:
  - The exact CLI output signature that reveals it
  - A specific attack scenario (not "this is bad")
  - A real fix command with placeholder IDs
  - A CIS/compliance reference if applicable

### Step 4: Write Attack Chains
- Think about how findings combine across categories
- Example: weak IAM + network exposure + no logging = invisible full compromise

### Step 5: Write False Positive Patterns
- This is where skill files add the most value
- Prevents the AI from flagging things that are intentional

### Step 6: Test
- Run a scan with the skill loaded
- Compare output with and without the skill
- Check: Are there fewer false positives? More specific fix commands? Better narrative?

---

## The `common_patterns.md` Skill

This file is always loaded regardless of which service is being analyzed. It contains:

1. **Tagging standards** — Flag untagged resources, suggest tag keys
2. **Encryption baseline** — Every data store should be encrypted
3. **Logging baseline** — Every service should have logging enabled
4. **Least privilege principle** — How to evaluate if permissions are too broad
5. **Cost patterns** — Unused resources, oversized instances, orphaned storage
6. **Multi-account patterns** — Cross-account access rules
7. **Region awareness** — Resources in unexpected regions

---

## Integrating Skills into the Analyzer

The `analyzer.py` module needs to:

1. Accept a `service` parameter
2. Load `CLAUDE.md` as the system prompt
3. Check if `skills/{service}_skill.md` exists → load it
4. Always load `skills/common_patterns.md`
5. Concatenate: skill content + scan output as the user message
6. Send to Claude API
7. Parse the JSON response
8. Handle errors (malformed JSON, missing fields, API failures)

### Token Budget Consideration
Skills add to the input token count. Keep each skill file under 3,000 words (~4,000 tokens). The raw scanner output can be 5,000–15,000 tokens. CLAUDE.md is ~3,000 tokens. Total input should stay under 30,000 tokens to leave room for the response.

---

## Summary

| Component | Purpose | When Loaded |
|-----------|---------|-------------|
| `CLAUDE.md` | Core analysis rules, output format, severity tables | Always |
| `common_patterns.md` | Cross-service security patterns | Always |
| `{service}_skill.md` | Service-specific patterns, attack chains, false positives | Per service |

This three-layer system gives the AI both breadth (CLAUDE.md + common) and depth (service skill) for every analysis.
