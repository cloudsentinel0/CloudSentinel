from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


BUCKET_LIST_QUERY = "Buckets[].{Name:Name,CreationDate:CreationDate}"
ACCOUNT_PUBLIC_ACCESS_BLOCK_QUERY = (
    "{"
    "BlockPublicAcls:PublicAccessBlockConfiguration.BlockPublicAcls,"
    "IgnorePublicAcls:PublicAccessBlockConfiguration.IgnorePublicAcls,"
    "BlockPublicPolicy:PublicAccessBlockConfiguration.BlockPublicPolicy,"
    "RestrictPublicBuckets:PublicAccessBlockConfiguration.RestrictPublicBuckets"
    "}"
)

ROLE_LIST_QUERY = "Roles[].{RoleName:RoleName,Arn:Arn,Path:Path,Tags:Tags}"
USER_LIST_QUERY = "Users[].{UserName:UserName,Arn:Arn,CreateDate:CreateDate}"
ROLE_QUERY = (
    "{"
    "RoleName:Role.RoleName,"
    "Arn:Role.Arn,"
    "AssumeRolePolicyDocument:Role.AssumeRolePolicyDocument,"
    "CreateDate:Role.CreateDate,"
    "Tags:Role.Tags"
    "}"
)
ATTACHED_ROLE_POLICIES_QUERY = (
    "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
)
INLINE_ROLE_POLICIES_QUERY = "PolicyNames"
ATTACHED_USER_POLICIES_QUERY = (
    "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
)
INLINE_USER_POLICIES_QUERY = "PolicyNames"
MANAGED_POLICY_QUERY = (
    "{"
    "Arn:Policy.Arn,"
    "DefaultVersionId:Policy.DefaultVersionId,"
    "Description:Policy.Description,"
    "PolicyName:Policy.PolicyName,"
    "AttachmentCount:Policy.AttachmentCount,"
    "CreateDate:Policy.CreateDate,"
    "UpdateDate:Policy.UpdateDate"
    "}"
)
MANAGED_POLICY_VERSION_QUERY = (
    "{"
    "VersionId:PolicyVersion.VersionId,"
    "IsDefaultVersion:PolicyVersion.IsDefaultVersion,"
    "Document:PolicyVersion.Document,"
    "CreateDate:PolicyVersion.CreateDate"
    "}"
)
INLINE_ROLE_POLICY_QUERY = (
    "{"
    "RoleName:RoleName,"
    "PolicyName:PolicyName,"
    "PolicyDocument:PolicyDocument"
    "}"
)
INLINE_USER_POLICY_QUERY = (
    "{"
    "UserName:UserName,"
    "PolicyName:PolicyName,"
    "PolicyDocument:PolicyDocument"
    "}"
)
TRAILS_QUERY = (
    "trailList[].{"
    "Name:Name,"
    "TrailARN:TrailARN,"
    "HomeRegion:HomeRegion,"
    "S3BucketName:S3BucketName,"
    "IsMultiRegionTrail:IsMultiRegionTrail,"
    "IsOrganizationTrail:IsOrganizationTrail,"
    "HasCustomEventSelectors:HasCustomEventSelectors"
    "}"
)
TRAIL_STATUS_QUERY = (
    "{"
    "IsLogging:IsLogging,"
    "LatestDeliveryTime:LatestDeliveryTime,"
    "LatestCloudWatchLogsDeliveryTime:LatestCloudWatchLogsDeliveryTime,"
    "LatestNotificationTime:LatestNotificationTime,"
    "StartLoggingTime:StartLoggingTime,"
    "StopLoggingTime:StopLoggingTime"
    "}"
)
EVENT_SELECTORS_QUERY = (
    "{"
    "TrailARN:TrailARN,"
    "EventSelectors:EventSelectors,"
    "AdvancedEventSelectors:AdvancedEventSelectors"
    "}"
)
EC2_INSTANCE_QUERY = (
    "Reservations[].Instances[].{"
    "InstanceId:InstanceId,"
    "Name:Tags[?Key=='Name']|[0].Value,"
    "State:State.Name,"
    "VpcId:VpcId,"
    "SubnetId:SubnetId,"
    "PublicIpAddress:PublicIpAddress,"
    "PrivateIpAddress:PrivateIpAddress,"
    "IamInstanceProfile:IamInstanceProfile.Arn,"
    "SecurityGroups:SecurityGroups[].{GroupId:GroupId,GroupName:GroupName},"
    "Tags:Tags"
    "}"
)
LAMBDA_LIST_QUERY = (
    "Functions[].{FunctionName:FunctionName,FunctionArn:FunctionArn,Role:Role,Runtime:Runtime}"
)


@dataclass(slots=True)
class RelevantIdentityResult:
    role_results: list[CommandResult]
    role_names: set[str]
    user_results: list[CommandResult]
    user_names: set[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect S3-centered AWS CLI evidence for CloudSentinel."
    )
    parser.add_argument("--region", required=True, help="AWS region used for account-scoped APIs.")
    parser.add_argument("--profile", help="Optional AWS CLI profile name.")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="Per-command timeout in seconds.",
    )
    parser.add_argument(
        "--output-file",
        help="Optional path to write the formatted scan output.",
    )
    return parser.parse_args()


def get_parsed_payload(result: CommandResult) -> object | None:
    return result.parsed_stdout()


def ensure_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ensure_lower_actions(action_value: object) -> list[str]:
    actions: list[str] = []
    for action in ensure_list(action_value):
        if isinstance(action, str):
            actions.append(action.lower())
    return actions


def ensure_resource_strings(resource_value: object) -> list[str]:
    resources: list[str] = []
    for resource in ensure_list(resource_value):
        if isinstance(resource, str):
            resources.append(resource)
    return resources


def iter_allow_statements(policy_document: dict) -> Iterable[dict]:
    for statement in ensure_list(policy_document.get("Statement")):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        yield statement


def extract_bucket_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for bucket in payload:
        if not isinstance(bucket, dict):
            continue
        name = bucket.get("Name")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def extract_role_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    role_names: set[str] = set()
    for role in payload:
        if not isinstance(role, dict):
            continue
        role_name = role.get("RoleName")
        if isinstance(role_name, str) and role_name:
            role_names.add(role_name)
    return sorted(role_names)


def extract_user_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    user_names: set[str] = set()
    for user in payload:
        if not isinstance(user, dict):
            continue
        user_name = user.get("UserName")
        if isinstance(user_name, str) and user_name:
            user_names.add(user_name)
    return sorted(user_names)


def get_managed_policy_arns(result: CommandResult) -> list[tuple[str, str]]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    policies: list[tuple[str, str]] = []
    for policy in payload:
        if not isinstance(policy, dict):
            continue
        arn = policy.get("PolicyArn")
        name = policy.get("PolicyName")
        if isinstance(arn, str) and arn and isinstance(name, str) and name:
            policies.append((arn, name))
    return policies


def get_inline_policy_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for name in payload:
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def get_policy_document(result: CommandResult) -> dict | None:
    payload = get_parsed_payload(result)
    if not isinstance(payload, dict):
        return None
    document = payload.get("Document")
    if isinstance(document, dict):
        return document
    document = payload.get("PolicyDocument")
    if isinstance(document, dict):
        return document
    return None


def extract_default_version_id(result: CommandResult) -> str | None:
    payload = get_parsed_payload(result)
    if not isinstance(payload, dict):
        return None
    version_id = payload.get("DefaultVersionId")
    if isinstance(version_id, str) and version_id:
        return version_id
    return None


def extract_trail_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for trail in payload:
        if not isinstance(trail, dict):
            continue
        name = trail.get("Name")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def normalize_bucket_region(location_constraint: object, fallback_region: str) -> str:
    if location_constraint in (None, "", "None"):
        return "us-east-1"
    if location_constraint == "EU":
        return "eu-west-1"
    if isinstance(location_constraint, str):
        return location_constraint
    return fallback_region


def resolve_bucket_region(runner: AWSCLIRunner, bucket_name: str) -> str:
    result = runner.run(
        ["s3api", "get-bucket-location", "--bucket", bucket_name],
        label=f"get-bucket-location ({bucket_name})",
        include_region=False,
    )
    payload = get_parsed_payload(result)
    if isinstance(payload, dict):
        return normalize_bucket_region(payload.get("LocationConstraint"), runner.region)
    return runner.region


def policy_name_hints_s3(policy_name: str) -> bool:
    lowered = policy_name.lower()
    return any(
        hint in lowered
        for hint in (
            "s3",
            "administratoraccess",
            "poweruseraccess",
            "readonlyaccess",
            "fullaccess",
        )
    )


def policy_document_mentions_s3(document: dict, bucket_names: set[str]) -> bool:
    for statement in iter_allow_statements(document):
        actions = ensure_lower_actions(statement.get("Action"))
        resources = ensure_resource_strings(statement.get("Resource"))
        if any(action == "*" or action.startswith("s3:") for action in actions):
            return True
        for resource in resources:
            if resource == "*" or resource.startswith("arn:aws:s3:::"):
                return True
            if any(bucket_name in resource for bucket_name in bucket_names):
                return True
    return False


def collect_primary_s3(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], str | None]:
    results: list[CommandResult] = []

    caller_identity = runner.run(
        ["sts", "get-caller-identity"],
        label="get-caller-identity",
        include_region=False,
    )
    caller_payload = get_parsed_payload(caller_identity)
    account_id = None
    if isinstance(caller_payload, dict):
        account_candidate = caller_payload.get("Account")
        if isinstance(account_candidate, str) and account_candidate:
            account_id = account_candidate

    list_result = runner.run(
        ["s3api", "list-buckets", "--query", BUCKET_LIST_QUERY],
        label="list-buckets",
        include_region=False,
    )
    results.append(list_result)

    if account_id:
        results.append(
            runner.run(
                [
                    "s3control",
                    "get-public-access-block",
                    "--account-id",
                    account_id,
                    "--query",
                    ACCOUNT_PUBLIC_ACCESS_BLOCK_QUERY,
                ],
                label="get-public-access-block (account-level via s3control)",
            )
        )

    bucket_names = extract_bucket_names(list_result)
    for bucket_name in bucket_names:
        bucket_region = resolve_bucket_region(runner, bucket_name)
        bucket_prefix = ["--region", bucket_region]
        results.append(
            runner.run(
                ["s3api", "get-public-access-block", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-public-access-block ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-policy", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-policy ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-policy-status", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-policy-status ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-acl", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-acl ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-encryption", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-encryption ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-versioning", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-versioning ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-logging", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-logging ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-tagging", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-tagging ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-website", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-website ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                [
                    "s3api",
                    "get-bucket-ownership-controls",
                    "--bucket",
                    bucket_name,
                    *bucket_prefix,
                ],
                label=f"get-bucket-ownership-controls ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-replication", "--bucket", bucket_name, *bucket_prefix],
                label=f"get-bucket-replication ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                [
                    "s3api",
                    "get-bucket-notification-configuration",
                    "--bucket",
                    bucket_name,
                    *bucket_prefix,
                ],
                label=f"get-bucket-notification-configuration ({bucket_name})",
                include_region=False,
            )
        )

    return results, bucket_names, account_id


def collect_role_policy_results(
    runner: AWSCLIRunner, role_name: str, bucket_names: set[str]
) -> tuple[bool, list[CommandResult]]:
    results: list[CommandResult] = []
    relevant = False

    get_role_result = runner.run(
        ["iam", "get-role", "--role-name", role_name, "--query", ROLE_QUERY],
        label=f"get-role ({role_name})",
        include_region=False,
    )
    results.append(get_role_result)

    attached_result = runner.run(
        [
            "iam",
            "list-attached-role-policies",
            "--role-name",
            role_name,
            "--query",
            ATTACHED_ROLE_POLICIES_QUERY,
        ],
        label=f"list-attached-role-policies ({role_name})",
        include_region=False,
    )
    results.append(attached_result)

    inline_result = runner.run(
        [
            "iam",
            "list-role-policies",
            "--role-name",
            role_name,
            "--query",
            INLINE_ROLE_POLICIES_QUERY,
        ],
        label=f"list-role-policies ({role_name})",
        include_region=False,
    )
    results.append(inline_result)

    for policy_arn, policy_name in get_managed_policy_arns(attached_result):
        if policy_name_hints_s3(policy_name):
            relevant = True
        if policy_arn.startswith("arn:aws:iam::aws:"):
            continue
        policy_result = runner.run(
            ["iam", "get-policy", "--policy-arn", policy_arn, "--query", MANAGED_POLICY_QUERY],
            label=f"get-policy ({policy_arn})",
            include_region=False,
        )
        results.append(policy_result)
        version_id = extract_default_version_id(policy_result)
        if not version_id:
            continue
        version_result = runner.run(
            [
                "iam",
                "get-policy-version",
                "--policy-arn",
                policy_arn,
                "--version-id",
                version_id,
                "--query",
                MANAGED_POLICY_VERSION_QUERY,
            ],
            label=f"get-policy-version ({policy_arn}, {version_id})",
            include_region=False,
        )
        results.append(version_result)
        document = get_policy_document(version_result)
        if document and policy_document_mentions_s3(document, bucket_names):
            relevant = True

    for policy_name in get_inline_policy_names(inline_result):
        policy_result = runner.run(
            [
                "iam",
                "get-role-policy",
                "--role-name",
                role_name,
                "--policy-name",
                policy_name,
                "--query",
                INLINE_ROLE_POLICY_QUERY,
            ],
            label=f"get-role-policy ({role_name}, {policy_name})",
            include_region=False,
        )
        results.append(policy_result)
        document = get_policy_document(policy_result)
        if document and policy_document_mentions_s3(document, bucket_names):
            relevant = True

    return relevant, results


def collect_user_policy_results(
    runner: AWSCLIRunner, user_name: str, bucket_names: set[str]
) -> tuple[bool, list[CommandResult]]:
    results: list[CommandResult] = []
    relevant = False

    attached_result = runner.run(
        [
            "iam",
            "list-attached-user-policies",
            "--user-name",
            user_name,
            "--query",
            ATTACHED_USER_POLICIES_QUERY,
        ],
        label=f"list-attached-user-policies ({user_name})",
        include_region=False,
    )
    results.append(attached_result)

    inline_result = runner.run(
        [
            "iam",
            "list-user-policies",
            "--user-name",
            user_name,
            "--query",
            INLINE_USER_POLICIES_QUERY,
        ],
        label=f"list-user-policies ({user_name})",
        include_region=False,
    )
    results.append(inline_result)

    for policy_arn, policy_name in get_managed_policy_arns(attached_result):
        if policy_name_hints_s3(policy_name):
            relevant = True
        if policy_arn.startswith("arn:aws:iam::aws:"):
            continue
        policy_result = runner.run(
            ["iam", "get-policy", "--policy-arn", policy_arn, "--query", MANAGED_POLICY_QUERY],
            label=f"get-policy ({policy_arn})",
            include_region=False,
        )
        results.append(policy_result)
        version_id = extract_default_version_id(policy_result)
        if not version_id:
            continue
        version_result = runner.run(
            [
                "iam",
                "get-policy-version",
                "--policy-arn",
                policy_arn,
                "--version-id",
                version_id,
                "--query",
                MANAGED_POLICY_VERSION_QUERY,
            ],
            label=f"get-policy-version ({policy_arn}, {version_id})",
            include_region=False,
        )
        results.append(version_result)
        document = get_policy_document(version_result)
        if document and policy_document_mentions_s3(document, bucket_names):
            relevant = True

    for policy_name in get_inline_policy_names(inline_result):
        policy_result = runner.run(
            [
                "iam",
                "get-user-policy",
                "--user-name",
                user_name,
                "--policy-name",
                policy_name,
                "--query",
                INLINE_USER_POLICY_QUERY,
            ],
            label=f"get-user-policy ({user_name}, {policy_name})",
            include_region=False,
        )
        results.append(policy_result)
        document = get_policy_document(policy_result)
        if document and policy_document_mentions_s3(document, bucket_names):
            relevant = True

    return relevant, results


def collect_iam_context(
    runner: AWSCLIRunner, bucket_names: list[str]
) -> RelevantIdentityResult:
    bucket_name_set = set(bucket_names)
    role_results: list[CommandResult] = []
    user_results: list[CommandResult] = []
    relevant_role_names: set[str] = set()
    relevant_user_names: set[str] = set()

    roles_result = runner.run(
        ["iam", "list-roles", "--query", ROLE_LIST_QUERY],
        label="list-roles",
        include_region=False,
    )
    role_results.append(roles_result)
    for role_name in extract_role_names(roles_result):
        is_relevant, results = collect_role_policy_results(runner, role_name, bucket_name_set)
        if is_relevant:
            relevant_role_names.add(role_name)
            role_results.extend(results)

    users_result = runner.run(
        ["iam", "list-users", "--query", USER_LIST_QUERY],
        label="list-users",
        include_region=False,
    )
    user_results.append(users_result)
    for user_name in extract_user_names(users_result):
        is_relevant, results = collect_user_policy_results(runner, user_name, bucket_name_set)
        if is_relevant:
            relevant_user_names.add(user_name)
            user_results.extend(results)

    return RelevantIdentityResult(
        role_results=role_results,
        role_names=relevant_role_names,
        user_results=user_results,
        user_names=relevant_user_names,
    )


def collect_cloudtrail_context(runner: AWSCLIRunner) -> list[CommandResult]:
    results: list[CommandResult] = []
    trails_result = runner.run(
        ["cloudtrail", "describe-trails", "--query", TRAILS_QUERY],
        label="describe-trails",
    )
    results.append(trails_result)
    for trail_name in extract_trail_names(trails_result):
        results.append(
            runner.run(
                ["cloudtrail", "get-trail-status", "--name", trail_name, "--query", TRAIL_STATUS_QUERY],
                label=f"get-trail-status ({trail_name})",
            )
        )
        results.append(
            runner.run(
                [
                    "cloudtrail",
                    "get-event-selectors",
                    "--trail-name",
                    trail_name,
                    "--query",
                    EVENT_SELECTORS_QUERY,
                ],
                label=f"get-event-selectors ({trail_name})",
            )
        )
    return results


def collect_ec2_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["ec2", "describe-instances", "--query", EC2_INSTANCE_QUERY],
            label="describe-instances",
        )
    ]


def collect_lambda_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["lambda", "list-functions", "--query", LAMBDA_LIST_QUERY],
            label="list-functions",
        )
    ]


def build_scan_output(args: argparse.Namespace) -> str:
    runner = AWSCLIRunner(
        region=args.region,
        profile=args.profile,
        timeout_seconds=args.timeout_seconds,
        should_cancel=getattr(args, "should_cancel", None),
    )

    primary_results, bucket_names, _ = collect_primary_s3(runner)
    iam_context = collect_iam_context(runner, bucket_names)
    iam_results = iam_context.role_results + iam_context.user_results

    sections = [
        render_section("PRIMARY SERVICE: S3", primary_results),
        render_section("DEPENDENCY CONTEXT: IAM", iam_results),
        render_section("DEPENDENCY CONTEXT: CLOUDTRAIL", collect_cloudtrail_context(runner)),
        render_section("DEPENDENCY CONTEXT: EC2", collect_ec2_context(runner)),
        render_section("DEPENDENCY CONTEXT: LAMBDA", collect_lambda_context(runner)),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
