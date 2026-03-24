from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


ACCOUNT_AUTHORIZATION_DETAILS_QUERY = (
    "{"
    "UserDetailList:UserDetailList[].{"
    "UserName:UserName,"
    "Arn:Arn,"
    "GroupList:GroupList,"
    "AttachedManagedPolicies:AttachedManagedPolicies,"
    "UserPolicyList:UserPolicyList,"
    "PermissionsBoundary:PermissionsBoundary"
    "},"
    "GroupDetailList:GroupDetailList[].{"
    "GroupName:GroupName,"
    "Arn:Arn,"
    "AttachedManagedPolicies:AttachedManagedPolicies,"
    "GroupPolicyList:GroupPolicyList"
    "},"
    "RoleDetailList:RoleDetailList[].{"
    "RoleName:RoleName,"
    "Arn:Arn,"
    "AssumeRolePolicyDocument:AssumeRolePolicyDocument,"
    "AttachedManagedPolicies:AttachedManagedPolicies,"
    "RolePolicyList:RolePolicyList,"
    "PermissionsBoundary:PermissionsBoundary,"
    "Tags:Tags"
    "},"
    "Policies:Policies[].{"
    "PolicyName:PolicyName,"
    "Arn:Arn,"
    "DefaultVersionId:DefaultVersionId"
    "}"
    "}"
)

USER_LIST_QUERY = "Users[].{UserName:UserName,Arn:Arn,CreateDate:CreateDate,PasswordLastUsed:PasswordLastUsed,Tags:Tags}"
ROLE_LIST_QUERY = "Roles[].{RoleName:RoleName,Arn:Arn,CreateDate:CreateDate,MaxSessionDuration:MaxSessionDuration,Tags:Tags}"
GROUP_LIST_QUERY = "Groups[].{GroupName:GroupName,Arn:Arn,CreateDate:CreateDate}"
LOCAL_POLICIES_QUERY = (
    "Policies[].{"
    "PolicyName:PolicyName,"
    "Arn:Arn,"
    "DefaultVersionId:DefaultVersionId,"
    "AttachmentCount:AttachmentCount,"
    "CreateDate:CreateDate,"
    "UpdateDate:UpdateDate"
    "}"
)
MFA_DEVICES_QUERY = "MFADevices[].{UserName:UserName,SerialNumber:SerialNumber,EnableDate:EnableDate}"
ACCESS_KEYS_QUERY = (
    "AccessKeyMetadata[].{UserName:UserName,AccessKeyId:AccessKeyId,Status:Status,CreateDate:CreateDate}"
)
ACCESS_KEY_LAST_USED_QUERY = (
    "{"
    "AccessKeyId:AccessKeyId,"
    "UserName:UserName,"
    "Status:Status,"
    "AccessKeyLastUsed:AccessKeyLastUsed"
    "}"
)
ATTACHED_POLICIES_QUERY = "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
INLINE_POLICY_NAMES_QUERY = "PolicyNames"
USER_POLICY_QUERY = "{UserName:UserName,PolicyName:PolicyName,PolicyDocument:PolicyDocument}"
ROLE_QUERY = (
    "{"
    "RoleName:Role.RoleName,"
    "Arn:Role.Arn,"
    "AssumeRolePolicyDocument:Role.AssumeRolePolicyDocument,"
    "CreateDate:Role.CreateDate,"
    "MaxSessionDuration:Role.MaxSessionDuration,"
    "Tags:Role.Tags"
    "}"
)
ROLE_POLICY_QUERY = "{RoleName:RoleName,PolicyName:PolicyName,PolicyDocument:PolicyDocument}"
GROUPS_FOR_USER_QUERY = "Groups[].{GroupName:GroupName,Arn:Arn}"
GROUP_POLICY_QUERY = "{GroupName:GroupName,PolicyName:PolicyName,PolicyDocument:PolicyDocument}"
POLICY_VERSION_QUERY = (
    "{"
    "VersionId:PolicyVersion.VersionId,"
    "IsDefaultVersion:PolicyVersion.IsDefaultVersion,"
    "Document:PolicyVersion.Document,"
    "CreateDate:PolicyVersion.CreateDate"
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
SECURITY_GROUP_QUERY = (
    "SecurityGroups[].{"
    "GroupId:GroupId,"
    "GroupName:GroupName,"
    "VpcId:VpcId,"
    "IpPermissions:IpPermissions,"
    "IpPermissionsEgress:IpPermissionsEgress,"
    "Tags:Tags"
    "}"
)
S3_BUCKETS_QUERY = "Buckets[].{Name:Name,CreationDate:CreationDate}"
LAMBDA_LIST_QUERY = (
    "Functions[].{FunctionName:FunctionName,FunctionArn:FunctionArn,Role:Role,Runtime:Runtime}"
)
SECRETS_LIST_QUERY = (
    "SecretList[].{Name:Name,ARN:ARN,RotationEnabled:RotationEnabled,Tags:Tags}"
)


@dataclass(slots=True)
class DependencyTargets:
    bucket_names: set[str]
    has_s3_wildcard: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect IAM-centered AWS CLI evidence for CloudSentinel."
    )
    parser.add_argument("--region", required=True, help="AWS region used for dependency services.")
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


def extract_user_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for user in payload:
        if not isinstance(user, dict):
            continue
        user_name = user.get("UserName")
        if isinstance(user_name, str) and user_name:
            names.add(user_name)
    return sorted(names)


def extract_role_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for role in payload:
        if not isinstance(role, dict):
            continue
        role_name = role.get("RoleName")
        if isinstance(role_name, str) and role_name:
            names.add(role_name)
    return sorted(names)


def extract_group_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for group in payload:
        if not isinstance(group, dict):
            continue
        group_name = group.get("GroupName")
        if isinstance(group_name, str) and group_name:
            names.add(group_name)
    return sorted(names)


def extract_policy_versions(result: CommandResult) -> list[tuple[str, str, str]]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    versions: list[tuple[str, str, str]] = []
    for policy in payload:
        if not isinstance(policy, dict):
            continue
        arn = policy.get("Arn")
        version_id = policy.get("DefaultVersionId")
        policy_name = policy.get("PolicyName")
        if (
            isinstance(arn, str)
            and arn
            and isinstance(version_id, str)
            and version_id
            and isinstance(policy_name, str)
            and policy_name
        ):
            versions.append((arn, version_id, policy_name))
    return versions


def extract_access_key_ids(result: CommandResult) -> list[tuple[str, str]]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    keys: list[tuple[str, str]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        key_id = item.get("AccessKeyId")
        user_name = item.get("UserName")
        if isinstance(key_id, str) and key_id and isinstance(user_name, str) and user_name:
            keys.append((user_name, key_id))
    return keys


def get_inline_policy_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for name in payload:
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def get_group_names_for_user(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("GroupName")
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


def extract_bucket_name_from_resource(resource: str) -> str | None:
    prefix = "arn:aws:s3:::"
    if not resource.startswith(prefix):
        return None
    bucket_name = resource[len(prefix) :].split("/", 1)[0]
    if bucket_name and bucket_name != "*":
        return bucket_name
    return None


def derive_dependency_targets(policy_results: Iterable[CommandResult]) -> DependencyTargets:
    bucket_names: set[str] = set()
    has_s3_wildcard = False

    for result in policy_results:
        document = get_policy_document(result)
        if not document:
            continue
        for statement in iter_allow_statements(document):
            actions = ensure_lower_actions(statement.get("Action"))
            resources = ensure_resource_strings(statement.get("Resource"))
            if not any(action == "*" or action.startswith("s3:") for action in actions):
                continue
            for resource in resources:
                if resource == "*" or resource == "arn:aws:s3:::*":
                    has_s3_wildcard = True
                bucket_name = extract_bucket_name_from_resource(resource)
                if bucket_name:
                    bucket_names.add(bucket_name)

    return DependencyTargets(bucket_names=bucket_names, has_s3_wildcard=has_s3_wildcard)


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


def get_credential_report(runner: AWSCLIRunner) -> CommandResult:
    runner.run(
        ["iam", "generate-credential-report"],
        label="generate-credential-report",
        include_region=False,
    )
    last_result = runner.run(
        ["iam", "get-credential-report"],
        label="get-credential-report",
        include_region=False,
    )
    if last_result.ok:
        return last_result
    for _ in range(4):
        time.sleep(2)
        last_result = runner.run(
            ["iam", "get-credential-report"],
            label="get-credential-report",
            include_region=False,
        )
        if last_result.ok:
            return last_result
    return last_result


def collect_primary_iam(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[CommandResult]]:
    results: list[CommandResult] = []
    policy_results: list[CommandResult] = []

    results.append(
        runner.run(
            ["iam", "get-account-summary"],
            label="get-account-summary",
            include_region=False,
        )
    )
    results.append(
        runner.run(
            ["iam", "get-account-authorization-details", "--query", ACCOUNT_AUTHORIZATION_DETAILS_QUERY],
            label="get-account-authorization-details",
            include_region=False,
        )
    )
    results.append(get_credential_report(runner))
    results.append(
        runner.run(
            ["iam", "get-account-password-policy"],
            label="get-account-password-policy",
            include_region=False,
        )
    )

    users_result = runner.run(
        ["iam", "list-users", "--query", USER_LIST_QUERY],
        label="list-users",
        include_region=False,
    )
    roles_result = runner.run(
        ["iam", "list-roles", "--query", ROLE_LIST_QUERY],
        label="list-roles",
        include_region=False,
    )
    groups_result = runner.run(
        ["iam", "list-groups", "--query", GROUP_LIST_QUERY],
        label="list-groups",
        include_region=False,
    )
    local_policies_result = runner.run(
        ["iam", "list-policies", "--scope", "Local", "--query", LOCAL_POLICIES_QUERY],
        label="list-policies (customer-managed, Scope=Local)",
        include_region=False,
    )
    results.extend([users_result, roles_result, groups_result, local_policies_result])

    group_names = extract_group_names(groups_result)
    user_group_memberships: dict[str, list[str]] = {}

    for user_name in extract_user_names(users_result):
        results.append(
            runner.run(
                ["iam", "list-mfa-devices", "--user-name", user_name, "--query", MFA_DEVICES_QUERY],
                label=f"list-mfa-devices ({user_name})",
                include_region=False,
            )
        )
        access_keys_result = runner.run(
            ["iam", "list-access-keys", "--user-name", user_name, "--query", ACCESS_KEYS_QUERY],
            label=f"list-access-keys ({user_name})",
            include_region=False,
        )
        results.append(access_keys_result)
        for _, access_key_id in extract_access_key_ids(access_keys_result):
            results.append(
                runner.run(
                    [
                        "iam",
                        "get-access-key-last-used",
                        "--access-key-id",
                        access_key_id,
                        "--query",
                        ACCESS_KEY_LAST_USED_QUERY,
                    ],
                    label=f"get-access-key-last-used ({access_key_id})",
                    include_region=False,
                )
            )

        results.append(
            runner.run(
                [
                    "iam",
                    "list-attached-user-policies",
                    "--user-name",
                    user_name,
                    "--query",
                    ATTACHED_POLICIES_QUERY,
                ],
                label=f"list-attached-user-policies ({user_name})",
                include_region=False,
            )
        )
        inline_user_result = runner.run(
            [
                "iam",
                "list-user-policies",
                "--user-name",
                user_name,
                "--query",
                INLINE_POLICY_NAMES_QUERY,
            ],
            label=f"list-user-policies ({user_name})",
            include_region=False,
        )
        results.append(inline_user_result)
        for policy_name in get_inline_policy_names(inline_user_result):
            policy_result = runner.run(
                [
                    "iam",
                    "get-user-policy",
                    "--user-name",
                    user_name,
                    "--policy-name",
                    policy_name,
                    "--query",
                    USER_POLICY_QUERY,
                ],
                label=f"get-user-policy ({user_name}, {policy_name})",
                include_region=False,
            )
            results.append(policy_result)
            policy_results.append(policy_result)

        groups_for_user_result = runner.run(
            ["iam", "list-groups-for-user", "--user-name", user_name, "--query", GROUPS_FOR_USER_QUERY],
            label=f"list-groups-for-user ({user_name})",
            include_region=False,
        )
        results.append(groups_for_user_result)
        user_group_memberships[user_name] = get_group_names_for_user(groups_for_user_result)

    for role_name in extract_role_names(roles_result):
        results.append(
            runner.run(
                ["iam", "get-role", "--role-name", role_name, "--query", ROLE_QUERY],
                label=f"get-role ({role_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                [
                    "iam",
                    "list-attached-role-policies",
                    "--role-name",
                    role_name,
                    "--query",
                    ATTACHED_POLICIES_QUERY,
                ],
                label=f"list-attached-role-policies ({role_name})",
                include_region=False,
            )
        )
        inline_role_result = runner.run(
            [
                "iam",
                "list-role-policies",
                "--role-name",
                role_name,
                "--query",
                INLINE_POLICY_NAMES_QUERY,
            ],
            label=f"list-role-policies ({role_name})",
            include_region=False,
        )
        results.append(inline_role_result)
        for policy_name in get_inline_policy_names(inline_role_result):
            policy_result = runner.run(
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    role_name,
                    "--policy-name",
                    policy_name,
                    "--query",
                    ROLE_POLICY_QUERY,
                ],
                label=f"get-role-policy ({role_name}, {policy_name})",
                include_region=False,
            )
            results.append(policy_result)
            policy_results.append(policy_result)

    for group_name in group_names:
        results.append(
            runner.run(
                [
                    "iam",
                    "list-attached-group-policies",
                    "--group-name",
                    group_name,
                    "--query",
                    ATTACHED_POLICIES_QUERY,
                ],
                label=f"list-attached-group-policies ({group_name})",
                include_region=False,
            )
        )
        inline_group_result = runner.run(
            [
                "iam",
                "list-group-policies",
                "--group-name",
                group_name,
                "--query",
                INLINE_POLICY_NAMES_QUERY,
            ],
            label=f"list-group-policies ({group_name})",
            include_region=False,
        )
        results.append(inline_group_result)
        for policy_name in get_inline_policy_names(inline_group_result):
            policy_result = runner.run(
                [
                    "iam",
                    "get-group-policy",
                    "--group-name",
                    group_name,
                    "--policy-name",
                    policy_name,
                    "--query",
                    GROUP_POLICY_QUERY,
                ],
                label=f"get-group-policy ({group_name}, {policy_name})",
                include_region=False,
            )
            results.append(policy_result)
            policy_results.append(policy_result)

    for policy_arn, version_id, policy_name in extract_policy_versions(local_policies_result):
        policy_result = runner.run(
            [
                "iam",
                "get-policy-version",
                "--policy-arn",
                policy_arn,
                "--version-id",
                version_id,
                "--query",
                POLICY_VERSION_QUERY,
            ],
            label=f"get-policy-version ({policy_name}, {version_id})",
            include_region=False,
        )
        results.append(policy_result)
        policy_results.append(policy_result)

    return results, policy_results


def collect_ec2_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["ec2", "describe-instances", "--query", EC2_INSTANCE_QUERY],
            label="describe-instances",
        ),
        runner.run(
            ["ec2", "describe-security-groups", "--query", SECURITY_GROUP_QUERY],
            label="describe-security-groups",
        ),
    ]


def collect_s3_context(
    runner: AWSCLIRunner, targets: DependencyTargets
) -> list[CommandResult]:
    if not targets.bucket_names and not targets.has_s3_wildcard:
        return []

    results: list[CommandResult] = [
        runner.run(
            ["s3api", "list-buckets", "--query", S3_BUCKETS_QUERY],
            label="list-buckets",
            include_region=False,
        )
    ]
    for bucket_name in sorted(targets.bucket_names):
        bucket_region = resolve_bucket_region(runner, bucket_name)
        bucket_region_args = ["--region", bucket_region]
        results.append(
            runner.run(
                ["s3api", "get-bucket-policy", "--bucket", bucket_name, *bucket_region_args],
                label=f"get-bucket-policy ({bucket_name})",
                include_region=False,
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-public-access-block", "--bucket", bucket_name, *bucket_region_args],
                label=f"get-public-access-block ({bucket_name})",
                include_region=False,
            )
        )
    return results


def collect_lambda_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["lambda", "list-functions", "--query", LAMBDA_LIST_QUERY],
            label="list-functions",
        )
    ]


def collect_secrets_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["secretsmanager", "list-secrets", "--query", SECRETS_LIST_QUERY],
            label="list-secrets",
        )
    ]


def collect_sts_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["sts", "get-caller-identity"],
            label="get-caller-identity",
            include_region=False,
        )
    ]


def build_scan_output(args: argparse.Namespace) -> str:
    runner = AWSCLIRunner(
        region=args.region,
        profile=args.profile,
        timeout_seconds=args.timeout_seconds,
        should_cancel=getattr(args, "should_cancel", None),
    )

    primary_results, policy_results = collect_primary_iam(runner)
    dependency_targets = derive_dependency_targets(policy_results)

    sections = [
        render_section("PRIMARY SERVICE: IAM", primary_results),
        render_section("DEPENDENCY CONTEXT: EC2", collect_ec2_context(runner)),
        render_section("DEPENDENCY CONTEXT: S3", collect_s3_context(runner, dependency_targets)),
        render_section("DEPENDENCY CONTEXT: LAMBDA", collect_lambda_context(runner)),
        render_section("DEPENDENCY CONTEXT: SECRETS_MANAGER", collect_secrets_context(runner)),
        render_section("DEPENDENCY CONTEXT: STS", collect_sts_context(runner)),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
