from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


INSTANCE_QUERY = (
    "Reservations[].Instances[].{"
    "InstanceId:InstanceId,"
    "Name:Tags[?Key=='Name']|[0].Value,"
    "State:State.Name,"
    "InstanceType:InstanceType,"
    "LaunchTime:LaunchTime,"
    "PrivateIpAddress:PrivateIpAddress,"
    "PublicIpAddress:PublicIpAddress,"
    "VpcId:VpcId,"
    "SubnetId:SubnetId,"
    "IamInstanceProfile:IamInstanceProfile.Arn,"
    "SecurityGroups:SecurityGroups[].{GroupId:GroupId,GroupName:GroupName},"
    "MetadataOptions:MetadataOptions,"
    "Monitoring:Monitoring.State,"
    "Tags:Tags"
    "}"
)

SECURITY_GROUP_QUERY = (
    "SecurityGroups[].{"
    "GroupId:GroupId,"
    "GroupName:GroupName,"
    "Description:Description,"
    "VpcId:VpcId,"
    "IpPermissions:IpPermissions,"
    "IpPermissionsEgress:IpPermissionsEgress,"
    "Tags:Tags"
    "}"
)

VOLUME_QUERY = (
    "Volumes[].{"
    "VolumeId:VolumeId,"
    "State:State,"
    "Encrypted:Encrypted,"
    "KmsKeyId:KmsKeyId,"
    "Size:Size,"
    "VolumeType:VolumeType,"
    "SnapshotId:SnapshotId,"
    "CreateTime:CreateTime,"
    "Attachments:Attachments[].{InstanceId:InstanceId,State:State,Device:Device},"
    "Tags:Tags"
    "}"
)

SNAPSHOT_QUERY = (
    "Snapshots[].{"
    "SnapshotId:SnapshotId,"
    "StartTime:StartTime,"
    "State:State,"
    "Encrypted:Encrypted,"
    "VolumeId:VolumeId,"
    "VolumeSize:VolumeSize,"
    "Description:Description,"
    "OwnerId:OwnerId,"
    "Tags:Tags"
    "}"
)

IMAGE_QUERY = (
    "Images[].{"
    "ImageId:ImageId,"
    "Name:Name,"
    "Public:Public,"
    "CreationDate:CreationDate,"
    "State:State,"
    "Description:Description,"
    "ImageOwnerAlias:ImageOwnerAlias,"
    "BlockDeviceMappings:BlockDeviceMappings[].{DeviceName:DeviceName,Ebs:Ebs},"
    "Tags:Tags"
    "}"
)

KEY_PAIR_QUERY = (
    "KeyPairs[].{"
    "KeyPairId:KeyPairId,"
    "KeyName:KeyName,"
    "KeyFingerprint:KeyFingerprint,"
    "Tags:Tags"
    "}"
)

ADDRESS_QUERY = (
    "Addresses[].{"
    "AllocationId:AllocationId,"
    "AssociationId:AssociationId,"
    "PublicIp:PublicIp,"
    "InstanceId:InstanceId,"
    "NetworkInterfaceId:NetworkInterfaceId,"
    "PrivateIpAddress:PrivateIpAddress,"
    "Domain:Domain,"
    "Tags:Tags"
    "}"
)

SUBNET_QUERY = (
    "Subnets[].{"
    "SubnetId:SubnetId,"
    "VpcId:VpcId,"
    "AvailabilityZone:AvailabilityZone,"
    "CidrBlock:CidrBlock,"
    "MapPublicIpOnLaunch:MapPublicIpOnLaunch,"
    "Tags:Tags"
    "}"
)

ROUTE_TABLE_QUERY = (
    "RouteTables[].{"
    "RouteTableId:RouteTableId,"
    "VpcId:VpcId,"
    "Associations:Associations[].{SubnetId:SubnetId,Main:Main,RouteTableAssociationId:RouteTableAssociationId},"
    "Routes:Routes,"
    "Tags:Tags"
    "}"
)

INTERNET_GATEWAY_QUERY = (
    "InternetGateways[].{"
    "InternetGatewayId:InternetGatewayId,"
    "Attachments:Attachments,"
    "Tags:Tags"
    "}"
)

INSTANCE_PROFILE_QUERY = (
    "{"
    "InstanceProfileName:InstanceProfile.InstanceProfileName,"
    "Arn:InstanceProfile.Arn,"
    "Roles:InstanceProfile.Roles[].{RoleName:RoleName,Arn:Arn}"
    "}"
)

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

ATTACHED_ROLE_POLICIES_QUERY = (
    "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
)

INLINE_ROLE_POLICIES_QUERY = "PolicyNames"

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

S3_LIST_QUERY = "Buckets[].{Name:Name,CreationDate:CreationDate}"

LAMBDA_LIST_QUERY = (
    "Functions[].{FunctionName:FunctionName,FunctionArn:FunctionArn,Role:Role,Runtime:Runtime}"
)

SECRETS_LIST_QUERY = (
    "SecretList[].{Name:Name,ARN:ARN,RotationEnabled:RotationEnabled,Tags:Tags}"
)

SSM_INFO_QUERY = (
    "InstanceInformationList[].{"
    "InstanceId:InstanceId,"
    "PingStatus:PingStatus,"
    "PlatformName:PlatformName,"
    "PlatformVersion:PlatformVersion,"
    "ResourceType:ResourceType,"
    "IPAddress:IPAddress,"
    "ComputerName:ComputerName,"
    "AgentVersion:AgentVersion,"
    "LastPingDateTime:LastPingDateTime"
    "}"
)


@dataclass(slots=True)
class DependencyTargets:
    bucket_names: set[str]
    has_s3_wildcard: bool
    lambda_functions: set[str]
    has_lambda_wildcard: bool
    secret_identifiers: set[str]
    has_secret_wildcard: bool
    needs_ssm_context: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect EC2-centered AWS CLI evidence for CloudSentinel."
    )
    parser.add_argument("--region", required=True, help="AWS region to scan.")
    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile name.",
    )
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


def extract_name_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def extract_instance_profile_names(instances: Iterable[object]) -> list[str]:
    profile_names: set[str] = set()
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        arn = instance.get("IamInstanceProfile")
        if isinstance(arn, str) and arn:
            profile_names.add(extract_name_from_arn(arn))
    return sorted(profile_names)


def extract_instance_ids(instances: Iterable[object]) -> list[str]:
    instance_ids: set[str] = set()
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        instance_id = instance.get("InstanceId")
        if isinstance(instance_id, str) and instance_id:
            instance_ids.add(instance_id)
    return sorted(instance_ids)


def extract_subnet_ids(instances: Iterable[object]) -> list[str]:
    subnet_ids: set[str] = set()
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        subnet_id = instance.get("SubnetId")
        if isinstance(subnet_id, str) and subnet_id:
            subnet_ids.add(subnet_id)
    return sorted(subnet_ids)


def extract_vpc_ids(instances: Iterable[object]) -> list[str]:
    vpc_ids: set[str] = set()
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        vpc_id = instance.get("VpcId")
        if isinstance(vpc_id, str) and vpc_id:
            vpc_ids.add(vpc_id)
    return sorted(vpc_ids)


def extract_snapshot_ids(snapshots: Iterable[object]) -> list[str]:
    snapshot_ids: set[str] = set()
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        snapshot_id = snapshot.get("SnapshotId")
        if isinstance(snapshot_id, str) and snapshot_id:
            snapshot_ids.add(snapshot_id)
    return sorted(snapshot_ids)


def extract_role_names(instance_profile_results: Iterable[CommandResult]) -> list[str]:
    role_names: set[str] = set()
    for result in instance_profile_results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, dict):
            continue
        for role in ensure_list(payload.get("Roles")):
            if not isinstance(role, dict):
                continue
            role_name = role.get("RoleName")
            if isinstance(role_name, str) and role_name:
                role_names.add(role_name)
    return sorted(role_names)


def get_managed_policy_arns(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    arns: set[str] = set()
    if not isinstance(payload, list):
        return []
    for policy in payload:
        if not isinstance(policy, dict):
            continue
        arn = policy.get("PolicyArn")
        if isinstance(arn, str) and arn:
            arns.add(arn)
    return sorted(arns)


def get_inline_policy_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    names: set[str] = set()
    if not isinstance(payload, list):
        return []
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


def iter_allow_statements(policy_document: dict) -> Iterable[dict]:
    statements = ensure_list(policy_document.get("Statement"))
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = statement.get("Effect")
        if effect != "Allow":
            continue
        yield statement


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


def resource_matches(resources: Iterable[str], service_prefix: str) -> bool:
    for resource in resources:
        if resource == "*":
            return True
        if resource.startswith(f"arn:aws:{service_prefix}:"):
            return True
        if service_prefix == "s3" and resource.startswith("arn:aws:s3:::"):
            return True
    return False


def action_matches(actions: Iterable[str], prefixes: tuple[str, ...]) -> bool:
    for action in actions:
        if action == "*":
            return True
        if any(action.startswith(prefix) for prefix in prefixes):
            return True
    return False


def extract_s3_bucket(resource: str) -> str | None:
    prefix = "arn:aws:s3:::"
    if not resource.startswith(prefix):
        return None
    bucket = resource[len(prefix) :].split("/", 1)[0]
    if bucket and bucket != "*":
        return bucket
    return None


def extract_lambda_name(resource: str) -> str | None:
    marker = ":function:"
    if marker not in resource:
        return None
    function_part = resource.split(marker, 1)[1]
    function_name = function_part.split(":", 1)[0]
    if function_name and function_name != "*":
        return function_name
    return None


def extract_secret_identifier(resource: str) -> str | None:
    marker = ":secret:"
    if marker not in resource:
        return None
    secret_part = resource.split(marker, 1)[1]
    if secret_part and secret_part != "*":
        return secret_part
    return None


def derive_dependency_targets(policy_results: Iterable[CommandResult]) -> DependencyTargets:
    bucket_names: set[str] = set()
    lambda_functions: set[str] = set()
    secret_identifiers: set[str] = set()
    has_s3_wildcard = False
    has_lambda_wildcard = False
    has_secret_wildcard = False
    needs_ssm_context = False

    for result in policy_results:
        document = get_policy_document(result)
        if not document:
            continue
        for statement in iter_allow_statements(document):
            actions = ensure_lower_actions(statement.get("Action"))
            resources = ensure_resource_strings(statement.get("Resource"))

            if action_matches(actions, ("s3:",)):
                for resource in resources:
                    if resource == "*" or resource == "arn:aws:s3:::*":
                        has_s3_wildcard = True
                    bucket_name = extract_s3_bucket(resource)
                    if bucket_name:
                        bucket_names.add(bucket_name)

            if action_matches(actions, ("lambda:",)):
                for resource in resources:
                    if resource == "*" or (":function:" in resource and resource.endswith(":*")):
                        has_lambda_wildcard = True
                    function_name = extract_lambda_name(resource)
                    if function_name:
                        lambda_functions.add(function_name)
                if not resources or resource_matches(resources, "lambda"):
                    has_lambda_wildcard = has_lambda_wildcard or "*" in resources

            if action_matches(actions, ("secretsmanager:", "ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath")):
                for resource in resources:
                    if resource == "*":
                        has_secret_wildcard = True
                    secret_identifier = extract_secret_identifier(resource)
                    if secret_identifier:
                        secret_identifiers.add(secret_identifier)
                if any(action.startswith("ssm:") for action in actions):
                    needs_ssm_context = True

            if action_matches(actions, ("ssm:sendcommand", "ssm:startsession", "ssm:startsessions", "ssm:resume", "ssm:")):
                needs_ssm_context = True

            if any(action == "*" for action in actions):
                has_s3_wildcard = True
                has_lambda_wildcard = True
                has_secret_wildcard = True
                needs_ssm_context = True

    return DependencyTargets(
        bucket_names=bucket_names,
        has_s3_wildcard=has_s3_wildcard,
        lambda_functions=lambda_functions,
        has_lambda_wildcard=has_lambda_wildcard,
        secret_identifiers=secret_identifiers,
        has_secret_wildcard=has_secret_wildcard,
        needs_ssm_context=needs_ssm_context,
    )


def collect_primary_ec2(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], list[str], list[str], list[str]]:
    results: list[CommandResult] = []

    instances_result = runner.run(
        ["ec2", "describe-instances", "--query", INSTANCE_QUERY],
        label="describe-instances",
    )
    results.append(instances_result)
    instances = ensure_list(get_parsed_payload(instances_result))
    instance_ids = extract_instance_ids(instances)
    subnet_ids = extract_subnet_ids(instances)
    vpc_ids = extract_vpc_ids(instances)
    instance_profile_names = extract_instance_profile_names(instances)

    results.append(
        runner.run(
            ["ec2", "describe-security-groups", "--query", SECURITY_GROUP_QUERY],
            label="describe-security-groups",
        )
    )
    results.append(
        runner.run(
            ["ec2", "describe-volumes", "--query", VOLUME_QUERY],
            label="describe-volumes",
        )
    )

    snapshots_result = runner.run(
        [
            "ec2",
            "describe-snapshots",
            "--owner-ids",
            "self",
            "--query",
            SNAPSHOT_QUERY,
        ],
        label="describe-snapshots",
    )
    results.append(snapshots_result)
    snapshots = ensure_list(get_parsed_payload(snapshots_result))
    for snapshot_id in extract_snapshot_ids(snapshots):
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-snapshot-attribute",
                    "--snapshot-id",
                    snapshot_id,
                    "--attribute",
                    "createVolumePermission",
                ],
                label=f"describe-snapshot-attribute ({snapshot_id}, createVolumePermission)",
            )
        )

    results.append(
        runner.run(
            ["ec2", "describe-images", "--owners", "self", "--query", IMAGE_QUERY],
            label="describe-images",
        )
    )
    results.append(
        runner.run(
            ["ec2", "describe-key-pairs", "--query", KEY_PAIR_QUERY],
            label="describe-key-pairs",
        )
    )
    results.append(
        runner.run(
            ["ec2", "describe-addresses", "--query", ADDRESS_QUERY],
            label="describe-addresses",
        )
    )
    results.append(
        runner.run(
            [
                "ec2",
                "describe-instances",
                "--query",
                "Reservations[].Instances[].{InstanceId:InstanceId,MetadataOptions:MetadataOptions}",
            ],
            label="describe-instances (metadata-options)",
        )
    )

    for instance_id in instance_ids:
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-instance-attribute",
                    "--instance-id",
                    instance_id,
                    "--attribute",
                    "userData",
                ],
                label=f"describe-instance-attribute ({instance_id}, userData)",
            )
        )
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-instance-attribute",
                    "--instance-id",
                    instance_id,
                    "--attribute",
                    "disableApiTermination",
                ],
                label=f"describe-instance-attribute ({instance_id}, disableApiTermination)",
            )
        )

    return results, instance_ids, subnet_ids, vpc_ids, instance_profile_names


def collect_iam_context(
    runner: AWSCLIRunner, instance_profile_names: Iterable[str]
) -> tuple[list[CommandResult], list[str], list[CommandResult]]:
    results: list[CommandResult] = []
    instance_profile_results: list[CommandResult] = []
    policy_results: list[CommandResult] = []

    for profile_name in sorted(set(instance_profile_names)):
        result = runner.run(
            ["iam", "get-instance-profile", "--instance-profile-name", profile_name, "--query", INSTANCE_PROFILE_QUERY],
            label=f"get-instance-profile ({profile_name})",
            include_region=False,
        )
        results.append(result)
        instance_profile_results.append(result)

    role_names = extract_role_names(instance_profile_results)
    for role_name in role_names:
        results.append(
            runner.run(
                ["iam", "get-role", "--role-name", role_name, "--query", ROLE_QUERY],
                label=f"get-role ({role_name})",
                include_region=False,
            )
        )
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

        for policy_arn in get_managed_policy_arns(attached_result):
            policy_result = runner.run(
                ["iam", "get-policy", "--policy-arn", policy_arn, "--query", MANAGED_POLICY_QUERY],
                label=f"get-policy ({policy_arn})",
                include_region=False,
            )
            results.append(policy_result)
            payload = get_parsed_payload(policy_result)
            version_id = None
            if isinstance(payload, dict):
                candidate = payload.get("DefaultVersionId")
                if isinstance(candidate, str):
                    version_id = candidate
            if version_id:
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
                policy_results.append(version_result)

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
            policy_results.append(policy_result)

    return results, role_names, policy_results


def collect_s3_context(
    runner: AWSCLIRunner, targets: DependencyTargets
) -> list[CommandResult]:
    if not targets.bucket_names and not targets.has_s3_wildcard:
        return []

    results: list[CommandResult] = [
        runner.run(
            ["s3api", "list-buckets", "--query", S3_LIST_QUERY],
            label="list-buckets",
        )
    ]
    for bucket_name in sorted(targets.bucket_names):
        results.append(
            runner.run(
                ["s3api", "get-bucket-acl", "--bucket", bucket_name],
                label=f"get-bucket-acl ({bucket_name})",
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-bucket-policy", "--bucket", bucket_name],
                label=f"get-bucket-policy ({bucket_name})",
            )
        )
        results.append(
            runner.run(
                ["s3api", "get-public-access-block", "--bucket", bucket_name],
                label=f"get-public-access-block ({bucket_name})",
            )
        )
    return results


def collect_lambda_context(
    runner: AWSCLIRunner, targets: DependencyTargets
) -> list[CommandResult]:
    if not targets.lambda_functions and not targets.has_lambda_wildcard:
        return []

    results: list[CommandResult] = []
    if targets.has_lambda_wildcard:
        results.append(
            runner.run(
                ["lambda", "list-functions", "--query", LAMBDA_LIST_QUERY],
                label="list-functions",
            )
        )
    for function_name in sorted(targets.lambda_functions):
        results.append(
            runner.run(
                ["lambda", "get-function", "--function-name", function_name],
                label=f"get-function ({function_name})",
            )
        )
        results.append(
            runner.run(
                ["lambda", "get-policy", "--function-name", function_name],
                label=f"get-policy ({function_name})",
            )
        )
    return results


def collect_secrets_context(
    runner: AWSCLIRunner, targets: DependencyTargets
) -> list[CommandResult]:
    if not targets.secret_identifiers and not targets.has_secret_wildcard:
        return []
    return [
        runner.run(
            ["secretsmanager", "list-secrets", "--query", SECRETS_LIST_QUERY],
            label="list-secrets",
        )
    ]


def collect_ssm_context(
    runner: AWSCLIRunner, instance_ids: Iterable[str]
) -> list[CommandResult]:
    instance_id_list = sorted(set(instance_ids))
    if not instance_id_list:
        return []
    command = [
        "ssm",
        "describe-instance-information",
        "--filters",
        f"Key=InstanceIds,Values={','.join(instance_id_list)}",
        "--query",
        SSM_INFO_QUERY,
    ]
    return [runner.run(command, label="describe-instance-information")]


def collect_vpc_context(
    runner: AWSCLIRunner, subnet_ids: Iterable[str], vpc_ids: Iterable[str]
) -> list[CommandResult]:
    subnet_id_list = sorted(set(subnet_ids))
    vpc_id_list = sorted(set(vpc_ids))
    if not subnet_id_list and not vpc_id_list:
        return []

    results: list[CommandResult] = []
    if subnet_id_list:
        results.append(
            runner.run(
                ["ec2", "describe-subnets", "--subnet-ids", *subnet_id_list, "--query", SUBNET_QUERY],
                label="describe-subnets",
            )
        )
    if vpc_id_list:
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-route-tables",
                    "--filters",
                    f"Name=vpc-id,Values={','.join(vpc_id_list)}",
                    "--query",
                    ROUTE_TABLE_QUERY,
                ],
                label="describe-route-tables",
            )
        )
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-internet-gateways",
                    "--filters",
                    f"Name=attachment.vpc-id,Values={','.join(vpc_id_list)}",
                    "--query",
                    INTERNET_GATEWAY_QUERY,
                ],
                label="describe-internet-gateways",
            )
        )
    return results


def build_scan_output(args: argparse.Namespace) -> str:
    runner = AWSCLIRunner(
        region=args.region,
        profile=args.profile,
        timeout_seconds=args.timeout_seconds,
        should_cancel=getattr(args, "should_cancel", None),
    )

    primary_results, instance_ids, subnet_ids, vpc_ids, instance_profile_names = collect_primary_ec2(
        runner
    )

    iam_results, _, policy_results = collect_iam_context(runner, instance_profile_names)
    dependency_targets = derive_dependency_targets(policy_results)

    sections = [
        render_section("PRIMARY SERVICE: EC2", primary_results),
        render_section("DEPENDENCY CONTEXT: IAM", iam_results),
        render_section("DEPENDENCY CONTEXT: S3", collect_s3_context(runner, dependency_targets)),
        render_section(
            "DEPENDENCY CONTEXT: LAMBDA",
            collect_lambda_context(runner, dependency_targets),
        ),
        render_section(
            "DEPENDENCY CONTEXT: SECRETS_MANAGER",
            collect_secrets_context(runner, dependency_targets),
        ),
        render_section(
            "DEPENDENCY CONTEXT: SSM",
            collect_ssm_context(runner, instance_ids),
        ),
        render_section(
            "DEPENDENCY CONTEXT: VPC",
            collect_vpc_context(runner, subnet_ids, vpc_ids),
        ),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
