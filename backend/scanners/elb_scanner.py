from __future__ import annotations

import argparse
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


ELBV2_LOAD_BALANCERS_QUERY = (
    "LoadBalancers[].{"
    "LoadBalancerArn:LoadBalancerArn,"
    "LoadBalancerName:LoadBalancerName,"
    "DNSName:DNSName,"
    "Scheme:Scheme,"
    "Type:Type,"
    "VpcId:VpcId,"
    "IpAddressType:IpAddressType,"
    "State:State.Code,"
    "SecurityGroups:SecurityGroups,"
    "AvailabilityZones:AvailabilityZones[].{ZoneName:ZoneName,SubnetId:SubnetId,LoadBalancerAddresses:LoadBalancerAddresses},"
    "CreatedTime:CreatedTime"
    "}"
)

ELBV2_LISTENERS_QUERY = (
    "Listeners[].{"
    "ListenerArn:ListenerArn,"
    "LoadBalancerArn:LoadBalancerArn,"
    "Port:Port,"
    "Protocol:Protocol,"
    "SslPolicy:SslPolicy,"
    "Certificates:Certificates,"
    "DefaultActions:DefaultActions,"
    "AlpnPolicy:AlpnPolicy,"
    "MutualAuthentication:MutualAuthentication"
    "}"
)

ELBV2_RULES_QUERY = (
    "Rules[].{"
    "RuleArn:RuleArn,"
    "Priority:Priority,"
    "Conditions:Conditions,"
    "Actions:Actions,"
    "IsDefault:IsDefault"
    "}"
)

ELBV2_TARGET_GROUPS_QUERY = (
    "TargetGroups[].{"
    "TargetGroupArn:TargetGroupArn,"
    "TargetGroupName:TargetGroupName,"
    "Protocol:Protocol,"
    "Port:Port,"
    "VpcId:VpcId,"
    "TargetType:TargetType,"
    "HealthCheckProtocol:HealthCheckProtocol,"
    "HealthCheckPort:HealthCheckPort,"
    "HealthCheckPath:HealthCheckPath,"
    "Matcher:Matcher,"
    "LoadBalancerArns:LoadBalancerArns"
    "}"
)

ELBV2_TARGET_HEALTH_QUERY = (
    "TargetHealthDescriptions[].{"
    "Target:Target,"
    "HealthCheckPort:HealthCheckPort,"
    "TargetHealth:TargetHealth"
    "}"
)

ELBV2_ATTRIBUTES_QUERY = "Attributes[].{Key:Key,Value:Value}"
ELBV2_TAGS_QUERY = "TagDescriptions[].{ResourceArn:ResourceArn,Tags:Tags}"

CLASSIC_ELB_QUERY = (
    "LoadBalancerDescriptions[].{"
    "LoadBalancerName:LoadBalancerName,"
    "DNSName:DNSName,"
    "Scheme:Scheme,"
    "VPCId:VPCId,"
    "Subnets:Subnets,"
    "AvailabilityZones:AvailabilityZones,"
    "SecurityGroups:SecurityGroups,"
    "Instances:Instances,"
    "ListenerDescriptions:ListenerDescriptions[].{Listener:Listener,PolicyNames:PolicyNames},"
    "HealthCheck:HealthCheck,"
    "CreatedTime:CreatedTime"
    "}"
)

CLASSIC_ELB_ATTRIBUTES_QUERY = "LoadBalancerAttributes"
CLASSIC_ELB_POLICIES_QUERY = (
    "PolicyDescriptions[].{"
    "PolicyName:PolicyName,"
    "PolicyTypeName:PolicyTypeName,"
    "PolicyAttributeDescriptions:PolicyAttributeDescriptions"
    "}"
)

CLASSIC_ELB_TAGS_QUERY = "TagDescriptions[].{LoadBalancerName:LoadBalancerName,Tags:Tags}"

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

INSTANCE_QUERY = (
    "Reservations[].Instances[].{"
    "InstanceId:InstanceId,"
    "ImageId:ImageId,"
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

CERTIFICATE_QUERY = (
    "{"
    "CertificateArn:Certificate.CertificateArn,"
    "DomainName:Certificate.DomainName,"
    "Status:Certificate.Status,"
    "Type:Certificate.Type,"
    "KeyAlgorithm:Certificate.KeyAlgorithm,"
    "InUseBy:Certificate.InUseBy,"
    "NotBefore:Certificate.NotBefore,"
    "NotAfter:Certificate.NotAfter"
    "}"
)

INSTANCE_PROFILES_QUERY = (
    "InstanceProfiles[].{"
    "InstanceProfileName:InstanceProfileName,"
    "Arn:Arn,"
    "Roles:Roles[].{RoleName:RoleName,Arn:Arn}"
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

ATTACHED_ROLE_POLICIES_QUERY = "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect ELB-centered AWS CLI evidence for CloudSentinel."
    )
    parser.add_argument("--region", required=True, help="AWS region to scan.")
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


def chunked(values: Iterable[str], size: int) -> list[list[str]]:
    items = [value for value in values if value]
    return [items[index:index + size] for index in range(0, len(items), size)]


def extract_load_balancer_arns(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    arns: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        arn = item.get("LoadBalancerArn")
        if isinstance(arn, str) and arn:
            arns.add(arn)
    return sorted(arns)


def extract_application_load_balancer_arns(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    arns: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        lb_type = item.get("Type")
        arn = item.get("LoadBalancerArn")
        if lb_type == "application" and isinstance(arn, str) and arn:
            arns.add(arn)
    return sorted(arns)


def extract_vpc_ids(*results: CommandResult) -> list[str]:
    vpc_ids: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            vpc_id = item.get("VpcId")
            if not isinstance(vpc_id, str):
                vpc_id = item.get("VPCId")
            if isinstance(vpc_id, str) and vpc_id:
                vpc_ids.add(vpc_id)
    return sorted(vpc_ids)


def extract_subnet_ids(*results: CommandResult) -> list[str]:
    subnet_ids: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            for availability_zone in ensure_list(item.get("AvailabilityZones")):
                if not isinstance(availability_zone, dict):
                    continue
                subnet_id = availability_zone.get("SubnetId")
                if isinstance(subnet_id, str) and subnet_id:
                    subnet_ids.add(subnet_id)
            for subnet_id in ensure_list(item.get("Subnets")):
                if isinstance(subnet_id, str) and subnet_id:
                    subnet_ids.add(subnet_id)
    return sorted(subnet_ids)


def extract_listener_arns(*listener_results: CommandResult) -> list[str]:
    listener_arns: set[str] = set()
    for result in listener_results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for listener in payload:
            if not isinstance(listener, dict):
                continue
            listener_arn = listener.get("ListenerArn")
            if isinstance(listener_arn, str) and listener_arn:
                listener_arns.add(listener_arn)
    return sorted(listener_arns)


def extract_certificate_arns(*listener_results: CommandResult) -> list[str]:
    certificate_arns: set[str] = set()
    for result in listener_results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for listener in payload:
            if not isinstance(listener, dict):
                continue
            for certificate in ensure_list(listener.get("Certificates")):
                if not isinstance(certificate, dict):
                    continue
                certificate_arn = certificate.get("CertificateArn")
                if isinstance(certificate_arn, str) and certificate_arn:
                    certificate_arns.add(certificate_arn)
    return sorted(certificate_arns)


def extract_target_group_arns(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    target_group_arns: set[str] = set()
    for target_group in payload:
        if not isinstance(target_group, dict):
            continue
        arn = target_group.get("TargetGroupArn")
        if isinstance(arn, str) and arn:
            target_group_arns.add(arn)
    return sorted(target_group_arns)


def extract_target_instance_ids(*results: CommandResult) -> list[str]:
    instance_ids: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            for instance in ensure_list(item.get("Instances")):
                if not isinstance(instance, dict):
                    continue
                instance_id = instance.get("InstanceId")
                if isinstance(instance_id, str) and instance_id:
                    instance_ids.add(instance_id)
            target = item.get("Target")
            if isinstance(target, dict):
                target_id = target.get("Id")
                if isinstance(target_id, str) and target_id.startswith("i-"):
                    instance_ids.add(target_id)
    return sorted(instance_ids)


def extract_classic_load_balancer_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("LoadBalancerName")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def extract_classic_policy_names_per_lb(result: CommandResult) -> dict[str, list[str]]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return {}
    policies_per_lb: dict[str, set[str]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        lb_name = item.get("LoadBalancerName")
        if not isinstance(lb_name, str) or not lb_name:
            continue
        policy_set = policies_per_lb.setdefault(lb_name, set())
        for listener_description in ensure_list(item.get("ListenerDescriptions")):
            if not isinstance(listener_description, dict):
                continue
            for policy_name in ensure_list(listener_description.get("PolicyNames")):
                if isinstance(policy_name, str) and policy_name:
                    policy_set.add(policy_name)
    return {lb_name: sorted(policy_names) for lb_name, policy_names in policies_per_lb.items()}


def extract_profile_names(instance_results: Iterable[CommandResult]) -> list[str]:
    profile_names: set[str] = set()
    for result in instance_results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for instance in payload:
            if not isinstance(instance, dict):
                continue
            arn = instance.get("IamInstanceProfile")
            if isinstance(arn, str) and arn:
                profile_names.add(arn.rsplit("/", 1)[-1])
    return sorted(profile_names)


def extract_attached_role_names(instance_profiles_result: CommandResult, profile_names: set[str]) -> list[str]:
    payload = get_parsed_payload(instance_profiles_result)
    if not isinstance(payload, list):
        return []
    role_names: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        profile_name = item.get("InstanceProfileName")
        if not isinstance(profile_name, str) or profile_name not in profile_names:
            continue
        for role in ensure_list(item.get("Roles")):
            if not isinstance(role, dict):
                continue
            role_name = role.get("RoleName")
            if isinstance(role_name, str) and role_name:
                role_names.add(role_name)
    return sorted(role_names)


def get_managed_policy_arns(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    policy_arns: set[str] = set()
    for policy in payload:
        if not isinstance(policy, dict):
            continue
        policy_arn = policy.get("PolicyArn")
        if isinstance(policy_arn, str) and policy_arn:
            policy_arns.add(policy_arn)
    return sorted(policy_arns)


def get_inline_policy_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    policy_names: set[str] = set()
    for policy_name in payload:
        if isinstance(policy_name, str) and policy_name:
            policy_names.add(policy_name)
    return sorted(policy_names)


def collect_primary_elb(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], list[str], list[str], list[str], list[str], list[CommandResult]]:
    results: list[CommandResult] = []

    elbv2_result = runner.run(
        ["elbv2", "describe-load-balancers", "--query", ELBV2_LOAD_BALANCERS_QUERY],
        label="describe-load-balancers (elbv2)",
    )
    classic_result = runner.run(
        ["elb", "describe-load-balancers", "--query", CLASSIC_ELB_QUERY],
        label="describe-load-balancers (classic)",
    )
    results.extend([elbv2_result, classic_result])

    load_balancer_arns = extract_load_balancer_arns(elbv2_result)
    application_lb_arns = set(extract_application_load_balancer_arns(elbv2_result))

    listener_results: list[CommandResult] = []
    for load_balancer_arn in load_balancer_arns:
        listener_result = runner.run(
            ["elbv2", "describe-listeners", "--load-balancer-arn", load_balancer_arn, "--query", ELBV2_LISTENERS_QUERY],
            label=f"describe-listeners ({load_balancer_arn})",
        )
        results.append(listener_result)
        listener_results.append(listener_result)

    for listener_result in listener_results:
        payload = get_parsed_payload(listener_result)
        if not isinstance(payload, list):
            continue
        for listener in payload:
            if not isinstance(listener, dict):
                continue
            load_balancer_arn = listener.get("LoadBalancerArn")
            listener_arn = listener.get("ListenerArn")
            if (
                isinstance(load_balancer_arn, str)
                and load_balancer_arn in application_lb_arns
                and isinstance(listener_arn, str)
                and listener_arn
            ):
                results.append(
                    runner.run(
                        ["elbv2", "describe-rules", "--listener-arn", listener_arn, "--query", ELBV2_RULES_QUERY],
                        label=f"describe-rules ({listener_arn})",
                    )
                )

    target_groups_result = runner.run(
        ["elbv2", "describe-target-groups", "--query", ELBV2_TARGET_GROUPS_QUERY],
        label="describe-target-groups",
    )
    results.append(target_groups_result)
    target_group_arns = extract_target_group_arns(target_groups_result)

    target_health_results: list[CommandResult] = []
    for target_group_arn in target_group_arns:
        results.append(
            runner.run(
                ["elbv2", "describe-target-group-attributes", "--target-group-arn", target_group_arn, "--query", ELBV2_ATTRIBUTES_QUERY],
                label=f"describe-target-group-attributes ({target_group_arn})",
            )
        )
        target_health_result = runner.run(
            ["elbv2", "describe-target-health", "--target-group-arn", target_group_arn, "--query", ELBV2_TARGET_HEALTH_QUERY],
            label=f"describe-target-health ({target_group_arn})",
        )
        results.append(target_health_result)
        target_health_results.append(target_health_result)

    for load_balancer_arn in load_balancer_arns:
        results.append(
            runner.run(
                ["elbv2", "describe-load-balancer-attributes", "--load-balancer-arn", load_balancer_arn, "--query", ELBV2_ATTRIBUTES_QUERY],
                label=f"describe-load-balancer-attributes ({load_balancer_arn})",
            )
        )

    for index, arn_chunk in enumerate(chunked(load_balancer_arns, 20), start=1):
        label = "describe-tags (elbv2 load balancers)" if index == 1 else f"describe-tags (elbv2 load balancers batch {index})"
        results.append(
            runner.run(
                ["elbv2", "describe-tags", "--resource-arns", *arn_chunk, "--query", ELBV2_TAGS_QUERY],
                label=label,
            )
        )

    for index, arn_chunk in enumerate(chunked(target_group_arns, 20), start=1):
        label = "describe-tags (elbv2 target groups)" if index == 1 else f"describe-tags (elbv2 target groups batch {index})"
        results.append(
            runner.run(
                ["elbv2", "describe-tags", "--resource-arns", *arn_chunk, "--query", ELBV2_TAGS_QUERY],
                label=label,
            )
        )

    classic_load_balancer_names = extract_classic_load_balancer_names(classic_result)
    classic_policy_names = extract_classic_policy_names_per_lb(classic_result)
    for load_balancer_name in classic_load_balancer_names:
        results.append(
            runner.run(
                ["elb", "describe-load-balancer-attributes", "--load-balancer-name", load_balancer_name, "--query", CLASSIC_ELB_ATTRIBUTES_QUERY],
                label=f"describe-load-balancer-attributes ({load_balancer_name})",
            )
        )
        policy_names = classic_policy_names.get(load_balancer_name, [])
        if policy_names:
            results.append(
                runner.run(
                    [
                        "elb",
                        "describe-load-balancer-policies",
                        "--load-balancer-name",
                        load_balancer_name,
                        "--policy-names",
                        *policy_names,
                        "--query",
                        CLASSIC_ELB_POLICIES_QUERY,
                    ],
                    label=f"describe-load-balancer-policies ({load_balancer_name})",
                )
            )

    for index, name_chunk in enumerate(chunked(classic_load_balancer_names, 20), start=1):
        label = "describe-tags (classic)" if index == 1 else f"describe-tags (classic batch {index})"
        results.append(
            runner.run(
                ["elb", "describe-tags", "--load-balancer-names", *name_chunk, "--query", CLASSIC_ELB_TAGS_QUERY],
                label=label,
            )
        )

    vpc_ids = extract_vpc_ids(elbv2_result, classic_result, target_groups_result)
    subnet_ids = extract_subnet_ids(elbv2_result, classic_result)
    certificate_arns = extract_certificate_arns(*listener_results)
    target_instance_ids = extract_target_instance_ids(classic_result, *target_health_results)

    return (
        results,
        vpc_ids,
        subnet_ids,
        target_instance_ids,
        sorted(application_lb_arns),
        certificate_arns,
        target_health_results,
    )


def collect_ec2_context(
    runner: AWSCLIRunner,
    *,
    vpc_ids: Iterable[str],
    subnet_ids: Iterable[str],
    target_instance_ids: Iterable[str],
) -> list[CommandResult]:
    results: list[CommandResult] = []
    vpc_id_list = sorted(set(vpc_ids))
    subnet_id_list = sorted(set(subnet_ids))
    instance_id_list = sorted(set(target_instance_ids))

    if vpc_id_list:
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-security-groups",
                    "--filters",
                    f"Name=vpc-id,Values={','.join(vpc_id_list)}",
                    "--query",
                    SECURITY_GROUP_QUERY,
                ],
                label="describe-security-groups",
            )
        )
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

    for index, subnet_chunk in enumerate(chunked(subnet_id_list, 100), start=1):
        label = "describe-subnets" if index == 1 else f"describe-subnets (batch {index})"
        results.append(
            runner.run(
                ["ec2", "describe-subnets", "--subnet-ids", *subnet_chunk, "--query", SUBNET_QUERY],
                label=label,
            )
        )

    for index, instance_chunk in enumerate(chunked(instance_id_list, 100), start=1):
        label = "describe-instances" if index == 1 else f"describe-instances (batch {index})"
        results.append(
            runner.run(
                ["ec2", "describe-instances", "--instance-ids", *instance_chunk, "--query", INSTANCE_QUERY],
                label=label,
            )
        )

    return results


def collect_wafv2_context(
    runner: AWSCLIRunner, application_lb_arns: Iterable[str]
) -> list[CommandResult]:
    results: list[CommandResult] = []
    for load_balancer_arn in sorted(set(application_lb_arns)):
        results.append(
            runner.run(
                ["wafv2", "get-web-acl-for-resource", "--resource-arn", load_balancer_arn],
                label=f"get-web-acl-for-resource ({load_balancer_arn})",
            )
        )
    return results


def collect_acm_context(
    runner: AWSCLIRunner, certificate_arns: Iterable[str]
) -> list[CommandResult]:
    results: list[CommandResult] = []
    for certificate_arn in sorted(set(certificate_arns)):
        results.append(
            runner.run(
                ["acm", "describe-certificate", "--certificate-arn", certificate_arn, "--query", CERTIFICATE_QUERY],
                label=f"describe-certificate ({certificate_arn})",
            )
        )
    return results


def collect_iam_context(
    runner: AWSCLIRunner, ec2_results: list[CommandResult]
) -> list[CommandResult]:
    profile_names = set(extract_profile_names(ec2_results))
    if not profile_names:
        return []

    instance_profiles_result = runner.run(
        ["iam", "list-instance-profiles", "--query", INSTANCE_PROFILES_QUERY],
        label="list-instance-profiles",
        include_region=False,
    )
    results: list[CommandResult] = [instance_profiles_result]

    for role_name in extract_attached_role_names(instance_profiles_result, profile_names):
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
            if not isinstance(payload, dict):
                continue
            version_id = payload.get("DefaultVersionId")
            if not isinstance(version_id, str) or not version_id:
                continue
            results.append(
                runner.run(
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
            )

        for policy_name in get_inline_policy_names(inline_result):
            results.append(
                runner.run(
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
            )

    return results


def build_scan_output(args: argparse.Namespace) -> str:
    runner = AWSCLIRunner(
        region=args.region,
        profile=args.profile,
        timeout_seconds=args.timeout_seconds,
        should_cancel=getattr(args, "should_cancel", None),
    )

    (
        primary_results,
        vpc_ids,
        subnet_ids,
        target_instance_ids,
        application_lb_arns,
        certificate_arns,
        _,
    ) = collect_primary_elb(runner)

    ec2_results = collect_ec2_context(
        runner,
        vpc_ids=vpc_ids,
        subnet_ids=subnet_ids,
        target_instance_ids=target_instance_ids,
    )

    sections = [
        render_section("PRIMARY SERVICE: ELB", primary_results),
        render_section("DEPENDENCY CONTEXT: EC2", ec2_results),
        render_section(
            "DEPENDENCY CONTEXT: WAFV2",
            collect_wafv2_context(runner, application_lb_arns),
        ),
        render_section(
            "DEPENDENCY CONTEXT: ACM",
            collect_acm_context(runner, certificate_arns),
        ),
        render_section(
            "DEPENDENCY CONTEXT: IAM",
            collect_iam_context(runner, ec2_results),
        ),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
