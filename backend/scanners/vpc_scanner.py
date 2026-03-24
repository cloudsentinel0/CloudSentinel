from __future__ import annotations

import argparse
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


VPC_QUERY = "Vpcs[].{VpcId:VpcId,CidrBlock:CidrBlock,IsDefault:IsDefault,State:State,Tags:Tags}"
SUBNET_QUERY = (
    "Subnets[].{"
    "SubnetId:SubnetId,"
    "VpcId:VpcId,"
    "AvailabilityZone:AvailabilityZone,"
    "CidrBlock:CidrBlock,"
    "Ipv6CidrBlockAssociationSet:Ipv6CidrBlockAssociationSet,"
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
NACL_QUERY = (
    "NetworkAcls[].{"
    "NetworkAclId:NetworkAclId,"
    "VpcId:VpcId,"
    "Associations:Associations[].{SubnetId:SubnetId,NetworkAclAssociationId:NetworkAclAssociationId},"
    "Entries:Entries,"
    "IsDefault:IsDefault,"
    "Tags:Tags"
    "}"
)
IGW_QUERY = (
    "InternetGateways[].{"
    "InternetGatewayId:InternetGatewayId,"
    "Attachments:Attachments,"
    "Tags:Tags"
    "}"
)
NAT_QUERY = (
    "NatGateways[].{"
    "NatGatewayId:NatGatewayId,"
    "VpcId:VpcId,"
    "SubnetId:SubnetId,"
    "State:State,"
    "ConnectivityType:ConnectivityType,"
    "NatGatewayAddresses:NatGatewayAddresses,"
    "Tags:Tags"
    "}"
)
VPC_ENDPOINTS_QUERY = (
    "VpcEndpoints[].{"
    "VpcEndpointId:VpcEndpointId,"
    "VpcId:VpcId,"
    "ServiceName:ServiceName,"
    "VpcEndpointType:VpcEndpointType,"
    "State:State,"
    "RouteTableIds:RouteTableIds,"
    "SubnetIds:SubnetIds,"
    "Groups:Groups,"
    "PrivateDnsEnabled:PrivateDnsEnabled,"
    "PolicyDocument:PolicyDocument,"
    "Tags:Tags"
    "}"
)
PEERING_QUERY = (
    "VpcPeeringConnections[].{"
    "VpcPeeringConnectionId:VpcPeeringConnectionId,"
    "Status:Status,"
    "RequesterVpcInfo:RequesterVpcInfo,"
    "AccepterVpcInfo:AccepterVpcInfo,"
    "Tags:Tags"
    "}"
)
FLOW_LOGS_QUERY = (
    "FlowLogs[].{"
    "FlowLogId:FlowLogId,"
    "ResourceId:ResourceId,"
    "ResourceType:ResourceType,"
    "TrafficType:TrafficType,"
    "LogDestinationType:LogDestinationType,"
    "LogDestination:LogDestination,"
    "DeliverLogsStatus:DeliverLogsStatus,"
    "Tags:Tags"
    "}"
)
EGRESS_ONLY_IGW_QUERY = (
    "EgressOnlyInternetGateways[].{"
    "EgressOnlyInternetGatewayId:EgressOnlyInternetGatewayId,"
    "Attachments:Attachments,"
    "Tags:Tags"
    "}"
)
TGW_ATTACHMENTS_QUERY = (
    "TransitGatewayAttachments[].{"
    "TransitGatewayAttachmentId:TransitGatewayAttachmentId,"
    "TransitGatewayId:TransitGatewayId,"
    "ResourceId:ResourceId,"
    "ResourceType:ResourceType,"
    "State:State,"
    "Association:Association,"
    "Tags:Tags"
    "}"
)
VPCE_SERVICE_QUERY = (
    "ServiceDetails[].{"
    "ServiceName:ServiceName,"
    "Owner:Owner,"
    "ServiceType:ServiceType,"
    "AcceptanceRequired:AcceptanceRequired,"
    "AvailabilityZones:AvailabilityZones,"
    "VpcEndpointPolicySupported:VpcEndpointPolicySupported,"
    "BaseEndpointDnsNames:BaseEndpointDnsNames"
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
    "Ipv6Address:NetworkInterfaces[].Ipv6Addresses[].Ipv6Address | [0],"
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
NETWORK_INTERFACE_QUERY = (
    "NetworkInterfaces[].{"
    "NetworkInterfaceId:NetworkInterfaceId,"
    "Status:Status,"
    "VpcId:VpcId,"
    "SubnetId:SubnetId,"
    "PrivateIpAddress:PrivateIpAddress,"
    "Association:Association,"
    "Attachment:Attachment,"
    "Groups:Groups,"
    "Ipv6Addresses:Ipv6Addresses,"
    "InterfaceType:InterfaceType,"
    "TagSet:TagSet"
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
RDS_QUERY = (
    "DBInstances[].{"
    "DBInstanceIdentifier:DBInstanceIdentifier,"
    "DBInstanceArn:DBInstanceArn,"
    "Engine:Engine,"
    "EngineVersion:EngineVersion,"
    "PubliclyAccessible:PubliclyAccessible,"
    "DBSubnetGroup:DBSubnetGroup,"
    "VpcSecurityGroups:VpcSecurityGroups,"
    "AvailabilityZone:AvailabilityZone,"
    "MultiAZ:MultiAZ,"
    "StorageEncrypted:StorageEncrypted,"
    "TagList:TagList"
    "}"
)
ELBV2_QUERY = (
    "LoadBalancers[].{"
    "LoadBalancerArn:LoadBalancerArn,"
    "LoadBalancerName:LoadBalancerName,"
    "Scheme:Scheme,"
    "Type:Type,"
    "VpcId:VpcId,"
    "AvailabilityZones:AvailabilityZones,"
    "SecurityGroups:SecurityGroups,"
    "State:State"
    "}"
)
CLASSIC_ELB_QUERY = (
    "LoadBalancerDescriptions[].{"
    "LoadBalancerName:LoadBalancerName,"
    "Scheme:Scheme,"
    "VPCId:VPCId,"
    "Subnets:Subnets,"
    "SecurityGroups:SecurityGroups,"
    "Instances:Instances"
    "}"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect VPC-centered AWS CLI evidence for CloudSentinel."
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


def extract_profile_names(instance_result: CommandResult) -> list[str]:
    payload = get_parsed_payload(instance_result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for instance in payload:
        if not isinstance(instance, dict):
            continue
        arn = instance.get("IamInstanceProfile")
        if isinstance(arn, str) and arn:
            names.add(arn.rsplit("/", 1)[-1])
    return sorted(names)


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
        roles = item.get("Roles")
        if not isinstance(roles, list):
            continue
        for role in roles:
            if not isinstance(role, dict):
                continue
            role_name = role.get("RoleName")
            if isinstance(role_name, str) and role_name:
                role_names.add(role_name)
    return sorted(role_names)


def collect_primary_vpc(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(["ec2", "describe-vpcs", "--query", VPC_QUERY], label="describe-vpcs"),
        runner.run(["ec2", "describe-subnets", "--query", SUBNET_QUERY], label="describe-subnets"),
        runner.run(["ec2", "describe-route-tables", "--query", ROUTE_TABLE_QUERY], label="describe-route-tables"),
        runner.run(["ec2", "describe-network-acls", "--query", NACL_QUERY], label="describe-network-acls"),
        runner.run(
            ["ec2", "describe-internet-gateways", "--query", IGW_QUERY],
            label="describe-internet-gateways",
        ),
        runner.run(["ec2", "describe-nat-gateways", "--query", NAT_QUERY], label="describe-nat-gateways"),
        runner.run(
            ["ec2", "describe-vpc-endpoints", "--query", VPC_ENDPOINTS_QUERY],
            label="describe-vpc-endpoints",
        ),
        runner.run(
            ["ec2", "describe-vpc-peering-connections", "--query", PEERING_QUERY],
            label="describe-vpc-peering-connections",
        ),
        runner.run(["ec2", "describe-flow-logs", "--query", FLOW_LOGS_QUERY], label="describe-flow-logs"),
        runner.run(
            ["ec2", "describe-egress-only-internet-gateways", "--query", EGRESS_ONLY_IGW_QUERY],
            label="describe-egress-only-internet-gateways",
        ),
        runner.run(
            ["ec2", "describe-transit-gateway-attachments", "--query", TGW_ATTACHMENTS_QUERY],
            label="describe-transit-gateway-attachments",
        ),
        runner.run(
            ["ec2", "describe-vpc-endpoint-services", "--query", VPCE_SERVICE_QUERY],
            label="describe-vpc-endpoint-services",
        ),
    ]


def collect_ec2_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(["ec2", "describe-instances", "--query", EC2_INSTANCE_QUERY], label="describe-instances"),
        runner.run(
            ["ec2", "describe-security-groups", "--query", SECURITY_GROUP_QUERY],
            label="describe-security-groups",
        ),
        runner.run(
            ["ec2", "describe-network-interfaces", "--query", NETWORK_INTERFACE_QUERY],
            label="describe-network-interfaces",
        ),
    ]


def collect_iam_context(runner: AWSCLIRunner, ec2_results: list[CommandResult]) -> list[CommandResult]:
    instance_result = ec2_results[0]
    profile_names = set(extract_profile_names(instance_result))

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

    return results


def collect_rds_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["rds", "describe-db-instances", "--query", RDS_QUERY],
            label="describe-db-instances",
        )
    ]


def collect_elb_context(runner: AWSCLIRunner) -> list[CommandResult]:
    return [
        runner.run(
            ["elbv2", "describe-load-balancers", "--query", ELBV2_QUERY],
            label="describe-load-balancers (elbv2)",
        ),
        runner.run(
            ["elb", "describe-load-balancers", "--query", CLASSIC_ELB_QUERY],
            label="describe-load-balancers (classic)",
        ),
    ]


def build_scan_output(args: argparse.Namespace) -> str:
    runner = AWSCLIRunner(
        region=args.region,
        profile=args.profile,
        timeout_seconds=args.timeout_seconds,
        should_cancel=getattr(args, "should_cancel", None),
    )

    primary_results = collect_primary_vpc(runner)
    ec2_results = collect_ec2_context(runner)

    sections = [
        render_section("PRIMARY SERVICE: VPC", primary_results),
        render_section("DEPENDENCY CONTEXT: EC2", ec2_results),
        render_section("DEPENDENCY CONTEXT: IAM", collect_iam_context(runner, ec2_results)),
        render_section("DEPENDENCY CONTEXT: RDS", collect_rds_context(runner)),
        render_section("DEPENDENCY CONTEXT: ELB", collect_elb_context(runner)),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
