from __future__ import annotations

import argparse
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


DB_INSTANCES_QUERY = (
    "DBInstances[].{"
    "DBInstanceIdentifier:DBInstanceIdentifier,"
    "DBInstanceArn:DBInstanceArn,"
    "Engine:Engine,"
    "EngineVersion:EngineVersion,"
    "DBInstanceClass:DBInstanceClass,"
    "Endpoint:{Address:Endpoint.Address,Port:Endpoint.Port,HostedZoneId:Endpoint.HostedZoneId},"
    "DBSubnetGroup:{"
    "DBSubnetGroupName:DBSubnetGroup.DBSubnetGroupName,"
    "VpcId:DBSubnetGroup.VpcId,"
    "Subnets:DBSubnetGroup.Subnets[].{SubnetIdentifier:SubnetIdentifier,SubnetAvailabilityZone:SubnetAvailabilityZone.Name,SubnetStatus:SubnetStatus}"
    "},"
    "VpcSecurityGroups:VpcSecurityGroups[].{VpcSecurityGroupId:VpcSecurityGroupId,Status:Status},"
    "PubliclyAccessible:PubliclyAccessible,"
    "StorageEncrypted:StorageEncrypted,"
    "KmsKeyId:KmsKeyId,"
    "BackupRetentionPeriod:BackupRetentionPeriod,"
    "DeletionProtection:DeletionProtection,"
    "EnabledCloudwatchLogsExports:EnabledCloudwatchLogsExports,"
    "DBParameterGroups:DBParameterGroups[].{DBParameterGroupName:DBParameterGroupName,ParameterApplyStatus:ParameterApplyStatus},"
    "IAMDatabaseAuthenticationEnabled:IAMDatabaseAuthenticationEnabled,"
    "CACertificateIdentifier:CACertificateIdentifier,"
    "ManageMasterUserPassword:ManageMasterUserPassword,"
    "MasterUserSecret:MasterUserSecret,"
    "AssociatedRoles:AssociatedRoles,"
    "TagList:TagList"
    "}"
)

DB_CLUSTERS_QUERY = (
    "DBClusters[].{"
    "DBClusterIdentifier:DBClusterIdentifier,"
    "DBClusterArn:DBClusterArn,"
    "Engine:Engine,"
    "EngineVersion:EngineVersion,"
    "Endpoint:Endpoint,"
    "ReaderEndpoint:ReaderEndpoint,"
    "Port:Port,"
    "DBSubnetGroup:DBSubnetGroup,"
    "VpcSecurityGroups:VpcSecurityGroups[].{VpcSecurityGroupId:VpcSecurityGroupId,Status:Status},"
    "StorageEncrypted:StorageEncrypted,"
    "KmsKeyId:KmsKeyId,"
    "BackupRetentionPeriod:BackupRetentionPeriod,"
    "DeletionProtection:DeletionProtection,"
    "EnabledCloudwatchLogsExports:EnabledCloudwatchLogsExports,"
    "DBClusterParameterGroup:DBClusterParameterGroup,"
    "IAMDatabaseAuthenticationEnabled:IAMDatabaseAuthenticationEnabled,"
    "ManageMasterUserPassword:ManageMasterUserPassword,"
    "MasterUserSecret:MasterUserSecret,"
    "AssociatedRoles:AssociatedRoles,"
    "TagList:TagList"
    "}"
)

DB_SUBNET_GROUPS_QUERY = (
    "DBSubnetGroups[].{"
    "DBSubnetGroupName:DBSubnetGroupName,"
    "DBSubnetGroupDescription:DBSubnetGroupDescription,"
    "VpcId:VpcId,"
    "Subnets:Subnets[].{SubnetIdentifier:SubnetIdentifier,SubnetAvailabilityZone:SubnetAvailabilityZone.Name,SubnetStatus:SubnetStatus},"
    "DBSubnetGroupArn:DBSubnetGroupArn"
    "}"
)

DB_SNAPSHOTS_QUERY = (
    "DBSnapshots[].{"
    "DBSnapshotIdentifier:DBSnapshotIdentifier,"
    "DBSnapshotArn:DBSnapshotArn,"
    "DBInstanceIdentifier:DBInstanceIdentifier,"
    "SnapshotType:SnapshotType,"
    "Status:Status,"
    "Engine:Engine,"
    "EngineVersion:EngineVersion,"
    "Encrypted:Encrypted,"
    "KmsKeyId:KmsKeyId,"
    "PercentProgress:PercentProgress,"
    "TagList:TagList"
    "}"
)

DB_CLUSTER_SNAPSHOTS_QUERY = (
    "DBClusterSnapshots[].{"
    "DBClusterSnapshotIdentifier:DBClusterSnapshotIdentifier,"
    "DBClusterSnapshotArn:DBClusterSnapshotArn,"
    "DBClusterIdentifier:DBClusterIdentifier,"
    "SnapshotType:SnapshotType,"
    "Status:Status,"
    "Engine:Engine,"
    "EngineVersion:EngineVersion,"
    "StorageEncrypted:StorageEncrypted,"
    "KmsKeyId:KmsKeyId,"
    "PercentProgress:PercentProgress,"
    "TagList:TagList"
    "}"
)

SECURITY_RELEVANT_DB_PARAMETERS_QUERY = (
    "Parameters[?"
    "ParameterName=='rds.force_ssl' || "
    "ParameterName=='require_secure_transport' || "
    "ParameterName=='log_connections' || "
    "ParameterName=='log_disconnections' || "
    "ParameterName=='server_audit_logging' || "
    "ParameterName=='server_audit_events' || "
    "ParameterName=='audit_trail'"
    "].{"
    "ParameterName:ParameterName,"
    "ParameterValue:ParameterValue,"
    "ApplyType:ApplyType,"
    "ApplyMethod:ApplyMethod,"
    "IsModifiable:IsModifiable,"
    "Source:Source"
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

VPC_QUERY = "Vpcs[].{VpcId:VpcId,CidrBlock:CidrBlock,IsDefault:IsDefault,State:State,Tags:Tags}"

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

SECRETS_LIST_QUERY = "SecretList[].{Name:Name,ARN:ARN,KmsKeyId:KmsKeyId,RotationEnabled:RotationEnabled,Tags:Tags}"
SECRET_QUERY = "{ARN:ARN,Name:Name,KmsKeyId:KmsKeyId,RotationEnabled:RotationEnabled,DeletedDate:DeletedDate,Tags:Tags}"
KMS_KEY_QUERY = (
    "{"
    "KeyId:KeyMetadata.KeyId,"
    "Arn:KeyMetadata.Arn,"
    "Description:KeyMetadata.Description,"
    "Enabled:KeyMetadata.Enabled,"
    "KeyManager:KeyMetadata.KeyManager,"
    "KeyState:KeyMetadata.KeyState,"
    "MultiRegion:KeyMetadata.MultiRegion"
    "}"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect RDS-centered AWS CLI evidence for CloudSentinel."
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


def extract_db_parameter_group_names(instances_result: CommandResult) -> list[str]:
    payload = get_parsed_payload(instances_result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for instance in payload:
        if not isinstance(instance, dict):
            continue
        for parameter_group in ensure_list(instance.get("DBParameterGroups")):
            if not isinstance(parameter_group, dict):
                continue
            name = parameter_group.get("DBParameterGroupName")
            if isinstance(name, str) and name:
                names.add(name)
    return sorted(names)


def extract_db_cluster_parameter_group_names(clusters_result: CommandResult) -> list[str]:
    payload = get_parsed_payload(clusters_result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for cluster in payload:
        if not isinstance(cluster, dict):
            continue
        name = cluster.get("DBClusterParameterGroup")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def extract_db_snapshot_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    snapshot_ids: set[str] = set()
    for snapshot in payload:
        if not isinstance(snapshot, dict):
            continue
        snapshot_id = snapshot.get("DBSnapshotIdentifier")
        if isinstance(snapshot_id, str) and snapshot_id:
            snapshot_ids.add(snapshot_id)
    return sorted(snapshot_ids)


def extract_db_cluster_snapshot_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    snapshot_ids: set[str] = set()
    for snapshot in payload:
        if not isinstance(snapshot, dict):
            continue
        snapshot_id = snapshot.get("DBClusterSnapshotIdentifier")
        if isinstance(snapshot_id, str) and snapshot_id:
            snapshot_ids.add(snapshot_id)
    return sorted(snapshot_ids)


def extract_resource_arns(*results: CommandResult) -> list[str]:
    arns: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            for key in (
                "DBInstanceArn",
                "DBClusterArn",
                "DBSnapshotArn",
                "DBClusterSnapshotArn",
            ):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate:
                    arns.add(candidate)
    return sorted(arns)


def extract_secret_arns(*results: CommandResult) -> list[str]:
    secret_arns: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            secret = item.get("MasterUserSecret")
            if not isinstance(secret, dict):
                continue
            arn = secret.get("SecretArn")
            if isinstance(arn, str) and arn:
                secret_arns.add(arn)
    return sorted(secret_arns)


def extract_kms_key_ids(*results: CommandResult) -> list[str]:
    key_ids: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            kms_key_id = item.get("KmsKeyId")
            if isinstance(kms_key_id, str) and kms_key_id:
                key_ids.add(kms_key_id)
    return sorted(key_ids)


def extract_vpc_ids(instances_result: CommandResult, subnet_groups_result: CommandResult) -> list[str]:
    vpc_ids: set[str] = set()
    for result in (instances_result, subnet_groups_result):
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            subnet_group = item.get("DBSubnetGroup")
            if isinstance(subnet_group, dict):
                vpc_id = subnet_group.get("VpcId")
                if isinstance(vpc_id, str) and vpc_id:
                    vpc_ids.add(vpc_id)
            else:
                vpc_id = item.get("VpcId")
                if isinstance(vpc_id, str) and vpc_id:
                    vpc_ids.add(vpc_id)
    return sorted(vpc_ids)


def extract_subnet_ids(subnet_groups_result: CommandResult, instances_result: CommandResult) -> list[str]:
    subnet_ids: set[str] = set()
    for result in (subnet_groups_result, instances_result):
        payload = get_parsed_payload(result)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            subnet_group = item.get("DBSubnetGroup")
            if isinstance(subnet_group, dict):
                subnets = ensure_list(subnet_group.get("Subnets"))
            else:
                subnets = ensure_list(item.get("Subnets"))
            for subnet in subnets:
                if not isinstance(subnet, dict):
                    continue
                subnet_id = subnet.get("SubnetIdentifier")
                if isinstance(subnet_id, str) and subnet_id:
                    subnet_ids.add(subnet_id)
    return sorted(subnet_ids)


def collect_primary_rds(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], list[str], list[str], list[str]]:
    results: list[CommandResult] = []

    db_instances_result = runner.run(
        ["rds", "describe-db-instances", "--query", DB_INSTANCES_QUERY],
        label="describe-db-instances",
    )
    db_clusters_result = runner.run(
        ["rds", "describe-db-clusters", "--query", DB_CLUSTERS_QUERY],
        label="describe-db-clusters",
    )
    subnet_groups_result = runner.run(
        ["rds", "describe-db-subnet-groups", "--query", DB_SUBNET_GROUPS_QUERY],
        label="describe-db-subnet-groups",
    )
    db_snapshots_result = runner.run(
        [
            "rds",
            "describe-db-snapshots",
            "--snapshot-type",
            "manual",
            "--query",
            DB_SNAPSHOTS_QUERY,
        ],
        label="describe-db-snapshots (manual snapshots)",
    )
    db_cluster_snapshots_result = runner.run(
        [
            "rds",
            "describe-db-cluster-snapshots",
            "--snapshot-type",
            "manual",
            "--query",
            DB_CLUSTER_SNAPSHOTS_QUERY,
        ],
        label="describe-db-cluster-snapshots (manual cluster snapshots)",
    )

    results.extend(
        [
            db_instances_result,
            db_clusters_result,
            subnet_groups_result,
            db_snapshots_result,
            db_cluster_snapshots_result,
        ]
    )

    for snapshot_id in extract_db_snapshot_ids(db_snapshots_result):
        results.append(
            runner.run(
                [
                    "rds",
                    "describe-db-snapshot-attributes",
                    "--db-snapshot-identifier",
                    snapshot_id,
                ],
                label=f"describe-db-snapshot-attributes ({snapshot_id})",
            )
        )

    for snapshot_id in extract_db_cluster_snapshot_ids(db_cluster_snapshots_result):
        results.append(
            runner.run(
                [
                    "rds",
                    "describe-db-cluster-snapshot-attributes",
                    "--db-cluster-snapshot-identifier",
                    snapshot_id,
                ],
                label=f"describe-db-cluster-snapshot-attributes ({snapshot_id})",
            )
        )

    for parameter_group_name in extract_db_parameter_group_names(db_instances_result):
        results.append(
            runner.run(
                [
                    "rds",
                    "describe-db-parameters",
                    "--db-parameter-group-name",
                    parameter_group_name,
                    "--query",
                    SECURITY_RELEVANT_DB_PARAMETERS_QUERY,
                ],
                label=f"describe-db-parameters ({parameter_group_name})",
            )
        )

    for parameter_group_name in extract_db_cluster_parameter_group_names(db_clusters_result):
        results.append(
            runner.run(
                [
                    "rds",
                    "describe-db-cluster-parameters",
                    "--db-cluster-parameter-group-name",
                    parameter_group_name,
                    "--query",
                    SECURITY_RELEVANT_DB_PARAMETERS_QUERY,
                ],
                label=f"describe-db-cluster-parameters ({parameter_group_name})",
            )
        )

    for resource_arn in extract_resource_arns(
        db_instances_result,
        db_clusters_result,
        db_snapshots_result,
        db_cluster_snapshots_result,
    ):
        results.append(
            runner.run(
                ["rds", "list-tags-for-resource", "--resource-name", resource_arn],
                label=f"list-tags-for-resource ({resource_arn})",
            )
        )

    results.append(
        runner.run(
            ["rds", "describe-certificates"],
            label="describe-certificates",
        )
    )

    return (
        results,
        extract_vpc_ids(db_instances_result, subnet_groups_result),
        extract_subnet_ids(subnet_groups_result, db_instances_result),
        extract_secret_arns(db_instances_result, db_clusters_result),
        extract_kms_key_ids(
            db_instances_result,
            db_clusters_result,
            db_snapshots_result,
            db_cluster_snapshots_result,
        ),
    )


def collect_ec2_context(
    runner: AWSCLIRunner,
    *,
    vpc_ids: Iterable[str],
    subnet_ids: Iterable[str],
) -> list[CommandResult]:
    results: list[CommandResult] = []
    vpc_id_list = sorted(set(vpc_ids))
    subnet_id_list = sorted(set(subnet_ids))

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
        results.append(
            runner.run(
                ["ec2", "describe-vpcs", "--vpc-ids", *vpc_id_list, "--query", VPC_QUERY],
                label="describe-vpcs",
            )
        )
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-instances",
                    "--filters",
                    f"Name=vpc-id,Values={','.join(vpc_id_list)}",
                    "--query",
                    EC2_INSTANCE_QUERY,
                ],
                label="describe-instances",
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

    return results


def collect_secrets_context(
    runner: AWSCLIRunner, secret_arns: Iterable[str]
) -> list[CommandResult]:
    results: list[CommandResult] = [
        runner.run(
            ["secretsmanager", "list-secrets", "--query", SECRETS_LIST_QUERY],
            label="list-secrets",
        )
    ]
    for secret_arn in sorted(set(secret_arns)):
        results.append(
            runner.run(
                ["secretsmanager", "describe-secret", "--secret-id", secret_arn, "--query", SECRET_QUERY],
                label=f"describe-secret ({secret_arn})",
            )
        )
    return results


def collect_kms_context(
    runner: AWSCLIRunner, kms_key_ids: Iterable[str]
) -> list[CommandResult]:
    results: list[CommandResult] = []
    for kms_key_id in sorted(set(kms_key_ids)):
        results.append(
            runner.run(
                ["kms", "describe-key", "--key-id", kms_key_id, "--query", KMS_KEY_QUERY],
                label=f"describe-key ({kms_key_id})",
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

    primary_results, vpc_ids, subnet_ids, secret_arns, kms_key_ids = collect_primary_rds(runner)

    sections = [
        render_section("PRIMARY SERVICE: RDS", primary_results),
        render_section(
            "DEPENDENCY CONTEXT: EC2",
            collect_ec2_context(runner, vpc_ids=vpc_ids, subnet_ids=subnet_ids),
        ),
        render_section(
            "DEPENDENCY CONTEXT: SECRETS_MANAGER",
            collect_secrets_context(runner, secret_arns),
        ),
        render_section(
            "DEPENDENCY CONTEXT: KMS",
            collect_kms_context(runner, kms_key_ids),
        ),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
