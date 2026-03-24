from __future__ import annotations

import argparse
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


VOLUME_QUERY = (
    "Volumes[].{"
    "VolumeId:VolumeId,"
    "AvailabilityZone:AvailabilityZone,"
    "State:State,"
    "Encrypted:Encrypted,"
    "KmsKeyId:KmsKeyId,"
    "Size:Size,"
    "VolumeType:VolumeType,"
    "SnapshotId:SnapshotId,"
    "CreateTime:CreateTime,"
    "Attachments:Attachments[].{InstanceId:InstanceId,State:State,Device:Device,DeleteOnTermination:DeleteOnTermination},"
    "Tags:Tags"
    "}"
)

SNAPSHOT_QUERY = (
    "Snapshots[].{"
    "SnapshotId:SnapshotId,"
    "VolumeId:VolumeId,"
    "State:State,"
    "StartTime:StartTime,"
    "Encrypted:Encrypted,"
    "KmsKeyId:KmsKeyId,"
    "VolumeSize:VolumeSize,"
    "Description:Description,"
    "OwnerId:OwnerId,"
    "Tags:Tags"
    "}"
)

INSTANCE_QUERY = (
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

IMAGE_QUERY = (
    "Images[].{"
    "ImageId:ImageId,"
    "Name:Name,"
    "Public:Public,"
    "CreationDate:CreationDate,"
    "State:State,"
    "BlockDeviceMappings:BlockDeviceMappings[].{DeviceName:DeviceName,Ebs:Ebs},"
    "Tags:Tags"
    "}"
)

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
        description="Collect EBS-centered AWS CLI evidence for CloudSentinel."
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


def chunked(values: Iterable[str], size: int) -> list[list[str]]:
    items = [value for value in values if value]
    return [items[index:index + size] for index in range(0, len(items), size)]


def extract_snapshot_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    snapshot_ids: set[str] = set()
    for snapshot in payload:
        if not isinstance(snapshot, dict):
            continue
        snapshot_id = snapshot.get("SnapshotId")
        if isinstance(snapshot_id, str) and snapshot_id:
            snapshot_ids.add(snapshot_id)
    return sorted(snapshot_ids)


def extract_attached_instance_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    instance_ids: set[str] = set()
    for volume in payload:
        if not isinstance(volume, dict):
            continue
        attachments = volume.get("Attachments")
        if not isinstance(attachments, list):
            continue
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            instance_id = attachment.get("InstanceId")
            if isinstance(instance_id, str) and instance_id:
                instance_ids.add(instance_id)
    return sorted(instance_ids)


def extract_kms_key_ids(*results: CommandResult) -> list[str]:
    key_ids: set[str] = set()
    for result in results:
        payload = get_parsed_payload(result)
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                kms_key_id = item.get("KmsKeyId")
                if isinstance(kms_key_id, str) and kms_key_id:
                    key_ids.add(kms_key_id)
        elif isinstance(payload, dict):
            kms_key_id = payload.get("KmsKeyId")
            if isinstance(kms_key_id, str) and kms_key_id:
                key_ids.add(kms_key_id)
    return sorted(key_ids)


def collect_primary_ebs(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], list[str]]:
    results: list[CommandResult] = []

    volumes_result = runner.run(
        ["ec2", "describe-volumes", "--query", VOLUME_QUERY],
        label="describe-volumes",
    )
    snapshots_result = runner.run(
        ["ec2", "describe-snapshots", "--owner-ids", "self", "--query", SNAPSHOT_QUERY],
        label="describe-snapshots (owner self)",
    )
    encryption_by_default_result = runner.run(
        ["ec2", "get-ebs-encryption-by-default"],
        label="get-ebs-encryption-by-default",
    )
    default_kms_key_result = runner.run(
        ["ec2", "get-ebs-default-kms-key-id"],
        label="get-ebs-default-kms-key-id",
    )
    snapshot_block_result = runner.run(
        ["ec2", "get-snapshot-block-public-access-state"],
        label="get-snapshot-block-public-access-state",
    )

    results.extend(
        [
            volumes_result,
            snapshots_result,
            encryption_by_default_result,
            default_kms_key_result,
            snapshot_block_result,
        ]
    )

    for snapshot_id in extract_snapshot_ids(snapshots_result):
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

    kms_key_ids = extract_kms_key_ids(volumes_result, snapshots_result, default_kms_key_result)
    instance_ids = extract_attached_instance_ids(volumes_result)
    return results, instance_ids, kms_key_ids


def collect_ec2_context(
    runner: AWSCLIRunner, instance_ids: Iterable[str]
) -> list[CommandResult]:
    results: list[CommandResult] = []
    instance_id_list = sorted(set(instance_ids))
    for index, instance_chunk in enumerate(chunked(instance_id_list, 100), start=1):
        label = "describe-instances" if index == 1 else f"describe-instances (batch {index})"
        results.append(
            runner.run(
                ["ec2", "describe-instances", "--instance-ids", *instance_chunk, "--query", INSTANCE_QUERY],
                label=label,
            )
        )

    results.append(
        runner.run(
            ["ec2", "describe-images", "--owners", "self", "--query", IMAGE_QUERY],
            label="describe-images",
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

    primary_results, instance_ids, kms_key_ids = collect_primary_ebs(runner)

    sections = [
        render_section("PRIMARY SERVICE: EBS", primary_results),
        render_section(
            "DEPENDENCY CONTEXT: EC2",
            collect_ec2_context(runner, instance_ids),
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
