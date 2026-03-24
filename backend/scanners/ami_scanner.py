from __future__ import annotations

import argparse
from typing import Iterable

from aws_cli_runner import AWSCLIRunner, CommandResult, render_section, write_output


IMAGE_QUERY = (
    "Images[].{"
    "ImageId:ImageId,"
    "Name:Name,"
    "Description:Description,"
    "CreationDate:CreationDate,"
    "DeprecationTime:DeprecationTime,"
    "LastLaunchedTime:LastLaunchedTime,"
    "State:State,"
    "Public:Public,"
    "ImdsSupport:ImdsSupport,"
    "DeregistrationProtection:DeregistrationProtection,"
    "BlockDeviceMappings:BlockDeviceMappings[].{DeviceName:DeviceName,Ebs:Ebs},"
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
    "Description:Description,"
    "VolumeSize:VolumeSize,"
    "OwnerId:OwnerId,"
    "Tags:Tags"
    "}"
)

INSTANCE_QUERY = (
    "Reservations[].Instances[].{"
    "InstanceId:InstanceId,"
    "ImageId:ImageId,"
    "Name:Tags[?Key=='Name']|[0].Value,"
    "State:State.Name,"
    "LaunchTime:LaunchTime,"
    "VpcId:VpcId,"
    "SubnetId:SubnetId,"
    "PublicIpAddress:PublicIpAddress,"
    "PrivateIpAddress:PrivateIpAddress,"
    "IamInstanceProfile:IamInstanceProfile.Arn,"
    "Tags:Tags"
    "}"
)

LAUNCH_TEMPLATES_QUERY = (
    "LaunchTemplates[].{"
    "LaunchTemplateId:LaunchTemplateId,"
    "LaunchTemplateName:LaunchTemplateName,"
    "DefaultVersionNumber:DefaultVersionNumber,"
    "LatestVersionNumber:LatestVersionNumber,"
    "Tags:Tags"
    "}"
)

LAUNCH_TEMPLATE_VERSIONS_QUERY = (
    "LaunchTemplateVersions[].{"
    "LaunchTemplateId:LaunchTemplateId,"
    "LaunchTemplateName:LaunchTemplateName,"
    "VersionNumber:VersionNumber,"
    "DefaultVersion:DefaultVersion,"
    "LaunchTemplateData:{"
    "ImageId:ImageId,"
    "InstanceType:InstanceType,"
    "IamInstanceProfile:IamInstanceProfile,"
    "MetadataOptions:MetadataOptions"
    "},"
    "CreateTime:CreateTime,"
    "CreatedBy:CreatedBy"
    "}"
)

AUTO_SCALING_GROUP_QUERY = (
    "AutoScalingGroups[].{"
    "AutoScalingGroupName:AutoScalingGroupName,"
    "DesiredCapacity:DesiredCapacity,"
    "MinSize:MinSize,"
    "MaxSize:MaxSize,"
    "LaunchConfigurationName:LaunchConfigurationName,"
    "LaunchTemplate:LaunchTemplate,"
    "MixedInstancesPolicy:MixedInstancesPolicy,"
    "Instances:Instances[].{InstanceId:InstanceId,LifecycleState:LifecycleState}"
    "}"
)

LAUNCH_CONFIGURATION_QUERY = (
    "LaunchConfigurations[].{"
    "LaunchConfigurationName:LaunchConfigurationName,"
    "ImageId:ImageId,"
    "InstanceType:InstanceType,"
    "IamInstanceProfile:IamInstanceProfile,"
    "CreatedTime:CreatedTime,"
    "MetadataOptions:MetadataOptions"
    "}"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect AMI-centered AWS CLI evidence for CloudSentinel."
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


def extract_image_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    image_ids: set[str] = set()
    for image in payload:
        if not isinstance(image, dict):
            continue
        image_id = image.get("ImageId")
        if isinstance(image_id, str) and image_id:
            image_ids.add(image_id)
    return sorted(image_ids)


def extract_backing_snapshot_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    snapshot_ids: set[str] = set()
    for image in payload:
        if not isinstance(image, dict):
            continue
        for mapping in ensure_list(image.get("BlockDeviceMappings")):
            if not isinstance(mapping, dict):
                continue
            ebs = mapping.get("Ebs")
            if not isinstance(ebs, dict):
                continue
            snapshot_id = ebs.get("SnapshotId")
            if isinstance(snapshot_id, str) and snapshot_id:
                snapshot_ids.add(snapshot_id)
    return sorted(snapshot_ids)


def extract_launch_template_ids(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    template_ids: set[str] = set()
    for template in payload:
        if not isinstance(template, dict):
            continue
        template_id = template.get("LaunchTemplateId")
        if isinstance(template_id, str) and template_id:
            template_ids.add(template_id)
    return sorted(template_ids)


def extract_launch_configuration_names(result: CommandResult) -> list[str]:
    payload = get_parsed_payload(result)
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for group in payload:
        if not isinstance(group, dict):
            continue
        name = group.get("LaunchConfigurationName")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def collect_primary_ami(
    runner: AWSCLIRunner,
) -> tuple[list[CommandResult], list[str], list[str]]:
    results: list[CommandResult] = []

    images_result = runner.run(
        ["ec2", "describe-images", "--owners", "self", "--query", IMAGE_QUERY],
        label="describe-images (owners self)",
    )
    results.append(images_result)

    image_ids = extract_image_ids(images_result)
    for image_id in image_ids:
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-image-attribute",
                    "--image-id",
                    image_id,
                    "--attribute",
                    "launchPermission",
                ],
                label=f"describe-image-attribute ({image_id}, launchPermission)",
            )
        )
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-image-attribute",
                    "--image-id",
                    image_id,
                    "--attribute",
                    "imdsSupport",
                ],
                label=f"describe-image-attribute ({image_id}, imdsSupport)",
            )
        )
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-image-attribute",
                    "--image-id",
                    image_id,
                    "--attribute",
                    "deregistrationProtection",
                ],
                label=f"describe-image-attribute ({image_id}, deregistrationProtection)",
            )
        )

    return results, image_ids, extract_backing_snapshot_ids(images_result)


def collect_ec2_context(
    runner: AWSCLIRunner,
    *,
    image_ids: Iterable[str],
    snapshot_ids: Iterable[str],
) -> list[CommandResult]:
    results: list[CommandResult] = []
    snapshot_id_list = sorted(set(snapshot_ids))
    image_id_list = sorted(set(image_ids))

    for index, snapshot_chunk in enumerate(chunked(snapshot_id_list, 150), start=1):
        label = (
            "describe-snapshots (backing snapshots)"
            if index == 1
            else f"describe-snapshots (backing snapshots batch {index})"
        )
        results.append(
            runner.run(
                ["ec2", "describe-snapshots", "--snapshot-ids", *snapshot_chunk, "--query", SNAPSHOT_QUERY],
                label=label,
            )
        )

    for snapshot_id in snapshot_id_list:
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

    for index, image_chunk in enumerate(chunked(image_id_list, 100), start=1):
        label = "describe-instances" if index == 1 else f"describe-instances (owned-ami batch {index})"
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-instances",
                    "--filters",
                    f"Name=image-id,Values={','.join(image_chunk)}",
                    "--query",
                    INSTANCE_QUERY,
                ],
                label=label,
            )
        )

    launch_templates_result = runner.run(
        ["ec2", "describe-launch-templates", "--query", LAUNCH_TEMPLATES_QUERY],
        label="describe-launch-templates",
    )
    results.append(launch_templates_result)
    for template_id in extract_launch_template_ids(launch_templates_result):
        results.append(
            runner.run(
                [
                    "ec2",
                    "describe-launch-template-versions",
                    "--launch-template-id",
                    template_id,
                    "--versions",
                    "$Default",
                    "$Latest",
                    "--query",
                    LAUNCH_TEMPLATE_VERSIONS_QUERY,
                ],
                label=f"describe-launch-template-versions ({template_id})",
            )
        )

    return results


def collect_autoscaling_context(runner: AWSCLIRunner) -> list[CommandResult]:
    results: list[CommandResult] = []
    asg_result = runner.run(
        ["autoscaling", "describe-auto-scaling-groups", "--query", AUTO_SCALING_GROUP_QUERY],
        label="describe-auto-scaling-groups",
    )
    results.append(asg_result)

    launch_configuration_names = extract_launch_configuration_names(asg_result)
    for index, name_chunk in enumerate(chunked(launch_configuration_names, 50), start=1):
        label = (
            "describe-launch-configurations"
            if index == 1
            else f"describe-launch-configurations (batch {index})"
        )
        results.append(
            runner.run(
                [
                    "autoscaling",
                    "describe-launch-configurations",
                    "--launch-configuration-names",
                    *name_chunk,
                    "--query",
                    LAUNCH_CONFIGURATION_QUERY,
                ],
                label=label,
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

    primary_results, image_ids, snapshot_ids = collect_primary_ami(runner)

    sections = [
        render_section("PRIMARY SERVICE: AMI", primary_results),
        render_section(
            "DEPENDENCY CONTEXT: EC2",
            collect_ec2_context(runner, image_ids=image_ids, snapshot_ids=snapshot_ids),
        ),
        render_section(
            "DEPENDENCY CONTEXT: AUTOSCALING",
            collect_autoscaling_context(runner),
        ),
    ]
    return "\n\n".join(section for section in sections if section)


def main() -> None:
    args = parse_args()
    output = build_scan_output(args)
    write_output(output, args.output_file)


if __name__ == "__main__":
    main()
