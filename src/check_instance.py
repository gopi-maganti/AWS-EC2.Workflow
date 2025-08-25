#!/usr/bin/env python3
import argparse
import logging
import os
import time
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, WaiterError


# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------
# EC2 helpers
# -----------------------------
def _find_running_or_pending_by_tag(
    ec2, *, tag_key: str, tag_value: str
) -> Optional[str]:
    """
    Return an instance-id with given tag in running/pending, or None.

    Args:
        ec2: Boto3 EC2 client
        tag_key: Tag key to search for
        tag_value: Tag value to search for

    Returns:
        The instance ID if found, else None.
    """
    resp = ec2.describe_instances(
        Filters=[
            {"Name": f"tag:{tag_key}", "Values": [tag_value]},
            {"Name": "instance-state-name", "Values": ["pending", "running"]},
        ]
    )
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            return inst["InstanceId"]
    return None


def get_or_create_instance(
    *,
    region: str,
    ami_id: str,
    instance_type: str,
    tag_key: str = "Name",
    tag_value: str = "fruitstore-ec2",
    iam_instance_profile: Optional[str] = None,  # Name or ARN
    subnet_id: Optional[str] = None,
    security_group_ids: Optional[List[str]] = None,
) -> str:
    """
    Reuse a running/pending instance by tag or create a new one (no KeyPair—SSM only).
    Returns the instance-id.

    Args:
        region: AWS region (e.g. us-east-1)
        ami_id: AMI ID to launch
        instance_type: EC2 instance type (e.g. t3.medium)
        tag_key: Tag key to search for existing instance (default: "Name")
        tag_value: Tag value to search for existing instance (default: "fruitstore-ec2")
        iam_instance_profile: Optional instance profile Name or ARN with SSM permissions
        subnet_id: Optional subnet ID to launch into
        security_group_ids: Optional list of security group IDs to attach

    Returns:
        The instance ID of the running or newly created instance.

    Raises:
        ClientError: If AWS API calls fail.
        WaiterError: If waiting for instance to run fails.
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Reuse if present
    instance_id = _find_running_or_pending_by_tag(ec2, tag_key=tag_key, tag_value=tag_value)
    if instance_id:
        logger.info(f"Reusing existing instance: {instance_id}")
        return instance_id

    # Build run_instances arguments
    run_args: Dict[str, Any] = {
        "ImageId": ami_id,
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": tag_key, "Value": tag_value}],
            }
        ],
    }

    if iam_instance_profile:
        run_args["IamInstanceProfile"] = (
            {"Arn": iam_instance_profile}
            if iam_instance_profile.startswith("arn:")
            else {"Name": iam_instance_profile}
        )

    if subnet_id:
        run_args["SubnetId"] = subnet_id

    if security_group_ids:
        run_args["SecurityGroupIds"] = security_group_ids

    logger.info("No existing instance found. Creating new EC2 instance (SSM)…")
    try:
        res = ec2.run_instances(**run_args)
    except ClientError as e:
        logger.error(f"Failed to run instance: {e}")
        raise

    instance_id = res["Instances"][0]["InstanceId"]
    logger.info(f"Created instance: {instance_id}")

    # Wait until instance is RUNNING
    waiter = ec2.get_waiter("instance_running")
    try:
        logger.info("Waiting for EC2 to enter 'running' state…")
        waiter.wait(InstanceIds=[instance_id])
        logger.info(f"Instance {instance_id} is now running.")
    except WaiterError as e:
        logger.error(f"Waiter failed while waiting for instance to run: {e}")
        raise

    return instance_id


# -----------------------------
# SSM helpers
# -----------------------------
def wait_for_ssm_managed(instance_id: str, region: str, timeout: int = 600) -> None:
    """
    Wait until the instance is registered as an SSM managed instance.
    Requires the instance role to include AmazonSSMManagedInstanceCore and
    network egress to SSM endpoints (or VPC endpoints).

    Args:
        instance_id: The EC2 instance ID to check.
        region: AWS region (e.g. us-east-1)
        timeout: Maximum time to wait in seconds (default: 600)

    Raises:
        TimeoutError: If the instance does not register within the timeout.
    """
    ssm = boto3.client("ssm", region_name=region)
    logger.info("Waiting for SSM agent to register this instance…")

    start = time.time()
    while time.time() - start < timeout:
        time.sleep(6)
        try:
            page = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            infos = page.get("InstanceInformationList", [])
            if infos and infos[0].get("PingStatus") == "Online":
                logger.info("SSM agent is online.")
                return
        except ClientError:
            # ignore transient permissions/registration propagation
            pass

    raise TimeoutError(
        "Timed out waiting for SSM agent to register (check IAM role and networking)."
    )


def run_script_via_ssm(
    instance_id: str, region: str, script_path: str, timeout_seconds: int = 1800
) -> None:
    """Reads a local shell script and executes it on the instance via SSM."""
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")

    with open(script_path, "r", encoding="utf-8") as f:
        script = f.read()

    ssm = boto3.client("ssm", region_name=region)

    logger.info(f"Sending SSM command to {instance_id}…")
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            CloudWatchOutputConfig={"CloudWatchOutputEnabled": False},
            TimeoutSeconds=timeout_seconds,
        )
    except ClientError as e:
        logger.error(f"Failed to send SSM command: {e}")
        raise

    cmd_id = resp["Command"]["CommandId"]
    logger.info(f"Command sent. CommandId={cmd_id}. Waiting for completion…")

    start = time.time()
    while time.time() - start < timeout_seconds:
        time.sleep(5)
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        status = inv.get("Status")

        if status in ("Pending", "InProgress", "Delayed"):
            continue

        stdout = inv.get("StandardOutputContent", "")
        stderr = inv.get("StandardErrorContent", "")

        if stdout:
            logger.info("SSM STDOUT:\n" + stdout)
        if stderr.strip():
            logger.warning("SSM STDERR:\n" + stderr)

        if status == "Success":
            logger.info("✔ SSM command completed successfully.")
            return

        raise RuntimeError(f"SSM command finished with status: {status}")

    raise TimeoutError("Timed out waiting for SSM command to finish.")


# -----------------------------
# CLI
# -----------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create/reuse EC2, run setup via SSM")
    p.add_argument("--region", required=True, help="AWS region (e.g. us-east-1)")
    p.add_argument("--ami-id", required=True, help="AMI ID")
    p.add_argument("--instance-type", required=True, help="EC2 instance type")
    p.add_argument("--tag-value", default="fruitstore-ec2", help="Name tag to reuse")
    p.add_argument("--script-path", default="scripts/setup.sh", help="Script to run")
    # Optional launch-time wiring:
    p.add_argument(
        "--iam-instance-profile",
        help="Instance profile (Name or ARN) with AmazonSSMManagedInstanceCore",
    )
    p.add_argument("--subnet-id", help="Subnet to launch into (optional)")
    p.add_argument(
        "--security-group-ids",
        help="Comma-separated SG IDs to attach (optional)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    sgs = (
        [sg.strip() for sg in args.security_group_ids.split(",")]
        if args.security_group_ids
        else None
    )

    instance_id = get_or_create_instance(
        region=args.region,
        ami_id=args.ami_id,
        instance_type=args.instance_type,
        tag_key="Name",
        tag_value=args.tag_value,
        iam_instance_profile=args.iam_instance_profile,
        subnet_id=args.subnet_id,
        security_group_ids=sgs,
    )

    # SSM readiness (instance running != agent online)
    wait_for_ssm_managed(instance_id, args.region)

    # Execute your setup script remotely
    run_script_via_ssm(instance_id, args.region, args.script_path)


if __name__ == "__main__":
    main()
